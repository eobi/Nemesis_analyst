"""Containment-first sample loading.

How loading really behaves (measured live, 3/3 trials): `debug_init` returns instantly, the
debuggee then RUNS the Windows loader for ~2 s (state "running", eip moving through ntdll /
kernel32), and the debugger itself stops it at the program's ENTRY with the module registered.
So "controlled" can only mean: paused AT the entry. Rules:

  * wait PASSIVELY for that entry stop — never pause/poke during loading (an earlier version
    called debug_pause while "running", interrupting the loader and leaving a half-state);
  * the debugger going silent (empty state) for a few polls = LOSS OF CONTROL -> stop the
    debuggee AND hard-kill the sample's process tree on the guest, then abort;
  * the process exiting before it reaches its entry, or never reaching it within the budget:
    same containment, then abort.

Known uncontrolled window: the loader phase above (DLL initialisers and any TLS callbacks run
before the entry stop). The static scan reports TLS callbacks so that risk is visible.

Containment = debug_stop + `taskkill /f /t` on the sample's image name. It cannot undo anything
a sample already did, so the VM must still be reverted after any aborted load.
"""
from __future__ import annotations

import ntpath
import time


def _state(eng) -> str:
    try:
        s = eng.call("debug_get_state")
        return (s.get("state") or "") if isinstance(s, dict) else ""
    except Exception:
        return ""


def contain(eng, guest, guest_sample: str, reason: str, log=print, sleep=time.sleep) -> None:
    """Stop the debuggee and kill the sample's whole process tree on the guest."""
    log(f"[SAFETY] {reason} — containing (debug_stop + taskkill /f /t)")
    try:
        eng.call("debug_stop")
    except Exception:
        pass
    sleep(1.0)
    try:
        guest.run(f'cmd /c "taskkill /f /t /im {ntpath.basename(guest_sample)} 2>nul"', timeout=20)
    except Exception:
        pass


def _compact(seq) -> str:
    """['stopped','running','running','paused'] -> 'stopped x1 -> running x2 -> paused x1'."""
    out = []
    for x in seq:
        if out and out[-1][0] == x:
            out[-1][1] += 1
        else:
            out.append([x, 1])
    return " -> ".join(f"{a} x{n}" for a, n in out)


def _same(a, b) -> bool:
    try:
        return int(str(a), 16) == int(str(b), 16)
    except Exception:
        return False


def safe_load(eng, guest, guest_sample: str, want: str, log=print,
              sleep=time.sleep, polls: int = 60, blind_limit: int = 3, stop_limit: int = 3,
              early_pause: bool = True, pause_after: int = 2):
    """Load `guest_sample` under the debugger with containment.

    Returns (controlled, module_info, init_ok, reason). `controlled` is True only when the
    debuggee is PAUSED with its main module (name contains `want`) registered; module_info then
    carries `eip` and `at_entry` (False = the debugger's first stop was NOT the entry: code before
    that stop was not observed).
    On any False return the sample has already been contained."""
    r = eng.call("debug_init", {"path": guest_sample})
    init_ok = isinstance(r, dict) and bool(r.get("success"))
    blind, mg, saw_running, stopped, seq = 0, {}, False, 0, []
    running_polls, pause_sent, unreg_paused = 0, False, 0
    for _ in range(polls):
        st = _state(eng)
        seq.append(st or "(silent)")
        if st != "stopped":
            stopped = 0
        if st == "running":
            blind, saw_running = 0, True
            running_polls += 1
            # Measured: the debugger's own entry stop does not always come (dridex: first stop was INSIDE its
            # decryption code, after it had already run its early steps; a .NET program: inside the CLR). So we
            # pause ONCE, early, while the program is certainly still in the loader (the loader runs ~2 s and the
            # entry stop comes after it). run_to_entry then goes to the entry under our own breakpoints.
            if early_pause and not pause_sent and running_polls >= pause_after:
                pause_sent = True
                try:
                    eng.call("debug_pause")
                except Exception:
                    pass
        elif st == "stopped":
            blind = 0
            stopped += 1
            # a real exit STAYS stopped; a single reading may be a flicker between debugger events
            if saw_running and stopped >= stop_limit:
                reason = f"process exited before reaching its entry point (it ran uncontrolled); debugger states seen: {_compact(seq)}"
                contain(eng, guest, guest_sample, reason, log, sleep)
                return False, mg, init_ok, reason
        elif not st:
            blind += 1
            if blind >= blind_limit:
                reason = f"debugger stopped answering after debug_init (loss of control); debugger states seen: {_compact(seq)}"
                contain(eng, guest, guest_sample, reason, log, sleep)
                return False, mg, init_ok, reason
        else:
            blind = 0
        if st == "paused":
            try:
                mg = eng.call("module_get_main") or {}
            except Exception:
                mg = {}
            if pause_sent and not (isinstance(mg, dict) and mg.get("entry")):
                unreg_paused += 1
                if unreg_paused == 3:                    # paused too early for the module to be registered: let the loader go on
                    try:
                        eng.call("debug_run")
                    except Exception:
                        pass
                    unreg_paused, pause_sent = 0, True
            if isinstance(mg, dict) and mg.get("entry") and want in (mg.get("name") or "").lower():
                cur = ""
                try:
                    cur = (eng.call("debug_get_state") or {}).get("eip", "")
                except Exception:
                    pass
                # Under control = the debugger is PAUSED and the main module is registered. The debugger
                # does not always stop at the entry (measured: a .NET program's first stop was inside the
                # CLR, after its entry stub had run), so record WHERE we are; callers must not assume entry.
                at = _same(cur, mg.get("entry"))
                # early_pause=True means: we stopped it ourselves in the loader, BEFORE any of its code ran
                mg = dict(mg, eip=cur, at_entry=at, early_pause=bool(pause_sent and not at))
                return True, mg, init_ok, ""
        sleep(0.4)
    reason = f"never reached its entry point under debugger control; debugger states seen: {_compact(seq)}"
    contain(eng, guest, guest_sample, reason, log, sleep)
    return False, mg if isinstance(mg, dict) else {}, init_ok, reason
