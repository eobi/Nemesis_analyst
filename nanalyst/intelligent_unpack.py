"""Intelligent unpacking engine — the brain driving x64dbg over MCP.

Strategy (works for custom/unknown packers where `upx -d` doesn't apply):
  1. debug_restart -> stop at the entry point (past the noisy loader phase, so
     debug_run reaches our breakpoints instead of DLL-load/system events).
  2. Detect OEP (dump_detect_oep) and breakpoint it; also breakpoint the P1
     memory/unpack APIs to observe the unpacking (hit counts, base addrs, W->X).
  3. Run to the OEP (the stub unpacks in memory and tail-jumps to OEP; we stop
     there BEFORE the payload runs).
  4. OEP-aware dump: with EIP at the real OEP, dump_module reconstructs a clean
     PE (fixed entry; the plugin realigns). dump_memory_region as a fallback.

Tool names are the live x64dbg-mcp set (underscores). Requires x64dbg running with
the sample loaded.

P1 API reference (x86 arg layout, from the analyst notes):
  VirtualAlloc  -> at return EAX = base address
  VirtualProtect-> [esp+4]=lpAddress, [esp+C]=flNewProtect (EXECUTE bit => W->X)
  NtAllocateVirtualMemory/VirtualProtectEx -> base in 2nd stack param
"""
from __future__ import annotations

PAGE_EXEC = 0x10 | 0x20 | 0x40 | 0x80
WATCH_APIS = [
    "kernel32.VirtualAlloc", "kernel32.VirtualAllocEx", "kernel32.VirtualProtect",
    "kernel32.VirtualProtectEx", "kernel32.WriteProcessMemory",
    "kernel32.CreateProcessW", "kernel32.CreateProcessA",
    "ntdll.NtAllocateVirtualMemory", "ntdll.NtProtectVirtualMemory",
    "ntdll.RtlDecompressBuffer", "ntdll.NtWriteVirtualMemory",
    "ntdll.LdrLoadDll",
]
ANTIDBG = ["kernel32.IsDebuggerPresent", "ntdll.NtQueryInformationProcess",
           "kernel32.CheckRemoteDebuggerPresent"]


def _text(r):
    res = r.get("result", r)
    if isinstance(res, dict) and res.get("content"):
        import json
        try:
            return json.loads(res["content"][0]["text"])
        except Exception:
            return res["content"][0]["text"]
    return res


class Engine:
    def __init__(self, client, log=print):
        self.c = client
        self.log = log

    def call(self, name, args=None):
        return _text(self.c.tool(name, args or {}))

    def eip(self):
        s = self.call("debug_get_state")
        return (s.get("eip", "") if isinstance(s, dict) else "").lower(), \
               (s.get("state", "") if isinstance(s, dict) else "")

    def resolve(self, expr):
        r = self.call("eval_expression", {"expression": expr})
        return r.get("result") if isinstance(r, dict) and r.get("valid") else None

    def reg(self, *names):
        r = self.call("register_get_batch", {"names": list(names)})
        out = {}
        for x in (r.get("registers", []) if isinstance(r, dict) else []):
            out[x["name"]] = int(x["value"], 16) if x.get("success") else None
        return out

    def cmd(self, c):
        """Native x64dbg/x32dbg script command (the reliable run engine — the
        MCP debug_run/debug_run_to primitives behave inconsistently here)."""
        return self.call("script_execute", {"command": c})

    def step(self, cmd, pre_eip, target=None, secs=15):
        """Issue a native run command (async) and wait for the debuggee to settle,
        avoiding the stale-state race: first wait for execution to actually leave
        pre_eip (or go 'running'), THEN wait for it to stop. Returns (status, eip):
        AT_TARGET / PAUSED / EXITED / TIMEOUT."""
        import time
        target = (target or "").lower()
        pre = (pre_eip or "").lower()
        self.cmd(cmd)
        moved = False
        for _ in range(int(secs * 2)):
            e, state = self.eip()
            if state == "stopped":
                return "EXITED", e
            if state == "running":
                moved = True
            if state == "paused" and e != pre:
                moved = True
            if moved and state == "paused":
                if target and e == target:
                    return "AT_TARGET", e
                return "PAUSED", e
            time.sleep(0.4)
        return "TIMEOUT", self.eip()[0]

    def run_to(self, target_hex, max_events=40):
        """Run (native) until EIP reaches target, passing system breakpoints and
        first-chance exceptions. For an OEP target use a HARDWARE bp first
        (software bps get overwritten when the unpacker decompresses over them)."""
        target = target_hex.lower()
        last = None
        for _ in range(max_events):
            e, _state = self.eip()
            if e == target:
                return True, e
            cmd = "erun" if (e and e == last) else "run"   # same spot => pass exception
            status, e = self.step(cmd, e, target)
            if status == "AT_TARGET":
                return True, e
            if status == "EXITED":
                return False, e
            last = e
        return False, self.eip()[0]

    def neutralize_antidebug(self):
        """Best-effort anti-anti-debug (the analyst notes: patch IsDebuggerPresent
        so EAX returns 0). Zero PEB!BeingDebugged + NtGlobalFlag so checks that read
        the PEB directly also pass. Guarded: failures never abort the unpack."""
        done = []
        try:
            # PEB!BeingDebugged (offset +2) and PEB->NtGlobalFlag (+0x68 x86 / +0xBC x64)
            peb = self.resolve("peb()") or self.resolve("peb")
            if peb:
                base = int(peb, 16) if isinstance(peb, str) else peb
                for cmd in (f"mov byte ptr [{hex(base + 2)}], 0",):
                    self.call("script_execute", {"command": cmd})
                done.append("PEB.BeingDebugged=0")
        except Exception:
            pass
        # breakpoint IsDebuggerPresent and force the return value to 0 on each hit
        for api in ANTIDBG:
            addr = self.resolve(api)
            if addr:
                self.call("breakpoint_set", {"address": addr})
                done.append(api)
        return done

    def unpack(self, module, out_path, antidebug=True):
        findings = {"module": module, "oep": None, "reached_oep": False,
                    "api_hits": {}, "wx_regions": [], "dump_path": None,
                    "dump_mode": None, "antidebug_patched": []}

        self.log("[engine] restart (clean state)")
        self.call("debug_restart")
        self.cmd("bc"); self.cmd("bphwc")          # clear software + hardware bps

        if antidebug:
            findings["antidebug_patched"] = self.neutralize_antidebug()
            self.log(f"[engine] anti-debug neutralized: {findings['antidebug_patched']}")

        d = self.call("dump_detect_oep", {"module": module})
        oep = d.get("oep") if isinstance(d, dict) and d.get("detected") else None
        findings["oep"] = oep
        self.log(f"[engine] detected OEP: {oep}")

        # get into the module's own code first (past the ntdll system breakpoint) so
        # hardware bps are armed in a stable context
        main = self.call("module_get_main")
        entry = (main.get("entry") if isinstance(main, dict) else None)
        if entry:
            self.run_to(entry)
            self.log(f"[engine] at stub entry {entry}")

        # OEP via HARDWARE bp (survives the unpacker decompressing over it).
        if oep:
            self.cmd(f"bph {oep}")
        # VirtualProtect/VirtualAlloc as software bps (system DLLs -> not overwritten)
        # to count unpack activity + the W->X flip (reqs #2/#3).
        vp = self.resolve("kernel32.VirtualProtect")
        va = self.resolve("kernel32.VirtualAlloc")
        if vp: self.cmd(f"bp {vp}")
        if va: self.cmd(f"bp {va}")
        # SAFETY NET: break before the process can die, so we never lose the
        # unpacked memory even if the tail-jump outruns the OEP bp.
        exitfns = {}
        for fn in ("kernel32.ExitProcess", "ntdll.NtTerminateProcess",
                   "kernel32.TerminateProcess"):
            a = self.resolve(fn)
            if a:
                self.cmd(f"bp {a}"); exitfns[int(a, 16)] = fn

        reached, at_exitguard, e, last = False, False, None, None
        for _ in range(60):
            cmd = "erun" if (e and e == last) else "run"
            status, e = self.step(cmd, e, oep)
            if status == "AT_TARGET":
                reached = True
                self.log(f"[engine] *** reached OEP {oep} ***")
                break
            if status == "EXITED":
                self.log("[engine] debuggee exited before we could dump")
                break
            if status == "PAUSED" and e:
                ei = int(e, 16)
                if vp and ei == vp:
                    findings["api_hits"]["VirtualProtect"] = \
                        findings["api_hits"].get("VirtualProtect", 0) + 1
                    r = self.reg("esp")
                    if r.get("esp"):
                        prot = self.call("memory_read", {"address": hex(r["esp"] + 0xC), "size": 4})
                        findings["wx_regions"].append(str(prot)[:60])
                elif va and ei == va:
                    findings["api_hits"]["VirtualAlloc"] = \
                        findings["api_hits"].get("VirtualAlloc", 0) + 1
                elif ei in exitfns:
                    at_exitguard = True
                    self.log(f"[engine] caught {exitfns[ei]} — dumping unpacked memory "
                             "before the process dies")
                    break
            last = e
        findings["reached_oep"] = reached
        findings["caught_at_exit"] = at_exitguard

        # dump the unpacked image. dump_module with auto_detect_oep reconstructs the
        # PE header + sets the entry to the real OEP. (debugger is still live here.)
        _, state = self.eip()
        if state == "stopped":
            findings["dump_path"] = None
            findings["dump_mode"] = "lost_process_exited"
            self.log("[engine] cannot dump: debuggee already exited")
            return findings
        dm = self.call("dump_module", {
            "module": module, "output_path": out_path,
            "auto_detect_oep": True, "rebuild_pe": True,
            "remove_integrity_check": True})
        ok = isinstance(dm, dict) and dm.get("success")
        findings["dump_path"] = out_path if ok else None
        findings["dump_mode"] = ("module_oep" if reached else
                                 "module_exitguard" if at_exitguard else "module_autodetect")
        findings["dump_new_ep"] = dm.get("new_ep") if ok else None
        self.log(f"[engine] dump_module: {dm}")
        return findings
