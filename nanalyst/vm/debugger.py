"""Bitness-aware debugger control.

x32dbg (for PE32) and x64dbg (for PE32+) each carry the MCP plugin, but only ONE
can bind the plugin's MCP port at a time. So analysing a 64-bit sample while
x32dbg owns the port means switching debuggers:

    kill the wrong-bitness debugger  ->  launch the right one ON THE INTERACTIVE
    DESKTOP  ->  wait for its MCP server to rebind the port.

A GUI app spawned from an SSH session lands in session 0 (no desktop) and fails
to create its window, so we launch via PsExec -i 1 into the logged-in console
session. This needs the VM console to be logged in (it is, whenever x32dbg is up).

Nothing here runs unless the needed bitness differs from what's already live, so
an x86 sample with x32dbg already running is a no-op.
"""
from __future__ import annotations

import time
import urllib.request

DBG_EXE = {"x86": r"C:\x64dbg_new\release\x32\x32dbg.exe",
           "x64": r"C:\x64dbg_new\release\x64\x64dbg.exe"}
IMG = {"x86": "x32dbg.exe", "x64": "x64dbg.exe"}
PSEXEC = r"C:\Tools\PsExec64.exe"


def running(guest) -> str | None:
    """'x86' / 'x64' / None — which debugger process is live on the guest."""
    _, out, _ = guest.run(
        'cmd /c "tasklist /FO CSV /NH /FI \"IMAGENAME eq x32dbg.exe\" & '
        'tasklist /FO CSV /NH /FI \"IMAGENAME eq x64dbg.exe\""', timeout=30)
    o = (out or "").lower()
    live = []
    if "x64dbg.exe" in o:
        live.append("x64")
    if "x32dbg.exe" in o:
        live.append("x86")
    # if somehow both are up, report x64 first so the caller knows to clean up
    return live[0] if live else None


def _mcp_responds(mcp_url: str, timeout: int = 4) -> bool:
    """MCP is up if the endpoint answers an HTTP request at all (the plugin may
    return 400/406 to a bare GET, which still proves it rebound the port)."""
    try:
        with urllib.request.urlopen(urllib.request.Request(mcp_url), timeout=timeout):
            return True
    except urllib.error.HTTPError:
        return True          # answered with an HTTP status => server is up
    except Exception:
        return False


def kill(guest, bits: str | None = None, log=print):
    """Kill one debugger (by bitness) or both (bits=None)."""
    imgs = [IMG[bits]] if bits else ["x32dbg.exe", "x64dbg.exe"]
    for im in imgs:
        guest.run(f'cmd /c "taskkill /f /im {im} 2>nul & echo ok"', timeout=30)
    log(f"[debugger] killed {', '.join(imgs)}")


def launch(guest, bits: str, log=print) -> bool:
    """Launch the given-bitness debugger on the interactive desktop (session 1)."""
    exe = DBG_EXE[bits]
    cmd = (f'cmd /c "\"{PSEXEC}\" -accepteula -nobanner -i 1 -d \"{exe}\""')
    rc, out, err = guest.run(cmd, timeout=60)
    ok = rc == 0 or "started" in ((out or "") + (err or "")).lower()
    log(f"[debugger] launch {IMG[bits]} via PsExec -i 1 -> rc={rc}")
    return ok


def ensure(guest, bits: str, mcp_url: str, log=print, wait: int = 90) -> bool:
    """Make the `bits` debugger the live one and confirm its MCP is reachable.

    No-op fast path: if the right debugger is already running AND its MCP answers,
    return immediately (the common x86 case). Otherwise switch debuggers.
    Returns True once MCP responds for the requested bitness.
    """
    up = _mcp_responds(mcp_url)
    cur = running(guest)      # best-effort; tasklist over SSH can be unreliable -> may be None

    # SAFE FAST PATH: if the MCP is already responding, a debugger is live and serving. Do NOT
    # disrupt it unless we can CONFIRM a bitness mismatch. `running()` returning None (common
    # SSH flakiness) is NOT a mismatch — trust the live MCP and proceed.
    if up and (cur is None or cur == bits):
        log(f"[debugger] MCP live" + (f" ({IMG[cur]})" if cur else "") + " — using it, no relaunch")
        return True

    # CONFIRMED mismatch: the wrong-bitness debugger owns the port — switch.
    if up and cur and cur != bits:
        log(f"[debugger] CONFIRMED bitness mismatch: {IMG[cur]} live but need {IMG[bits]} — switching")
        kill(guest, cur, log)
        time.sleep(3)
    elif not up:
        # nothing is answering on the MCP port — bring up the needed debugger
        log(f"[debugger] MCP not responding — launching {IMG[bits]}")
        if cur:                       # a stale process may hold the port; clear it first
            kill(guest, cur, log); time.sleep(2)

    if not launch(guest, bits, log):
        log("[debugger] launch command failed"); return False

    deadline = time.time() + wait
    while time.time() < deadline:
        if _mcp_responds(mcp_url):
            log(f"[debugger] {IMG[bits]} MCP is up"); return True
        time.sleep(3)
    log(f"[debugger] MCP did not come up within {wait}s"); return False
