"""Kill the sample's process tree and check what it left behind, so a VM revert is only
needed when there is actual residue.

  snapshot(guest)                 read-only inventory of the guest (processes, Run keys,
                                  scheduled tasks, services, files in user/temp/startup dirs)
  kill_tree(guest, names, base)   kill the sample by image name + all descendants + any NEW
                                  process running from a user-writable path (renamed copies)
  diff(before, after)             what changed, with a verdict
  finish(guest, names, base)      kill_tree -> snapshot -> diff

Limits (the verdict says so): this only inspects the locations above. It cannot see injected
code in surviving processes, WMI subscriptions, kernel-level changes, or changes elsewhere on
disk/registry. "No residue detected" is a heuristic, not proof — revert for ransomware or
anything you do not fully understand.
"""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

GUEST_PS = r"C:\nemesis\_residue.ps1"

PS_SCRIPT = r'''
param([string]$Mode = "snapshot", [string]$Names = "", [string]$BasePids = "")
$ErrorActionPreference = "SilentlyContinue"
function Get-Procs {
  Get-CimInstance Win32_Process | ForEach-Object {
    [pscustomobject]@{ pid = [int]$_.ProcessId; ppid = [int]$_.ParentProcessId; name = $_.Name; path = $_.ExecutablePath }
  }
}
if ($Mode -eq "snapshot") {
  $runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
  $run = @()
  foreach ($k in $runKeys) {
    $p = Get-ItemProperty -Path $k
    if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object { $run += ("{0}|{1}={2}" -f $k, $_.Name, $_.Value) } }
  }
  $tasks = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | ForEach-Object { $_.TaskPath + $_.TaskName })
  $svcs = @(Get-CimInstance Win32_Service | ForEach-Object { "{0}|{1}" -f $_.Name, $_.PathName })
  $dirs = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, "C:\ProgramData", "C:\Users\Public", "C:\Windows\Temp",
            "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
  foreach ($u in (Get-ChildItem "C:\Users" -Directory)) {
    foreach ($s in @("Desktop", "Documents", "Downloads", "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")) { $dirs += (Join-Path $u.FullName $s) }
  }
  $files = @()
  foreach ($d in ($dirs | Select-Object -Unique)) {
    if (Test-Path $d) {
      $files += Get-ChildItem -Path $d -Recurse -Force -File -Depth 3 | Select-Object -First 3000 | ForEach-Object { "{0}|{1}" -f $_.FullName, $_.Length }
    }
  }
  [pscustomobject]@{ procs = @(Get-Procs); run = $run; tasks = $tasks; services = $svcs; files = $files } | ConvertTo-Json -Depth 4 -Compress
}
else {
  $names = @($Names -split "," | Where-Object { $_ })
  $base = @($BasePids -split "," | Where-Object { $_ } | ForEach-Object { [int]$_ })
  $killed = @()
  for ($i = 0; $i -lt 6; $i++) {
    $dead = @($killed | ForEach-Object { $_.pid })
    $targets = @()
    foreach ($p in @(Get-Procs)) {
      if ($p.pid -eq $PID -or ($base -contains $p.pid) -or ($dead -contains $p.pid)) { continue }
      $path = [string]$p.path
      $byName = $names -contains $p.name
      $child = $dead -contains $p.ppid
      # ONLY things that are provably the sample's: its exact staged name, its descendants, or anything running
      # from our own staging folder (a renamed copy it dropped there). NEVER other programs — a tool the operator
      # opened by hand during a run must not be killed. Unknown new processes are REPORTED by the diff, not killed.
      $ours = $path -and ($path -match "^C:\\nemesis\\")
      if ($byName -or $child -or $ours) { $targets += $p }
    }
    if (-not $targets) { break }
    foreach ($t in $targets) { Stop-Process -Id $t.pid -Force; $killed += $t }
  }
  $left = @(Get-Procs | Where-Object { ($base -notcontains $_.pid) -and ($names -contains $_.name) })
  [pscustomobject]@{
    killed = @($killed | ForEach-Object { "{0}:{1}:{2}" -f $_.pid, $_.name, $_.path })
    remaining = @($left | ForEach-Object { "{0}:{1}" -f $_.pid, $_.name })
  } | ConvertTo-Json -Depth 3 -Compress
}
'''

# paths that change on their own on a healthy Windows box — ignored in the file diff
NOISE = re.compile(
    r"(?i)(\\Microsoft\\(Windows|Edge|Office|Network|Crypto|Vault)|\\Packages\\|\\Google\\|\\Mozilla\\|"
    r"\\Prefetch|\\x64dbg|\\nemesis\\|ntuser\.|\.etl$|\.log$|\.tmp$|\\Temp\\(__PS|chocolatey)|"
    r"\\Programs\\Startup\\desktop\.ini$)")
STARTUP = re.compile(r"(?i)\\Start Menu\\Programs\\Startup\\")


def is_noise(p: str) -> bool:
    """Startup-folder entries are never noise (only their desktop.ini is) — that is exactly
    where persistence lands, even though the path sits under \\Microsoft\\Windows\\."""
    if STARTUP.search(p):
        return p.lower().endswith("desktop.ini")
    return bool(NOISE.search(p))


MASS = 20       # this many modified/removed files, or one new extension on this many files


# Windows service/helper hosts that start on demand and are not residue by themselves
BENIGN_OS = {"dllhost.exe", "svchost.exe", "conhost.exe", "taskhostw.exe", "wmiprvse.exe",
             "backgroundtaskhost.exe", "runtimebroker.exe", "searchprotocolhost.exe",
             "searchfilterhost.exe", "audiodg.exe", "sppsvc.exe", "mpcmdrun.exe", "smartscreen.exe",
             "applicationframehost.exe", "ctfmon.exe", "fontdrvhost.exe", "msiexec.exe", "trustedinstaller.exe"}
PROTECTED_OK = {"nissrv.exe", "msmpeng.exe", "mpdefendercoreservice.exe", "sgrmbroker.exe",
                "svchost.exe"}  # path unreadable = protected process (an impostor svchost from a user folder has a readable path and stays suspicious)
SYS_DIR = re.compile(r"(?i)^C:\\Windows\\(System32|SysWOW64)\\")


def classify_new_processes(before: dict, after: dict, exclude_pids=()):
    """Split processes that appeared after the baseline into (suspicious, benign_info).
    Benign = our own SSH session chain (any ancestor is sshd.exe) or a known on-demand Windows
    service host running from System32/SysWOW64 (or a Defender process whose path is protected).
    Everything else — including cmd/powershell not under our session — stays suspicious."""
    base = {p["pid"] for p in before["procs"]} | set(exclude_pids)   # exclude = pids we killed ourselves
    by_pid = {p["pid"]: p for p in after["procs"]}

    def under_ssh(p):
        seen, cur = set(), p
        while cur and cur["pid"] not in seen:
            seen.add(cur["pid"])
            if str(cur.get("name", "")).lower() == "sshd.exe":
                return True
            cur = by_pid.get(cur.get("ppid"))
        return False

    sus, ok = [], []
    for p in after["procs"]:
        if p["pid"] in base:
            continue
        label = f'{p["pid"]}:{p["name"]}:{p.get("path")}'
        name, path = str(p["name"]).lower(), str(p.get("path") or "")
        if under_ssh(p) or (name in BENIGN_OS and SYS_DIR.match(path)) or \
                (name in PROTECTED_OK and not path):
            ok.append(label)
        else:
            sus.append(label)
    return sus, ok


def _parse(out: str):
    for ln in reversed((out or "").splitlines()):
        ln = ln.strip()
        if ln.startswith("{"):
            try:
                return json.loads(ln)
            except Exception:
                return None
    return None


def _as_list(v):
    return [] if v is None else ([v] if isinstance(v, (str, dict)) else list(v))


def _run_ps(guest, args: str, timeout: int = 180):
    """Push the helper script (small file, transfers reliably) and run it."""
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False) as f:
        f.write(PS_SCRIPT); local = f.name
    try:
        guest.run('cmd /c "if not exist C:\\nemesis mkdir C:\\nemesis"', timeout=30)
        if not guest.push(local, GUEST_PS):
            return None
        _, out, _ = guest.run(f'powershell -NoProfile -ExecutionPolicy Bypass -File {GUEST_PS} {args}',
                              timeout=timeout)
        return _parse(out)
    finally:
        Path(local).unlink(missing_ok=True)


def snapshot(guest):
    """Read-only inventory. Returns a dict, or None if the guest could not be read."""
    d = _run_ps(guest, "-Mode snapshot")
    if not d:
        return None
    d["procs"] = _as_list(d.get("procs"))
    for k in ("run", "tasks", "services", "files"):
        d[k] = _as_list(d.get(k))
    return d


def kill_tree(guest, names, base=None):
    """Kill by image name + descendants + new processes running from user-writable paths."""
    base_pids = ",".join(str(p["pid"]) for p in (base or {}).get("procs", []))
    d = _run_ps(guest, f'-Mode kill -Names "{",".join(names)}" -BasePids "{base_pids}"', timeout=120)
    if d is None:
        return {"killed": [], "remaining": [], "ok": False}
    return {"killed": _as_list(d.get("killed")), "remaining": _as_list(d.get("remaining")), "ok": True}


def _files(snap):
    out = {}
    for ln in snap.get("files", []):
        p, _, sz = ln.rpartition("|")
        out[p] = sz
    return out


def diff(before: dict, after: dict, exclude_pids=()) -> dict:
    """What the run left behind, with a verdict. Both args come from snapshot()."""
    new_procs, benign_procs = classify_new_processes(before, after, exclude_pids)
    new_run = sorted(set(after["run"]) - set(before["run"]))
    new_tasks = sorted(set(after["tasks"]) - set(before["tasks"]))
    new_svcs = sorted(set(after["services"]) - set(before["services"]))

    bf, af = _files(before), _files(after)
    new_all = [p for p in af if p not in bf]
    new_files = [p for p in new_all if not is_noise(p)]
    removed = [p for p in bf if p not in af and not is_noise(p)]
    modified = [p for p in af if p in bf and af[p] != bf[p] and not is_noise(p)]
    ext_new = {}
    for p in new_files:
        e = Path(p).suffix.lower()
        ext_new[e] = ext_new.get(e, 0) + 1
    mass_ext = [e for e, n in ext_new.items() if e and n >= MASS]
    mass = len(removed) >= MASS or len(modified) >= MASS or bool(mass_ext)
    startup = [p for p in new_files if STARTUP.search(p)]

    persistence = bool(new_run or new_tasks or new_svcs or startup)
    findings = []
    if new_procs:    findings.append(f"{len(new_procs)} new process(es) still running")
    if new_run:      findings.append(f"{len(new_run)} new Run/RunOnce value(s)")
    if new_tasks:    findings.append(f"{len(new_tasks)} new scheduled task(s)")
    if new_svcs:     findings.append(f"{len(new_svcs)} new service(s)")
    if startup:      findings.append(f"{len(startup)} new startup-folder file(s)")
    if mass:         findings.append(f"mass file change (removed {len(removed)}, modified {len(modified)}"
                                     + (f", new extension(s) {mass_ext}" if mass_ext else "") + ")")
    elif new_files:  findings.append(f"{len(new_files)} new file(s) in user/temp dirs")
    reusable = not (new_procs or persistence or mass or new_files)
    verdict = ("NO RESIDUE DETECTED in the checked locations — VM may be reused "
               "(heuristic, not proof; revert for ransomware/unknown samples)" if reusable
               else "RESIDUE FOUND — revert the VM: " + "; ".join(findings))
    return {"reusable": reusable, "persistence": persistence, "mass_file_change": mass,
            "new_processes": new_procs, "new_processes_benign": benign_procs, "new_run_values": new_run, "new_tasks": new_tasks,
            "new_services": new_svcs, "new_files": new_files[:50], "new_file_count": len(new_files),
            "removed_count": len(removed), "modified_count": len(modified),
            "ignored_noise_files": len(new_all) - len(new_files), "verdict": verdict}


def finish(guest, names, base, log=print):
    """Kill the tree, re-inventory, diff against `base`. Returns a result dict (never raises)."""
    try:
        k = kill_tree(guest, names, base)
        log(f"[residue] killed {len(k['killed'])} process(es)"
            + (f"; STILL RUNNING: {k['remaining']}" if k["remaining"] else ""))
        after = snapshot(guest)
        if base is None or after is None:
            return {"killed": k, "reusable": False,
                    "verdict": "could not inventory the guest — revert the VM to be safe"}
        # pids we killed: if one still shows up, it is a ghost entry (the debugger often keeps a handle on
        # the dead debuggee). A survivor would also have been caught by kill_tree's `remaining` check.
        killed_pids = {int(x.split(":")[0]) for x in k["killed"] if x.split(":")[0].isdigit()}
        d = diff(base, after, exclude_pids=killed_pids)
        d["killed"] = k
        if k["remaining"]:
            d["reusable"] = False
            d["verdict"] = f"sample process(es) survived the kill {k['remaining']} — revert the VM"
        log(f"[residue] {d['verdict']}")
        return d
    except Exception as exc:
        log(f"[residue] check failed ({exc}) — revert the VM to be safe")
        return {"reusable": False, "verdict": f"residue check failed: {exc} — revert the VM"}
