"""Detonation worker — full behavioral run + memory dump, over SSH, detached.

Runs the canonical sequence inside the guest as a scheduled task (survives
FakeNet tearing down SSH):
  snapshot 1 -> Procmon -> FakeNet (live log) -> COPY sample to .exe + RUN it ->
  MiniDump its process memory (comsvcs.dll LOLBIN) -> wait -> stop Procmon ->
  snapshot 2 (diff) -> stop FakeNet -> DONE.
Then we reconnect, pull artifacts (incl. the memory .dmp), filter tooling/OS
noise, and parse behavior + network IOCs. The memory dump is re-analyzed
statically (memstatic.py) to reveal decrypted strings/URLs/config.

ONLY run against an isolated instance you can revert. benign=True uses a harmless
stand-in to validate the flow.
"""
from __future__ import annotations

import base64
import time
from pathlib import Path

PROCMON = r"C:\Users\Administrator\Desktop\Procmon64.exe"
TSHARK = r"C:\Wireshark36\tshark.exe"
FAKENET_DIR = r"C:\Users\Public\Desktop\fakenet3.5"
WORK = r"C:\nemesis\run"

PERSIST_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
]
FS_WATCH = r'C:\Users\Public C:\ProgramData "%TEMP%" C:\Windows\Temp C:\Users\Administrator\AppData\Roaming'

# Tooling + OS background noise to drop from reported IOCs.
NOISE_NET = ("microsoft.com", "windowsupdate.com", "windows.com", "lencr.org",
             "digicert.com", "msftconnecttest", "msftncsi", "bing.com",
             "in-addr.arpa", "ip6.arpa", "wpad", "teredo", "office.com",
             "live.com", "verisign", "entrust", "akamai", "root-servers")
NOISE_FILE = ("_mei", r"\nemesis\run", "fakenet3.5", "packets_", "http_",
              ".pml", ".dmp", "procmon")


def _benign_script() -> str:
    return (
        "@echo off\r\n"
        'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" '
        "/v NemesisDryrun /d C:\\dummy.exe /f\r\n"
        "echo dryrun > C:\\Windows\\Temp\\nemesis_dryrun.txt\r\n"
        "nslookup example.com\r\n"
        "ping -n 3 example.com\r\n"
    )


def _snap(keys, n):
    return "\r\n".join(
        f'reg export "{k}" "{WORK}\\reg{i}_{n}.reg" /y >nul 2>&1'
        for i, k in enumerate(keys))


def _batch(mode: str, sample_path: str, duration: int) -> str:
    pid_from_log = (f"powershell -NoProfile -Command \"(Select-String -Path "
                    f"'{WORK}\\psexec.log' -Pattern 'process ID (\\d+)')"
                    f".Matches.Groups[1].Value\"")
    if mode == "real":
        detonate_block = (
            f'copy "{sample_path}" "{WORK}\\malware.exe" >nul 2>&1\r\n'
            "rem launch INTO the interactive desktop (session 1) so GUI malware runs\r\n"
            f'C:\\Tools\\PsExec64.exe -accepteula -i 1 -d "{WORK}\\malware.exe" > "{WORK}\\psexec.log" 2>&1\r\n'
            "timeout /t 3 /nobreak >nul\r\n"
            "rem --- PID straight from PsExec; dump + carve ASAP (before it exits) ---\r\n"
            f'set "MPID="\r\n'
            f"for /f %%p in ('{pid_from_log}') do set MPID=%%p\r\n"
            f'if defined MPID rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump %MPID% "{WORK}\\malware.dmp" full\r\n'
            f'if defined MPID C:\\Tools\\pe-sieve64.exe /pid %MPID% /dir "{WORK}\\pesieve1" /quiet /dmode 2 /data 3 >nul 2>&1\r\n'
            "timeout /t 16 /nobreak >nul\r\n"
            "rem --- pass 2: later unpack stage (if still alive) ---\r\n"
            f'if defined MPID C:\\Tools\\pe-sieve64.exe /pid %MPID% /dir "{WORK}\\pesieve2" /quiet /dmode 2 /data 3 >nul 2>&1\r\n'
        )
        rest = max(duration - 22, 8)
    else:
        detonate_block = (
            f'call "{WORK}\\sample.bat"\r\n'
            "timeout /t 12 /nobreak >nul\r\n"
        )
        rest = max(duration - 12, 10)
    return (
        "@echo off\r\n"
        f'if not exist "{WORK}" mkdir "{WORK}"\r\n'
        f"{_snap(PERSIST_KEYS, 1)}\r\n"
        f'dir /s /b {FS_WATCH} > "{WORK}\\files_1.txt" 2>nul\r\n'
        f'start "" /b "{PROCMON}" /AcceptEula /Quiet /Minimized /BackingFile "{WORK}\\pm.pml"\r\n'
        "timeout /t 5 /nobreak >nul\r\n"
        f'del /q "{FAKENET_DIR}\\packets_*.pcap" 2>nul\r\n'
        f"powershell -NoProfile -Command \"Start-Process -FilePath '{FAKENET_DIR}\\fakenet.exe' "
        f"-WorkingDirectory '{FAKENET_DIR}' -RedirectStandardOutput '{WORK}\\fakenet_console.txt' "
        f"-RedirectStandardError '{WORK}\\fakenet_err.txt' -WindowStyle Hidden\"\r\n"
        "timeout /t 12 /nobreak >nul\r\n"
        "rem --- DETONATE ---\r\n"
        f"{detonate_block}"
        f"timeout /t {rest} /nobreak >nul\r\n"
        f'"{PROCMON}" /Terminate >nul 2>&1\r\n'
        'taskkill /f /im malware.exe >nul 2>&1\r\n'
        "taskkill /im fakenet.exe >nul 2>&1\r\n"
        "timeout /t 10 /nobreak >nul\r\n"
        "taskkill /f /im fakenet.exe >nul 2>&1\r\n"
        "timeout /t 2 /nobreak >nul\r\n"
        f'"{PROCMON}" /OpenLog "{WORK}\\pm.pml" /SaveAs "{WORK}\\pm.csv" >nul 2>&1\r\n'
        f"{_snap(PERSIST_KEYS, 2)}\r\n"
        f'dir /s /b {FS_WATCH} > "{WORK}\\files_2.txt" 2>nul\r\n'
        f'copy "{FAKENET_DIR}\\packets_*.pcap" "{WORK}\\" >nul 2>&1\r\n'
        f'echo DONE > "{WORK}\\DONE.marker"\r\n'
    )


def run(guest, sample_path, rl=None, cl=None, duration=90, benign=False, artifacts_dir=None):
    def log(ev, detail=""):
        if rl: rl.log("detonate", ev, detail)
        print(f"   [detonate] {ev} {detail}".rstrip())

    guest.run(f'cmd /c "rmdir /s /q {WORK} 2>nul & mkdir {WORK}"', timeout=60)
    mode = "benign" if benign else "real"
    if benign:
        for line in _benign_script().splitlines():
            guest.run(f'cmd /c ">>{WORK}\\sample.bat echo {line}"', timeout=20)
        log("mode", "BENIGN dry-run")
    else:
        log("mode", f"REAL: run as malware.exe + memory dump: {sample_path}")

    b64 = base64.b64encode(_batch(mode, sample_path, duration).encode()).decode()
    guest.run(f'powershell -NoProfile -Command "[IO.File]::WriteAllBytes(\'{WORK}\\detonate.bat\',[Convert]::FromBase64String(\'{b64}\'))"', timeout=60)
    if cl:
        for p in ("fakenet_start", "regshot_1", "procmon_start"):
            cl.done(p, "scripted")

    guest.run(f'cmd /c "schtasks /create /tn nemdet /tr \\"{WORK}\\detonate.bat\\" /sc once /st 00:00 /ru SYSTEM /f"', timeout=60)
    guest.run('cmd /c "schtasks /run /tn nemdet"', timeout=60)
    started = time.strftime("%Y-%m-%dT%H:%M:%S")
    log("launched", f"detached; waiting up to ~{duration+120}s (SSH drops while FakeNet is up)")

    deadline = time.time() + duration + 240
    done = False
    while time.time() < deadline:
        rc, out, _ = guest.run(f'cmd /c "if exist {WORK}\\DONE.marker echo DONE"', timeout=20)
        if "DONE" in out:
            done = True; break
        time.sleep(10)
    if cl:
        for p in ("detonate", "observe", "procmon_stop", "regshot_2_diff", "fakenet_stop"):
            cl.done(p)
    log("complete" if done else "timeout")
    guest.run('cmd /c "schtasks /delete /tn nemdet /f"', timeout=30)

    # per-analysis artifacts folder (kept with the case); falls back to a shared dir
    local_dir = Path(artifacts_dir) if artifacts_dir else (Path("cases") / "_detonation_artifacts")
    import shutil as _sh
    _sh.rmtree(local_dir, ignore_errors=True)
    local_dir.mkdir(parents=True, exist_ok=True)
    guest.pull(WORK, str(local_dir), timeout=1200)
    run_dir = local_dir / "run"
    log("artifacts pulled", str(run_dir))

    result = _parse(run_dir, started, duration, done)
    result["benign"] = benign

    from nanalyst import memstatic
    # full-process memory dump re-static
    dmp = run_dir / "malware.dmp"
    if dmp.exists() and dmp.stat().st_size > 0:
        log("memory dump", f"{dmp.stat().st_size//1024} KB -> re-static")
        result["memory_dump"] = str(dmp)
        result["memory_static"] = memstatic.analyze(str(dmp))
        if cl: cl.done("memory_dump"); cl.done("re_static")
    else:
        result["memory_dump"] = None
        log("memory dump", "none captured (process may have exited/injected)")

    # PE-sieve carved PEs (requirement #1: every PE in memory, main + injected)
    carved = []
    for f in run_dir.glob("pesieve*/**/*"):
        if not f.is_file() or f.suffix.lower() in (".json", ".txt", ".tag", ".imports"):
            continue
        try:
            with open(f, "rb") as fh:
                if fh.read(2) != b"MZ":
                    continue
        except Exception:
            continue
        ms = memstatic.analyze(str(f))
        carved.append({
            "name": f.name, "size": f.stat().st_size,
            "urls": ms["urls"][:20], "ips": ms["ips"][:20],
            "registry": ms["registry"][:15],
            "suspicious_keywords": ms["suspicious_keywords"],
        })
    result["carved_pes"] = carved
    if carved:
        log("carved PEs", f"{len(carved)} PE(s) carved from memory")

    if cl:
        cl.done("pcap_analysis"); cl.done("behavior_parse")
    log("parsed", f"net={len(result['network'])} reg={len(result['registry_changes'])} "
                   f"files={len(result['files_dropped'])} mem_urls={len(result.get('memory_static',{}).get('urls',[]))}")
    return result


def _parse(run_dir, started, duration, done):
    net, reg_changes, files_dropped = [], [], []

    def read(name):
        p = run_dir / name
        if not p.exists():
            return ""
        if name.endswith(".reg"):
            try:
                return p.read_text(encoding="utf-16", errors="replace")
            except Exception:
                return p.read_text(errors="replace")
        return p.read_text(errors="replace")

    fnlog = read("fakenet_console.txt")
    seen = set()
    for line in fnlog.splitlines():
        low = line.lower()
        if not any(k in low for k in ("request for", "received a", " get ", " post ",
                                      "dns query", "connected", "http", "ssl", "resolved")):
            continue
        if any(n in low for n in NOISE_NET):
            continue
        s = line.strip()[:160]
        if s and s not in seen:
            seen.add(s); net.append(s)

    _NOISE = ("windivert", "fakenet", "nemesisdryrun")
    for i in range(len(PERSIST_KEYS)):
        a = set(read(f"reg{i}_1.reg").splitlines())
        for line in read(f"reg{i}_2.reg").splitlines():
            s = line.strip()
            if not s or line in a or "=" not in s or s.startswith("[") or "Windows Registry" in s:
                continue
            if any(n in s.lower() for n in _NOISE):
                continue
            reg_changes.append(f"{PERSIST_KEYS[i].split(chr(92))[-1]}: {s[:120]}")

    f1 = set(read("files_1.txt").splitlines())
    for line in read("files_2.txt").splitlines():
        if not line or line in f1:
            continue
        if any(n in line.lower() for n in NOISE_FILE):
            continue
        files_dropped.append(line.strip())

    return {
        "started": started, "duration_s": duration, "completed": done,
        "artifacts_dir": str(run_dir),
        "network": net[:60], "registry_changes": reg_changes[:50],
        "files_dropped": files_dropped[:50], "processes": [],
    }
