"""Re-static analysis of a process memory dump.

After detonation unpacks/decrypts the malware in memory, its real strings, URLs,
C2 endpoints, and config are present in the dump even though static analysis of
the on-disk file could not see them. We extract ASCII + UTF-16LE strings from the
.dmp and pull out indicators. Runs on the host (the .dmp is inert data).
"""
from __future__ import annotations

import re

ASCII = re.compile(rb"[\x20-\x7e]{5,}")
UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")

URL = re.compile(r"(?i)\b(?:https?|ftp)://[\w.\-/%?=&:#@~+]+")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
REG = re.compile(r"(?i)(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[\\\w .-]+")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")

# --- richer categories for deep_scan (3-stage: packed / unpacked / decrypted) ---
DOMAIN = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                    r"(?:com|net|org|ru|cn|info|biz|xyz|top|pw|cc|io|co|me|su|onion|tk|ml|ga|cf|gq|site|online|club|shop|app|dev|life|icu)\b")
WINPATH = re.compile(r"(?i)[a-z]:\\(?:[^\s\"<>|:*?\r\n]{1,80}\\?){1,10}")
PDB = re.compile(r"(?i)[a-z]:\\[^\r\n\"]{0,120}\.pdb")
GUID = re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")
UA = re.compile(r"(?i)(?:Mozilla/\d\.\d[^\r\n\"]{0,160}|User-Agent:[^\r\n]{0,160})")
BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
B64 = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
CMD = re.compile(r"(?i)\b(?:cmd(?:\.exe)?\s*/c|powershell(?:\.exe)?[^\r\n]{0,120}|rundll32[^\r\n]{0,120}|"
                 r"regsvr32[^\r\n]{0,120}|schtasks[^\r\n]{0,120}|wscript|cscript|mshta[^\r\n]{0,120}|"
                 r"bitsadmin[^\r\n]{0,120}|certutil[^\r\n]{0,120}|vssadmin[^\r\n]{0,120})")
# object names that carry campaign/config signal
MUTEX_HINT = re.compile(r"(?i)\b(?:Global|Local|Session)\\[\w.{}$-]{3,64}")
SERVICE = re.compile(r"(?i)\b(?:net\s+start|sc\s+create|CreateService|StartService)[^\r\n]{0,120}")

# anti-analysis indicators to flag in strings (names of checks malware uses)
ANTI_KW = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
           "OutputDebugString", "GetTickCount", "QueryPerformanceCounter", "rdtsc",
           "NtGlobalFlag", "BeingDebugged", "VirtualBox", "VBoxGuest", "vmware", "vmtoolsd",
           "SbieDll", "sandboxie", "wine_get_unix_file_name", "cuckoo", "Sleep",
           "GetCursorPos", "GetForegroundWindow", "cpuid", "hypervisor", "qemu", "Xen",
           "SetUnhandledExceptionFilter", "ProcessDebugPort", "FindWindow", "dbghelp"]

SUS_KW = ["cmd.exe", "powershell", "schtasks", "rundll32", "regsvr32", "\\run",
          "appdata", "temp\\", "bot", "gate.php", "/gate", "panel", "c2",
          "ziraat", "bank", "keylog", "clipboard", "screenshot", "webcam",
          "password", "cookie", "wallet", "mutex", ".onion", "token",
          "CreateMutex", "User-Agent", "POST", "base64"]

NOISE_HOST = ("microsoft.com", "windowsupdate", "windows.com", "lencr.org",
              "digicert", "msftconnecttest", "msftncsi", "verisign", "entrust",
              "schemas.", "w3.org", "mozilla.org", "gstatic", "googleapis")


def _extract_strings(data: bytes, cap: int = 400000) -> list[str]:
    out = []
    for m in ASCII.finditer(data):
        out.append(m.group().decode("latin-1", "replace"))
        if len(out) >= cap:
            break
    for m in UTF16.finditer(data):
        try:
            out.append(m.group().decode("utf-16-le", "replace"))
        except Exception:
            pass
        if len(out) >= cap * 2:
            break
    return out


def analyze(dmp_path: str) -> dict:
    with open(dmp_path, "rb") as f:
        data = f.read()
    strings = _extract_strings(data)
    blob = "\n".join(strings)

    def uniq(matches, noise=()):
        seen, res = set(), []
        for m in matches:
            m = m.strip()
            if not m or m in seen:
                continue
            if noise and any(n in m.lower() for n in noise):
                continue
            seen.add(m); res.append(m)
        return res

    urls = uniq(URL.findall(blob), NOISE_HOST)
    ips = uniq(IP.findall(blob))
    ips = [i for i in ips if not i.startswith(("0.", "127.", "255.", "224.")) and i != "0.0.0.0"]
    regs = uniq(REG.findall(blob))
    emails = uniq(EMAIL.findall(blob), NOISE_HOST)
    low_blob = blob.lower()
    sus = [kw for kw in SUS_KW if kw.lower() in low_blob]

    return {
        "dump_size": len(data),
        "string_count": len(strings),
        "urls": urls[:60],
        "ips": ips[:60],
        "registry": regs[:60],
        "emails": emails[:30],
        "suspicious_keywords": sorted(set(sus)),
    }


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    import math
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in Counter(data).values()), 3)


def deep_scan(src, stage: str = "unknown", cap: int = 600000) -> dict:
    """Deep string/IOC extraction + categorization for ANY stage (packed / unpacked /
    decrypted). `src` is a file path (str) or raw bytes. Returns a rich, structured dict
    the report and (later) the AI reasoner consume.

    Categories: urls, ips, domains, emails, registry, file_paths, pdb_paths, guids,
    user_agents, wallets, commands, service_ops, mutex_hints, base64_blobs,
    suspicious_keywords, anti_analysis_indicators. Plus entropy + string stats."""
    data = src if isinstance(src, (bytes, bytearray)) else open(src, "rb").read()
    data = bytes(data)
    strings = _extract_strings(data, cap=cap)
    blob = "\n".join(strings)
    low = blob.lower()

    def uniq(matches, noise=(), limit=80, minlen=0):
        seen, res = set(), []
        for m in matches:
            m = (m or "").strip()
            if not m or len(m) < minlen or m in seen:
                continue
            if noise and any(n in m.lower() for n in noise):
                continue
            seen.add(m); res.append(m)
            if len(res) >= limit:
                break
        return res

    urls = uniq(URL.findall(blob), NOISE_HOST)
    ips = [i for i in uniq(IP.findall(blob))
           if not i.startswith(("0.", "127.", "255.", "224.")) and i != "0.0.0.0"]
    # domains: drop ones already covered by a URL + noise
    url_hosts = " ".join(urls).lower()
    domains = [d for d in uniq(DOMAIN.findall(blob), NOISE_HOST, limit=120)
               if d.lower() not in url_hosts]
    b64 = [b for b in uniq(B64.findall(blob), limit=40, minlen=40)
           if not b.isdigit()]            # drop long digit runs

    anti = sorted({kw for kw in ANTI_KW if kw.lower() in low})
    return {
        "stage": stage,
        "size": len(data),
        "entropy": _shannon(data),
        "string_count": len(strings),
        "urls": urls,
        "ips": ips,
        "domains": domains,
        "emails": uniq(EMAIL.findall(blob), NOISE_HOST, limit=40),
        "registry": uniq(REG.findall(blob), limit=80),
        "file_paths": uniq(WINPATH.findall(blob), limit=80, minlen=6),
        "pdb_paths": uniq(PDB.findall(blob), limit=20),
        "guids": uniq(GUID.findall(blob), limit=40),
        "user_agents": uniq(UA.findall(blob), limit=20),
        "wallets": uniq(BTC.findall(blob) + ETH.findall(blob), limit=20),
        "commands": uniq(CMD.findall(blob), limit=40),
        "service_ops": uniq(SERVICE.findall(blob), limit=20),
        "mutex_hints": uniq(MUTEX_HINT.findall(blob), limit=40),
        "base64_blobs": b64,
        "suspicious_keywords": sorted({kw for kw in SUS_KW if kw.lower() in low}),
        "anti_analysis_indicators": anti,
    }
