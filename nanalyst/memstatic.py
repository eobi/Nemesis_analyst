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
