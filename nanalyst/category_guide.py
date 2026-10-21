"""Malware category guide: what kind of malware is it, what should be tracked for that kind, and
for each tracked item whether it was OBSERVED live, only PRESENT in the code, ABSENT, or not instrumented.

Six categories (the analyst guide): dropper/downloader, keylogger/info-stealer, spam bot, banker, worm,
ransomware. Each carries a "what to track" checklist and "how to investigate" steps. The checklist is the
point: an analyst can see at a glance what was proven by the run and what is only a lead.

Status vocabulary (never blurred):
  observed live       the sample was seen calling it (or producing the artifact) during the debugger run
  present in code     imported / referenced in the code or strings, but not seen executing
  absent              no static or dynamic trace (an arsenal API that was armed and never fired is "not observed")
  not instrumented    we did not hook it, so absence says nothing
Counts from live breakpoints are lower bounds (">= N"): the plugin cannot count without stopping.
"""
from __future__ import annotations

from .classify import _haystacks, classify
from .api_spec import API_SPEC, BEHAVIOR_CAP

# item: (label, kind, needles, why it matters)   kind: "api" | "kw"
GUIDE = {
    "dropper / downloader": {
        "maps_from": ["dropper"],
        "track": [
            ("download a file from the network", "api", ["URLDownloadToFile", "InternetOpenUrl", "InternetReadFile", "InetGet", "HttpSendRequest"], "where the next stage comes from (URL = IOC)"),
            ("write a file to disk", "api", ["WriteFile", "CreateFile", "FileInstall", "CopyFile"], "what it drops and where (path + hash = IOC)"),
            ("execute the dropped file", "api", ["CreateProcess", "WinExec", "ShellExecute"], "what it runs, with what command line"),
            ("stage in a temp/user folder", "kw", ["\\temp\\", "appdata", "@tempdir", "\\users\\"], "typical drop location"),
            ("inject into another process", "api", ["WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "NtQueueApcThread"], "payload delivered via injection instead of a file"),
            ("persist", "kw", ["currentversion\\run", "schtasks", "startup"], "how the dropper survives reboot"),
        ],
        "investigate": ["Record every URL it contacts and the filename it saves (network IOC + file IOC).",
                        "Hash each dropped file and analyse it as the next stage.",
                        "Note the exact command line used to launch the payload (CreateProcess/WinExec capture)."],
    },
    "keylogger / info-stealer": {
        "maps_from": ["keylogger", "infostealer"],
        "track": [
            ("install a keyboard/input hook", "api", ["SetWindowsHookEx", "RegisterRawInputDevices"], "keystroke capture mechanism"),
            ("poll key state", "api", ["GetAsyncKeyState", "GetKeyState"], "polling keylogger"),
            ("track the active window", "api", ["GetForegroundWindow", "GetWindowText"], "tags keystrokes with the application"),
            ("steal clipboard", "api", ["GetClipboardData", "OpenClipboard"], "crypto-address / password theft"),
            ("decrypt stored secrets", "api", ["CryptUnprotectData"], "browser/credential-store theft (DPAPI)"),
            ("read browser/credential stores", "kw", ["login data", "cookies", "passwords", "wallet", "\\google\\chrome", "mozilla\\firefox"], "what it harvests"),
            ("screenshot / screen capture", "api", ["BitBlt", "GetDC", "CreateCompatibleBitmap"], "visual capture"),
            ("send data out", "api", ["send", "connect", "HttpSendRequest", "InternetConnect", "WinHttpConnect"], "exfiltration channel (host/URL = IOC)"),
        ],
        "investigate": ["Find where captured data is stored locally (log file path) and how it is sent (HTTP, SMTP, FTP, Telegram).",
                        "Identify which applications/windows trigger capture.",
                        "Extract the exfiltration endpoint and any credentials embedded for it."],
    },
    "spam bot": {
        "maps_from": ["bot"],
        "track": [
            ("connect out (C2 / mail servers)", "api", ["connect", "InternetConnect", "WinHttpConnect", "getaddrinfo", "gethostbyname"], "C2 and relay hosts"),
            ("send network data", "api", ["send", "HttpSendRequest"], "tasking and spam transmission"),
            ("SMTP traffic / mail templates", "kw", ["smtp", "mail from", "rcpt to", "data\\r\\n", "subject:", "mx"], "spam capability"),
            ("C2 tasking pattern", "kw", ["gate.php", "/gate", "botid", "cmd=", "heartbeat", "panel"], "bot protocol markers"),
            ("create a single-instance mutex", "api", ["CreateMutex"], "infection marker"),
        ],
        "investigate": ["Capture the C2 address and protocol; look for a periodic beacon.",
                        "Find the recipient list, message templates and the SMTP relay it uses.",
                        "Check whether it contacts many different mail servers (mass mailing) or one relay."],
    },
    "banker": {
        "maps_from": ["banker"],
        "track": [
            ("hook browser network functions (man-in-the-browser)", "api", ["HttpSendRequest", "PR_Write", "InternetReadFile", "HttpQueryInfo"], "intercepts banking sessions"),
            ("inject into browser processes", "api", ["WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "NtQueueApcThread", "OpenProcess"], "gets code into the browser"),
            ("web-inject / form-grab configuration", "kw", ["webinject", "formgrab", "set_url", "data_before", "data_inject", "data_after"], "bank target configuration (target list = IOC)"),
            ("bank/financial target strings", "kw", ["bank", "paypal", "login", "card", "iban", "swift"], "who it targets"),
            ("certificate store tampering", "api", ["CertOpenSystemStore", "CertAddEncodedCertificateToStore"], "defeats TLS warnings"),
            ("steal credentials/keystrokes", "api", ["SetWindowsHookEx", "GetAsyncKeyState", "GetClipboardData"], "credential capture"),
            ("send stolen data to C2", "api", ["send", "connect", "InternetConnect", "WinHttpConnect"], "drop server (IOC)"),
        ],
        "investigate": ["Recover the web-inject / target list (the banks it attacks).",
                        "Identify which browsers are hooked and how (API hook vs injection).",
                        "Extract the C2/drop server and any configuration decrypted at runtime."],
    },
    "worm": {
        "maps_from": ["worm"],
        "track": [
            ("map/enumerate network shares", "api", ["WNetAddConnection", "NetShareEnum", "WNetOpenEnum"], "network propagation"),
            ("enumerate drives and files", "api", ["GetLogicalDrives", "FindFirstFile", "GetDriveType"], "local/removable propagation"),
            ("copy itself", "api", ["CopyFile", "MoveFileEx"], "replication"),
            ("removable-drive autorun", "kw", ["autorun.inf", "\\\\.\\pipe"], "USB spreading"),
            ("admin shares / lateral movement", "kw", ["admin$", "c$", "ipc$", "psexec"], "SMB spreading"),
            ("scan many hosts", "api", ["connect", "getaddrinfo"], "scanning (many different targets)"),
        ],
        "investigate": ["Determine the propagation vector (shares, USB, e-mail, exploit).",
                        "Record target selection (subnets, drive types) and the copy destination paths.",
                        "Check whether it scans (connect to many hosts) and which ports."],
    },
    "ransomware": {
        "maps_from": ["ransomware"],
        "track": [
            ("encrypt data", "api", ["CryptEncrypt", "BCryptEncrypt"], "the encryption call: captures plaintext and ciphertext"),
            ("generate / derive / import a key", "api", ["CryptGenKey", "CryptDeriveKey", "CryptImportKey", "BCryptGenerateSymmetricKey", "BCryptImportKey"], "key source (hardcoded, derived, or random)"),
            ("walk the file system", "api", ["FindFirstFile", "FindNextFile", "GetLogicalDrives"], "which files are targeted"),
            ("rename/replace files", "api", ["MoveFileEx", "DeleteFile", "CopyFile"], "encrypted-file extension / original removal"),
            ("delete shadow copies / backups", "kw", ["vssadmin", "shadowcopy", "wbadmin", "bcdedit", "delete shadows"], "anti-recovery"),
            ("ransom note", "kw", ["your files", "decrypt", "bitcoin", ".onion", "readme", "how_to"], "note text, wallet and contact (IOC)"),
            ("encrypted-file extension", "kw", [".locked", ".encrypted", ".crypt", ".enc"], "marker for scoping and decryption"),
            ("embedded public key / key wrapping", "kw", ["begin public key", "rsa", "publickey"], "decides whether a decryptor is possible offline"),
        ],
        "investigate": ["Identify the cipher and mode, and where the key comes from (hardcoded, derived, generated then wrapped by RSA).",
                        "Capture a plaintext/ciphertext pair and test the candidate key: a verified key allows a decryptor.",
                        "If the key is wrapped by an attacker RSA public key, offline recovery is not possible; say so.",
                        "Record the file extension, ransom note, and payment/contact details."],
    },
}

_ARSENAL = {sp["sym"].split(".")[-1].lower() for sp in API_SPEC}


def _api_match(needle: str, name: str) -> bool:
    """Exact name or the same name with an A/W/Ex/2 suffix. Never a loose substring ('send' != 'SendMessage')."""
    n, a = needle.lower(), name.lower()
    return a == n or (a.startswith(n) and len(a) - len(n) <= 3)


def _kw_match(needle: str, blob: str) -> bool:
    import re
    n = needle.lower()
    return bool(re.search(r"\b" + re.escape(n) + r"\b", blob)) if len(n) <= 4 else n in blob


def _instrumented(needle: str) -> bool:
    return any(_api_match(needle, a) for a in _ARSENAL)


def _live_calls(case: dict) -> dict:
    """api short name (lower) -> number of live events recorded (lower bound; behaviour sentinels cap at BEHAVIOR_CAP)."""
    out = {}
    for ev in ((case.get("stages", {}) or {}).get("api_trace", {}) or {}).get("trace", []) or []:
        short = str(ev.get("api", "")).split(".")[-1].lower()
        out[short] = max(out.get(short, 0), int(ev.get("n", 1)))
    return out


def _evidence_item(kind, needles, apis_l, blob, live):
    if kind == "api":
        hit_live = [(n, c) for n in needles for a, c in live.items() if _api_match(n, a)]
        if hit_live:
            n, c = max(hit_live, key=lambda x: x[1])
            tag = f">= {c}" if c >= BEHAVIOR_CAP else str(c)
            return "observed live", f"{n} called {tag}x during the run"
        hit_static = [n for n in needles if any(_api_match(n, a) for a in apis_l)]
        if hit_static:
            return "present in code", f"{', '.join(hit_static[:3])} referenced but not seen executing"
        if not any(_instrumented(n) for n in needles):
            return "not instrumented", "none of these APIs are hooked by the arsenal, so absence proves nothing"
        return "absent", "hooked and never fired; no static reference"
    hits = [n for n in needles if _kw_match(n, blob)]
    if hits:
        return "present in code", f"string(s) seen: {', '.join(hits[:4])}"
    return "absent", "no matching string in any stage"


def categorize(case: dict) -> dict:
    apis, blob = _haystacks(case)
    apis_l = {a.lower() for a in apis}
    live = _live_calls(case)
    fam = {f["family"]: f for f in classify(case).get("families", [])}
    cats = []
    for name, g in GUIDE.items():
        score = sum(fam[m]["score"] for m in g["maps_from"] if m in fam)
        items, observed, present = [], 0, 0
        for label, kind, needles, why in g["track"]:
            status, detail = _evidence_item(kind, needles, apis_l, blob, live)
            observed += status == "observed live"
            present += status == "present in code"
            items.append({"item": label, "status": status, "detail": detail, "why": why})
        # confidence from evidence, not from a score threshold alone
        strong = observed >= 2 or (observed >= 1 and present >= 1)
        conf = "high" if (strong and score >= 6) else "medium" if (observed + present >= 2 and score >= 3) else "low" if score >= 3 else "none"
        cats.append({"category": name, "classifier_score": score, "confidence": conf,
                     "observed": observed, "present_only": present, "of": len(items),
                     "checklist": items, "investigate": g["investigate"]})
    cats.sort(key=lambda c: (c["classifier_score"], c["observed"], c["present_only"]), reverse=True)
    shown = [c for c in cats if c["confidence"] != "none"][:3]
    primary = shown[0]["category"] if shown else "no category supported by the evidence"
    return {"primary": primary, "categories": shown,
            "other_families": [f for f in fam if f in ("loader/packer", "injector")],
            "note": ("Counts from live breakpoints are lower bounds. 'present in code' is a lead, not proof of behaviour. "
                     "A loader/packer stage often hides the real category: analyse the unpacked payload for it.")}


def to_markdown(res: dict) -> list:
    if not res or not res.get("categories"):
        return ["## 3d. Malware category", "No category is supported by the evidence from this run. "
                "If the sample is a packer or loader, the category belongs to the unpacked payload.", ""]
    L = ["## 3d. Malware category and what to track", f"**Most likely category: {res['primary']}**", ""]
    if res.get("other_families"):
        L.append(f"Also behaves as: {', '.join(res['other_families'])} (a stage, not necessarily the final purpose).")
        L.append("")
    for c in res["categories"]:
        L += [f"### {c['category']}  (confidence: {c['confidence']}; {c['observed']} observed live, "
              f"{c['present_only']} present in code, of {c['of']} tracked)", "",
              "| Tracked behaviour | Status | Evidence | Why it matters |", "|---|---|---|---|"]
        for it in c["checklist"]:
            L.append(f"| {it['item']} | **{it['status']}** | {it['detail']} | {it['why']} |")
        L += ["", "How to investigate:"] + [f"- {x}" for x in c["investigate"]] + [""]
    L += [f"_{res['note']}_", ""]
    return L
