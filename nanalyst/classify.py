"""Behavioral classification — dropper / keylogger / bot / banker / worm /
ransomware / infostealer, from the capabilities and indicators the pipeline
already gathered (PE imports, Ghidra xrefs, memory-dump strings, live behavior).

Scoring is additive and evidence-linked: each signal adds to a family's score and
records WHY, so the report can justify the label instead of asserting it. This is
the API+behavior classification the analyst notes asked for.
"""
from __future__ import annotations

# family -> list of (signal_type, needle, weight, human reason)
#   signal_type: "api" (imported/xref'd API), "kw" (string/indicator keyword)
RULES = {
    "ransomware": [
        ("api", "CryptEncrypt", 3, "bulk file encryption API"),
        ("api", "BCryptEncrypt", 3, "CNG encryption API"),
        ("api", "CryptGenKey", 2, "generates an encryption key"),
        ("api", "CryptDeriveKey", 2, "derives a key (often from attacker pubkey)"),
        ("kw", "readme.txt", 1, "ransom-note style filename"),
        ("kw", ".onion", 2, "Tor payment/leak site"),
        ("kw", "bitcoin", 2, "ransom payment reference"),
        ("kw", "decrypt", 2, "decryption/ransom-note language"),
        ("kw", "your files", 3, "ransom-note phrasing"),
        ("kw", "vssadmin", 3, "deletes shadow copies (anti-recovery)"),
        ("kw", "shadowcopy", 3, "deletes volume shadow copies"),
        ("kw", ".locked", 2, "encrypted-file extension"),
        ("kw", ".encrypted", 2, "encrypted-file extension"),
    ],
    "keylogger": [
        ("api", "SetWindowsHookEx", 3, "installs a keyboard/input hook"),
        ("api", "GetAsyncKeyState", 3, "polls keystrokes"),
        ("api", "GetKeyState", 2, "reads key state"),
        ("api", "RegisterRawInputDevices", 2, "raw keyboard capture"),
        ("api", "GetForegroundWindow", 1, "tracks active window per keystroke"),
        ("kw", "keylog", 3, "keylog artifact string"),
        ("kw", "[enter]", 2, "logged-keystroke formatting"),
        ("kw", "clipboard", 1, "clipboard capture"),
        ("api", "GetClipboardData", 2, "steals clipboard contents"),
    ],
    "banker": [
        ("kw", "bank", 2, "banking target string"),
        ("kw", "ziraat", 3, "named bank target"),
        ("kw", "login", 1, "credential-form targeting"),
        ("kw", "webinject", 3, "browser web-inject (banker hallmark)"),
        ("kw", "formgrab", 3, "HTTP form grabbing"),
        ("kw", "paypal", 2, "financial target"),
        ("api", "PR_Write", 2, "NSS hook (Firefox traffic intercept)"),
        ("api", "HttpSendRequest", 1, "intercepts web requests"),
        ("kw", "card", 1, "payment-card targeting"),
    ],
    "infostealer": [
        ("kw", "cookies", 2, "browser cookie theft"),
        ("kw", "passwords", 2, "credential store theft"),
        ("kw", "login data", 3, "Chrome 'Login Data' DB"),
        ("kw", "wallet", 2, "crypto-wallet theft"),
        ("kw", "\\appdata\\", 1, "harvests per-user app data"),
        ("api", "CryptUnprotectData", 3, "decrypts DPAPI secrets (saved creds)"),
        ("kw", "telegram", 1, "session/token theft target"),
        ("kw", "discord", 1, "token theft target"),
        ("kw", ".ldb", 1, "browser LevelDB (tokens)"),
    ],
    "bot": [
        ("kw", "gate.php", 3, "C2 gate endpoint"),
        ("kw", "/gate", 2, "C2 gate endpoint"),
        ("kw", "panel", 1, "C2 panel reference"),
        ("kw", "cmd=", 1, "command-tasking parameter"),
        ("kw", "botid", 3, "bot identifier field"),
        ("kw", "c2", 2, "command-and-control reference"),
        ("api", "InternetOpen", 1, "HTTP beaconing"),
        ("api", "WinHttpOpen", 1, "HTTP beaconing"),
        ("kw", "heartbeat", 2, "beacon/keepalive"),
        ("kw", "user-agent", 1, "custom beacon UA"),
    ],
    "dropper": [
        ("api", "URLDownloadToFile", 3, "downloads a payload"),
        ("api", "InetGet", 3, "downloads a payload (AutoIt InetGet)"),
        ("api", "FileInstall", 3, "drops a bundled file (AutoIt FileInstall)"),
        ("api", "WinExec", 2, "executes a dropped file"),
        ("api", "ShellExecute", 2, "executes a dropped file"),
        ("api", "CreateProcess", 1, "spawns a child payload"),
        ("api", "WriteFile", 1, "writes a payload to disk"),
        ("api", "FileWrite", 1, "writes a payload to disk (script)"),
        ("kw", "\\temp\\", 1, "stages payload in %TEMP%"),
        ("kw", "@tempdir", 1, "stages payload in the temp dir (script)"),
        ("kw", ".vbs", 1, "drops a VBScript helper"),
        ("api", "VirtualAlloc", 1, "allocates memory for a payload (unpack/inject)"),
        ("api", "DllCall", 1, "calls Win32 APIs directly (script shellcode loader)"),
        ("api", "CreateRemoteThread", 2, "injects into another process"),
        ("api", "WriteProcessMemory", 2, "writes into another process"),
    ],
    "worm": [
        ("api", "WNetAddConnection", 3, "maps network shares to spread"),
        ("kw", "\\\\.\\pipe", 1, "named-pipe lateral movement"),
        ("kw", "admin$", 3, "spreads over admin shares"),
        ("kw", "c$", 2, "spreads over default shares"),
        ("api", "NetShareEnum", 2, "enumerates shares to spread"),
        ("kw", "autorun.inf", 3, "removable-drive propagation"),
        ("api", "FindFirstFile", 1, "walks drives to copy itself"),
    ],
}

PERSIST = [("api", "RegSetValueEx", "Run-key persistence"),
           ("kw", "\\run", "Run-key persistence"),
           ("kw", "currentversion\\run", "Run-key persistence"),
           ("api", "CreateService", "service persistence"),
           ("kw", "schtasks", "scheduled-task persistence"),
           ("api", "schtasks", "scheduled-task persistence"),
           ("kw", "startupdir", "Startup-folder persistence"),
           ("kw", "@startup", "Startup-folder persistence"),
           ("kw", ".url", "Startup .url shortcut persistence")]


def _haystacks(case: dict):
    """Gather APIs seen (imports + ghidra xrefs) and a keyword blob (strings +
    memory indicators) from whatever stages ran."""
    st = case.get("stages", {})
    triage = st.get("triage", {})
    unpacked = st.get("triage_unpacked") or st.get("triage_dumped")
    pe = (unpacked or triage).get("pe", {})
    apis = set()
    for cat in (pe.get("suspicious_apis", {}) or {}).values():
        apis.update(cat)
    gh = st.get("static_ghidra", {})
    apis.update(gh.get("suspicious_apis", []) or [])

    kw = []
    s = gh.get("strings", {}) or {}
    for k in ("urls", "ips", "registry", "suspicious"):
        kw += s.get(k, []) or []
    det = st.get("detonation", {}) or {}
    # memory re-static from either the detonation dump or the debugger unpack dump
    for memstage in (det.get("memory_static", {}), st.get("memory_static_unpack", {})):
        for k in ("urls", "ips", "registry", "suspicious_keywords", "emails"):
            kw += (memstage or {}).get(k, []) or []
    mem = det.get("memory_static", {}) or {}

    # recovered framework source (AutoIt/.au3, PyInstaller/.py, ...) — the real logic
    fw = st.get("framework_extract", {}) or {}
    if fw.get("status") == "extracted":
        kw += (fw.get("urls") or []) + (fw.get("commands") or []) + \
              (fw.get("decoded_hex_strings") or [])
        # script commands map to the same behavioural signals as native APIs
        apis.update(fw.get("commands") or [])
    kw += det.get("network", []) or []
    kw += det.get("registry_changes", []) or []
    kw += det.get("files_dropped", []) or []
    for c in det.get("carved_pes", []) or []:
        kw += c.get("urls", []) + c.get("suspicious_keywords", [])
    blob = "\n".join(str(x) for x in kw).lower()
    return apis, blob


def classify(case: dict) -> dict:
    apis, blob = _haystacks(case)
    apis_l = {a.lower() for a in apis}

    scores, reasons = {}, {}
    for fam, rules in RULES.items():
        for kind, needle, weight, why in rules:
            hit = (needle.lower() in apis_l or any(needle.lower() in a for a in apis_l)) \
                if kind == "api" else (needle.lower() in blob)
            if hit:
                scores[fam] = scores.get(fam, 0) + weight
                reasons.setdefault(fam, []).append(f"{why} ({needle})")

    persistence = []
    for kind, needle, why in PERSIST:
        hit = any(needle.lower() in a for a in apis_l) if kind == "api" else (needle.lower() in blob)
        if hit and why not in persistence:
            persistence.append(why)

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    families = [{"family": f, "score": s, "evidence": reasons[f][:6]} for f, s in ranked if s >= 3]
    primary = families[0]["family"] if families else "unclassified"
    secondary = [f["family"] for f in families[1:3]]

    return {
        "primary": primary,
        "secondary": secondary,
        "families": families,
        "persistence": persistence,
        "summary": _summary(primary, secondary, persistence),
    }


def _summary(primary, secondary, persistence):
    if primary == "unclassified":
        return "Insufficient behavioral signal to classify the family."
    s = f"Behaves as a **{primary}**"
    if secondary:
        s += f" with {' and '.join(secondary)} characteristics"
    if persistence:
        s += f"; establishes persistence via {', '.join(persistence)}"
    return s + "."
