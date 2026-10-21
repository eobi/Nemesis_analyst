"""Proof of Compromise — synthesize one report from a Case.

Deterministic synthesis of everything the workers found (triage + static today;
dynamic + re-static later) into a single evidence-backed report: identity,
verdict, capabilities mapped to MITRE ATT&CK, IOCs, obfuscation evidence, and
the dynamic next-steps. Emits Markdown and a structured dict.

The AI brain (an LLM client over MCP) calls this to produce the final artifact; it also
runs standalone so the pipeline always yields a report with no LLM required.
"""
from __future__ import annotations

# Capability (by imported/referenced API category) -> MITRE ATT&CK techniques.
ATTACK_MAP = {
    "injection": ["T1055 Process Injection"],
    "dynamic_resolution": ["T1027 Obfuscated Files or Information", "T1620 Reflective Code Loading"],
    "execution": ["T1106 Native API", "T1059 Command and Scripting Interpreter"],
    "anti_analysis": ["T1622 Debugger Evasion", "T1497 Virtualization/Sandbox Evasion"],
    "network": ["T1071 Application Layer Protocol", "TA0011 Command and Control"],
    "persistence": ["T1547 Boot or Logon Autostart", "T1543 Create or Modify System Process"],
    "crypto": ["T1486 Data Encrypted for Impact", "T1027 Obfuscated Files or Information"],
}


# APIs whose runtime, by-name resolution is a classic loader/injector tell (as opposed to the
# hundreds of ordinary lookups any CRT/.NET start-up performs)
SUSPICIOUS_RESOLVED = {"virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
                       "writeprocessmemory", "createremotethread", "ntcreatethreadex", "ntunmapviewofsection",
                       "setthreadcontext", "resumethread", "queueuserapc", "rtldecompressbuffer",
                       "cryptdecrypt", "winexec", "urldownloadtofilea", "urldownloadtofilew",
                       "internetopena", "internetopenw", "internetopenurla", "createprocessa", "createprocessw",
                       "ntwritevirtualmemory", "ntallocatevirtualmemory", "ntprotectvirtualmemory"}

STATIC_ONLY_CAP = 55        # static indicators alone cannot "confirm" malice — cap confidence

def _verdict(triage: dict, static: dict, stg: dict | None = None) -> dict:
    """Maliciousness assessment with a POINT-ATTRIBUTED evidence list, split into
    static indicators and dynamic (runtime) proof.

    Honesty rules (so the verdict can never over-claim):
      * The MALICIOUS label and any high confidence require DYNAMIC evidence — what
        the sample actually did at runtime (confirmed unpack, behavioral class,
        memory-API activity, recovered crypto/IOCs). Static imports describe
        *capability*, not behavior, so static-only is capped at STATIC_ONLY_CAP and
        can rise no higher than 'SUSPICIOUS (static-only)'.
      * Every point added states its reason inline as '(+N)'.
      * `caveats` spells out what was NOT established (e.g. payload not captured)."""
    stg = stg or {}
    s_score, d_score = 0, 0           # static vs dynamic, kept separate
    static_ev, dynamic_ev, caveats = [], [], []
    caps = triage.get("pe", {}).get("suspicious_apis", {})

    def S(pts, why):
        nonlocal s_score; s_score += pts; static_ev.append(f"{why} (+{pts})")
    def D(pts, why):
        nonlocal d_score; d_score += pts; dynamic_ev.append(f"{why} (+{pts})")

    # ---- STATIC indicators (capability, not proof of behaviour) ----
    if "injection" in caps:          S(25, "imports process-injection APIs")
    if "dynamic_resolution" in caps: S(15, "resolves APIs at runtime (hides intent from static analysis)")
    if "anti_analysis" in caps:      S(15, "imports anti-analysis / anti-debug APIs")
    if "network" in caps:            S(10, "networking capability present")
    if "persistence" in caps:        S(10, "persistence capability present")

    pk = triage.get("packing", {})
    if pk.get("likely_packed"):      S(20, f"packed/obfuscated ({pk.get('packer') or 'custom'})")

    if static.get("available"):
        if static.get("indirect_register_count", 0) > 0:
            S(10, f"{static['indirect_register_count']} indirect-register control transfers (obfuscation)")
        s = static.get("strings", {})
        if s.get("urls") or s.get("ips"):
            S(10, "embedded network indicators (URLs/IPs) in the packed file")
        if static.get("function_count", 0) <= 2 and pk.get("likely_packed"):
            static_ev.append("static analysis blind (few functions) — payload hidden until unpacked (+0)")

    # ---- DYNAMIC evidence (what it actually DID — the decisive part) ----
    dynamic = False
    vf = stg.get("verify_unpack", {}) or {}
    if vf.get("verdict") == "CONFIRMED_UNPACKED":
        dynamic = True; D(30, "CONFIRMED self-unpacking at runtime (payload captured + verified)")
    # `dynamic` = the sample actually EXECUTED under instrumentation. Only a real
    # API trace or a CONFIRMED unpack proves that — classification/crypto can be
    # static-derived, so they add points but never by themselves claim "it ran".
    at = stg.get("api_trace", {}) or {}
    cnt = at.get("counts", {}) or {}
    if cnt:
        dynamic = True
        trace = at.get("trace", []) or []
        # Only an ACTUAL write->execute flip is unpacking evidence. Calling VirtualAlloc and
        # VirtualProtect is what every runtime (.NET, the CRT) does and proves nothing.
        wx = [ev for ev in trace if "W->X" in str(((ev.get("capture") or {}).get("note") or ""))]
        if wx:
            D(10, f"runtime: memory made executable after being written ({len(wx)} W->X event(s)) — the unpacking moment")
        # Resolving a LOT of APIs is normal; resolving specifically security-relevant ones by name is not.
        resolved = sorted({str(((ev.get("capture") or {}).get("note") or "")).strip('"').lower()
                           for ev in trace if str(ev.get("api", "")).endswith("GetProcAddress")} & SUSPICIOUS_RESOLVED)
        if len(resolved) >= 2:
            D(10, "runtime: resolves security-relevant APIs by name (" + ", ".join(resolved[:6]) + ")")
    cls = stg.get("classification", {}) or {}
    fams = [f["family"] for f in cls.get("families", [])]
    if any(f in ("loader/packer", "injector", "dropper", "banker", "ransomware",
                 "infostealer", "bot", "keylogger", "worm") for f in fams):
        tag = "behavioral" if dynamic else "pattern-based"
        D(25, f"{tag} classification: {cls.get('primary')} ({', '.join(fams[:3])})")
    cr = stg.get("crypto_recovery", {}) or {}
    if cr.get("schemes"):
        tag = "runtime cryptography" if dynamic else "crypto indicators (static)"
        D(10, f"{tag} in use ({cr['schemes'][0]['algo']})")

    # ---- did a payload actually get captured? (the thing that was being faked) ----
    du = stg.get("dynamic_unpack", {}) or {}
    dumps = ((stg.get("dumps_manifest", {}) or {}).get("dumps")) or []
    payload_captured = bool(du.get("payload_captured")) and bool(dumps)
    if not payload_captured:
        caveats.append("No unpacked payload was captured/dumped — the unpacked code was NOT recovered or verified.")
    if not dynamic:
        caveats.append("No dynamic (runtime) analysis evidence — verdict rests on STATIC indicators only.")

    # ---- combine, with the static-only cap ----
    score = min(s_score + d_score, 100)
    basis = "dynamic-confirmed" if dynamic else "static-only"
    if not dynamic:
        score = min(score, STATIC_ONLY_CAP)

    if dynamic and score >= 60:
        label = "MALICIOUS"
    elif dynamic and score >= 35:
        label = "LIKELY MALICIOUS"
    elif score >= 30:
        label = "SUSPICIOUS (static-only)" if not dynamic else "SUSPICIOUS"
    elif score > 0:
        label = "SUSPICIOUS"
    else:
        label = "INCONCLUSIVE"

    return {"label": label, "confidence": score, "basis": basis,
            "dynamic": dynamic, "payload_captured": payload_captured,
            "static_score": s_score, "dynamic_score": d_score,
            "evidence": static_ev + dynamic_ev,          # back-compat flat list (now point-attributed)
            "static_evidence": static_ev, "dynamic_evidence": dynamic_ev,
            "caveats": caveats}


def _iocs(triage: dict, static: dict) -> dict:
    s = static.get("strings", {}) if static.get("available") else {}
    return {
        "urls": s.get("urls", []),
        "ips": s.get("ips", []),
        "registry": s.get("registry", []),
        "paths": s.get("paths", []),
        "suspicious_strings": s.get("suspicious", []),
    }


def _attack(triage: dict, static: dict, stg: dict | None = None) -> list[str]:
    stg = stg or {}
    caps = set(triage.get("pe", {}).get("suspicious_apis", {}).keys())
    techniques: list[str] = []
    for cap in caps:
        for t in ATTACK_MAP.get(cap, []):
            if t not in techniques:
                techniques.append(t)

    # map observed DYNAMIC behavior to techniques (the real evidence for packed malware)
    def tech(t):
        if t not in techniques:
            techniques.append(t)
    if (stg.get("verify_unpack", {}) or {}).get("verdict") == "CONFIRMED_UNPACKED":
        tech("T1027.002 Software Packing"); tech("T1140 Deobfuscate/Decode Files or Information")
    at = stg.get("api_trace", {}) or {}
    cnt = at.get("counts", {}) or {}
    names = {ev.get("capture", {}).get("note", "") for ev in at.get("trace", [])}
    if any("Alloc" in k for k in cnt) and any("Protect" in k for k in cnt):
        tech("T1620 Reflective Code Loading")
    if sum(v for k, v in cnt.items() if "GetProcAddress" in k) >= 10:
        tech("T1027 Obfuscated Files or Information")
    blob = " ".join(names)
    if "GetComputerName" in blob or "GetUserName" in blob:
        tech("T1082 System Information Discovery"); tech("T1033 System Owner/User Discovery")
    if "AddVectoredExceptionHandler" in blob or "OutputDebugString" in blob:
        tech("T1622 Debugger Evasion")
    if any("remote" in f["family"] for f in (stg.get("classification", {}) or {}).get("families", [])) \
       or "injector" in [f["family"] for f in (stg.get("classification", {}) or {}).get("families", [])]:
        tech("T1055 Process Injection")
    if (stg.get("crypto_recovery", {}) or {}).get("schemes"):
        tech("T1573 Encrypted Channel / config")
    return techniques


def generate(case: dict) -> dict:
    """Build the Proof of Compromise dict from a case's stages."""
    stg = case.get("stages", {})
    triage = stg.get("triage", {})
    static = stg.get("static_ghidra", {})
    deob = stg.get("guest_deobfuscation", {})
    dynamic = stg.get("detonation", {})

    verdict = _verdict(triage, static, stg)
    iocs = _iocs(triage, static)
    attack = _attack(triage, static, stg)

    ran_dynamic = any(k in stg for k in ("api_trace", "dynamic_unpack", "hint_dumps"))
    completeness = ("static + dynamic + detonation" if dynamic else
                    "static + dynamic" if ran_dynamic else "static-only")

    pending = []
    if not deob and triage.get("pe", {}):
        pass
    if not dynamic:
        pending = [
            "full detonation (FakeNet network capture, Regshot reg/FS diff, Procmon)",
            "re-static on reconstructed dump (reveal hidden functions/URLs/config)",
        ]

    return {
        "sample": case.get("name"),
        "sha256": case.get("sha256"),
        "size": case.get("size"),
        "arch": triage.get("arch"),
        "type": triage.get("filetype"),
        "compiler": triage.get("compiler"),
        "verdict": verdict,
        "packing": triage.get("packing", {}),
        "capabilities": triage.get("pe", {}).get("suspicious_apis", {}),
        "attack_techniques": attack,
        "iocs": iocs,
        "anomalies": static.get("anomalies", []) if static.get("available") else [],
        "deobfuscation": deob or None,
        "detonation": dynamic or None,
        "dynamic_hints": case.get("hints", []),
        "completeness": completeness,
        "pending": pending,
        "attribution": stg.get("attribution") or None,
        "classification": stg.get("classification") or None,
        "verify_unpack": stg.get("verify_unpack") or None,
        "crypto_recovery": stg.get("crypto_recovery") or None,
    }


def to_markdown(poc: dict) -> str:
    L = []
    L.append(f"# Proof of Compromise — {poc['sample']}")
    L.append("")
    v = poc["verdict"]
    L.append(f"**Verdict: {v['label']}**  (confidence {v['confidence']}/100, {poc['completeness']})")
    cls = poc.get("classification")
    if cls and cls.get("primary") and cls["primary"] != "unclassified":
        L.append("")
        L.append(f"**Family:** {cls['summary']}")
    L.append("")
    L.append("## Identity")
    L.append(f"- SHA-256: `{poc['sha256']}`")
    L.append(f"- Size: {poc['size']:,} bytes")
    L.append(f"- Type: {poc['type']} ({poc['arch']})")
    if poc.get("compiler"):
        L.append(f"- Compiler: {poc['compiler']}")
    L.append("")

    attr = poc.get("attribution")
    if attr and attr.get("available") and attr.get("summary"):
        L.append("## Author / build reconnaissance")
        for b in attr["summary"]:
            L.append(f"- {b}")
        L.append("")

    L.append("## Why (evidence)")
    for e in v["evidence"] or ["no strong signals from static analysis alone"]:
        L.append(f"- {e}")
    L.append("")

    vf = poc.get("verify_unpack")
    if vf:
        L.append("## Unpack verification")
        L.append(f"- **{vf['verdict']}** (confidence {vf['confidence']}/100) — the dumped/unpacked "
                 "payload was compared against the packed file.")
        for r in vf.get("reasons", []):
            L.append(f"  - {r}")
        L.append("")

    pk = poc.get("packing", {})
    L.append("## Packing")
    if pk.get("likely_packed"):
        L.append(f"- Packed: yes — {pk.get('packer') or 'custom/unknown'} (confidence {pk.get('confidence')}/100)")
    else:
        L.append(f"- Packed: not conclusively (confidence {pk.get('confidence', 0)}/100)")
    for r in pk.get("reasons", []):
        L.append(f"  - {r}")
    L.append("")

    if poc["capabilities"]:
        L.append("## Capabilities")
        for cat, apis in poc["capabilities"].items():
            L.append(f"- **{cat}**: {', '.join(apis)}")
        L.append("")

    if poc["attack_techniques"]:
        L.append("## MITRE ATT&CK")
        for t in poc["attack_techniques"]:
            L.append(f"- {t}")
        L.append("")

    io = poc["iocs"]
    if any(io.values()):
        L.append("## Indicators of Compromise")
        for label, key in [("URLs", "urls"), ("IPs (candidate)", "ips"),
                           ("Registry", "registry"), ("Paths", "paths"),
                           ("Suspicious strings", "suspicious_strings")]:
            vals = io.get(key, [])
            if vals:
                L.append(f"- **{label}**:")
                for x in vals[:20]:
                    L.append(f"  - `{x}`")
        L.append("")

    deob = poc.get("deobfuscation")
    if deob:
        L.append("## Deobfuscation (.NET)")
        L.append(f"- .NET: {deob.get('dotnet')}")
        if deob.get("obfuscator"):
            L.append(f"- Obfuscator (de4dot): {deob['obfuscator']}")
        if deob.get("deobfuscated"):
            L.append(f"- Deobfuscated assembly: `{deob['deobfuscated']}` (open in dnSpy for clean symbols)")
        L.append("")

    deton = poc.get("detonation")
    if deton:
        L.append("## Detonation (behavioral)")
        for k in ("started", "duration_s", "artifacts_dir"):
            if deton.get(k) is not None:
                L.append(f"- {k}: {deton[k]}")
        for label in ("network", "registry_changes", "files_dropped", "processes"):
            vals = deton.get(label) or []
            if vals:
                L.append(f"- **{label}**:")
                for v in vals[:20]:
                    L.append(f"  - `{v}`")
        L.append("")

    if poc["anomalies"]:
        L.append("## Obfuscation / control-flow anomalies")
        for a in poc["anomalies"][:15]:
            L.append(f"- `{a['addr']}` {a['type']}: {a['detail']}")
        L.append("")

    if poc["dynamic_hints"]:
        L.append("## Dynamic analysis plan (hints from static)")
        for h in poc["dynamic_hints"]:
            where = f" @ `{h['where']}`" if h.get("where") else ""
            L.append(f"- [{h['kind']}]{where} {h['why']}")
        L.append("")

    cr = poc.get("crypto_recovery")
    if cr and cr.get("schemes"):
        L.append("## Encryption / recovery")
        for n in cr.get("notes", []):
            L.append(f"- {n}")
        for s in cr["schemes"]:
            tag = ("RUNNABLE decryptor" if s.get("recoverable") and not s.get("asymmetric")
                   else "NOT recoverable offline" if s.get("asymmetric") else "template (needs key)")
            L.append(f"- **{s['algo'].upper()}** (confidence {s['confidence']}/100) — {tag}")
        gen = [g for g in cr.get("generated", []) if g.get("path")]
        if gen:
            L.append(f"- Decryptors generated in `decryptor/` ({', '.join(__import__('pathlib').Path(g['path']).name for g in gen)}) — see decryptor/README.md")
        L.append("")

    if poc["pending"]:
        L.append("## Pending (to complete the proof)")
        for p in poc["pending"]:
            L.append(f"- [ ] {p}")
        L.append("")

    return "\n".join(L)
