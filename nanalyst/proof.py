"""Proof of Compromise — synthesize one report from a Case.

Deterministic synthesis of everything the workers found (triage + static today;
dynamic + re-static later) into a single evidence-backed report: identity,
verdict, capabilities mapped to MITRE ATT&CK, IOCs, obfuscation evidence, and
the dynamic next-steps. Emits Markdown and a structured dict.

The AI brain (Claude over MCP) calls this to produce the final artifact; it also
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


def _verdict(triage: dict, static: dict) -> dict:
    """Heuristic maliciousness assessment with an evidence list."""
    score = 0
    evidence = []
    caps = triage.get("pe", {}).get("suspicious_apis", {})

    if "injection" in caps:
        score += 25
        evidence.append("imports process-injection APIs")
    if "dynamic_resolution" in caps:
        score += 15
        evidence.append("resolves APIs at runtime (hides intent from static analysis)")
    if "anti_analysis" in caps:
        score += 15
        evidence.append("imports anti-analysis / anti-debug APIs")
    if "network" in caps:
        score += 10
        evidence.append("networking capability present")
    if "persistence" in caps:
        score += 10
        evidence.append("persistence capability present")

    pk = triage.get("packing", {})
    if pk.get("likely_packed"):
        score += 20
        evidence.append(f"packed/obfuscated ({pk.get('packer') or 'custom'})")

    if static.get("available"):
        if static.get("indirect_register_count", 0) > 0:
            score += 10
            evidence.append(
                f"{static['indirect_register_count']} indirect-register control transfers (obfuscation)"
            )
        s = static.get("strings", {})
        if s.get("urls") or s.get("ips"):
            score += 10
            evidence.append("embedded network indicators (URLs/IPs)")
        # Packed samples reveal almost no functions statically — itself a signal.
        if static.get("function_count", 0) <= 2 and pk.get("likely_packed"):
            evidence.append("static analysis blind (few functions) — payload hidden until unpacked")

    score = min(score, 100)
    if score >= 60:
        label = "LIKELY MALICIOUS"
    elif score >= 30:
        label = "SUSPICIOUS"
    else:
        label = "INCONCLUSIVE (static only)"
    return {"label": label, "confidence": score, "evidence": evidence}


def _iocs(triage: dict, static: dict) -> dict:
    s = static.get("strings", {}) if static.get("available") else {}
    return {
        "urls": s.get("urls", []),
        "ips": s.get("ips", []),
        "registry": s.get("registry", []),
        "paths": s.get("paths", []),
        "suspicious_strings": s.get("suspicious", []),
    }


def _attack(triage: dict, static: dict) -> list[str]:
    caps = set(triage.get("pe", {}).get("suspicious_apis", {}).keys())
    techniques: list[str] = []
    for cap in caps:
        for t in ATTACK_MAP.get(cap, []):
            if t not in techniques:
                techniques.append(t)
    return techniques


def generate(case: dict) -> dict:
    """Build the Proof of Compromise dict from a case's stages."""
    stg = case.get("stages", {})
    triage = stg.get("triage", {})
    static = stg.get("static_ghidra", {})
    deob = stg.get("guest_deobfuscation", {})
    dynamic = stg.get("detonation", {})

    verdict = _verdict(triage, static)
    iocs = _iocs(triage, static)
    attack = _attack(triage, static)

    completeness = "static-only"
    if dynamic:
        completeness = "static + dynamic"

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
