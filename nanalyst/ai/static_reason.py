"""AI-assisted deep static reasoning.

The brain is given the hard facts the deterministic tools extracted (imports, section
entropy, categorized strings from whichever stage, attribution, optional disasm) and
reasons like an analyst: likely family, capabilities, config/C2 leads, which strings to
pivot on, packer assessment, and — most useful for the next phase — a concrete DYNAMIC
STRATEGY (what to breakpoint, what to watch for, anti-evasion to expect).

Guardrails baked into the prompt: use ONLY the supplied evidence, quote the strings you
rely on, say "unknown" rather than guess, and DO NOT assign a maliciousness score
(scoring is deterministic in proof.py). Returns {} when the brain is unavailable.
"""
from __future__ import annotations

OBJECTIVE = ("OBJECTIVE: unpack and fully analyze this malware — identify it, recover its "
             "payload/config/C2, and produce a plan to capture what static tooling can't yet see.")

SYSTEM = (
    "You are a senior malware reverse-engineer assisting an automated analysis pipeline.\n"
    + OBJECTIVE + "\n"
    "Your job is to ENHANCE the deterministic tooling's findings, not to repeat them and not to "
    "wander: add only what a human expert would add on top of the provided facts — a sharper "
    "family call, overlooked leads, and a focused next-step plan. Be concise and surgical.\n"
    "Rules: (1) use ONLY the evidence provided; (2) quote the exact strings/imports you rely on; "
    "(3) if something is not determinable, say \"unknown\" — never fabricate C2s, families, or "
    "hashes; (4) do NOT output a maliciousness score or verdict (a separate deterministic engine, "
    "gated on captured evidence, does that); (5) keep lists tight — the few highest-signal items, "
    "not everything."
)

_SCHEMA = (
    "Return ONLY this JSON object:\n"
    "{\n"
    '  "stage": "<which stage you were given: packed|unpacked|decrypted>",\n'
    '  "likely_family": "<family/toolkit or \'unknown\'>",\n'
    '  "family_confidence": "low|medium|high",\n'
    '  "capabilities": ["<behaviour inferred from imports/strings, each tied to evidence>"],\n'
    '  "config_leads": ["<candidate C2 / mutex / path / key / campaign id, with the string you saw>"],\n'
    '  "url_leads": ["<only a real URL/domain/IP seen in the facts, or a concrete hint one is built at runtime; NOT version numbers, NOT the word unknown; use an empty list if none>"],\n'
    '  "encrypted_regions": [{"where": "<section/rva/resource/overlay from the facts — ONLY where entropy there is >= 7.0 or the section is flagged RUNTIME-EXPANDED; compiled code is normally 5.5-6.5, that is NOT encrypted>", "likely": "encrypted|compressed|resource payload", "evidence": "<entropy/size/section clue>"}],\n'
    '  "notable_strings": ["<strings worth pivoting on and why>"],\n'
    '  "packer_assessment": "<is it packed/crypted, what kind, what to expect at runtime>",\n'
    '  "anti_analysis_expected": ["<anti-debug/anti-vm/evasion you expect, from imports/strings>"],\n'
    '  "dynamic_strategy": ["<ordered, concrete steps: which APIs to breakpoint, what memory to watch, when to dump>"],\n'
    '  "reasoning": "<2-4 sentence justification grounded in the evidence>"\n'
    "}"
)


def _fmt_context(ctx: dict) -> str:
    """Render the extracted facts compactly for the prompt (bounded to stay cheap)."""
    L = []
    L.append(f"STAGE: {ctx.get('stage', 'packed')}")
    if ctx.get("filetype"):
        L.append(f"File type: {ctx['filetype']}  arch: {ctx.get('arch')}  compiler: {ctx.get('compiler')}")
    if ctx.get("packing"):
        L.append(f"Packing: {ctx['packing']}")
    if ctx.get("entropy") is not None:
        L.append(f"Overall entropy: {ctx['entropy']}")
    if ctx.get("sections"):
        L.append("Sections (name, vsize, entropy): " + "; ".join(str(s) for s in ctx["sections"][:12]))
    if ctx.get("imports"):
        L.append("Notable imports: " + ", ".join(ctx["imports"][:80]))
    if ctx.get("suspicious_apis"):
        L.append(f"Suspicious API categories: {ctx['suspicious_apis']}")
    if ctx.get("attribution"):
        L.append(f"Attribution: {ctx['attribution']}")
    for k in ("urls", "ips", "domains", "registry", "mutexes", "suspicious_keywords", "paths", "commands"):
        v = ctx.get(k)
        if v:
            L.append(f"{k}: " + ", ".join(str(x) for x in v[:40]))
    if ctx.get("strings_sample"):
        L.append("String sample (truncated):\n" + "\n".join(ctx["strings_sample"][:120]))
    em = ctx.get("entropy_map") or {}
    if em:
        L.append(f"Entropy map: file H={em.get('file_entropy')}, image_base={em.get('image_base')}, "
                 f"size_of_image={em.get('size_of_image')}, entry_rva={em.get('entry_rva')}")
        for sec in (em.get("sections") or [])[:12]:
            L.append(f"  section {sec['name']} rva={sec['rva']} vsize=0x{sec['vsize']:x} raw=0x{sec['raw_size']:x} "
                     f"H={sec['entropy']}{' RUNTIME-EXPANDED' if sec.get('runtime_expanded') else ''}")
        for r in (em.get("regions") or [])[:10]:
            L.append(f"  HIGH-ENTROPY {r.get('kind')} section={r.get('section')} rva={r.get('rva')} "
                     f"size=0x{r['size']:x} H={r['entropy']}")
        if em.get("overlay"):
            L.append(f"  overlay: {em['overlay']}")
        for r in (em.get("resources") or [])[:6]:
            L.append(f"  resource {r['type']}/{r['name']} size={r['size']} H={r['entropy']}")
    for fnd in (ctx.get("code_findings") or [])[:14]:
        L.append(f"Code pattern [{fnd['severity']}] {fnd['title']} x{fnd['count']} at {fnd['offsets'][:4]}")
    for ln in (ctx.get("entry_flagged") or [])[:8]:
        L.append("Entry disasm flagged: " + ln)
    if ctx.get("disasm"):
        L.append("Disassembly snippet:\n" + ctx["disasm"][:3000])
    return "\n".join(L)


def build_context(case: dict, stage: str = "packed") -> dict:
    """Assemble the facts the brain reasons over, from a case's stages. `stage` selects
    which deep_static stage to foreground (packed/unpacked/decrypted)."""
    st = case.get("stages", {}) if "stages" in case else case
    tri = st.get("triage", {}) or {}
    pe = tri.get("pe", {}) or {}
    ds = st.get(f"deep_static_{stage}") or st.get("deep_static_packed") or {}
    if stage == "decrypted":
        srcs = (st.get("deep_static_decrypted") or {}).get("sources") or []
        ds = srcs[0] if srcs else ds
    attr = st.get("attribution") or {}
    sections = [(s.get("name"), s.get("virtual_size"), s.get("entropy"))
                for s in (pe.get("sections") or [])]
    imports = []
    for dll, fns in (pe.get("imports_by_dll") or {}).items():
        imports += [f"{dll}:{f}" for f in (fns or [])[:12]]
    return {
        "stage": stage,
        "filetype": tri.get("filetype"), "arch": tri.get("arch"),
        "compiler": tri.get("compiler"), "packing": tri.get("packing"),
        "entropy": ds.get("entropy"), "sections": sections,
        "imports": imports or list((pe.get("suspicious_apis") or {}).keys()),
        "suspicious_apis": pe.get("suspicious_apis"),
        "attribution": attr.get("summary"),
        "urls": ds.get("urls"), "ips": ds.get("ips"), "domains": ds.get("domains"),
        "registry": ds.get("registry"), "paths": ds.get("file_paths"),
        "commands": ds.get("commands"), "mutexes": ds.get("mutex_hints"),
        "suspicious_keywords": ds.get("suspicious_keywords"),
        "anti_analysis_indicators": ds.get("anti_analysis_indicators"),
        "strings_sample": (ds.get("file_paths") or [])[:10] + (ds.get("commands") or [])[:10],
        "entropy_map": st.get("entropy_map"),
        "code_findings": ((st.get(f"code_patterns_{stage}") or st.get("code_patterns_packed") or {}).get("findings") or []),
        "entry_flagged": (((st.get(f"code_patterns_{stage}") or st.get("code_patterns_packed") or {}).get("entry_disasm")) or {}).get("flagged") or [],
    }


def assess(brain, ctx: dict) -> dict:
    """Run the AI static assessment. `brain` is an ai.brain.Brain. Returns {} if unavailable."""
    if brain is None or not getattr(brain, "available", False):
        return {}
    user = _fmt_context(ctx) + "\n\n" + _SCHEMA
    out = brain.decide(SYSTEM, user, max_tokens=2000,
                       purpose=f"static-assess:{ctx.get('stage','packed')}")
    if isinstance(out, dict):
        out["_ai_model"] = brain.model
        return out
    return {}
