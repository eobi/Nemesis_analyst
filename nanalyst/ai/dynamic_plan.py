"""Static -> dynamic hand-off: the AI turns what static analysis found into a plan for the
debugger, and a validator decides what the debugger is actually allowed to act on.

The AI proposes (one bounded call, logged). The validator is the guardrail:
  * priority APIs must be in OUR arsenal (api_spec) — those are the ones with capture handlers;
    anything else is recorded as rejected, never armed;
  * watch regions must lie inside the image and are size-clamped and capped;
  * anti-evasion items stay advisory text (shown in the report, never executed).
Everything proposed, accepted and rejected is stored, so the plan is auditable.
"""
from __future__ import annotations

from ..api_spec import API_SPEC

ALLOWED_APIS = {s["sym"].split(".")[-1].lower(): s["sym"].split(".")[-1] for s in API_SPEC}
MAX_WATCH, MAX_PRIORITY = 8, 12
MIN_SIZE, MAX_SIZE = 0x100, 0x100000

OBJECTIVE = ("OBJECTIVE: unpack and fully analyze this sample on a debugger — reach the "
             "decrypted/unpacked payload, recover config/C2, and stay in control of the process.")

SYSTEM = (
    "You are a senior malware reverse-engineer planning the DYNAMIC phase for an automated "
    "debugger, using the static findings you are given.\n" + OBJECTIVE + "\n"
    "Be surgical: pick only what the evidence justifies. Rules: (1) priority_apis may ONLY be "
    "chosen from the ALLOWED list given; (2) watch_regions are RVAs inside the image that static "
    "evidence says will hold decrypted/unpacked content (e.g. a high-entropy section or resource, "
    "or a section whose virtual size dwarfs its raw size); (3) every item needs a one-line 'why' "
    "quoting the evidence; (4) if the evidence is thin, return short lists — do not pad."
)

SCHEMA = (
    "Return ONLY this JSON object:\n"
    "{\n"
    '  "hypothesis": "<what you think the unpacking/decryption mechanism is, from the evidence>",\n'
    '  "priority_apis": [{"api": "<name from ALLOWED>", "why": "<evidence>"}],\n'
    '  "watch_regions": [{"rva": "0x...", "size": "0x...", "why": "<evidence>"}],\n'
    '  "anti_evasion": [{"technique": "<what the sample likely does>", "action": "<what the analyst should do>"}],\n'
    '  "expected_events": ["<what should happen at runtime if your hypothesis is right>"]\n'
    "}"
)


def _facts(case: dict) -> str:
    """Compact fact sheet for the plan call (derived data only — never raw sample bytes)."""
    st = case.get("stages", case)
    tri, em = st.get("triage", {}) or {}, st.get("entropy_map", {}) or {}
    cp = st.get("code_patterns_packed", {}) or {}
    asm = st.get("ai_assessment_packed", {}) or {}
    L = [f"File: {tri.get('filetype')} {tri.get('arch')} compiler={tri.get('compiler')} "
         f"packer={(tri.get('packing') or {}).get('packer')}"]
    if em:
        L.append(f"Image base {em.get('image_base')} size_of_image {em.get('size_of_image')} "
                 f"entry_rva {em.get('entry_rva')} file_entropy {em.get('file_entropy')}")
        L.append("Sections: " + "; ".join(
            f"{s['name']} rva={s['rva']} vsize=0x{s['vsize']:x} raw=0x{s['raw_size']:x} H={s['entropy']}"
            f"{' X' if s['exec'] else ''}{' W' if s['write'] else ''}{' RUNTIME-EXPANDED' if s.get('runtime_expanded') else ''}"
            for s in em.get("sections", [])))
        for r in em.get("regions", [])[:10]:
            L.append(f"High-entropy region: {r.get('kind')} section={r.get('section')} rva={r.get('rva')} "
                     f"file_off=0x{r['file_off']:x} size=0x{r['size']:x} H={r['entropy']}")
        if em.get("overlay"):
            L.append(f"Overlay: {em['overlay']}")
        for r in em.get("resources", [])[:6]:
            L.append(f"Resource {r['type']}/{r['name']} size={r['size']} H={r['entropy']} rva={r['rva']}")
    for f in (cp.get("findings") or [])[:14]:
        L.append(f"Code pattern [{f['severity']}] {f['title']} x{f['count']} at {f['offsets'][:4]}")
    for ln in ((cp.get("entry_disasm") or {}).get("flagged") or [])[:8]:
        L.append("Entry disasm flagged: " + ln)
    imps = (tri.get("pe", {}) or {}).get("suspicious_apis") or {}
    if imps:
        L.append(f"Suspicious import categories: {imps}")
    if asm:
        L.append(f"Prior static assessment: family={asm.get('likely_family')} "
                 f"packer={asm.get('packer_assessment')} anti_analysis={asm.get('anti_analysis_expected')}")
    L.append("ALLOWED priority_apis: " + ", ".join(sorted(ALLOWED_APIS.values())))
    return "\n".join(L)


def propose(brain, case: dict) -> dict:
    """One bounded, logged AI call. Returns the raw proposed plan ({} if unavailable)."""
    if brain is None or not getattr(brain, "available", False):
        return {}
    out = brain.decide(SYSTEM, _facts(case) + "\n\n" + SCHEMA, max_tokens=1800, purpose="dynamic-plan")
    return out if isinstance(out, dict) else {}


def _int(v):
    try:
        return int(str(v), 0)
    except Exception:
        return None


def _items(plan: dict, key: str, rej: list) -> list:
    """The list under `key`, keeping only dict items; anything else is recorded as rejected."""
    v = plan.get(key)
    if v is None:
        return []
    if not isinstance(v, list):
        rej.append({"item": key, "reason": f"expected a list, got {type(v).__name__} — ignored"}); return []
    good = [x for x in v if isinstance(x, dict)]
    if len(good) != len(v):
        rej.append({"item": key, "reason": f"{len(v) - len(good)} non-object item(s) ignored"})
    return good


def validate(plan: dict, size_of_image: int | None) -> dict:
    """Return {accepted:{...}, rejected:[...]} — only `accepted` ever reaches the debugger."""
    rej = []
    ev = plan.get("expected_events")
    acc = {"hypothesis": str(plan.get("hypothesis", ""))[:600], "priority_apis": [], "watch_regions": [],
           "anti_evasion": [], "expected_events": [str(x)[:200] for x in (ev if isinstance(ev, list) else [])[:8]]}
    seen = set()
    for it in _items(plan, "priority_apis", rej):
        name = str((it or {}).get("api", "")).split(".")[-1].strip()
        canon = ALLOWED_APIS.get(name.lower())
        if not canon:
            rej.append({"item": f"priority_api {name!r}", "reason": "not in the API arsenal (no capture handler) — not armed"})
        elif canon not in seen and len(acc["priority_apis"]) < MAX_PRIORITY:
            seen.add(canon); acc["priority_apis"].append({"api": canon, "why": str(it.get("why", ""))[:200]})
    wseen = set()
    for it in _items(plan, "watch_regions", rej):
        rva, size = _int((it or {}).get("rva")), _int((it or {}).get("size"))
        if rva is None or size is None:
            rej.append({"item": f"watch_region {it!r}", "reason": "rva/size not parseable"}); continue
        if rva < 0 or (size_of_image and rva >= size_of_image):
            rej.append({"item": f"watch_region rva=0x{rva:x}", "reason": "outside the image"}); continue
        size = max(MIN_SIZE, min(size, MAX_SIZE))
        if size_of_image:
            size = min(size, size_of_image - rva)
        if rva in wseen or len(acc["watch_regions"]) >= MAX_WATCH:
            continue
        wseen.add(rva); acc["watch_regions"].append({"rva": rva, "size": size, "why": str(it.get("why", ""))[:200]})
    for it in _items(plan, "anti_evasion", rej)[:8]:
        acc["anti_evasion"].append({"technique": str((it or {}).get("technique", ""))[:160],
                                    "action": str((it or {}).get("action", ""))[:200],
                                    "status": "advisory only (not executed automatically)"})
    return {"accepted": acc, "rejected": rej}
