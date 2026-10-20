"""Human-readable rendering of a triage result for the terminal."""
from __future__ import annotations


def _bar(score: int) -> str:
    filled = round(score / 10)
    return "[" + "#" * filled + "-" * (10 - filled) + f"] {score}/100"


def render(t: dict) -> str:
    if t.get("error"):
        return f"! {t['path']}\n  ERROR: {t['error']}"

    h = t["hashes"]
    pe = t["pe"]
    pk = t["packing"]
    lines = []
    lines.append(f"== {t['path']}")
    lines.append(f"   {h['sha256']}")
    lines.append(f"   size {h['size']:,} bytes")
    lines.append("")
    lines.append(f"   type      : {t.get('filetype') or '?'}  ({t.get('arch')}, {t.get('kind')})")
    if t.get("compiler"):
        lines.append(f"   compiler  : {t['compiler']}")
    if not t.get("die_available"):
        lines.append(f"   (DIE unavailable: {t.get('die_error')})")
    lines.append("")

    verdict = "LIKELY PACKED" if pk["likely_packed"] else "not obviously packed"
    pkname = f" — {pk['packer']}" if pk["packer"] else ""
    lines.append(f"   PACKING   : {verdict}{pkname}")
    lines.append(f"   confidence: {_bar(pk['confidence'])}")
    for r in pk["reasons"]:
        lines.append(f"     - {r}")
    lines.append("")

    lines.append(f"   entry     : 0x{pe['entrypoint_rva']:x} in '{pe['entrypoint_section']}'")
    lines.append(f"   imports   : {pe['import_func_count']} funcs from {pe['import_dll_count']} DLLs")
    lines.append(f"   tls cbs   : {len(pe['tls_callbacks'])}   signed: {pe['signed']}   overlay: {pe['overlay_bytes']} bytes")
    lines.append("   sections  :")
    for s in pe["sections"]:
        flags = "".join([
            "X" if s["exec"] else "-",
            "W" if s["write"] else "-",
            "!" if s["w_and_x"] else " ",
        ])
        star = " <EP" if s["contains_ep"] else ""
        lines.append(
            f"     {s['name']:<10} {flags}  ent {s['entropy']:>5}  "
            f"vsz 0x{s['vsize']:<7x} raw 0x{s['rawsize']:<7x}{star}"
        )
    lines.append("")

    if pe["suspicious_apis"]:
        lines.append("   capabilities (by imported API):")
        for cat, apis in pe["suspicious_apis"].items():
            lines.append(f"     {cat:<18}: {', '.join(apis)}")
        lines.append("")

    nxt = t["next"]
    lines.append(f"   NEXT      : {nxt['action']}  ({nxt['why']})")
    return "\n".join(lines)


def render_static(g: dict) -> str:
    """Render the Ghidra static worker result."""
    if not g.get("available"):
        return f"   [Ghidra static] unavailable: {g.get('error')}"
    lines = []
    lines.append("   -- Ghidra static analysis --")
    lines.append(f"   functions : {g.get('function_count')}")
    lines.append(
        f"   anomalies : {g.get('anomaly_count')} "
        f"(indirect-register calls/jmps: {g.get('indirect_register_count')})"
    )
    apis = g.get("suspicious_apis", [])
    if apis:
        lines.append(f"   sus APIs  : {', '.join(apis)}")

    s = g.get("strings", {})
    for label in ("urls", "ips", "registry", "suspicious"):
        vals = s.get(label, [])
        if vals:
            shown = ", ".join(vals[:8])
            more = f" (+{len(vals) - 8} more)" if len(vals) > 8 else ""
            lines.append(f"   {label:<9}: {shown}{more}")

    anoms = g.get("anomalies", [])
    if anoms:
        lines.append("   anomaly samples:")
        for a in anoms[:8]:
            lines.append(f"     {a['addr']:<12} {a['type']:<18} {a['detail']}")

    hints = g.get("dynamic_hints", [])
    if hints:
        lines.append("   DYNAMIC HINTS (feed to x64dbg):")
        for h in hints[:12]:
            where = f" @ {h['where']}" if h.get("where") else ""
            lines.append(f"     [{h['kind']}]{where}  {h['why']}")
    return "\n".join(lines)
