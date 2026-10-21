"""Understand every dump by its CONTENT, and compare the stages with each other.

Before this, a dump's "role" was guessed from its filename. Here each dump is classified from what it
actually contains, and consecutive dumps are compared so the analyst can see what each stage added:

  per dump   kind (PE image / executable code / text-config / encrypted-or-compressed / zero-filled / data),
             entropy, printable and zero ratios, hashes, embedded PE images, instruction density (Capstone),
             for a PE: sections, import count, imphash, packed-looking or not, strings/IOCs found;
  per pair   byte similarity at the same offsets, shared 4 KB blocks, containment ("B contains A"),
             entropy change, and what is NEW in the later stage (strings, imports, indicators).

Deterministic and host-side. Findings are facts about bytes; interpretation text says what the evidence
supports and no more.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .entropy_map import shannon

BLOCK = 4096


def _ratio(data: bytes, pred) -> float:
    return round(sum(1 for b in data if pred(b)) / len(data), 3) if data else 0.0


def code_density(data: bytes, arch="x86", n=400) -> float:
    """Fraction of the first `n` instructions-worth of bytes that disassemble as plausible x86 (Capstone).
    Real code decodes almost entirely; encrypted/compressed data and text do not."""
    try:
        import capstone
    except Exception:
        return 0.0
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if arch == "x64" else capstone.CS_MODE_32)
    chunk, ok, total, off = data[:2048], 0, 0, 0
    while off < len(chunk) and total < n:
        got = False
        for ins in md.disasm(chunk[off:off + 16], off):
            ok += ins.size; total += ins.size; off += ins.size; got = True
            break
        if not got:
            total += 1; off += 1
    return round(ok / total, 3) if total else 0.0


def embedded_pes(data: bytes, limit=6) -> list:
    out, start = [], 1
    while len(out) < limit:
        i = data.find(b"MZ", start)
        if i < 0:
            break
        start = i + 2
        if i + 0x40 > len(data):
            continue
        lf = int.from_bytes(data[i + 0x3C:i + 0x40], "little")
        if 0 < lf < 0x1000 and data[i + lf:i + lf + 4] == b"PE\x00\x00":
            out.append(hex(i))
    return out


def _pe_info(data: bytes) -> dict:
    try:
        import pefile
        pe = pefile.PE(data=data)
    except Exception:
        return {}
    info = {"machine": hex(pe.FILE_HEADER.Machine), "sections": [], "imports": 0, "dlls": [],
            "entry_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000)}
    for s in pe.sections:
        info["sections"].append({"name": s.Name.rstrip(b"\x00").decode("latin-1", "replace"),
                                 "entropy": round(s.get_entropy(), 2), "raw": int(s.SizeOfRawData)})
    try:
        pe.parse_data_directories(directories=[1])
        for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            info["dlls"].append(e.dll.decode("latin-1", "replace"))
            info["imports"] += len(e.imports)
        ih = pe.get_imphash()
        if ih:
            info["imphash"] = ih
    except Exception:
        pass
    hi = [s["name"] for s in info["sections"] if s["entropy"] >= 7.2]
    info["packed_looking"] = bool(hi) or info["imports"] <= 3
    info["high_entropy_sections"] = hi
    return info


def classify_kind(data: bytes, arch="x86") -> dict:
    """What the bytes ARE, from content only."""
    n = len(data)
    if n == 0:
        return {"kind": "empty", "why": "no bytes"}
    ent, zero = shannon(data[:262144]), _ratio(data[:262144], lambda b: b == 0)
    printable = _ratio(data[:262144], lambda b: 32 <= b < 127 or b in (9, 10, 13))
    if zero >= 0.9:
        return {"kind": "zero-filled", "entropy": ent, "zero_ratio": zero,
                "why": f"{int(zero*100)}% zero bytes: memory the program allocated but had not (yet) filled"}
    if data[:2] == b"MZ":
        pe = _pe_info(data)
        if pe:
            return {"kind": "PE image", "entropy": ent, "pe": pe,
                    "why": f"valid PE header; {pe['imports']} imports across {len(pe['dlls'])} DLL(s)"
                           + ("; still packed-looking (high-entropy section or almost no imports)" if pe["packed_looking"] else "; imports present")}
        return {"kind": "PE image (partial/invalid)", "entropy": ent, "why": "starts with MZ but the PE structure does not parse (a raw memory dump needs its headers/IAT rebuilt)"}
    cd = code_density(data, arch)
    if printable >= 0.85 and ent < 6.0:
        return {"kind": "text / configuration", "entropy": ent, "printable_ratio": printable,
                "why": f"{int(printable*100)}% printable at entropy {ent}: readable text, a script, or a configuration"}
    if cd >= 0.9 and ent < 7.0:
        return {"kind": "executable code", "entropy": ent, "code_density": cd,
                "why": f"{int(cd*100)}% of the first bytes decode as valid x86 instructions: looks like shellcode or a code region"}
    if ent >= 7.2:
        return {"kind": "encrypted / compressed", "entropy": ent,
                "why": f"entropy {ent} with no structure (no header, not code, not text): ciphertext or compressed data — a key/decompressor is needed"}
    return {"kind": "data", "entropy": ent, "printable_ratio": printable, "code_density": cd,
            "why": "structured or mixed data (neither clearly code, text, nor random)"}


def _blocks(data: bytes) -> list:
    return [hashlib.md5(data[i:i + BLOCK]).digest() for i in range(0, len(data), BLOCK) if len(data[i:i + BLOCK]) == BLOCK or i == 0]


def similarity(a: bytes, b: bytes) -> dict:
    """How two dumps relate. Same-offset byte match, shared whole 4 KB blocks, and containment."""
    m = min(len(a), len(b))
    same = sum(1 for x, y in zip(a[:m], b[:m]) if x == y) if m else 0
    ba, bb = _blocks(a), _blocks(b)
    nz = lambda L: [x for x in L if x != hashlib.md5(b"\x00" * BLOCK).digest()]       # ignore all-zero blocks
    sa, sb = set(nz(ba)), set(nz(bb))
    shared = len(sa & sb)
    return {"byte_match_at_same_offsets": round(same / m, 3) if m else 0.0, "bytes_compared": m,
            "shared_nonzero_blocks": shared, "blocks_a": len(sa), "blocks_b": len(sb),
            "a_inside_b": bool(sa) and sa <= sb, "b_inside_a": bool(sb) and sb <= sa,
            "identical": a == b}


def _strings(data: bytes, minlen=6) -> set:
    return {m.group().decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data[:2_000_000])} | \
           {m.group().decode("utf-16-le", "ignore") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data[:2_000_000])}


def analyze_dumps(items: list, arch="x86") -> dict:
    """`items` = [{"name","path","order"(optional),"role"(optional)}] in capture order. Returns the analysis."""
    rows, blobs = [], {}
    for it in items:
        p = Path(it["path"])
        if not p.exists():
            continue
        data = p.read_bytes()
        k = classify_kind(data, arch)
        row = {"name": it["name"], "size": len(data), "md5": hashlib.md5(data).hexdigest(),
               "sha256": hashlib.sha256(data).hexdigest(), "order": it.get("order"), **k}
        emb = embedded_pes(data)
        if emb and k["kind"] != "PE image":
            row["embedded_pe_offsets"] = emb
        rows.append(row); blobs[it["name"]] = data
    # exact duplicates
    seen = {}
    for r in rows:
        r["duplicate_of"] = seen.get(r["sha256"])
        seen.setdefault(r["sha256"], r["name"])
    # compare each stage with the previous distinct stage, and find containment
    comps = []
    uniq = [r for r in rows if not r["duplicate_of"]]
    for prev, cur in zip(uniq, uniq[1:]):
        a, b = blobs[prev["name"]], blobs[cur["name"]]
        sim = similarity(a, b)
        sa, sb = _strings(a), _strings(b)
        new = sorted(sb - sa, key=len, reverse=True)
        pi, ci = (prev.get("pe") or {}), (cur.get("pe") or {})
        c = {"from": prev["name"], "to": cur["name"], **sim,
             "entropy_change": round(cur.get("entropy", 0) - prev.get("entropy", 0), 2),
             "new_strings": len(new), "new_string_examples": new[:6]}
        if pi and ci:
            c["imports_change"] = f'{pi.get("imports", 0)} -> {ci.get("imports", 0)}'
            c["same_imphash"] = bool(pi.get("imphash")) and pi.get("imphash") == ci.get("imphash")
        c["reading"] = _reading(prev, cur, sim, c)
        comps.append(c)
    payloads = [r["name"] for r in rows if r["kind"] in ("PE image", "executable code") and not r["duplicate_of"]]
    return {"dumps": rows, "comparisons": comps,
            "summary": {"count": len(rows), "distinct": len(uniq), "payload_candidates": payloads,
                        "kinds": {k: sum(1 for r in rows if r["kind"] == k) for k in sorted({r["kind"] for r in rows})}}}


def _reading(a: dict, b: dict, sim: dict, c: dict) -> str:
    """One honest sentence about how stage b relates to stage a."""
    if sim["identical"]:
        return "identical content"
    if sim["a_inside_b"]:
        return f'{b["name"]} contains all of {a["name"]} (a larger capture of the same memory)'
    if sim["byte_match_at_same_offsets"] >= 0.9:
        return f'{int(sim["byte_match_at_same_offsets"]*100)}% of bytes unchanged: the same buffer, modified in place'
    if a["kind"] == "encrypted / compressed" and b["kind"] in ("PE image", "executable code", "text / configuration"):
        return f'{a["name"]} (ciphertext) became {b["kind"]} in {b["name"]}: this is the decryption/unpacking step'
    if a["kind"] == "zero-filled" and b["kind"] != "zero-filled":
        return f'the region was empty in {a["name"]} and filled with {b["kind"]} by {b["name"]}'
    if sim["byte_match_at_same_offsets"] < 0.1 and sim["shared_nonzero_blocks"] == 0:
        return "unrelated content (different buffers)"
    return f'{int(sim["byte_match_at_same_offsets"]*100)}% of bytes match at the same offsets; partly related'


def to_markdown(an: dict) -> list:
    """Report lines: a content-based table plus what each step changed."""
    if not an or not an.get("dumps"):
        return []
    L = ["## 3c. Dump-by-dump analysis (what each dump actually is, from its bytes)",
         f"{an['summary']['count']} dump(s), {an['summary']['distinct']} distinct. Classified by CONTENT, not by file name.", "",
         "| # | Dump | Size | What it is | Entropy | Why |", "|---|---|---|---|---|---|"]
    for i, r in enumerate(an["dumps"], 1):
        dup = f" _(duplicate of {r['duplicate_of']})_" if r.get("duplicate_of") else ""
        L.append(f"| {i} | `{r['name']}`{dup} | {r['size']:,} | **{r['kind']}** | {r.get('entropy', '-')} | {r['why']} |")
    L.append("")
    pes = [r for r in an["dumps"] if r["kind"] == "PE image" and r.get("pe")]
    if pes:
        L.append("**PE images:**")
        for r in pes:
            p = r["pe"]
            L.append(f"- `{r['name']}`: {p['imports']} imports / {len(p['dlls'])} DLLs ({', '.join(p['dlls'][:6])}), "
                     f"entry `{p['entry_rva']}`, imphash `{p.get('imphash', '-')}`, "
                     f"sections {[s['name'] for s in p['sections']]}"
                     + (f", high-entropy sections {p['high_entropy_sections']}" if p["high_entropy_sections"] else ""))
        L.append("")
    emb = [r for r in an["dumps"] if r.get("embedded_pe_offsets")]
    for r in emb:
        L.append(f"- `{r['name']}` carries embedded PE image(s) at offsets {r['embedded_pe_offsets']} (a second stage inside this dump).")
    if an["comparisons"]:
        L += ["", "**How consecutive stages relate:**", "| From | To | Same bytes at same offsets | Shared blocks | Entropy change | New strings | Reading |",
              "|---|---|---|---|---|---|---|"]
        for c in an["comparisons"]:
            extra = f" imports {c['imports_change']}" if c.get("imports_change") else ""
            L.append(f"| `{c['from']}` | `{c['to']}` | {int(c['byte_match_at_same_offsets']*100)}% | {c['shared_nonzero_blocks']} | "
                     f"{c['entropy_change']:+} | {c['new_strings']} | {c['reading']}{extra} |")
        L.append("")
    return L
