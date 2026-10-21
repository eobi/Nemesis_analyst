"""Unpack verification — "is this dump really the unpacked malware?"

After the dynamic engine dumps memory (or `upx -d` runs), we must not blindly
trust it. This compares the PACKED on-disk view against the DUMPED/unpacked view
and emits a verdict with evidence, so an analyst (and the report) can state with
confidence that the recovered payload is the real, unpacked code — not a bad dump
or still-packed bytes.

Signals (each adds to confidence):
  - import table grew (packed hides imports; unpacking reveals the real IAT)
  - packer section names gone (UPX0/UPX1/.aspack... replaced by .text/.data)
  - entry-point entropy dropped (compressed/encrypted -> real code)
  - new IOCs present in the dump that the packed file never exposed
  - the dump is a structurally valid PE / contains an MZ-PE image
"""
from __future__ import annotations


def _ep_entropy(tri: dict) -> float | None:
    pe = tri.get("pe", {})
    ep = pe.get("entrypoint_section")
    for s in pe.get("sections", []):
        if s.get("name") == ep:
            return s.get("entropy")
    return None


def _secnames(tri: dict) -> set:
    return {s.get("name", "").upper() for s in tri.get("pe", {}).get("sections", [])}


PACKER_SECTIONS = {"UPX0", "UPX1", "UPX2", ".ASPACK", ".ADATA", "FSG!", ".PETITE",
                   ".MPRESS1", ".MPRESS2", ".NSP0", ".NSP1", "PACKED", ".THEMIDA"}


def verify_unpack(packed: dict, dumped: dict,
                  packed_ioc: dict | None = None, dumped_ioc: dict | None = None,
                  dumped_label: str = "dumped payload", dynamic: dict | None = None) -> dict:
    """packed/dumped = triage() dicts; *_ioc = memstatic.analyze() dicts (optional);
    dynamic = the dynamic_unpack stage (W->X capture evidence). Returns a detailed
    verdict: per-signal score breakdown, both files' hashes, and the metric deltas."""
    reasons, score = [], 0
    breakdown = []   # [{signal, points, max, detail}]
    metrics = {}

    def add(signal, pts, mx, detail):
        nonlocal score
        score += pts
        breakdown.append({"signal": signal, "points": pts, "max": mx, "detail": detail})
        if pts:
            reasons.append(detail)

    # 0. DIRECT evidence: the debugger watched the packer decrypt code into memory and
    #    flip it writable->executable (W->X), and we dumped it at that instant. This is
    #    the strongest proof of unpacking — independent of the heuristics below.
    if dynamic and dynamic.get("payload_captured"):
        n = len(dynamic.get("wx_flips", []) or [])
        add("W->X decryption captured", 50, 50,
            f"debugger captured the payload at {n} write->execute flip(s) (direct unpack evidence)")
    else:
        add("W->X decryption captured", 0, 50, "no W->X flip captured dynamically")

    # 1. imports (the strongest signal — packing hides the IAT)
    pi = (packed.get("pe", {}) or {}).get("import_func_count", 0) or 0
    di = (dumped.get("pe", {}) or {}).get("import_func_count", 0) or 0
    metrics["imports_packed"], metrics["imports_dumped"] = pi, di
    if di > pi + 5:
        add("import table grew", 35, 35, f"imports {pi} -> {di} (real IAT revealed)")
    elif di > pi:
        add("import table grew", 10, 35, f"imports {pi} -> {di}")
    else:
        add("import table grew", 0, 35, f"imports {pi} -> {di} (no growth)")

    # 2. packer section names gone
    ps, ds = _secnames(packed), _secnames(dumped)
    gone = (ps & PACKER_SECTIONS) - ds
    metrics["packer_sections_packed"] = sorted(ps & PACKER_SECTIONS)
    if gone:
        add("packer sections removed", 25, 25, f"packer sections removed: {sorted(gone)}")
    elif (ds & PACKER_SECTIONS):
        add("packer sections removed", 0, 25,
            f"dump still carries packer section names {sorted(ds & PACKER_SECTIONS)} "
            "(raw region keeps original headers; content may still be unpacked)")
    else:
        add("packer sections removed", 0, 25, "no packer section names in either")

    # 3. entropy drop at entry (compressed/encrypted -> real code)
    pe_ent, de_ent = _ep_entropy(packed), _ep_entropy(dumped)
    metrics["ep_entropy_packed"], metrics["ep_entropy_dumped"] = pe_ent, de_ent
    if pe_ent and de_ent and pe_ent - de_ent >= 1.0:
        add("entropy dropped", 20, 20, f"entry-point entropy {pe_ent} -> {de_ent} (decompressed)")
    else:
        add("entropy dropped", 0, 20, f"entry-point entropy {pe_ent} -> {de_ent} (no significant drop)")

    # 4. new IOCs revealed in the dump
    pu = set((packed_ioc or {}).get("urls", []))
    pip = set((packed_ioc or {}).get("ips", []))
    new_urls = [u for u in (dumped_ioc or {}).get("urls", []) if u not in pu]
    new_ips = [i for i in (dumped_ioc or {}).get("ips", []) if i not in pip]
    metrics["new_urls"], metrics["new_ips"] = len(new_urls), len(new_ips)
    if new_urls or new_ips:
        add("hidden IOCs revealed", 25, 25,
            f"dump reveals {len(new_urls)} URL(s)/{len(new_ips)} IP(s) not in the packed file")
    else:
        add("hidden IOCs revealed", 0, 25, "no new network IOCs in the dump (may be encrypted config)")

    # 5. structurally a PE?
    dumped_is_pe = (dumped.get("pe", {}) or {}).get("arch") is not None and "error" not in dumped
    metrics["dump_is_valid_pe"] = dumped_is_pe
    add("valid PE image", 10 if dumped_is_pe else 0, 10,
        "dump parses as a valid PE image" if dumped_is_pe else "dump is a raw region (not a full PE)")

    score = min(score, 100)
    verdict = ("CONFIRMED_UNPACKED" if score >= 60 else
               "LIKELY_UNPACKED" if score >= 35 else
               "INCONCLUSIVE")
    ph = packed.get("hashes", {}) or {}
    dh = dumped.get("hashes", {}) or {}
    return {
        "verdict": verdict, "confidence": score, "reasons": reasons,
        "metrics": metrics, "breakdown": breakdown,
        "compared": {
            "packed": {"name": packed.get("name") or "packed sample",
                       "size": ph.get("size"), "md5": ph.get("md5"), "sha256": ph.get("sha256")},
            "unpacked": {"name": dumped_label,
                         "size": dh.get("size"), "md5": dh.get("md5"), "sha256": dh.get("sha256")},
        },
        "note": ("Compare these MD5s against your file set — a packer that writes copies of "
                 "itself will show the SAME hash across dropped files."),
    }
