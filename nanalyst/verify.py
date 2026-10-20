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
                  packed_ioc: dict | None = None, dumped_ioc: dict | None = None) -> dict:
    """packed/dumped = triage() dicts; *_ioc = memstatic.analyze() dicts (optional).
    Returns {verdict, confidence, reasons[], metrics}."""
    reasons, score = [], 0
    metrics = {}

    # 1. imports
    pi = (packed.get("pe", {}) or {}).get("import_func_count", 0) or 0
    di = (dumped.get("pe", {}) or {}).get("import_func_count", 0) or 0
    metrics["imports_packed"], metrics["imports_dumped"] = pi, di
    if di > pi + 5:
        score += 35
        reasons.append(f"import table grew {pi} -> {di} (real IAT revealed)")
    elif di > pi:
        score += 10
        reasons.append(f"import table grew {pi} -> {di}")

    # 2. packer section names gone
    ps, ds = _secnames(packed), _secnames(dumped)
    gone = (ps & PACKER_SECTIONS) - ds
    metrics["packer_sections_packed"] = sorted(ps & PACKER_SECTIONS)
    if gone:
        score += 25
        reasons.append(f"packer sections removed: {sorted(gone)}")
    elif (ds & PACKER_SECTIONS):
        reasons.append(f"NOTE: dump still carries packer section names {sorted(ds & PACKER_SECTIONS)} "
                       "(raw memory dump keeps original headers; content may still be unpacked)")

    # 3. entropy drop at entry
    pe_ent, de_ent = _ep_entropy(packed), _ep_entropy(dumped)
    metrics["ep_entropy_packed"], metrics["ep_entropy_dumped"] = pe_ent, de_ent
    if pe_ent and de_ent and pe_ent - de_ent >= 1.0:
        score += 20
        reasons.append(f"entry-point entropy dropped {pe_ent} -> {de_ent} (decompressed)")

    # 4. new IOCs revealed in the dump
    if dumped_ioc:
        pu = set((packed_ioc or {}).get("urls", []))
        pip = set((packed_ioc or {}).get("ips", []))
        new_urls = [u for u in dumped_ioc.get("urls", []) if u not in pu]
        new_ips = [i for i in dumped_ioc.get("ips", []) if i not in pip]
        metrics["new_urls"], metrics["new_ips"] = len(new_urls), len(new_ips)
        if new_urls or new_ips:
            score += 25
            reasons.append(f"dump reveals {len(new_urls)} URL(s)/{len(new_ips)} IP(s) hidden in the packed file")

    # 5. structurally a PE?
    dumped_is_pe = (dumped.get("pe", {}) or {}).get("arch") is not None and "error" not in dumped
    metrics["dump_is_valid_pe"] = dumped_is_pe
    if dumped_is_pe:
        score += 10
        reasons.append("dump parses as a valid PE image")

    score = min(score, 100)
    verdict = ("CONFIRMED_UNPACKED" if score >= 60 else
               "LIKELY_UNPACKED" if score >= 35 else
               "INCONCLUSIVE")
    return {"verdict": verdict, "confidence": score, "reasons": reasons, "metrics": metrics}
