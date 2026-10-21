"""Audit the AI's static claims against the deterministic facts.

The AI interprets; it can also overclaim (measured on a clean Microsoft binary: it called a
.text section "encrypted" at entropy 6.27, which is ordinary compiled code). So every claim
that can be checked against evidence we computed ourselves is checked, and the report shows
which claims are SUPPORTED and which are NOT — unsupported claims are never silently trusted.
"""
from __future__ import annotations

import re

HIGH_H = 7.0          # entropy at/above which "encrypted/compressed" is a defensible claim
_URL = re.compile(r"(?i)(https?://|ftp://|\b[a-z0-9-]+(\.[a-z0-9-]+)+\.(com|net|org|ru|cn|info|biz|xyz|top|pw|cc|io|co|me|su|onion|tk|ml|ga|cf|gq|site|online|club|shop|app|dev)\b|\b\d{1,3}(\.\d{1,3}){3}\b)")


def _match_sections(where: str, em: dict) -> list:
    w = (where or "").lower()
    return [s for s in (em.get("sections") or [])
            if s["name"].lower() and (s["name"].lower() in w or w in s["name"].lower())]


def check_encrypted_regions(claims: list, em: dict) -> list:
    out = []
    for c in (claims or []):
        if not isinstance(c, dict):
            continue
        where = str(c.get("where", ""))
        secs = _match_sections(where, em)
        hi_regions = [r for r in (em.get("regions") or [])
                      if (r.get("section") or "").lower() in where.lower() or (r.get("rva") and str(r["rva"]).lower() in where.lower())]
        if any(s["entropy"] >= HIGH_H for s in secs) or hi_regions:
            basis = ("section entropy " + ", ".join(f"{s['name']}={s['entropy']}" for s in secs)) if secs else \
                    f"{len(hi_regions)} high-entropy region(s) in the entropy map"
            out.append({"claim": where, "likely": c.get("likely"), "supported": True, "basis": basis})
        elif any(s.get("runtime_expanded") for s in secs):
            out.append({"claim": where, "likely": c.get("likely"), "supported": True,
                        "basis": "section is runtime-expanded (virtual >> raw): filled in at runtime"})
        elif secs:
            out.append({"claim": where, "likely": c.get("likely"), "supported": False,
                        "basis": "entropy " + ", ".join(f"{s['name']}={s['entropy']}" for s in secs)
                                 + f" is below {HIGH_H} — normal for compiled code"})
        else:
            out.append({"claim": where, "likely": c.get("likely"), "supported": False,
                        "basis": "does not match any section, region or resource in the entropy map"})
    return out


_QUAD = re.compile(r"^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\s*$")


def _version_like(text: str, known_versions) -> bool:
    """A bare dotted quad that is really a version number (manifest/VERSIONINFO), not an address."""
    m = _QUAD.match(text)
    if not m:
        return False
    o = [int(x) for x in m.groups()]
    return (text.strip() in set(known_versions or [])) or o[2:] == [0, 0] or o[3] == 0 and o[0] < 20


def check_leads(leads: list, known_versions=None) -> list:
    """A URL/C2 lead must actually contain a URL, domain or IP; 'unknown', 'none' and bare
    version numbers (e.g. 5.1.0.0 from a manifest) are not leads."""
    out = []
    for l in (leads or []):
        text = str(l)
        if _version_like(text, known_versions):
            out.append({"lead": text[:200], "supported": False,
                        "basis": "looks like a version number (e.g. from a manifest), not an address"})
            continue
        ok = bool(_URL.search(text))
        out.append({"lead": text[:200], "supported": ok,
                    "basis": "contains a URL/domain/IP" if ok else "no URL, domain or IP in it — not a lead"})
    return out


def check_plan_regions(regions: list, em: dict) -> list:
    """A watch region is justified if it overlaps a high-entropy region, or lies in a section that
    is high-entropy or runtime-expanded. (Unjustified regions are still harmless to dump, but are
    labelled so the report does not pass the AI's guess off as evidence.)"""
    out = []
    secs = em.get("sections") or []
    for w in (regions or []):
        rva, size = int(w["rva"]), int(w["size"])
        why = None
        for r in (em.get("regions") or []):
            try:
                r_rva = int(str(r.get("rva")), 16)
            except Exception:
                continue
            if r_rva < rva + size and rva < r_rva + int(r["size"]):
                why = f"overlaps a high-entropy {r.get('kind')} (H={r['entropy']})"; break
        if not why:
            for sec in secs:
                s_rva, s_len = int(sec["rva"], 16), max(sec["vsize"], sec["raw_size"])
                if s_rva <= rva < s_rva + s_len and (sec["entropy"] >= HIGH_H or sec.get("runtime_expanded")):
                    why = f"inside {sec['name']} (H={sec['entropy']}{', runtime-expanded' if sec.get('runtime_expanded') else ''})"; break
        out.append({"rva": hex(rva), "supported": bool(why), "basis": why or "no high-entropy or runtime-expanded content there"})
    return out


def audit(assessment: dict, entropy_map: dict, known_versions=None) -> dict:
    """Return {'encrypted_regions': [...], 'url_leads': [...], 'unsupported': n}."""
    er = check_encrypted_regions((assessment or {}).get("encrypted_regions"), entropy_map or {})
    ul = check_leads((assessment or {}).get("url_leads"), known_versions)
    return {"encrypted_regions": er, "url_leads": ul,
            "unsupported": sum(1 for x in er + ul if not x["supported"])}
