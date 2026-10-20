"""Triage: combine DIE + PE profile into one verdict with a packer assessment.

This is Phase 0 of the pipeline. It does NOT execute the sample. It produces the
structured facts and a packer-likelihood score the AI brain (later phase) uses to
decide the next action (unpack, deep static, dynamic).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from .tools import die as die_tool
from .tools import pe as pe_tool


def _hashes(path: str) -> dict:
    data = Path(path).read_bytes()
    return {
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def assess_packing(die: dict, pe: dict) -> dict:
    """Heuristic packer assessment combining DIE signatures and PE structure.

    Returns {likely_packed, confidence(0-100), packer, reasons[]}.
    """
    reasons: list[str] = []
    score = 0
    packer_name = None

    # 1. DIE signature is the strongest single signal.
    if die.get("available"):
        if die.get("packer"):
            packer_name = die["packer"]
            score += 60
            reasons.append(f"DIE identified packer: {die['packer']}")
        if die.get("protector"):
            packer_name = packer_name or die["protector"]
            score += 60
            reasons.append(f"DIE identified protector: {die['protector']}")

    # 2. Entry-point section entropy (encrypted/compressed code).
    ep_sec = pe.get("entrypoint_section")
    for sec in pe.get("sections", []):
        if sec["name"] == ep_sec and sec["entropy"] >= 7.0:
            score += 25
            reasons.append(
                f"entry-point section '{ep_sec}' entropy {sec['entropy']} (>=7.0)"
            )
        # Writable+executable section = classic unpacking stub target.
        if sec["w_and_x"]:
            score += 15
            reasons.append(f"section '{sec['name']}' is writable AND executable")
        if sec["uncommon_name"] and sec["entropy"] >= 7.0:
            score += 10
            reasons.append(
                f"uncommon high-entropy section '{sec['name']}' ({sec['entropy']})"
            )

    # 3. Few imports + dynamic resolution = imports resolved at runtime.
    nfuncs = pe.get("import_func_count", 0)
    dyn = pe.get("suspicious_apis", {}).get("dynamic_resolution")
    if nfuncs < 15 and dyn:
        score += 20
        reasons.append(
            f"only {nfuncs} imported functions + dynamic resolution {dyn}"
        )
    elif nfuncs < 8:
        score += 15
        reasons.append(f"very few imports ({nfuncs}) — imports may be hidden")

    # 4. UPX section names are a dead giveaway.
    names = {s["name"].upper() for s in pe.get("sections", [])}
    if {"UPX0", "UPX1"} & names:
        packer_name = packer_name or "UPX"
        score += 40
        reasons.append("UPX section names present (UPX0/UPX1)")

    # 5. Entry point in a writable section.
    for sec in pe.get("sections", []):
        if sec["contains_ep"] and sec["write"]:
            score += 15
            reasons.append(f"entry point lies in writable section '{sec['name']}'")

    score = min(score, 100)
    return {
        "likely_packed": score >= 40,
        "confidence": score,
        "packer": packer_name,
        "reasons": reasons,
    }


def suggest_next(packing: dict, pe: dict) -> dict:
    """Rule-based next-step suggestion (placeholder for the AI brain in Phase 3)."""
    if not packing["likely_packed"]:
        return {"action": "static_deep", "why": "no strong packing signal; go to Ghidra"}
    if (packing["packer"] or "").upper() == "UPX":
        return {"action": "unpack_upx", "why": "UPX detected; `upx -d` then re-triage"}
    return {
        "action": "unpack_dynamic",
        "why": "packed by unknown/custom packer; needs dynamic unpack (x64dbg/PE-sieve) in the VM",
    }


def triage(path: str) -> dict:
    """Full Phase-0 triage of a single file. No execution."""
    pe = pe_tool.profile(path)
    if "error" in pe:
        return {"path": path, "error": pe["error"], "hashes": _hashes(path)}

    die = die_tool.run_die(path)
    packing = assess_packing(die, pe)

    # Prefer DIE's arch; fall back to the PE header.
    arch = die.get("arch") or pe.get("arch")

    return {
        "path": path,
        "hashes": _hashes(path),
        "arch": arch,
        "kind": pe.get("kind"),
        "filetype": die.get("filetype"),
        "compiler": die.get("compiler"),
        "linker": die.get("linker"),
        "die_available": die.get("available", False),
        "die_error": die.get("error"),
        "packing": packing,
        "pe": pe,
        "next": suggest_next(packing, pe),
    }
