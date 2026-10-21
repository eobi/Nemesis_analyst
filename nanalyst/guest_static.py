"""Guest-side static + deobfuscation worker (Windows, over SSH).

For samples with obfuscated sections: DIE identifies the file (and .NET), de4dot
detects the obfuscator and produces a deobfuscated/cleaned assembly, and we report
what changed. STATIC — de4dot rewrites the assembly's metadata; it does not run
the sample. Complements the Mac-side static workers (DIE/pefile/Ghidra).
"""
from __future__ import annotations

import json
import ntpath
import re
from .audit import audited

DIEC = r"C:\Tools\die\diec.exe"


def _die(guest, sample: str) -> dict:
    rc, out, err = guest.run(f'"{DIEC}" -j "{sample}"', timeout=120)
    try:
        raw = json.loads(out)
    except Exception:
        return {"available": False, "error": (err or out or "")[:200]}
    res = {"available": True, "filetype": None, "compiler": None,
           "linker": None, "library": None, "packer": None, "dotnet": False}
    for det in raw.get("detects", []):
        res["filetype"] = res["filetype"] or det.get("filetype")
        for v in det.get("values", []):
            t = (v.get("type") or "").lower()
            label = f"{v.get('name','')} {v.get('version','')}".strip()
            if t in res and not res[t]:
                res[t] = label
            if ".NET" in (v.get("name", "") + v.get("string", "")):
                res["dotnet"] = True
    return res


def _de4dot_detect(guest, sample: str) -> str:
    rc, out, err = guest.run(f'de4dot -d "{sample}"', timeout=180)
    m = re.search(r"Detected (.+?) \(", out or "")
    return m.group(1).strip() if m else "unknown"


def _cleaned_path(sample: str) -> str:
    d = ntpath.dirname(sample)
    base = ntpath.basename(sample)
    if "." in base:
        name, ext = base.rsplit(".", 1)
        return f"{d}\\{name}-cleaned.{ext}"
    return f"{d}\\{base}-cleaned"


@audited("de4dot", category="static")
def analyze(guest, sample: str) -> dict:
    die = _die(guest, sample)
    result = {
        "sample": sample,
        "die": die,
        "dotnet": die.get("dotnet", False),
        "obfuscator": None,
        "deobfuscated": None,
        "de4dot_log": None,
    }
    if not die.get("dotnet"):
        result["note"] = "not a .NET assembly; use the native unpacking path (x64dbg/Ghidra)"
        return result

    result["obfuscator"] = _de4dot_detect(guest, sample)
    rc, out, err = guest.run(f'de4dot "{sample}"', timeout=600)
    result["de4dot_log"] = (out or err or "")[-1200:]

    cleaned = _cleaned_path(sample)
    folder = ntpath.dirname(sample)
    _, listing, _ = guest.run(f'dir /b "{folder}"', timeout=60)
    if "-cleaned" in listing:
        result["deobfuscated"] = cleaned
        # quick before/after readable-string count as a deobfuscation signal
        result["strings_after"] = _ascii_count(guest, cleaned)
        result["strings_before"] = _ascii_count(guest, sample)
    return result


def _ascii_count(guest, path: str) -> int:
    """Count printable 'strings'-like tokens via DIE's string scan (rough signal)."""
    rc, out, err = guest.run(f'"{DIEC}" -j "{path}"', timeout=60)
    return len(out or "")  # proxy: cleaned assemblies typically expose more metadata
