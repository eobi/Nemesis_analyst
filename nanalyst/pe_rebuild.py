"""Reconstruct a valid on-disk PE from a memory dump (the Scylla / PE-bear fix).

A module dumped from memory is in its LOADED (virtual) layout, but the PE header
still carries FILE (raw) offsets — so tools read the wrong bytes and the import
table/IAT don't resolve. The fix (done by hand in PE-bear, automated here):

  1. For each section, set PointerToRawData = VirtualAddress  (align raw to virtual)
  2. Set SizeOfRawData = VirtualSize                          (raw size = virtual size)
  3. Set OptionalHeader.ImageBase = the address it was dumped from
  4. Re-parse: the import directory now maps correctly, so imports/IAT appear.

This also sidesteps the "extra NUL bytes before .text in the section table" dump
artifact, because we rewrite the section headers from the parsed structure rather
than relying on their on-disk byte positions.
"""
from __future__ import annotations

from pathlib import Path

try:
    import pefile
except Exception:
    pefile = None


def rebuild(dump_path: str, image_base: int, out_path: str) -> dict:
    """Memory-align a dumped PE and fix ImageBase so imports resolve. Returns a
    summary incl. recovered imports. Non-destructive: writes a new file."""
    if pefile is None:
        return {"ok": False, "error": "pefile not available"}
    try:
        data = Path(dump_path).read_bytes()
        pe = pefile.PE(data=data, fast_load=True)
    except Exception as exc:
        return {"ok": False, "error": f"not a parseable PE: {exc}"}

    before = {"image_base": hex(pe.OPTIONAL_HEADER.ImageBase)}
    # 1-3: align each section's raw layout to its virtual layout + fix ImageBase
    for s in pe.sections:
        vsize = s.Misc_VirtualSize or s.SizeOfRawData
        s.PointerToRawData = s.VirtualAddress
        s.SizeOfRawData = vsize
    if image_base:
        pe.OPTIONAL_HEADER.ImageBase = int(image_base)

    try:
        pe.write(out_path)
    except Exception as exc:
        return {"ok": False, "error": f"write failed: {exc}"}

    # 4: re-parse the rebuilt file and read the import table
    imports, dlls = [], []
    try:
        pe2 = pefile.PE(out_path)
        pe2.parse_data_directories()
        for d in getattr(pe2, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = d.dll.decode("latin-1", "replace") if d.dll else "?"
            dlls.append(dll)
            for imp in d.imports:
                nm = imp.name.decode("latin-1", "replace") if imp.name else f"ordinal_{imp.ordinal}"
                imports.append(f"{dll}!{nm}")
        pe2.close()
    except Exception as exc:
        return {"ok": True, "out": out_path, "imports": 0, "dlls": [],
                "note": f"rebuilt but import parse failed: {exc}", "before": before}

    return {"ok": True, "out": out_path, "image_base": hex(int(image_base)) if image_base else before["image_base"],
            "imports": len(imports), "dll_count": len(set(dlls)),
            "dlls": sorted(set(dlls))[:20], "sample_imports": imports[:40], "before": before}


def rebuild_if_pe(dump_path: str, image_base: int, out_dir: Path) -> dict | None:
    """Rebuild only if the dump starts with an MZ header. Returns the summary or None."""
    try:
        if Path(dump_path).read_bytes(2) if False else open(dump_path, "rb").read(2) != b"MZ":
            return None
    except Exception:
        return None
    out = Path(out_dir) / (Path(dump_path).stem + "_rebuilt.exe")
    return rebuild(dump_path, image_base, str(out))
