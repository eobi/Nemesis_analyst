"""Detect It Easy adapter.

Wraps the `diec` console binary and normalizes its JSON output into a small,
stable dict the rest of the pipeline consumes. DIE is optional: if the binary
cannot be found or run, callers fall back to the LIEF/pefile heuristics in pe.py.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from ..audit import audited

# Project root = two levels up from this file (nanalyst/tools/die.py -> project).
_ROOT = Path(__file__).resolve().parents[2]
_BUNDLED = _ROOT / "vendor" / "die" / "die.app" / "Contents" / "MacOS" / "diec"


def find_diec() -> str | None:
    """Locate the diec binary: env override, then bundled, then PATH."""
    env = os.environ.get("NANALYST_DIEC")
    if env and Path(env).exists():
        return env
    if _BUNDLED.exists():
        return str(_BUNDLED)
    return shutil.which("diec")


@audited("diec", category="static")
def run_die(path: str, timeout: int = 60) -> dict:
    """Run DIE on `path`. Returns a normalized dict.

    Shape: {available, filetype, arch, compiler, linker, packer, protector,
            raw, error}. `available` is False when DIE could not run.
    """
    diec = find_diec()
    if not diec:
        return {"available": False, "error": "diec not found"}

    try:
        proc = subprocess.run(
            [diec, "-j", path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"available": False, "error": "diec timed out"}
    except OSError as exc:  # e.g. Rosetta missing for an x86_64 build
        return {"available": False, "error": f"diec failed to launch: {exc}"}

    if proc.returncode != 0 and not proc.stdout.strip():
        return {"available": False, "error": proc.stderr.strip()[:200] or "diec error"}

    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"available": False, "error": "diec produced non-JSON output"}

    return _normalize(raw)


def _normalize(raw: dict) -> dict:
    """Flatten DIE's nested detects/values into typed buckets."""
    out = {
        "available": True,
        "filetype": None,
        "arch": None,
        "compiler": None,
        "linker": None,
        "packer": None,
        "protector": None,
        "installer": None,
        "library": None,
        "all": [],
        "raw": raw,
    }
    detects = raw.get("detects") or []
    for det in detects:
        if out["filetype"] is None and det.get("filetype"):
            out["filetype"] = det["filetype"]
        for val in det.get("values", []):
            vtype = (val.get("type") or "").lower()
            name = val.get("name") or ""
            version = val.get("version") or ""
            label = f"{name} {version}".strip()
            out["all"].append({"type": vtype, "name": name, "version": version})
            # First hit of each kind wins.
            if vtype in out and out[vtype] is None:
                out[vtype] = label
    # DIE encodes 32/64 in filetype (PE32 vs PE32+ / PE64).
    ft = (out["filetype"] or "").upper()
    if "PE32+" in ft or "PE64" in ft:
        out["arch"] = "x64"
    elif "PE32" in ft:
        out["arch"] = "x86"
    return out
