"""Ghidra static worker.

Runs Ghidra headless with the NemesisStatic.java script and returns the parsed
JSON: functions, categorized strings, suspicious-API xrefs, control-flow
anomalies, and dynamic hints. STATIC — never executes the sample.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from ..audit import audited

_SCRIPTS = Path(__file__).resolve().parent / "ghidra_scripts"


def find_headless() -> str | None:
    env = os.environ.get("NANALYST_GHIDRA")
    candidates = [
        env,
        str(Path.home() / "Applications/GhidraApp/support/analyzeHeadless"),
        shutil.which("analyzeHeadless"),
    ]
    for c in candidates:
        if c and Path(c).exists():
            return c
    return None


@audited("ghidra", category="static")
def analyze(sample_path: str, timeout: int = 600) -> dict:
    headless = find_headless()
    if not headless:
        return {"available": False, "error": "analyzeHeadless not found (set NANALYST_GHIDRA)"}

    proj = tempfile.mkdtemp(prefix="nanalyst_gh_")
    out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    out_path = out.name
    out.close()
    try:
        cmd = [
            headless, proj, "nanalyst",
            "-import", sample_path,
            "-overwrite",
            "-scriptPath", str(_SCRIPTS),
            "-postScript", "NemesisStatic.java", out_path,
            "-deleteProject",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if not Path(out_path).exists() or Path(out_path).stat().st_size == 0:
            tail = (proc.stderr or proc.stdout or "")[-800:]
            return {"available": False, "error": "no output from Ghidra script", "log_tail": tail}
        data = json.loads(Path(out_path).read_text())
        data["available"] = True
        return data
    except subprocess.TimeoutExpired:
        return {"available": False, "error": f"Ghidra timed out after {timeout}s"}
    except json.JSONDecodeError as exc:
        return {"available": False, "error": f"bad JSON from Ghidra script: {exc}"}
    finally:
        shutil.rmtree(proj, ignore_errors=True)
        try:
            os.unlink(out_path)
        except OSError:
            pass
