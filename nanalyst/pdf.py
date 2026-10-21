"""Render a Markdown report to PDF (pandoc + a LaTeX engine).

Used to produce shareable REPORT.pdf / METHODOLOGY.pdf next to the .md files.
Falls back gracefully: if pandoc or an engine is missing, returns None (the .md
is still there).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

_PREAMBLE = (
    "-V", "geometry:margin=0.8in",
    "-V", "fontsize=9pt",
    "-V", "colorlinks=true",
    "-V", "linkcolor=blue",
)


def md_to_pdf(md_path: str, pdf_path: str | None = None, timeout: int = 240) -> str | None:
    md = Path(md_path)
    if not md.exists():
        return None
    pdf = Path(pdf_path) if pdf_path else md.with_suffix(".pdf")
    pandoc = shutil.which("pandoc")
    if not pandoc:
        return None
    engine = (shutil.which("tectonic") or shutil.which("xelatex")
              or shutil.which("pdflatex") or shutil.which("wkhtmltopdf"))
    # parse as GitHub-flavored markdown so special chars (backslashes, $, arrows in
    # debugger replay steps) are escaped rather than read as raw LaTeX commands.
    cmd = [pandoc, str(md), "-f", "gfm", "-o", str(pdf), *_PREAMBLE]
    if engine:
        cmd += ["--pdf-engine", Path(engine).name]
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception:
        return None
    return str(pdf) if pdf.exists() else None
