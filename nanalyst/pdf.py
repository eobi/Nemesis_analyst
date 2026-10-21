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


def _fix_tables(text: str) -> str:
    """A pipe table only parses when a blank line precedes it; several report sections put the header row
    straight after a sentence, which renders as raw '|' text in the PDF. Insert the blank line."""
    import re
    sep = re.compile(r"^\|[\s:|\-]+\|\s*$")
    lines, out = text.split("\n"), []
    for i, ln in enumerate(lines):
        if (ln.startswith("|") and i + 1 < len(lines) and sep.match(lines[i + 1])
                and out and out[-1].strip() and not out[-1].startswith("|")):
            out.append("")
        out.append(ln)
    return "\n".join(out)


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
    try:                                   # render a table-fixed copy; the original markdown is left as written
        fixed = md.with_name("." + md.stem + ".pdfsrc.md")
        fixed.write_text(_fix_tables(md.read_text()))
        src = fixed
    except Exception:
        fixed, src = None, md
    here = Path(__file__).resolve().parent
    cmd = [pandoc, str(src), "-f", "gfm", "-o", str(pdf), *_PREAMBLE,
           "--lua-filter", str(here / "pdf_filter.lua"), "-H", str(here / "pdf_header.tex")]
    if engine:
        cmd += ["--pdf-engine", Path(engine).name]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if (not pdf.exists() or r.returncode != 0) and "--lua-filter" in cmd:
            # a filter/header problem must never cost the report: retry plain
            plain = [c for i, c in enumerate(cmd) if c not in ("--lua-filter", "-H")
                     and cmd[i - 1] not in ("--lua-filter", "-H")]
            subprocess.run(plain, capture_output=True, timeout=timeout)
    except Exception:
        return None
    finally:
        if fixed is not None:
            fixed.unlink(missing_ok=True)
    return str(pdf) if pdf.exists() else None
