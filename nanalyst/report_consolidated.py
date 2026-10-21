"""Build ONE consolidated analysis document (-> one PDF).

Merges the three previously-separate outputs into a single, well-structured report:
  * the full analyst report (verdict, deep static 3-stage, dynamic, dumps, IOCs, ATT&CK)
  * Appendix A — Methodology & reproducibility (how it was produced, deterministically)
  * Appendix B — Proof of Compromise (the evidence-gated verdict + ATT&CK mapping)

A short cover block (title, verdict, key facts) leads, then a table of contents, then
the body. The component markdowns are still written to disk for reference, but the PDF
is this single file.
"""
from __future__ import annotations

import time

from . import detailed_report, reproducibility, proof


def _cover(case: dict) -> list:
    st = case.get("stages", {})
    poc = st.get("proof_of_compromise", {}) or {}
    v = poc.get("verdict", {}) or {}
    tri = st.get("triage", {}) or {}
    cls = st.get("classification", {}) or {}
    L = [f"# Malware Analysis — {case.get('name')}", ""]
    _mc = st.get("malware_category") or {}
    if _mc.get("primary"):
        L.append(f"**Category:** {_mc['primary']}  ")
    L.append(f"**Triage hint:** {v.get('label','?')} ({v.get('confidence','?')}/100, basis: {v.get('basis','?')}); "
             f"a screening flag only  ")
    if cls.get("primary"):
        L.append(f"**Family:** {cls.get('primary')}  ")
    L.append(f"**Completeness:** {poc.get('completeness','?')}  ")
    L.append(f"**SHA-256:** `{case.get('sha256')}`  ")
    L.append(f"**Type:** {tri.get('filetype','?')} / {tri.get('arch','?')} · "
             f"{case.get('size',0):,} bytes  ")
    L.append(f"**Report generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}  ")
    for cav in v.get("caveats", []):
        L.append(f"> ⚠ {cav}  ")
    L.append("")
    L.append("**Contents:** 1) Analyst report · 2) Appendix A — Methodology & reproducibility "
             "· 3) Appendix B — Proof of compromise")
    L.append("")
    L.append("---")
    L.append("")
    return L


def build(case: dict) -> str:
    """Return the full consolidated markdown document."""
    parts = []
    parts += _cover(case)
    # the body report already opens with its own '# Malware Analysis Report' header; keep it
    parts.append(detailed_report.generate(case))
    parts.append("")
    parts.append("\n\\newpage\n")
    parts.append("# Appendix A — Methodology & reproducibility")
    parts.append("")
    parts.append(reproducibility.generate(case))
    parts.append("")
    parts.append("\n\\newpage\n")
    parts.append("# Appendix B — Proof of compromise")
    parts.append("")
    poc = case.get("stages", {}).get("proof_of_compromise") or proof.generate(case)
    parts.append(proof.to_markdown(poc))
    return "\n".join(parts)
