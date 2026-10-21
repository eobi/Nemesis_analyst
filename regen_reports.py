#!/usr/bin/env python3
"""Regenerate REPORT.md / METHODOLOGY.md / proof_of_compromise.md (+ PDFs) for
every case from its stored case.json — no VM needed. Pure re-render, so it picks
up report/verdict code changes without re-running the debugger.

Usage: python3 regen_reports.py [cases/<dir> ...]   (default: all under cases/)
"""
import json, sys
from pathlib import Path

from nanalyst import proof, detailed_report, reproducibility
from nanalyst import pdf as _pdf


def regen(case_dir: Path) -> str:
    cj = case_dir / "case.json"
    if not cj.exists():
        return f"skip {case_dir.name} (no case.json)"
    case = json.loads(cj.read_text())
    st = case.setdefault("stages", {})
    try:                                   # derived stages are recomputed from saved data (no VM needed)
        from nanalyst import category_guide, crypto_analysis, dump_analysis
        from nanalyst import attribution
        fps = dict(st.get("author_fingerprints") or {})
        if case.get("sample") and Path(case["sample"]).is_file():
            fps["packed sample"] = attribution.fingerprints(case["sample"])
        for f in sorted((case_dir / "dumps").glob("*")):
            if f.is_file() and f.read_bytes()[:2] == b"MZ":
                x = attribution.fingerprints(str(f))
                if x:
                    fps[f.name] = x
        st["author_fingerprints"] = fps
        st["author_links"] = {"links": attribution.link_cases(fps, str(case_dir.parent), exclude=case_dir.name)[:25]}
        st["malware_category"] = category_guide.categorize(case)
        st["file_crypto"] = crypto_analysis.analyze_case(case, case_dir / "decryptor")
        fs = sorted((f for f in (case_dir / "dumps").glob("*") if f.is_file() and f.name != "DUMPS.md"), key=lambda f: f.stat().st_mtime)
        if fs:
            st["dump_analysis"] = dump_analysis.analyze_dumps([{"name": f.name, "path": str(f), "order": i} for i, f in enumerate(fs)])
    except Exception as exc:
        print(f"   (derived stages skipped: {exc})")
    pm = case_dir / "artifacts" / "run" / "pm.csv"
    if pm.exists() and not st.get("procmon_summary"):
        from nanalyst import procmon_summary
        st["procmon_summary"] = procmon_summary.summarize(str(pm), "malware.exe")
    poc = proof.generate(case)
    case.setdefault("stages", {})["proof_of_compromise"] = poc
    cj.write_text(json.dumps(case, indent=2))
    (case_dir / "proof_of_compromise.md").write_text(proof.to_markdown(poc))
    (case_dir / "REPORT.md").write_text(detailed_report.generate(case))
    (case_dir / "METHODOLOGY.md").write_text(reproducibility.generate(case))
    from nanalyst import report_consolidated
    (case_dir / "ANALYSIS.md").write_text(report_consolidated.build(case))
    for name in ("ANALYSIS.md", "REPORT.md", "METHODOLOGY.md", "proof_of_compromise.md"):
        try:
            _pdf.md_to_pdf(str(case_dir / name))
        except Exception:
            pass
    v = poc["verdict"]
    return f"ok   {case_dir.name} :: {v['label']} {v['confidence']}/100 ({poc['completeness']})"


def main():
    args = sys.argv[1:]
    dirs = [Path(a) for a in args] if args else sorted(p for p in Path("cases").iterdir() if p.is_dir())
    for d in dirs:
        try:
            print(regen(d))
        except Exception as exc:
            print(f"FAIL {d.name}: {exc}")


if __name__ == "__main__":
    main()
