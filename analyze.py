#!/usr/bin/env python3
"""Nemesis Analyst — static pipeline (Phase 0 triage + Phase 2 Ghidra static).

Usage:
    python3 analyze.py <file> [<file> ...]
    python3 analyze.py --no-ghidra <file>     # triage only
    python3 analyze.py <dir>                   # every file in a directory

STATIC ONLY. Never executes the sample. Builds a case under ./cases/<sha256>/.
"""
import sys
from pathlib import Path

from nanalyst.triage import triage
from nanalyst.report import render, render_static
from nanalyst.case import Case
from nanalyst.tools import ghidra_worker
from nanalyst import proof


def iter_targets(args):
    for a in args:
        p = Path(a)
        if p.is_dir():
            for f in sorted(p.iterdir()):
                if f.is_file():
                    yield str(f)
        elif p.is_file():
            yield str(p)
        else:
            print(f"! skip (not found): {a}", file=sys.stderr)


def main(argv):
    use_ghidra = "--no-ghidra" not in argv
    targets = [a for a in argv if not a.startswith("--")]
    if not targets:
        print(__doc__)
        return 1

    for tgt in iter_targets(targets):
        case = Case(tgt)
        t = triage(tgt)
        case.add("triage", t, state="triaged")
        print(render(t))
        if t.get("error"):
            print()
            continue
        if use_ghidra:
            print("   [running Ghidra headless static analysis ...]")
            g = ghidra_worker.analyze(tgt)
            case.add("static_ghidra", g, state="static_done")
            print(render_static(g))
        poc = proof.generate(case.data)
        md = proof.to_markdown(poc)
        (case.dir / "proof_of_compromise.md").write_text(md)
        case.add("proof_of_compromise", poc, state="reported")
        print()
        print(md)
        print(f"   case: {case.path}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
