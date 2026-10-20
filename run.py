#!/usr/bin/env python3
"""Nemesis Analyst — Phase 0 triage CLI.

Usage:
    python3 run.py <file> [<file> ...]
    python3 run.py --json <file>        # emit JSON instead of a report
    python3 run.py <dir>                # triage every file in a directory

STATIC ONLY. This never executes the sample. Safe to run on the host.
"""
import json
import sys
from pathlib import Path

from nanalyst.triage import triage
from nanalyst.report import render


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
    as_json = "--json" in argv
    targets = [a for a in argv if a != "--json"]
    if not targets:
        print(__doc__)
        return 1
    results = [triage(t) for t in iter_targets(targets)]
    outdir = Path("out")
    outdir.mkdir(exist_ok=True)
    for r in results:
        name = Path(r["path"]).name
        (outdir / f"{name}.triage.json").write_text(json.dumps(r, indent=2))
    if as_json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(render(r))
            print()
        print(f"[saved {len(results)} JSON report(s) to ./out/]")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
