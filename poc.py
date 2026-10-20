#!/usr/bin/env python3
"""Regenerate the Proof of Compromise from a saved case.
Usage: python3 poc.py <sha256 | path/to/case.json>
"""
import json, sys
from pathlib import Path
from nanalyst import proof

def main(argv):
    if not argv:
        print(__doc__); return 1
    arg = argv[0]
    p = Path(arg)
    if not p.exists():
        p = Path("cases") / arg / "case.json"
    if not p.exists():
        print(f"case not found: {arg}"); return 1
    case = json.loads(p.read_text())
    print(proof.to_markdown(proof.generate(case)))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
