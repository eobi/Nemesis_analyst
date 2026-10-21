#!/usr/bin/env python3
"""Batch dynamic unpack — hand it a folder or a list of samples; each one is
auto-loaded into x32dbg (push + debug_stop + debug_init) and fully analyzed in
turn, with its own organized case folder + REPORT/PDF. No manual GUI loading.

x32dbg is 32-bit, so only PE32 (x86) samples run here; PE32+ (x64) samples are
listed for a separate x64dbg pass.

Trade-off: all samples share ONE live VM session (fast, no revert between each).
For maximum isolation on a sensitive sample, run it alone and revert after.

Usage:
    python3 batch_dynamic.py <folder | sample.exe> [more ...] [--detonate]
"""
import subprocess, sys
from pathlib import Path

from nanalyst.triage import triage


def arch_of(p: Path):
    try:
        if open(p, "rb").read(2) != b"MZ":
            return None
        return "x64" if "64" in str(triage(str(p)).get("arch", "")) else "x86"
    except Exception:
        return None


def main():
    detonate = "--detonate" in sys.argv
    args = [x for x in sys.argv[1:] if not x.startswith("--")]
    if not args:
        print(__doc__); return 1
    samples = []
    for a in args:
        p = Path(a)
        if p.is_dir():
            samples += sorted(f for f in p.rglob("*")
                              if f.is_file() and f.suffix.lower() in (".exe", ".bin", ".dll", ".dat"))
        elif p.is_file():
            samples.append(p)

    x86, skipped = [], []
    for s in samples:
        a = arch_of(s)
        (x86 if a == "x86" else skipped).append((s, a))

    print(f"[batch] {len(x86)} x86 sample(s) to run via x32dbg; "
          f"{len(skipped)} skipped (non-PE32 / x64)")
    results = []
    for i, (s, _) in enumerate(x86, 1):
        print(f"\n{'#'*70}\n# [{i}/{len(x86)}] {s.name}\n{'#'*70}")
        cmd = [sys.executable, "unpack.py", str(s)] + (["--detonate"] if detonate else [])
        rc = subprocess.run(cmd).returncode
        results.append((s.name, rc))

    print("\n================ BATCH SUMMARY ================")
    for n, rc in results:
        print(f"  {'OK  ' if rc == 0 else f'FAIL({rc})'}  {n}")
    for s, a in skipped:
        print(f"  SKIP  {s.name}  ({a or 'not PE'} — x64 needs x64dbg)")
    print(f"\n{sum(1 for _, rc in results if rc == 0)}/{len(x86)} analyzed OK. "
          "VM is now dirty — revert to clean-baseline before the next batch.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
