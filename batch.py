#!/usr/bin/env python3
"""Batch end-to-end LOCAL analysis over a folder of samples (Phase 7 groundwork).

Per sample, runs the full automatable pipeline into an organized analysis folder:
  triage -> attribution -> UPX auto-unpack + verify -> framework source recovery
  (AutoIt/...) -> Ghidra static -> classification -> crypto detect + decryptor
  -> Proof of Compromise + REPORT.md + manifest, with a per-tool audit ledger.

Does NOT pull from a VM, run guest-side de4dot, drive the live x64dbg unpacker, or
detonate — those need the analysis instance / manual x64dbg and are run per-sample.
This path is host-safe (never executes a sample).

Usage:
    python3 batch.py [folder] [--no-ghidra] [--workroot cases]
"""
import argparse, subprocess, sys, time, traceback
from pathlib import Path

from nanalyst.case import Case
from nanalyst.runlog import RunLog
from nanalyst import (triage as T, attribution, framework_extract as fx, classify,
                      decryptor, verify, proof, detailed_report, audit)
from nanalyst.tools import ghidra_worker

DEFAULT_FOLDER = "samples"
import shutil as _shutil
UPX = _shutil.which("upx") or "upx"


def is_pe(p: Path) -> bool:
    try:
        with open(p, "rb") as f:
            return f.read(2) == b"MZ"
    except Exception:
        return False


def analyze_one(sample: str, workroot: str, do_ghidra: bool) -> dict:
    row = {"sample": Path(sample).name, "errors": []}
    case = Case(sample, workroot=workroot)
    row["folder"] = case.dir.name
    rl = RunLog(case.logs_dir)
    ta = audit.ToolAudit(case.logs_dir); audit.activate(ta)

    def step(name, fn, store=None):
        try:
            v = fn()
            if store and v is not None:
                case.add(store, v)
            return v
        except Exception as e:
            row["errors"].append(f"{name}: {e!r}")
            rl.log("batch", f"ERR {name}", repr(e))
            return None

    t = step("triage", lambda: T.triage(sample), "triage")
    step("attribution", lambda: attribution.analyze(sample), "attribution")

    analysis_file = sample
    pk = ((t or {}).get("packing") or {}).get("packer") or ""
    if "upx" in pk.lower():
        unp = case.dumps_dir / "unpacked.exe"
        step("upx", lambda: subprocess.run([UPX, "-d", sample, "-o", str(unp)], capture_output=True))
        if unp.exists():
            analysis_file = str(unp)
            t2 = step("triage_unpacked", lambda: T.triage(analysis_file), "triage_unpacked")
            if t2:
                step("verify", lambda: verify.verify_unpack(t, t2), "verify_unpack")

    det = step("fw_detect", lambda: fx.detect(analysis_file))
    if det and det.get("framework"):
        step("fw_extract", lambda: fx.host_extract(det["framework"], analysis_file, case.source_dir),
             "framework_extract")

    if do_ghidra:
        step("ghidra", lambda: ghidra_worker.analyze(analysis_file, timeout=480), "static_ghidra")

    step("classify", lambda: classify.classify(case.data), "classification")
    step("crypto", lambda: decryptor.build_all(case.data, case.decryptor_dir, log=lambda m: None),
         "crypto_recovery")

    pocd = step("proof", lambda: proof.generate(case.data))
    if pocd:
        case.add("proof_of_compromise", pocd)
        (case.dir / "proof_of_compromise.md").write_text(proof.to_markdown(pocd))
        row["verdict"] = pocd["verdict"]["label"]
    step("report", lambda: (case.dir / "REPORT.md").write_text(detailed_report.generate(case.data)))
    case.add("tool_audit", ta.summary())
    audit.activate(None)
    case.write_manifest()

    cls = case.data["stages"].get("classification", {})
    vf = case.data["stages"].get("verify_unpack", {})
    row.update({"family": cls.get("primary", "?"),
                "framework": (det or {}).get("framework", "-"),
                "verify": vf.get("verdict", "-"),
                "crypto": [s["algo"] for s in (case.data["stages"].get("crypto_recovery", {}) or {}).get("schemes", [])],
                "ghidra_funcs": (case.data["stages"].get("static_ghidra", {}) or {}).get("function_count", "-")})
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder", nargs="?", default=DEFAULT_FOLDER)
    ap.add_argument("--no-ghidra", action="store_true")
    ap.add_argument("--workroot", default="cases")
    a = ap.parse_args()

    folder = Path(a.folder)
    samples = sorted(p for p in folder.rglob("*")
                     if p.is_file() and p.suffix.lower() in (".exe", ".bin", ".dll", ".dat")
                     and is_pe(p))
    print(f"[batch] {len(samples)} PE sample(s) under {folder}")
    rows, t0 = [], time.time()
    for i, p in enumerate(samples, 1):
        print(f"\n[{i}/{len(samples)}] {p.name} ...")
        try:
            r = analyze_one(str(p), a.workroot, not a.no_ghidra)
        except Exception as e:
            r = {"sample": p.name, "errors": [f"FATAL: {e!r}"]}
            traceback.print_exc()
        rows.append(r)
        print(f"      verdict={r.get('verdict','?')} family={r.get('family','?')} "
              f"fw={r.get('framework','-')} verify={r.get('verify','-')} "
              f"crypto={r.get('crypto','-')} ghidra_funcs={r.get('ghidra_funcs','-')} "
              f"errors={len(r.get('errors',[]))}")

    # batch index
    idx = [f"# Batch analysis index ({len(rows)} samples, {int(time.time()-t0)}s)", "",
           "| Sample | Verdict | Family | Framework | Verify | Crypto | Ghidra fns | Errors | Folder |",
           "|---|---|---|---|---|---|---|---|---|"]
    total_err = 0
    for r in rows:
        total_err += len(r.get("errors", []))
        idx.append(f"| {r['sample']} | {r.get('verdict','?')} | {r.get('family','?')} | "
                   f"{r.get('framework','-')} | {r.get('verify','-')} | {r.get('crypto','-')} | "
                   f"{r.get('ghidra_funcs','-')} | {len(r.get('errors',[]))} | {r.get('folder','-')} |")
    out = Path(a.workroot) / "_batch_index.md"
    out.write_text("\n".join(idx))
    print(f"\n[batch] DONE — {len(rows)} samples, {total_err} total errors, {int(time.time()-t0)}s")
    print(f"[batch] index -> {out}")
    for r in rows:
        for e in r.get("errors", []):
            print(f"   !! {r['sample']}: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
