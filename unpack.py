#!/usr/bin/env python3
"""Nemesis Analyst — intelligent dynamic unpack (custom/unknown packers).

Drives x64dbg (live, over the SSH tunnel) to run the packer stub to its OEP,
does an OEP-aware dump, pulls the clean PE into the case folder, re-statics it,
and classifies the behavior.

Prereq: launch x64dbg ON THE VM DESKTOP with the sample loaded (it can't run
headless), plugin's MCP server up on 127.0.0.1:3000.

Usage:
    python3 unpack.py samples/<sample> [--module <name.exe>] [--target default]
If --module is omitted, the main module is used.
"""
import argparse, json, sys
from pathlib import Path

from nanalyst.vm.target import load
from nanalyst.x64dbg_mcp import X64dbgMCP
from nanalyst.intelligent_unpack import Engine
from nanalyst.case import Case
from nanalyst.runlog import RunLog
from nanalyst import memstatic, classify as classifier, audit, verify, decryptor, attribution
from nanalyst.triage import triage


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sample", help="local path to the (packed) sample, for case keying")
    ap.add_argument("--module", default=None, help="module name in x64dbg (default: main)")
    ap.add_argument("--target", default="default")
    a = ap.parse_args()

    t = load(a.target)
    if not t:
        print("no target; run remote_check.py --save default"); return 1

    case = Case(a.sample)
    rl = RunLog(case.logs_dir, redact=[t.password or "\x00"])
    ta = audit.ToolAudit(case.logs_dir, redact=[t.password or "\x00"])
    audit.activate(ta)
    rl.log("unpack", "START", f"module={a.module} folder={case.dir}")
    # triage the packed sample up front (baseline for the unpack-verification diff)
    packed_triage = triage(a.sample); case.add("triage", packed_triage)

    c = X64dbgMCP(t)
    print("opening SSH tunnel to guest 127.0.0.1:3000 ...")
    if not c.ensure_tunnel():
        print("!! tunnel failed (is x64dbg running with the plugin loaded?)"); return 2
    c.initialize()

    eng = Engine(c, log=lambda m: (print(m), rl.log("engine", m)))
    module = a.module
    if not module:
        main_mod = eng.call("module_get_main")
        module = main_mod.get("name") if isinstance(main_mod, dict) else None
        print(f"[unpack] main module: {module}")

    guest_out = f"C:\\nemesis\\{Path(a.sample).stem}_unpacked.bin"
    findings = eng.unpack(module, guest_out)
    case.add("dynamic_unpack", findings)
    print("\n[unpack] findings:", json.dumps(findings, indent=2))
    c.close()

    # pull the dump into the case dumps/ folder and re-static it
    if findings.get("dump_path"):
        g = t.guest()
        local_dump = case.dumps_dir / "unpacked_dump.bin"
        if g.pull(guest_out.replace("\\", "/"), str(local_dump)):
            print(f"[unpack] pulled dump -> {local_dump}")
            mem = memstatic.analyze(str(local_dump))
            case.add("memory_static_unpack", mem)
            # if the dump is a clean PE, triage it too
            try:
                tri = triage(str(local_dump)); case.add("triage_dumped", tri)
                pk = tri.get("packing", {}).get("packer")
                print(f"[unpack] dumped PE: {tri.get('filetype')} "
                      f"packer={pk or 'none'} "
                      f"imports={tri.get('pe',{}).get('import_func_count')}")
                # --- verify this dump really is the unpacked payload ---
                v = verify.verify_unpack(packed_triage, tri, None, mem)
                case.add("verify_unpack", v)
                print(f"[unpack] VERIFY: {v['verdict']} ({v['confidence']}/100)")
                for r in v["reasons"]:
                    print(f"           - {r}")
                if pk:
                    print(f"[unpack] NOTE: dump still shows '{pk}' section names / no IAT rebuild "
                          "(plugin has no Scylla). Unpacked CODE + IOCs are recovered; for a "
                          "byte-clean PE use `upx -d` (UPX) or Scylla in the GUI (custom).")
            except Exception as exc:
                print(f"[unpack] (dump not a clean PE for triage: {exc})")
            print(f"[unpack] memory re-static (recovered from the unpacked image): "
                  f"{len(mem['urls'])} URLs, {len(mem['ips'])} IPs, {len(mem['registry'])} reg keys")
            for u in mem["urls"][:8]:
                print(f"           C2/URL: {u}")
            for ip in mem["ips"][:8]:
                print(f"           IP:     {ip}")
        else:
            print("!! could not pull the dump from the guest")

    # author / build recon on the packed sample
    attr = attribution.analyze(a.sample); case.add("attribution", attr)
    for b in attr.get("summary", []):
        print(f"[recon] {b}")

    # behavioral classification over everything gathered
    cls = classifier.classify(case.data)
    case.add("classification", cls)
    print("\n[classification]", cls["summary"])
    for f in cls["families"]:
        print(f"  - {f['family']} (score {f['score']}): {'; '.join(f['evidence'])}")

    # crypto recovery + decryptor
    dec = decryptor.build_all(case.data, case.decryptor_dir,
                              log=lambda m: rl.log("crypto_recovery", m))
    case.add("crypto_recovery", dec)
    for n in dec.get("notes", []):
        print(f"[crypto] {n}")

    case.add("tool_audit", ta.summary())
    audit.activate(None)
    manifest = case.write_manifest()
    rl.log("unpack", "DONE")
    print(f"\n[analysis folder] {case.dir}")
    print(f"[manifest] {manifest}")
    print("[tool audit]\n" + ta.render())
    return 0


if __name__ == "__main__":
    sys.exit(main())
