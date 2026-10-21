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
from nanalyst import (memstatic, classify as classifier, audit, verify, decryptor,
                      attribution, reproducibility, detailed_report)
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

    case = Case(a.sample).load()   # preserve prior static results (anomalies/hints)
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
    main_mod = eng.call("module_get_main")
    module = a.module or (main_mod.get("name") if isinstance(main_mod, dict) else None)
    runtime_base = main_mod.get("base") if isinstance(main_mod, dict) else None
    static_base = (packed_triage.get("pe", {}) or {}).get("image_base")
    print(f"[unpack] module: {module} | runtime base: {runtime_base} | static base: {hex(static_base) if static_base else '?'}")
    arch = "x64" if "64" in str(packed_triage.get("arch", "")) else "x86"

    # --- full API-arsenal trace: live play-by-play of alloc/protect/write/decompress,
    #     capturing the decoded payload regions (defensive) ---
    print("\n[api-trace] arming the P1/P2 API breakpoint arsenal (live log in logs/run.log)")
    at = eng.api_trace("C:\\nemesis\\api", arch=arch)
    case.add("api_trace", at)
    g2 = t.guest()

    def _pull_and_scan(guest_path, tag):
        lp = case.dumps_dir / Path(guest_path.replace("\\", "/")).name
        if g2.pull(guest_path.replace("\\", "/"), str(lp)):
            try:
                ioc = memstatic.analyze(str(lp))
                if ioc.get("urls") or ioc.get("ips") or ioc.get("suspicious_keywords"):
                    print(f"   [{tag}] {lp.name}: {len(ioc['urls'])} URLs, {len(ioc['ips'])} IPs, "
                          f"{len(ioc.get('suspicious_keywords', []))} keywords")
                return str(lp), ioc
            except Exception:
                return str(lp), {}
        return None, {}

    # pull + re-static every captured region (W->X flips, decompressed/written buffers)
    for ev in at.get("trace", []):
        cap = ev.get("capture") or {}
        dp = cap.get("dump")
        if dp:
            lp, ioc = _pull_and_scan(dp, "capture")
            if lp:
                cap["local_dump"] = lp; cap["ioc"] = ioc
        mdp = cap.get("module_dump")           # full-module dump at the W->X flip
        if mdp:
            lp, _ = _pull_and_scan(mdp, "module")
            if lp:
                cap["local_module_dump"] = lp
    # pull + re-static the allocated regions (they hold the decoded payload)
    for rd in at.get("region_dumps", []):
        lp, ioc = _pull_and_scan(rd["dump"], "region")
        if lp:
            rd["local_dump"] = lp; rd["ioc"] = ioc
    print(f"[api-trace] {sum(at.get('counts', {}).values())} calls across "
          f"{len(at.get('counts', {}))} APIs; {len(at.get('region_dumps', []))} payload region(s) dumped")

    guest_out = f"C:\\nemesis\\{Path(a.sample).stem}_unpacked.bin"
    findings = eng.unpack(module, guest_out)
    case.add("dynamic_unpack", findings)
    print("\n[unpack] findings:", json.dumps(findings, indent=2))

    # --- hint-driven dumps: break at static-flagged indirect transfers (call reg /
    #     push-ret) and dump the memory the register points to (the unpacked payload).
    #     Rebase Ghidra addresses to runtime (ASLR): runtime_base + (addr - image_base) ---
    anomalies = (case.data["stages"].get("static_ghidra", {}) or {}).get("anomalies", [])
    rb = int(runtime_base, 16) if isinstance(runtime_base, str) else (runtime_base or 0)
    sb = static_base or 0
    sites = []
    for a_ in anomalies:
        rt_addr = hex(Engine.rebase(a_["addr"], sb, rb)) if (rb and sb) else \
                  ("0x" + a_["addr"] if not str(a_["addr"]).startswith("0x") else a_["addr"])
        if a_.get("type") == "indirect_register":
            sites.append({"addr": rt_addr, "static_addr": a_["addr"], "type": "indirect_register",
                          "reg": eng._reg_from_detail(a_.get("detail", "")),
                          "detail": a_.get("detail")})
        elif a_.get("type") == "push_ret":
            sites.append({"addr": rt_addr, "static_addr": a_["addr"], "type": "push_ret",
                          "reg": None, "detail": a_.get("detail")})
    if sites:
        print(f"[hint-dump] rebased {len(sites)} sites (ASLR: static base {hex(sb) if sb else '?'} "
              f"-> runtime {runtime_base})")
        print(f"\n[hint-dump] {len(sites)} static indirect-transfer site(s) -> break + dump target memory")
        hd = eng.hint_driven_dump(sites, "C:\\nemesis\\hintdump")
        # pull each produced dump + re-static it
        g2 = t.guest()
        for rec in hd:
            if rec.get("dump_path"):
                lp = case.dumps_dir / Path(rec["dump_path"].replace("\\", "/")).name
                if g2.pull(rec["dump_path"].replace("\\", "/"), str(lp)):
                    rec["local_dump"] = str(lp)
                    try:
                        rec["ioc"] = memstatic.analyze(str(lp))
                    except Exception:
                        pass
        case.add("hint_dumps", {"sites": len(sites), "results": hd})
        for rec in hd:
            tag = rec.get("classification") or ("not reached" if not rec["reached"] else "?")
            ioc = rec.get("ioc", {})
            extra = (f" | {len(ioc.get('urls',[]))} URLs {len(ioc.get('ips',[]))} IPs"
                     if ioc else "")
            print(f"  {rec['detail']} @ {rec['site']} -> {rec['reg']}={rec.get('target')} "
                  f"[{tag}]{extra}")
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

    # --- PE reconstruction: rebuild valid PEs from every memory dump (Scylla-style:
    #     align raw<->virtual + fix ImageBase) so the import table/IAT resolve ---
    import re as _re
    from nanalyst import pe_rebuild
    rebuilds = []
    for dumpf in sorted(case.dumps_dir.glob("*.bin")):
        try:
            if open(dumpf, "rb").read(2) != b"MZ":
                continue
        except Exception:
            continue
        m = _re.search(r"0x([0-9a-fA-F]+)", dumpf.name)
        base = int(m.group(1), 16) if m else (int(runtime_base, 16) if isinstance(runtime_base, str) else (runtime_base or 0))
        out = case.dumps_dir / (dumpf.stem + "_rebuilt.exe")
        r = pe_rebuild.rebuild(str(dumpf), base, str(out))
        if r.get("ok") and r.get("imports", 0) > 0:
            r["source"] = dumpf.name
            rebuilds.append(r)
            print(f"[rebuild] {dumpf.name} (base {hex(base)}) -> {r['imports']} imports, "
                  f"{r['dll_count']} DLLs: {', '.join(r.get('dlls', [])[:6])}")
    if rebuilds:
        best = max(rebuilds, key=lambda x: x["imports"])
        case.add("pe_reconstruction", {"rebuilds": rebuilds, "best": best})
        # re-triage + re-static the best reconstructed PE (now imports resolve)
        try:
            bt = triage(best["out"]); case.add("triage_reconstructed", bt)
            bm = memstatic.analyze(best["out"]); case.add("memory_static_reconstructed", bm)
            print(f"[rebuild] BEST: {Path(best['out']).name} -> {best['imports']} imports; "
                  f"re-static: {len(bm['urls'])} URLs, {len(bm['ips'])} IPs")
        except Exception as exc:
            print(f"[rebuild] (re-triage failed: {exc})")

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
    # full analyst report + reproducible methodology
    (case.dir / "REPORT.md").write_text(detailed_report.generate(case.data))
    (case.dir / "METHODOLOGY.md").write_text(reproducibility.generate(case.data))
    manifest = case.write_manifest()
    rl.log("unpack", "DONE")
    print(f"\n[analysis folder] {case.dir}")
    print(f"[REPORT] {case.dir / 'REPORT.md'}")
    print(f"[METHODOLOGY] {case.dir / 'METHODOLOGY.md'}  (deterministic repro steps)")
    print(f"[manifest] {manifest}")
    print("[tool audit]\n" + ta.render())
    return 0


if __name__ == "__main__":
    sys.exit(main())
