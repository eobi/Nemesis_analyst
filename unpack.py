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
    ap.add_argument("--detonate", action="store_true",
                    help="after unpack, fully DETONATE (FakeNet + Procmon + Regshot). "
                         "This EXECUTES the malware and dirties the VM — revert to clean-baseline after.")
    ap.add_argument("--no-autoload", action="store_true",
                    help="don't push + debug_init the sample; analyze whatever is already loaded in x32dbg")
    a = ap.parse_args()

    t = load(a.target)
    if not t:
        print("no target; run remote_check.py --save default"); return 1

    case = Case(a.sample).load()   # preserve prior static results (anomalies/hints)
    # start clean: drop prior-run dynamic stages + volatile artifacts so the report
    # shows ONLY this run (keep static_ghidra for the indirect-transfer hints)
    for _stale in ("dynamic_unpack", "api_trace", "hint_dumps", "pe_reconstruction",
                   "triage_reconstructed", "memory_static_reconstructed", "triage_dumped",
                   "memory_static_unpack", "verify_unpack", "detonation"):
        case.data["stages"].pop(_stale, None)
    for _sub in (case.dumps_dir, case.decryptor_dir):
        for _f in _sub.glob("*"):
            try:
                _f.unlink()
            except Exception:
                pass
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

    # --- auto-load the sample into the debugger (no manual GUI step) ---
    if not a.no_autoload:
        sarch = "x64" if "64" in str(packed_triage.get("arch", "")) else "x86"
        dbg_bits = "x64" if "64" in str((eng.call("module_get_main") or {}).get("name", "")) else "x86"
        import time as _t
        guest_sample = f"C:\\nemesis\\{Path(a.sample).stem}{Path(a.sample).suffix or '.exe'}"
        want = Path(a.sample).stem.lower()[:8]
        gL = t.guest()
        gL.run('cmd /c "if not exist C:\\nemesis mkdir C:\\nemesis"', timeout=30)
        if gL.push(a.sample, guest_sample):
            eng.call("debug_stop")                      # close any current debuggee first
            _t.sleep(1.5)
            r = eng.call("debug_init", {"path": guest_sample})
            ok = isinstance(r, dict) and r.get("success")
            mg = {}
            for _ in range(24):                         # wait for THIS module to load + settle
                mg = eng.call("module_get_main") or {}
                nm = (mg.get("name") or "").lower()
                st_ = (eng.call("debug_get_state") or {}).get("state")
                if want in nm and mg.get("entry") and st_ == "paused":
                    break
                _t.sleep(0.5)
            if (eng.call("debug_get_state") or {}).get("state") == "running":
                eng.call("debug_pause")                 # don't let it run free before we arm bps
            print(f"[load] debug_init {guest_sample} -> success={ok}, "
                  f"module={mg.get('name')}, entry={mg.get('entry')}")
            if not (mg.get("entry") and want in (mg.get("name") or "").lower()):
                print("!! debug_init did not load the expected sample. If it's 64-bit, it needs "
                      "x64dbg (x32dbg can't load it). Aborting."); c.close(); return 3
        else:
            print("!! could not push the sample to the guest"); c.close(); return 3

    main_mod = eng.call("module_get_main")
    module = a.module or (main_mod.get("name") if isinstance(main_mod, dict) else None)
    runtime_base = main_mod.get("base") if isinstance(main_mod, dict) else None
    static_base = (packed_triage.get("pe", {}) or {}).get("image_base")
    print(f"[unpack] module: {module} | runtime base: {runtime_base} | static base: {hex(static_base) if static_base else '?'}")
    arch = "x64" if "64" in str(packed_triage.get("arch", "")) else "x86"

    # --- full API-arsenal trace: live play-by-play of alloc/protect/write/decompress,
    #     capturing the decoded payload regions (defensive) ---
    print("\n[api-trace] arming the P1/P2 API breakpoint arsenal (live log in logs/run.log)")
    # run from the freshly-loaded state (do NOT debug_restart — it de-registers the
    # module on this build; the operator reloads the sample before each run)
    at = eng.api_trace("C:\\nemesis\\api", arch=arch, restart=False)
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

    # The API trace already recovered the payload: the W->X flip dumped the decrypted
    # region + a full-module image (reconstructed below). We do NOT run a separate
    # restart-based OEP/hint phase — debug_restart de-registers the module on this build,
    # so a clean run uses the operator's fresh load in one pass.
    wx = [ev for ev in at.get("trace", []) if "W->X" in ((ev.get("capture") or {}).get("note") or "")]
    findings = {"module": module, "payload_captured": bool(wx), "reached_oep": bool(wx),
                "wx_flips": [(ev.get("capture") or {}).get("note") for ev in wx],
                "note": "payload captured at the W->X flip during the API trace"}
    case.add("dynamic_unpack", findings)
    print(f"[unpack] payload captured at W->X flip: {bool(wx)} ({len(wx)} flip event(s))")
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
            # authoritative verification: packed vs the reconstructed PE (IAT resolved)
            v2 = verify.verify_unpack(packed_triage, bt, None, bm,
                                      dumped_label=f"reconstructed: {Path(best['out']).name}",
                                      dynamic=case.data["stages"].get("dynamic_unpack"))
            case.add("verify_unpack", v2)
            print(f"[verify] {v2['verdict']} ({v2['confidence']}/100) vs reconstructed PE")
            for b in v2.get("breakdown", []):
                print(f"           [{b['points']}/{b['max']}] {b['detail']}")
        except Exception as exc:
            print(f"[rebuild] (re-triage failed: {exc})")

    # --- label every dump so it's clear what each is (not all are payloads) ---
    def _dump_role(n):
        if n.startswith("unpacked_dump"): return "OEP module dump (dump_module)"
        if "fullmodule" in n: return "full module at W->X flip (-> reconstruct)"
        if "_wx_" in n or "_ntwx_" in n: return "W->X region = DECRYPTED PAYLOAD (made executable)"
        if "keyblob" in n: return "crypto KEY BLOB (CryptImportKey)"
        if n.startswith("api_region"): return "memory region the malware ALLOCATED (work buffer / staged data)"
        if "wsrc" in n or "writeSrc" in n: return "buffer written into another process"
        if "decomp" in n: return "decompression output (RtlDecompressBuffer)"
        if n.startswith("hintdump"): return "target of an indirect call/jmp (register pointer)"
        if n.endswith("_rebuilt.exe"): return "RECONSTRUCTED valid PE (imports/IAT fixed)"
        return "memory dump"
    # rename MZ dumps so the filename itself flags them as installable PE images
    for df in list(case.dumps_dir.glob("*.bin")):
        try:
            if open(df, "rb").read(2) == b"MZ" and "_PE" not in df.name:
                df.rename(df.with_name(df.stem + "_PE.bin"))
        except Exception:
            pass
    # build a full dumps manifest: per-dump hashes + PE imports + re-static IOCs, and a
    # comparison vs the packed input (same file? more APIs? what did re-static reveal?)
    import hashlib
    packed_h = packed_triage.get("hashes", {}) or {}
    packed_md5 = packed_h.get("md5")
    manifest = []
    for df in sorted(case.dumps_dir.glob("*")):
        if not df.is_file() or df.name in ("DUMPS.md",):
            continue
        data = df.read_bytes()
        mz = data[:2] == b"MZ"
        rec = {"name": df.name, "path": f"dumps/{df.name}", "size": len(data),
               "md5": hashlib.md5(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest(),
               "pe": mz, "role": _dump_role(df.name),
               "same_as_packed": hashlib.md5(data).hexdigest() == packed_md5}
        if mz:
            try:
                tri = triage(str(df)); pe = tri.get("pe", {}) or {}
                rec["imports"] = pe.get("import_func_count")
                rec["dll_count"] = pe.get("import_dll_count")
                rec["sections"] = [s["name"] for s in pe.get("sections", [])]
            except Exception:
                pass
        try:
            m = memstatic.analyze(str(df))
            rec["strings"] = m.get("string_count"); rec["urls"] = len(m.get("urls", []))
            rec["ips"] = len(m.get("ips", []))
        except Exception:
            pass
        manifest.append(rec)
    case.add("dumps_manifest", {"packed_md5": packed_md5,
                                "packed_sha256": packed_h.get("sha256"),
                                "packed_imports": (packed_triage.get("pe", {}) or {}).get("import_func_count"),
                                "dumps": manifest})
    # human index file
    idx = ["# Dumps — what each file is", "",
           "Each memory region the sample allocated/protected/targeted is dumped so nothing is "
           "missed. **PE** = carries an MZ header (installable/mappable image).", "",
           "| File | Size | PE? | MD5 | Role |", "|---|---|---|---|---|"]
    for r in manifest:
        idx.append(f"| `{r['name']}` | {r['size']:,} | {'**PE**' if r['pe'] else '-'} | "
                   f"`{r['md5']}` | {r['role']} |")
    (case.dumps_dir / "DUMPS.md").write_text("\n".join(idx))

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

    # --- optional final phase: full detonation (behavioral capture for ProcDOT) ---
    if a.detonate:
        from nanalyst import detonate as det
        print("\n[detonate] FINAL phase: executing the malware with FakeNet + Procmon + Regshot")
        print("[detonate] (this DIRTIES the VM — revert to clean-baseline afterwards)")
        g3 = t.guest()
        g3.run('cmd /c "if not exist C:\\nemesis mkdir C:\\nemesis"', timeout=30)
        staged = r"C:\nemesis\det_sample.exe"
        if g3.push(a.sample, staged):
            dres = det.run(g3, staged, rl, None, artifacts_dir=case.artifacts_dir)
            case.add("detonation", dres)
            print(f"[detonate] artifacts -> {case.artifacts_dir}")
            print("[detonate] Procmon CSV ready for ProcDOT: "
                  f"{case.artifacts_dir}/run/pm.csv (import into ProcDOT for the visual graph)")
            # re-classify with behavioral evidence now included
            case.add("classification", classifier.classify(case.data))
        else:
            print("[detonate] could not stage the sample on the guest; skipped")

    case.add("tool_audit", ta.summary())
    audit.activate(None)
    # full analyst report + reproducible methodology (+ PDF versions)
    (case.dir / "REPORT.md").write_text(detailed_report.generate(case.data))
    (case.dir / "METHODOLOGY.md").write_text(reproducibility.generate(case.data))
    from nanalyst import pdf as _pdf
    for name in ("REPORT.md", "METHODOLOGY.md", "proof_of_compromise.md"):
        outp = _pdf.md_to_pdf(str(case.dir / name))
        if outp:
            print(f"[pdf] {name} -> {Path(outp).name}")
    manifest = case.write_manifest()
    rl.log("unpack", "DONE")
    print(f"\n[analysis folder] {case.dir}")
    print(f"[REPORT] {case.dir / 'REPORT.md'}")
    print(f"[METHODOLOGY] {case.dir / 'METHODOLOGY.md'}  (deterministic repro steps)")
    print(f"[manifest] {manifest}")
    print(f"[dumps index] {case.dumps_dir / 'DUMPS.md'}")
    print("[tool audit]\n" + ta.render())
    # analysis ran the sample under the debugger (and detonation if requested) — the VM
    # is now dirty. Reset before the next sample.
    print("\n" + "=" * 68)
    print("  ANALYSIS COMPLETE. The VM has executed malware code and is DIRTY.")
    print("  -> Shut down the VM, then WIPE/REVERT to the clean baseline:")
    print("     ./ReverseEngineeringMalwareAnalysis/revert-clean.sh")
    print("  Then boot fresh for the next sample. Never reuse a dirty VM.")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
