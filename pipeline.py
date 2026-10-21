#!/usr/bin/env python3
"""Nemesis Analyst — end-to-end pipeline.

Pull sample from the user's instance -> Mac static (triage + Ghidra) ->
guest-side deobfuscation (.NET, DIE+de4dot) -> [optional detonation] ->
unified Proof of Compromise. Every step logged (run.log/run.jsonl) and tracked
in the phase checklist.

Usage:
    python3 pipeline.py '<guest\\path\\to\\sample>' [--target NAME] [--detonate]
"""
import argparse, ntpath, sys
from pathlib import Path

from nanalyst.case import Case
from nanalyst.runlog import RunLog, Checklist
from nanalyst.triage import triage
from nanalyst.tools import ghidra_worker
from nanalyst import (proof, guest_static, detailed_report, classify, framework_extract,
                      audit, attribution, verify, decryptor, reproducibility)
from nanalyst.report import render, render_static
from nanalyst.vm.target import load as load_target
import shutil


def run(guest_sample, target_name="default", detonate=False):
    target = load_target(target_name)
    if not target:
        print("no target configured — run remote_check.py --save default first"); return 1
    g = target.guest()

    samples = Path("samples"); samples.mkdir(exist_ok=True)
    local = samples / (ntpath.basename(guest_sample) or "sample.bin")
    print(f"[pull] {guest_sample}")
    # stage to a space-free path first (scp chokes on spaces in remote paths)
    g.run('cmd /c "if not exist C:\\nemesis mkdir C:\\nemesis"', timeout=30)
    g.run(f"powershell -NoProfile -Command \"Copy-Item -LiteralPath '{guest_sample}' "
          f"-Destination 'C:\\nemesis\\_stage.bin' -Force\"", timeout=120)
    if not g.pull("C:/nemesis/_stage.bin", str(local)):
        print("!! could not pull sample from the instance"); return 1
    print(f"       -> {local}")
    staged = r"C:\nemesis\_stage.bin"  # space-free path for detonation

    case = Case(str(local))
    rl = RunLog(case.logs_dir, redact=[target.password or "\x00"])
    cl = Checklist(case.logs_dir)
    # per-tool audit ledger: every subtool call (inputs/output/timing/status)
    ta = audit.ToolAudit(case.logs_dir, redact=[target.password or "\x00"])
    audit.activate(ta)
    rl.log("pipeline", "START", f"guest_sample={guest_sample} folder={case.dir}")

    # --- Mac static: triage ---
    cl.start("triage"); rl.log("triage", "run DIE+PE")
    t = triage(str(local)); case.add("triage", t)
    cl.done("triage", f"{t.get('filetype')} {t.get('arch')}")
    rl.log("triage", "done", str(t.get("filetype")))
    print(render(t))

    # --- author / build-environment reconnaissance (static) ---
    attr = attribution.analyze(str(local)); case.add("attribution", attr)
    if attr.get("available"):
        rl.log("attribution", "done", "; ".join(attr.get("summary", [])[:3]))
        for b in attr.get("summary", []):
            print(f"   [recon] {b}")

    # --- auto-unpack UPX (clean static unpack) BEFORE deeper analysis ---
    analysis_file = str(local)
    pk = (t.get("packing") or {}).get("packer") or ""
    if "upx" in pk.lower():
        import subprocess
        unpacked = local.with_name(local.stem + "_unpacked" + local.suffix)
        rl.log("upx_unpack", "UPX detected -> upx -d", pk)
        ta.run("upx -d", {"in": str(local), "out": str(unpacked)},
               lambda: subprocess.run([__import__("shutil").which("upx") or "upx", "-d", str(local),
                                       "-o", str(unpacked)], capture_output=True),
               category="static")
        if unpacked.exists():
            analysis_file = str(unpacked)
            t2 = triage(analysis_file)
            case.add("triage_unpacked", t2)
            rl.log("upx_unpack", "done -> analyzing clean file", analysis_file)
            print(f"   [upx] UPX {pk} auto-unpacked -> {unpacked.name} "
                  f"(now {t2['pe'].get('import_func_count')} imports, sections "
                  f"{[s['name'] for s in t2['pe'].get('sections', [])]})")
            # --- verify the unpacked file really is the unpacked payload ---
            v = verify.verify_unpack(t, t2)
            case.add("verify_unpack", v)
            rl.log("verify_unpack", v["verdict"], f"confidence {v['confidence']}")
            print(f"   [verify] {v['verdict']} ({v['confidence']}/100): {'; '.join(v['reasons'][:3])}")
        else:
            rl.log("upx_unpack", "upx -d failed; analyzing packed file")

    # --- framework-aware extraction (AutoIt/PyInstaller/NSIS/Inno/...) ---
    # Framework-compiled malware is just an interpreter stub + bundled script;
    # a framework extractor recovers the REAL structured source (host-safe).
    fwdet = framework_extract.detect(analysis_file)
    if fwdet.get("framework"):
        cl.start("framework_extract")
        rl.log("framework_extract", fwdet["framework"], str(fwdet.get("evidence")))
        print(f"   [framework] {fwdet['label']} detected ({', '.join(fwdet.get('evidence', []))})")
        fwdir = case.source_dir
        fwstage = framework_extract.host_extract(fwdet["framework"], analysis_file, fwdir,
                                                 log=lambda m: rl.log("framework_extract", m))
        if fwstage.get("status") == "no_host_tool":  # fall back to guest tools
            fwstage = framework_extract.extract(g, fwdet["framework"], guest_sample, fwdir,
                                                log=lambda m: rl.log("framework_extract", m))
        fwstage["detect"] = fwdet
        case.add("framework_extract", fwstage)
        if fwstage.get("status") == "extracted":
            cl.done("framework_extract", f"{fwdet['framework']} -> {fwstage.get('source_file')}")
            print(f"   [framework] recovered source: {fwstage.get('source_file')} "
                  f"({fwstage.get('line_count')} lines, {len(fwstage.get('urls', []))} URLs, "
                  f"{len(fwstage.get('commands', []))} commands, "
                  f"{fwstage.get('shellcode_blob_count', 0)} shellcode blobs)")
        else:
            cl.fail("framework_extract", fwstage.get("status"))
            print(f"   [framework] {fwstage.get('status')}: {fwstage.get('hint', '')}")

    # --- Mac static: Ghidra (on the unpacked file if we unpacked) ---
    cl.start("static_ghidra"); rl.log("static_ghidra", f"run Ghidra headless on {analysis_file}")
    gh = ghidra_worker.analyze(analysis_file); case.add("static_ghidra", gh)
    if gh.get("available"):
        cl.done("static_ghidra", f"{gh.get('function_count')} funcs")
    else:
        cl.fail("static_ghidra", str(gh.get("error")))
    print(render_static(gh))

    # --- guest-side deobfuscation (.NET) ---
    cl.start("guest_deobfuscation"); rl.log("guest_deobfuscation", "DIE + de4dot over SSH")
    gs = guest_static.analyze(g, guest_sample); case.add("guest_deobfuscation", gs)
    if gs.get("dotnet"):
        cl.done("guest_deobfuscation", f"obf={gs.get('obfuscator')}, cleaned={bool(gs.get('deobfuscated'))}")
        rl.log("guest_deobfuscation", "done", f"deobfuscated={gs.get('deobfuscated')}")
        print(f"   [deobfuscation] .NET obfuscator={gs.get('obfuscator')} -> {gs.get('deobfuscated')}")
    else:
        cl.skip("guest_deobfuscation", "not .NET")
        print("   [deobfuscation] not a .NET assembly, skipped")

    # --- detonation (optional, real malware) ---
    if detonate:
        from nanalyst import detonate as det
        cl.start("detonate"); rl.log("detonate", "START full behavioral run")
        dres = det.run(g, staged, rl, cl, artifacts_dir=case.artifacts_dir)
        case.add("detonation", dres)

    # --- behavioral classification (family: dropper/keylogger/bot/banker/...) ---
    cls = classify.classify(case.data); case.add("classification", cls)
    rl.log("classification", cls.get("primary", "?"), cls.get("summary", ""))
    print(f"   [classification] {cls.get('summary')}")

    # --- crypto recovery: understand the encryption + emit a decryptor ---
    dec = decryptor.build_all(case.data, case.decryptor_dir,
                              log=lambda m: rl.log("crypto_recovery", m))
    case.add("crypto_recovery", dec)
    if dec.get("schemes"):
        print(f"   [crypto] {', '.join(s['algo'] for s in dec['schemes'])}; "
              f"{len(dec.get('generated', []))} decryptor(s) -> {case.decryptor_dir}")
    for n in dec.get("notes", []):
        print(f"   [crypto] {n}")

    # --- Proof of Compromise ---
    cl.start("proof_of_compromise"); rl.log("proof_of_compromise", "assemble")
    poc = proof.generate(case.data); md = proof.to_markdown(poc)
    (case.dir / "proof_of_compromise.md").write_text(md)
    case.add("proof_of_compromise", poc, state="reported")
    cl.done("proof_of_compromise")

    # detailed itemized report (REPORT.md at the folder root) + copy to Desktop
    dr = detailed_report.generate(case.data)
    dr_path = case.dir / "REPORT.md"
    dr_path.write_text(dr)
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in case.data["name"])
    desktop = Path.home() / "Desktop" / f"malware_report_{safe}.md"
    try:
        shutil.copy(dr_path, desktop)
    except Exception as exc:
        desktop = f"(copy failed: {exc})"
    # persist the tool-audit summary into the case + end the ledger + index the folder
    case.add("tool_audit", ta.summary())
    audit.activate(None)
    (case.dir / "METHODOLOGY.md").write_text(reproducibility.generate(case.data))
    from nanalyst import pdf as _pdf
    for _n in ("REPORT.md", "METHODOLOGY.md", "proof_of_compromise.md"):
        _pdf.md_to_pdf(str(case.dir / _n))
    manifest = case.write_manifest()
    rl.log("pipeline", "DONE")

    print("\n" + md)
    print(f"\n[analysis folder] {case.dir}")
    print(f"[REPORT] {dr_path}")
    print(f"[manifest] {manifest}")
    print(f"[DESKTOP COPY] {desktop}")
    print("[checklist]\n" + cl.render())
    print("[tool audit]\n" + ta.render())
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("guest_sample")
    ap.add_argument("--target", default="default")
    ap.add_argument("--detonate", action="store_true")
    a = ap.parse_args()
    sys.exit(run(a.guest_sample, a.target, a.detonate))
