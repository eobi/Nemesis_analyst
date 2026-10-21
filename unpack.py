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
import argparse, json, sys, time
from pathlib import Path

from nanalyst.vm.target import load
from nanalyst.vm import debugger
from nanalyst.x64dbg_mcp import X64dbgMCP
from nanalyst.intelligent_unpack import Engine
from nanalyst.case import Case
from nanalyst.runlog import RunLog
from nanalyst import (memstatic, classify as classifier, audit, verify, decryptor, proof,
                      attribution, reproducibility, detailed_report)
from nanalyst.triage import triage


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sample", nargs="?", help="local path to the (packed) sample, for case keying")
    ap.add_argument("--finalize", metavar="CASE_DIR", default=None,
                    help="no VM: rebuild every report/PDF from a (possibly interrupted) case folder's saved case.json")
    ap.add_argument("--observe", type=int, default=0, metavar="SECS",
                    help="after the payload is captured, let it KEEP RUNNING for SECS seconds under the behaviour hooks "
                         "(gives the malware category and live indicators). EXECUTES the payload: VM must be disposable.")
    ap.add_argument("--run-id", default=None, help="use this UUID for the case folder name (the MCP server sets it so it can find the run)")
    ap.add_argument("--module", default=None, help="module name in x64dbg (default: main)")
    ap.add_argument("--target", default="default")
    ap.add_argument("--detonate", action="store_true",
                    help="after unpack, fully DETONATE (FakeNet + Procmon + Regshot). "
                         "This EXECUTES the malware and dirties the VM — revert to clean-baseline after.")
    ap.add_argument("--no-autoload", action="store_true",
                    help="don't push + debug_init the sample; analyze whatever is already loaded in x32dbg")
    ap.add_argument("--no-dbg-switch", action="store_true",
                    help="don't auto-switch x32dbg<->x64dbg by sample bitness (use the live debugger as-is)")
    ap.add_argument("--no-ai", action="store_true",
                    help="disable the AI analyst brain (deterministic pipeline only)")
    a = ap.parse_args()
    if a.finalize:
        import regen_reports
        print(regen_reports.regen(Path(a.finalize))); return 0
    if not a.sample:
        ap.error("a sample path is required (or --finalize CASE_DIR)")

    t = load(a.target)
    if not t:
        print("no target; run remote_check.py --save default"); return 1

    case = Case(a.sample, unique=True, run_id=a.run_id).load()   # one UUID_<malware> folder per run (no mixing between runs)
    _ACTIVE["case"] = case
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
    # STAGE 1 deep static (packed): strings/IOCs/anti-analysis on the on-disk file.
    # Usually sparse for a crypted sample — that's expected; stages 2 (unpacked) and
    # 3 (decrypted) are where the real config/C2 surfaces.
    ds_packed = memstatic.deep_scan(a.sample, stage="packed")
    case.add("deep_static_packed", ds_packed)
    print(f"[static] packed: entropy {ds_packed['entropy']}, {ds_packed['string_count']} strings, "
          f"{len(ds_packed['urls'])} URLs, {len(ds_packed['domains'])} domains, "
          f"{len(ds_packed['anti_analysis_indicators'])} anti-analysis indicators")
    # analyst-grade suspicious CODE/byte-pattern scan (shellcode stubs, PEB walks,
    # anti-debug/anti-VM instrs, packer stubs, indirect call/jmp, embedded PEs, W+X sections)
    from nanalyst import code_patterns as _cp
    _cp_arch = "x64" if "64" in str(packed_triage.get("arch", "")) else "x86"
    cpp = _cp.scan(a.sample, _cp_arch, path=a.sample)
    case.add("code_patterns_packed", cpp)
    print(f"[static] code patterns: {cpp['counts']['high']} high / {cpp['counts']['medium']} medium / "
          f"{cpp['counts']['info']} info across {len(cpp['findings'])} indicator type(s)")

    # ---- entropy map: WHERE the encrypted/compressed bytes are (deterministic) ----
    from nanalyst import entropy_map as _em
    emap = _em.map_regions(a.sample); case.add("entropy_map", emap)
    print(f"[static] entropy map: {len(emap['regions'])} high-entropy region(s), "
          f"{len(emap.get('resources', []))} sizeable resource(s)"
          + (", overlay present" if emap.get("overlay") else ""))
    for r in emap["regions"][:6]:
        print(f"[static]   {r.get('kind')} in {r.get('section')} rva={r.get('rva')} "
              f"size=0x{r['size']:x} H={r['entropy']}")
    if emap.get("tls_callbacks"):
        print(f"[static] !! TLS CALLBACKS at RVA {', '.join(emap['tls_callbacks'])} — they run BEFORE the "
              "debugger's entry stop, i.e. sample code executes uncontrolled during loading")
        rl.log("safety", f"TLS callbacks present: {emap['tls_callbacks']}")

    # ---- AI-driven static analysis -> validated dynamic plan (BEFORE the debugger starts) ----
    brain, ai_plan, _ai_log = None, None, None
    if not a.no_ai:
        import json as _json, time as _time
        from nanalyst.ai.brain import Brain
        from nanalyst.ai import static_reason as _sr, dynamic_plan as _dp
        _ai_log = open(case.logs_dir / "ai_transcript.jsonl", "a")

        def _ai_rec(rec):
            rec = {"ts": _time.strftime("%Y-%m-%dT%H:%M:%S"), **rec}
            _ai_log.write(_json.dumps(rec) + "\n"); _ai_log.flush()

        brain = Brain(log=lambda m: (print(m), rl.log("ai", m)), transcript=_ai_rec)
        if brain.available:
            print(f"[ai] analyst brain online: {brain.provider}  "
                  f"(every request logged -> logs/ai_transcript.jsonl)")
            a0 = _sr.assess(brain, _sr.build_context(case.data, "packed"))
            if a0:
                from nanalyst.ai import claims as _cl
                aud = _cl.audit(a0, emap)                  # check the AI's claims against OUR evidence
                a0["claims_audit"] = aud
                case.add("ai_assessment_packed", a0)
                sup_er = [x for x in aud["encrypted_regions"] if x["supported"]]
                sup_ul = [x for x in aud["url_leads"] if x["supported"]]
                print(f"[ai] packed: family={a0.get('likely_family')} ({a0.get('family_confidence')}); "
                      f"{len(a0.get('config_leads', []))} config lead(s), {len(sup_ul)} supported URL lead(s), "
                      f"{len(sup_er)} supported encrypted region(s); "
                      f"{aud['unsupported']} AI claim(s) NOT supported by the evidence")
                for x in aud["encrypted_regions"][:6]:
                    print(f"[ai]   encrypted region {'OK ' if x['supported'] else 'NOT SUPPORTED'}: {x['claim']} — {x['basis']}")
                for x in aud["url_leads"][:6]:
                    print(f"[ai]   url lead {'OK ' if x['supported'] else 'NOT SUPPORTED'}: {x['lead'][:80]} — {x['basis']}")
            try:
                raw_plan = _dp.propose(brain, case.data)
                v = _dp.validate(raw_plan, emap.get("size_of_image")) if raw_plan else None
            except Exception as exc:                       # a bad AI response must never block analysis
                print(f"[plan] AI plan skipped ({exc}) — dynamic phase runs with the default arsenal")
                raw_plan, v = {}, None
            if raw_plan and v:
                ai_plan = v["accepted"]
                from nanalyst.ai import claims as _cl
                ra = _cl.check_plan_regions(ai_plan["watch_regions"], emap)
                case.add("ai_dynamic_plan", {"proposed": raw_plan, **v, "region_audit": ra})
                print(f"[plan] AI hypothesis: {ai_plan['hypothesis'][:160]}")
                for p in ai_plan["priority_apis"]:
                    print(f"[plan]   priority API  {p['api']:<26} {p['why'][:80]}")
                for w in ai_plan["watch_regions"]:
                    _ok = next((x for x in ra if x["rva"] == hex(w["rva"])), {})
                    print(f"[plan]   watch region  rva=0x{w['rva']:x} size=0x{w['size']:x}  "
                          f"[{'justified' if _ok.get('supported') else 'NOT JUSTIFIED by entropy map'}] {w['why'][:70]}")
                for r in v["rejected"]:
                    print(f"[plan]   REJECTED      {r['item']}: {r['reason']}")
        else:
            print("[ai] no analyst brain available (no API key found) — deterministic only")

    c = X64dbgMCP(t)
    print("opening SSH tunnel to guest 127.0.0.1:3000 ...")
    if not c.ensure_tunnel():
        print("!! tunnel failed (is x64dbg running with the plugin loaded?)"); return 2
    # Bitness management is CONSERVATIVE: we only touch the debugger when we might
    # actually need to switch — i.e. an x64 sample, or no MCP responding at all. For an
    # x86 sample with a live MCP, we use the operator's already-open x32dbg AS-IS and
    # never relaunch it (relaunching a working GUI debugger disrupts the operator).
    if not a.no_autoload and not a.no_dbg_switch:
        import os as _os
        want_bits = "x64" if "64" in str(packed_triage.get("arch", "")) else "x86"
        mcp_url = _os.environ.get("PENTAGON_MCP_URL", "http://127.0.0.1:13300/mcp")
        if want_bits == "x64" or not debugger._mcp_responds(mcp_url):
            if not debugger.ensure(t.guest(), want_bits, mcp_url,
                                   log=lambda m: (print(m), rl.log("debugger", m))):
                print("!! could not bring up the right-bitness debugger "
                      f"({want_bits}); aborting."); c.close(); return 2
        else:
            print(f"[debugger] x86 sample + MCP live — using the open debugger as-is")
    c.initialize()

    eng = Engine(c, log=lambda m: (print(m), rl.log("engine", m)))

    res_base, res_names, res_result = None, [], None   # residue check (kill tree + diff)
    # --- auto-load the sample into the debugger (no manual GUI step) ---
    if not a.no_autoload:
        sarch = "x64" if "64" in str(packed_triage.get("arch", "")) else "x86"
        dbg_bits = "x64" if "64" in str((eng.call("module_get_main") or {}).get("name", "")) else "x86"
        import time as _t
        # x32dbg/x64dbg load a PE by extension — a `.bin`/`.dat` sample must be staged as
        # `.exe` (or `.dll` for a DLL) or debug_init returns module=None. Normalize it.
        _suf = Path(a.sample).suffix.lower()
        if _suf not in (".exe", ".dll"):
            _suf = ".dll" if (packed_triage.get("pe", {}) or {}).get("is_dll") else ".exe"
        from nanalyst.vm import transfer as _tr
        guest_sample = "C:\\nemesis\\" + _tr.unique_name(Path(a.sample).stem, _suf)
        want = Path(a.sample).stem.lower()[:8]
        gL = t.guest()
        gL.run('cmd /c "if not exist C:\\nemesis mkdir C:\\nemesis"', timeout=30)
        eng.call("debug_stop")                          # release any held debuggee BEFORE push
        _t.sleep(1.5)                                    # so the on-disk file isn't locked
        # verified push: unique name, kill/delete any holder, size + SHA-256 checked on the guest
        pushed, push_why = _tr.push_verified(
            gL, a.sample, guest_sample,
            log=lambda m: (print(m), rl.log("push", m)))
        if not pushed:
            print(f"!! push never verified: {push_why}")
        if pushed:
            # containment-first load: pause the moment it runs; if the debugger goes silent or
            # the module never registers under control, stop it AND kill its process tree.
            from nanalyst import safe_load as _sl, residue as _res
            res_names = [Path(guest_sample).name, "det_sample.exe"]
            res_base = _res.snapshot(gL)          # read-only inventory BEFORE the sample can run
            if res_base:                           # keep it on disk: an aborted/crashed run can still be diffed
                import json as _rj
                (case.artifacts_dir / "residue_baseline.json").write_text(_rj.dumps(res_base))
            print("[residue] baseline " + (f"captured ({len(res_base['procs'])} procs, "
                  f"{len(res_base['files'])} files)" if res_base else "FAILED — will advise revert"))
            controlled, mg, ok, why = _sl.safe_load(
                eng, gL, guest_sample, want,
                log=lambda m: (print(m), rl.log("safety", m)))
            print(f"[load] debug_init {guest_sample} -> success={ok}, "
                  f"module={mg.get('name')}, entry={mg.get('entry')}, controlled={controlled}")
            if controlled:
                # NOTE: running to the entry from the early pause was tried and REJECTED: measured live, our own entry
                # breakpoint failed to stop the program in 4 of 5 trials and a harmless canary ran to completion twice
                # (marker file appeared). So no chase: we arm the arsenal right at the early pause instead.
                eng._pre_entry = False
                eng._early_paused = bool(mg.get("early_pause"))
                eng._tls_rvas = [int(x, 16) for x in (emap.get("tls_callbacks") or [])]
                if eng._pre_entry:
                    print("[load] paused EARLY in the loader, before any of the sample's code — arming the API arsenal "
                          "from here" + (f" (TLS callbacks at {emap['tls_callbacks']} will run under the arsenal)" if emap.get("tls_callbacks") else ""))
                case.add("load_info", {"module": mg.get("name"), "entry": mg.get("entry"), "eip": mg.get("eip"),
                                       "at_entry": mg.get("at_entry"), "early_pause": mg.get("early_pause"),
                                       "note": ("paused at the entry point" if mg.get("at_entry") else
                                ("paused early in the loader, before any of the sample's code ran" if mg.get("early_pause") else
                                                "the debugger's first stop was NOT the entry point: whatever the "
                                                "sample ran before that stop was not observed"))})
                if not mg.get("at_entry"):
                    print(f"[load] !! first stop was at {mg.get('eip')}, NOT the entry {mg.get('entry')} — code before "
                          "this stop was not observed (arsenal is armed from here)")
            if not controlled:
                print(f"!! load aborted: {why}. The sample was contained, but it may have "
                      "executed — checking what it left behind.")
                res_result = _res.finish(gL, res_names, res_base, log=lambda m: (print(m), rl.log("residue", m)))
                case.add("residue", res_result)
                print("!! " + res_result["verdict"])
                c.close(); return 3
        else:
            eng.call("debug_stop")
            print("!! could not push the sample to the guest. Aborting."); c.close(); return 3

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
    at = eng.api_trace("C:\\nemesis\\api", arch=arch, restart=False, plan=ai_plan, observe_secs=a.observe,
                       max_events=400)   # .NET/runtime start-up noise alone can use 150 events before the sample's own code runs
    case.add("api_trace", at)
    if at.get("aborted"):
        print(f"!! trace aborted: {at['aborted']}. Containing the sample.")
        rl.log("safety", f"trace aborted: {at['aborted']}")
        if not a.no_autoload:
            from nanalyst import safe_load as _sl2
            _sl2.contain(eng, gL, guest_sample, f"trace aborted ({at['aborted']})",
                         log=lambda m: (print(m), rl.log("safety", m)))
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
        for _k, _lk in (("plain_dump", "local_plain_dump"), ("cipher_dump", "local_cipher_dump")):
            if cap.get(_k):                    # file-encryption pair (plaintext before, ciphertext after)
                lp, _ = _pull_and_scan(cap[_k], "encrypt-pair")
                if lp:
                    cap[_lk] = lp
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
    for pd in at.get("plan_dumps", []):
        lp, ioc = _pull_and_scan(pd["dump"], "plan-region")
        if lp:
            pd["local_dump"] = lp; pd["ioc"] = ioc
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
    try:
        eng.call("debug_stop")        # end the debug session first so the debugger drops its handle on the sample
    except Exception:
        pass
    c.close()
    if res_base is not None and not a.detonate:
        from nanalyst import residue as _res
        res_result = _res.finish(t.guest(), res_names, res_base,
                                 log=lambda m: (print(m), rl.log("residue", m)))
        case.add("residue", res_result)

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
            # STAGE 2 deep static (unpacked): the real config/C2/strings usually appear here
            ds_unpacked = memstatic.deep_scan(best["out"], stage="unpacked")
            case.add("deep_static_unpacked", ds_unpacked)
            case.add("code_patterns_unpacked", _cp.scan(best["out"], _cp_arch, path=best["out"]))
            print(f"[static] unpacked: entropy {ds_unpacked['entropy']}, "
                  f"{len(ds_unpacked['urls'])} URLs, {len(ds_unpacked['domains'])} domains, "
                  f"{len(ds_unpacked['commands'])} commands")
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
    try:                                    # content-based classification + stage-to-stage comparison (additive)
        from nanalyst import dump_analysis
        _fs = sorted((f for f in case.dumps_dir.glob("*") if f.is_file() and f.name != "DUMPS.md"),
                     key=lambda f: f.stat().st_mtime)
        case.add("dump_analysis", dump_analysis.analyze_dumps(
            [{"name": f.name, "path": str(f), "order": i} for i, f in enumerate(_fs)], arch=arch))
    except Exception as _e:
        print(f"  [dump-analysis] skipped: {_e}")
    try:                                                      # fingerprints of every PE the run produced, then link to prior cases
        _fps = dict(case.data["stages"].get("author_fingerprints") or {})
        for _f in sorted(case.dumps_dir.glob("*")):
            if _f.is_file() and _f.read_bytes()[:2] == b"MZ":
                _x = attribution.fingerprints(str(_f))
                if _x:
                    _fps[_f.name] = _x
        case.add("author_fingerprints", _fps)
        _lk = attribution.link_cases(_fps, str(case.dir.parent), exclude=case.dir.name)
        case.add("author_links", {"links": _lk[:25]})
        if _lk:
            print(f"[recon] {len(_lk)} shared-fingerprint lead(s) with earlier cases (see report)")
    except Exception as _e:
        print(f"[recon] author linking skipped: {_e}")
    # human index file
    idx = ["# Dumps — what each file is", "",
           "Each memory region the sample allocated/protected/targeted is dumped so nothing is "
           "missed. **PE** = carries an MZ header (installable/mappable image).", "",
           "| File | Size | PE? | MD5 | Role |", "|---|---|---|---|---|"]
    for r in manifest:
        idx.append(f"| `{r['name']}` | {r['size']:,} | {'**PE**' if r['pe'] else '-'} | "
                   f"`{r['md5']}` | {r['role']} |")
    (case.dumps_dir / "DUMPS.md").write_text("\n".join(idx))

    # ---- framework source recovery (AutoIt / .NET) + guest .NET de4dot (guarded, additive) ----
    from nanalyst import framework_extract as _fx, guest_static as _gs
    _esuf = Path(a.sample).suffix.lower()
    if _esuf not in (".exe", ".dll"):
        _esuf = ".dll" if (packed_triage.get("pe", {}) or {}).get("is_dll") else ".exe"
    _guest_path = f"C:\\nemesis\\{Path(a.sample).stem}{_esuf}"
    fwdet = _fx.detect(a.sample)
    if fwdet.get("framework"):
        print(f"[framework] detected: {fwdet['framework']} ({fwdet.get('evidence')})")
        fw = _fx.host_extract(fwdet["framework"], a.sample, case.source_dir,
                              log=lambda m: rl.log("framework", m))
        if fw.get("status") != "extracted" and not a.no_autoload:
            try:
                fw = _fx.extract(t.guest(), fwdet["framework"], _guest_path,
                                 case.source_dir, log=lambda m: rl.log("framework", m))
            except Exception as exc:
                rl.log("framework", f"guest extract failed: {exc}")
        case.add("framework_extract", fw)
        print(f"[framework] {fw.get('status')}: {fw.get('source_file') or '-'}")
    if not a.no_autoload:
        try:
            gs = _gs.analyze(t.guest(), _guest_path); case.add("guest_deobfuscation", gs)
            if gs.get("dotnet"):
                print(f"[.net] de4dot: obfuscator={gs.get('obfuscator')}, "
                      f"deobfuscated={bool(gs.get('deobfuscated'))}")
        except Exception as exc:
            rl.log("guest_static", f"failed: {exc}")

    # author / build recon on the packed sample
    attr = attribution.analyze(a.sample); case.add("attribution", attr)
    for b in attr.get("summary", []):
        print(f"[recon] {b}")

    try:                                                      # author clustering: fingerprints of the packed sample
        _fp = dict(case.data["stages"].get("author_fingerprints") or {})     # merge: the dump fingerprints may already be there
        _fp["packed sample"] = attribution.fingerprints(a.sample)
        _mq = attribution.masquerade_note(attr, _fp["packed sample"], bool((packed_triage.get("packing") or {}).get("likely_packed")))
        if _mq:
            print(f"[recon] {_mq}"); attr.setdefault("summary", []).append(_mq); case.add("attribution", attr)
        case.add("author_fingerprints", _fp)
        case.add("author_links", {"links": attribution.link_cases(_fp, str(case.dir.parent), exclude=case.dir.name)[:25]})
    except Exception as _e:
        print(f"[recon] fingerprints skipped: {_e}")

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
    # STAGE 3 deep static (decrypted): scan any decrypted output the decryptor produced.
    # Inert until we actually run a recovered decryptor (Phase 2); forward-wired here.
    dec_outputs = list(dec.get("decrypted_files", []))
    dec_outputs += [str(p) for p in case.decryptor_dir.glob("*.decrypted")]
    # in-place CryptDecrypt plaintext captured during the trace (tagged `decrypted`)
    for ev in (case.data["stages"].get("api_trace", {}) or {}).get("trace", []):
        capx = ev.get("capture") or {}
        if capx.get("decrypted") and capx.get("local_dump"):
            dec_outputs.append(capx["local_dump"])
    if dec_outputs:
        merged = {"stage": "decrypted", "sources": []}
        for p in dec_outputs:
            try:
                ds = memstatic.deep_scan(p, stage="decrypted"); ds["source"] = Path(p).name
                merged["sources"].append(ds)
            except Exception:
                pass
        if merged["sources"]:
            case.add("deep_static_decrypted", merged)
            print(f"[static] decrypted: scanned {len(merged['sources'])} decrypted artifact(s)")

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
            try:                                       # what it DID (reads, loads, crypto use), not only what it changed
                from nanalyst import procmon_summary as _pms
                _pm = case.artifacts_dir / "run" / "pm.csv"
                if _pm.exists():
                    case.add("procmon_summary", _pms.summarize(str(_pm), "malware.exe"))
            except Exception as _e:
                print(f"[detonate] procmon summary skipped: {_e}")
            # re-classify with behavioral evidence now included
            case.add("classification", classifier.classify(case.data))
        else:
            print("[detonate] could not stage the sample on the guest; skipped")

    # ---- category (what kind of malware + what to track) and file-encryption analysis (additive, guarded) ----
    try:
        from nanalyst import category_guide as _cg, crypto_analysis as _ca
        cat = _cg.categorize(case.data); case.add("malware_category", cat)
        print(f"[category] {cat['primary']}" + "".join(
            f" | {c['category']}: {c['confidence']} ({c['observed']} live / {c['present_only']} in code)" for c in cat["categories"][:3]))
        fc = _ca.analyze_case(case.data, case.decryptor_dir); case.add("file_crypto", fc)
        print(f"[crypto] {fc['verdict']}")
    except Exception as _e:
        print(f"[category/crypto] skipped: {_e}")

    # ---- AI assessment of the later stages (unpacked / decrypted) — same brain, same log ----
    if brain is not None and brain.available:
        for stg_name in ("unpacked", "decrypted"):
            if not case.data["stages"].get(f"deep_static_{stg_name}"):
                continue
            a_out = _sr.assess(brain, _sr.build_context(case.data, stg_name))
            if a_out:
                case.add(f"ai_assessment_{stg_name}", a_out)
                print(f"[ai] {stg_name}: family={a_out.get('likely_family')} "
                      f"({a_out.get('family_confidence')}); "
                      f"{len(a_out.get('config_leads', []))} config lead(s)")
    if _ai_log is not None:
        try:
            _ai_log.close()
        except Exception:
            pass

    # ---- finalize: proof + reports + PDF. Wrapped so a failure here can NEVER lose the
    # analysis silently — the MD reports are written before the (external) PDF step, and any
    # error is surfaced, not swallowed. ----
    from nanalyst import report_consolidated as _consolidated
    from nanalyst import pdf as _pdf
    try:
        poc = proof.generate(case.data); case.add("proof_of_compromise", poc)
        print(f"[verdict] {poc['verdict']['label']} (confidence {poc['verdict']['confidence']}/100, "
              f"basis: {poc['verdict'].get('basis','?')}, {poc['completeness']})")
        case.add("tool_audit", ta.summary())
        audit.activate(None)
        # detection package for vendors: IOCs (tiered + filtered), YARA, Suricata, Sigma, STIX, hashes
        try:
            from nanalyst import package as _pkg
            _gw = Path("goodware")
            pk = _pkg.write_package(case.data, case.dir, goodware_dir=_gw if _gw.exists() else None)
            case.add("intel_package", pk)
            print(f"[intel] detection package: {pk.get('indicators', 0)} indicators "
                  f"({pk.get('high_confidence', 0)} high-confidence), {pk.get('excluded', 0)} filtered as noise, "
                  f"{pk.get('suricata_rules', 0)} Suricata, {pk.get('sigma_rules', 0)} Sigma, "
                  f"{sum(1 for y in pk.get('yara', []) if y.get('written'))}/{len(pk.get('yara', []))} YARA -> {pk['dir']}")
            for e in pk.get("errors", []):
                print(f"[intel]   !! {e}")
        except Exception as pexc:
            print(f"!! detection package failed (the analysis itself is intact): {pexc}")
        # write all markdown FIRST (cheap, local) so output survives even if the PDF step fails
        (case.dir / "ANALYSIS.md").write_text(_consolidated.build(case.data))
        (case.dir / "REPORT.md").write_text(detailed_report.generate(case.data))
        (case.dir / "METHODOLOGY.md").write_text(reproducibility.generate(case.data))
        (case.dir / "proof_of_compromise.md").write_text(proof.to_markdown(poc))
        print(f"[report] wrote ANALYSIS.md / REPORT.md / METHODOLOGY.md")
        try:
            outp = _pdf.md_to_pdf(str(case.dir / "ANALYSIS.md"))
            if outp:
                print(f"[pdf] consolidated report -> {Path(outp).name}")
        except Exception as pexc:
            print(f"!! PDF step failed (markdown reports are intact): {pexc}")
            rl.log("unpack", f"pdf failed: {pexc}")
    except Exception as fexc:
        import traceback as _tb
        print(f"!! finalization error: {fexc}\n{_tb.format_exc()}")
        rl.log("unpack", f"finalize failed: {fexc}")
    manifest = case.write_manifest()
    rl.log("unpack", "DONE")
    print(f"\n[analysis folder] {case.dir}")
    print(f"[REPORT] {case.dir / 'ANALYSIS.pdf'}  (single consolidated PDF)")
    print(f"[sources] REPORT.md / METHODOLOGY.md / proof_of_compromise.md (component markdown)")
    print(f"[manifest] {manifest}")
    print(f"[dumps index] {case.dumps_dir / 'DUMPS.md'}")
    print("[tool audit]\n" + ta.render())
    # analysis ran the sample under the debugger (and detonation if requested) — the VM
    # is now dirty. Reset before the next sample.
    print("\n" + "=" * 68)
    if res_result is not None and res_result.get("reusable"):
        print("  ANALYSIS COMPLETE. Sample process tree killed; no residue found.")
        print("  " + res_result["verdict"])
    else:
        print("  ANALYSIS COMPLETE. The VM has executed malware code and may be DIRTY.")
        if res_result is not None:
            print("  " + res_result["verdict"])
        print("  -> Shut down the VM, then WIPE/REVERT to the clean baseline:")
        print("     ./ReverseEngineeringMalwareAnalysis/revert-clean.sh")
        print("  Then boot fresh for the next sample. Never snapshot a VM that ran malware.")
    print("=" * 68)
    return 0


_ACTIVE = {}


class _Interrupted(BaseException):
    pass


def _rescue(reason: str):
    """The run broke (signal, crash, hang-kill). Never lose the work: contain the debuggee, mark the
    case interrupted, and render reports from every stage already persisted in case.json."""
    case = _ACTIVE.get("case")
    if case is None:
        return
    print(f"\n!! RUN INTERRUPTED ({reason}) — saving what was captured", flush=True)
    try:                                              # stop the debuggee so nothing is left loaded
        from nanalyst.vm.target import load as _load
        from nanalyst.x64dbg_mcp import X64dbgMCP
        _c = X64dbgMCP(_load("default"))
        if _c.ensure_tunnel():
            _c.initialize(); _c.tool("debug_stop", {})
            print("   debuggee stopped (contained)", flush=True)
    except BaseException as e:
        print(f"   could not contain the debuggee: {e}", flush=True)
    try:
        case.data["state"] = f"interrupted: {reason}"
        case.data["interrupted"] = {"reason": reason, "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                    "stages_completed": list(case.data["stages"].keys())}
        case.save()
        import regen_reports
        print("   " + regen_reports.regen(case.dir), flush=True)
        (case.dir / "ANALYSIS.md").write_text(__import__("nanalyst.report_consolidated", fromlist=["x"]).build(case.data))
        case.write_manifest()
        print(f"   partial case saved: {case.dir}\n   VM may be DIRTY — revert it before the next sample.", flush=True)
    except BaseException as e:
        print(f"   could not render partial reports: {e}  (case.json is intact in {case.dir})", flush=True)


def _guarded():
    import signal
    signal.signal(signal.SIGHUP, signal.SIG_IGN)          # terminal/shell closing must not kill the run
    def _term(signum, _f):
        raise _Interrupted(signal.Signals(signum).name)
    signal.signal(signal.SIGTERM, _term)
    try:
        return main()
    except (_Interrupted, KeyboardInterrupt) as e:
        _rescue(str(e) or "keyboard interrupt"); return 130
    except Exception as e:
        import traceback; traceback.print_exc()
        _rescue(f"crash: {type(e).__name__}: {e}"); return 1


if __name__ == "__main__":
    sys.exit(_guarded())
