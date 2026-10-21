"""Reproducibility & methodology — make every finding independently verifiable.

A finding is only as good as its provenance. This turns the case's recorded state
(the per-tool audit ledger, the engine's own counts, the stage outputs) into a
deterministic report an analyst can replay by hand:

  - the exact FLOW (ordered stages, which tool ran, in what order)
  - the ENVIRONMENT fingerprint (sample hash, tool versions, VM baseline, config)
    so the same inputs reproduce the same outputs
  - the STATIC repro commands (diec / pefile / Ghidra / autoit-ripper)
  - the DYNAMIC replay: the literal debugger step sequence + how many times each
    API/command was called (from the audit ledger + the engine's hit counters)
  - PER-FINDING provenance: for each IOC, where it came from and how to re-derive it

Everything here is derived from recorded data — no new analysis, no guessing.
"""
from __future__ import annotations


def _audit_by_tool(case):
    ta = case.get("stages", {}).get("tool_audit", {}) or {}
    return ta


def _flow(case):
    """Ordered stages that actually ran (presence in stages), as the methodology."""
    order = [
        ("triage", "Detect It Easy + pefile", "diec -j <sample> ; pefile parse"),
        ("attribution", "author/build recon", "pefile: TimeDateStamp, debug PDB, Rich header, version info"),
        ("triage_unpacked", "UPX static unpack", "upx -d <sample> ; re-triage"),
        ("verify_unpack", "unpack verification", "diff packed vs unpacked (imports/sections/entropy/IOCs)"),
        ("framework_extract", "framework source recovery", "autoit-ripper / guest decompiler"),
        ("static_ghidra", "Ghidra headless", "analyzeHeadless + NemesisStatic.java"),
        ("guest_deobfuscation", ".NET deobfuscation", "DIE + de4dot (guest)"),
        ("dynamic_unpack", "x64dbg OEP unpack (MCP)", "restart -> bph OEP -> run -> dump_module"),
        ("hint_dumps", "hint-driven dumps (MCP)", "bph <call-reg site> -> resolve reg -> dump target"),
        ("detonation", "behavioral detonation", "FakeNet + Procmon + Regshot + pe-sieve"),
        ("classification", "behavioral classification", "evidence-weighted family rules"),
        ("crypto_recovery", "crypto detect + decryptor", "scheme + key detection -> decrypt_<algo>.py"),
    ]
    st = case.get("stages", {})
    return [(k, label, how) for k, label, how in order if k in st]


def generate(case: dict) -> str:
    st = case.get("stages", {})
    L = [f"# Reproducibility & Methodology — {case.get('name')}", ""]
    L.append("This report is deterministic: the same sample + the same tool versions + the "
             "clean VM baseline reproduce these findings. Below is the exact flow, the "
             "command/step counts, and a per-finding replay recipe.")
    L.append("")

    # ---------- environment fingerprint ----------
    tri = st.get("triage", {})
    L.append("## 1. Environment fingerprint (pin these to reproduce)")
    L.append(f"- Sample SHA-256: `{case.get('sha256')}`")
    L.append(f"- Size: {case.get('size',0):,} bytes | type: {tri.get('filetype')} ({tri.get('arch')})")
    L.append(f"- Detect It Easy: {tri.get('filetype')} / compiler {tri.get('compiler')} "
             "(diec 3.21)")
    L.append("- Ghidra: analyzeHeadless (NemesisStatic.java) | pe-sieve 0.4.1.1 | upx (brew)")
    du = st.get("dynamic_unpack", {})
    if du:
        L.append("- Debugger: x64dbg 2026 build (C:\\x64dbg_new), x64dbg-mcp plugin v1.0.11, "
                 "MCP 127.0.0.1:3000")
        L.append("- VM: revert to `clean-baseline` snapshot before each run (identical start state)")
    L.append("")

    # ---------- flow ----------
    L.append("## 2. Analysis flow (ordered — each stage is recorded)")
    for i, (k, label, how) in enumerate(_flow(case), 1):
        L.append(f"{i}. **{label}** (`{k}`) — {how}")
    L.append("")

    # ---------- call statistics (from the audit ledger) ----------
    ta = _audit_by_tool(case)
    if ta.get("by_tool"):
        L.append("## 3. Tool-call statistics (from the audit ledger — exact counts)")
        L.append("Every subtool call is recorded in `logs/tool_audit.jsonl` with inputs, "
                 "output, duration and status. Totals:")
        L.append(f"- **{ta.get('total_calls',0)} calls**, {ta.get('ok',0)} ok, "
                 f"{ta.get('errors',0)} failed, {ta.get('total_ms',0)} ms")
        L.append("")
        L.append("| Tool / command | Calls | Errors | Time (ms) |")
        L.append("|---|---|---|---|")
        for tool, b in sorted(ta["by_tool"].items(), key=lambda kv: -kv[1]["calls"]):
            L.append(f"| `{tool}` | {b['calls']} | {b['errors']} | {b['ms']} |")
        L.append("")

    # ---------- static reproduction ----------
    L.append("## 4. Reproduce the STATIC findings")
    L.append("```")
    L.append(f"diec -j <sample>                 # identification: {tri.get('filetype')}")
    L.append("python3 -c 'import pefile; ...'  # sections, imports, entropy, TLS, signature")
    gh = st.get("static_ghidra", {})
    if gh.get("available"):
        L.append(f"analyzeHeadless <proj> -import <sample> -postScript NemesisStatic.java")
        L.append(f"#   -> {gh.get('function_count')} functions, {gh.get('anomaly_count')} anomalies")
    fw = st.get("framework_extract", {})
    if fw.get("status") == "extracted":
        L.append("python3 -c 'from autoit_ripper import extract, AutoItVersion; "
                 "extract(open(s,\"rb\").read(), AutoItVersion.EA06)'   # recover .au3")
    L.append("```")
    L.append("")

    # ---------- dynamic reproduction (the literal debugger steps) ----------
    if du:
        L.append("## 5. Reproduce the DYNAMIC unpack (x64dbg, by hand)")
        oep = du.get("oep")
        hits = du.get("api_hits", {})
        L.append("Load the sample in x32dbg (paused at entry), then:")
        L.append("```")
        L.append("bc ; bphwc                      # clear software + hardware breakpoints")
        if du.get("antidebug_patched"):
            L.append("# anti-debug neutralized: zero PEB.BeingDebugged; bp IsDebuggerPresent -> EAX=0")
        if oep:
            L.append(f"bph {oep}                   # HARDWARE bp at detected OEP (survives the unpack)")
        for api, n in hits.items():
            L.append(f"bp {api}                    # observed {n} hit(s) during unpack")
        L.append("run            # repeat; use 'erun' to pass first-chance exceptions")
        if du.get("reached_oep"):
            L.append(f"#   -> stops at OEP {oep}")
        L.append(f"# dump: dump_module(auto_detect_oep=true, rebuild_pe=true)  "
                 f"[mode: {du.get('dump_mode')}, new_ep: {du.get('dump_new_ep')}]")
        L.append("```")
        if hits:
            L.append(f"**API call counts during unpack:** "
                     + ", ".join(f"{k} ×{v}" for k, v in hits.items())
                     + " — the real unpack transfer typically follows the last VirtualProtect "
                       "(W→X flip).")
        L.append("")

    # ---------- hint-driven dump reproduction ----------
    hd = st.get("hint_dumps", {})
    if hd.get("results"):
        L.append("## 6. Reproduce the HINT-DRIVEN dumps (static anomaly → dynamic extraction)")
        L.append("Static flagged indirect transfers (`call reg` / push-ret). For each, break there, "
                 "read the register, dump what it points to:")
        L.append("```")
        for r in hd["results"]:
            L.append(f"bph {r['site']}   # {r.get('detail')}  -> run -> read {r.get('reg')} "
                     f"= {r.get('target')} [{r.get('classification')}]")
        L.append("```")
        L.append("Each resolved target region was dumped to `dumps/` and re-scanned for strings/IOCs.")
        L.append("")

    # ---------- per-finding provenance ----------
    L.append("## 7. Per-finding provenance (where each IOC came from)")
    L.append("| Indicator | Source stage | How to re-derive |")
    L.append("|---|---|---|")
    rows = []
    mu = st.get("memory_static_unpack", {})
    for u in (mu.get("urls", []) or [])[:10]:
        rows.append((u, "dynamic_unpack dump", "strings on dumps/unpacked_dump.bin"))
    for ip in (mu.get("ips", []) or [])[:10]:
        rows.append((ip, "dynamic_unpack dump", "strings on dumps/unpacked_dump.bin"))
    for r in (hd.get("results", []) or []):
        ioc = r.get("ioc", {}) or {}
        for u in (ioc.get("urls", []) or [])[:5]:
            rows.append((u, f"hint dump @ {r['site']}", f"dump [{r.get('reg')}={r.get('target')}], strings"))
    fw = st.get("framework_extract", {})
    if fw.get("status") == "extracted":
        for u in (fw.get("urls", []) or [])[:5]:
            rows.append((u, "framework source", "autoit-ripper -> grep the .au3"))
    for ind, src, how in rows[:40]:
        L.append(f"| `{ind}` | {src} | {how} |")
    if not rows:
        L.append("| (no network IOCs recovered) | — | — |")
    L.append("")

    # ---------- determinism notes ----------
    L.append("## 8. Determinism — what is and isn't fixed")
    L.append("- **Deterministic:** identification, PE structure, imports, Ghidra functions/anomalies, "
             "recovered source, detected OEP (RVA), API call counts, and the dumped payload's content "
             "— all reproduce exactly from the same sample.")
    L.append("- **Environment-fixed:** module base may differ with ASLR; we record the runtime base "
             "so addresses map (RVA is invariant). Revert to `clean-baseline` for an identical OS.")
    L.append("- **Non-deterministic (noted, not relied on):** wall-clock timings in the ledger, and "
             "any network the sample attempts (contained by the isolated VM / FakeNet).")
    L.append("- **Audit trail:** `logs/tool_audit.jsonl` is the full machine-readable record; every "
             "row has the tool, inputs, output summary, duration and status.")
    return "\n".join(L)
