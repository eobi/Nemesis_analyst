"""Detailed analyst report — itemized per tool and per phase, with a
static vs memory-dump vs live-detonation comparison.
"""
from __future__ import annotations

from .proof import ATTACK_MAP


def _h(s): return "\n".join(s) if isinstance(s, list) else s


def generate(case: dict) -> str:
    st = case.get("stages", {})
    triage = st.get("triage", {})
    unpacked = st.get("triage_unpacked")      # present if UPX was auto-unpacked
    pe = (unpacked or triage).get("pe", {})   # prefer the unpacked PE profile
    ghidra = st.get("static_ghidra", {})
    deob = st.get("guest_deobfuscation", {})
    det = st.get("detonation", {})
    mem = (det or {}).get("memory_static", {})
    poc = st.get("proof_of_compromise", {})
    cls = st.get("classification", {})
    L = []

    L.append(f"# Malware Analysis Report — {case.get('name')}")
    L.append("")
    v = poc.get("verdict", {})
    L.append(f"**Verdict:** {v.get('label','?')}  (confidence {v.get('confidence','?')}/100)  ")
    if cls.get("primary"):
        L.append(f"**Family (behavioral):** {cls['primary']}"
                 + (f" (+{', '.join(cls['secondary'])})" if cls.get("secondary") else "") + "  ")
    L.append(f"**Completeness:** {poc.get('completeness','?')}  ")
    L.append(f"**SHA-256:** `{case.get('sha256')}`  ")
    L.append(f"**Size:** {case.get('size',0):,} bytes  ")
    L.append("")

    # ---------- executive summary ----------
    L.append("## 1. Executive summary")
    summary = []
    summary.append(f"- Identified as **{triage.get('filetype')} / {triage.get('compiler')}** "
                   f"({triage.get('arch')}).")
    pk = triage.get("packing", {})
    if pk.get("likely_packed"):
        summary.append(f"- **Packed/obfuscated** ({pk.get('packer') or 'custom'}); "
                       f"entry-point entropy high — static view of the on-disk file is limited.")
    if deob and deob.get("dotnet"):
        summary.append(f"- .NET assembly; deobfuscated with de4dot "
                       f"(obfuscator: {deob.get('obfuscator')}).")
    if det:
        summary.append(f"- Detonated live in an isolated instance for {det.get('duration_s')}s; "
                       f"behavior, network, and a process memory dump were captured.")
    if mem.get("urls") or mem.get("ips"):
        summary.append(f"- Memory dump revealed **{len(mem.get('urls',[]))} URL(s)** and "
                       f"**{len(mem.get('ips',[]))} IP(s)** not visible in static analysis.")
    L += summary
    L.append("")

    # ---------- author / build reconnaissance ----------
    attr = st.get("attribution", {}) or {}
    if attr.get("available") and attr.get("summary"):
        L.append("## 1a. Author / build reconnaissance")
        for b in attr["summary"]:
            L.append(f"- {b}")
        vi = attr.get("version_info", {})
        if vi:
            L.append("- Full version-info resource:")
            for k, vv in vi.items():
                L.append(f"  - {k}: `{vv}`")
        L.append("")

    # ---------- behavioral classification ----------
    if cls.get("families"):
        L.append("## 1b. Behavioral classification")
        L.append(cls.get("summary", ""))
        L.append("")
        L.append("| Family | Score | Evidence |")
        L.append("|---|---|---|")
        for f in cls["families"]:
            L.append(f"| **{f['family']}** | {f['score']} | {'; '.join(f['evidence'])} |")
        if cls.get("persistence"):
            L.append("")
            L.append(f"**Persistence:** {', '.join(cls['persistence'])}")
        L.append("")

    # ---------- dynamic unpack (debugger-driven, custom packers) ----------
    du = st.get("dynamic_unpack")
    if du:
        L.append("## 1c. Dynamic unpack (x64dbg, debugger-driven)")
        L.append(f"- Detected OEP: `{du.get('oep')}` | reached OEP: **{du.get('reached_oep')}** "
                 f"| dump mode: {du.get('dump_mode')}")
        if du.get("api_hits"):
            L.append(f"- Unpack API hit counts: "
                     f"{', '.join(f'{k}×{v}' for k,v in du['api_hits'].items())} "
                     "(real unpack often happens on the Nth call).")
        dtri = st.get("triage_dumped")
        if dtri:
            L.append(f"- Dumped PE after OEP-aware reconstruction: **{dtri.get('filetype')}**, "
                     f"packer `{dtri.get('packing',{}).get('packer') or 'none'}`, "
                     f"{dtri.get('pe',{}).get('import_func_count')} imports "
                     f"(vs {pe.get('import_func_count')} in the packed view).")
        vf = st.get("verify_unpack")
        if vf:
            L.append("")
            L.append(f"**Unpack verification: {vf['verdict']} ({vf['confidence']}/100)**")
            cmp = vf.get("compared", {})
            if cmp:
                L.append("")
                L.append("| File | Size | MD5 | SHA-256 |")
                L.append("|---|---|---|---|")
                for role, d in (("packed (input)", cmp.get("packed", {})),
                                ("unpacked (output)", cmp.get("unpacked", {}))):
                    L.append(f"| {role}: {d.get('name','?')} | {d.get('size') or '?'} | "
                             f"`{d.get('md5') or '?'}` | `{d.get('sha256') or '?'}` |")
                if vf.get("note"):
                    L.append(f"> {vf['note']}")
            if vf.get("breakdown"):
                L.append("")
                L.append("Score breakdown (why this verdict):")
                L.append("| Signal | Points | Detail |")
                L.append("|---|---|---|")
                for b in vf["breakdown"]:
                    L.append(f"| {b['signal']} | {b['points']}/{b['max']} | {b['detail']} |")
        mu = st.get("memory_static_unpack")
        if mu:
            L.append(f"- Re-static of the clean dump: {len(mu.get('urls',[]))} URL(s), "
                     f"{len(mu.get('ips',[]))} IP(s), {len(mu.get('registry',[]))} registry key(s).")
            for u in mu.get("urls", [])[:12]:
                L.append(f"  - URL `{u}`")
            for ip in mu.get("ips", [])[:12]:
                L.append(f"  - IP `{ip}`")
        L.append("")

    # ---------- hint-driven dumps (indirect-transfer sites) ----------
    hd = st.get("hint_dumps", {}) or {}
    if hd.get("results"):
        L.append("## 1d. Hint-driven dumps (static anomaly -> dynamic extraction)")
        L.append("Static analysis flagged indirect control transfers (`call reg` / push-ret) "
                 "where a register points at code the packer wrote. The debugger broke at each "
                 "site, resolved the register, and dumped the memory it pointed to:")
        L.append("")
        L.append("| Site | Instr | Target | Classification | IOCs | Dump |")
        L.append("|---|---|---|---|---|---|")
        for r in hd["results"]:
            ioc = r.get("ioc", {}) or {}
            iocs = f"{len(ioc.get('urls',[]))}U/{len(ioc.get('ips',[]))}I" if ioc else "-"
            dump = "yes" if r.get("dump_path") else ("not reached" if not r.get("reached") else "no")
            L.append(f"| `{r['site']}` | {r.get('detail')} | `{r.get('target')}` | "
                     f"{r.get('classification') or '-'} | {iocs} | {dump} |")
        L.append("")

    # ---------- API-arsenal trace ----------
    at = st.get("api_trace", {}) or {}
    if at.get("trace"):
        L.append("## 1e. API trace (live dynamic behavior)")
        counts = at.get("counts", {})
        L.append("Watched the P1/P2 API arsenal during execution. Call counts:")
        L.append("| API | Calls |")
        L.append("|---|---|")
        for api, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            L.append(f"| `{api}` | {n} |")
        L.append("")
        L.append("Notable calls (with captured arguments / memory):")
        for ev in at["trace"][:30]:
            args = ", ".join(f"{k}={v}" for k, v in list((ev.get('args') or {}).items())[:4])
            cap = ev.get("capture") or {}
            note = f" — {cap['note']}" if cap.get("note") else ""
            dumped = " [dumped]" if cap.get("dump") or cap.get("local_dump") else ""
            L.append(f"- `{ev['api']}`({args}){note}{dumped}")
        if at.get("watched_regions"):
            L.append("")
            L.append(f"Allocated regions watched: {', '.join('`%s`' % r for r in at['watched_regions'][:12])}")
        L.append("")

    # ---------- PE reconstruction ----------
    pr = st.get("pe_reconstruction", {}) or {}
    if pr.get("best"):
        b = pr["best"]
        L.append("## 1f. PE reconstruction (memory dump -> valid PE, IAT rebuilt)")
        L.append("Memory dumps were rebuilt into valid PEs (align raw<->virtual + fix ImageBase), "
                 "so the import table/IAT resolve:")
        L.append(f"- Best image: `{__import__('pathlib').Path(b['out']).name}` from `{b.get('source')}` "
                 f"-> **{b['imports']} imports across {b['dll_count']} DLLs**")
        L.append(f"- DLLs: {', '.join('`%s`' % d for d in b.get('dlls', [])[:14])}")
        rtri = st.get("triage_reconstructed", {})
        if rtri:
            caps = (rtri.get("pe", {}) or {}).get("suspicious_apis", {})
            if caps:
                L.append("- Capabilities (from rebuilt imports):")
                for cat, apis_ in caps.items():
                    L.append(f"  - **{cat}**: {', '.join(apis_[:10])}")
        L.append("")

    # ---------- per-tool static ----------
    L.append("## 2. Static analysis — what each tool discovered")

    L.append("### 2.1 Detect It Easy (identification)")
    L.append(f"- File type: **{triage.get('filetype')}**")
    L.append(f"- Compiler/runtime: **{triage.get('compiler')}**")
    L.append(f"- Linker: {triage.get('linker')}")
    L.append(f"- Packer (signature): {pk.get('packer') or 'none matched (custom/unknown)'}")
    L.append("")

    if unpacked:
        pk0 = triage.get("packing", {})
        L.append(f"> **Auto-unpacked:** sample was {pk0.get('packer') or 'packed'}; "
                 f"statically unpacked (upx -d) before analysis. The PE profile and Ghidra "
                 f"results below are from the UNPACKED file. Packed on-disk had "
                 f"{triage.get('pe',{}).get('import_func_count')} imports / sections "
                 f"{[s['name'] for s in triage.get('pe',{}).get('sections',[])]}.")
        L.append("")
    L.append("### 2.2 PE profile (pefile) — the PE Studio data")
    L.append(f"- Architecture: {pe.get('arch')} | kind: {pe.get('kind')} | "
             f"entry point: 0x{pe.get('entrypoint_rva',0):x} in `{pe.get('entrypoint_section')}`")
    L.append(f"- Imports: {pe.get('import_func_count')} functions / {pe.get('import_dll_count')} DLLs "
             f"| TLS callbacks: {len(pe.get('tls_callbacks',[]))} | signed: {pe.get('signed')} "
             f"| overlay: {pe.get('overlay_bytes')} bytes")
    if pe.get("sections"):
        L.append("- Sections (name / flags / entropy):")
        for s in pe["sections"]:
            flags = ("X" if s["exec"] else "-") + ("W" if s["write"] else "-")
            ep = " <entry" if s["contains_ep"] else ""
            L.append(f"  - `{s['name']}` {flags} entropy {s['entropy']}{ep}")
    caps = pe.get("suspicious_apis", {})
    if caps:
        L.append("- Capabilities by imported API:")
        for cat, apis in caps.items():
            L.append(f"  - **{cat}**: {', '.join(apis)}")
    L.append("")

    fw = st.get("framework_extract", {}) or {}
    if fw.get("framework"):
        L.append(f"### 2.2b Framework extraction — {fw.get('label', fw['framework'])}")
        if fw.get("status") == "extracted":
            L.append(f"- This is a **{fw.get('label')}**: the EXE is an interpreter stub with the "
                     "real script bundled inside. A disassembler only shows the stub; the extractor "
                     "below recovered the **original structured source** (far more readable).")
            L.append(f"- Recovered source: `{fw.get('source_file')}` "
                     f"({fw.get('line_count')} lines) via {fw.get('mode')}")
            if fw.get("urls"):
                L.append(f"- URLs in source: {', '.join('`%s`' % u for u in fw['urls'][:10])}")
            if fw.get("ips"):
                L.append(f"- IPs in source: {', '.join('`%s`' % i for i in fw['ips'][:10])}")
            if fw.get("commands"):
                L.append(f"- Notable commands/APIs: {', '.join(fw['commands'])}")
            if fw.get("shellcode_blob_count"):
                L.append(f"- **{fw['shellcode_blob_count']} embedded shellcode blob(s)** "
                         "(hex literals that decode to non-printable x86 — a loader).")
            if fw.get("decoded_hex_strings"):
                L.append("- Decoded hidden (hex-literal) strings:")
                for s in fw["decoded_hex_strings"][:12]:
                    L.append(f"  - `{s[:160]}`")
        else:
            L.append(f"- Status: **{fw.get('status')}** — {fw.get('hint', '')}")
            for line in fw.get("instructions", []):
                L.append(f"  - {line}")
        L.append("")

    L.append("### 2.3 Ghidra (disassembly / code review)")
    if ghidra.get("available"):
        L.append(f"- Functions recovered: **{ghidra.get('function_count')}**")
        L.append(f"- Control-flow anomalies: {ghidra.get('anomaly_count')} "
                 f"(indirect-register call/jmp: {ghidra.get('indirect_register_count')})")
        for a in (ghidra.get("anomalies") or [])[:8]:
            L.append(f"  - `{a['addr']}` {a['type']}: {a['detail']}")
        if ghidra.get("suspicious_apis"):
            L.append(f"- Suspicious API references: {', '.join(ghidra['suspicious_apis'])}")
        s = ghidra.get("strings", {})
        for lbl in ("urls", "ips", "registry", "suspicious"):
            if s.get(lbl):
                L.append(f"- Static strings ({lbl}): {', '.join(s[lbl][:8])}")
    else:
        L.append(f"- unavailable: {ghidra.get('error')}")
    L.append("")

    L.append("### 2.4 de4dot (.NET deobfuscation)")
    if deob and deob.get("dotnet"):
        L.append(f"- .NET assembly: yes")
        L.append(f"- Obfuscator detected: **{deob.get('obfuscator')}**")
        if deob.get("deobfuscated"):
            L.append(f"- Cleaned assembly: `{deob['deobfuscated']}` — open in dnSpy for readable symbols")
    else:
        L.append("- not a .NET assembly (native path)")
    L.append("")

    # ---------- dynamic: debugger/memory ----------
    L.append("## 3. Dynamic analysis (A) — memory dump + re-static")
    if det and det.get("memory_dump"):
        L.append(f"- Process memory dumped during execution: `{det['memory_dump']}` "
                 f"({mem.get('dump_size',0)//1024} KB, {mem.get('string_count',0):,} strings extracted)")
        L.append("- **Re-static on the memory dump revealed (not visible on disk):**")
        for lbl in ("urls", "ips", "registry", "emails"):
            vals = mem.get(lbl, [])
            if vals:
                L.append(f"  - {lbl.upper()}:")
                for x in vals[:20]:
                    L.append(f"    - `{x}`")
        if mem.get("suspicious_keywords"):
            L.append(f"  - Keywords: {', '.join(mem['suspicious_keywords'])}")
    else:
        L.append("- No full-process dump captured (process exited quickly or injected elsewhere).")
    carved = (det or {}).get("carved_pes", [])
    if carved:
        SYSMOD = ("mscorwks", "mscoree", "clr.dll", "clrjit", "ntdll", "kernel32",
                  "kernelbase", "user32", "gdi32", "ole32", "oleaut32", "advapi32",
                  "mscorlib", "system.", "comctl", "shell32")

        def real_ips(ips):
            out = []
            for ip in ips:
                o = ip.split(".")
                if len(o) != 4 or not all(p.isdigit() for p in o):
                    continue
                if not all(0 <= int(p) <= 255 for p in o):   # drops OID fragments (e.g. .311, .999)
                    continue
                if int(o[0]) < 3 or int(o[0]) in (127, 169, 224):
                    continue
                if ip.endswith(".0.0") or ip.endswith(".0"):  # version-like, not an IP
                    continue
                out.append(ip)
            return out

        seen, uniq = set(), []
        for c in carved:
            if c["name"] in seen:
                continue
            seen.add(c["name"]); uniq.append(c)
        L.append(f"- **PE-sieve carved {len(uniq)} PE module(s) from process memory:**")
        for c in uniq:
            sysmod = any(s in c["name"].lower() for s in SYSMOD)
            tag = (" — a SYSTEM module flagged as modified in memory (possible in-memory "
                   "patch/hook; not the payload itself)") if sysmod else ""
            L.append(f"  - `{c['name']}` ({c['size']//1024} KB){tag}")
            for u in c["urls"][:8]:
                L.append(f"    - URL `{u}`")
            for ip in real_ips(c["ips"])[:8]:
                L.append(f"    - IP `{ip}`")
            kw = ", ".join(c.get("suspicious_keywords", [])[:8])
            if kw and not sysmod:
                L.append(f"    - keywords: {kw}")
        if uniq and all(any(s in c["name"].lower() for s in SYSMOD) for c in uniq):
            L.append("  - *Only system modules were flagged. For this .NET sample the real payload "
                     "lives in the managed heap — read it from the de4dot-cleaned assembly in dnSpy. "
                     "(PE-sieve carving is most decisive on NATIVE packed malware.)*")
    L.append("")

    # ---------- dynamic: live detonation ----------
    L.append("## 4. Dynamic analysis (B) — live detonation (observed behavior)")
    if det:
        L.append(f"- Ran {det.get('duration_s')}s, isolated (FakeNet contained all network). "
                 f"Completed: {det.get('completed')}")
        for label, key in [("Network (FakeNet)", "network"),
                           ("Registry changes (Regshot diff)", "registry_changes"),
                           ("Files dropped/created", "files_dropped")]:
            vals = det.get(key, [])
            L.append(f"- **{label}:** {len(vals)}")
            for x in vals[:20]:
                L.append(f"  - `{x}`")
    else:
        L.append("- Not detonated.")
    L.append("")

    # ---------- comparison ----------
    L.append("## 5. Comparison — static vs memory vs live detonation")
    L.append("| Indicator source | URLs | IPs | Registry | Notes |")
    L.append("|---|---|---|---|---|")
    s_urls = len((ghidra.get("strings", {}) or {}).get("urls", []))
    s_ips = len((ghidra.get("strings", {}) or {}).get("ips", []))
    L.append(f"| Static (on-disk) | {s_urls} | {s_ips} | - | limited (packed/obfuscated) |")
    L.append(f"| Memory dump (re-static) | {len(mem.get('urls',[]))} | {len(mem.get('ips',[]))} | "
             f"{len(mem.get('registry',[]))} | decrypted at runtime |")
    dn = det.get("network", []) if det else []
    L.append(f"| Live detonation | {sum('http' in x.lower() for x in dn)} | - | "
             f"{len(det.get('registry_changes',[])) if det else 0} | observed behavior |")
    L.append("")
    L.append("*Interpretation:* indicators the on-disk file hides (because it is packed/obfuscated) "
             "surface once the sample decrypts itself in memory and acts on the network — which is why "
             "the memory dump and live detonation are decisive.")
    L.append("")

    # ---------- ATT&CK ----------
    L.append("## 6. MITRE ATT&CK")
    for t in poc.get("attack_techniques", []):
        L.append(f"- {t}")
    L.append("")

    # ---------- artifacts ----------
    L.append("## 7. Artifacts")
    L.append(f"- Analysis folder: `{case.get('name')}_{(case.get('sha256') or '')[:12]}/` "
             "(subfolders: dumps/, source/, decryptor/, logs/, artifacts/)")
    if deob and deob.get("deobfuscated"):
        L.append(f"- Deobfuscated assembly: `{deob['deobfuscated']}`")
    if det:
        L.append(f"- Detonation artifacts: `{det.get('artifacts_dir')}` "
                 "(memory .dmp, FakeNet pcap/console, Procmon .pml/.csv, reg snapshots, file lists)")
    L.append("")
    cr = st.get("crypto_recovery", {}) or {}
    if cr.get("schemes"):
        L.append("## 7a. Encryption analysis & recovery")
        for n in cr.get("notes", []):
            L.append(f"- {n}")
        L.append("| Algorithm | Confidence | Status | Script |")
        L.append("|---|---|---|---|")
        gen_by_algo = {g["algo"]: g for g in cr.get("generated", [])}
        for s in cr["schemes"]:
            g = gen_by_algo.get(s["algo"])
            status = ("RUNNABLE" if s.get("recoverable") and not s.get("asymmetric")
                      else "NOT recoverable (asymmetric)" if s.get("asymmetric") else "template")
            script = f"`decryptor/{__import__('pathlib').Path(g['path']).name}`" if g and g.get("path") else "-"
            L.append(f"| {s['algo'].upper()} | {s['confidence']}/100 | {status} | {script} |")
        keys = (cr.get("candidate_keys_hex") or []) + (cr.get("candidate_keys_ascii") or [])
        if keys:
            L.append("")
            L.append("Candidate keys recovered: " + ", ".join(f"`{k}`" for k in keys[:8]))
        L.append("")

    ta = st.get("tool_audit", {}) or {}
    if ta:
        L.append("## 7b. Tool audit (per-subtool reliability)")
        L.append(f"- Total subtool calls: **{ta.get('total_calls', 0)}** "
                 f"({ta.get('ok', 0)} ok, {ta.get('errors', 0)} failed) in "
                 f"{ta.get('total_ms', 0)} ms.")
        if ta.get("by_tool"):
            L.append("| Tool | Calls | Errors | Time (ms) |")
            L.append("|---|---|---|---|")
            for tool, b in sorted(ta["by_tool"].items(), key=lambda kv: -kv[1]["ms"]):
                L.append(f"| `{tool}` | {b['calls']} | {b['errors']} | {b['ms']} |")
        if ta.get("failures"):
            L.append("")
            L.append("**Failed calls (trace these first):**")
            for fl in ta["failures"]:
                L.append(f"- #{fl['seq']} `{fl['tool']}` — {fl['error']}")
        L.append("- Full per-call ledger (inputs, output, timing): `logs/tool_audit.jsonl`")
        L.append("")

    L.append("## 8. Notes & limitations")
    L.append("- Detonation ran in an isolated VM with no real internet (FakeNet). Revert the snapshot after.")
    L.append("- Network/OS/tooling noise is filtered from the indicators above.")
    L.append("")
    return "\n".join(L)
