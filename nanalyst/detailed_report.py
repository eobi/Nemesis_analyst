"""Detailed analyst report — itemized per tool and per phase, with a
static vs memory-dump vs live-detonation comparison.
"""
from __future__ import annotations

import time

import re
from pathlib import Path

from .proof import ATTACK_MAP


def _h(s): return "\n".join(s) if isinstance(s, list) else s


_DOMAIN = re.compile(r"https?://([^/:\s]+)")


def _collect_iocs(st: dict) -> dict:
    """Consolidate attacker-communication indicators (URLs/IPs/domains) from EVERY
    source — static strings, recovered framework source, memory dumps, the
    reconstructed PE, the API trace, and live detonation — each tagged with where
    it came from, so nothing an analyst needs is scattered across the report."""
    urls, ips, regs, doms = {}, {}, {}, {}

    def feed(src, d):
        for u in (d.get("urls") or []):
            urls.setdefault(u, set()).add(src)
        for i in (d.get("ips") or []):
            ips.setdefault(i, set()).add(src)
        for r in (d.get("registry") or []):
            regs.setdefault(r, set()).add(src)
        for dm in (d.get("domains") or []):
            doms.setdefault(dm, set()).add(src)

    # 3-stage deep static (packed / unpacked / decrypted) — tagged by stage
    feed("deep static (packed)", st.get("deep_static_packed", {}) or {})
    feed("deep static (unpacked)", st.get("deep_static_unpacked", {}) or {})
    for s in (st.get("deep_static_decrypted", {}) or {}).get("sources", []):
        feed("deep static (decrypted)", s)

    gh = st.get("static_ghidra", {})
    if gh.get("available"):
        feed("static (Ghidra strings)", gh.get("strings", {}) or {})
    fw = st.get("framework_extract", {}) or {}
    if fw.get("status") == "extracted":
        feed("recovered source", fw)
        for s in (fw.get("decoded_hex_strings") or []):
            for m in _DOMAIN.findall(s):
                urls.setdefault(f"http(s)://{m}", set()).add("recovered source (decoded)")
    feed("memory dump (re-static)", st.get("memory_static_unpack", {}) or {})
    feed("reconstructed PE", st.get("memory_static_reconstructed", {}) or {})
    for rd in (st.get("api_trace", {}) or {}).get("region_dumps", []):
        feed("API-trace region dump", rd.get("ioc", {}) or {})
    for pd in (st.get("api_trace", {}) or {}).get("plan_dumps", []):
        feed("AI-plan watch region", pd.get("ioc", {}) or {})
    det = st.get("detonation", {}) or {}
    feed("live detonation (memory)", det.get("memory_static", {}) or {})
    for n in (det.get("network") or []):
        if "http" in str(n).lower():
            urls.setdefault(str(n), set()).add("live detonation (network)")
        else:
            ips.setdefault(str(n), set()).add("live detonation (network)")

    domains = dict(doms)
    for u in urls:
        for dm in _DOMAIN.findall(u):
            domains.setdefault(dm, set()).update(urls[u])
    return {"urls": urls, "ips": ips, "domains": domains, "registry": regs}


_DS_CATS = [
    ("urls", "URLs"), ("domains", "Domains"), ("ips", "IPs"),
    ("file_paths", "File paths"), ("pdb_paths", "PDB build paths"),
    ("registry", "Registry keys"), ("mutex_hints", "Named objects / mutexes"),
    ("commands", "Shell commands"), ("service_ops", "Service ops"),
    ("user_agents", "User-Agents"), ("wallets", "Crypto wallets"),
    ("guids", "GUIDs"), ("emails", "Emails"),
    ("anti_analysis_indicators", "Anti-analysis indicators"),
    ("suspicious_keywords", "Suspicious keywords"), ("base64_blobs", "Base64 blobs"),
]


def _ds_render(ds: dict, title: str, out: list):
    """Render one deep-static stage (packed/unpacked/decrypted)."""
    out.append(f"### {title}")
    out.append(f"- Size {ds.get('size',0):,} bytes · entropy **{ds.get('entropy','?')}** "
               f"· {ds.get('string_count',0):,} strings extracted")
    any_hit = False
    for key, label in _DS_CATS:
        vals = ds.get(key) or []
        if not vals:
            continue
        any_hit = True
        shown = ", ".join(f"`{x}`" for x in vals[:25])
        more = f" _(+{len(vals)-25} more)_" if len(vals) > 25 else ""
        out.append(f"- **{label}** ({len(vals)}): {shown}{more}")
    if not any_hit:
        out.append("- No notable indicators at this stage "
                   "(expected for a crypted/packed file — real config surfaces after unpack/decrypt).")
    out.append("")


def _code_patterns_section(st: dict) -> list:
    """Render analyst-grade suspicious code/byte patterns (packed + unpacked)."""
    stages = [(s, st.get(f"code_patterns_{s}")) for s in ("packed", "unpacked")]
    stages = [(s, c) for s, c in stages if c and c.get("findings")]
    if not stages:
        return []
    out = ["## 2·CODE — Suspicious code & byte patterns (what an analyst would flag)",
           "Machine-code idioms spotted in the bytes: shellcode stubs, PEB walks, "
           "anti-debug/anti-VM instructions, packer stubs, indirect control flow, embedded "
           "PEs and W+X sections — with file offsets.", ""]
    for stage, c in stages:
        cnt = c.get("counts", {})
        out.append(f"### {stage.capitalize()} — {cnt.get('high',0)} high / "
                   f"{cnt.get('medium',0)} medium / {cnt.get('info',0)} info")
        out.append("| Severity | Indicator | Count | Offsets / names | Why it matters |")
        out.append("|---|---|---|---|---|")
        for f in c["findings"]:
            offs = ", ".join(f"`{o}`" for o in f.get("offsets", [])[:6])
            out.append(f"| {f['severity'].upper()} | {f['title']} | {f['count']} | {offs} | {f['why']} |")
        da = c.get("entry_disasm") or {}
        if da.get("flagged"):
            out.append("")
            out.append(f"**Flagged instructions at/near entry ({da.get('entry_va','?')}, {da.get('arch','?')}):**")
            out.append("```")
            out += da["flagged"][:20]
            out.append("```")
        if da.get("listing"):
            out.append("")
            out.append("<details><summary>Entry-point disassembly (first instructions)</summary>")
            out.append("")
            out.append("```asm")
            out += da["listing"][:40]
            out.append("```")
            out.append("</details>")
        secs = c.get("sections") or []
        if secs:
            out.append("")
            out.append("**PE sections (anatomy):**")
            out.append("| Name | VSize | RawSize | Entropy | Flags |")
            out.append("|---|---|---|---|---|")
            for s in secs:
                flags = ("X" if s.get("exec") else "") + ("W" if s.get("write") else "")
                out.append(f"| `{s['name']}` | {s['vsize']:,} | {s['rawsize']:,} | "
                           f"{s['entropy']} | {flags or '-'} |")
        out.append("")
    return out


def _deep_static_section(st: dict) -> list:
    """3-stage deep static: packed -> unpacked -> decrypted, so the reader sees exactly
    what each stage revealed (and that strings were re-examined after unpacking + decryption)."""
    packed = st.get("deep_static_packed")
    unpacked = st.get("deep_static_unpacked")
    decrypted = st.get("deep_static_decrypted")
    if not (packed or unpacked or decrypted):
        return []
    out = ["## 2·DEEP — Deep static analysis (strings re-examined at every stage)",
           "Strings and indicators are extracted from the on-disk file, then **again after "
           "unpacking**, then **again after decryption** — unencrypted leads (C2, mutexes, paths, "
           "config) typically appear only in the later stages.", ""]
    if packed:
        _ds_render(packed, "Stage 1 — Packed (on-disk file)", out)
    if unpacked:
        _ds_render(unpacked, "Stage 2 — Unpacked (reconstructed payload)", out)
    else:
        out.append("### Stage 2 — Unpacked")
        out.append("- Not available — no payload was captured/reconstructed this run.")
        out.append("")
    if decrypted:
        for src in decrypted.get("sources", []):
            _ds_render(src, f"Stage 3 — Decrypted ({src.get('source','output')})", out)
    else:
        out.append("### Stage 3 — Decrypted")
        out.append("- Not available — no decrypted artifact was produced this run.")
        out.append("")
    return out


def _ai_section(st: dict) -> list:
    """Render the AI analyst assessment(s). Advisory interpretation + strategy — the
    maliciousness verdict/score remains the deterministic engine's (proof.py)."""
    stages = [(s, st.get(f"ai_assessment_{s}")) for s in ("packed", "unpacked", "decrypted")]
    stages = [(s, a) for s, a in stages if a]
    plan = st.get("ai_dynamic_plan")
    if not stages and not plan:
        return []
    out = ["## 1·AI — Analyst assessment (AI-assisted interpretation)",
           "_AI reasoning over the extracted evidence. Advisory: it guides analysis and "
           "strategy; it does **not** set the maliciousness score (that is the deterministic, "
           "evidence-gated verdict above)._", ""]
    for stage, a in stages:
        out.append(f"### Stage: {stage} — model `{a.get('_ai_model','?')}`")
        out.append(f"- **Likely family:** {a.get('likely_family','unknown')} "
                   f"(confidence: {a.get('family_confidence','?')})")
        audit = a.get("claims_audit") or {}
        if audit.get("encrypted_regions"):
            for x in audit["encrypted_regions"][:8]:
                mark = "✓ supported" if x["supported"] else "✗ NOT supported by the entropy map"
                out.append(f"- **AI claim — encrypted region:** {x['claim']} ({x.get('likely')}) — {mark}: {x['basis']}")
        else:
            for r in (a.get("encrypted_regions") or [])[:8]:
                out.append(f"- **Encrypted region (unaudited):** {r.get('where')} — {r.get('likely')} ({r.get('evidence')})")
        for x in (audit.get("url_leads") or [])[:6]:
            if not x["supported"]:
                out.append(f"- **AI lead discarded:** `{x['lead']}` — {x['basis']}")
        for x in (audit.get("url_leads") or [])[:6]:
            if x["supported"]:
                out.append(f"- **URL/C2 lead (supported):** `{x['lead']}` — {x['basis']}")
        for key, label in [("capabilities", "Capabilities"), ("config_leads", "Config/C2 leads"),
                           ("notable_strings", "Notable strings"),
                           ("anti_analysis_expected", "Anti-analysis expected"),
                           ("dynamic_strategy", "Suggested dynamic strategy")]:
            vals = a.get(key) or []
            if vals:
                out.append(f"- **{label}:**")
                for v in vals[:12]:
                    out.append(f"    - {v}")
        if a.get("packer_assessment"):
            out.append(f"- **Packer:** {a['packer_assessment']}")
        if a.get("reasoning"):
            out.append(f"- **Reasoning:** {a['reasoning']}")
        out.append("")
    if plan:
        acc, rej = plan.get("accepted") or {}, plan.get("rejected") or []
        out.append("### AI dynamic plan (static → dynamic hand-off)")
        out.append("_The AI proposed this from the static findings; a validator decides what the debugger may act on "
                   "(APIs must be in our arsenal, regions inside the image). Anti-evasion items are advisory only._")
        if acc.get("hypothesis"):
            out.append(f"- **Hypothesis:** {acc['hypothesis']}")
        for p in acc.get("priority_apis", []):
            out.append(f"- **Priority API (armed, raised noise cap):** `{p['api']}` — {p['why']}")
        ra = {x["rva"]: x for x in (plan.get("region_audit") or [])}
        for w in acc.get("watch_regions", []):
            a_ = ra.get(hex(int(w["rva"])), {})
            tag = "justified" if a_.get("supported") else "NOT justified by the entropy map"
            out.append(f"- **Watch region (dumped at end of trace, {tag}):** rva `0x{int(w['rva']):x}` size "
                       f"`0x{int(w['size']):x}` — {w['why']}" + (f" _(evidence: {a_['basis']})_" if a_ else ""))
        for e in acc.get("anti_evasion", []):
            out.append(f"- **Anti-evasion (advisory):** {e['technique']} → {e['action']}")
        for e in acc.get("expected_events", []):
            out.append(f"- **Expected at runtime:** {e}")
        for r in rej:
            out.append(f"- **Rejected:** {r['item']} — {r['reason']}")
        pd = (st.get("api_trace", {}) or {}).get("plan_dumps", [])
        if pd:
            out.append(f"- **Plan regions actually dumped:** {', '.join('`'+d['rva']+'`' for d in pd)}")
        out.append("")
    return out


def _entropy_section(st: dict) -> list:
    """Where the encrypted/compressed bytes are (entropy map)."""
    em = st.get("entropy_map")
    if not em or not em.get("sections"):
        return []
    out = ["## 2·ENT — Entropy map (where the encrypted / compressed bytes are)",
           f"File entropy **{em.get('file_entropy')}** · image base `{em.get('image_base')}` · "
           f"size of image `{em.get('size_of_image')}` · entry RVA `{em.get('entry_rva')}`", "",
           "| Section | RVA | Raw size | Virtual size | Entropy | Notes |", "|---|---|---|---|---|---|"]
    for s_ in em["sections"]:
        notes = ", ".join(x for x in ("RUNTIME-EXPANDED (fills in at runtime)" if s_.get("runtime_expanded") else "",
                                      "X" if s_.get("exec") else "", "W" if s_.get("write") else "") if x)
        out.append(f"| `{s_['name']}` | {s_['rva']} | {s_['raw_size']:,} | {s_['vsize']:,} | {s_['entropy']} | {notes} |")
    out.append("")
    if em.get("regions"):
        out.append("**High-entropy regions** (likely encrypted or compressed):")
        out.append("| Kind | Section | RVA | File offset | Size | Entropy |"); out.append("|---|---|---|---|---|---|")
        for r in em["regions"]:
            out.append(f"| {r.get('kind')} | {r.get('section')} | {r.get('rva')} | 0x{r['file_off']:x} | {r['size']:,} | {r['entropy']} |")
        out.append("")
    if em.get("tls_callbacks"):
        out.append(f"> ⚠ **TLS callbacks** at RVA {', '.join('`'+x+'`' for x in em['tls_callbacks'])}: they run before the "
                   "debugger's entry stop, so sample code executes uncontrolled while loading.")
        out.append("")
    if em.get("overlay"):
        o = em["overlay"]
        out.append(f"**Overlay** (data after the last section): {o['size']:,} bytes at 0x{o['file_off']:x}, entropy {o['entropy']}")
        out.append("")
    if em.get("resources"):
        out.append("**Largest resources:** " + "; ".join(
            f"{r['type']}/{r['name']} {r['size']:,}B H={r['entropy']}" for r in em["resources"][:6]))
        out.append("")
    return out


def _load_section(st: dict) -> list:
    """How the sample was started under the debugger, and whether its start was fully observed."""
    li = st.get("load_info")
    if not li:
        return []
    out = ["## 7·LOAD — How the sample was started under the debugger",
           f"- Module `{li.get('module')}`, entry `{li.get('entry')}`, first stop at `{li.get('eip')}`.",
           f"- **{li.get('note')}**"]
    if li.get("at_entry") is False:
        out.append("> ⚠ The debugger did not stop at the entry point (it can stop first inside the runtime or the "
                   "loader). Code that ran before that first stop was not observed; the API arsenal was armed from "
                   "the first stop onward.")
    out.append("")
    return out


def _intel_section(st: dict) -> list:
    """The detection package: what was filed for vendors, and what is NOT available and why."""
    p = st.get("intel_package")
    if not p:
        return []
    out = ["## 8·INTEL — Detection package (for AV, firewall, EDR and threat-intel vendors)",
           f"Files are in `intel/`: **{p.get('indicators', 0)}** indicators "
           f"(**{p.get('high_confidence', 0)}** high-confidence, tier >= 70), "
           f"{p.get('excluded', 0)} filtered out as known-good/noise (listed with reasons in `iocs.json`), "
           f"{p.get('suricata_rules', 0)} Suricata rule(s), {p.get('sigma_rules', 0)} Sigma rule(s), "
           f"STIX 2.1 bundle: {'yes' if p.get('stix') else 'no (no blockable high-confidence indicator)'}.", "",
           "| Indicator class | Found | Not available because |", "|---|---|---|"]
    for k, v in (p.get("availability") or {}).items():
        out.append(f"| {k} | {v.get('count', 0)}" + (f" ({v['high_confidence']} high-confidence)" if "high_confidence" in v else "")
                   + f" | {v.get('note') or ''} |")
    out.append("")
    if p.get("yara"):
        out.append("**YARA rules** (one per stage):")
        out.append("| Stage | File | Result |"); out.append("|---|---|---|")
        for y in p["yara"]:
            res = ("written — " + y["note"]) if y.get("written") else y["note"]
            if y.get("goodware_false_positives"):
                res += f"; goodware false positives {y['goodware_false_positives']}"
            out.append(f"| {y['stage']} | `{y['file']}` | {res} |")
        out.append("")
    out.append("_Tiers: observed 90 · decrypted 80 · unpacked 70 · static 40 · AI-suggested 20 (never emitted as a rule). "
               "Auto-generated YARA must be validated against your goodware set before deployment._")
    out.append("")
    return out


def _residue_section(st: dict) -> list:
    """What the run left on the guest, and whether the VM can be reused."""
    r = st.get("residue")
    if not r:
        return []
    out = ["## 7·VM — VM residue check (what the run left behind)",
           f"**{r.get('verdict', 'unknown')}**", ""]
    k = r.get("killed") or {}
    if isinstance(k, dict) and k.get("killed"):
        out.append(f"Processes killed ({len(k['killed'])}):")
        out += [f"- `{x}`" for x in k["killed"][:15]]
        out.append("")
    for key, label in (("new_processes", "New processes still running"), ("new_run_values", "New Run/RunOnce values"),
                       ("new_tasks", "New scheduled tasks"), ("new_services", "New services"),
                       ("new_files", "New files in user/temp/startup dirs")):
        vals = r.get(key) or []
        if vals:
            out.append(f"**{label}** ({len(vals)}):")
            out += [f"- `{v}`" for v in vals[:15]]
            out.append("")
    ben = r.get("new_processes_benign") or []
    if ben:
        out.append(f"_{len(ben)} new process(es) were ignored as our own SSH session or ordinary Windows "
                   "service hosts (not residue)._")
        out.append("")
    if r.get("mass_file_change"):
        out.append(f"**Mass file change:** removed {r.get('removed_count')}, modified {r.get('modified_count')}")
        out.append("")
    out.append("_Heuristic: only user/temp/startup dirs, Run keys, tasks, services and processes are "
               "inspected. It cannot see injected code, WMI subscriptions or kernel-level changes._")
    out.append("")
    return out


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
    _basis = v.get("basis")
    _basis_tag = f" · basis: {_basis}" if _basis else ""
    L.append(f"**Triage hint:** {v.get('label','?')} ({v.get('confidence','?')}/100{_basis_tag}). "
             f"This is a quick screening flag, not the purpose of this report: the analysis below (category, stages, dumps, "
             f"indicators, encryption, author leads) is the result.  ")
    _mc = st.get("malware_category") or {}
    if _mc.get("primary"):
        L.append(f"**Category:** {_mc['primary']}  ")
    if cls.get("primary"):
        L.append(f"**Family (behavioral):** {cls['primary']}"
                 + (f" (+{', '.join(cls['secondary'])})" if cls.get("secondary") else "") + "  ")
    L.append(f"**Completeness:** {poc.get('completeness','?')}  ")
    L.append(f"**SHA-256:** `{case.get('sha256')}`  ")
    L.append(f"**Size:** {case.get('size',0):,} bytes  ")
    # honesty banner: surface what was NOT established right at the top
    for cav in v.get("caveats", []):
        L.append(f"> ⚠ {cav}  ")
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
    # why the verdict got its score — every point is justified, split static vs dynamic
    s_ev = v.get("static_evidence") or []
    d_ev = v.get("dynamic_evidence") or []
    if s_ev or d_ev or v.get("evidence"):
        L.append(f"**Why the verdict is {v.get('label','?')} "
                 f"({v.get('confidence','?')}/100, basis: {v.get('basis','?')}):**")
        if s_ev:
            L.append(f"_Static indicators (capability, not proof of behaviour — "
                     f"subtotal {v.get('static_score','?')}):_")
            for e in s_ev:
                L.append(f"- {e}")
        if d_ev:
            L.append(f"_Dynamic evidence (what it actually did — subtotal {v.get('dynamic_score','?')}):_")
            for e in d_ev:
                L.append(f"- {e}")
        if not (s_ev or d_ev):            # back-compat: old flat evidence list
            for e in v.get("evidence", []):
                L.append(f"- {e}")
        if v.get("caveats"):
            L.append("_Caveats (not established):_")
            for c in v["caveats"]:
                L.append(f"- {c}")
        L.append("")

    # ---------- consolidated IOCs — attacker communication (front and center) ----------
    ioc = _collect_iocs(st)
    L.append("## 1·IOC — Indicators of Compromise (attacker communication / C2)")
    if ioc["urls"] or ioc["ips"] or ioc["domains"]:
        if ioc["urls"]:
            L.append("**URLs (callback / download):**")
            for u, srcs in sorted(ioc["urls"].items()):
                L.append(f"- `{u}`  _(from: {', '.join(sorted(srcs))})_")
        if ioc["domains"]:
            L.append(f"**Domains:** {', '.join('`%s`' % d for d in sorted(ioc['domains']))}")
        if ioc["ips"]:
            L.append("**IPs:**")
            for i, srcs in sorted(ioc["ips"].items()):
                L.append(f"- `{i}`  _(from: {', '.join(sorted(srcs))})_")
        if ioc["registry"]:
            L.append("**Registry:**")
            for r, srcs in sorted(ioc["registry"].items()):
                L.append(f"- `{r}`  _(from: {', '.join(sorted(srcs))})_")
    else:
        L.append("- No network IOCs recovered yet. For this sample the C2 config is likely "
                 "still encrypted (decrypted at beacon time) — see the Encryption section for how "
                 "to recover it, or run the detonation phase to capture live callbacks.")
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

    _al = (st.get("author_links") or {}).get("links") or []
    _fps = st.get("author_fingerprints") or {}
    if _fps:
        L.append("### Author / build fingerprints and clustering")
        L.append("| File | imphash | Rich-header hash | Compile time (UTC) | Signed |")
        L.append("|---|---|---|---|---|")
        for _n, _f in _fps.items():
            _t = time.strftime("%Y-%m-%d %H:%M", time.gmtime(_f["timestamp"])) if _f.get("timestamp") else "-"
            L.append(f"| `{_n}` | `{_f.get('imphash', '-')}` | `{_f.get('rich_hash', '-')}` | {_t} | {_f.get('signed', '-')} |")
        L.append("")
        if _al:
            L.append("Shared fingerprints with earlier analysed cases (a lead for same builder/author/toolchain, not proof):")
            for _l in _al[:12]:
                L.append(f"- **{_l['strength']}**: `{_l['label']}` shares {', '.join(_l['shared'])} with `{_l['other_label']}` in case `{_l['with_case']}`")
        else:
            L.append("No earlier analysed case shares these fingerprints.")
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
        if du.get("payload_captured"):
            n = len(du.get("wx_flips", []) or [])
            L.append(f"- **Payload captured: YES** — the packer decrypted its code in memory and "
                     f"flipped it writable→executable ({n} W→X flip event(s)); we dumped it at that "
                     "instant (see the Memory dumps section).")
        else:
            L.append("- Payload captured: no W→X flip observed in this run.")
        if du.get("api_hits"):
            L.append(f"- Unpack API hit counts: "
                     f"{', '.join(f'{k}×{v}' for k,v in du['api_hits'].items())}.")
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

    # ---------- AI analyst assessment (advisory interpretation + strategy) ----------
    L += _ai_section(st)

    # ---------- deep static (3-stage strings/IOC extraction) ----------
    L += _deep_static_section(st)
    L += _entropy_section(st)

    # ---------- suspicious code & byte patterns (analyst-grade) ----------
    L += _code_patterns_section(st)

    # ---------- VM residue check (kill tree + diff) ----------
    L += _load_section(st)
    L += _intel_section(st)
    L += _residue_section(st)

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
    # ---------- dumps: hashes, comparison, re-static (the solid artifact table) ----------
    dm = st.get("dumps_manifest", {}) or {}
    if dm.get("dumps"):
        L.append("## 3. Memory dumps — hashes, comparison & re-static")
        L.append(f"Packed input: MD5 `{dm.get('packed_md5')}` · SHA-256 `{dm.get('packed_sha256')}` "
                 f"· {dm.get('packed_imports', '?')} imports.")
        L.append("")
        L.append("Every dumped region, with its own hashes (copy to compare / VirusTotal) and what "
                 "re-static found in it:")
        L.append("")
        L.append("| Dump (link) | Size | PE | Imports | re-static URLs/IPs | Same as packed? | MD5 | SHA-256 |")
        L.append("|---|---|---|---|---|---|---|---|")
        _base = Path(case.get("dir", ""))
        missing = 0
        for r in dm["dumps"]:
            imp = r.get("imports", "-") if r.get("pe") else "-"
            same = "YES ⚠" if r.get("same_as_packed") else "no"
            ui = f"{r.get('urls', 0)}/{r.get('ips', 0)}"
            # reconcile with disk: never link a file that isn't there
            exists = (_base / r["path"]).exists() if case.get("dir") else True
            name_cell = f"[`{r['name']}`]({r['path']})" if exists else f"`{r['name']}` _(FILE MISSING)_"
            if not exists:
                missing += 1
            L.append(f"| {name_cell} | {r['size']:,} | {'yes' if r['pe'] else '-'} | "
                     f"{imp} | {ui} | {same} | `{r['md5']}` | `{r['sha256']}` |")
        if missing:
            L.append("")
            L.append(f"> ⚠ {missing} dump file(s) listed in the manifest are not present on disk "
                     "(cleaned up or never pulled). They are shown for the record but not linked.")
        L.append("")
        L.append("**Packed vs reconstructed — did unpacking change the file?**")
        L.append("| | Packed input | Reconstructed payload |")
        L.append("|---|---|---|")
        rtri = st.get("triage_reconstructed", {}) or {}
        rpe = rtri.get("pe", {}) or {}
        vfc = (st.get("verify_unpack", {}) or {}).get("compared", {})
        L.append(f"| MD5 | `{dm.get('packed_md5')}` | `{(vfc.get('unpacked') or {}).get('md5','-')}` |")
        L.append(f"| Imports | {dm.get('packed_imports','?')} | {rpe.get('import_func_count','-')} |")
        L.append(f"| Sections | {[s['name'] for s in (pe.get('sections') or [])]} | "
                 f"{[s['name'] for s in (rpe.get('sections') or [])]} |")
        L.append(f"| Different file? | — | "
                 f"{'NO (identical)' if (vfc.get('unpacked') or {}).get('md5')==dm.get('packed_md5') else 'YES (distinct content)'} |")
        rm = st.get("memory_static_reconstructed", {}) or {}
        if rm.get("urls") or rm.get("ips"):
            L.append("")
            L.append("Re-static of the reconstructed payload revealed:")
            for u in rm.get("urls", [])[:15]:
                L.append(f"- URL `{u}`")
            for ip in rm.get("ips", [])[:15]:
                L.append(f"- IP `{ip}`")
        L.append("")

    try:
        from . import dump_analysis as _da, category_guide as _cg, crypto_analysis as _ca
        L += _da.to_markdown(st.get("dump_analysis") or {})
        if st.get("malware_category") is not None:
            L += _cg.to_markdown(st["malware_category"])
        if st.get("file_crypto"):
            L += _ca.to_markdown(st["file_crypto"])
    except Exception:
        pass

    # ---------- legacy detonation memory dump (if --detonate ran) ----------
    L.append("## 3b. Detonation memory dump + re-static")
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
    try:
        from . import procmon_summary as _pms
        L += _pms.to_markdown(st.get("procmon_summary") or {})
    except Exception:
        pass
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
    L.append(f"- Analysis folder: `{Path(case.get('dir') or '').name or (str(case.get('name')) + '_' + (case.get('sha256') or '')[:12])}/` "
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
