# Nemesis Analyst — Strategy Roadmap & Status

Living record of **every strategy** specified for the analyst, with status, so we can
cross-check what is done vs outstanding. Updated 2026-10-21.

**Status key:** ✅ done & verified · 🟣 done, needs live-VM validation · 🟡 partial ·
⬜ not started · ♻️ wired but depends on capture working first

**Guiding principles (from the directives):**
- One malware per **clean VM**; revert after running (never reuse a dirty VM).
- **Extend, don't replace** load-bearing code; pin behavior; live-test before "done".
- **AI enhances** against the objective + rules — surgical, not looping; **every AI call logged**.
- Reports must be **honest** (no verdict without evidence) and **reproducible**.
- No secrets in chat or committed to git.

---

## 1. Static analysis
| # | Strategy (as specified) | Status | Where / notes |
|---|---|---|---|
| 1.1 | Detect It Easy identification (type/compiler/packer) | ✅ | `triage` (diec) |
| 1.2 | PE anatomy: sections, entropy, imports, overlay | ✅ | `triage` + `code_patterns._sections` |
| 1.3 | **Very deep static** — intense, structured | ✅ | `deep_scan` + `code_patterns` + Capstone entry disasm |
| 1.4 | **Strings — 3 stages** (packed → unpacked → decrypted) | 🟡 | `memstatic.deep_scan` wired at all 3 in `unpack.py`; stages 2/3 depend on capture (♻️) |
| 1.5 | Rich string categorization (URLs, IPs, domains, paths, PDB, registry, mutexes, commands, UAs, wallets, GUIDs, base64, anti-analysis) | ✅ | `memstatic.deep_scan` |
| 1.6 | **"Funny code / syntax" via patterns** (analyst-grade) | ✅ | `code_patterns.py`: GetPC stub, PEB walk (fs:[30]/gs:[60]), rdtsc, cpuid, int 2Dh, int3/NOP sleds, stack-strings, **indirect call/jmp reg**, pushad/popad stub, embedded PE, packer/high-entropy/W+X sections |
| 1.7 | Instruction-level disassembly of entry/suspicious code | ✅ | **Capstone** entry disasm in `code_patterns` (flags call/jmp reg, rdtsc, cpuid, int3, syscall). Ghidra module is missing + not installed here; Capstone covers host-side disasm |
| 1.10 | Entry-point disassembly flagged in report | ✅ | report §2·CODE (listing + flagged instructions) |
| 1.8 | **Re-static on the DUMPED memory** (confirm it's the real unpacked malware) | ♻️ | `deep_scan`/`triage`/`verify` run on dumps + reconstructed PE; needs capture to feed it |
| 1.9 | Author/attribution recon: compile date, PDB build path/user, Rich header toolchain, version info | ✅ | `attribution.py` (caught nProtect/npkpdb masquerade) |

## 2. Static → dynamic bridge
| # | Strategy | Status | Where / notes |
|---|---|---|---|
| 2.1 | Detect indirect register transfers (`call ebp/ecx`) + push/ret in static | ✅(detect) 🟡(carry) | `code_patterns` flags them; carrying into targeted dynamic breakpoints = ⬜ |
| 2.2 | Breakpoint those indirect sites at runtime, dump the register-pointed memory | ⬜ | `hint_driven_dump`/`_resolve_and_dump` exist but **dead code** (unwired) |
| 2.3 | **ASLR rebasing** — runtime `.text` base + static RVA (last digits) | 🟡 | `Engine.rebase()` exists; used ad hoc, not in a hint-driven pass |

## 3. Dynamic analysis — unpacking (the engine)
| # | Strategy | Status | Where / notes |
|---|---|---|---|
| 3.1 | **Full P1/P2 API breakpoint arsenal** | ✅ | `api_spec.py` (27 APIs) armed in `api_trace` |
| 3.2 | **Hardware breakpoints** (survive decompression) vs software | ✅ | `run_to_entry` sets `bph` at entry — VALIDATED: entry reached, 36 bps armed; OEP hw-bp path still unwired |
| 3.3 | **W→X flip detection** (VirtualProtect/NtProtect → EXEC) = unpack moment → dump | ✅ | VALIDATED on dridex: 3 W→X flips caught at 0x10001000 (both kernel32 + native ntdll) |
| 3.4 | Dump allocated regions + **full-module dump** at the flip | ✅ | VALIDATED: full-module (217 KB) + 4 region dumps pulled to host |
| 3.5 | **Broaden capture beyond W→X** — CryptDecrypt in-place output | 🟣 | `_capture` `crypt_out` wired; dridex used W→X (not CryptDecrypt), so needs a CryptDecrypt sample to exercise |
| 3.6 | OEP detection | ⬜ | `Engine.unpack()`/`dump_detect_oep` exist but **dead code** |
| 3.7 | **Scylla-style PE reconstruction** (align raw/virtual, fix ImageBase, rebuild IAT) | ✅ | VALIDATED: rebuilt PE, 7 imports resolved (ADVAPI32+KERNEL32) |
| 3.8 | **Reliable run/continue handshake** (plugin `running`-state quirk) | ✅ | **ROOT-CAUSE FIX VALIDATED**: `_poll_pause` frozen-eip+register-confirm → memory APIs now fire (was 0 before) |
| 3.9 | Reach entry before arming so kernel32/ntdll exports resolve | ✅ | VALIDATED: kernel32 resolved, 36 API bps armed |
| 3.10 | Programmatic sample load (no manual GUI) — `debug_init` = Run button | ✅ | `unpack.py` autoload (push → debug_stop → debug_init) |
| 3.11 | Per-API logging of the trace (which API, args, count, dumps) | ✅ | live `run.log` + `api_trace` counts |
| 3.12 | **CryptoAPI key recovery** (break CryptImportKey/DeriveKey, dump key blob) | 🟣 | `_capture` keyblob |

## 4. Anti-evasion
| # | Strategy | Status | Where / notes |
|---|---|---|---|
| 4.1 | Neutralize anti-debug (IsDebuggerPresent, PEB.BeingDebugged, NtGlobalFlag) | 🟣 | `neutralize_antidebug()` |
| 4.2 | Detect anti-debug/anti-VM in static (rdtsc/cpuid/int2d/PEB walk) | ✅ | `code_patterns` |
| 4.3 | Research-grounded evasion defeats (timing, hypervisor checks, sandbox artifacts) | ⬜ | planned — expand neutralization + AI-proposed defeats |

## 5. Ransomware / encryption
| # | Strategy | Status | Where / notes |
|---|---|---|---|
| 5.1 | Generate a working **decryptor** (`decrypt_<algo>.py` + README) | 🟡 | `decryptor.build_all`; emits runnable code only when a key is recovered, else template |
| 5.2 | Recover the key at runtime, then decrypt | ⬜ | depends on keyblob/crypt capture landing a key |

## 6. Framework-compiled malware
| # | Strategy | Status | Where / notes |
|---|---|---|---|
| 6.1 | **AutoIt** source recovery (autoit-ripper / exe2aut) | 🟣 | `framework_extract` now WIRED into `unpack.py` (detect → host/guest extract → `source/`); needs VM sample to validate |
| 6.2 | **.NET** deobfuscation (de4dot) + source | 🟣 | `guest_static.analyze` now WIRED into `unpack.py` (guarded); needs VM + de4dot on guest |
| 6.3 | `source/` folder populated | 🟣 | wired via 6.1/6.2 |

## 7. Detonation (LAST phase)
| # | Strategy | Status | Where / notes |
|---|---|---|---|
| 7.1 | Order: **Regshot baseline → Procmon + FakeNet → run → export → ProcDOT** | ✅ | `detonate.py` (gated behind `--detonate`) |
| 7.2 | Export Procmon CSV for ProcDOT | ✅ | `pm.csv` |
| 7.3 | **Spell out all C2 URLs / attacker comms** | ✅ | FakeNet log + memory re-static feed the consolidated IOC section |

## 8. Reporting
| # | Strategy | Status | Where / notes |
|---|---|---|---|
| 8.1 | **One consolidated PDF** (report + methodology + proof) | ✅ | `report_consolidated.build` → `ANALYSIS.pdf` |
| 8.2 | **Every score has a reason** (point attribution) | ✅ | `proof._verdict` `(+N)` per signal + static/dynamic subtotals |
| 8.3 | **Honest verdict** — no MALICIOUS/high without runtime evidence; caveats | ✅ | `proof._verdict` (static-only capped 55; caveats banner) |
| 8.4 | Dump bookkeeping: **MD5 + SHA256**, links, "same as packed?" | ✅ | `dumps_manifest` + report table |
| 8.5 | **Comparison table** (same file? more APIs? re-static) | ✅ | report §3 packed-vs-reconstructed |
| 8.6 | **Verify linked dump files exist** (no dead links / fake claims) | ✅ | report reconciles against `case["dir"]` |
| 8.7 | Consolidated **C2 / attacker-comms** section (static + dynamic, source-tagged) | ✅ | `_collect_iocs` incl. 3-stage deep static |
| 8.8 | **MITRE ATT&CK** mapping | ✅ | `proof._attack` + report §6 |
| 8.9 | **Deterministic / reproducible** (step counts, API call counts, replay) | ✅ | `reproducibility.py` METHODOLOGY (Appendix A) |
| 8.10 | **No failed-run noise** | ✅ | RunLog/ToolAudit truncate per run |
| 8.11 | Per-analysis **organized folder** (dumps/source/decryptor/logs/artifacts + manifest) | ✅ | `case.py` (source/ + artifacts/ populate only when 6.x / detonation fire) |

## 9. AI layer (enhance, don't loop — everything logged)
| # | Strategy | Status | Where / notes |
|---|---|---|---|
| 9.1 | AI brain (OpenAI default + pool rotation; fallback provider; graceful degrade) | ✅ | `ai/brain.py`; reads `kali_config.ini` `[openai]`/`[openai_pool]` |
| 9.2 | **Every AI request/response logged** (visible) | ✅ | console line + `logs/ai_transcript.jsonl` + audit |
| 9.3 | AI **enhances** against objective + rules, surgical (no looping) | ✅ | `static_reason` system prompt + single bounded call/stage |
| 9.4 | AI deep-static assessment (family, leads, strategy) rendered in report | ✅ | `ai_assessment_*` → report §1·AI |
| 9.5 | AI guardrail: never sets the maliciousness score | ✅ | verdict stays deterministic (`proof.py`) |
| 9.6 | **AI agentic dynamic loop** — brain chooses bp/dump/anti-evasion each step | ⬜ | next build; needs the fixed primitives (3.8/3.9) proven on VM |

## 10. Infrastructure / ops / VM
| # | Strategy | Status | Where / notes |
|---|---|---|---|
| 10.1 | Provisioning wizard over SSH (deploy 2026 x64dbg, remove old, plugin, shortcuts, tools) | ✅ | `provision.py` |
| 10.2 | **x64 auto-launch** by bitness (x32dbg ↔ x64dbg via PsExec -i 1) | 🟣 | `vm/debugger.py` + wired in `unpack.py` (no-op for x86) |
| 10.3 | Snapshot/backup clean baseline **before** malware | ✅ | capture/revert/restore scripts (operator-run) |
| 10.4 | **One malware per clean VM**; revert after | ✅(policy) | documented; batch-in-one-session proven unsafe (VM exhaustion) |
| 10.5 | Per-tool logging/auditing (tool, inputs, outputs, timing, status) | ✅ | `runlog.py` + `audit.py` |
| 10.6 | Live logs (see what's running) | ✅ | unbuffered `run.log` |
| 10.7 | GitHub push | ✅(prior) | pushed earlier; secrets-scan each push |

## 11. Known gaps to close next (priority order)
1. 🟣 **Validate Phase-2 capture on a clean VM** (dridex): handshake fix + CryptDecrypt capture → first true end-to-end payload.
2. ⬜ Wire the **dead engine code** into `unpack.py`: OEP/hw-bp (3.6), hint-driven indirect-call dump + ASLR (2.2/2.3).
3. ⬜ Wire **Ghidra re-static on dumps** (1.7/1.8) and **AutoIt/.NET recovery** (6.x) into `unpack.py`.
4. ⬜ **AI agentic dynamic loop** (9.6) on the proven primitives.
5. ⬜ **Anti-evasion** research defeats (4.3) + runtime key recovery → real decryptors (5.2).

## 2026-10-21 — END-TO-END VALIDATION (dridex, clean VM) ✅
First true capture, start to finish. Validated green:
- Handshake fix (3.8/3.9) → kernel32 resolved, **36 API bps armed** (was 0).
- Memory APIs fire: VirtualAlloc ×3, VirtualProtect/NtProtect — **3 W→X flips** at 0x10001000.
- **Payload dumped + pulled to host** (`api_ntwx_0x10001000.bin` 134 KB, full-module 217 KB, 4 regions) (3.4).
- **PE reconstruction** → 7 imports (3.7); **verify = CONFIRMED_UNPACKED 60/100** (50/50 W→X direct evidence).
- Classification: loader/packer; attribution: nProtect/npkpdb masquerade + compile date 2020-04-24.
- **Honest verdict: MALICIOUS, dynamic-confirmed, payload_captured=True** (not the old fake 95) — §8.3 ✅.
- Report: 2·AI + 2·DEEP + 2·CODE (call esi/ecx, int 2Dh) render; dump links reconcile (0 missing); consolidated PDF 93 KB.
- AI brain (OpenAI gpt-4o) ran packed+unpacked assessments, all logged to `ai_transcript.jsonl` (9.2/9.4 ✅).
- Hardened the finalizer: MD written before PDF, errors surfaced, AI handle closed (no more silent-death).

Still to validate on other samples / build: 3.5 crypt_out (CryptDecrypt sample), 3.12 keyblob, 5.x decryptor
(ransomware sample), 6.1/6.2 AutoIt/.NET recovery (framework samples), 10.2 x64 auto-launch (x64 sample);
and ⬜ 2.2 hint-dump, 3.6 OEP, 9.6 AI agentic loop, 4.3 anti-evasion.


## 2026-10-21 — Safety: containment-first load + residue check (offline-tested, NOT yet live-validated)
- `nanalyst/safe_load.py`: pause on running; silent debugger (3 empty polls) = loss of control -> debug_stop + `taskkill /f /t` + abort. 5 offline tests.
- `nanalyst/residue.py`: baseline before load, kill tree after, diff -> reusable-or-revert verdict, in the report (§7·VM). 9 offline tests.
- PowerShell residue helper VALIDATED live (snapshot 37 s, kill 11 s); found ransom notes `_RECOVERY_+vqujo.*` in C:\\nemesis = demo1 did execute earlier.
- 2026-10-21 transfer fix: truncation was a locked destination file (previous sample copy), not size/content. `nanalyst/vm/transfer.py` = unique name + kill/delete holder + size+SHA-256 verify; live 3/3 on demo1; 7 offline tests. demo1 LOAD under x32dbg still untested after this (separate issue).
- Open: demo1_ransomware load under x32dbg (debugger went silent after debug_init) — safe_load/residue/transfer not yet exercised by a live sample run.


## 2026-10-21 — Engine hardening from live measurements (benign whoami.exe, all verified live)
- safe_load = passive wait for the debugger's own entry stop (never debug_pause during loading); contains on silence/exit/timeout. 8 offline tests.
- run_to_entry never resumes when already at entry; numeric address compare (`_norm`).
- `_run_to_return` = one-shot bp on [esp]; `rtr` was unreliable AND the old double/unanchored rtr read return values at the wrong place (dridex alloc "bases" were garbage — the earlier region dumps for dridex came from bad addresses). Fixed + verified (return address match, eax valid, memory_write/register_set read back).
- Anti-debug: NtQueryInformationProcess(7/0x1E/0x1F), CheckRemoteDebuggerPresent, IsDebuggerPresent now neutralised on hit (was: silent pause -> livelock on demo1). Unknown pauses logged + livelock guard.
- Residue diff ignores our SSH session + on-demand OS hosts. Baseline persisted to artifacts/residue_baseline.json.
- TLS-callback detector (entropy_map): Trickbot has 3 -> loud warning, shown in report.
- Static->dynamic: entropy map + AI static assessment + validated AI dynamic plan wired before the debugger (priority APIs get a 3x noise cap; watch regions dumped). 
- Tests: safe_load 8, residue 12, transfer 7, plan/entropy 7, antidebug/entry 13.
- STILL OPEN: full unpack.py run with all of this on a live sample; demo1 payload run; anti-evasion beyond debugger checks (rdtsc/cpuid/int2d = advisory only); detonation phase.


## 2026-10-21 (late) — benign pipeline run end to end; four more real bugs found and fixed
- Debugger doesn't reliably stop at entry -> run_to_entry never resumes; api_trace refuses to resume unless arsenal armed; load_info + report §7·LOAD say whether the first stop was the entry.
- Double hook (kernel32 stub + kernelbase body): duplicates + wrong return values -> one address per API; verified live (0 duplicates, 0/11 wrong bases).
- Scoring: real W->X required for unpack evidence; security-relevant GetProcAddress names instead of a count; thread-in-self is not injection. Canary 45 -> 0, dridex 75 unchanged.
- Residue: ghost entry for a killed debuggee ignored; debug_stop before the check.
- 76 offline tests. STILL OPEN: dridex re-run on the final code; demo1 payload run; AI hypothesis text unaudited; whoami-copy failure unexplained (not a pipeline bug as far as shown).


## DIRECTION RESET (2026-10-21, late) — the goal is analysis, not scoring
Verdict demoted to a triage hint. Priorities (verified gaps): 1) IOC filing — NONE exists today; 2) per-dump understanding + dump-to-dump comparison — NONE exists (dump roles are filename-based); 3) malware-type categorisation with a per-category "what to track" checklist — classifier has all 6 categories as keyword weights, but the arsenal hooks only 4 of 22 relevant APIs; 4) arsenal extension + counting breakpoints; 5) file-encryption analysis (algorithm from code constants, plaintext/ciphertext capture, a decryptor proven by round-trip); 6) author tracing beyond basics (imphash, clustering). Each tested on harmless canaries first.

## Changelog
- 2026-10-21: Honest verdict engine; deep static + 3-stage strings; `code_patterns`; one
  consolidated PDF; report reconciliation; AI brain (OpenAI + pool) + static reasoning +
  full AI logging; Phase-2 capture primitives (handshake, hw-bp entry, CryptDecrypt);
  x64 auto-launch. Roadmap created.

## Closed out 2026-10-21 (status: DONE unless noted)

| Strategy | Status | Proof |
|---|---|---|
| One folder per run `<uuid>_<malware folder>` | DONE | `cases/<uuid>_dridex`; run id in case.json |
| Survive a broken run (SIGHUP ignored, SIGTERM/crash rescue: stop debuggee, save case, render reports) | DONE | simulated SIGTERM offline; `--finalize CASE_DIR` rebuilds all reports without a VM |
| Anti-debug flips IsDebuggerPresent + CheckRemoteDebuggerPresent | DONE, live | canary read False/False (was True/False: x64dbg syntax is `mov byte:[addr], 0`) |
| Dump-by-dump content analysis + stage comparison | DONE | report section 3c |
| Malware category (6-category guide) with per-item status: observed live / present in code / absent / not instrumented | DONE, live | ransomware canary classified ransomware (4 observed live) |
| Behaviour sentinels (31 APIs: network, input, file, crypto-file, process, persist, spread); first 3 calls with args | DONE, live | CryptEncrypt, CryptImportKey, FindFirstFile, CreateMutex, DeleteFile fired |
| Exact hit counts without stopping | NOT POSSIBLE with this plugin | measured: silent + fast-resume accepted but the sample still stops; counts are reported as ">= 3" |
| Late arming for statically imported DLLs (re-check pending APIs while paused) | DONE (bcrypt late-armed live) | |
| File-encryption analysis: plaintext+ciphertext capture, key candidates (CryptImportKey blob, strings, memory scan), cipher constants, decryptor proven by round trip | DONE, live | key CanaryKey-123456 recovered, decryptor executed and matched |
| Key wrapped by an attacker RSA public key | CANNOT be recovered offline; reported as such | |
| Author tracing: imphash, Rich hash, timestamp, signed?, masquerade note, shared-fingerprint links to earlier cases | DONE | section 1a; leads, not proof |
| Verdict demoted to a one-line "triage hint"; category leads the cover | DONE | |
| Observed indicators from behaviour sentinels (hosts, URLs, mutex, registry names, command lines) feed the detection package | DONE | tier observed |
| YARA goodware false-positive test | DONE | 0/28 benign Windows binaries (goodware/ is untracked) |
| Wide-string read bug (last char garbled) | FIXED | tests/test_read_str.py |
| Second CryptEncrypt call (Final=1) of the canary | n/a | carried zero data bytes (final padding block); the first call held the whole file and verified |
| Resume a dynamic run mid-way | NOT POSSIBLE (live debugger state); re-run on a clean VM | |
| `--observe SECS` (payload keeps running under the hooks after capture) | DONE, live on canary | window opened after capture and closed on time; one earlier run hung 909 s with no events (not reproduced, cause unknown) |
| Detonation run on dridex (FakeNet + Procmon + Regshot) | DONE | 0 network, 0 writes; 438k Procmon events, mostly Cryptography-provider registry reads (CryptoAPI used in a loop) |
| Procmon behaviour summary (what it did, not only what it changed) | DONE | report section 4a |
| PDF overflow (tables, long hashes, headings, code blocks, raw `\newpage`, tables glued to text) | FIXED | 0 overflow pixels on all pages of the dridex report |
| MCP server with background jobs and gates (15 tools + workflow prompt) | DONE, end to end | real MCP client over stdio: canary -> ransomware, AES key verified, decryptor proven; refusals tested |
| Event budget raised 150 -> 400 (.NET start-up noise used it all) | FIXED | found by the MCP end-to-end run |
| NULL-name calls no longer use a sentinel's budget | FIXED, live | canary mutex now caught as an observed indicator |
| Protected svchost (unreadable path) flagged as residue | FIXED | test added |
| `poc.py <sha256>` / get_proof_of_compromise could not find cases | FIXED | |
| Fresh install from the publishable files only | DONE | caught `mcp` 2.x breaking the server: pinned `<2` |
