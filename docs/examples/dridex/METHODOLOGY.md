# Reproducibility & Methodology — 178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1.exe

This report is deterministic: the same sample + the same tool versions + the clean VM baseline reproduce these findings. Below is the exact flow, the command/step counts, and a per-finding replay recipe.

## 1. Environment fingerprint (pin these to reproduce)
- Sample SHA-256: `178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1`
- Size: 212,992 bytes | type: PE32 (x86)
- Detect It Easy: PE32 / compiler Microsoft Visual C/C++ 19.00.24215 (diec 3.21)
- Ghidra: analyzeHeadless (NemesisStatic.java) | pe-sieve 0.4.1.1 | upx (brew)
- Debugger: x64dbg 2026 build (C:\x64dbg_new), x64dbg-mcp plugin v1.0.11, MCP 127.0.0.1:3000
- VM: revert to `clean-baseline` snapshot before each run (identical start state)

## 2. Analysis flow (ordered — each stage is recorded)
1. **Detect It Easy + pefile** (`triage`) — diec -j <sample> ; pefile parse
2. **author/build recon** (`attribution`) — pefile: TimeDateStamp, debug PDB, Rich header, version info
3. **unpack verification** (`verify_unpack`) — diff packed vs unpacked (imports/sections/entropy/IOCs)
4. **.NET deobfuscation** (`guest_deobfuscation`) — DIE + de4dot (guest)
5. **x64dbg OEP unpack (MCP)** (`dynamic_unpack`) — restart -> bph OEP -> run -> dump_module
6. **behavioral detonation** (`detonation`) — FakeNet + Procmon + Regshot + pe-sieve
7. **behavioral classification** (`classification`) — evidence-weighted family rules
8. **crypto detect + decryptor** (`crypto_recovery`) — scheme + key detection -> decrypt_<algo>.py

## 3. Tool-call statistics (from the audit ledger — exact counts)
Every subtool call is recorded in `logs/tool_audit.jsonl` with inputs, output, duration and status. Totals:
- **405 calls**, 386 ok, 19 failed, 218420 ms

| Tool / command | Calls | Errors | Time (ms) |
|---|---|---|---|
| `x64dbg.eval_expression` | 113 | 0 | 1500 |
| `x64dbg.debug_get_state` | 99 | 0 | 1394 |
| `x64dbg.script_execute` | 87 | 0 | 1383 |
| `ssh.run` | 39 | 2 | 119185 |
| `x64dbg.module_get_exports` | 18 | 15 | 1185 |
| `scp.pull` | 8 | 0 | 73230 |
| `pefile` | 6 | 0 | 173 |
| `diec` | 6 | 0 | 5779 |
| `x64dbg.dump_memory_region` | 6 | 0 | 162 |
| `x64dbg.module_get_main` | 5 | 1 | 63 |
| `scp.push` | 3 | 0 | 5289 |
| `x64dbg.breakpoint_set` | 3 | 0 | 44 |
| `x64dbg.register_get_batch` | 3 | 0 | 45 |
| `x64dbg.memory_read` | 3 | 1 | 42 |
| `x64dbg.debug_stop` | 2 | 0 | 26 |
| `x64dbg.debug_init` | 1 | 0 | 17 |
| `x64dbg.debug_pause` | 1 | 0 | 571 |
| `x64dbg.dump_module` | 1 | 0 | 39 |
| `de4dot` | 1 | 0 | 8293 |

## 4. Reproduce the STATIC findings
```
diec -j <sample>                 # identification: PE32
python3 -c 'import pefile; ...'  # sections, imports, entropy, TLS, signature
```

## 4b. Step-by-step execution (what the sample did, in order)
Addresses differ every run (ASLR) and across machines, so each step is given **relative** to the module base (RVA = address − base) and by **call order / arguments**, which are invariant. Follow these in any debugger regardless of where the module loads.

1. **1× VirtualAlloc** — lpAddress=0x0, dwSize=0x2b000, flType=0x1000  → returned base 0x670000
2. **2× VirtualAlloc** — lpAddress=0x0, dwSize=0x6000, flType=0x1000  → returned base 0x1e0000
3. **1× LoadLibraryA** — lpName=0x1e30f2  → ""
4. **3× VirtualAlloc** — lpAddress=0x0, dwSize=0x2a000, flType=0x1000  → returned base 0x6f0000
5. **2× LoadLibraryA** — lpName=0x717e80  → "KERNEL32.dll"
6. **3× LoadLibraryA** — lpName=0x717e9e  → "ADVAPI32.dll"
7. **1× VirtualProtect** — lpAddress=0x10000000, dwSize=0x35000, flNewProtect=0x4  → protect 0x4 (not exec)
8. **1× NtProtectVirtualMemory** — hProc=0xffffffff, pBase=0x19fcf8, pSize=0x19fcfc  → NtProtect newProt=0x4
9. **2× VirtualProtect** — lpAddress=0x10000000, dwSize=0x400, flNewProtect=0x2  → protect 0x2 (not exec)
10. **2× NtProtectVirtualMemory** — hProc=0xffffffff, pBase=0x19fcf8, pSize=0x19fcfc  → NtProtect newProt=0x2
11. **3× VirtualProtect** — lpAddress=0x10001000, dwSize=0x20d11, flNewProtect=0x20  → W->X region 0x10001000+0x20d11 [full-module dumped]
12. **3× NtProtectVirtualMemory** — hProc=0xffffffff, pBase=0x19fcf8, pSize=0x19fcfc  → W->X (native) 0x10001000+0x20d11
13. **4× VirtualProtect** — lpAddress=0x10022000, dwSize=0x5efe, flNewProtect=0x2  → protect 0x2 (not exec)
14. **4× NtProtectVirtualMemory** — hProc=0xffffffff, pBase=0x19fcf8, pSize=0x19fcfc  → NtProtect newProt=0x2
15. **5× VirtualProtect** — lpAddress=0x10028000, dwSize=0x3e8, flNewProtect=0x4  → protect 0x4 (not exec)
16. **5× NtProtectVirtualMemory** — hProc=0xffffffff, pBase=0x19fcf8, pSize=0x19fcfc  → NtProtect newProt=0x4
17. **6× VirtualProtect** — lpAddress=0x10029000, dwSize=0xec8, flNewProtect=0x2  → protect 0x2 (not exec)
18. **6× NtProtectVirtualMemory** — hProc=0xffffffff, pBase=0x19fcf8, pSize=0x19fcfc  → NtProtect newProt=0x2

*(module preferred base `0x10000000`; at runtime read the real base from the memory map and add the RVA. The payload W→X flip + its size are the anchor.)*

## 5. Reproduce the DYNAMIC unpack (x64dbg, by hand)
Load the sample in x32dbg (paused at entry), then:
```
bc ; bphwc                      # clear software + hardware breakpoints
run            # repeat; use 'erun' to pass first-chance exceptions
#   -> stops at OEP None
# dump: dump_module(auto_detect_oep=true, rebuild_pe=true)  [mode: None, new_ep: None]
```

## 7. Per-finding provenance (where each IOC came from)
| Indicator | Source stage | How to re-derive |
|---|---|---|
| (no network IOCs recovered) | — | — |

## 8. Determinism — what is and isn't fixed
- **Deterministic:** identification, PE structure, imports, Ghidra functions/anomalies, recovered source, detected OEP (RVA), API call counts, and the dumped payload's content — all reproduce exactly from the same sample.
- **Environment-fixed:** module base may differ with ASLR; we record the runtime base so addresses map (RVA is invariant). Revert to `clean-baseline` for an identical OS.
- **Non-deterministic (noted, not relied on):** wall-clock timings in the ledger, and any network the sample attempts (contained by the isolated VM / FakeNet).
- **Audit trail:** `logs/tool_audit.jsonl` is the full machine-readable record; every row has the tool, inputs, output summary, duration and status.