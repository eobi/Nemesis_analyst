# Nemesis Analyst — Roadmap & TODO

A central AI brain orchestrating malware analysis across remote systems
(Ghidra + IDA on the Mac host, x64dbg + detonation in disposable Windows VMs),
running a **static -> dynamic -> re-static** feedback loop that ends in a
**Proof of Compromise** report. Tools are MCP workers; the brain connects to
each wherever it runs.

## Core engine: iterative static<->dynamic deepening
1. Triage (DIE + PE)
2. STATIC pass 1 (Ghidra/IDA): limited if packed; detect anomalies ->
   emit DYNAMIC HINTS (call/jmp reg epilogues, push-addr+ret, API-hashing loops,
   anti-debug, .NET metadata)
3. DYNAMIC — two modes, brain picks per static findings:
   - A. Controlled (x64dbg + hint-driven breakpoints): unpack, dump, reconstruct
   - B. Full detonation (disposable VM): run to completion, capture behavior+network
4. RE-STATIC on the reconstructed dump (full functions/strings/URLs/config)
5. Loop 2<->4 until convergence
6. Proof of Compromise report

## Two dynamic modes
- Controlled/surgical: x64dbg worker, breakpoints from static hints -> OEP,
  dump, IAT/PE reconstruction.
- Full detonation/behavioral: let it run fully in a clean VM, capture real
  behavior incl. network.

## Phases / TODO
- [x] **Phase 0 — Triage** (DIE + PE profile). Static, host-safe. DONE.
- [x] **Phase 2a — Spine:** Case model (`nanalyst/case.py`): sample + stages + accumulated
      hints + state, persisted to cases/<sha256>/case.json. DONE. (MCP wrapping deferred to Phase 3.)
- [x] **Phase 2b — Ghidra static worker** (`nanalyst/tools/ghidra_worker.py` +
      `ghidra_scripts/NemesisStatic.java`): functions, categorized strings, suspicious-API
      xrefs, control-flow ANOMALIES (indirect-register call/jmp, push-ret), and DYNAMIC HINTS.
      DONE. Validated on Panda_Banker (packed -> 1 function, caught JMP EBX tail-jump -> OEP hint).
      Tuning TODO: filter version-like false-positive IPs (e.g. 6.0.200.2).
- [ ] **Phase 2c — IDA worker** (Hex-Rays decompile, type recovery) behind the same interface.
- [x] **Phase 2d — .NET + DEOBFUSCATION worker (guest-side, Windows via SSH):** BUILT+VALIDATED
      (`nanalyst/guest_static.py`) on real sample .NET_Malware.bin -> DIE=VB.NET/.NET, de4dot cleaned ->
      .NET_Malware-cleaned.bin. TODO: decompile cleaned asm to C#/VB (ilspycmd/dnSpy) + wire into Case/PoC.
      - [ ] DIE identifies the obfuscator/protector (it carries tool sigs, e.g. tool_de4dot)
      - [ ] .NET obfuscated -> `de4dot` (C:\Tools\de4dot, on PATH) generic, or NETReactorSlayer (.NET Reactor)
      - [ ] decompile cleaned assembly: dnSpy / ILSpy `ilspycmd`
      - [ ] guest-side static worker runs Windows-only tools over SSH (de4dot, NETReactorSlayer,
            dnSpy, DIE-win, PE-bear, trid); Mac-side keeps DIE/pefile/Ghidra for native PE
- [x] **Phase 3 — AI brain (MCP):** workers exposed as MCP tools (`mcp_server.py`) so Claude is the
      brain; deterministic Proof of Compromise generator (`nanalyst/proof.py`) + `analyze.py`/`poc.py`
      CLIs. DONE (static). The static<->dynamic *loop* closes once the dynamic worker lands (Phase 4-5).
      Tuning TODO: filter system DLL names out of path IOCs; drop version-like IPs.
- [~] **Phase 4 — Dynamic: x64dbg via MCP (SUPER-INTELLIGENT unpacking engine):**
      LEVERAGE an existing x64dbg MCP plugin (AgentSmithers/x64DbgMCPServer ~80 tools, or
      SetsunaYukiOvO/x64dbg-mcp C++). Plugin runs in x64dbg on the guest; brain drives it over
      host-only net (192.168.128.2:909x) + bearer token. Intelligent workflows the brain runs:
      - [ ] #1 carve EVERY PE in memory (main + injected, different regions) — + PE-sieve (pushed) as auto carver
      - [ ] #2 count VirtualAlloc/VirtualProtect hits; real unpack often the 2nd/Nth (note run1, apply run2)
      - [ ] #3 wait-for-write-complete: watch VirtualProtectEx region flip W->X before carving the MZ
      - [ ] anti-debug bypass: bp IsDebuggerPresent/CheckRemoteDebuggerPresent/NtQueryInformationProcess,
            patch return EAX 1->0; ScyllaHide. Then re-static each dumped PE (close the loop).
      - [x] PE-sieve pushed to guest C:\Tools (complementary post-hoc memory carver)
- [~] **Phase 4.5 — VM orchestration layer:** ENGINE BUILT (`nanalyst/vm/`), safe parts validated.
      - [x] Disposable copy-on-write clones (`disk.py`: create_overlay/destroy_overlay) — tested
      - [x] Headless boot + QMP lifecycle (`qemu.py`: build_command/boot/status/shutdown) — command verified; LIVE BOOT pending
      - [x] Isolation: user-net restrict=on (no internet) + SSH hostfwd port
      - [x] Guest control via SSH/scp, lab account (`guest.py`) — commands verified
      - [x] Sandbox context manager (`orchestrator.py`): clone->boot->wait-ssh->yield->destroy
      - [ ] ONE-TIME: build immutable base (`vm_prepare_base.py`, flattens clean-baseline) — not yet run
      - [ ] LIVE validation: first real boot + SSH into guest
      - [x] Anti-evasion (host side): hide hypervisor CPUID bit + SMBIOS spoof (OEM hardware look)
      - [ ] Anti-evasion (guest side): scrub ACPI/registry/driver artifacts that reveal QEMU/VM
- [ ] **Phase 5 — Dynamic B (detonation/behavioral worker, VM):** exact ordered sequence in
      `DETONATION_RUNBOOK.md`. Runs autonomously in-guest + logs every step.
      - [ ] FakeNet<->SSH fix: autonomous in-guest agent (don't need live SSH during FakeNet) +
            FakeNet HostBlackList the control peer; reconnect/pull after FakeNet stops
      - [ ] Sequence: reset -> FakeNet -> Regshot1 -> Procmon -> detonate -> 3-4min ->
            stop Procmon(+CSV) -> Regshot2(diff) -> stop FakeNet -> memdump
      - [ ] FakeNet-NG: contain network, capture `packets_*.pcap` + decrypted HTTPS + http logs
      - [ ] tshark (headless): HTTP streams, WebSocket(WS), DNS, TCP conversations -> IOCs
      - [ ] Regshot before/after (automatable = reg export + FS-walk diff; Regshot GUI for manual)
      - [ ] Procmon headless (/BackingFile, /Terminate, /SaveAs csv) / Noriben
      - [ ] Memory dump of unpacked payload -> feed back to static + recovery
      - [ ] Detonation timing/behavior guided by static hints
- [ ] **Phase 6 — Proof of Compromise report:** identity, unpacking record, static
      (pre+post unpack), behaviors, network IOCs, persistence, dropped files,
      config extraction, MITRE ATT&CK, verdict + evidence trail. JSON + human-readable.
- [ ] **Phase 7 — Scale:** batch runner, parallel disposable-VM pool ("many malwares in minutes"),
      optional IDA backend, config extractors per family.

## Environment realism & evasion (why the VM platform matters)
Malware fingerprints the hypervisor (QEMU/VBox/VMware) and host and changes
behavior to dodge analysis. We address this two ways:
- [x] Harden the sandbox so it looks like real hardware (host-side done; guest-side pending).
- [ ] **Differential detonation:** run the same sample across environments (QEMU now;
      VirtualBox/VMware/bare-metal adapters behind the Sandbox interface later) and DIFF the
      behavior to detect evasion and surface environment-sensitive payloads.
- [ ] Static detection of anti-VM/anti-sandbox checks (VBOX/VMware/QEMU/Sandboxie strings,
      CPUID hypervisor, sandbox process enumeration) -> feed the bypass/hardening plan.

## Recovery / decryptor generation (ransomware — DEFENSIVE, victim recovery)
Spirit of the No More Ransom project: help victims recover files when it is
cryptographically possible. HONEST SCOPE — only works for recoverable cases.
- [ ] Identify the crypto: static constants/signatures (AES S-box, RC4 KSA, ChaCha/Salsa,
      RSA/ECC, XOR), API use (CryptEncrypt/BCryptEncrypt), and the encryption routine.
- [ ] Capture key material during detonation: keys/IVs in memory, Crypt* call parameters,
      key schedules in the memory dump (the dynamic stage already dumps memory).
- [ ] Assess recoverability HONESTLY:
      - recoverable: weak/flawed crypto, hardcoded/derivable/predictable keys, symmetric
        keys recoverable from memory
      - NOT recoverable: correct unique-per-victim asymmetric schemes with secure key deletion
- [ ] When recoverable: emit a small standalone Python decryptor the victim runs to restore
      files; otherwise report the algorithm + IOCs and say recovery needs the attacker's key.
- [ ] Add the recoverability finding + decryptor (or clear "not recoverable" statement) to the
      Proof of Compromise report.

## Multi-platform expansion (after the Windows/PE pipeline is solid)
The Case model, worker interface, static<->dynamic loop, and Proof-of-Compromise
report are format-agnostic; these add new workers + detonation environments, not a
redesign. Ghidra is already multi-arch.
- [ ] **Phase 8 — Android** (APK / DEX / native .so):
      - Static: jadx + apktool (manifest, permissions, DEX->Java), Ghidra for ARM/ARM64 .so
      - Anomalies/hints: reflection, dynamic class loading, native JNI calls, packers (DexGuard etc.)
      - Dynamic: disposable Android emulator (AVD) snapshots, Frida instrumentation,
        network capture (mitmproxy/FakeNet), behavior like a MobSF-style run
- [ ] **Phase 9 — iOS** (IPA / Mach-O ARM64):
      - Static: class-dump, Ghidra/IDA Mach-O, entitlements/Info.plist
      - Handle FairPlay-encrypted App Store binaries (dump decrypted from memory)
      - Dynamic: jailbroken device or simulator + Frida
- [ ] **Phase 10 — Embedded / firmware** (ties to Nemesis Anvil hardware rig):
      - Extract: binwalk; multi-arch Ghidra (ARM, MIPS, PPC, RISC-V)
      - Dynamic: QEMU-system full-firmware emulation (Firmware Analysis Toolkit),
        Unicorn harnesses; on-device via the Anvil board-exploitation rig
      - Same loop + Proof of Compromise, extended to firmware behaviors

## Logging & checklist (BUILT: nanalyst/runlog.py)
Every command/input/artifact -> per-case run.log + run.jsonl (secrets redacted). Full ordered
phase list tracked in checklist.json (pending->running->done/failed/skipped) so no step is skipped.

## Safety (non-negotiable)
Static phases (0, 2, 4-static) never execute the sample and are host-safe.
ALL dynamic/detonation runs ONLY inside disposable, isolated VMs with the network
contained by FakeNet-NG — never the real internet, never the host. Every detonation
starts from a clean clone and the overlay is deleted after artifact collection.

## Environment
- Mac host: Ghidra 12.1.3 headless, IDA Pro, DIE 3.21 portable, upx, lief, pefile.
- Windows RE VM (UTM/QEMU): x64dbg, FakeNet-NG, Wireshark 3.6 + tshark, Regshot,
  Procmon, PE-sieve/mal_unpack. clean-baseline snapshot; `lab` SSH account.
- Transport: MCP (stdio local; HTTP over host-only net to VM workers).
