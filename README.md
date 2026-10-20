# Nemesis Analyst

An AI-orchestrated malware analysis pipeline. A control plane (the AI brain)
drives a toolchain (Detect It Easy, PE profiling, Ghidra, x64dbg, unpackers) and
produces an analyst report, batchable across many samples.

## Pipeline
1. Identify (Detect It Easy): arch, filetype, compiler, packer
2. Static PE profile (pefile): sections+entropy, imports, TLS, signature, overlay
3. Capabilities (capa) — Phase 1
4. Unpack: UPX (`upx -d`) or dynamic (x64dbg/PE-sieve), then re-triage
5. Deep static (Ghidra headless; IDA optional)
6. Dynamic (x64dbg AutoUnpack / PE-sieve) — in an isolated VM only
7. AI synthesis -> report (verdict, IOCs, C2, ATT&CK)

## Phases
- [x] Phase 0: triage (DIE + PE profile) — this commit, STATIC, host-safe
- [ ] Phase 1: capa + static UPX unpack + re-triage loop
- [ ] Phase 2: Ghidra headless adapter
- [ ] Phase 3: AI brain (LLM tool-calling, exposed as MCP)
- [ ] Phase 4: dynamic (x64dbg plugin / PE-sieve) in the VM
- [ ] Phase 5: batch runner + isolation + optional IDA backend

## Safety
Phases 0-3 are STATIC and never execute the sample. Dynamic analysis (Phase 4+)
runs the sample and MUST stay inside the isolated RE VM.

## Setup
    python3 -m pip install -r requirements.txt
    # Detect It Easy (optional but recommended): bundled portable build expected at
    # vendor/die/die.app/Contents/MacOS/diec  (or set NANALYST_DIEC, or put diec on PATH)

## Usage (Phase 0)
    python3 run.py <file>            # pretty report
    python3 run.py --json <file>     # JSON
    python3 run.py <dir>             # every file in a directory
JSON reports are saved to ./out/.

## Phase 3 — the AI brain (MCP)
The workers are exposed as MCP tools so an LLM client (Claude Code, Claude
Desktop, a Pentagon agent) acts as the orchestrating brain. All tools are STATIC.

Tools: `analyze_sample`, `triage_sample`, `ghidra_static`,
`get_proof_of_compromise`, `list_cases`.

Connect it (already in `.mcp.json`): open this folder as the project in Claude
Code, or add the same block to your client config. Then ask the brain, e.g.
"analyze /path/to/sample and give me the proof of compromise."

Standalone (no LLM needed):
    python3 analyze.py <file>     # triage + Ghidra + Proof of Compromise
    python3 poc.py <sha256>       # regenerate the report from a saved case
