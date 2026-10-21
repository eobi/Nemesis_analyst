# Example output — Dridex

The complete analyst output from one real run on a packed **Dridex** sample
(`SHA-256 178ba564…6c3e1`), static + dynamic + detonation.

| File | What it is |
|---|---|
| `ANALYSIS.pdf` | the single consolidated report (start here) |
| `REPORT.md` | the analyst report in Markdown |
| `METHODOLOGY.md` | how it was produced, step by step (reproducible) |
| `proof_of_compromise.md` | the evidence-gated verdict + ATT&CK mapping |
| `case.json` | the full machine-readable result (every stage) |
| `intel/` | detection package: `iocs.csv`/`iocs.json`, `stix.json`, `yara/`, `hashes.txt` |
| `dumps/DUMPS.md` | index of the captured memory regions |

**Not included, on purpose:** the raw payload dumps, the process memory image, the
FakeNet pcap and the malware binary itself. This repository never ships live malware —
only the analysis of it. Reproduce the raw artifacts by running the tool on your own copy.
