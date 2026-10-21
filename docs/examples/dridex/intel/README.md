# Detection package

Produced by Nemesis Labs from an automated analysis (TLP:AMBER). Generated 2026-10-21T21:28:23Z.
Sample SHA-256: `178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1`    Family: loader/packer    Categories: loader/packer

| File | Use | Trust |
|---|---|---|
| `iocs.json` / `iocs.csv` | every indicator with provenance, tier and intended use | tier tells you how it was obtained |
| `hashes.txt` | sample + unpacked payloads (MD5/SHA-1/SHA-256/imphash) | high for payload hashes |
| `yara/` | one rule per stage | auto-generated; **test against your goodware set** |
| `suricata.rules` | DNS/IP/HTTP rules | only from indicators observed or recovered (tier >= 70) |
| `sigma/` | host-behaviour rules | only where the run produced the evidence |
| `stix.json` | STIX 2.1 bundle | blockable indicators with tier >= 70 only |

## What is NOT available, and why
* **file hashes**: 9 found — sample + unpacked payloads
* **network (C2 / download)**: 0 found — none recovered with confidence: the C2 configuration is probably encrypted at rest and decrypted only when it beacons — run the detonation phase (FakeNet capture) or recover the config key
* **host artefacts**: 0 found — none observed in the code recovered so far
* **build / attribution**: 5 found

## Limits
* Tiers: observed (on the wire / live run) 90, decrypted 80, unpacked 70, static (strings of the packed file) 40, AI-suggested 20 (never emitted as a rule).
* Filtered-out indicators (known-good domains, private IPs, version numbers) are listed under `excluded` in `iocs.json`.
* A C2 list that is encrypted in the sample cannot be extracted without the key; that is stated above rather than guessed.
