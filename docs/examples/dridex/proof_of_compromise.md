# Proof of Compromise — 178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1.exe

**Verdict: MALICIOUS**  (confidence 65/100, static + dynamic + detonation)

**Family:** Behaves as a **loader/packer**.

## Identity
- SHA-256: `178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1`
- Size: 212,992 bytes
- Type: PE32 (x86)
- Compiler: Microsoft Visual C/C++ 19.00.24215

## Author / build reconnaissance
- Compiled 2020-04-24 02:04:11 UTC
- Version info: CompanyName=INCA Internet Co., Ltd., LegalCopyright=Copyright (C) INCA Internet. 2000-2003, Comments=nProtect KeyCrypt Program Database DLL, OriginalFilename=npkpdb.dll, ProductName=nProtect KeyCrypt Program Database DLL, InternalName=npkpdb.dll
- MSVC toolchain build IDs [21005, 21022, 23026, 23918, 24210, 24213, 24215, 25834, 30319, 30501, 30729, 31101, 40219, 40629, 50727, 60610, 61030] (Rich-header fingerprint for same-author clustering)

## Why (evidence)
- CONFIRMED self-unpacking at runtime (payload captured + verified) (+30)
- runtime: memory made executable after being written (2 W->X event(s)) — the unpacking moment (+10)
- behavioral classification: loader/packer (loader/packer) (+25)

## Unpack verification
- **CONFIRMED_UNPACKED** (confidence 60/100) — the dumped/unpacked payload was compared against the packed file.
  - debugger captured the payload at 2 write->execute flip(s) (direct unpack evidence)
  - dump parses as a valid PE image

## Packing
- Packed: not conclusively (confidence 10/100)
  - uncommon high-entropy section '.text1' (7.96)

## MITRE ATT&CK
- T1027.002 Software Packing
- T1140 Deobfuscate/Decode Files or Information
- T1620 Reflective Code Loading

## Deobfuscation (.NET)
- .NET: False

## Detonation (behavioral)
- started: 2026-10-21T16:22:18
- duration_s: 90
- artifacts_dir: cases/ce45ac67-2b3c-455d-9c12-e11b0a0c5059_dridex/artifacts/run
