"""Crypto recovery — understand the encryption, then emit a runnable decryptor.

When static analysis (imports, recovered framework source, memory strings) tells
us WHAT algorithm a sample uses and we can recover the KEY, we generate a
standalone Python decryptor the operator can run to reverse the encryption (the
No-More-Ransom spirit). We are honest about limits:

  - Symmetric (XOR / RC4 / AES / DES-3DES / ChaCha) with a RECOVERABLE key
    (hardcoded in the binary, in recovered source, or in a memory dump) -> we
    emit a ready-to-run decryptor.
  - Key not yet found -> we emit a TEMPLATE decryptor (algorithm wired, candidate
    keys listed, a clear TODO) so the analyst has a running start.
  - Asymmetric (RSA / ECC) where the private key is attacker-held -> NOT
    recoverable offline; we say so and state what would be needed.

Detection is evidence-linked and additive; generation never claims more certainty
than the evidence supports.
"""
from __future__ import annotations

import re
from pathlib import Path

# algorithm -> (word-boundary/call-pattern regex, api_substrings).
# Patterns are deliberately strict: a bare substring like "des" inside
# "Description" must NOT trigger a scheme. Evidence is a real crypto token.
ALGOS = {
    "aes":    (r"aes(?:[\s_-]?(?:128|192|256))?|rijndael|calg_aes", ["BCryptEncrypt", "CryptEncrypt", "AesEncrypt"]),
    "rc4":    (r"\brc4\b|arcfour|\bprga\b", []),
    "des":    (r"\b3?des\b|triple[\s_-]?des", ["CryptEncrypt"]),
    "chacha": (r"chacha20?|salsa20", []),
    "xor":    (r"\bxor\b", []),
    "rsa":    (r"\brsa\b|-----begin [a-z ]*key|publickey|rsaencrypt", []),
    "base64": (r"base64|frombase64|tobase64", []),
    # Windows CryptoAPI / CSP (CryptoSPI CP* exports) — algorithm set at runtime
    "cryptoapi": (r"cryptacquirecontext|cryptencrypt|cryptdecrypt|cryptderivekey|"
                  r"cpencrypt|cpdecrypt|cpderivekey|cpgenkey|cpimportkey|bcryptencrypt",
                  ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "BCryptEncrypt"]),
}
ASYMMETRIC = {"rsa"}

AES_SBOX_HEAD = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
B64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
# hex strings whose byte length is a common key size
HEXKEY = re.compile(r"(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{2}){16}|(?:[0-9A-Fa-f]{2}){24}|(?:[0-9A-Fa-f]{2}){32})(?![0-9A-Fa-f])")


def _gather_text(case: dict) -> tuple[str, set, bytes]:
    """Collect searchable text (source + strings), the imported-API set, and raw
    bytes of the dump (for constant scanning)."""
    st = case.get("stages", {})
    text_parts, apis = [], set()

    pe = (st.get("triage_unpacked") or st.get("triage_dumped") or st.get("triage", {})).get("pe", {})
    for cat, lst in (pe.get("suspicious_apis", {}) or {}).items():
        apis.update(lst)

    gh = st.get("static_ghidra", {})
    apis.update(gh.get("suspicious_apis", []) or [])
    for k in ("urls", "ips", "registry", "suspicious"):
        text_parts += (gh.get("strings", {}) or {}).get(k, []) or []

    # dynamic API trace — APIs called + names resolved at runtime (e.g. CPDecrypt)
    at = st.get("api_trace", {}) or {}
    for ev in at.get("trace", []):
        apis.add(ev.get("api", "").split(".")[-1])
        note = (ev.get("capture") or {}).get("note", "")
        if note:
            text_parts.append(note)

    fw = st.get("framework_extract", {}) or {}
    if fw.get("status") == "extracted":
        text_parts += (fw.get("commands") or []) + (fw.get("decoded_hex_strings") or [])
        # the recovered source file is the richest signal
        sf = fw.get("source_file")
        if sf and Path(sf).exists():
            try:
                text_parts.append(Path(sf).read_text(errors="replace"))
            except Exception:
                pass

    for memk in ("memory_static_unpack",):
        m = st.get(memk, {}) or {}
        for k in ("urls", "ips", "registry", "suspicious_keywords"):
            text_parts += m.get(k, []) or []

    raw = b""
    det = st.get("detonation", {}) or {}
    dumps = []
    for d in (st.get("dynamic_unpack", {}).get("dump_path"), det.get("memory_dump")):
        if d:
            dumps.append(d)
    return "\n".join(str(x) for x in text_parts), apis, raw


def detect_crypto(case: dict) -> dict:
    """Return {schemes:[...], notes:[]}. Conservative + honest: a scheme needs a
    real crypto token (not a substring); a key is 'strong' (-> runnable decryptor)
    only when it comes from a key/password assignment or a lone key-length constant,
    NOT from shellcode/data blobs."""
    text, apis, _ = _gather_text(case)
    low = text.lower()
    apis_l = {a.lower() for a in apis}
    schemes, notes = [], []

    # STRONG keys: explicit key/password/secret/iv assignments
    strong_ascii = sorted(set(re.findall(
        r"(?:key|pass(?:word)?|secret)\s*[:=]\s*[\"']([^\"']{4,64})[\"']", text, re.I)))
    strong_hex = sorted(set(re.findall(
        r"(?:key|iv)\s*[:=]\s*[\"']?((?:[0-9A-Fa-f]{2}){16,32})\b", text, re.I)))
    # WEAK candidates: standalone key-length hex constants. If there are MANY, they
    # are almost certainly embedded data/shellcode chunks, not keys -> discard.
    all_hex = HEXKEY.findall(text)
    weak_hex = sorted(set(all_hex))
    looks_like_data = len(all_hex) > 3
    if looks_like_data:
        notes.append(f"{len(all_hex)} key-length hex blobs found — treated as embedded "
                     "data/shellcode, NOT crypto keys (too many to be keys).")
        weak_hex = []

    strong_keys = strong_hex + [k if re.fullmatch(r"[0-9A-Fa-f]+", k) else k.encode().hex()
                                for k in strong_ascii]

    for algo, (pat, api_subs) in ALGOS.items():
        ev, strong = [], False
        if re.search(pat, low):
            ev.append(f"crypto token /{pat}/ in source/strings")
        for a in api_subs:
            if any(a.lower() in x for x in apis_l):
                ev.append(f"imports {a}*"); strong = True
        if not ev:
            continue
        asym = algo in ASYMMETRIC
        keys = [] if asym else (strong_keys + weak_hex)
        has_strong_key = bool(strong_keys) and not asym
        conf = 35 + 15 * len(ev) + (20 if has_strong_key else 0) + (10 if strong else 0)
        recoverable = (algo == "base64") or (not asym and has_strong_key)
        schemes.append({
            "algo": algo, "confidence": min(conf, 95), "evidence": ev,
            "candidate_keys": keys[:8], "strong_key": has_strong_key,
            "asymmetric": asym, "recoverable": recoverable,
        })

    if any(s["algo"] == "cryptoapi" for s in schemes):
        notes.append("Windows CryptoAPI/CSP in use (CryptAcquireContext / CP* exports) — the "
                     "algorithm + key are set at runtime. Recover the key by breaking on "
                     "CPImportKey / CPDeriveKey / CryptImportKey and reading the key blob, then "
                     "decrypt with that algorithm.")
    if any(s["asymmetric"] for s in schemes):
        notes.append("RSA/asymmetric detected: files are NOT recoverable offline without the "
                     "attacker's PRIVATE key (or an implementation flaw / leaked key).")
    if schemes and not any(s["recoverable"] for s in schemes):
        notes.append("Crypto indicators present but NO usable key recovered — decryptors below are "
                     "TEMPLATES; supply the key once found (debugger breakpoint on the crypto call).")
    if not schemes:
        notes.append("No clear crypto scheme recovered from static evidence.")
    schemes.sort(key=lambda s: -s["confidence"])
    return {"schemes": schemes, "notes": notes,
            "candidate_keys_hex": strong_hex + weak_hex,
            "candidate_keys_ascii": strong_ascii}


# ---------------- decryptor code generation ----------------
_HEADER = '''#!/usr/bin/env python3
"""AUTO-GENERATED decryptor — Nemesis Analyst.
Algorithm: {algo}   Confidence: {conf}/100
{note}

Usage:  python3 decrypt.py <encrypted_file> [output_file]
Review the KEY/IV below before trusting the output. This is a reversing aid, not a
guarantee; verify a few bytes of the result.
"""
import sys
from pathlib import Path

'''

_XOR = '''KEY = bytes.fromhex("{hexkey}")  # <-- recovered/candidate key ({note})

def decrypt(data: bytes) -> bytes:
    if not KEY:
        raise SystemExit("set KEY first")
    return bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(data))
'''

_RC4 = '''KEY = bytes.fromhex("{hexkey}")  # <-- recovered/candidate key ({note})

def decrypt(data: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + KEY[i % len(KEY)]) & 0xff
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)
'''

_AES = '''# needs: pip install cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes.fromhex("{hexkey}")  # 16/24/32 bytes ({note})
IV  = bytes.fromhex("{hexiv}")   # 16 bytes for CBC; b"" for ECB
MODE = "{mode}"  # "CBC" or "ECB"

def decrypt(data: bytes) -> bytes:
    if MODE == "CBC":
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    else:
        cipher = Cipher(algorithms.AES(KEY), modes.ECB())
    d = cipher.decryptor()
    out = d.update(data) + d.finalize()
    pad = out[-1] if out else 0          # strip PKCS#7 if present
    return out[:-pad] if 0 < pad <= 16 and out[-pad:] == bytes([pad]) * pad else out
'''

_DES = '''# needs: pip install cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes.fromhex("{hexkey}")  # 8 bytes (DES) / 24 (3DES) ({note})
IV  = bytes.fromhex("{hexiv}")

def decrypt(data: bytes) -> bytes:
    algo = algorithms.TripleDES(KEY) if len(KEY) > 8 else algorithms.TripleDES(KEY*3)
    cipher = Cipher(algo, modes.CBC(IV) if IV else modes.ECB())
    d = cipher.decryptor()
    return d.update(data) + d.finalize()
'''

_BASE64 = '''import base64

def decrypt(data: bytes) -> bytes:
    try:
        return base64.b64decode(data)
    except Exception:
        return base64.b64decode(data + b"=" * (-len(data) % 4))
'''

_RSA_STUB = '''# RSA / asymmetric: files are NOT recoverable offline without the attacker's
# PRIVATE key. This stub documents what would be required.
def decrypt(data: bytes) -> bytes:
    raise SystemExit(
        "RSA detected. Offline recovery needs the attacker PRIVATE key, a leaked/seized "
        "key, or an implementation flaw (reused primes, small/predictable key). "
        "Supply the private key (PEM) and switch this to cryptography's RSA OAEP/PKCS1 decrypt."
    )
'''

_MAIN = '''

def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    inp = Path(sys.argv[1]); out = Path(sys.argv[2]) if len(sys.argv) > 2 else inp.with_suffix(inp.suffix + ".dec")
    out.write_bytes(decrypt(inp.read_bytes()))
    print("wrote", out)

if __name__ == "__main__":
    main()
'''

_BODY = {"xor": _XOR, "rc4": _RC4, "aes": _AES, "des": _DES,
         "base64": _BASE64, "rsa": _RSA_STUB}


def generate(scheme: dict, out_dir: Path, key_hex: str = "", iv_hex: str = "",
             mode: str = "CBC") -> dict:
    """Emit a decryptor for one scheme. Returns {path, runnable, note}."""
    algo = scheme["algo"]
    body = _BODY.get(algo)
    if body is None:
        return {"algo": algo, "path": None, "runnable": False,
                "note": "no generator for this algorithm"}
    out_dir.mkdir(parents=True, exist_ok=True)

    key = key_hex or (scheme.get("candidate_keys") or [""])[0]
    # ascii candidate -> hex
    if key and not re.fullmatch(r"[0-9A-Fa-f]+", key):
        key = key.encode().hex()
    runnable = bool(key) and scheme.get("recoverable", False)
    note = ("key recovered from static evidence" if runnable else
            "PLACEHOLDER key — supply the real key (see candidate_keys)" if algo not in ("base64",)
            else "no key needed")

    code = _HEADER.format(algo=algo.upper(), conf=scheme["confidence"],
                          note="; ".join(scheme.get("evidence", [])))
    if algo in ("aes",):
        code += body.format(hexkey=key, hexiv=iv_hex, mode=mode, note=note)
    elif algo in ("des",):
        code += body.format(hexkey=key, hexiv=iv_hex, note=note)
    elif algo in ("xor", "rc4"):
        code += body.format(hexkey=key, note=note)
    else:
        code += body
    code += _MAIN

    path = out_dir / f"decrypt_{algo}.py"
    path.write_text(code)
    return {"algo": algo, "path": str(path), "runnable": runnable,
            "confidence": scheme["confidence"], "note": note,
            "candidate_keys": scheme.get("candidate_keys", [])}


def build_all(case: dict, out_dir: Path, log=print) -> dict:
    """Detect crypto for a case and emit decryptors/templates. Returns a stage dict."""
    det = detect_crypto(case)
    generated = []
    for sc in det["schemes"]:
        # emit only meaningful ones: a recoverable key, strong confidence, or an
        # asymmetric scheme (to state the honest "not recoverable" case). Weak
        # bare-substring hits are reported in schemes/notes but not written out.
        emit = sc["algo"] in _BODY and (sc["recoverable"] or sc["confidence"] >= 60
                                        or sc["asymmetric"])
        if emit:
            g = generate(sc, out_dir)
            generated.append(g)
            log(f"[decryptor] {sc['algo']} conf={sc['confidence']} "
                f"{'RUNNABLE' if g['runnable'] else 'template'} -> {g['path']}")
    # always leave a README when ANY crypto was detected (even if only a template /
    # CryptoAPI note), so the decryptor/ folder explains what to do — never empty.
    readme = None
    if det["schemes"]:
        _write_readme(det, generated, out_dir)
        readme = str(out_dir / "README.md")
    status = "generated" if generated else ("crypto_found_no_decryptor" if det["schemes"] else "none")
    return {"status": status, "schemes": det["schemes"], "notes": det["notes"],
            "generated": generated, "readme": readme}


def _write_readme(det: dict, generated: list, out_dir: Path) -> None:
    L = ["# Decryption / crypto recovery", ""]
    for n in det["notes"]:
        L.append(f"> {n}")
    L.append("")
    L.append("| Algorithm | Confidence | Status | Script |")
    L.append("|---|---|---|---|")
    for g in generated:
        L.append(f"| {g['algo'].upper()} | {g['confidence']}/100 | "
                 f"{'RUNNABLE' if g['runnable'] else 'template (needs key)'} | `{Path(g['path']).name}` |")
    L.append("")
    keys = det.get("candidate_keys_hex", []) + det.get("candidate_keys_ascii", [])
    if keys:
        L.append("## Candidate keys recovered from the sample")
        for k in keys[:12]:
            L.append(f"- `{k}`")
        L.append("")
    L.append("## Usage")
    L.append("```\npython3 decrypt_<algo>.py <encrypted_file> [output_file]\n```")
    L.append("Verify a few bytes of the output. Templates need the real KEY/IV set at the top.")
    (out_dir / "README.md").write_text("\n".join(L))
