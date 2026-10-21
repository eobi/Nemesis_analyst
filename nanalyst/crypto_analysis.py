"""File-encryption analysis: identify the cipher from what the sample actually did, recover the key if it is
recoverable, and PROVE a decryptor by round trip. Nothing is claimed that was not verified.

Inputs (all optional, all from the live run):
  pairs        (plaintext, ciphertext) captured around CryptEncrypt / BCryptEncrypt
  key material blobs dumped at CryptImportKey, memory dumps (candidate keys), strings/hex keys
  code         raw bytes of the payload/dumps, scanned for cipher constants

What it reports
  constants    cipher/hash tables found in the code (AES S-box, SHA-256 K, ChaCha "expand", CRC32, TEA delta ...)
  pair facts   length relation, block alignment, ECB repetition, IV/nonce hints
  recovery     XOR key from plaintext^ciphertext, RC4/AES key found among candidates by KNOWN-PLAINTEXT test
  verdict      "verified": a (algo, mode, key, iv) that reproduces the plaintext from the ciphertext, and a decryptor
               script that was executed against the ciphertext and returned the plaintext. Otherwise an explicit
               statement of what is missing (e.g. key wrapped by an attacker RSA public key: not recoverable offline).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

CONSTANTS = [
    ("AES S-box", bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])),
    ("AES inverse S-box", bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB])),
    ("AES T-table (Te0)", bytes.fromhex("a56363c6847c7cf8")),
    ("SHA-256 K constants", bytes.fromhex("982f8a4291443771")),
    ("SHA-1 init", bytes.fromhex("0123456789abcdef")),
    ("MD5 T constants", bytes.fromhex("78a46ad756b7c7e8")),
    ("ChaCha/Salsa 'expand 32-byte k'", b"expand 32-byte k"),
    ("ChaCha/Salsa 'expand 16-byte k'", b"expand 16-byte k"),
    ("CRC32 table (0xEDB88320)", bytes.fromhex("0000000096300777")),
    ("TEA/XTEA delta 0x9E3779B9", bytes.fromhex("b979379e")),
    ("Blowfish P-array (pi)", bytes.fromhex("886a3f24d308a385")),
    ("Base64 alphabet", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
    ("RSA/PEM public key", b"-----BEGIN PUBLIC KEY-----"),
    ("RSA/PEM RSA public key", b"-----BEGIN RSA PUBLIC KEY-----"),
    ("RSA public-key blob (RSA1)", b"RSA1"),
    ("RSA private-key blob (RSA2)", b"RSA2"),
]


def scan_constants(data: bytes, limit=3) -> list:
    out = []
    for name, sig in CONSTANTS:
        i, hits = 0, []
        while len(hits) < limit:
            i = data.find(sig, i)
            if i < 0:
                break
            hits.append(hex(i)); i += 1
        if hits:
            out.append({"constant": name, "offsets": hits})
    return out


# ---- primitives -------------------------------------------------------------------------------------------
def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255; S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i + 1) & 255; j = (j + S[i]) & 255; S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 255])
    return bytes(out)


def _aes_ecb(key: bytes, block: bytes, decrypt=True) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    c = Cipher(algorithms.AES(key), modes.ECB())
    x = c.decryptor() if decrypt else c.encryptor()
    return x.update(block) + x.finalize()


def _unpad(b: bytes) -> bytes:
    if b and 1 <= b[-1] <= 16 and b.endswith(bytes([b[-1]]) * b[-1]):
        return b[:-b[-1]]
    return b


def aes_decrypt(key: bytes, ct: bytes, mode: str, iv: bytes | None = None) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    m = modes.ECB() if mode == "ECB" else modes.CBC(iv or b"\x00" * 16)
    d = Cipher(algorithms.AES(key), m).decryptor()
    return d.update(ct[: len(ct) // 16 * 16]) + d.finalize()


# ---- key candidates --------------------------------------------------------------------------------------------
def parse_key_blob(blob: bytes) -> list:
    """CryptoAPI PLAINTEXTKEYBLOB: BLOBHEADER(bType=8, bVersion=2, reserved, aiKeyAlg) + dwKeySize + key."""
    out = []
    for off in range(0, max(0, len(blob) - 12)):
        if blob[off] == 0x08 and blob[off + 1] == 0x02 and blob[off + 2:off + 4] == b"\x00\x00":
            alg = int.from_bytes(blob[off + 4:off + 8], "little")
            n = int.from_bytes(blob[off + 8:off + 12], "little")
            if n in (5, 7, 8, 16, 24, 32) and off + 12 + n <= len(blob):
                out.append({"alg_id": hex(alg), "key": blob[off + 12:off + 12 + n], "source": f"key blob @+{off}"})
        if len(out) >= 4:
            break
    return out


def candidate_keys(blobs=(), texts=()) -> list:
    """[{key: bytes, source}] from key blobs and printable/hex strings. (Raw memory is searched separately, by known-plaintext test.)"""
    c, seen = [], set()

    def add(k, src):
        if k and k not in seen and len(k) in (5, 7, 8, 16, 24, 32):
            seen.add(k); c.append({"key": k, "source": src})
    for b in blobs:
        for kb in parse_key_blob(b):
            add(kb["key"], kb["source"])
    for t in texts:
        for m in re.finditer(r"(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{2}){16}|(?:[0-9A-Fa-f]{2}){24}|(?:[0-9A-Fa-f]{2}){32})(?![0-9A-Fa-f])", t):
            add(bytes.fromhex(m.group(1)), "hex string")
        for m in re.finditer(r"[\x21-\x7e]{16,32}", t):
            s = m.group().encode()
            add(s if len(s) in (16, 24, 32) else s[:16], "ascii string")
    return c


def _memory_key_scan(cipher: bytes, plain: bytes, mem: bytes, budget=400_000) -> list:
    """Known-plaintext scan: slide over the memory dump; a window is the AES key if it decrypts the first
    ciphertext block to the first plaintext block (ECB, or CBC with a zero/derivable IV)."""
    found = []
    if len(cipher) < 16 or len(plain) < 16:
        return found
    c1, p1 = cipher[:16], plain[:16]
    lim = min(len(mem) - 32, budget)
    for i in range(0, max(lim, 0), 4):
        for n in (16, 32):
            k = mem[i:i + n]
            if len(set(k)) < 6:
                continue
            try:
                if _aes_ecb(k, c1) == p1:
                    found.append({"key": k, "source": f"memory dump @+{i}", "mode": "ECB", "iv": b""})
                elif bytes(a ^ b for a, b in zip(_aes_ecb(k, c1), p1)) == b"\x00" * 16:
                    pass
            except Exception:
                continue
        if found:
            break
    return found


# ---- recovery ----------------------------------------------------------------------------------------------
def pair_facts(plain: bytes, cipher: bytes) -> dict:
    f = {"plain_len": len(plain), "cipher_len": len(cipher)}
    n = len(plain)
    ct = cipher[:n] if len(cipher) >= n else cipher
    f["same_length"] = len(cipher) == n
    f["cipher_longer_by"] = len(cipher) - n
    f["block_aligned_16"] = len(cipher) % 16 == 0
    f["block_aligned_8"] = len(cipher) % 8 == 0
    blocks = [cipher[i:i + 16] for i in range(0, len(cipher) - 15, 16)]
    f["ecb_repetition"] = len(blocks) != len(set(blocks))
    pb = [plain[i:i + 16] for i in range(0, len(plain) - 15, 16)]
    f["plain_repeats_blocks"] = len(pb) != len(set(pb))
    f["unchanged_bytes"] = sum(1 for a, b in zip(plain, ct) if a == b)
    return f


def _xor_period(plain: bytes, cipher: bytes):
    n = min(len(plain), len(cipher))
    ks = bytes(a ^ b for a, b in zip(plain[:n], cipher[:n]))
    for p in range(1, min(65, n // 2 + 1)):
        if all(ks[i] == ks[i % p] for i in range(n)):
            return ks[:p]
    return None


def recover(plain: bytes, cipher: bytes, keys: list, memory: list | None = None) -> dict:
    """Find (algo, mode, key, iv) that turns `cipher` into `plain`. Returns the verified result or the facts."""
    facts = pair_facts(plain, cipher)
    res = {"facts": facts, "verified": None, "tried": []}
    n = len(plain)
    # 1. XOR: keystream repeats
    k = _xor_period(plain, cipher[:n])
    if k and (len(k) < n // 2 or n < 16):
        out = bytes(c ^ k[i % len(k)] for i, c in enumerate(cipher[:n]))
        if out == plain:
            res["verified"] = {"algo": "xor", "mode": "repeating-key", "key": k, "iv": b"", "source": "plaintext XOR ciphertext"}
            return res
    # 2. RC4 / AES with candidate keys (known-plaintext test)
    for kc in keys:
        key = kc["key"]
        res["tried"].append(kc["source"])
        try:
            if len(cipher) >= n and rc4(key, plain)[:n] == cipher[:n]:
                res["verified"] = {"algo": "rc4", "mode": "stream", "key": key, "iv": b"", "source": kc["source"]}
                return res
        except Exception:
            pass
        if len(key) in (16, 24, 32) and len(cipher) >= 16:
            try:
                if aes_decrypt(key, cipher, "ECB")[:n] == plain or _unpad(aes_decrypt(key, cipher, "ECB")) == plain:
                    res["verified"] = {"algo": "aes", "mode": "ECB", "key": key, "iv": b"", "source": kc["source"]}
                    return res
                if _unpad(aes_decrypt(key, cipher, "CBC", b"\x00" * 16)) == plain or aes_decrypt(key, cipher, "CBC", b"\x00" * 16)[:n] == plain:
                    res["verified"] = {"algo": "aes", "mode": "CBC", "key": key, "iv": b"\x00" * 16, "source": kc["source"]}
                    return res
                # CBC with unknown IV: derive it from block 1 and confirm on the whole message
                d1 = _aes_ecb(key, cipher[:16])
                iv = bytes(a ^ b for a, b in zip(d1, plain[:16]))
                if _unpad(aes_decrypt(key, cipher, "CBC", iv)) == plain or aes_decrypt(key, cipher, "CBC", iv)[:n] == plain:
                    res["verified"] = {"algo": "aes", "mode": "CBC", "key": key, "iv": iv, "source": kc["source"]}
                    return res
                # IV prepended to the ciphertext
                if len(cipher) > 16 and (_unpad(aes_decrypt(key, cipher[16:], "CBC", cipher[:16])) == plain):
                    res["verified"] = {"algo": "aes", "mode": "CBC (IV prefixed)", "key": key, "iv": cipher[:16], "source": kc["source"]}
                    return res
            except Exception:
                continue
    # 3. scan memory dumps for the key itself
    for mem in memory or []:
        for hit in _memory_key_scan(cipher, plain, mem):
            try:
                if aes_decrypt(hit["key"], cipher, "ECB")[:n] == plain:
                    res["verified"] = {"algo": "aes", "mode": "ECB", "key": hit["key"], "iv": b"", "source": hit["source"]}
                    return res
            except Exception:
                pass
    return res


# ---- decryptor + proof --------------------------------------------------------------------------------------
def _decryptor_source(v: dict) -> str:
    key, iv = v["key"].hex(), v["iv"].hex()
    return f'''#!/usr/bin/env python3
"""Decryptor generated and verified by Nemesis Analyst.
Algorithm: {v["algo"].upper()} / {v["mode"]}   key source: {v["source"]}
Usage: python3 {{name}} <encrypted_file> [output_file]
Requires: pip install cryptography"""
import sys
KEY = bytes.fromhex("{key}")
IV = bytes.fromhex("{iv}")

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255; S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i + 1) & 255; j = (j + S[i]) & 255; S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 255])
    return bytes(out)

def unpad(b):
    return b[:-b[-1]] if b and 1 <= b[-1] <= 16 and b.endswith(bytes([b[-1]]) * b[-1]) else b

def decrypt(data):
    algo, mode = "{v["algo"]}", "{v["mode"]}"
    if algo == "xor":
        return bytes(c ^ KEY[i % len(KEY)] for i, c in enumerate(data))
    if algo == "rc4":
        return rc4(KEY, data)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if "IV prefixed" in mode:
        iv, data = data[:16], data[16:]
    else:
        iv = IV or b"\\x00" * 16
    m = modes.ECB() if mode == "ECB" else modes.CBC(iv)
    d = Cipher(algorithms.AES(KEY), m).decryptor()
    return unpad(d.update(data[: len(data) // 16 * 16]) + d.finalize())

if __name__ == "__main__":
    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else src + ".decrypted"
    open(out, "wb").write(decrypt(open(src, "rb").read()))
    print("wrote", out)
'''


def write_and_prove(v: dict, plain: bytes, cipher: bytes, out_dir: Path) -> dict:
    """Write the decryptor, then EXECUTE it against the captured ciphertext; only a matching output counts."""
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"decrypt_{v['algo']}_{v['mode'].split()[0].lower()}.py"
    path = out_dir / name
    path.write_text(_decryptor_source(v).replace("{name}", name))
    ct, outp = out_dir / "_proof_cipher.bin", out_dir / "_proof_plain.bin"
    ct.write_bytes(cipher)
    try:
        r = subprocess.run([sys.executable, "-I", str(path), str(ct), str(outp)], capture_output=True, timeout=60)
        got = outp.read_bytes() if outp.exists() else b""
        ok = r.returncode == 0 and got[:len(plain)] == plain
    except Exception:
        ok = False
    for f in (ct, outp):
        f.unlink(missing_ok=True)
    return {"script": str(path), "round_trip_verified": ok}


# ---- case-level driver -----------------------------------------------------------------------------------------
def analyze_case(case: dict, out_dir: Path) -> dict:
    """Use everything the run captured. Never raises; always returns an honest result."""
    st = case.get("stages", {}) or {}
    trace = (st.get("api_trace", {}) or {}).get("trace", []) or []
    pairs, blobs, memory, texts = [], [], [], []
    for ev in trace:
        cap = ev.get("capture") or {}
        pl, cl = cap.get("local_plain_dump"), cap.get("local_cipher_dump")
        if cap.get("encrypt") and pl and cl and Path(pl).exists() and Path(cl).exists():
            pairs.append({"api": ev.get("api"), "plain": Path(pl).read_bytes(), "cipher": Path(cl).read_bytes(),
                          "key_handle": cap.get("key_handle")})
        if "KEY BLOB" in str(cap.get("note", "")) and cap.get("local_dump") and Path(cap["local_dump"]).exists():
            blobs.append(Path(cap["local_dump"]).read_bytes())
        if cap.get("decrypted") and cap.get("local_dump") and Path(cap["local_dump"]).exists():
            memory.append(Path(cap["local_dump"]).read_bytes())
    for rd in (st.get("api_trace", {}) or {}).get("region_dumps", []) or []:
        if rd.get("local_dump") and Path(rd["local_dump"]).exists():
            memory.append(Path(rd["local_dump"]).read_bytes())
    for k in ("urls", "ips", "registry", "suspicious_keywords"):
        texts += (st.get("memory_static_unpack", {}) or {}).get(k, []) or []
    code = b"".join(memory[:6])
    res = {"constants": scan_constants(code) if code else [], "pairs": len(pairs), "results": [], "verdict": ""}
    keys = candidate_keys(blobs, ["\n".join(map(str, texts))])
    res["key_candidates"] = len(keys)
    for p in pairs[:4]:
        r = recover(p["plain"][:4096], p["cipher"][:len(p["plain"][:4096]) + 32] if len(p["cipher"]) >= len(p["plain"]) else p["cipher"], keys, memory[:3])
        row = {"api": p["api"], "key_handle": p["key_handle"], "facts": r["facts"], "tried": len(r["tried"])}
        if r["verified"]:
            v = r["verified"]
            proof = write_and_prove(v, p["plain"][:4096], p["cipher"][:len(p["plain"][:4096]) + 32], out_dir)
            row["recovered"] = {"algo": v["algo"], "mode": v["mode"], "key_hex": v["key"].hex(), "iv_hex": v["iv"].hex(),
                                "key_source": v["source"], **proof}
        res["results"].append(row)
    ver = [r for r in res["results"] if r.get("recovered", {}).get("round_trip_verified")]
    rsa = any(c["constant"].startswith("RSA") for c in res["constants"])
    if ver:
        v = ver[0]["recovered"]
        res["verdict"] = (f"VERIFIED: {v['algo'].upper()}/{v['mode']} with key {v['key_hex']} (from {v['key_source']}) reproduces the "
                          f"captured plaintext; decryptor {Path(v['script']).name} was executed and matched.")
    elif pairs:
        res["verdict"] = ("A plaintext/ciphertext pair was captured but no candidate key reproduces it. "
                          + ("An RSA key structure was found in memory: the file key may be wrapped by an attacker public key, "
                             "which is not recoverable offline. " if rsa else "")
                          + "The pair and the key handle are saved for offline work.")
    elif any(r in str(st.get("api_trace", {}).get("counts", {})) for r in ("CryptEncrypt", "BCryptEncrypt")):
        res["verdict"] = "An encryption API was called but its buffers were not captured."
    else:
        res["verdict"] = "No file-encryption call was observed in this run."
    return res


def to_markdown(res: dict) -> list:
    if not res:
        return []
    L = ["## 3e. File-encryption analysis", f"**{res.get('verdict', '')}**", ""]
    if res.get("constants"):
        L += ["Cipher constants found in the captured code:", ""] + [f"- {c['constant']} at {', '.join(c['offsets'])}" for c in res["constants"]] + [""]
    for r in res.get("results", []):
        f = r["facts"]
        L.append(f"- `{r['api']}`: plaintext {f['plain_len']} bytes -> ciphertext {f['cipher_len']} bytes "
                 f"({'same length' if f['same_length'] else 'padded +' + str(f['cipher_longer_by'])}; "
                 f"16-byte aligned: {f['block_aligned_16']}); {r['tried']} candidate key(s) tested.")
        if r.get("recovered"):
            x = r["recovered"]
            L.append(f"  - Recovered: {x['algo'].upper()}/{x['mode']}, key `{x['key_hex']}`, IV `{x['iv_hex'] or '-'}` "
                     f"(source: {x['key_source']}). Decryptor: `{Path(x['script']).name}` — round trip "
                     f"{'VERIFIED' if x['round_trip_verified'] else 'FAILED'}.")
    L.append("")
    return L
