import os
import struct
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from nanalyst import crypto_analysis as ca

PLAIN = b"Quarterly report: account 4471-22, balance 10,482.55 USD. Confidential. " * 3


def _pad(b):
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def _cbc(key, iv, pt):
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(_pad(pt)) + e.finalize()


def test_xor_recovered_from_pair():
    key = b"K3y!"
    ct = bytes(c ^ key[i % 4] for i, c in enumerate(PLAIN))
    r = ca.recover(PLAIN, ct, [])
    assert r["verified"]["algo"] == "xor" and r["verified"]["key"] == key


def test_rc4_with_candidate_key():
    key = b"sixteen byte key"
    ct = ca.rc4(key, PLAIN)
    r = ca.recover(PLAIN, ct, [{"key": b"wrong key 123456", "source": "x"}, {"key": key, "source": "string"}])
    assert r["verified"]["algo"] == "rc4" and r["verified"]["source"] == "string"


def test_aes_cbc_zero_iv_and_unknown_iv_and_wrong_key():
    key = os.urandom(16)
    assert ca.recover(PLAIN, _cbc(key, b"\0" * 16, PLAIN), [{"key": key, "source": "blob"}])["verified"]["mode"] == "CBC"
    iv = os.urandom(16)
    r = ca.recover(PLAIN, _cbc(key, iv, PLAIN), [{"key": key, "source": "blob"}])
    assert r["verified"]["iv"] == iv
    assert ca.recover(PLAIN, _cbc(key, iv, PLAIN), [{"key": os.urandom(16), "source": "bad"}])["verified"] is None


def test_key_blob_parse_and_memory_scan():
    key = os.urandom(16)
    blob = b"\x08\x02\x00\x00" + struct.pack("<I", 0x660E) + struct.pack("<I", 16) + key
    assert ca.parse_key_blob(b"junk" + blob)[0]["key"] == key
    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ct = ecb.update(PLAIN[:48]) + ecb.finalize()
    mem = os.urandom(4096) + key + os.urandom(4096)
    r = ca.recover(PLAIN[:48], ct, [], [mem])
    assert r["verified"] and r["verified"]["key"] == key


def test_decryptor_is_executed_and_proven(tmp_path):
    key, iv = os.urandom(32), os.urandom(16)
    ct = _cbc(key, iv, PLAIN)
    v = ca.recover(PLAIN, ct, [{"key": key, "source": "blob"}])["verified"]
    proof = ca.write_and_prove(v, PLAIN, ct, tmp_path)
    assert proof["round_trip_verified"] and Path(proof["script"]).exists()


def test_constants_found():
    data = b"\x00" * 50 + ca.CONSTANTS[0][1] + b"expand 32-byte k"
    names = {c["constant"] for c in ca.scan_constants(data)}
    assert "AES S-box" in names and "ChaCha/Salsa 'expand 32-byte k'" in names


def test_case_driver_verdicts(tmp_path):
    case = {"stages": {"api_trace": {"trace": [], "counts": {}}}}
    assert "No file-encryption call" in ca.analyze_case(case, tmp_path)["verdict"]
    key = os.urandom(16); ct = _cbc(key, b"\0" * 16, PLAIN)
    (tmp_path / "p.bin").write_bytes(PLAIN); (tmp_path / "c.bin").write_bytes(ct)
    blob = tmp_path / "k.bin"; blob.write_bytes(b"\x08\x02\x00\x00" + struct.pack("<II", 0x660E, 16) + key)
    case["stages"]["api_trace"]["trace"] = [
        {"api": "advapi32.CryptEncrypt", "capture": {"encrypt": True, "local_plain_dump": str(tmp_path / "p.bin"), "local_cipher_dump": str(tmp_path / "c.bin"), "key_handle": "0x1"}},
        {"api": "advapi32.CryptImportKey", "capture": {"note": "KEY BLOB 0x1+0x1c (import to decrypt config)", "local_dump": str(blob)}}]
    res = ca.analyze_case(case, tmp_path / "dec")
    assert res["verdict"].startswith("VERIFIED") and ca.to_markdown(res)
