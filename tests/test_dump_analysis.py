import os
from nanalyst import dump_analysis as da


def test_kinds_and_comparison(tmp_path):
    rnd = os.urandom(20000)
    txt = b"http://evil.example/gate.php user=admin password=1234\n" * 200
    z = b"\x00" * 8192
    paths = []
    for n, d in (("a_zero.bin", z), ("b_cipher.bin", rnd), ("c_text.bin", txt), ("d_dup.bin", txt)):
        p = tmp_path / n; p.write_bytes(d); paths.append({"name": n, "path": str(p)})
    an = da.analyze_dumps(paths)
    k = {r["name"]: r["kind"] for r in an["dumps"]}
    assert k["a_zero.bin"] == "zero-filled"
    assert k["b_cipher.bin"] == "encrypted / compressed"
    assert k["c_text.bin"] == "text / configuration"
    assert an["dumps"][3]["duplicate_of"] == "c_text.bin"
    assert an["summary"]["distinct"] == 3
    assert "decryption" in an["comparisons"][1]["reading"]
    assert da.to_markdown(an)
