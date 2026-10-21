from nanalyst.intelligent_unpack import Engine


def _eng(b):
    e = Engine.__new__(Engine)
    e.read_mem = lambda addr, size=64: b
    return e


def test_wide_string_not_cut_mid_char():
    raw = "C:\\nemesis\\report.txt".encode("utf-16-le") + b"\x00\x00" + b"garbage"
    assert _eng(raw).read_str(0x1000) == "C:\\nemesis\\report.txt"


def test_ascii_string():
    assert _eng(b"kernel32.dll\x00junk").read_str(0x1000) == "kernel32.dll"
