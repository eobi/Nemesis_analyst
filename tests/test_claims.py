"""The AI's claims are checked against the deterministic entropy map (no VM, no network)."""
from nanalyst.ai import claims

EM = {"sections": [
    {"name": ".text", "rva": "0x1000", "vsize": 0x9000, "raw_size": 0x9000, "entropy": 6.272, "runtime_expanded": False},
    {"name": ".data", "rva": "0xd000", "vsize": 0x568, "raw_size": 0x600, "entropy": 3.1, "runtime_expanded": False},
    {"name": "CODE", "rva": "0x72000", "vsize": 0x186b8, "raw_size": 0x19000, "entropy": 7.86, "runtime_expanded": False},
    {"name": ".bss2", "rva": "0x90000", "vsize": 0x80000, "raw_size": 0x1000, "entropy": 1.0, "runtime_expanded": True}],
    "regions": [{"section": "CODE", "rva": "0x72000", "size": 0x12000, "entropy": 7.82, "kind": "high-entropy"}]}


def test_normal_compiled_code_is_not_called_encrypted():
    a = claims.check_encrypted_regions([{"where": ".text section", "likely": "encrypted"}], EM)
    assert a[0]["supported"] is False and "below" in a[0]["basis"]            # the real overclaim, caught


def test_high_entropy_section_claim_is_supported():
    assert claims.check_encrypted_regions([{"where": "CODE"}], EM)[0]["supported"] is True


def test_runtime_expanded_section_claim_is_supported():
    assert claims.check_encrypted_regions([{"where": ".bss2"}], EM)[0]["supported"] is True


def test_claim_about_a_nonexistent_section_is_unsupported():
    assert claims.check_encrypted_regions([{"where": ".nowhere"}], EM)[0]["supported"] is False


def test_unknown_and_version_numbers_are_not_leads():
    out = claims.check_leads(["unknown", "5.1.0.0", "none", "hxxp-less text"])
    assert [x["supported"] for x in out] == [False, False, False, False]


def test_real_urls_domains_and_ips_are_leads():
    out = claims.check_leads(["http://evil.example.ru/gate.php", "c2.bad-site.top", "185.220.101.5"])
    assert all(x["supported"] for x in out)


def test_known_version_strings_are_rejected():
    assert claims.check_leads(["6.3.9600.17415"], known_versions={"6.3.9600.17415"})[0]["supported"] is False


def test_plan_region_in_a_normal_section_is_flagged_but_one_in_packed_code_is_supported():
    r = claims.check_plan_regions([{"rva": 0xd000, "size": 0x568}, {"rva": 0x72000, "size": 0x1000},
                                   {"rva": 0x91000, "size": 0x1000}], EM)
    assert [x["supported"] for x in r] == [False, True, True]


def test_audit_counts_unsupported():
    a = claims.audit({"encrypted_regions": [{"where": ".text"}, {"where": "CODE"}], "url_leads": ["unknown"]}, EM)
    assert a["unsupported"] == 2


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("PASS", n)
