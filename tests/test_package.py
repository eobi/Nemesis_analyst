"""Detection package: noise filtering, rule generation, and validation by real parsers (no VM)."""
import json, tempfile, uuid
from pathlib import Path
import yaml, yara, stix2
from nanalyst import package as P


def test_known_good_and_noise_indicators_are_filtered():
    assert not P.filter_domain("update.microsoft.com")[0]
    assert not P.filter_domain("crl.digicert.com")[0]
    assert not P.filter_domain("kernel32.dll")[0]
    assert P.filter_domain("gate.evil-update.top")[0]
    assert not P.filter_ip("192.168.1.10")[0] and not P.filter_ip("127.0.0.1")[0] and not P.filter_ip("10.0.0.5")[0]
    assert not P.filter_ip("5.1.0.0")[0]                    # a version number, not an address
    assert P.filter_ip("185.220.101.5")[0]
    assert not P.filter_url("http://schemas.microsoft.com/x")[0] and P.filter_url("http://185.220.101.5/gate.php")[0]


def test_tier_comes_from_the_best_source():
    assert P._tier(["deep static (packed)", "live detonation (network)"]) == "observed"
    assert P._tier(["deep static (packed)"]) == "static"
    assert P._tier(["API-trace region dump"]) == "unpacked"


def make_pkg(indicators, family="Testfam", cats=("ransomware",)):
    return {"schema": "x", "producer": P.PRODUCER, "tlp": "AMBER", "generated": "2026-10-21T00:00:00Z",
            "sample": {"name": "s.exe", "sha256": "ab" * 32, "size": 1}, "family": family, "categories": list(cats),
            "indicators": indicators, "excluded": [], "availability": P.availability(indicators)}


def ind(t, v, tier, usage="block"):
    return {"type": t, "value": v, "usage": usage, "tier": tier, "confidence": P.TIER_SCORE[tier], "sources": ["t"], "context": ""}


def test_suricata_rules_only_from_high_confidence_and_are_escaped_and_unique():
    pkg = make_pkg([ind("domain", "gate.evil-update.top", "observed"), ind("ipv4", "185.220.101.5", "decrypted"),
                    ind("url", "http://a.evil.top/gate.php?id=1;x", "unpacked"),
                    ind("domain", "weak.example.top", "static")])               # static: must NOT become a rule
    text, n = P.suricata_rules(pkg)
    assert n == 3 and "weak.example" not in text
    assert 'dns.query; content:"gate.evil-update.top"' in text and "alert ip $HOME_NET any -> 185.220.101.5" in text
    assert "|3B|" in text and ';x' not in text.split("http.uri")[1].split(";")[0]    # ';' in the URL is hex-escaped
    sids = [l.split("sid:")[1].split(";")[0] for l in text.splitlines()]
    assert len(set(sids)) == len(sids)


def test_stix_bundle_is_valid_and_only_has_blockable_high_confidence_indicators():
    pkg = make_pkg([ind("file:sha256", "ab" * 32, "observed"), ind("domain", "gate.evil-update.top", "observed"),
                    ind("domain", "weak.example.top", "static"), ind("registry-key", "HKCU\\x", "static", "hunt")])
    b = stix2.parse(P.stix_bundle(pkg), allow_custom=False, version="2.1")
    kinds = [o["type"] for o in b.objects]
    assert kinds.count("indicator") == 2 and "malware" in kinds and kinds.count("relationship") == 2
    assert "weak.example" not in P.stix_bundle(pkg)


def test_sigma_rules_parse_and_only_exist_with_evidence():
    assert P.sigma_rules(make_pkg([]), {}) == []
    pkg = make_pkg([ind("ransom-note", r"C:\nemesis\_RECOVERY_+abc.txt", "observed", "hunt"),
                    ind("registry-run-value", r"HKCU:\...\Run|upd=C:\x.exe", "observed", "hunt"),
                    ind("command-line", "vssadmin delete shadows /all /quiet", "unpacked", "hunt")])
    rules = P.sigma_rules(pkg, {})
    assert len(rules) == 3
    for fn, text in rules:
        d = yaml.safe_load(text)
        assert {"title", "id", "logsource", "detection", "level"} <= set(d) and d["detection"]["condition"] == "selection"
        uuid.UUID(d["id"])


def test_yara_rule_compiles_matches_its_stage_and_not_unrelated_data():
    payload = b"MZ" + b"\x00" * 58 + b"".join(s.encode() + b"\x00" for s in (
        r"C:\Users\Public\svcupd\cfg_9f31.dat", "Global\\MtxA7c1e44b-77aa", "POST /gate.php?bot=%s&v=3",
        "Mozilla/5.0 (compatible; UpdChk/2.7)", "HKCU\\Software\\Cls\\Zq9k\\Settings", "cmd /c ping -n 3 127.0.0.1 > nul")) + b"\x90" * 400
    text, note = P.yara_rule("t_rule", payload, "Testfam", "ab" * 32, "unpacked")
    assert text, note
    rules = yara.compile(source=text)
    assert rules.match(data=payload)
    assert not rules.match(data=b"MZ" + b"\x00" * 3000)
    assert not rules.match(data=b"hello world " * 400)


def test_yara_rule_is_withheld_when_the_stage_has_no_distinctive_strings():
    text, note = P.yara_rule("t", b"MZ" + b"\x00" * 2000 + b"kernel32.dll\x00GetProcAddress\x00", "x", "ab" * 32, "packed")
    assert text is None and "withheld" in note


def test_availability_states_why_network_iocs_are_missing():
    av = P.availability([ind("file:sha256", "ab" * 32, "observed"), ind("domain", "x.evil.top", "static")])
    assert av["network (C2 / download)"]["high_confidence"] == 0 and "encrypted at rest" in av["network (C2 / download)"]["note"]


def test_write_package_end_to_end_on_a_synthetic_case():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td); (td / "dumps").mkdir()
        payload = b"MZ" + b"\x00" * 58 + b"".join(s.encode() + b"\x00" for s in (
            r"C:\Users\Public\svcupd\cfg_9f31.dat", "Global\\MtxA7c1e44b-77aa", "POST /gate.php?bot=%s&v=3",
            "Mozilla/5.0 (compatible; UpdChk/2.7)", "HKCU\\Software\\Cls\\Zq9k\\Settings")) + b"\x90" * 400
        (td / "dumps" / "api_ntwx_0x10001000_PE.bin").write_bytes(payload)
        case = {"name": "s.exe", "sample": "/nonexistent", "stages": {
            "triage": {"hashes": {"sha256": "cd" * 32, "md5": "11" * 16, "sha1": "22" * 20, "size": 10}},
            "dumps_manifest": {"dumps": [{"name": "api_ntwx_0x10001000_PE.bin", "path": "dumps/api_ntwx_0x10001000_PE.bin",
                                          "role": "W->X region = DECRYPTED PAYLOAD (made executable)", "md5": "a", "sha256": "b",
                                          "size": len(payload), "pe": True, "same_as_packed": False}]},
            "deep_static_unpacked": {"domains": ["gate.evil-update.top", "update.microsoft.com"], "ips": ["185.220.101.5", "192.168.0.1"],
                                     "urls": [], "registry": [], "mutex_hints": ["Global\\MtxA7c1e44b-77aa"], "file_paths": [],
                                     "commands": [], "user_agents": [], "wallets": [], "pdb_paths": []},
            "classification": {"primary": "ransomware", "families": [{"family": "ransomware"}]}}}
        s = P.write_package(case, td)
        assert not s["errors"], s["errors"]
        iocs = json.loads((td / "intel" / "iocs.json").read_text())
        vals = {i["value"] for i in iocs["indicators"]}
        assert "gate.evil-update.top" in vals and "185.220.101.5" in vals
        assert "update.microsoft.com" not in vals and "192.168.0.1" not in vals
        assert {e["value"] for e in iocs["excluded"]} >= {"update.microsoft.com", "192.168.0.1"}
        assert (td / "intel" / "iocs.csv").exists() and (td / "intel" / "hashes.txt").exists() and (td / "intel" / "README.md").exists()
        assert any((td / "intel" / "yara").glob("*.yar"))


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("PASS", n)


def test_behavior_sentinel_strings_become_observed_indicators(tmp_path):
    case = {"name": "x", "sha256": "0" * 64, "stages": {"api_trace": {"trace": [
        {"api": "wininet.InternetConnectA", "cat": "beh-network", "behavior": "network", "capture": {"note": '"c2.evil-example.xyz"'}},
        {"api": "kernel32.CreateMutexW", "cat": "beh-process", "behavior": "process", "capture": {"note": '"Global\\XyzMutex9"'}},
        {"api": "advapi32.RegSetValueExW", "cat": "beh-persist", "behavior": "persist", "capture": {"note": '"Updater"'}},
        {"api": "kernel32.CreateProcessW", "cat": "spawn", "capture": {"note": '"cmd.exe /c vssadmin delete shadows"'}},
    ]}}}
    pk = P.collect(case, tmp_path)
    got = {(i["type"], i["value"]): i for i in pk["indicators"]}
    assert got[("domain", "c2.evil-example.xyz")]["tier"] == "observed"
    assert ("mutex", "Global\\XyzMutex9") in got and ("registry-key", "Updater") in got
    assert got[("command-line", "cmd.exe /c vssadmin delete shadows")]["tier"] == "observed"
