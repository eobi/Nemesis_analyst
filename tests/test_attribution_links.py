import json
from nanalyst import attribution as at


def test_link_cases_shares_and_strength(tmp_path):
    other = tmp_path / "aaa_dridex"; other.mkdir()
    (other / "case.json").write_text(json.dumps({"stages": {"author_fingerprints": {
        "payload.exe": {"imphash": "abc", "rich_hash": "r1", "timestamp": 100, "section_names": ".text,.zz"}}}}))
    me = {"x.exe": {"imphash": "abc", "rich_hash": "r1", "timestamp": 5, "section_names": ".text,.zz"}}
    links = at.link_cases(me, str(tmp_path), exclude="mine")
    assert links and links[0]["strength"] == "strong lead" and "imphash" in links[0]["shared"]
    assert at.link_cases(me, str(tmp_path), exclude="aaa_dridex") == []
    plain = {"x.exe": {"section_names": ".text,.data,.rsrc"}}
    (other / "case.json").write_text(json.dumps({"stages": {"author_fingerprints": {"y": {"section_names": ".text,.data,.rsrc"}}}}))
    assert at.link_cases(plain, str(tmp_path)) == []          # ordinary section names are not a clue


def test_masquerade_note():
    res = {"version_info": {"CompanyName": "INCA Internet Co."}}
    assert at.masquerade_note(res, {"signed": False}, True)
    assert at.masquerade_note(res, {"signed": True}, True) is None
