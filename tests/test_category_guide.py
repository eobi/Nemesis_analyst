from nanalyst import category_guide as cg


def _case(trace=None, apis=None, strings=None):
    st = {"api_trace": {"trace": trace or []},
          "triage": {"pe": {"suspicious_apis": {"x": apis or []}}},
          "static_ghidra": {"strings": {"suspicious": strings or []}}}
    return {"stages": st}


def test_api_match_is_not_loose():
    assert cg._api_match("send", "send")
    assert cg._api_match("CreateProcess", "CreateProcessW")
    assert not cg._api_match("send", "SendMessageW")
    assert not cg._api_match("CreateFile", "CreateFileMappingW")


def test_ransomware_checklist_statuses():
    ev = [{"api": "advapi32.CryptEncrypt", "n": 3, "cat": "beh-crypto-file", "behavior": "crypto-file"},
          {"api": "kernel32.FindFirstFileW", "n": 3, "cat": "beh-file", "behavior": "file"}]
    case = _case(ev, apis=["CryptGenKey", "MoveFileExW"], strings=["vssadmin delete shadows", "your files are encrypted", "bitcoin"])
    res = cg.categorize(case)
    assert res["primary"] == "ransomware"
    by = {i["item"]: i for i in res["categories"][0]["checklist"]}
    assert by["encrypt data"]["status"] == "observed live" and ">= 3" in by["encrypt data"]["detail"]
    assert by["generate / derive / import a key"]["status"] == "present in code"
    assert by["delete shadow copies / backups"]["status"] == "present in code"
    assert cg.to_markdown(res)


def test_nothing_supported_says_so():
    res = cg.categorize(_case())
    assert res["categories"] == [] and "no category" in res["primary"]
    assert "No category is supported" in "\n".join(cg.to_markdown(res))


def test_short_keyword_needs_word_boundary():
    assert not cg._kw_match("rsa", "universal serial")
    assert cg._kw_match("rsa", "uses rsa key")
