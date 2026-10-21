"""Verdict/classification must not call ordinary runtime behaviour malicious (no VM, no network)."""
from nanalyst import classify, proof, residue
from nanalyst.intelligent_unpack import Engine

BENIGN_CLR_TRACE = [
    {"api": "ntdll.NtCreateThreadEx", "cat": "thread-remote", "args": {"pThread": "0x73f850", "access": "0x1fffff", "objAttr": "0x0", "hProc": "0xffffffff"}},
    {"api": "kernel32.VirtualAlloc", "cat": "alloc", "args": {}, "capture": {"note": "returned base 0x2540000"}},
    {"api": "kernel32.VirtualProtect", "cat": "protect", "args": {}, "capture": {"note": "protect 0x4 (not exec)"}},
] + [{"api": "kernel32.GetProcAddress", "cat": "resolve", "args": {}, "capture": {"note": f'"{n}"'}}
     for n in ("FlsGetValue", "DecodePointer", "EncodePointer", "SetSystemFileCacheSize", "NtSetSystemInformation") * 3]


def case_with(trace, counts=None):
    counts = counts or {}
    for ev in trace:
        counts[ev["api"]] = counts.get(ev["api"], 0) + 1
    return {"stages": {"triage": {"pe": {"suspicious_apis": {}}, "packing": {}}, "static_ghidra": {},
                       "api_trace": {"trace": trace, "counts": counts}}}


def test_a_thread_started_in_the_current_process_is_not_injection():
    assert classify._targets_self({"hProc": "0xffffffff"}) is True
    assert classify._targets_self({"hProcess": "0xffffffffffffffff"}) is True
    assert classify._targets_self({"hProc": "0x1c4"}) is False           # a real other-process handle
    assert classify._targets_self({}) is False                           # unknown -> category decides


def test_benign_runtime_trace_is_not_scored_as_malicious():
    v = proof._verdict({"pe": {"suspicious_apis": {}}, "packing": {}}, {}, case_with(BENIGN_CLR_TRACE)["stages"])
    assert v["confidence"] == 0 and v["label"] == "INCONCLUSIVE", v


def test_an_actual_write_then_execute_flip_is_scored():
    tr = BENIGN_CLR_TRACE + [{"api": "kernel32.VirtualProtect", "cat": "protect", "args": {},
                              "capture": {"note": "W->X region 0x10001000+0x20d11"}}]
    v = proof._verdict({"pe": {"suspicious_apis": {}}, "packing": {}}, {}, case_with(tr)["stages"])
    assert v["dynamic_score"] >= 10 and any("W->X" in e for e in v["dynamic_evidence"])


def test_resolving_security_relevant_apis_by_name_is_scored_but_bulk_lookups_are_not():
    sus = [{"api": "kernel32.GetProcAddress", "cat": "resolve", "args": {}, "capture": {"note": f'"{n}"'}}
           for n in ("VirtualProtect", "WriteProcessMemory", "CreateRemoteThread")]
    v = proof._verdict({"pe": {"suspicious_apis": {}}, "packing": {}}, {}, case_with(sus)["stages"])
    assert any("security-relevant" in e for e in v["dynamic_evidence"])
    v2 = proof._verdict({"pe": {"suspicious_apis": {}}, "packing": {}}, {}, case_with(BENIGN_CLR_TRACE)["stages"])
    assert not any("security-relevant" in e for e in v2["dynamic_evidence"])


def test_a_process_we_killed_that_lingers_as_a_ghost_is_not_residue():
    before = {"procs": [{"pid": 100, "ppid": 4, "name": "sshd.exe", "path": r"C:\Windows\System32\OpenSSH\sshd.exe"}],
              "run": [], "tasks": [], "services": [], "files": []}
    after = {"procs": before["procs"] + [{"pid": 5852, "ppid": 300, "name": "canary_9c5cde.exe", "path": r"C:\nemesis\canary_9c5cde.exe"}],
             "run": [], "tasks": [], "services": [], "files": []}
    assert not residue.diff(before, after)["reusable"]                    # unknown process: suspicious
    assert residue.diff(before, after, exclude_pids={5852})["reusable"]   # one WE killed: ghost entry, ignored


def test_getprocaddress_by_ordinal_is_reported_as_an_ordinal():
    class C:
        def tool(self, name, args=None): return {"content": [{"text": "{}"}]}
    e = Engine(C(), log=lambda m: None)
    rec = e._capture({"capture": "str:lpProc"}, {"lpProc": 0x18}, "x86", "C:\\x")
    assert "ordinal 24" in rec["note"]


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("PASS", n)
