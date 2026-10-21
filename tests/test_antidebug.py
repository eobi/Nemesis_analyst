"""Anti-debug neutralization + run-to-return anchoring, against a fake debugger (no VM)."""
import json
from nanalyst.intelligent_unpack import Engine, _norm


class FakeClient:
    """Models just enough: paused at a function entry; `rtr` resumes, then re-pauses at the return."""
    def __init__(self, stack, regs=None, entry="0x771d2bf0", ret="0x76834ec7"):
        self.stack, self.regs, self.entry, self.ret = stack, regs or {}, entry, ret
        self.stack.setdefault("esp", int(ret, 16))              # [esp] at a function entry = return address
        self.cmds, self.writes, self.regsets = [], [], []
        self.eip, self.state, self.polls_left = entry, "paused", 0

    def _ok(self, obj):
        return {"content": [{"text": json.dumps(obj)}]}

    def tool(self, name, args=None):
        args = args or {}
        if name == "debug_get_state":
            if self.state == "running":
                self.polls_left -= 1
                if self.polls_left <= 0:
                    self.state, self.eip = "paused", self.ret
            return self._ok({"eip": self.eip, "state": self.state})
        if name == "script_execute":
            self.cmds.append(args["command"])
            if args["command"] == "run":
                self.state, self.polls_left = "running", 2     # resume; re-pause at the return after 2 polls
            return self._ok({"success": True})
        if name == "eval_expression":
            m = args["expression"].strip("[]").replace("esp+", "")
            return self._ok({"valid": True, "result": hex(self.stack[m])} if m in self.stack else {"valid": False})
        if name == "register_get_batch":
            return self._ok({"registers": [{"name": n, "value": hex(self.regs.get(n, 0)), "success": True}
                                           for n in args["names"]]})
        if name == "memory_write":
            self.writes.append((args["address"], args["data"])); return self._ok({"success": True})
        if name == "register_set":
            self.regsets.append((args["name"], args["value"])); return self._ok({"success": True})
        return self._ok({})


def eng(stack=None, regs=None):
    c = FakeClient(stack or {}, regs)
    return Engine(c, log=lambda m: None), c


def test_debug_port_query_is_reported_as_no_debugger():
    e, c = eng({"0x8": 7, "0xc": 0x19FE14})
    out = e._neutralize_hit("ntdll.NtQueryInformationProcess", "x86")
    assert c.cmds.count("run") == 1 and c.writes == [("0x19fe14", "00000000")] and not c.regsets
    assert "no debugger" in out


def test_debug_object_handle_gets_port_not_set_status():
    e, c = eng({"0x8": 0x1E, "0xc": 0x19FE14})
    e._neutralize_hit("ntdll.NtQueryInformationProcess", "x86")
    assert c.writes == [("0x19fe14", "00000000")] and c.regsets == [("eax", "0xC0000353")]


def test_debug_flags_set_to_one():
    e, c = eng({"0x8": 0x1F, "0xc": 0x19FE14})
    e._neutralize_hit("ntdll.NtQueryInformationProcess", "x86")
    assert c.writes == [("0x19fe14", "01000000")]


def test_non_debug_class_is_left_alone():
    e, c = eng({"0x8": 0, "0xc": 0x19FE14})                 # ProcessBasicInformation
    e._neutralize_hit("ntdll.NtQueryInformationProcess", "x86")
    assert "run" not in c.cmds and not c.writes and not c.regsets


def test_x64_debug_port_writes_eight_bytes():
    e, c = eng(regs={"rdx": 7, "r8": 0x7FFE0000})
    e._neutralize_hit("ntdll.NtQueryInformationProcess", "x64")
    assert c.writes == [("0x7ffe0000", "00" * 8)]


def test_check_remote_debugger_present_clears_the_bool():
    e, c = eng({"0x8": 0x19FDB0})
    e._neutralize_hit("kernel32.CheckRemoteDebuggerPresent", "x86")
    assert c.cmds.count("run") == 1 and c.writes == [("0x19fdb0", "00000000")]


def test_is_debugger_present_returns_zero():
    e, c = eng()
    e._neutralize_hit("kernel32.IsDebuggerPresent", "x86")
    assert c.regsets == [("eax", "0x0")]


def test_run_to_return_uses_a_one_shot_breakpoint_on_the_return_address():
    e, c = eng()
    status, at = e._run_to_return()
    assert status == "PAUSED" and at == c.ret.lower()
    assert c.cmds == [f"bp {c.ret}", "run", f"bc {c.ret}"]       # set, resume, delete — never `rtr`


def test_run_to_return_reports_when_something_else_stops_it_first():
    e, c = eng()
    c.ret_for_stop = None
    c.ret = "0x76834ec7"; orig = c.tool
    def tool(name, args=None):
        r = orig(name, args)
        if name == "debug_get_state" and c.state == "paused" and c.eip == c.ret:
            c.eip = "0x77777777"                                 # we stopped somewhere other than the return
            return c._ok({"eip": c.eip, "state": c.state})
        return r
    c.tool = tool
    status, at = e._run_to_return()
    assert status == "STOPPED_ELSEWHERE"


def test_norm_makes_addresses_comparable():
    assert _norm("0x771D2BF0") == _norm("771d2bf0") == _norm(0x771D2BF0) == "0x771d2bf0"


# ---- run_to_entry: never resume when already paused at the entry ----
class EntryClient:
    def __init__(self, eip, state="paused", entry="0x001CB900"):
        self.eip, self.state, self.entry, self.cmds, self.left = eip, state, entry, [], 0

    def _ok(self, o): return {"content": [{"text": json.dumps(o)}]}

    def tool(self, name, args=None):
        args = args or {}
        if name == "module_get_main":
            return self._ok({"name": "whoami.exe", "base": "0x001C0000", "entry": self.entry})
        if name == "debug_get_state":
            if self.state == "running":
                self.left -= 1
                if self.left <= 0: self.state, self.eip = "paused", self.entry.lower()
            return self._ok({"eip": self.eip, "state": self.state})
        if name == "register_get_batch":                   # numeric value, NOT zero-padded like the state call
            v = hex(int(self.eip, 16))
            return self._ok({"registers": [{"name": n, "value": v, "success": True} for n in args["names"]]})
        if name == "script_execute":
            self.cmds.append(args["command"])
            if args["command"] in ("run", "erun"): self.state, self.left = "running", 2
            return self._ok({"success": True})
        return self._ok({})


def test_already_at_entry_is_not_resumed_even_with_zero_padded_address():
    c = EntryClient(eip="0x001cb900")                      # the debugger zero-pads; entry is "0x001CB900"
    reached, entry, _ = Engine(c, log=lambda m: None).run_to_entry()
    assert reached and not [x for x in c.cmds if x in ("run", "erun")], c.cmds


def test_confirm_paused_compares_numbers_not_text():
    c = EntryClient(eip="0x001cb900")
    assert Engine(c, log=lambda m: None)._confirm_paused("0x001cb900")      # reg gives 0x1cb900


def test_not_at_entry_is_never_resumed_to_chase_it():
    c = EntryClient(eip="0x771d2bf0")                      # paused somewhere else (e.g. inside the CLR / ntdll)
    reached, entry, _ = Engine(c, log=lambda m: None).run_to_entry()
    assert reached is False and entry and not [x for x in c.cmds if x in ("run", "erun")], c.cmds


def test_missing_entry_returns_not_reached_without_resuming():
    class NoEntry(EntryClient):
        def tool(self, name, args=None):
            if name == "module_get_main": return self._ok({})
            return super().tool(name, args)
    c = NoEntry(eip="0x771d2bf0")
    import nanalyst.intelligent_unpack as iu
    reached, entry, _ = Engine(c, log=lambda m: None).run_to_entry()
    assert reached is False and entry is None and not [x for x in c.cmds if x in ("run", "erun")]


def test_api_trace_refuses_to_resume_when_nothing_could_be_armed():
    c = EntryClient(eip="0x001cb900")                      # paused at entry; exports cannot be resolved
    e = Engine(c, log=lambda m: None)
    e.build_export_map = lambda *a, **k: setattr(e, "_exports", {}) or {}
    e.api_addrs = lambda sym: []
    out = e.api_trace("C:\\nemesis\\api", arch="x86", restart=False)
    assert out.get("aborted") and not [x for x in c.cmds if x in ("run", "erun")], c.cmds


# ---- one hook per API, and return values only read at the real return ----
def _eng_with_exports(exports, mods):
    e = Engine(EntryClient(eip="0x1"), log=lambda m: None)
    e._exports, e._export_mod = exports, mods
    return e


def test_kernel32_api_is_armed_once_at_the_kernelbase_body():
    k32, kb = "0x76840000", "0x76ab0000"
    e = _eng_with_exports({"VirtualAlloc": [k32, kb]}, {("VirtualAlloc", k32): "kernel32.dll", ("VirtualAlloc", kb): "kernelbase.dll"})
    assert e.api_addrs("kernel32.VirtualAlloc") == [kb]


def test_ntdll_api_keeps_its_single_ntdll_address():
    e = _eng_with_exports({"NtProtectVirtualMemory": ["0x771d1000"]}, {("NtProtectVirtualMemory", "0x771d1000"): "ntdll.dll"})
    assert e.api_addrs("ntdll.NtProtectVirtualMemory") == ["0x771d1000"]


def test_ntdll_api_also_exported_by_kernel32_prefers_ntdll():
    nt, k32 = "0x771d2000", "0x76840100"
    e = _eng_with_exports({"RtlDecompressBuffer": [nt, k32]}, {("RtlDecompressBuffer", nt): "ntdll.dll", ("RtlDecompressBuffer", k32): "kernel32.dll"})
    assert e.api_addrs("ntdll.RtlDecompressBuffer") == [nt]


def test_kernel32_only_api_without_kernelbase_copy_is_still_armed():
    e = _eng_with_exports({"OnlyInK32": ["0x76841000"]}, {("OnlyInK32", "0x76841000"): "kernel32.dll"})
    assert e.api_addrs("kernel32.OnlyInK32") == ["0x76841000"]


class SteppedClient(FakeClient):
    """After each `run`, the debuggee pauses at the next address in `stops`."""
    def __init__(self, stops, **kw):
        super().__init__({}, **kw); self.stops = list(stops)

    def tool(self, name, args=None):
        args = args or {}
        if name == "script_execute" and args["command"] == "run":
            self.cmds.append("run"); self.eip, self.state = self.stops.pop(0), "paused"
            return self._ok({"success": True})
        if name == "debug_get_state":
            return self._ok({"eip": self.eip, "state": self.state})
        return super().tool(name, args)


def test_run_to_return_passes_through_a_second_armed_hit_of_the_same_call():
    # kernel32 stub -> kernelbase body: the call hits a second armed address before it returns
    c = SteppedClient(["0x76ab0000", "0x76834ec7"])
    e = Engine(c, log=lambda m: None); e._armed_addrs = {_norm("0x76ab0000")}
    status, at = e._run_to_return()
    assert status == "PAUSED" and _norm(at) == _norm("0x76834ec7") and c.cmds.count("run") == 2


def test_run_to_return_stopping_at_an_unarmed_address_is_reported_not_trusted():
    c = SteppedClient(["0x77777777"])
    e = Engine(c, log=lambda m: None); e._armed_addrs = set()
    status, _ = e._run_to_return()
    assert status == "STOPPED_ELSEWHERE"


def _capture_alloc(eax, status="PAUSED"):
    e = Engine(EntryClient(eip="0x1"), log=lambda m: None)
    e._run_to_return = lambda secs=8: (status, "0x1")
    e.reg = lambda *n: {"eax": eax}
    e._watch_regions = []
    return e, e._capture({"capture": "alloc_ret", "sym": "kernel32.VirtualAlloc"}, {}, "x86", "C:\\x")


def test_a_page_aligned_base_is_recorded():
    e, rec = _capture_alloc(0x7B1000)
    assert "returned base 0x7b1000" in rec["note"] and e._watch_regions == [0x7B1000]


def test_a_size_masquerading_as_a_base_is_rejected():
    e, rec = _capture_alloc(0x10068)                       # the dwSize that used to be logged as a "base"
    assert "not page-aligned" in rec["note"] and e._watch_regions == []


def test_no_return_value_is_read_when_the_return_was_not_reached():
    e, rec = _capture_alloc(0x7B1000, status="STOPPED_ELSEWHERE")
    assert "return not reached" in rec["note"] and e._watch_regions == []


def test_nt_query_information_process_breakpoint_is_conditional_on_the_debug_classes():
    cmds = []
    class C(FakeClient):
        def tool(self, name, args=None):
            args = args or {}
            if name == "script_execute": cmds.append(args["command"])
            if name == "eval_expression": return self._ok({"valid": True, "result": "0x771d2bf0"})
            return super().tool(name, args)
    e = Engine(C({}), log=lambda m: None)
    e.neutralize_antidebug("x86")
    cond = [c for c in cmds if c.startswith("bpcnd")]
    assert cond and "dword(esp+8)==7" in cond[0] and "==0x1e" in cond[0] and "==0x1f" in cond[0]
    cmds.clear(); e.neutralize_antidebug("x64")
    assert any(c.startswith("bpcnd") and "edx==7" in c for c in cmds)


class ChaseClient(EntryClient):
    """Paused in the loader. Each run/erun pauses at the next address in `stops`; 'STOP' = process ends."""
    def __init__(self, stops, **kw):
        super().__init__(**kw); self.stops = list(stops); self.pause_calls = 0

    def tool(self, name, args=None):
        args = args or {}
        if name == "debug_pause":
            self.pause_calls += 1; self.state = "paused"; return self._ok({"success": True})
        if name == "script_execute":
            self.cmds.append(args["command"])
            if args["command"] in ("run", "erun"):
                nxt = self.stops.pop(0) if self.stops else None
                if nxt == "STOP": self.state, self.eip = "stopped", ""
                elif nxt: self.state, self.eip = "paused", nxt
                else: self.state = "running"                       # never stops
            return self._ok({"success": True})
        if name == "debug_get_state":
            return self._ok({"eip": self.eip, "state": self.state})
        return super().tool(name, args)


def _chase(stops, tls=(), pre=True, secs=1.0):
    c = ChaseClient(stops, eip="0x771d5050")                       # EntryClient default entry is 0x001CB900, base 0x001C0000
    e = Engine(c, log=lambda m: None); e._pre_entry = pre; e._tls_rvas = list(tls)
    return e.run_to_entry(chase_secs=secs), c


def test_from_an_early_pause_it_runs_to_the_entry_under_its_own_breakpoints():
    (reached, entry, _), c = _chase(["0x001cb900"])
    assert reached and "run" in c.cmds and f"bp {entry}" in c.cmds and f"bc {entry}" in c.cmds
    assert any(x.startswith("bph") for x in c.cmds) and any(x.startswith("bphwc") for x in c.cmds)


def test_tls_callbacks_are_breakpointed_and_passed_on_the_way_to_the_entry():
    (reached, _, _), c = _chase(["0x1c2000", "0x001cb900"], tls=[0x2000])     # base 0x1c0000 + 0x2000
    assert reached and "bp 0x1c2000" in c.cmds and c.cmds.count("run") == 2


def test_an_exception_on_the_way_is_passed_with_erun_not_run():
    (reached, _, _), c = _chase(["0x77777777", "0x001cb900"])
    assert reached and "erun" in c.cmds


def test_if_the_entry_never_comes_it_takes_control_back_and_does_not_leave_it_running():
    (reached, _, _), c = _chase([], secs=0.5)
    assert reached is False and c.pause_calls >= 1


def test_if_the_process_ends_while_chasing_the_entry_it_is_reported_not_reached():
    (reached, _, _), c = _chase(["STOP"])
    assert reached is False


def test_without_the_early_pause_flag_it_never_resumes():
    (reached, _, _), c = _chase(["0x001cb900"], pre=False)
    assert reached is False and not [x for x in c.cmds if x in ("run", "erun")]


# ---- late arming: APIs whose DLL was not loaded when the arsenal was armed ----
from nanalyst.api_spec import API_SPEC


class ExportsClient(FakeClient):
    def __init__(self, exports):
        super().__init__({}); self.exports, self.bps = exports, []

    def tool(self, name, args=None):
        args = args or {}
        if name == "module_get_exports":
            return self._ok({"exports": [{"name": n, "va": v} for n, v in self.exports.get(args["module"].lower(), {}).items()]})
        if name == "script_execute" and args["command"].startswith("bp "):
            self.bps.append(args["command"][3:])
        return super().tool(name, args)


def _spec(name):
    return next(x for x in API_SPEC if x["sym"].endswith("." + name))


def test_pending_dlls_for_advapi32_include_cryptsp():
    assert Engine._pending_dlls(_spec("CryptDecrypt")) == {"advapi32", "cryptsp"}
    assert Engine._pending_dlls(_spec("VirtualAlloc")) == {"kernel32"}


def test_late_arming_arms_only_what_the_loaded_dll_provides_and_leaves_the_rest_pending():
    c = ExportsClient({"advapi32.dll": {"CryptDecrypt": "0x76f00010", "CryptHashData": "0x76f00020", "RegOpenKeyExA": "0x76f00030"}})
    e = Engine(c, log=lambda m: None)
    pending = [_spec("CryptDecrypt"), _spec("CryptHashData"), _spec("CryptImportKey")]
    a2s, s2a, known = {}, {}, set()
    armed = e._arm_pending("advapi32", pending, a2s, s2a, known)
    assert sorted(armed) == ["CryptDecrypt", "CryptHashData"]
    assert [p["sym"].split(".")[-1] for p in pending] == ["CryptImportKey"]            # not provided -> still pending
    assert sorted(c.bps) == ["0x76f00010", "0x76f00020"] and _norm("0x76f00010") in known and e._armed_addrs is known
    assert a2s["0x76f00010"]["sym"].endswith("CryptDecrypt") and s2a["advapi32.CryptHashData"] == ["0x76f00020"]


def test_late_arming_ignores_a_dll_that_is_not_one_the_pending_apis_belong_to():
    c = ExportsClient({"wininet.dll": {"CryptDecrypt": "0x70000010"}})                # a lookalike export in the wrong DLL
    e = Engine(c, log=lambda m: None)
    pending = [_spec("CryptDecrypt")]
    assert e._arm_pending("wininet", pending, {}, {}, set()) == [] and len(pending) == 1 and not c.bps


def test_cryptsp_provides_the_crypto_exports_on_newer_windows():
    c = ExportsClient({"cryptsp.dll": {"CryptDecrypt": "0x74100010"}})
    e = Engine(c, log=lambda m: None)
    pending = [_spec("CryptDecrypt")]
    assert e._arm_pending("cryptsp", pending, {}, {}, set()) == ["CryptDecrypt"] and not pending


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("PASS", n)
