"""Containment rules for nanalyst.safe_load, exercised against a fake debugger (no VM)."""
from nanalyst import safe_load as sl

ENTRY = "0x00403C40"


class FakeEng:
    """states: sequence of debugger states per poll; 'paused' reports eip == entry (zero-padded,
    like the real plugin). `module` is what module_get_main returns once paused."""
    def __init__(self, states, module=None, paused_eip="0x00403c40", pause_eip="0x771d5050"):
        self.states, self.module, self.paused_eip, self.pause_eip = list(states), module, paused_eip, pause_eip
        self.calls, self._i = [], 0

    def call(self, name, args=None):
        self.calls.append(name)
        if name == "debug_init":
            return {"success": True}
        if name == "debug_pause":                      # our early pause: stop wherever the loader is
            self.states, self._i, self.paused_eip = ["paused"], 0, self.pause_eip
            return {"success": True}
        if name == "debug_get_state":
            s = self.states[min(self._i, len(self.states) - 1)]; self._i += 1
            if not s:
                return {}
            return {"state": s, "eip": self.paused_eip if s == "paused" else "0x771d5050"}
        if name == "module_get_main":
            return self.module or {}
        return {"success": True}


class FakeGuest:
    def __init__(self): self.cmds = []
    def run(self, cmd, timeout=0): self.cmds.append(cmd); return 0, "", ""


GOOD = {"name": "demo1_ransomware_ab12cd.exe", "entry": ENTRY}
nosleep = lambda s: None


def run(states, module=None, paused_eip="0x00403c40", pause_eip="0x771d5050", **kw):
    e, g = FakeEng(states, module, paused_eip, pause_eip), FakeGuest()
    out = sl.safe_load(e, g, r"C:\nemesis\demo1_ransomware_ab12cd.exe", "demo1_ra",
                       log=lambda m: None, sleep=nosleep, **kw)
    return out, e, g


def test_clean_load_is_controlled_and_not_killed():
    (ok, mg, _, why), e, g = run(["paused"], GOOD)
    assert ok and not why and not g.cmds and "debug_stop" not in e.calls


def test_passive_mode_waits_out_the_loader_and_never_pokes_it():
    (ok, *_), e, g = run(["stopped", "running", "running", "running", "paused"], GOOD, early_pause=False)
    assert ok and "debug_pause" not in e.calls and not g.cmds


def test_default_mode_pauses_once_early_in_the_loader_and_reports_it():
    # dridex's own entry stop never came; the first stop was inside its code. So we stop it ourselves, early.
    (ok, mg, _, _), e, g = run(["stopped", "running", "running", "running", "running"], GOOD)
    assert ok and e.calls.count("debug_pause") == 1 and mg["early_pause"] is True and mg["at_entry"] is False
    assert not g.cmds                                              # control was taken, nothing was killed


def test_no_early_pause_when_the_debugger_already_stopped_at_the_entry():
    (ok, mg, _, _), e, g = run(["running", "paused"], GOOD)        # entry stop arrived before our pause point
    assert ok and "debug_pause" not in e.calls and mg["at_entry"] is True and mg["early_pause"] is False


def test_zero_padded_and_unpadded_entry_addresses_match():
    (ok, *_), e, g = run(["paused"], {"name": "demo1_ra.exe", "entry": "0x403C40"}, paused_eip="0x00403c40")
    assert ok


def test_paused_away_from_the_entry_is_controlled_but_flagged_not_at_entry():
    # measured live: a .NET program's first stop is inside the CLR, after its entry stub ran
    (ok, mg, _, why), e, g = run(["paused"], GOOD, paused_eip="0x76acd6c2")
    assert ok and mg["at_entry"] is False and mg["eip"] == "0x76acd6c2" and not g.cmds


def test_paused_at_the_entry_is_flagged_at_entry():
    (ok, mg, _, _), e, g = run(["paused"], GOOD)
    assert ok and mg["at_entry"] is True


def test_process_exiting_before_entry_is_contained_and_reported():
    # it ends within the first poll, before our early-pause point
    (ok, _, _, why), e, g = run(["running", "stopped", "stopped", "stopped"], None)
    assert not ok and "exited before reaching its entry" in why and g.cmds


def test_a_single_stopped_flicker_during_loading_is_tolerated():
    (ok, *_), e, g = run(["running", "stopped", "running", "running", "paused"], GOOD)
    assert ok and not g.cmds and "debug_stop" not in e.calls


def test_silent_debugger_triggers_containment():
    (ok, _, _, why), e, g = run(["running", "", "", "", ""], None)
    assert not ok and "loss of control" in why
    assert "debug_stop" in e.calls and any("taskkill /f /t /im demo1_ransomware_ab12cd.exe" in c for c in g.cmds)


def test_endless_running_is_contained_after_the_budget():
    (ok, _, _, why), e, g = run(["running"], None, polls=10)
    assert not ok and "never reached" in why and "debug_stop" in e.calls and g.cmds


def test_module_never_registering_while_paused_is_contained():
    (ok, _, _, why), e, g = run(["paused"], {}, polls=5)
    assert not ok and "never reached" in why and g.cmds


def test_failure_reason_carries_the_state_sequence_for_diagnosis():
    (ok, _, _, why), e, g = run(["stopped", "running", "running", "stopped", "stopped", "stopped"], None, early_pause=False)
    assert not ok and "stopped x1 -> running x2 -> stopped x3" in why


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("PASS", n)
