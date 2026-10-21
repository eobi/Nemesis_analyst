"""Entropy-region merging and the AI-plan validator guardrail (no VM, no network)."""
from nanalyst import entropy_map
from nanalyst.ai import dynamic_plan as dp


def test_merge_blocks_joins_runs_and_skips_singletons():
    ents = [3.0, 7.9, 7.8, 7.5, 2.0, 7.9, 1.0]           # one 3-block run, one lone high block
    r = entropy_map.merge_blocks(ents, base_off=0x1000, block=4096)
    assert len(r) == 1 and r[0]["file_off"] == 0x1000 + 4096 and r[0]["size"] == 3 * 4096 and r[0]["blocks"] == 3


def test_validate_rejects_apis_outside_the_arsenal():
    plan = {"priority_apis": [{"api": "kernel32.VirtualProtect", "why": "w"}, {"api": "CreateFileW", "why": "x"},
                              {"api": "ntdll.NtProtectVirtualMemory", "why": "n"}, {"api": "virtualprotect", "why": "dup"}]}
    v = dp.validate(plan, 0x50000)
    names = [p["api"] for p in v["accepted"]["priority_apis"]]
    assert names == ["VirtualProtect", "NtProtectVirtualMemory"]          # canonical, deduped
    assert any("CreateFileW" in r["item"] and "arsenal" in r["reason"] for r in v["rejected"])


def test_validate_watch_regions_inside_image_clamped_and_capped():
    plan = {"watch_regions": [{"rva": "0x1000", "size": "0x20"}, {"rva": "0x60000", "size": "0x1000"},
                              {"rva": "zzz", "size": "1"}, {"rva": "0x4f000", "size": "0x900000"}]
            + [{"rva": hex(0x2000 + i * 0x100), "size": "0x400"} for i in range(20)]}
    v = dp.validate(plan, 0x50000)
    w = v["accepted"]["watch_regions"]
    assert len(w) <= dp.MAX_WATCH
    assert all(0 <= x["rva"] < 0x50000 and dp.MIN_SIZE <= x["size"] <= dp.MAX_SIZE for x in w)
    assert w[0]["size"] == dp.MIN_SIZE                                    # 0x20 raised to the floor
    assert any("outside the image" in r["reason"] for r in v["rejected"])
    assert any("not parseable" in r["reason"] for r in v["rejected"])
    big = [x for x in w if x["rva"] == 0x4f000][0]
    assert big["rva"] + big["size"] <= 0x50000                            # clamped to the image end


def test_anti_evasion_is_advisory_only():
    v = dp.validate({"anti_evasion": [{"technique": "rdtsc timing", "action": "patch it"}]}, 0x1000)
    assert v["accepted"]["anti_evasion"][0]["status"].startswith("advisory")


def test_garbage_plan_is_harmless():
    v = dp.validate({"priority_apis": "nope", "watch_regions": None}, None)
    assert v["accepted"]["priority_apis"] == [] and v["accepted"]["watch_regions"] == []


class FakeBrain:
    available = True
    def __init__(self, out): self.out, self.purposes = out, []
    def decide(self, system, user, max_tokens=0, purpose="", **k):
        self.purposes.append(purpose); self.last_user = user; return self.out


def test_propose_makes_one_logged_call_with_the_allowed_list():
    b = FakeBrain({"hypothesis": "h"})
    out = dp.propose(b, {"stages": {"triage": {"filetype": "PE32"}}})
    assert out == {"hypothesis": "h"} and b.purposes == ["dynamic-plan"] and "ALLOWED priority_apis" in b.last_user


def test_propose_without_brain_returns_empty():
    assert dp.propose(None, {}) == {}


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("PASS", n)
