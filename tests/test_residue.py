"""Residue diff/verdict logic against hand-made before/after inventories (no VM)."""
from nanalyst import residue


def snap(procs=(), run=(), tasks=(), svcs=(), files=()):
    return {"procs": [{"pid": p, "ppid": 4, "name": n, "path": f"C:\\Windows\\System32\\{n}"} for p, n in procs],
            "run": list(run), "tasks": list(tasks), "services": list(svcs), "files": list(files)}


BASE = snap(procs=[(100, "sshd.exe"), (200, "x32dbg.exe")],
            files=[r"C:\Users\lab\Documents\a.docx|100", r"C:\Users\lab\Documents\b.docx|200"])


def test_identical_is_reusable():
    d = residue.diff(BASE, snap(procs=[(100, "sshd.exe"), (200, "x32dbg.exe")], files=BASE["files"]))
    assert d["reusable"] and "NO RESIDUE" in d["verdict"]


def test_new_run_key_is_persistence():
    after = snap(procs=[(100, "sshd.exe"), (200, "x32dbg.exe")], files=BASE["files"],
                 run=[r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run|upd=C:\Users\lab\AppData\upd.exe"])
    d = residue.diff(BASE, after)
    assert not d["reusable"] and d["persistence"] and "Run/RunOnce" in d["verdict"]


def test_new_scheduled_task_and_service_flagged():
    after = snap(procs=[(100, "sshd.exe"), (200, "x32dbg.exe")], files=BASE["files"],
                 tasks=[r"\EvilTask"], svcs=["evil|C:\\ProgramData\\e.exe"])
    d = residue.diff(BASE, after)
    assert d["persistence"] and d["new_tasks"] and d["new_services"] and not d["reusable"]


def test_surviving_new_process_flagged():
    after = snap(procs=[(100, "sshd.exe"), (200, "x32dbg.exe"), (999, "svch0st.exe")], files=BASE["files"])
    d = residue.diff(BASE, after)
    assert not d["reusable"] and any("svch0st.exe" in p for p in d["new_processes"])


def test_ransomware_style_mass_rename_detected():
    enc = [f"C:\\Users\\lab\\Documents\\f{i}.docx.locked|50" for i in range(25)]
    before = snap(procs=[(100, "sshd.exe")], files=[f"C:\\Users\\lab\\Documents\\f{i}.docx|40" for i in range(25)])
    d = residue.diff(before, snap(procs=[(100, "sshd.exe")], files=enc))
    assert d["mass_file_change"] and not d["reusable"] and "mass file change" in d["verdict"]


def test_system_noise_is_ignored():
    after = snap(procs=[(100, "sshd.exe"), (200, "x32dbg.exe")],
                 files=BASE["files"] + [r"C:\ProgramData\Microsoft\Windows\Defender\x.log|9",
                                        r"C:\nemesis\sample.exe|9"])
    d = residue.diff(BASE, after)
    assert d["reusable"] and d["ignored_noise_files"] == 2


def test_startup_folder_file_is_persistence():
    after = snap(procs=[(100, "sshd.exe"), (200, "x32dbg.exe")],
                 files=BASE["files"] + [r"C:\Users\lab\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk|9"])
    # path is under \Microsoft\Windows\ so noise filter hides it — startup entries must NOT be hidden
    d = residue.diff(BASE, after)
    assert d["persistence"], "startup-folder entries must never be filtered as noise"


def test_parse_ignores_leading_noise():
    assert residue._parse('WARNING: x\n{"a":1}\n') == {"a": 1}
    assert residue._parse("garbage") is None


class DeadGuest:
    def run(self, *a, **k): return 255, "", ""
    def push(self, *a, **k): return False


def test_finish_fails_safe_when_guest_unreadable():
    d = residue.finish(DeadGuest(), ["x.exe"], BASE, log=lambda m: None)
    assert not d["reusable"] and "revert" in d["verdict"].lower()


def _p(pid, name, path, ppid=4):
    return {"pid": pid, "ppid": ppid, "name": name, "path": path}


def test_own_ssh_session_and_os_service_hosts_are_not_residue():
    before = snap(procs=[(100, "sshd.exe")], files=BASE["files"])
    after = {"procs": before["procs"] + [
        _p(2732, "sshd.exe", r"C:\Windows\System32\OpenSSH\sshd.exe", 100),
        _p(6752, "sshd.exe", r"C:\Windows\System32\OpenSSH\sshd.exe", 2732),
        _p(4228, "cmd.exe", r"c:\windows\system32\cmd.exe", 6752),
        _p(6432, "conhost.exe", r"C:\Windows\system32\conhost.exe", 4228),
        _p(5416, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", 4228),
        _p(1916, "dllhost.exe", r"C:\Windows\system32\DllHost.exe", 600),
        _p(408, "NisSrv.exe", None, 600)],
        "run": [], "tasks": [], "services": [], "files": BASE["files"]}
    d = residue.diff(before, after)
    assert d["reusable"] and d["new_processes"] == [] and len(d["new_processes_benign"]) == 7


def test_cmd_not_under_our_session_is_still_suspicious():
    before = snap(procs=[(100, "sshd.exe")], files=BASE["files"])
    after = {"procs": before["procs"] + [_p(777, "cmd.exe", r"C:\Windows\System32\cmd.exe", 4242)],
             "run": [], "tasks": [], "services": [], "files": BASE["files"]}
    d = residue.diff(before, after)
    assert not d["reusable"] and any("cmd.exe" in x for x in d["new_processes"])


def test_service_host_outside_system32_is_suspicious():
    before = snap(procs=[(100, "sshd.exe")], files=BASE["files"])
    after = {"procs": before["procs"] + [_p(778, "svchost.exe", r"C:\Users\lab\AppData\svchost.exe", 4242)],
             "run": [], "tasks": [], "services": [], "files": BASE["files"]}
    d = residue.diff(before, after)
    assert not d["reusable"] and d["new_processes"]


def test_the_kill_script_only_targets_the_sample_its_descendants_and_our_staging_folder():
    ps = residue.PS_SCRIPT
    assert "$byName" in ps and "$child" in ps and "$ours" in ps
    assert "$suspect" not in ps                                     # the old 'any new process from a user folder' rule is gone
    assert r'^C:\\nemesis\\' in ps


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("PASS", n)


def test_protected_svchost_without_path_is_not_residue():
    from nanalyst.residue import classify_new_processes
    before = {"procs": []}
    after = {"procs": [{"pid": 10, "ppid": 4, "name": "svchost.exe", "path": None},
                       {"pid": 11, "ppid": 4, "name": "svchost.exe", "path": "C:\\Users\\lab\\AppData\\svchost.exe"}]}
    sus, ok = classify_new_processes(before, after)
    assert any(":svchost.exe:None" in x for x in ok)
    assert any("AppData" in x for x in sus)
