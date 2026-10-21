"""push_verified against a fake guest that misbehaves in the ways the real one did (no VM)."""
import hashlib, os, re, tempfile
from nanalyst.vm import transfer


class FakeGuest:
    def __init__(self, behaviors, size_read_fails=0):
        self.behaviors = list(behaviors)       # per push: "ok" | "lock" | "trunc" | "corrupt"
        self.files, self.cmds, self.size_read_fails = {}, [], size_read_fails
        self.pushes = 0

    def push(self, local, remote, timeout=0):
        b = self.behaviors[min(self.pushes, len(self.behaviors) - 1)]; self.pushes += 1
        data = open(local, "rb").read()
        if b == "lock":    self.files[remote] = b"";            return False
        if b == "trunc":   self.files[remote] = data[:32768];   return False
        if b == "corrupt": self.files[remote] = bytes([data[0] ^ 1]) + data[1:]; return True
        self.files[remote] = data; return True

    def run(self, cmd, timeout=0):
        self.cmds.append(cmd)
        m = re.search(r'for %I in \("(.+?)"\)', cmd)
        if m:
            if self.size_read_fails > 0:
                self.size_read_fails -= 1; return 0, "", ""
            d = self.files.get(m.group(1)); return 0, (f"{len(d)}\n" if d is not None else ""), ""
        m = re.search(r'certutil -hashfile "(.+?)" SHA256', cmd)
        if m:
            d = self.files.get(m.group(1), b"")
            return 0, f"SHA256 hash of file:\n{hashlib.sha256(d).hexdigest()}\nCertUtil: ok\n", ""
        m = re.search(r'del /f /q "(.+?)"', cmd)
        if m: self.files.pop(m.group(1), None)
        return 0, "", ""


def sample(n=368640):
    f = tempfile.NamedTemporaryFile(delete=False); f.write(os.urandom(n)); f.close(); return f.name


def go(behaviors, **kw):
    g, p = FakeGuest(behaviors, **kw), sample()
    out = transfer.push_verified(g, p, r"C:\nemesis\s_a1b2c3.exe", attempts=4, log=lambda m: None, sleep=lambda s: None)
    os.unlink(p); return out, g


def test_clean_push_verifies():
    (ok, why), g = go(["ok"]); assert ok and g.pushes == 1


def test_recovers_after_lock_then_trunc():
    (ok, _), g = go(["lock", "trunc", "ok"]); assert ok and g.pushes == 3


def test_corrupt_same_size_is_caught_by_hash():
    (ok, _), g = go(["corrupt", "ok"]); assert ok and g.pushes == 2


def test_never_proceeds_on_unreadable_size():
    (ok, why), g = go(["ok"], size_read_fails=16)    # read-back always fails -> must NOT pass
    assert not ok and "could not read" in why


def test_permanent_failure_reports_cause():
    (ok, why), g = go(["lock"]); assert not ok and "held open" in why and g.pushes == 4


def test_kills_holder_and_deletes_before_each_push():
    (ok, _), g = go(["ok"])
    assert any("taskkill /f /t /im s_a1b2c3.exe" in c for c in g.cmds) and any("del /f /q" in c for c in g.cmds)


def test_unique_names_differ_and_keep_stem():
    a, b = transfer.unique_name("demo1_ransomware", ".exe"), transfer.unique_name("demo1_ransomware", ".exe")
    assert a != b and a.startswith("demo1_ransomware_") and a.endswith(".exe")


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("PASS", n)
