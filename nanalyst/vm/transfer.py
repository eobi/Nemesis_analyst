"""Verified, lock-proof file push to the guest.

Root cause of the "truncated at 32 KB / size 0" pushes (reproduced with a harmless file):
Windows OpenSSH cannot overwrite a file another process holds open — the push fails and
leaves 0 (or one SFTP block of) bytes. In practice the holder was the previous copy of the
sample, still running or just killed. So:

  * stage under a UNIQUE name per run (`unique_name`) — a leftover/locked copy can never
    block the push;
  * before each attempt, kill anything running under the target's image name and delete it;
  * after each attempt, verify BOTH size and SHA-256 on the guest. A size that cannot be
    read counts as a failure (never "proceed unverified");
  * retry with backoff, and say what went wrong if it never verifies.
"""
from __future__ import annotations

import hashlib
import ntpath
import os
import re
import secrets
import time
from pathlib import Path


def unique_name(stem: str, suffix: str) -> str:
    """e.g. demo1_ransomware -> demo1_ransomware_a3f9c2.exe (keeps the stem prefix so the
    debugger's module name still matches the sample)."""
    return f"{stem}_{secrets.token_hex(3)}{suffix}"


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def guest_size(guest, remote: str, tries: int = 4, sleep=time.sleep):
    for _ in range(tries):
        _, out, _ = guest.run(f'cmd /c "for %I in ("{remote}") do @echo %~zI"', timeout=25)
        m = re.search(r"^\s*(\d+)\s*$", out or "", re.M)
        if m:
            return int(m.group(1))
        sleep(0.7)
    return None


def guest_sha256(guest, remote: str, tries: int = 3, sleep=time.sleep):
    for _ in range(tries):
        _, out, _ = guest.run(f'cmd /c "certutil -hashfile "{remote}" SHA256"', timeout=90)
        for ln in (out or "").splitlines():
            h = ln.strip().replace(" ", "").lower()
            if re.fullmatch(r"[0-9a-f]{64}", h):
                return h
        sleep(0.7)
    return None


def push_verified(guest, local: str, remote: str, attempts: int = 4, log=print,
                  sleep=time.sleep):
    """Push `local` -> `remote` and verify size + SHA-256 on the guest.
    Returns (ok, reason). On ok=True the guest copy is byte-identical to `local`."""
    want_size, want_hash = os.path.getsize(local), _sha256(local)
    name = ntpath.basename(remote)
    reason = "not attempted"
    for i in range(1, attempts + 1):
        # release anything holding the target, then clear it
        guest.run(f'cmd /c "taskkill /f /t /im {name} 2>nul"', timeout=20)
        guest.run(f'cmd /c "del /f /q "{remote}" 2>nul"', timeout=20)
        pushed = guest.push(local, remote)
        got = guest_size(guest, remote, sleep=sleep)
        if pushed and got == want_size:
            h = guest_sha256(guest, remote, sleep=sleep)
            if h == want_hash:
                log(f"[push] {remote} verified ({want_size} bytes, sha256 {want_hash[:12]}…)")
                return True, ""
            reason = f"size matched but sha256 differs (guest {str(h)[:12]} vs {want_hash[:12]})"
        elif got is None:
            reason = "could not read the guest file back (SSH flaky or file missing)"
        elif got == 0 or got < want_size:
            reason = (f"guest has {got} of {want_size} bytes — typical of a destination held open "
                      "by a running process, or a dropped connection")
        else:
            reason = f"guest size {got} != local {want_size}"
        log(f"[push] attempt {i}/{attempts} failed: {reason}")
        sleep(2.0 * i)
    return False, reason
