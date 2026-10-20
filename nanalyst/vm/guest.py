"""Guest control over SSH — hypervisor-agnostic.

The tool does NOT manage the VM. You power your own analysis instance (UTM,
VirtualBox, VMware, a cloud VM, bare metal) and enable SSH; we connect to it over
SSH to copy the sample in, run the detonation, and pull artifacts out.

Supports password auth (via sshpass) or private-key auth (cloud instances).
Works against any reachable host:port, not just localhost.
"""
from __future__ import annotations

import shutil
import subprocess
import time

SSHPASS = shutil.which("sshpass") or "/opt/homebrew/bin/sshpass"
_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=10",
]


class Guest:
    def __init__(self, host: str, port: int = 22, user: str = "analyst",
                 password: str | None = None, key: str | None = None):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.key = key  # path to a private key; takes precedence over password

    def _base(self, tool: str) -> list[str]:
        """Build the ssh/scp prefix for the chosen auth method."""
        if self.key:
            return [tool, "-i", self.key, "-o", "PubkeyAuthentication=yes",
                    "-o", "PasswordAuthentication=no", *_OPTS]
        if self.password:
            return [SSHPASS, "-p", self.password, tool,
                    "-o", "PubkeyAuthentication=no", *_OPTS]
        return [tool, *_OPTS]  # agent / default keys

    def _ssh(self, extra: list[str]) -> list[str]:
        return [*self._base("ssh"), "-p", str(self.port),
                f"{self.user}@{self.host}", *extra]

    def wait_for_ssh(self, timeout: int = 120, interval: int = 5) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            rc, out, _ = self._try(["echo", "ready"], interval + 10)
            if rc == 0 and "ready" in out:
                return True
            time.sleep(interval)
        return False

    def _try(self, extra: list[str], timeout: int):
        try:
            p = subprocess.run(self._ssh(extra), capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except Exception as exc:
            return 255, "", str(exc)

    def run(self, command: str, timeout: int = 300) -> tuple[int, str, str]:
        from .. import audit
        au = audit.active()
        if au is None:
            return self._try([command], timeout)
        return au.run("ssh.run", {"host": self.host, "command": command},
                      lambda: self._try([command], timeout), category="guest")

    @staticmethod
    def _scp_path(p: str) -> str:
        # scp to/from Windows OpenSSH wants forward slashes, not backslashes.
        return p.replace("\\", "/")

    def _push(self, local: str, remote: str, timeout: int) -> bool:
        cmd = [*self._base("scp"), "-P", str(self.port), local,
               f"{self.user}@{self.host}:{self._scp_path(remote)}"]
        return subprocess.run(cmd, capture_output=True, timeout=timeout).returncode == 0

    def _pull(self, remote: str, local: str, timeout: int) -> bool:
        cmd = [*self._base("scp"), "-r", "-P", str(self.port),
               f"{self.user}@{self.host}:{self._scp_path(remote)}", local]
        return subprocess.run(cmd, capture_output=True, timeout=timeout).returncode == 0

    def push(self, local: str, remote: str, timeout: int = 600) -> bool:
        from .. import audit
        au = audit.active()
        if au is None:
            return self._push(local, remote, timeout)
        return au.run("scp.push", {"local": local, "remote": remote},
                      lambda: self._push(local, remote, timeout), category="guest")

    def pull(self, remote: str, local: str, timeout: int = 600) -> bool:
        from .. import audit
        au = audit.active()
        if au is None:
            return self._pull(remote, local, timeout)
        return au.run("scp.pull", {"remote": remote, "local": local},
                      lambda: self._pull(remote, local, timeout), category="guest")
