"""Sandbox orchestrator — disposable VM lifecycle as a context manager.

    with Sandbox() as box:
        box.guest.push(sample, "C:/Users/Public/sample.exe")
        box.guest.run("C:/tools/run_detonation.bat")
        box.guest.pull("C:/artifacts", "./out")
    # overlay + instance are destroyed automatically on exit

Spins a fresh copy-on-write clone off the immutable clean base, boots it headless
and isolated (no internet), waits for SSH, yields guest control, then powers it
down and deletes the overlay. Each sample gets a pristine box; many can run in
parallel (distinct overlays + ports).
"""
from __future__ import annotations

import uuid
from pathlib import Path

from . import config as vmcfg
from . import disk
from .qemu import Instance
from .guest import Guest


class SandboxError(RuntimeError):
    pass


class Sandbox:
    def __init__(self, cfg: vmcfg.VMConfig | None = None, boot_timeout: int = 420):
        self.cfg = cfg or vmcfg.load()
        self.boot_timeout = boot_timeout
        self.id = uuid.uuid4().hex[:12]
        self.workdir = vmcfg.INSTANCES / self.id
        self.overlay = self.workdir / "disk.qcow2"
        self.instance: Instance | None = None
        self.guest: Guest | None = None

    def __enter__(self) -> "Sandbox":
        if not vmcfg.BASE_DISK.exists():
            raise SandboxError(
                f"clean base not found at {vmcfg.BASE_DISK}. "
                "Run: python3 vm_prepare_base.py  (one-time)."
            )
        self.workdir.mkdir(parents=True, exist_ok=True)
        ok, msg = disk.create_overlay(vmcfg.BASE_DISK, self.overlay)
        if not ok:
            raise SandboxError(f"overlay creation failed: {msg}")

        self.instance = Instance(self.id, self.overlay, self.cfg, self.workdir)
        self.instance.boot()
        self.guest = Guest(self.instance.ssh_port, self.cfg.ssh_user, self.cfg.ssh_pass)
        if not self.guest.wait_for_ssh(timeout=self.boot_timeout):
            self.__exit__(None, None, None)
            raise SandboxError("guest did not become reachable over SSH before timeout")
        return self

    def __exit__(self, *exc) -> None:
        if self.instance:
            self.instance.shutdown()
            self.instance.kill()
        disk.destroy_overlay(self.overlay)
        try:
            for f in self.workdir.glob("*"):
                f.unlink()
            self.workdir.rmdir()
        except OSError:
            pass
