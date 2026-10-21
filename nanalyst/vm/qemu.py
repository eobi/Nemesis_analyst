"""QEMU instance — build the command, boot headless, control via QMP.

Drives qemu-system-x86_64 directly (TCG; x86 guest on Apple Silicon), matching
the UTM machine spec. Networking uses user-net with restrict=on (NO real
internet) plus an SSH hostfwd port for control — isolated by construction.
"""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
from pathlib import Path

from . import config as vmcfg

import shutil as _sh
QEMU = _sh.which("qemu-system-x86_64") or "qemu-system-x86_64"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Instance:
    def __init__(self, name: str, overlay: Path, cfg: vmcfg.VMConfig, workdir: Path):
        self.name = name
        self.overlay = overlay
        self.cfg = cfg
        self.workdir = workdir
        self.ssh_port = free_port()
        self.qmp_sock = workdir / f"{name}.qmp"
        self.efivars = workdir / f"{name}.efivars.fd"
        self.serial_log = workdir / f"{name}.serial.log"
        self.proc: subprocess.Popen | None = None

    def build_command(self) -> list[str]:
        c = self.cfg
        # Anti-evasion: drop the hypervisor CPUID bit so CPUID-based VM checks fail.
        cpu = f"{c.cpu},-hypervisor" if c.extra.get("anti_evasion", True) else c.cpu
        cmd = [
            QEMU,
            "-name", self.name,
            "-machine", c.machine,
            # Multi-threaded TCG: each vCPU on its own host thread (what UTM uses).
            # Single-thread TCG with several vCPUs serializes and crawls.
            "-accel", "tcg,thread=multi,tb-size=512",
            "-cpu", cpu,
            "-smp", str(c.cores),
            "-m", str(c.memory_mb),
            "-rtc", "base=localtime",
            "-device", "virtio-rng-pci",
            "-vga", "std",   # framebuffer present so we can QMP screendump headlessly
        ]
        # Anti-evasion: spoof SMBIOS so the box looks like real OEM hardware,
        # not "QEMU"/"Standard PC". (Full de-QEMU-ing also needs ACPI/registry
        # scrubbing inside the guest — tracked in the roadmap.)
        if c.extra.get("anti_evasion", True):
            cmd += [
                "-smbios", "type=0,vendor=Dell Inc.,version=2.18.0,date=03/15/2024",
                "-smbios", "type=1,manufacturer=Dell Inc.,product=OptiPlex 7090,"
                           "version=1.0,serial=7GXTW01,family=OptiPlex",
                "-smbios", "type=2,manufacturer=Dell Inc.,product=0K240Y",
            ]
        if c.uefi and vmcfg.OVMF_CODE.exists():
            cmd += [
                "-drive", f"if=pflash,format=raw,readonly=on,file={vmcfg.OVMF_CODE}",
                "-drive", f"if=pflash,format=raw,file={self.efivars}",
            ]
        # Disk on the q35 AHCI controller.
        cmd += [
            "-device", "ich9-ahci,id=ahci",
            # Disposable overlay: fast, no-fsync caching (we throw it away anyway).
            "-drive", f"id=disk0,if=none,format=qcow2,file={self.overlay},cache=unsafe,aio=threads",
            "-device", "ide-hd,bus=ahci.0,drive=disk0",
        ]
        # Isolated user-net: no internet (restrict=on), SSH control via hostfwd.
        cmd += [
            "-netdev", f"user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22",
            "-device", f"e1000,netdev=net0,mac={c.mac}",
        ]
        # Display: headless by default, or a VNC server you can watch/interact with
        # live (open vnc://127.0.0.1:<5900+display> in macOS Screen Sharing).
        vnc_display = self.cfg.extra.get("vnc_display")
        if vnc_display is not None:
            self.vnc_port = 5900 + int(vnc_display)
            cmd += ["-vnc", f"127.0.0.1:{int(vnc_display)}"]
        else:
            self.vnc_port = None
            cmd += ["-display", "none"]
        cmd += [
            "-serial", f"file:{self.serial_log}",
            "-qmp", f"unix:{self.qmp_sock},server,nowait",
        ]
        return cmd

    def boot(self) -> None:
        # Fresh EFI vars per instance so boot entries persist within the run.
        if self.cfg.efi_vars_template.exists():
            shutil.copy(self.cfg.efi_vars_template, self.efivars)
        self.proc = subprocess.Popen(
            self.build_command(),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    # ---- QMP ----
    def _qmp(self, command: str, args: dict | None = None, timeout: float = 10) -> dict:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(str(self.qmp_sock))
        f = s.makefile("rw")
        f.readline()  # greeting
        f.write(json.dumps({"execute": "qmp_capabilities"}) + "\n"); f.flush()
        f.readline()
        msg = {"execute": command}
        if args:
            msg["arguments"] = args
        f.write(json.dumps(msg) + "\n"); f.flush()
        resp = json.loads(f.readline())
        s.close()
        return resp

    def screendump(self, path) -> bool:
        try:
            r = self._qmp("screendump", {"filename": str(path), "format": "png"})
            if "error" in r:
                r = self._qmp("screendump", {"filename": str(path)})  # ppm fallback
            return "error" not in r
        except Exception:
            return False

    def status(self) -> str:
        try:
            return self._qmp("query-status").get("return", {}).get("status", "unknown")
        except Exception as exc:
            return f"error: {exc}"

    def shutdown(self, wait: int = 60) -> None:
        """Graceful ACPI power-down, then force-kill if it lingers."""
        try:
            self._qmp("system_powerdown")
        except Exception:
            pass
        for _ in range(wait):
            if not self.is_running():
                return
            time.sleep(1)
        self.kill()

    def kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            try:
                self.proc.wait(timeout=10)
            except Exception:
                pass
