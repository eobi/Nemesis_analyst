"""VM configuration — derived from the UTM VM, with safe automation defaults.

Reads the machine spec (arch, cpu, cores, memory, firmware) from the UTM
config.plist so the QEMU we drive matches the VM you built, and holds the paths,
credentials, and firmware locations the orchestrator needs.
"""
from __future__ import annotations

import plistlib
from dataclasses import dataclass, field
from pathlib import Path

HOME = Path.home()
UTM_BUNDLE = HOME / "Library/Containers/com.utmapp.UTM/Data/Documents/Windows.utm"
UTM_DATA = UTM_BUNDLE / "Data"

# Firmware shipped with brew's qemu — a MATCHED OVMF 4M-split pair (code + vars).
# (UTM's own efi_vars.fd is a qcow2 for a different build; mixing it with this code
# hangs the firmware, so we use brew's matched raw vars template and fresh NVRAM.)
OVMF_CODE = Path("/opt/homebrew/share/qemu/edk2-x86_64-code.fd")
OVMF_VARS = Path("/opt/homebrew/share/qemu/edk2-i386-vars.fd")

# Where disposable instances and the immutable base live.
WORK = HOME / ".nemesis-analyst-vm"
BASE_DISK = WORK / "clean-base.qcow2"          # immutable backing file
INSTANCES = WORK / "instances"


@dataclass
class VMConfig:
    arch: str = "x86_64"
    cpu: str = "Icelake-Server"
    cores: int = 4
    memory_mb: int = 4096
    machine: str = "q35"
    uefi: bool = True
    mac: str = "6A:80:AD:DA:2B:56"
    disk_image: str | None = None               # source disk in the UTM bundle
    efi_vars_template: Path = OVMF_VARS          # matched raw vars for OVMF_CODE
    # SSH into the guest (user-net hostfwd). lab account per the RE-VM runbook.
    ssh_user: str = "lab"
    ssh_pass: str = "CHANGEME"
    extra: dict = field(default_factory=dict)


def load() -> VMConfig:
    """Build a VMConfig from the UTM config.plist, falling back to defaults."""
    cfg = VMConfig()
    plist = UTM_BUNDLE / "config.plist"
    if plist.exists():
        try:
            d = plistlib.load(open(plist, "rb"))
            sysd = d.get("System", {})
            cfg.arch = sysd.get("Architecture", cfg.arch)
            cfg.cpu = sysd.get("CPU", cfg.cpu) or cfg.cpu
            cfg.cores = int(sysd.get("CPUCount", cfg.cores) or cfg.cores)
            cfg.memory_mb = int(sysd.get("MemorySize", cfg.memory_mb) or cfg.memory_mb)
            cfg.machine = sysd.get("Target", cfg.machine) or cfg.machine
            for drive in d.get("Drive", []):
                if drive.get("ImageType") == "Disk" and drive.get("ImageName"):
                    cfg.disk_image = str(UTM_DATA / drive["ImageName"])
            for net in d.get("Network", []):
                if net.get("MacAddress"):
                    cfg.mac = net["MacAddress"]
        except Exception as exc:  # malformed plist: keep defaults
            cfg.extra["config_error"] = str(exc)
    return cfg


def source_disk(cfg: VMConfig) -> Path | None:
    if cfg.disk_image and Path(cfg.disk_image).exists():
        return Path(cfg.disk_image)
    return None
