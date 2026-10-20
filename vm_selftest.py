#!/usr/bin/env python3
"""Validate the VM engine without booting Windows: config parse, overlay
create/destroy on a dummy base, and QEMU/SSH command construction (dry run)."""
import subprocess, tempfile
from pathlib import Path
from nanalyst.vm import config as vmcfg, disk
from nanalyst.vm.qemu import Instance
from nanalyst.vm.guest import Guest

def main():
    cfg = vmcfg.load()
    print("== config ==")
    print(f"  arch={cfg.arch} cpu={cfg.cpu} cores={cfg.cores} mem={cfg.memory_mb}MB machine={cfg.machine}")
    print(f"  disk_image={cfg.disk_image}")
    print(f"  OVMF present: {vmcfg.OVMF_CODE.exists()}")
    print(f"  base exists: {vmcfg.BASE_DISK.exists()}  (run vm_prepare_base.py once if False)")

    print("\n== overlay create/destroy (dummy 10MB base) ==")
    tmp = Path(tempfile.mkdtemp())
    base = tmp / "dummy-base.qcow2"
    subprocess.run([disk.QEMU_IMG, "create", "-f", "qcow2", str(base), "10M"],
                   capture_output=True)
    ov = tmp / "overlay.qcow2"
    ok, msg = disk.create_overlay(base, ov)
    print(f"  create: {ok} ({'overlay exists' if ov.exists() else 'MISSING'})")
    disk.destroy_overlay(ov)
    print(f"  destroy: {'gone' if not ov.exists() else 'STILL THERE'}")
    for f in tmp.glob("*"): f.unlink()
    tmp.rmdir()

    print("\n== QEMU command (dry run) ==")
    inst = Instance("selftest", Path("/tmp/x.qcow2"), cfg, tmp.parent)
    cmd = inst.build_command()
    print("  " + " \\\n    ".join(cmd))
    print(f"\n  ssh hostfwd port: {inst.ssh_port}  (restrict=on -> NO internet)")

    print("\n== guest control commands (dry run) ==")
    g = Guest(inst.ssh_port, cfg.ssh_user, cfg.ssh_pass)
    print("  ssh : " + " ".join(g._ssh(["whoami"])).replace(cfg.ssh_pass, "***"))
    print("\nOK — engine ready. Live boot validates when we run a detonation.")

if __name__ == "__main__":
    main()
