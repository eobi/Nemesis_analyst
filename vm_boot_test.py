#!/usr/bin/env python3
"""First live boot validation with diagnostics (manual lifecycle, no auto-destroy
on failure so we can inspect the serial log)."""
import time, uuid
from pathlib import Path
from nanalyst.vm import config as vmcfg, disk
from nanalyst.vm.qemu import Instance
from nanalyst.vm.guest import Guest

def main():
    cfg = vmcfg.load()
    if not vmcfg.BASE_DISK.exists():
        print("base missing"); return 1
    iid = "boottest-" + uuid.uuid4().hex[:6]
    wd = vmcfg.INSTANCES / iid; wd.mkdir(parents=True, exist_ok=True)
    overlay = wd / "disk.qcow2"
    ok, msg = disk.create_overlay(vmcfg.BASE_DISK, overlay)
    print("overlay:", ok, msg)
    inst = Instance(iid, overlay, cfg, wd)
    print("booting (TCG, slow)... ssh port", inst.ssh_port)
    inst.boot()
    guest = Guest(inst.ssh_port, cfg.ssh_user, cfg.ssh_pass)

    deadline = time.time() + 540  # 9 min
    ssh_ok = False
    last = 0
    while time.time() < deadline:
        if not inst.is_running():
            print("!! qemu exited early. stderr:")
            try: print(inst.proc.stderr.read().decode()[-1500:])
            except Exception: pass
            break
        # quick SSH probe
        try:
            import subprocess
            p = subprocess.run(guest._ssh(["echo","ready"]), capture_output=True, text=True, timeout=12)
            if p.returncode == 0 and "ready" in p.stdout:
                ssh_ok = True; break
        except Exception:
            pass
        if time.time() - last > 60:
            last = time.time()
            print(f"[{int(time.time()-(deadline-540))}s] qmp status: {inst.status()}  (serial tail:)")
            try: print("  " + "\n  ".join(Path(inst.serial_log).read_text(errors='replace').splitlines()[-6:]))
            except Exception: print("  (no serial yet)")
        time.sleep(8)

    if ssh_ok:
        print("\n*** SSH UP ***")
        rc,out,err = guest.run("whoami")
        print("whoami:", out.strip(), "| rc", rc)
        rc,out,err = guest.run("ver")
        print("ver:", out.strip())
    else:
        print("\n!! SSH did not come up in time")
        try: print("serial tail:\n" + "\n".join(Path(inst.serial_log).read_text(errors='replace').splitlines()[-25:]))
        except Exception: pass

    print("\nshutting down + cleanup...")
    inst.shutdown(wait=40); inst.kill()
    disk.destroy_overlay(overlay)
    for f in wd.glob("*"):
        try: f.unlink()
        except Exception: pass
    try: wd.rmdir()
    except Exception: pass
    print("done. ssh_ok =", ssh_ok)
    return 0 if ssh_ok else 2

if __name__ == "__main__":
    import sys; sys.exit(main())
