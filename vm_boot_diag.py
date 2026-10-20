#!/usr/bin/env python3
"""Diagnostic boot: capture screenshots over 15 min so we can SEE the boot state,
while probing SSH. Screenshots -> ~/.nemesis-analyst-vm/diag/."""
import subprocess, time, uuid
from pathlib import Path
from nanalyst.vm import config as vmcfg, disk
from nanalyst.vm.qemu import Instance
from nanalyst.vm.guest import Guest

def main():
    cfg = vmcfg.load()
    diag = vmcfg.WORK / "diag"; diag.mkdir(parents=True, exist_ok=True)
    for old in diag.glob("*.png"): old.unlink()
    iid = "diag-" + uuid.uuid4().hex[:6]
    wd = vmcfg.INSTANCES / iid; wd.mkdir(parents=True, exist_ok=True)
    overlay = wd / "disk.qcow2"
    disk.create_overlay(vmcfg.BASE_DISK, overlay)
    inst = Instance(iid, overlay, cfg, wd)
    print("booting diag, ssh port", inst.ssh_port); inst.boot()
    guest = Guest(inst.ssh_port, cfg.ssh_user, cfg.ssh_pass)

    shots = []
    end = time.time() + 720
    nxt_shot = time.time() + 45
    ssh_ok = False
    while time.time() < end:
        if not inst.is_running():
            print("qemu exited early"); 
            try: print(inst.proc.stderr.read().decode()[-1500:])
            except Exception: pass
            break
        if time.time() >= nxt_shot:
            t = int(900 - (end - time.time()))
            shot = diag / f"shot_{t:04d}s.png"
            ok = inst.screendump(shot)
            print(f"[{t}s] status={inst.status()} screendump={'ok' if ok and shot.exists() else 'FAIL'} -> {shot.name}")
            if ok and shot.exists(): shots.append(shot)
            nxt_shot = time.time() + 45
        try:
            p = subprocess.run(guest._ssh(["echo","ready"]), capture_output=True, text=True, timeout=12)
            if p.returncode == 0 and "ready" in p.stdout:
                ssh_ok = True; print("SSH UP"); break
        except Exception: pass
        time.sleep(10)

    # final shot
    final = diag / "shot_final.png"
    if inst.is_running(): inst.screendump(final)
    print("ssh_ok =", ssh_ok, "| shots:", [s.name for s in shots] + (["shot_final.png"] if final.exists() else []))
    print("shutting down..."); inst.shutdown(wait=30); inst.kill()
    disk.destroy_overlay(overlay)
    for f in wd.glob("*"):
        try: f.unlink()
        except Exception: pass
    try: wd.rmdir()
    except Exception: pass
    print("diag done")

if __name__ == "__main__":
    main()
