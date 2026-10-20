#!/usr/bin/env python3
"""Boot one instance with a VNC display so the user can WATCH it live
(open vnc://127.0.0.1:5905) and interact (e.g. Cancel the Sysprep dialog).
Keeps it running, probes SSH, screenshots periodically. Cleans up at the end."""
import subprocess, time, uuid
from pathlib import Path
from nanalyst.vm import config as vmcfg, disk
from nanalyst.vm.qemu import Instance
from nanalyst.vm.guest import Guest

VNC_DISPLAY = 5  # -> vnc://127.0.0.1:5905
WATCH_SECS = 1500

def main():
    cfg = vmcfg.load()
    cfg.extra["vnc_display"] = VNC_DISPLAY
    diag = vmcfg.WORK / "diag"; diag.mkdir(parents=True, exist_ok=True)
    for old in diag.glob("watch_*.png"): old.unlink()
    iid = "watch-" + uuid.uuid4().hex[:6]
    wd = vmcfg.INSTANCES / iid; wd.mkdir(parents=True, exist_ok=True)
    overlay = wd / "disk.qcow2"
    disk.create_overlay(vmcfg.BASE_DISK, overlay)
    inst = Instance(iid, overlay, cfg, wd)
    inst.boot()
    print(f"VNC: vnc://127.0.0.1:{5900+VNC_DISPLAY}   SSH hostfwd port: {inst.ssh_port}")
    guest = Guest(inst.ssh_port, cfg.ssh_user, cfg.ssh_pass)

    end = time.time() + WATCH_SECS
    nxt = time.time() + 60
    ssh_ok = False
    while time.time() < end:
        if not inst.is_running():
            print("qemu exited"); break
        if time.time() >= nxt:
            t = int(WATCH_SECS - (end - time.time()))
            shot = diag / f"watch_{t:04d}s.png"
            inst.screendump(shot)
            print(f"[{t}s] status={inst.status()} ssh={'UP' if ssh_ok else '...'} shot={shot.name}({shot.stat().st_size if shot.exists() else 0}b)")
            nxt = time.time() + 60
        if not ssh_ok:
            try:
                p = subprocess.run(guest._ssh(["echo","ready"]), capture_output=True, text=True, timeout=12)
                if p.returncode == 0 and "ready" in p.stdout:
                    ssh_ok = True; print(">>> SSH UP <<<")
            except Exception: pass
        time.sleep(10)

    print("ssh_ok =", ssh_ok, "| shutting down")
    inst.shutdown(wait=30); inst.kill()
    disk.destroy_overlay(overlay)
    for f in wd.glob("*"):
        try: f.unlink()
        except Exception: pass
    try: wd.rmdir()
    except Exception: pass
    print("done")

if __name__ == "__main__":
    main()
