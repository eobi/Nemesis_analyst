#!/usr/bin/env python3
"""Headless boot with a LIVE TERMINAL LOG you can watch end-to-end.

No GUI. Everything the engine does streams to ~/.nemesis-analyst-vm/live.log.
Watch it in a terminal:   tail -f ~/.nemesis-analyst-vm/live.log

Uses 2 vCPUs (TCG is more responsive with fewer) and drives the guest over SSH.
"""
import subprocess, time, uuid
from pathlib import Path
from nanalyst.vm import config as vmcfg, disk
from nanalyst.vm.qemu import Instance
from nanalyst.vm.guest import Guest

LIVE = vmcfg.WORK / "live.log"

def log(msg: str):
    line = f"{time.strftime('%H:%M:%S')}  {msg}"
    print(line, flush=True)
    with open(LIVE, "a") as f:
        f.write(line + "\n")

def main():
    LIVE.parent.mkdir(parents=True, exist_ok=True)
    open(LIVE, "w").close()
    cfg = vmcfg.load()
    # cores/mem/machine come from the UTM config (5 vCPU, 8GB, q35)
    log("=== Nemesis Analyst — live sandbox boot ===")
    log(f"machine: {cfg.cores} vCPU, {cfg.memory_mb} MB, {cfg.machine}, MTTCG, headless")

    iid = "live-" + uuid.uuid4().hex[:6]
    wd = vmcfg.INSTANCES / iid; wd.mkdir(parents=True, exist_ok=True)
    overlay = wd / "disk.qcow2"
    log("creating disposable copy-on-write overlay off the clean base ...")
    ok, _ = disk.create_overlay(vmcfg.BASE_DISK, overlay)
    log(f"overlay ready: {ok}")

    inst = Instance(iid, overlay, cfg, wd)
    log(f"booting Windows headless, isolated (no internet); SSH control on 127.0.0.1:{inst.ssh_port}")
    inst.boot()
    guest = Guest(inst.ssh_port, cfg.ssh_user, cfg.ssh_pass)

    start = time.time(); deadline = start + 1500; ssh_ok = False
    log("waiting for Windows to finish booting and answer SSH (slow under TCG emulation) ...")
    while time.time() < deadline:
        if not inst.is_running():
            log("!! qemu exited early"); break
        try:
            p = subprocess.run(guest._ssh(["echo", "ready"]), capture_output=True, text=True, timeout=12)
            if p.returncode == 0 and "ready" in p.stdout:
                ssh_ok = True; break
        except Exception:
            pass
        log(f"  ...still booting, SSH not up yet ({int(time.time()-start)}s elapsed)")
        time.sleep(12)

    if ssh_ok:
        secs = int(time.time() - start)
        log(f"*** SSH UP after {secs}s — guest control works end to end! ***")
        for cmd in ["whoami", "hostname", "ver"]:
            rc, out, err = guest.run(cmd)
            log(f"  guest$ {cmd}  ->  {out.strip() or err.strip()}")
        log("engine proven. leaving the VM up 3 min, then cleaning up ...")
        time.sleep(180)
    else:
        log("SSH did not come up within the window (likely still booting under TCG).")

    log("shutting down + deleting the disposable overlay ...")
    inst.shutdown(wait=30); inst.kill()
    disk.destroy_overlay(overlay)
    for f in wd.glob("*"):
        try: f.unlink()
        except Exception: pass
    try: wd.rmdir()
    except Exception: pass
    log("done.")

if __name__ == "__main__":
    main()
