#!/usr/bin/env python3
"""One-time: build the immutable clean base from the VM's clean-baseline snapshot.
Heavy (flattens the qcow2). The VM MUST be powered off. Run once.
    python3 vm_prepare_base.py [snapshot_name]   # default: clean-baseline
"""
import sys
from nanalyst.vm import config as vmcfg
from nanalyst.vm import disk

def main(argv):
    snap = argv[0] if argv else "clean-baseline"
    cfg = vmcfg.load()
    src = vmcfg.source_disk(cfg)
    if not src:
        print("source disk not found from UTM config"); return 1
    print(f"flattening '{snap}' from {src}\n  -> {vmcfg.BASE_DISK}\n(this copies ~tens of GB; be patient)")
    ok, msg = disk.prepare_base(src, snap, vmcfg.BASE_DISK)
    print(msg); return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
