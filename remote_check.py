#!/usr/bin/env python3
"""Connect to a user-powered analysis instance over SSH and report readiness.

Usage:
    python3 remote_check.py --host 192.168.64.3 [--port 22] [--user lab] \
        [--password 'YOUR_VM_PASSWORD' | --key ~/.ssh/id_ed25519] [--os windows] [--save NAME]

Verifies connectivity, identifies the OS, and checks for the dynamic-analysis
tools. Does NOT run any sample. Does NOT manage the VM.
"""
import argparse, sys
from nanalyst.vm.target import Target, save
from nanalyst.vm.guest import Guest

WIN_TOOLS = {
    "tshark": "where tshark",
    "procmon": "where procmon",
    "fakenet": "where fakenet",
    "python": "where python",
    "upx": "where upx",
}
NIX_TOOLS = {t: f"which {t}" for t in ["tshark", "python3", "upx", "ssh"]}


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--user", default="analyst")
    ap.add_argument("--password")
    ap.add_argument("--key")
    ap.add_argument("--os", default="windows", choices=["windows", "linux"])
    ap.add_argument("--save", help="save as a named target in targets.json")
    a = ap.parse_args(argv)

    g = Guest(a.host, a.port, a.user, a.password, a.key)
    print(f"connecting to {a.user}@{a.host}:{a.port} ...")
    if not g.wait_for_ssh(timeout=30, interval=5):
        print("!! could not establish SSH. Check the instance is up, SSH is enabled,\n"
              "   the host/port is reachable from this Mac, and the credentials are right.")
        return 2
    print("SSH OK.")

    rc, out, _ = g.run("whoami")
    print("  whoami:", out.strip())

    # OS identity
    if a.os == "windows":
        rc, out, _ = g.run("cmd /c ver")
        print("  os    :", out.strip() or "(no ver output)")
        tools = WIN_TOOLS
    else:
        rc, out, _ = g.run("uname -a")
        print("  os    :", out.strip())
        tools = NIX_TOOLS

    print("  tools :")
    for name, probe in tools.items():
        rc, out, _ = g.run(probe)
        found = out.strip().splitlines()[0] if (rc == 0 and out.strip()) else "NOT FOUND"
        print(f"    {name:<8}: {found}")

    if a.save:
        t = Target(host=a.host, port=a.port, user=a.user, password=a.password,
                   key=a.key, os=a.os, name=a.save)
        save(t)
        print(f"saved target '{a.save}' to targets.json")

    print("\nReady. Give me the go and we run the pipeline against this target.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
