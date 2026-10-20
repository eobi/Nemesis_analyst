#!/usr/bin/env python3
"""Connect to the x64dbg MCP plugin (over SSH tunnel) and introspect.
Run this AFTER launching x64dbg on the VM desktop with a sample loaded.
    python3 x64dbg_connect.py
"""
import json, sys
from nanalyst.vm.target import load
from nanalyst.x64dbg_mcp import X64dbgMCP

def main():
    t = load("default")
    if not t:
        print("no target; run remote_check.py --save default"); return 1
    c = X64dbgMCP(t)
    print("opening SSH tunnel to guest 127.0.0.1:3000 ...")
    if not c.ensure_tunnel():
        print("!! tunnel failed (is x64dbg running with the plugin? port 3000 up?)"); return 2
    print("tunnel OK. initialize ...")
    init = c.initialize()
    print(json.dumps(init, indent=2)[:600])
    print("\n=== tools ===")
    tools = c.list_tools()
    names = [ (x.get("name") if isinstance(x, dict) else x) for x in (tools or []) ]
    print(f"{len(names)} tools:")
    for n in names:
        print("  ", n)
    # introspect full method signatures if available
    sm = c.rpc("system.methods")
    if "result" in sm:
        print("\n=== system.methods (first 1500 chars) ===")
        print(json.dumps(sm["result"], indent=2)[:1500])
    c.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
