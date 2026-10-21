"""Brain-side client for the x64dbg MCP plugin (SetsunaYukiOvO/x64dbg-mcp).

The plugin's HTTP server is localhost-bound on the guest; we reach it through an
SSH tunnel (Mac:LPORT -> guest 127.0.0.1:3000) and speak JSON-RPC on /rpc.
Tools use dotted names (breakpoint.set, module.get_main, ...). All operations
require the debugger to be PAUSED.

Prereq: x64dbg must be running on the guest with the plugin loaded (it auto-starts
the server via config auto_start_mcp_on_plugin_load=true). Launch x64dbg on the VM
desktop with the sample; then this client drives it.
"""
from __future__ import annotations

import json
import socket
import subprocess
import time
import urllib.request

from .vm.target import Target


class X64dbgMCP:
    def __init__(self, target: Target, remote_port: int = 3000, local_port: int = 13300):
        self.target = target
        self.remote_port = remote_port
        self.local_port = local_port
        self.base = f"http://127.0.0.1:{local_port}"
        self.endpoint = self.base + "/mcp"   # Streamable HTTP (this build has /mcp + /sse)
        self.session_id = None
        self._id = 0
        self._tunnel = None

    # ---- SSH tunnel ----
    def ensure_tunnel(self) -> bool:
        if self._port_open(self.local_port):
            return True
        cmd = ["/opt/homebrew/bin/sshpass", "-p", self.target.password, "ssh",
               "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
               "-o", "PubkeyAuthentication=no", "-o", "ExitOnForwardFailure=yes",
               "-N", "-L", f"{self.local_port}:127.0.0.1:{self.remote_port}",
               "-p", str(self.target.port), f"{self.target.user}@{self.target.host}"]
        self._tunnel = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(15):
            if self._port_open(self.local_port):
                return True
            time.sleep(0.5)
        return False

    def close(self):
        if self._tunnel:
            self._tunnel.terminate()

    @staticmethod
    def _port_open(port: int) -> bool:
        s = socket.socket(); s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", port)); return True
        except OSError:
            return False
        finally:
            s.close()

    # ---- MCP Streamable HTTP (/mcp) ----
    @staticmethod
    def _parse_body(ctype: str, body: str) -> dict:
        if "text/event-stream" in (ctype or ""):
            # SSE: take the last 'data:' JSON line
            out = {}
            for line in body.splitlines():
                if line.startswith("data:"):
                    try:
                        out = json.loads(line[5:].strip())
                    except Exception:
                        pass
            return out
        try:
            return json.loads(body)
        except Exception:
            return {"raw": body}

    def rpc(self, method: str, params: dict | None = None,
            notification: bool = False, timeout: int = 60) -> dict:
        payload = {"jsonrpc": "2.0", "method": method}
        if not notification:
            self._id += 1
            payload["id"] = self._id
        if params is not None:
            payload["params"] = params
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream",
                   "Mcp-Protocol-Version": "2025-03-26"}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        req = urllib.request.Request(self.endpoint, data=json.dumps(payload).encode(),
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                sid = r.headers.get("Mcp-Session-Id")
                if sid:
                    self.session_id = sid
                body = r.read().decode("utf-8", "replace")
                ctype = r.headers.get("Content-Type", "")
            return {} if notification else self._parse_body(ctype, body)
        except Exception as exc:
            return {"error": {"message": str(exc)}}

    def initialize(self) -> dict:
        r = self.rpc("initialize", {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "nemesis-analyst", "version": "1.0"}})
        # MCP handshake: tell the server we're initialized
        self.rpc("notifications/initialized", notification=True)
        return r

    def list_tools(self) -> list:
        r = self.rpc("tools/list")
        res = r.get("result", {})
        return res.get("tools", res) if isinstance(res, dict) else res

    def tool(self, name: str, args: dict | None = None) -> dict:
        """Call a plugin tool. Tries MCP tools/call, falls back to direct method.
        Every call is recorded on the active audit ledger (tool=x64dbg.<name>)."""
        from . import audit
        au = audit.active()

        def _do():
            r = self.rpc("tools/call", {"name": name, "arguments": args or {}})
            if "error" in r and "method" in str(r["error"]).lower():
                r = self.rpc(name, args or {})   # /rpc direct-method fallback
            return r

        if au is None:
            return _do()
        return au.run(f"x64dbg.{name}", args or {}, _do, category="dynamic")

    # convenience
    def paused(self) -> bool:
        r = self.tool("debug.is_debugging") if True else {}
        return bool(r.get("result"))
