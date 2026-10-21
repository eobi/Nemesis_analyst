#!/usr/bin/env python3
"""Setup wizard — provision a Windows analysis instance over SSH, end to end.

Run this ONCE against a fresh Windows VM, then shut down and snapshot: you get a
reusable, ready-to-analyze baseline. It is idempotent (safe to re-run).

What it does:
  1. Deploys a known-good x64dbg build (bundled) to C:\\x64dbg_new (guarantees a
     debugger new enough for the MCP plugin).
  2. DISCOVERS every x64dbg/x32dbg install on the box and installs the matching
     MCP plugin (.dp64/.dp32) + a tuned config.json into EACH — so "all versions"
     have the MCP server (auto-starts on load, port 3000, auth off, and the
     permissions the unpack engine needs: script exec + memory/register write).
  3. Creates work dirs (C:\\Tools, C:\\nemesis) and pushes the tool chain
     (PsExec64, pe-sieve64, exe2aut).
  4. Verifies everything and prints a readiness report + what is still missing
     (optional detonation/.NET tools it couldn't find locally).

Usage:
    python3 provision.py [--target default] [--no-deploy-build]
"""
import argparse, json, sys, tempfile
from pathlib import Path

from nanalyst.vm.target import load

CACHE = Path(__file__).parent / "tools-cache"

# tuned plugin config — the permissions the unpack engine actually needs
PLUGIN_CONFIG = {
    "version": "1.0.11",
    "server": {"address": "127.0.0.1", "port": 3000},
    "permissions": {
        "allow_memory_write": True, "allow_register_write": True,
        "allow_script_execution": True, "allow_breakpoint_modification": True,
        "allowed_methods": ["*"],
    },
    "security": {"origin_allowlist": [], "host_allowlist": [],
                 "auth_enabled": False, "auth_token": ""},
    "logging": {"enabled": True, "level": "info", "file": "x64dbg_mcp.log",
                "max_file_size_mb": 10, "console_output": True},
    "timeout": {"request_timeout_ms": 30000, "step_timeout_ms": 10000,
                "memory_read_timeout_ms": 5000},
    "features": {"enable_notifications": True, "enable_heartbeat": True,
                 "heartbeat_interval_seconds": 30, "enable_batch_requests": True,
                 "auto_start_mcp_on_plugin_load": True},
}

# support tools we push to C:\Tools when present locally
SUPPORT_TOOLS = ["PsExec64.exe", "pe-sieve64.exe"]
# optional tools we check for but won't fail on
OPTIONAL_MISSING_NOTE = {
    "diec.exe (Windows DIE)": "guest-side .NET DIE (guest_static) — put at C:\\Tools\\die\\diec.exe",
    "de4dot.exe": ".NET deobfuscation — put on PATH or C:\\Tools",
    "Procmon64.exe": "detonation behavior capture — C:\\Tools\\Procmon64.exe",
    "FakeNet-NG": "detonation network capture — C:\\Tools\\fakenet",
}


class Wizard:
    def __init__(self, guest):
        self.g = guest
        self.steps = []   # (name, ok, detail)

    def rec(self, name, ok, detail=""):
        self.steps.append((name, ok, detail))
        print(f"  [{'OK ' if ok else 'XX '}] {name}" + (f" — {detail}" if detail else ""))
        return ok

    def exists(self, win_path):
        rc, _, _ = self.g.run(f'cmd /c "if exist \"{win_path}\" (exit 0) else (exit 1)"', timeout=30)
        return rc == 0

    def mkdir(self, win_path):
        self.g.run(f'cmd /c "if not exist \"{win_path}\" mkdir \"{win_path}\""', timeout=30)

    # ---- 1. known-good build ----
    def deploy_build(self):
        zip_local = CACHE / "x64dbg_new.zip"
        if not zip_local.exists():
            return self.rec("deploy known-good x64dbg build", False, "x64dbg_new.zip not in tools-cache")
        if self.exists(r"C:\x64dbg_new\release\x64\x64dbg.exe"):
            return self.rec("deploy known-good x64dbg build", True, "already present at C:\\x64dbg_new")
        self.g.push(str(zip_local), r"C:\x64dbg_new.zip")
        self.g.run('powershell -NoProfile -Command "Expand-Archive -Path C:\\x64dbg_new.zip '
                   '-DestinationPath C:\\x64dbg_new -Force"', timeout=180)
        ok = self.exists(r"C:\x64dbg_new\release\x64\x64dbg.exe")
        return self.rec("deploy known-good x64dbg build", ok, "C:\\x64dbg_new\\release")

    # ---- 2. discover installs ----
    def discover(self):
        ps = (
            "$roots=@('C:\\x64dbg_new','C:\\Program Files','C:\\Program Files (x86)');"
            "$roots+=(Get-ChildItem 'C:\\Users\\*\\Desktop','C:\\Users\\*\\Downloads' -Directory -EA SilentlyContinue|%{$_.FullName});"
            "$found=@();"
            "foreach($r in $roots){ if(Test-Path $r){ $found+=Get-ChildItem $r -Recurse -Depth 4 -Include x32dbg.exe,x64dbg.exe -EA SilentlyContinue } }"
            "$found|Select-Object -Expand FullName -Unique"
        )
        rc, out, _ = self.g.run(f'powershell -NoProfile -Command "{ps}"', timeout=120)
        installs = []
        for line in out.splitlines():
            p = line.strip()
            if not p.lower().endswith(("x32dbg.exe", "x64dbg.exe")):
                continue
            arch = "x64" if p.lower().endswith("x64dbg.exe") else "x32"
            plugins = p.rsplit("\\", 1)[0] + "\\plugins"
            installs.append({"exe": p, "arch": arch, "plugins": plugins})
        self.rec("discover x64dbg/x32dbg installs", bool(installs),
                 f"{len(installs)} found: " + ", ".join(i["exe"] for i in installs))
        return installs

    # ---- 3. install MCP plugin into each ----
    def install_plugin(self, inst, cfg_local):
        dp = CACHE / ("x64dbg_mcp.dp64" if inst["arch"] == "x64" else "x32dbg_mcp.dp32")
        if not dp.exists():
            return self.rec(f"MCP -> {inst['exe']}", False, f"{dp.name} missing in tools-cache")
        self.mkdir(inst["plugins"])
        cfgdir = inst["plugins"] + ("\\x64dbg-mcp" if inst["arch"] == "x64" else "\\x32dbg-mcp")
        self.mkdir(cfgdir)
        self.g.push(str(dp), inst["plugins"] + "\\" + dp.name)
        self.g.push(str(cfg_local), cfgdir + "\\config.json")
        ok = self.exists(inst["plugins"] + "\\" + dp.name) and self.exists(cfgdir + "\\config.json")
        return self.rec(f"MCP plugin -> {inst['arch']} @ {inst['plugins']}", ok)

    # ---- 4. tools + workdirs ----
    def tools(self):
        self.mkdir(r"C:\Tools"); self.mkdir(r"C:\nemesis")
        self.rec("work dirs C:\\Tools + C:\\nemesis", self.exists(r"C:\Tools") and self.exists(r"C:\nemesis"))
        for t in SUPPORT_TOOLS:
            lp = CACHE / t
            if lp.exists():
                self.g.push(str(lp), rf"C:\Tools\{t}")
                self.rec(f"push {t}", self.exists(rf"C:\Tools\{t}"), r"C:\Tools")
            else:
                self.rec(f"push {t}", False, "not in tools-cache")
        # exe2aut from the Malware Analysis Tools folder, if present
        e2a = Path.home() / "Documents" / "Malware Analysis Tools" / "exe2aut.exe"
        if e2a.exists():
            self.g.push(str(e2a), r"C:\Tools\exe2aut.exe")
            self.rec("push exe2aut.exe", self.exists(r"C:\Tools\exe2aut.exe"), r"C:\Tools")

    # ---- kill running debuggers (so files unlock for delete/replace) ----
    def kill_debuggers(self):
        self.g.run('cmd /c "taskkill /f /im x32dbg.exe 2>nul & taskkill /f /im x64dbg.exe 2>nul & echo ok"', timeout=30)

    # ---- remove OTHER (old/incompatible) x64dbg installs, keep only the good build ----
    def remove_other_installs(self, installs, keep_root=r"C:\x64dbg_new"):
        roots = set()
        for i in installs:
            # install root = the dir ABOVE \x32 or \x64  (…\release)
            exe = i["exe"]
            parent = exe.rsplit("\\", 2)[0]  # …\release
            if keep_root.lower() not in parent.lower():
                roots.add(parent)
        for r in roots:
            self.g.run(f'powershell -NoProfile -Command "Remove-Item \'{r}\' -Recurse -Force -EA SilentlyContinue"', timeout=120)
            self.rec(f"remove old/incompatible install {r}", not self.exists(r))
        return roots

    # ---- create/repoint desktop shortcuts on ALL user desktops to the good build ----
    def make_shortcuts(self):
        ps = r'''$ws=New-Object -ComObject WScript.Shell
$new=@{'x32'='C:\x64dbg_new\release\x32\x32dbg.exe';'x64'='C:\x64dbg_new\release\x64\x64dbg.exe'}
$desks=Get-ChildItem 'C:\Users\*\Desktop' -Directory -EA SilentlyContinue | %{$_.FullName}
$desks+='C:\Users\Public\Desktop'
foreach($d in ($desks|Select-Object -Unique)){ if(Test-Path $d){ foreach($a in 'x32','x64'){
  $lnk=Join-Path $d ("{0}dbg.lnk" -f $a); $s=$ws.CreateShortcut($lnk)
  $s.TargetPath=$new[$a]; $s.WorkingDirectory=Split-Path $new[$a]; $s.IconLocation=$new[$a]; $s.Save()
  Write-Output ("shortcut {0} -> {1}" -f $lnk,$new[$a]) } } }'''
        self._run_ps(ps, "desktop shortcuts -> 2026 build")

    # ---- wire desktop analysis tools into C:\Tools in the layout the code expects ----
    def wire_desktop_tools(self):
        ps = r'''$dst='C:\Tools'; if(-not(Test-Path $dst)){New-Item -ItemType Directory $dst|Out-Null}
function F($n){Get-ChildItem 'C:\Users\*\Desktop','C:\Users\Public\Desktop' -Recurse -Depth 5 -Filter $n -EA SilentlyContinue|Select-Object -First 1 -Expand FullName}
$diec=F 'diec.exe'; if($diec){Copy-Item (Split-Path $diec) "$dst\die" -Recurse -Force -EA SilentlyContinue; Write-Output ("die="+(Test-Path "$dst\die\diec.exe"))}
$pm=F 'Procmon64.exe'; if(-not $pm){$pm=F 'Procmon.exe'}; if($pm){Copy-Item $pm "$dst\Procmon64.exe" -Force; Write-Output ("procmon="+(Test-Path "$dst\Procmon64.exe"))}
$fn=F 'fakenet.exe'; if($fn){Copy-Item (Split-Path $fn) "$dst\fakenet" -Recurse -Force -EA SilentlyContinue; Write-Output ("fakenet="+(Test-Path "$dst\fakenet\fakenet.exe"))}
$dd=F 'de4dot.exe'; if($dd){Copy-Item $dd "$dst\de4dot.exe" -Force; Write-Output ("de4dot="+(Test-Path "$dst\de4dot.exe"))}'''
        self._run_ps(ps, "wire desktop tools -> C:\\Tools")

    def _run_ps(self, ps_text, label):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False) as f:
            f.write(ps_text); local = f.name
        remote = r"C:\nemesis\_prov.ps1"
        self.mkdir(r"C:\nemesis")
        self.g.push(local, remote)
        rc, out, _ = self.g.run(f'powershell -NoProfile -ExecutionPolicy Bypass -File {remote}', timeout=300)
        self.rec(label, rc == 0, out.strip().replace("\n", " ")[:120])

    def report_missing(self):
        print("\n  Optional tools NOT provisioned (add before snapshot if you want them):")
        for name, why in OPTIONAL_MISSING_NOTE.items():
            print(f"    - {name}: {why}")

    def run(self, deploy_build=True):
        print("== Nemesis Analyst — Windows provisioning wizard ==\n")
        self.kill_debuggers()
        if deploy_build:
            self.deploy_build()
        installs = self.discover()
        # remove old/incompatible installs (e.g. base-image C:\Program Files\release)
        print("\n  Removing old/incompatible debuggers (keep only the 2026 build):")
        self.remove_other_installs(installs)
        good = [i for i in installs if r"c:\x64dbg_new" in i["exe"].lower()]
        # write tuned config once, push into the good build only
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(PLUGIN_CONFIG, f, indent=2); cfg_local = f.name
        print("\n  Installing MCP plugin into the 2026 build:")
        for inst in good:
            self.install_plugin(inst, cfg_local)
        print("\n  Desktop shortcuts:")
        self.make_shortcuts()
        print("\n  Tools + work dirs:")
        self.tools()
        print("\n  Wiring desktop analysis tools into C:\\Tools:")
        self.wire_desktop_tools()
        self.report_missing()

        ok = sum(1 for _, o, _ in self.steps if o)
        bad = [n for n, o, _ in self.steps if not o]
        print(f"\n== {ok}/{len(self.steps)} steps OK ==")
        if bad:
            print("  FAILED: " + "; ".join(bad))
        mcp_ok = any("MCP plugin" in n and o for n, o, _ in self.steps)
        print("\nReadiness:")
        print(f"  - MCP plugin installed on {sum(1 for n,o,_ in self.steps if 'MCP plugin' in n and o)} debugger(s)")
        print("  - To use: launch x64dbg/x32dbg on the DESKTOP with a sample; the MCP server")
        print("    auto-starts on 127.0.0.1:3000; then run unpack.py from the Mac.")
        print("  - SAFE TO SNAPSHOT once you've added any optional tools you want.")
        return 0 if mcp_ok else 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="default")
    ap.add_argument("--no-deploy-build", action="store_true",
                    help="don't deploy the bundled x64dbg build (use existing installs only)")
    a = ap.parse_args()
    t = load(a.target)
    if not t:
        print("no target; run remote_check.py --save default"); return 1
    return Wizard(t.guest()).run(deploy_build=not a.no_deploy_build)


if __name__ == "__main__":
    sys.exit(main())
