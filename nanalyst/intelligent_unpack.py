"""Intelligent unpacking engine — the brain driving x64dbg over MCP.

Strategy (works for custom/unknown packers where `upx -d` doesn't apply):
  1. debug_restart -> stop at the entry point (past the noisy loader phase, so
     debug_run reaches our breakpoints instead of DLL-load/system events).
  2. Detect OEP (dump_detect_oep) and breakpoint it; also breakpoint the P1
     memory/unpack APIs to observe the unpacking (hit counts, base addrs, W->X).
  3. Run to the OEP (the stub unpacks in memory and tail-jumps to OEP; we stop
     there BEFORE the payload runs).
  4. OEP-aware dump: with EIP at the real OEP, dump_module reconstructs a clean
     PE (fixed entry; the plugin realigns). dump_memory_region as a fallback.

Tool names are the live x64dbg-mcp set (underscores). Requires x64dbg running with
the sample loaded.

P1 API reference (x86 arg layout, from the analyst notes):
  VirtualAlloc  -> at return EAX = base address
  VirtualProtect-> [esp+4]=lpAddress, [esp+C]=flNewProtect (EXECUTE bit => W->X)
  NtAllocateVirtualMemory/VirtualProtectEx -> base in 2nd stack param
"""
from __future__ import annotations

PAGE_EXEC = 0x10 | 0x20 | 0x40 | 0x80
WATCH_APIS = [
    "kernel32.VirtualAlloc", "kernel32.VirtualAllocEx", "kernel32.VirtualProtect",
    "kernel32.VirtualProtectEx", "kernel32.WriteProcessMemory",
    "kernel32.CreateProcessW", "kernel32.CreateProcessA",
    "ntdll.NtAllocateVirtualMemory", "ntdll.NtProtectVirtualMemory",
    "ntdll.RtlDecompressBuffer", "ntdll.NtWriteVirtualMemory",
    "ntdll.LdrLoadDll",
]
ANTIDBG = ["kernel32.IsDebuggerPresent", "ntdll.NtQueryInformationProcess",
           "kernel32.CheckRemoteDebuggerPresent"]


def _norm(x):
    """Canonical lowercase hex for an address ('0x771D2BF0' / '771d2bf0' / int -> '0x771d2bf0')."""
    try:
        return hex(int(str(x), 16) if not isinstance(x, int) else x)
    except Exception:
        return str(x).lower()


def _text(r):
    res = r.get("result", r)
    if isinstance(res, dict) and res.get("content"):
        import json
        try:
            return json.loads(res["content"][0]["text"])
        except Exception:
            return res["content"][0]["text"]
    return res


class Engine:
    def __init__(self, client, log=print):
        self.c = client
        self.log = log
        self._watch_regions = []   # bases returned by allocations, for later dumps
        self._mod = None           # main module {name, base, size} (set during api_trace)

    def call(self, name, args=None):
        return _text(self.c.tool(name, args or {}))

    # ---- ASLR-aware address mapping + memory helpers ----
    @staticmethod
    def rebase(static_addr, static_base, runtime_base):
        """Map a Ghidra (static) address to the runtime address: runtime finds the
        module's real base (ASLR), and the RVA (addr - static_base) is invariant."""
        sa = int(static_addr, 16) if isinstance(static_addr, str) else static_addr
        sb = int(static_base, 16) if isinstance(static_base, str) else static_base
        rb = int(runtime_base, 16) if isinstance(runtime_base, str) else runtime_base
        return rb + (sa - sb)

    def read_mem(self, addr, size=64):
        a = addr if str(addr).startswith("0x") else hex(addr)
        r = self.call("memory_read", {"address": a, "size": size})
        if isinstance(r, dict):
            h = r.get("data") or r.get("hex") or r.get("bytes") or ""
            if isinstance(h, str):
                try:
                    return bytes.fromhex(h.replace("0x", "").replace(" ", ""))
                except Exception:
                    return b""
        return b""

    def read_str(self, addr, maxlen=200):
        b = self.read_mem(addr, maxlen)
        if len(b) > 1 and b[1] == 0:            # looks like UTF-16LE
            try:
                # terminator = a zero WORD on a 2-byte boundary (a plain split on \x00\x00 cuts 'x\x00' + '\x00\x00' mid-char)
                end = next((i for i in range(0, len(b) - 1, 2) if b[i] == 0 and b[i + 1] == 0), len(b) - len(b) % 2)
                return b[:end].decode("utf-16-le", "replace")
            except Exception:
                pass
        return b.split(b"\x00")[0].decode("latin-1", "replace")

    def read_args(self, spec, arch):
        out = {}
        if arch == "x64":
            regs = ["rcx", "rdx", "r8", "r9"]
            rv = self.reg(*regs)
            for i, name in enumerate(spec.get("x64", [])[:4]):
                out[name] = rv.get(regs[i])
        else:
            for name, off in spec.get("x86", []):
                v = self.resolve(f"[esp+{hex(off)}]")
                out[name] = int(v, 16) if isinstance(v, str) else v
        return out

    def eip(self):
        s = self.call("debug_get_state")
        return (s.get("eip", "") if isinstance(s, dict) else "").lower(), \
               (s.get("state", "") if isinstance(s, dict) else "")

    def resolve(self, expr, tries=1):
        """Evaluate an expression (symbol/address). eval_expression is occasionally
        flaky right after a restart/run (transient 'invalid'); retry when asked."""
        import time
        for i in range(max(tries, 1)):
            r = self.call("eval_expression", {"expression": expr})
            if isinstance(r, dict) and r.get("valid"):
                return r.get("result")
            if i + 1 < tries:
                time.sleep(0.2)
        return None

    def wait_symbols(self, sentinel="kernel32.ExitProcess", tries=25):
        """Block until module exports resolve (symbols loaded). Returns True once the
        sentinel resolves, so arming API breakpoints never silently no-ops."""
        return self.resolve(sentinel, tries=tries) is not None

    def build_export_map(self, modules=("ntdll.dll", "kernel32.dll", "kernelbase.dll"),
                         sentinel="VirtualAlloc", tries=20):
        """Read export tables directly (module_get_exports) -> {name: [VA,...]}. The
        plugin loads a module's exports lazily, so retry until the sentinel (a kernel32
        export) appears — otherwise arming would silently miss kernel32 APIs."""
        import time
        m, mods = {}, {}
        for _ in range(tries):
            m, mods = {}, {}
            for mod in modules:
                r = self.call("module_get_exports", {"module": mod})
                for e in (r.get("exports", []) if isinstance(r, dict) else []):
                    n, va = e.get("name"), e.get("va")
                    if n and va:
                        m.setdefault(n, [])
                        if va not in m[n]:
                            m[n].append(va)
                        mods[(n, va)] = mod
            if sentinel in m:
                break
            time.sleep(0.4)
        self._exports = m
        self._export_mod = mods
        return m

    def api_addrs(self, sym):
        """The address to arm for an API — exactly ONE where possible.

        kernel32 exports are thin stubs that jump into kernelbase. Arming both hooks the same
        call twice: duplicate events, and a run-to-return that stops at the SECOND hook instead of
        the real return (measured: every kernel32.VirtualAlloc 'returned base' was really dwSize).
        So prefer the kernelbase body for kernel32/kernelbase APIs, ntdll for ntdll APIs."""
        dll, _, name = sym.rpartition(".")
        dll = dll.lower()
        hits = (getattr(self, "_exports", {}) or {}).get(name, [])
        if len(hits) > 1:
            mods = getattr(self, "_export_mod", {}) or {}
            kb = [h for h in hits if mods.get((name, h)) == "kernelbase.dll"]
            if kb and dll in ("kernel32", "kernelbase", ""):
                return kb[:1]
            mine = [h for h in hits if str(mods.get((name, h), "")).startswith(dll)] if dll else []
            return (mine or hits)[:1]
        if hits:
            return hits
        a = self.resolve(sym, tries=2)        # fallback to eval
        return [a] if a else []

    def reg(self, *names):
        r = self.call("register_get_batch", {"names": list(names)})
        out = {}
        for x in (r.get("registers", []) if isinstance(r, dict) else []):
            out[x["name"]] = int(x["value"], 16) if x.get("success") else None
        return out

    def cmd(self, c):
        """Native x64dbg/x32dbg script command (the reliable run engine — the
        MCP debug_run/debug_run_to primitives behave inconsistently here)."""
        return self.call("script_execute", {"command": c})

    def _confirm_paused(self, e):
        """Registers are only readable when the debuggee is TRULY paused. Use that to
        confirm a suspected breakpoint hit that debug_get_state mis-reported as
        'running' (a known quirk of this plugin build). Returns True if a register read
        yields an instruction pointer matching `e`."""
        try:
            r = self.reg("cip", "eip", "rip")
            for k in ("cip", "eip", "rip"):
                v = r.get(k)
                if v is not None and _norm(v) == _norm(e):
                    return True
        except Exception:
            pass
        return False

    def _poll_pause(self, pre, secs, require_new=True, stable_needed=5):
        """Poll debug_get_state until the debuggee is paused (or exits/timeout).

        Robust to the plugin quirk where a real breakpoint hit is reported as
        state='running' with a FROZEN eip: if eip holds the same NEW address for
        `stable_needed` consecutive polls, we confirm via a register read and treat it
        as paused. Returns (status, eip): PAUSED / EXITED / TIMEOUT."""
        import time
        pre = (pre or "").lower()
        deadline = time.time() + secs
        last_eip, stable = None, 0
        while time.time() < deadline:
            e, state = self.eip()
            if state == "stopped":
                return "EXITED", e
            if state == "paused" and e and (e != pre or not require_new):
                return "PAUSED", e
            # quirk path: 'running' but eip frozen at a new address -> likely a real hit
            if e and e not in ("", "0x0"):
                if e == last_eip:
                    stable += 1
                else:
                    last_eip, stable = e, 1
                if stable >= stable_needed and (e != pre or not require_new) \
                        and self._confirm_paused(e):
                    return "PAUSED", e
            time.sleep(0.12)
        return "TIMEOUT", self.eip()[0]

    def step(self, cmd, pre_eip, target=None, secs=12):
        """Issue a native run command (async) and return as soon as the debuggee is
        PAUSED at a NEW address (or EXITED). (status, eip): AT_TARGET/PAUSED/EXITED/TIMEOUT."""
        target = (target or "").lower()
        self.cmd(cmd)
        status, e = self._poll_pause(pre_eip, secs, require_new=True)
        if status == "PAUSED" and target and e == target:
            return "AT_TARGET", e
        return status, e

    @staticmethod
    def _pending_dlls(sp):
        """DLL names whose load can make this API armable (advapi32's crypto exports live in cryptsp on newer Windows)."""
        dll = sp["sym"].split(".")[0].lower()
        return {dll} | ({"cryptsp"} if dll == "advapi32" else set())

    def _arm_pending(self, lib, pending, addr2spec, sym2addrs, known_bps):
        """`lib` has just been loaded: arm every still-pending API whose exports it provides. Returns names armed."""
        r = self.call("module_get_exports", {"module": lib + ".dll"})
        exp = {e["name"]: e["va"] for e in (r.get("exports", []) if isinstance(r, dict) else []) if e.get("name") and e.get("va")}
        armed = []
        for sp in list(pending):
            name = sp["sym"].split(".")[-1]
            va = exp.get(name)
            if va and lib in self._pending_dlls(sp):
                self.cmd(f"bp {va}")
                addr2spec[str(va).lower()] = sp
                sym2addrs.setdefault(sp["sym"], []).append(va)
                known_bps.add(_norm(va))
                pending.remove(sp)
                armed.append(name)
        self._armed_addrs = known_bps
        return armed

    def _run_to_return(self, secs=8):
        """Run until the CURRENT function returns. Called while stopped at an API's entry, where
        [esp] (x64: [rsp]) is the return address. Measured live: the plugin's `rtr` did not stop
        reliably (timeout, registers unreadable afterwards), so this is explicit — one-shot
        breakpoint on the return address, resume, wait for the stop, delete the breakpoint.
        Returns (status, eip); status is PAUSED when we are back at the return address."""
        ret = self.resolve("[esp]") or self.resolve("[rsp]")
        if not ret:
            return "NO_RETURN_ADDRESS", self.eip()[0]
        cur = self.eip()[0]
        self.cmd(f"bp {ret}")
        armed = getattr(self, "_armed_addrs", set())
        try:
            status, e = "TIMEOUT", cur
            for _ in range(4):
                status, e = self.step("run", cur, secs=secs)
                if status == "PAUSED" and _norm(e) != _norm(ret) and _norm(e) in armed:
                    cur = e                       # the same call reaching a second armed address: keep going
                    continue
                break
        finally:
            self.cmd(f"bc {ret}")
        if status == "PAUSED" and _norm(e) != _norm(ret):
            status = "STOPPED_ELSEWHERE"            # something else paused us first (another bp / exception)
        return status, e

    def wait_for_pause(self, secs=10):
        """Poll (issuing NO new run command) until the debuggee pauses at a breakpoint
        or exits — used while it is already running past a prior run/erun."""
        return self._poll_pause(None, secs, require_new=False)

    def _where(self, addr):
        """Classify where an eip sits, for live trace heartbeats: the sample's own
        module (unpacker/decryption code), a system DLL, or fresh allocated memory
        (a strong 'already in the unpacked payload' signal)."""
        try:
            v = int(addr, 16) if isinstance(addr, str) else int(addr)
        except Exception:
            return "?"
        m = getattr(self, "_mod", None) or {}
        mb, ms = m.get("base", 0) or 0, m.get("size", 0) or 0
        if mb and mb <= v < mb + ms:
            return "main module (unpacker/decrypt code)"
        if 0x70000000 <= v < 0x80000000:
            return "system DLL"
        prot = ""
        try:
            info = self.call("memory_get_info",
                             {"address": addr if isinstance(addr, str) else hex(v)}) or {}
            prot = str(info.get("protect", "")).lower() if isinstance(info, dict) else ""
        except Exception:
            pass
        if "x" in prot or "execute" in prot:
            return "ALLOCATED EXECUTABLE memory (likely unpacked payload!)"
        return f"other memory (prot={prot or '?'})"

    def run_to(self, target_hex, max_events=40):
        """Run (native) until EIP reaches target, passing system breakpoints and
        first-chance exceptions. For an OEP target use a HARDWARE bp first
        (software bps get overwritten when the unpacker decompresses over them)."""
        target = target_hex.lower()
        last = None
        for _ in range(max_events):
            e, _state = self.eip()
            if e == target:
                return True, e
            cmd = "erun" if (e and e == last) else "run"   # same spot => pass exception
            status, e = self.step(cmd, e, target)
            if status == "AT_TARGET":
                return True, e
            if status == "EXITED":
                return False, e
            last = e
        return False, self.eip()[0]

    def run_to_entry(self, max_events=45, chase_secs=25):
        """Report whether the debuggee is paused AT the EXE entry.

        Resuming is only done in ONE situation: `self._pre_entry` — safe_load paused the program early, in the
        loader, so the entry is certainly still AHEAD. Then we go to it under our own breakpoints (the entry, and
        every TLS callback, which runs before the entry), bounded by `chase_secs`. In every other case we NEVER
        resume to chase the entry (it may already be behind us, and resuming would run the sample unobserved —
        measured on a .NET program). Returns (at_entry, entry, module_info)."""
        import time
        mm, entry = {}, ""
        for _ in range(20):
            mm = self.call("module_get_main")
            entry = ((mm.get("entry") or "") if isinstance(mm, dict) else "").lower()
            if entry:
                break
            time.sleep(0.3)
        if not entry:
            return False, None, mm
        cur, st = self.eip()
        if st == "paused" and cur and _norm(cur) == _norm(entry):
            self.log(f"[api-trace] paused at the entry {entry} — not resuming")
            return True, entry, mm
        if st == "paused" and getattr(self, "_pre_entry", False):
            return self._run_to_entry_from_loader(entry, mm, chase_secs)
        if getattr(self, "_early_paused", False):
            self.log(f"[api-trace] paused EARLY in the loader at {cur or '?'} — before any of the sample's code ran. "
                     f"Arming the API arsenal from here (no chase to the entry: that proved unreliable).")
            return False, entry, mm
        self.log(f"[api-trace] paused at {cur or '?'} [{self._where(cur) if cur else '?'}], NOT at the entry "
                 f"{entry} — NOT resuming to chase it (the entry may already be behind us, and resuming "
                 f"could run the sample unobserved). Arming from here.")
        return False, entry, mm

    def _run_to_entry_from_loader(self, entry, mm, chase_secs=25):
        """Stopped early in the loader: run to the entry under our own breakpoints (entry + TLS callbacks)."""
        import time
        try:
            base = int(str(mm.get("base")), 16)
        except Exception:
            base = 0
        stops = {_norm(entry)}
        self.cmd(f"bph {entry}")
        self.cmd(f"bp {entry}")
        tls = []
        for rva in getattr(self, "_tls_rvas", []) or []:
            if base:
                a = hex(base + int(rva))
                self.cmd(f"bp {a}"); stops.add(_norm(a)); tls.append(a)
        self.log(f"[api-trace] stopped early in the loader, BEFORE any of the sample's code — running to the entry "
                 f"{entry} under our own breakpoints" + (f" (+{len(tls)} TLS callback(s): {', '.join(tls)})" if tls else ""))
        deadline, reached, cur, first = time.time() + chase_secs, False, self.eip()[0], True
        try:
            for _ in range(12):
                left = deadline - time.time()
                if left <= 0:
                    break
                # after OUR pause, or at one of OUR breakpoints -> plain run; at anything else it is an exception -> pass it on
                cmd = "run" if (first or _norm(cur) in stops) else "erun"
                first = False
                status, e = self.step(cmd, cur, secs=max(left, 1))
                if status == "EXITED":
                    self.log("[api-trace] !! the process ended while running to its entry")
                    return False, entry, mm
                if status == "TIMEOUT":
                    break
                if _norm(e) == _norm(entry):
                    reached = True
                    break
                if _norm(e) in stops:
                    self.log(f"[api-trace] stopped in a TLS callback at {e} — sample code is running here (observed)")
                cur = e
        finally:
            for a in [entry] + tls:
                self.cmd(f"bc {a}")
            self.cmd(f"bphwc {entry}")
        if not reached:
            try:
                self.call("debug_pause")                 # never leave it running: take control back
            except Exception:
                pass
            self.log("[api-trace] did not reach the entry within the limit — paused again; arming from here")
        else:
            self.log(f"[api-trace] reached the entry {entry} — nothing of the sample's own code ran before this point")
        return reached, entry, mm

    def neutralize_antidebug(self, arch="x86"):
        """Best-effort anti-anti-debug (the analyst notes: patch IsDebuggerPresent
        so EAX returns 0). Zero PEB!BeingDebugged + NtGlobalFlag so checks that read
        the PEB directly also pass. Guarded: failures never abort the unpack."""
        done = []
        try:
            # PEB!BeingDebugged (offset +2) and PEB->NtGlobalFlag (+0x68 x86 / +0xBC x64)
            peb = self.resolve("peb()") or self.resolve("peb")
            if peb:
                base = int(peb, 16) if isinstance(peb, str) else peb
                # x64dbg syntax is `mov byte:[addr], 0` (measured live; `byte ptr` is silently rejected)
                gf = base + (0xBC if arch == "x64" else 0x68)
                for cmd in (f"mov byte:[{hex(base + 2)}], 0", f"mov dword:[{hex(gf)}], 0"):
                    self.cmd(cmd)
                bd = self.resolve(f"byte({hex(base + 2)})")
                if bd is not None and int(str(bd), 16) == 0:
                    done.append("PEB.BeingDebugged=0 (verified)")
                else:
                    done.append("PEB.BeingDebugged write NOT verified")
        except Exception:
            pass
        # breakpoint IsDebuggerPresent and force the return value to 0 on each hit
        self._antidbg = {}
        for api in ANTIDBG:
            addr = self.resolve(api)
            if addr:
                self.call("breakpoint_set", {"address": addr})
                self._antidbg[_norm(addr)] = api
                if api.endswith("NtQueryInformationProcess"):
                    # Stop ONLY for the three debugger-detection classes. Measured on dridex: it calls this
                    # function 80x with class 0x22 (not a debug query); stopping on every call cost ~200 s of
                    # round trips. The debugger evaluates the condition itself, with no round trip.
                    cls = "edx" if arch == "x64" else "dword(esp+8)"
                    cond = f"{cls}==7||{cls}==0x1e||{cls}==0x1f"
                    self.cmd(f"bpcnd {addr}, {cond}")
                    self._antidbg_cond = cond
                done.append(api)
        return done

    def _neutralize_hit(self, api, arch="x86"):
        """The sample just called a debugger check (stopped at its entry). Let it run to the
        return, then rewrite the result to 'no debugger'. Returns a short description."""
        short = api.split(".")[-1]
        x64 = arch == "x64"
        regs = ["rcx", "rdx", "r8", "r9"]

        def arg(i):                                   # i-th argument (1-based), at function entry
            if x64:
                return self.reg(*regs).get(regs[i - 1])
            v = self.resolve(f"[esp+{hex(4 * i)}]")
            return int(v, 16) if isinstance(v, str) else v

        ret = "rax" if x64 else "eax"
        if short == "NtQueryInformationProcess":
            cls, buf = arg(2), arg(3)
            if cls not in (0x7, 0x1E, 0x1F):          # not a debugger query -> leave it alone
                return f"class {hex(cls) if cls is not None else '?'} (not a debug query)"
            self._run_to_return()
            if buf:
                width = 4 if (cls == 0x1F or not x64) else 8
                val = 1 if cls == 0x1F else 0         # DebugFlags=1 means "not debugged"
                self.call("memory_write", {"address": hex(buf), "data": val.to_bytes(width, "little").hex(),
                                           "encoding": "hex"})
            if cls == 0x1E:                           # DebugObjectHandle: STATUS_PORT_NOT_SET
                self.call("register_set", {"name": ret, "value": "0xC0000353"})
            return f"class {hex(cls)} -> reported 'no debugger'"
        if short == "CheckRemoteDebuggerPresent":
            ptr = arg(2)
            self._run_to_return()
            if ptr:
                self.call("memory_write", {"address": hex(ptr), "data": "00000000", "encoding": "hex"})
            return "reported 'no debugger'"
        if short == "IsDebuggerPresent":
            self._run_to_return()
            self.call("register_set", {"name": ret, "value": "0x0"})
            return "returned 0"
        return "no handler"

    @staticmethod
    def _reg_from_detail(detail: str):
        """'CALL ECX' / 'JMP EAX' -> 'ecx'/'eax'."""
        toks = (detail or "").replace(",", " ").split()
        return toks[-1].lower() if toks else None

    def _maybe_full_module_dump(self, base, out_prefix):
        """When a W->X flip lands inside the main module, dump the FULL module (headers
        + now-decrypted sections) once — that image reconstructs into a clean PE with a
        resolvable import table. Returns the guest dump path, or None."""
        m = self._mod
        if not m or not m.get("base") or not (m["base"] <= base < m["base"] + (m.get("size") or 0)):
            return None
        if getattr(self, "_fm_dumped", False):
            return None
        self._fm_dumped = True
        outp = f"{out_prefix}_fullmodule_{hex(m['base'])}.bin"
        dm = self.call("dump_module", {"module": m["name"], "output_path": outp,
                                       "rebuild_pe": True, "remove_integrity_check": True})
        return outp if isinstance(dm, dict) and dm.get("success") else None

    def _capture(self, sp, args, arch, out_prefix):
        """Capture the memory a watched API exposes (defensive payload recovery)."""
        cap = sp.get("capture")
        if not cap:
            return None
        eax = "rax" if arch == "x64" else "eax"
        try:
            if cap.startswith("str:"):
                p = args.get(cap.split(":", 1)[1])
                if p is not None and 0 < p < 0x10000:       # lpProcName < 64K is an ORDINAL, not a pointer
                    return {"note": f"(by ordinal {p})"}
                return {"note": f'"{self.read_str(p)}"'} if p else None
            if cap == "protect_wx":
                prot = args.get("flNewProtect") or 0
                if prot & PAGE_EXEC:
                    base = args.get("lpAddress"); size = min(args.get("dwSize") or 0x1000, 0x100000)
                    outp = f"{out_prefix}_wx_{hex(base)}.bin"
                    dm = self.call("dump_memory_region", {"address": hex(base), "size": size, "output_path": outp})
                    ok = isinstance(dm, dict) and dm.get("success")
                    rec = {"note": f"W->X region {hex(base)}+{hex(size)}", "dump": outp if ok else None}
                    fm = self._maybe_full_module_dump(base, out_prefix)
                    if fm:
                        rec["module_dump"] = fm; rec["note"] += " [full-module dumped]"
                    return rec
                return {"note": f"protect {hex(prot)} (not exec)"}
            if cap == "nt_protect_wx":
                # native protect: pBase/pSize are POINTERS to the base/size values
                newprot = args.get("newProt") or 0
                if newprot & PAGE_EXEC:
                    pb, ps = args.get("pBase"), args.get("pSize")
                    base = self.resolve(f"[{hex(pb)}]") if pb else None
                    size = self.resolve(f"[{hex(ps)}]") if ps else None
                    base = int(base, 16) if isinstance(base, str) else base
                    size = int(size, 16) if isinstance(size, str) else size
                    if base:
                        size = min(size or 0x40000, 0x100000)
                        outp = f"{out_prefix}_ntwx_{hex(base)}.bin"
                        dm = self.call("dump_memory_region", {"address": hex(base), "size": size, "output_path": outp})
                        ok = isinstance(dm, dict) and dm.get("success")
                        rec = {"note": f"W->X (native) {hex(base)}+{hex(size)}", "dump": outp if ok else None}
                        fm = self._maybe_full_module_dump(base, out_prefix)
                        if fm:
                            rec["module_dump"] = fm; rec["note"] += " [full-module dumped]"
                        return rec
                return {"note": f"NtProtect newProt={hex(newprot)}"}
            if cap == "nt_alloc":
                st_, _ = self._run_to_return()
                if st_ != "PAUSED":
                    return {"note": f"native alloc: return not reached ({st_}) — base not read"}
                pb = args.get("pBase")
                base = self.resolve(f"[{hex(pb)}]") if pb else None
                base = int(base, 16) if isinstance(base, str) else base
                if base:
                    self._watch_regions.append(base)
                    return {"note": f"native alloc base {hex(base)}"}
            if cap == "keyblob":
                # CryptImportKey: pbData[dwDataLen] is the key BLOB — dump it; the analyst
                # can import it to decrypt the config/C2 (key recovery for CryptoAPI malware)
                buf = args.get("pbData"); n = min(args.get("dwDataLen") or 0x200, 0x10000)
                if buf:
                    outp = f"{out_prefix}_keyblob_{hex(buf)}.bin"
                    dm = self.call("dump_memory_region", {"address": hex(buf), "size": n, "output_path": outp})
                    ok = isinstance(dm, dict) and dm.get("success")
                    return {"note": f"KEY BLOB {hex(buf)}+{hex(n)} (import to decrypt config)",
                            "dump": outp if ok else None}
            if cap == "write_src":
                buf = args.get("lpBuffer"); n = min(args.get("nSize") or 0x1000, 0x100000)
                if buf:
                    outp = f"{out_prefix}_wsrc_{hex(buf)}.bin"
                    dm = self.call("dump_memory_region", {"address": hex(buf), "size": n, "output_path": outp})
                    ok = isinstance(dm, dict) and dm.get("success")
                    return {"note": f"source buffer {hex(buf)}+{hex(n)}", "dump": outp if ok else None}
            if cap in ("encrypt_in", "encrypt_in_cng"):
                # file-encryption evidence: the PLAINTEXT is in the buffer at entry and the CIPHERTEXT after the call.
                # A (plaintext, ciphertext) pair from the sample's own run is what lets the cipher be identified
                # and a decryptor be proven by round trip.
                if cap == "encrypt_in":
                    pb, pl = args.get("pbData"), args.get("pdwLen")
                    n = 0
                    if pl:
                        v = self.resolve(f"[{hex(pl)}]"); n = int(v, 16) if isinstance(v, str) else (v or 0)
                    out_ptr = pb
                else:
                    pb, n = args.get("pbInput"), args.get("cbInput") or 0
                    out_ptr = None
                n = min(n or 0x200, 0x4000)
                if not pb:
                    return {"note": "encrypt: no input buffer on this arch"}
                self._enc_n = getattr(self, "_enc_n", 0) + 1
                pin = f"{out_prefix}_encin_{self._enc_n}.bin"
                self.call("dump_memory_region", {"address": hex(pb), "size": n, "output_path": pin})
                rec = {"note": f"ENCRYPT input {hex(pb)}+{hex(n)} (plaintext)", "plain_dump": pin, "encrypt": True,
                       "key_handle": hex(args.get("hKey") or 0)}
                if cap == "encrypt_in":
                    st_, _ = self._run_to_return()
                    if st_ == "PAUSED":
                        pout = f"{out_prefix}_encout_{self._enc_n}.bin"
                        self.call("dump_memory_region", {"address": hex(pb), "size": n + 32, "output_path": pout})
                        rec["cipher_dump"] = pout
                        rec["note"] += f" -> ciphertext captured ({n + 32} bytes)"
                return rec
            if cap == "crypt_out":
                # CryptDecrypt decrypts pbData IN PLACE; at RETURN pbData holds the
                # plaintext and *pdwDataLen its length. This is the in-place decrypt that
                # the W->X trigger can never catch (no VirtualAlloc / no protection flip) —
                # dump it: recovered config / C2 / payload. Tagged `decrypted` for stage-3.
                pb, pl = args.get("pbData"), args.get("pdwDataLen")
                st_, _ = self._run_to_return()   # run to return -> now plaintext
                if st_ != "PAUSED":
                    return {"note": f"CryptDecrypt: return not reached ({st_}) — plaintext not read"}
                n = 0
                if pl:
                    v = self.resolve(f"[{hex(pl)}]")
                    n = int(v, 16) if isinstance(v, str) else (v or 0)
                n = min(n or 0x1000, 0x100000)
                if pb:
                    outp = f"{out_prefix}_decrypted_{hex(pb)}.bin"
                    dm = self.call("dump_memory_region",
                                   {"address": hex(pb), "size": n, "output_path": outp})
                    ok = isinstance(dm, dict) and dm.get("success")
                    return {"note": f"CryptDecrypt plaintext {hex(pb)}+{hex(n)} (recovered config/payload)",
                            "dump": outp if ok else None, "decrypted": True}
                return {"note": "CryptDecrypt (no pbData arg on this arch)"}
            if cap in ("alloc_ret", "map_ret"):
                st_, _ = self._run_to_return()   # run to the return
                if st_ != "PAUSED":
                    return {"note": f"return not reached ({st_}) — return value not read"}
                base = self.reg(eax).get(eax)
                if base and base & 0xFFF:
                    return {"note": f"returned {hex(base)} — not page-aligned, not a base address; ignored"}
                if base:
                    self._watch_regions.append(base)
                    return {"note": f"returned base {hex(base)}"}
            if cap == "decompress_out":
                out = args.get("outBuf"); sz = min(args.get("outCap") or 0x1000, 0x100000)
                st_, _ = self._run_to_return()
                if st_ != "PAUSED":
                    return {"note": f"decompress: return not reached ({st_}) — output not dumped"}
                if out:
                    outp = f"{out_prefix}_decomp_{hex(out)}.bin"
                    dm = self.call("dump_memory_region", {"address": hex(out), "size": sz, "output_path": outp})
                    ok = isinstance(dm, dict) and dm.get("success")
                    return {"note": f"decompressed -> {hex(out)}", "dump": outp if ok else None}
        except Exception as ex:
            return {"note": f"capture error: {ex}"}
        return None

    def api_trace(self, out_prefix, arch="x86", max_events=150, restart=True, plan=None, observe_secs=0):
        """Break on the P1/P2 API arsenal, log each call's arguments LIVE, and capture
        the memory each exposes (allocated / protected / written / decompressed). This
        is the play-by-play an analyst watches to see exactly what the sample does."""
        from .api_spec import API_SPEC, EXIT_APIS
        if restart:
            self.call("debug_restart")
        self.cmd("bc"); self.cmd("bphwc")
        reached, entry, _ = self.run_to_entry()   # reach entry so all DLLs are mapped
        self.cmd("bc")                             # drop the entry bp before arming APIs
        self.build_export_map()                    # read export tables (reliable resolution)
        mm = self.call("module_get_main")
        self._mod = {"name": mm.get("name"),
                     "base": int(mm.get("base", "0"), 16) if isinstance(mm, dict) and mm.get("base") else 0,
                     "size": mm.get("size", 0) if isinstance(mm, dict) else 0}
        self.log(f"[api-trace] at entry {entry} (reached={reached}, "
                 f"{len(self._exports)} exports mapped)")
        if "VirtualAlloc" not in self._exports:
            self.log("[api-trace] WARNING: kernel32 not mapped (no VirtualAlloc export) — the "
                     "debuggee is in a DEGRADED state (often after many restarts in one session). "
                     "RELOAD the sample in a fresh x32dbg for a clean run; results below are partial.")
        elif not reached:
            if getattr(self, "_early_paused", False):
                self.log("[api-trace] note: paused early in the loader — nothing of the sample's code has run; "
                         "the arsenal is armed from this point, so the whole run is observed.")
            else:
              self.log("[api-trace] note: the debugger's first stop was NOT the entry point — anything the "
                     "sample ran before this stop was not observed. kernel32 is mapped and the arsenal is "
                     "armed from here, so the trace below is valid for what happens next.")
        self.neutralize_antidebug(arch)
        addr2spec, sym2addrs = {}, {}
        for sp in API_SPEC:
            for a in self.api_addrs(sp["sym"]):
                self.cmd(f"bp {a}"); addr2spec[str(a).lower()] = sp
                sym2addrs.setdefault(sp["sym"], []).append(a)
        pending = [sp for sp in API_SPEC if not sym2addrs.get(sp["sym"])]
        if pending:
            self.log(f"[api-trace] {len(pending)} API(s) cannot be armed yet — their DLL is not loaded "
                     f"({', '.join(p['sym'].split('.')[-1] for p in pending)}); they will be armed when it loads")
        exits = {}
        for fn in EXIT_APIS:
            for a in self.api_addrs(fn):
                self.cmd(f"bp {a}"); exits[str(a).lower()] = fn
        self.log(f"[api-trace] armed {len(addr2spec)} API breakpoints + {len(exits)} exit-guards; running")
        armed_names = {sp["sym"].split(".")[-1].lower() for sp in addr2spec.values()}
        if not ({"virtualalloc", "virtualprotect", "ntprotectvirtualmemory", "ntallocatevirtualmemory"} & armed_names):
            # a blind run is an UNOBSERVED run: refuse to resume the sample at all
            self.log("[SAFETY] none of the core memory APIs could be armed (kernel32/ntdll exports not "
                     "resolved) — NOT resuming the sample; a blind run would be unobserved")
            return {"trace": [], "counts": {}, "plan_dumps": [], "region_dumps": [], "watched_regions": [],
                    "aborted": "API arsenal could not be armed, so the sample was not resumed"}
        CAP = 12
        # AI static->dynamic plan (already validated by ai.dynamic_plan.validate): its priority
        # APIs get a 3x noise cap so they stay armed longer; its watch regions are dumped below.
        prio = {str(p.get("api", "")).lower() for p in ((plan or {}).get("priority_apis") or [])}
        if plan:
            self.log(f"[plan] AI plan applied: {len(prio)} priority API(s) {sorted(prio)}, "
                     f"{len((plan or {}).get('watch_regions') or [])} watch region(s)")
        self._fm_dumped = False; self._fm_countdown = 8
        import time as _t
        trace, counts, last = [], {}, None
        known_bps = ({_norm(a) for a in addr2spec} | set(getattr(self, "_antidbg", {}))
                     | {_norm(a) for a in exits})
        antidbg_hits, unknown_hits = {}, {}
        _last_rearm = 0.0
        null_hits = {}
        observe_deadline = None
        self._armed_addrs = known_bps
        wall_deadline = _t.time() + 900            # 15-min hard cap on the whole trace
        running_now = False                         # True while the debuggee runs past our last cmd
        waits = 0                                   # consecutive "still running" heartbeats
        logged = 0
        while (logged < max_events or observe_deadline is not None) and _t.time() < wall_deadline:
            if running_now:
                status, e = self.wait_for_pause(secs=10)   # already running — just watch for a bp
            else:
                cmd = "erun" if (last and last == self.eip()[0]) else "run"
                # resuming from a known breakpoint: the sample may hit the SAME one again at once,
                # so wait only briefly before deciding whether that happened
                status, e = self.step(cmd, last, secs=(3 if (last and _norm(last) in known_bps) else 12))
            if status == "EXITED":
                self.log("[api-trace] debuggee exited"); break
            if status == "TIMEOUT":
                e2, st2 = self.eip()
                if st2 == "paused" and e2 and _norm(e2) in known_bps:
                    status, e = "PAUSED", e2        # the same armed breakpoint hit again: a real event, not a stall
            if status == "TIMEOUT":
                # the debuggee is executing without hitting an armed bp (e.g. a decryption
                # loop before it calls VirtualAlloc). Keep watching; log WHERE eip is so we can
                # tell real progress (own code / system dll / fresh allocated payload) from a hang.
                if observe_deadline is not None and _t.time() >= observe_deadline:
                    self.log("[api-trace] observation window over — stopping"); break
                running_now = True; waits += 1
                moved = (e != last)
                self.log(f"[api-trace] …still running (wait #{waits}, eip={e} "
                         f"[{self._where(e)}], {'moving' if moved else 'SAME-eip'})")
                last = e
                continue
            # a breakpoint fired -> the debuggee is paused at a known address
            running_now = False; waits = 0
            last = e
            if not e:
                continue
            el = e.lower()
            if el in exits:
                self.log(f"[api-trace] reached {exits[el]} — stopping"); break
            if pending and _t.time() - _last_rearm > 4:
                # DLLs the sample statically imports are mapped by the loader (no LoadLibrary call to catch):
                # re-check the still-pending APIs whenever we are paused anyway, throttled.
                _last_rearm = _t.time()
                for _lib in sorted({d for p_ in pending for d in self._pending_dlls(p_)}):
                    try:
                        got = self._arm_pending(_lib, pending, addr2spec, sym2addrs, known_bps)
                    except Exception:
                        got = []
                    if got:
                        self.log(f"[api-trace] late-armed (module now loaded) {_lib}: {', '.join(got)}")
            ad = getattr(self, "_antidbg", {}).get(_norm(el))
            if ad:                                   # the sample is checking for a debugger
                antidbg_hits[ad] = antidbg_hits.get(ad, 0) + 1
                n = antidbg_hits[ad]
                try:
                    what = self._neutralize_hit(ad, arch)
                except Exception as exc:
                    what = f"neutralize failed: {exc}"
                if n <= 3 or n % 25 == 0:
                    self.log(f"[anti-debug] {ad} called by the sample (#{n}) — {what}")
                if n >= 80:
                    self.cmd(f"bpc {e}")
                    self.log(f"[anti-debug] {ad} hit {n}x — breakpoint removed (the sample polls it in a loop)")
                last = self.eip()[0] or e
                continue
            sp = addr2spec.get(el)
            if not sp:
                # a pause at an address that is not in the arsenal: never silent, never a livelock
                unknown_hits[el] = unknown_hits.get(el, 0) + 1
                if unknown_hits[el] <= 3:
                    self.log(f"[api-trace] paused at {e} [{self._where(e)}] — not an arsenal address "
                             f"(#{unknown_hits[el]})")
                if unknown_hits[el] >= 8:
                    self.cmd(f"bpc {e}")
                    self.log(f"[api-trace] {e} hit {unknown_hits[el]}x — breakpoint removed (livelock guard)")
                continue
            counts[sp["sym"]] = counts.get(sp["sym"], 0) + 1
            if sp.get("behavior") and str(sp.get("capture") or "").startswith("str:"):
                # a behaviour sentinel whose name/URL/path argument is NULL (e.g. the runtime creating unnamed
                # mutexes) is not evidence: it must not use up the 3-call budget before the sample's own call arrives
                if not self.read_args(sp, arch).get(sp["capture"].split(":", 1)[1]):
                    counts[sp["sym"]] -= 1
                    null_hits[sp["sym"]] = null_hits.get(sp["sym"], 0) + 1
                    if null_hits[sp["sym"]] >= 40:
                        for a in sym2addrs.get(sp["sym"], []):
                            self.cmd(f"bpc {a}")
                        self.log(f"[api-trace] {sp['sym']} called 40x with a NULL argument — breakpoint removed")
                    continue
            if not sp.get("behavior"):
                logged += 1                      # behaviour sentinels never eat the unpack-event budget
            # a chatty API (e.g. GetProcAddress, called hundreds of times) would dominate
            # run time — once past the cap, DELETE its breakpoint so it stops being hit.
            _cap = sp.get("cap") or (CAP * 3 if sp["sym"].split(".")[-1].lower() in prio else CAP)
            if counts[sp["sym"]] >= _cap:
                for a in sym2addrs.get(sp["sym"], []):
                    self.cmd(f"bpc {a}")
                self.log(f"[api-trace] {sp['sym']} hit {_cap}x — breakpoint removed "
                         f"({'behaviour sentinel: proven, count is >= ' + str(_cap) if sp.get('behavior') else 'noise cap'})")
                if sp.get("behavior"):
                    # the last allowed hit is still a real call: record it (args only, no run-to-return capture)
                    _a = self.read_args(sp, arch)
                    trace.append({"api": sp["sym"], "cat": sp["cat"], "n": counts[sp["sym"]], "behavior": sp["behavior"],
                                  "args": {k: (hex(v) if isinstance(v, int) else v) for k, v in _a.items()}})
                continue
            args = self.read_args(sp, arch)
            shown = ", ".join(f"{k}={hex(v) if isinstance(v, int) else v}"
                              for k, v in list(args.items())[:4])
            cap = self._capture(sp, args, arch, out_prefix)
            note = (" -> " + cap["note"]) if cap and cap.get("note") else ""
            self.log(f"[api-trace] #{counts[sp['sym']]} {sp['sym']}({shown}){note}")
            ev = {"api": sp["sym"], "cat": sp["cat"], "n": counts[sp["sym"]],
                  "args": {k: (hex(v) if isinstance(v, int) else v) for k, v in args.items()}}
            if sp.get("behavior"):
                ev["behavior"] = sp["behavior"]
            if cap:
                ev["capture"] = cap
            trace.append(ev)
            if pending and sp["sym"].split(".")[-1].startswith("LoadLibrary"):
                lib = str((cap or {}).get("note", "")).strip('"').lower().replace("\\", "/").split("/")[-1]
                lib = lib[:-4] if lib.endswith(".dll") else lib
                if any(lib in self._pending_dlls(p) for p in pending):
                    st_, _ = self._run_to_return()                       # let the DLL finish loading
                    if st_ == "PAUSED":
                        got = self._arm_pending(lib, pending, addr2spec, sym2addrs, known_bps)
                        if got:
                            self.log(f"[api-trace] {lib}.dll loaded — late-armed: {', '.join(got)}")
                    last = self.eip()[0] or last
            # EARLY STOP: once the module's W->X payload is captured + dumped, the unpack
            # is done — trace a few more events for context then stop (keeps batch fast).
            if getattr(self, "_fm_dumped", False):
                since_fm = getattr(self, "_fm_countdown", 8) - 1
                self._fm_countdown = since_fm
                if since_fm <= 0:
                    if observe_secs > 0:
                        # opt-in: let the unpacked payload keep running under the behaviour sentinels
                        if observe_deadline is None:
                            observe_deadline = _t.time() + observe_secs
                            self.log(f"[api-trace] payload captured — OBSERVING it for {observe_secs}s "
                                     f"(it is executing: the VM will be dirty)")
                            wall_deadline = max(wall_deadline, observe_deadline + 60)
                        if _t.time() < observe_deadline:
                            continue
                        self.log("[api-trace] observation window over — stopping")
                        break
                    self.log("[api-trace] payload captured — stopping trace (early-stop)")
                    break

        # dump the regions the sample allocated — they hold the decoded payload
        # dump the regions the AI plan flagged (runtime base + RVA) — guarded: never breaks the trace
        plan_dumps = []
        try:
            mbase = (getattr(self, "_mod", None) or {}).get("base") or 0
            for w in ((plan or {}).get("watch_regions") or []):
                if not mbase:
                    break
                addr, size = mbase + int(w["rva"]), int(w["size"])
                outp = f"{out_prefix}_plan_{int(w['rva']):x}.bin"
                dm = self.call("dump_memory_region", {"address": hex(addr), "size": size, "output_path": outp})
                ok = isinstance(dm, dict) and dm.get("success")
                self.log(f"[plan] watch region rva=0x{int(w['rva']):x} ({hex(addr)}+{hex(size)}) "
                         f"-> {'dumped' if ok else 'FAILED'}  ({w.get('why', '')[:80]})")
                if ok:
                    plan_dumps.append({"rva": hex(int(w["rva"])), "addr": hex(addr), "size": size,
                                       "dump": outp, "why": w.get("why", "")})
        except Exception as exc:
            self.log(f"[plan] watch-region dump skipped: {exc}")
        region_dumps = []
        for i, base in enumerate(dict.fromkeys(self._watch_regions)):
            if i >= 8:
                break
            outp = f"{out_prefix}_region{i}_{hex(base)}.bin"
            dm = self.call("dump_memory_region", {"address": hex(base), "size": 0x40000, "output_path": outp})
            if isinstance(dm, dict) and dm.get("success"):
                region_dumps.append({"base": hex(base), "dump": outp, "size": dm.get("dumped_size")})
                self.log(f"[api-trace] dumped allocated region {hex(base)} -> {outp}")
        return {"trace": trace, "counts": counts, "plan_dumps": plan_dumps,
                "watched_regions": [hex(r) for r in self._watch_regions],
                "region_dumps": region_dumps}

    def _resolve_and_dump(self, s, out_prefix, mbase, msize):
        """At a hit indirect-transfer site: resolve the target (register, or [esp] for
        push-ret), classify where it points, and dump that memory region."""
        addr = s["addr"]; reg = s.get("reg")
        is_pushret = s.get("type") == "push_ret"
        rec = {"site": addr, "reg": "[esp]" if is_pushret else reg, "detail": s.get("detail"),
               "reached": True, "target": None, "region": None,
               "classification": None, "dump_path": None}
        if is_pushret:
            self.cmd("sti")                       # execute the PUSH so [esp] = ret target
            val = self.resolve("[esp]")
        else:
            val = self.reg(reg).get(reg) if reg else None
        val = int(val, 16) if isinstance(val, str) else val
        if not val:
            return rec
        rec["target"] = hex(val)
        info = self.call("memory_get_info", {"address": hex(val)})
        rec["region"] = info if isinstance(info, dict) else None
        in_module = mbase and mbase <= val < mbase + (msize or 0)
        prot = (info or {}).get("protect", "") if isinstance(info, dict) else ""
        if in_module:
            rec["classification"] = "inside main module (intra-module call)"
        elif "x" in str(prot).lower() or "execute" in str(prot).lower():
            rec["classification"] = "FRESH EXECUTABLE REGION — likely unpacked payload"
        else:
            rec["classification"] = "outside module (resolved API or data)"
        base = (info or {}).get("base") or hex(val & ~0xFFF)
        size = (info or {}).get("size") or 0x40000
        outp = f"{out_prefix}_{(reg or 'esp')}_{addr.replace('0x','')}.bin"
        dm = self.call("dump_memory_region",
                       {"address": base if str(base).startswith("0x") else hex(base),
                        "size": size, "output_path": outp})
        if isinstance(dm, dict) and dm.get("success"):
            rec["dump_path"] = outp; rec["dump_size"] = dm.get("dumped_size")
        self.log(f"[hint-dump] {s.get('detail')} @ {addr} -> {reg}={rec['target']} "
                 f"[{rec['classification']}] dumped={bool(rec['dump_path'])}")
        return rec

    def hint_driven_dump(self, sites, out_prefix, antidebug=True, max_events=60):
        """SINGLE-PASS. Static flags indirect transfers (`call reg`, push/ret) where a
        register points at code the packer just wrote. These sites live in the crypter's
        own .text (NOT overwritten), so we software-breakpoint ALL of them at once, add
        an exit-guard, run ONCE, and resolve+dump at each site in real execution order.
        Stops as soon as a target lands in a FRESH EXECUTABLE REGION — that's the
        unpacked payload, dumped BEFORE it runs. Fast + reliable (no per-site restart)."""
        mm = self.call("module_get_main")
        mbase = int(mm.get("base", "0"), 16) if isinstance(mm, dict) and mm.get("base") else 0
        msize = mm.get("size", 0) if isinstance(mm, dict) else 0

        self.call("debug_restart"); self.cmd("bc"); self.cmd("bphwc")
        self.run_to_entry()                        # reach entry so exit-guard symbols resolve
        self.cmd("bc"); self.build_export_map()
        if antidebug:
            self.neutralize_antidebug()

        by_addr = {}
        for s in sites:
            a = (s["addr"] if str(s["addr"]).startswith("0x") else "0x" + str(s["addr"])).lower()
            s = dict(s); s["addr"] = a
            s["reg"] = s.get("reg") or self._reg_from_detail(s.get("detail", ""))
            by_addr[a] = s
            self.cmd(f"bp {a}")                    # software bp (site in crypter .text)
        # exit-guard: stop before the process can die
        exit_addrs = {}
        for fn in ("kernel32.ExitProcess", "ntdll.NtTerminateProcess",
                   "ntdll.RtlExitUserProcess", "kernel32.TerminateProcess"):
            for a in self.api_addrs(fn):
                self.cmd(f"bp {a}")
                exit_addrs[str(a).lower()] = fn
        self.log(f"[hint-dump] single-pass: {len(by_addr)} site bps + {len(exit_addrs)} exit-guards")

        results, seen, last = [], set(), None
        for _ in range(max_events):
            cmd = "erun" if (last and last == self.eip()[0]) else "run"
            status, e = self.step(cmd, last)
            if status == "EXITED":
                self.log("[hint-dump] debuggee exited"); break
            last = e
            if not e:
                continue
            el = e.lower()
            if el in exit_addrs:
                self.log(f"[hint-dump] reached {exit_addrs[el]} — stopping"); break
            if el in by_addr and el not in seen:
                seen.add(el)
                rec = self._resolve_and_dump(by_addr[el], out_prefix, mbase, msize)
                results.append(rec)
                if rec.get("classification", "").startswith("FRESH EXECUTABLE"):
                    self.log("[hint-dump] unpacked payload captured — stopping before it executes")
                    break
                if len(seen) == len(by_addr):
                    break
        for a, s in by_addr.items():
            if a not in seen:
                results.append({"site": a, "reg": s.get("reg"), "detail": s.get("detail"),
                                "reached": False, "target": None, "region": None,
                                "classification": None, "dump_path": None})
        return results

    def unpack(self, module, out_path, antidebug=True):
        findings = {"module": module, "oep": None, "reached_oep": False,
                    "api_hits": {}, "wx_regions": [], "dump_path": None,
                    "dump_mode": None, "antidebug_patched": []}

        self.log("[engine] restart (clean state)")
        self.call("debug_restart")
        self.cmd("bc"); self.cmd("bphwc")          # clear software + hardware bps

        # reach the EXE entry first (past the loader) so symbols resolve + bps arm in a
        # stable context
        reached, entry, _ = self.run_to_entry()
        self.cmd("bc"); self.build_export_map()
        self.log(f"[engine] at stub entry {entry} (reached={reached})")

        if antidebug:
            findings["antidebug_patched"] = self.neutralize_antidebug()
            self.log(f"[engine] anti-debug neutralized: {findings['antidebug_patched']}")

        d = self.call("dump_detect_oep", {"module": module})
        oep = d.get("oep") if isinstance(d, dict) and d.get("detected") else None
        findings["oep"] = oep
        self.log(f"[engine] detected OEP: {oep}")

        # OEP via HARDWARE bp (survives the unpacker decompressing over it).
        if oep:
            self.cmd(f"bph {oep}")
        # VirtualProtect/VirtualAlloc as software bps (system DLLs -> not overwritten)
        # to count unpack activity + the W->X flip (reqs #2/#3). Break on every module
        # variant (kernel32 stub + kernelbase) so the call is caught either way.
        vp = {int(a, 16) for a in self.api_addrs("kernel32.VirtualProtect")}
        va = {int(a, 16) for a in self.api_addrs("kernel32.VirtualAlloc")}
        for a in vp | va:
            self.cmd(f"bp {hex(a)}")
        # SAFETY NET: break before the process can die, so we never lose the
        # unpacked memory even if the tail-jump outruns the OEP bp.
        exitfns = {}
        for fn in ("kernel32.ExitProcess", "ntdll.NtTerminateProcess",
                   "kernel32.TerminateProcess"):
            for a in self.api_addrs(fn):
                self.cmd(f"bp {a}"); exitfns[int(a, 16)] = fn

        reached, at_exitguard, e, last = False, False, None, None
        for _ in range(60):
            cmd = "erun" if (e and e == last) else "run"
            status, e = self.step(cmd, e, oep)
            if status == "AT_TARGET":
                reached = True
                self.log(f"[engine] *** reached OEP {oep} ***")
                break
            if status == "EXITED":
                self.log("[engine] debuggee exited before we could dump")
                break
            if status == "PAUSED" and e:
                ei = int(e, 16)
                if vp and ei in vp:
                    findings["api_hits"]["VirtualProtect"] = \
                        findings["api_hits"].get("VirtualProtect", 0) + 1
                    r = self.reg("esp")
                    if r.get("esp"):
                        prot = self.call("memory_read", {"address": hex(r["esp"] + 0xC), "size": 4})
                        findings["wx_regions"].append(str(prot)[:60])
                elif va and ei in va:
                    findings["api_hits"]["VirtualAlloc"] = \
                        findings["api_hits"].get("VirtualAlloc", 0) + 1
                elif ei in exitfns:
                    at_exitguard = True
                    self.log(f"[engine] caught {exitfns[ei]} — dumping unpacked memory "
                             "before the process dies")
                    break
            last = e
        findings["reached_oep"] = reached
        findings["caught_at_exit"] = at_exitguard

        # dump the unpacked image. dump_module with auto_detect_oep reconstructs the
        # PE header + sets the entry to the real OEP. (debugger is still live here.)
        _, state = self.eip()
        if state == "stopped":
            findings["dump_path"] = None
            findings["dump_mode"] = "lost_process_exited"
            self.log("[engine] cannot dump: debuggee already exited")
            return findings
        dm = self.call("dump_module", {
            "module": module, "output_path": out_path,
            "auto_detect_oep": True, "rebuild_pe": True,
            "remove_integrity_check": True})
        ok = isinstance(dm, dict) and dm.get("success")
        findings["dump_path"] = out_path if ok else None
        findings["dump_mode"] = ("module_oep" if reached else
                                 "module_exitguard" if at_exitguard else "module_autodetect")
        findings["dump_new_ep"] = dm.get("new_ep") if ok else None
        self.log(f"[engine] dump_module: {dm}")
        return findings
