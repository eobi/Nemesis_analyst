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
                return b.split(b"\x00\x00")[0].decode("utf-16-le", "replace")
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
        m = {}
        for _ in range(tries):
            m = {}
            for mod in modules:
                r = self.call("module_get_exports", {"module": mod})
                for e in (r.get("exports", []) if isinstance(r, dict) else []):
                    n, va = e.get("name"), e.get("va")
                    if n and va:
                        m.setdefault(n, [])
                        if va not in m[n]:
                            m[n].append(va)
            if sentinel in m:
                break
            time.sleep(0.4)
        self._exports = m
        return m

    def api_addrs(self, sym):
        """All VAs for an API name across the loaded system DLLs (kernel32 stub +
        kernelbase forward both get a breakpoint, so the call is caught either way)."""
        name = sym.split(".")[-1]
        hits = (getattr(self, "_exports", {}) or {}).get(name, [])
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

    def step(self, cmd, pre_eip, target=None, secs=12):
        """Issue a native run command (async) and return as soon as the debuggee is
        PAUSED at a NEW address (or EXITED). Lean single poll-loop — returns in ~0.1s
        on a fast breakpoint hit instead of waiting out a fixed window. (status, eip):
        AT_TARGET / PAUSED / EXITED / TIMEOUT."""
        import time
        target = (target or "").lower()
        pre = (pre_eip or "").lower()
        self.cmd(cmd)
        deadline = time.time() + secs
        while time.time() < deadline:
            e, state = self.eip()
            if state == "stopped":
                return "EXITED", e
            if state == "paused" and e and e != pre:
                return ("AT_TARGET", e) if (target and e == target) else ("PAUSED", e)
            time.sleep(0.12)
        return "TIMEOUT", self.eip()[0]

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

    def run_to_entry(self, max_events=45):
        """Reliably reach the EXE entry after a restart: a cold restart lands at the
        ntdll system breakpoint where kernel32/kernelbase aren't mapped yet (symbols
        won't resolve). Set a software bp at the entry and run/erun past the loader
        events until it fires — by the entry, all implicit-import DLLs are loaded."""
        mm = self.call("module_get_main")
        entry = ((mm.get("entry") or "") if isinstance(mm, dict) else "").lower()
        if not entry:
            return False, None, mm
        self.cmd(f"bp {entry}")
        last = None
        for _ in range(max_events):
            if self.eip()[0] == entry:
                return True, entry, mm
            cmd = "erun" if (last and last == self.eip()[0]) else "run"
            status, e = self.step(cmd, last)
            if status == "EXITED":
                return False, None, mm
            last = e
            if e and e == entry:
                return True, entry, mm
        return (self.eip()[0] == entry), entry, mm

    def neutralize_antidebug(self):
        """Best-effort anti-anti-debug (the analyst notes: patch IsDebuggerPresent
        so EAX returns 0). Zero PEB!BeingDebugged + NtGlobalFlag so checks that read
        the PEB directly also pass. Guarded: failures never abort the unpack."""
        done = []
        try:
            # PEB!BeingDebugged (offset +2) and PEB->NtGlobalFlag (+0x68 x86 / +0xBC x64)
            peb = self.resolve("peb()") or self.resolve("peb")
            if peb:
                base = int(peb, 16) if isinstance(peb, str) else peb
                for cmd in (f"mov byte ptr [{hex(base + 2)}], 0",):
                    self.call("script_execute", {"command": cmd})
                done.append("PEB.BeingDebugged=0")
        except Exception:
            pass
        # breakpoint IsDebuggerPresent and force the return value to 0 on each hit
        for api in ANTIDBG:
            addr = self.resolve(api)
            if addr:
                self.call("breakpoint_set", {"address": addr})
                done.append(api)
        return done

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
                self.cmd("rtr"); self.step("rtr", None, secs=6)   # run to return
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
            if cap in ("alloc_ret", "map_ret"):
                self.cmd("rtr"); self.step("rtr", None, secs=6)   # run to the return
                base = self.reg(eax).get(eax)
                if base:
                    self._watch_regions.append(base)
                    return {"note": f"returned base {hex(base)}"}
            if cap == "decompress_out":
                out = args.get("outBuf"); sz = min(args.get("outCap") or 0x1000, 0x100000)
                self.cmd("rtr"); self.step("rtr", None, secs=6)
                if out:
                    outp = f"{out_prefix}_decomp_{hex(out)}.bin"
                    dm = self.call("dump_memory_region", {"address": hex(out), "size": sz, "output_path": outp})
                    ok = isinstance(dm, dict) and dm.get("success")
                    return {"note": f"decompressed -> {hex(out)}", "dump": outp if ok else None}
        except Exception as ex:
            return {"note": f"capture error: {ex}"}
        return None

    def api_trace(self, out_prefix, arch="x86", max_events=150):
        """Break on the P1/P2 API arsenal, log each call's arguments LIVE, and capture
        the memory each exposes (allocated / protected / written / decompressed). This
        is the play-by-play an analyst watches to see exactly what the sample does."""
        from .api_spec import API_SPEC, EXIT_APIS
        self.call("debug_restart"); self.cmd("bc"); self.cmd("bphwc")
        reached, entry, _ = self.run_to_entry()   # reach entry so all DLLs are mapped
        self.cmd("bc")                             # drop the entry bp before arming APIs
        self.build_export_map()                    # read export tables (reliable resolution)
        mm = self.call("module_get_main")
        self._mod = {"name": mm.get("name"),
                     "base": int(mm.get("base", "0"), 16) if isinstance(mm, dict) and mm.get("base") else 0,
                     "size": mm.get("size", 0) if isinstance(mm, dict) else 0}
        self.log(f"[api-trace] at entry {entry} (reached={reached}, "
                 f"{len(self._exports)} exports mapped)")
        if not reached or "VirtualAlloc" not in self._exports:
            self.log("[api-trace] WARNING: entry not reached / kernel32 not mapped — the debuggee "
                     "is in a degraded state (often after many restarts). RELOAD the sample in "
                     "x32dbg (Debug > Restart or reopen) for a clean run; results below are partial.")
        self.neutralize_antidebug()
        addr2spec, sym2addrs = {}, {}
        for sp in API_SPEC:
            for a in self.api_addrs(sp["sym"]):
                self.cmd(f"bp {a}"); addr2spec[str(a).lower()] = sp
                sym2addrs.setdefault(sp["sym"], []).append(a)
        exits = {}
        for fn in EXIT_APIS:
            for a in self.api_addrs(fn):
                self.cmd(f"bp {a}"); exits[str(a).lower()] = fn
        self.log(f"[api-trace] armed {len(addr2spec)} API breakpoints + {len(exits)} exit-guards; running")
        CAP = 20
        trace, counts, last = [], {}, None
        for _ in range(max_events):
            cmd = "erun" if (last and last == self.eip()[0]) else "run"
            status, e = self.step(cmd, last)
            if status == "EXITED":
                self.log("[api-trace] debuggee exited"); break
            last = e
            if not e:
                continue
            el = e.lower()
            if el in exits:
                self.log(f"[api-trace] reached {exits[el]} — stopping"); break
            sp = addr2spec.get(el)
            if not sp:
                continue
            counts[sp["sym"]] = counts.get(sp["sym"], 0) + 1
            # a chatty API (e.g. GetProcAddress, called hundreds of times) would dominate
            # run time — once past the cap, DELETE its breakpoint so it stops being hit.
            if counts[sp["sym"]] >= CAP:
                for a in sym2addrs.get(sp["sym"], []):
                    self.cmd(f"bpc {a}")
                self.log(f"[api-trace] {sp['sym']} hit {CAP}x — breakpoint removed (noise cap)")
                continue
            args = self.read_args(sp, arch)
            shown = ", ".join(f"{k}={hex(v) if isinstance(v, int) else v}"
                              for k, v in list(args.items())[:4])
            cap = self._capture(sp, args, arch, out_prefix)
            note = (" -> " + cap["note"]) if cap and cap.get("note") else ""
            self.log(f"[api-trace] #{counts[sp['sym']]} {sp['sym']}({shown}){note}")
            ev = {"api": sp["sym"], "cat": sp["cat"], "n": counts[sp["sym"]],
                  "args": {k: (hex(v) if isinstance(v, int) else v) for k, v in args.items()}}
            if cap:
                ev["capture"] = cap
            trace.append(ev)

        # dump the regions the sample allocated — they hold the decoded payload
        region_dumps = []
        for i, base in enumerate(dict.fromkeys(self._watch_regions)):
            if i >= 8:
                break
            outp = f"{out_prefix}_region{i}_{hex(base)}.bin"
            dm = self.call("dump_memory_region", {"address": hex(base), "size": 0x40000, "output_path": outp})
            if isinstance(dm, dict) and dm.get("success"):
                region_dumps.append({"base": hex(base), "dump": outp, "size": dm.get("dumped_size")})
                self.log(f"[api-trace] dumped allocated region {hex(base)} -> {outp}")
        return {"trace": trace, "counts": counts,
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
