"""Analyst-grade suspicious CODE / byte-pattern detection.

Beyond strings + imports, a real analyst eyeballs the bytes for tell-tale machine-code
idioms: position-independent shellcode stubs, PEB walks, packer stubs, anti-debug
instructions, stack-string construction, indirect control flow, NOP/int3 sleds, and
embedded PE images. This scans the raw bytes (and PE section anatomy when available) with
reliable opcode signatures and reports what it finds — with offsets — so the report shows
the "funny code" an analyst would flag, not just strings.

Works on any file or buffer (packed sample, unpacked dump, decrypted blob).
"""
from __future__ import annotations

import re

# (id, severity, title, byte-regex, why)  — high-signal, low-false-positive x86/x64 idioms
_SIGS = [
    ("getpc_stub", "high", "Position-independent GetPC stub (call $+5 / pop)",
     rb"\xe8\x00\x00\x00\x00[\x58-\x5f]",
     "shellcode resolving its own address — classic PIC/injected-code idiom"),
    ("peb_walk_x86", "high", "PEB access via fs:[0x30] (x86)",
     rb"\x64\xa1\x30\x00\x00\x00|\x64\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]\x30\x00\x00\x00",
     "walks the PEB to find modules/BeingDebugged without imports (manual API resolution / anti-debug)"),
    ("peb_walk_x64", "high", "PEB access via gs:[0x60] (x64)",
     rb"\x65\x48\x8b[\x00-\xff]\x60\x00\x00\x00|\x65\x48\xa1\x60\x00\x00\x00",
     "x64 PEB walk — manual API resolution / anti-debug"),
    ("rdtsc_timing", "medium", "rdtsc timing check",
     rb"\x0f\x31",
     "reads the CPU timestamp counter — common timing-based anti-debug/anti-sandbox"),
    ("cpuid", "medium", "cpuid instruction",
     rb"\x0f\xa2",
     "queries CPU/hypervisor features — common anti-VM (hypervisor-bit / vendor string) check"),
    ("int2d_antidbg", "high", "int 2Dh anti-debug",
     rb"\xcd\x2d",
     "int 2Dh — a well-known anti-debugging trap (behaves differently under a debugger)"),
    ("int3_sled", "medium", "int3 (0xCC) sled",
     rb"\xcc{6,}",
     "run of int3 bytes — padding/anti-disassembly or a breakpoint trap"),
    ("nop_sled", "medium", "NOP sled",
     rb"\x90{12,}",
     "long NOP run — landing pad typical of shellcode / exploit staging"),
    ("stack_strings", "medium", "Stack-string construction (mov byte [ebp+x], imm)",
     rb"(?:\xc6\x45[\x00-\xff][\x20-\x7e]){5,}",
     "builds ASCII strings on the stack byte-by-byte to hide them from a strings dump"),
    ("indirect_call_reg", "info", "Indirect call through register (call eax..edi)",
     rb"\xff[\xd0-\xd7]",
     "dynamically-resolved call target — obfuscated control flow / runtime API resolution"),
    ("indirect_jmp_reg", "info", "Indirect jump through register (jmp eax..edi)",
     rb"\xff[\xe0-\xe7]",
     "computed jump — tail-call into unpacked code / obfuscated control flow"),
    ("pushad_popad", "medium", "pushad/popad packer stub",
     rb"\x60[\s\S]{4,4096}?\x61",
     "save-all/restore-all register bracket — hallmark of a packer unpacking stub"),
    ("teb_selfmod", "info", "Writable self-reference (GetModuleHandle(NULL) pattern)",
     rb"\x6a\x00\xff\x15",
     "push 0 ; call [import] — often GetModuleHandleA(NULL) before manual mapping"),
]

_SECTION_PACKERS = ("upx", "aspack", ".vmp", "vmp0", "vmp1", "themida", ".enigma", "petite",
                    "mpress", ".nsp", "nspack", ".text1", ".boom", "pec1", ".y0da", "winlice",
                    ".mackt", ".perplex", "kkrunchy", "fsg!", ".taz", "charmve")

MZ = b"MZ"
PE_SIG = b"PE\x00\x00"


def _embedded_pes(data: bytes, limit: int = 8) -> list:
    """Find MZ images embedded at a non-zero offset (dropper/second-stage carrier)."""
    out = []
    start = 1
    while len(out) < limit:
        i = data.find(MZ, start)
        if i < 0:
            break
        start = i + 2
        # validate: e_lfanew at i+0x3C points to a 'PE\0\0' within the buffer
        if i + 0x40 > len(data):
            continue
        try:
            e_lfanew = int.from_bytes(data[i + 0x3C:i + 0x40], "little")
        except Exception:
            continue
        pe_off = i + e_lfanew
        if 0 < e_lfanew < 0x1000 and pe_off + 4 <= len(data) and data[pe_off:pe_off + 4] == PE_SIG:
            out.append(hex(i))
    return out


def _sections(path: str) -> list:
    """PE section anatomy (name, vsize, rawsize, entropy, flags) via pefile, if available."""
    try:
        import pefile
    except Exception:
        return []
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return []
    out = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        out.append({
            "name": name,
            "vsize": int(s.Misc_VirtualSize),
            "rawsize": int(s.SizeOfRawData),
            "entropy": round(s.get_entropy(), 3),
            "exec": bool(s.Characteristics & 0x20000000),
            "write": bool(s.Characteristics & 0x80000000),
        })
    return out


_SUS_MNEMONICS = {
    "rdtsc": "timing anti-debug", "cpuid": "CPU/hypervisor probe (anti-VM)",
    "int3": "breakpoint/anti-disasm", "int1": "anti-debug trap", "syscall": "direct syscall (EDR evasion)",
    "sysenter": "direct syscall", "sidt": "anti-VM (IDT)", "sgdt": "anti-VM (GDT)",
    "sldt": "anti-VM (LDT)", "str": "anti-VM (task register)", "in": "VMware I/O backdoor probe",
    "wrmsr": "MSR write", "rdmsr": "MSR read", "vmcall": "hypervisor call",
}


def _disasm_entry(path: str, count: int = 60) -> dict:
    """Disassemble the entry-point region with Capstone — real instructions an analyst
    reads, with suspicious mnemonics / indirect transfers flagged. Host-side, no Ghidra."""
    try:
        import capstone
        import pefile
    except Exception:
        return {}
    try:
        pe = pefile.PE(path, fast_load=True)
        machine = pe.FILE_HEADER.Machine
        is64 = machine == 0x8664
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        base = pe.OPTIONAL_HEADER.ImageBase
        ep_off = pe.get_offset_from_rva(ep_rva)
        data = pe.__data__[ep_off:ep_off + count * 16]
    except Exception:
        return {}
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
    listing, flags = [], []
    va = base + ep_rva
    try:
        for i, ins in enumerate(md.disasm(bytes(data), va)):
            if i >= count:
                break
            line = f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}".rstrip()
            listing.append(line)
            m = ins.mnemonic.lower()
            if m in _SUS_MNEMONICS:
                flags.append(f"{line}   ; {_SUS_MNEMONICS[m]}")
            elif m in ("call", "jmp") and ("[" in ins.op_str or ins.op_str in
                                           ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
                                            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8",
                                            "r9", "r10", "r11", "r12", "r13", "r14", "r15")):
                flags.append(f"{line}   ; indirect {m} (computed/obfuscated target)")
    except Exception:
        pass
    return {"entry_va": hex(va), "arch": "x64" if is64 else "x86",
            "listing": listing, "flagged": flags}


def scan(src, arch: str = "x86", path: str | None = None) -> dict:
    """Scan raw bytes (+ optional PE sections if `path` given) for suspicious code idioms.
    `src` is a path (str) or bytes. Returns a structured findings dict."""
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    else:
        data = open(src, "rb").read()
        path = path or src

    findings = []
    for sid, sev, title, rx, why in _SIGS:
        hits = list(re.finditer(rx, data))
        if not hits:
            continue
        offs = [hex(m.start()) for m in hits[:8]]
        findings.append({"id": sid, "severity": sev, "title": title,
                         "count": len(hits), "offsets": offs, "why": why})

    embedded = _embedded_pes(data)
    if embedded:
        findings.append({"id": "embedded_pe", "severity": "high",
                         "title": "Embedded PE image(s) at non-zero offset",
                         "count": len(embedded), "offsets": embedded,
                         "why": "a second PE is carried inside this file — dropper / packed payload"})

    sections = _sections(path) if path else []
    packer_secs = [s["name"] for s in sections
                   if any(p in s["name"].lower() for p in _SECTION_PACKERS)]
    high_entropy_secs = [f"{s['name']} (H={s['entropy']})" for s in sections
                         if s["entropy"] >= 7.0 and s["rawsize"] > 0]
    wx_secs = [s["name"] for s in sections if s["exec"] and s["write"]]
    if packer_secs:
        findings.append({"id": "packer_sections", "severity": "high",
                         "title": "Known packer section name(s)", "count": len(packer_secs),
                         "offsets": packer_secs,
                         "why": "section names match a known packer/protector"})
    if high_entropy_secs:
        findings.append({"id": "high_entropy_sections", "severity": "medium",
                         "title": "High-entropy (likely compressed/encrypted) section(s)",
                         "count": len(high_entropy_secs), "offsets": high_entropy_secs,
                         "why": "entropy >= 7.0 indicates packed/encrypted content (hidden payload)"})
    if wx_secs:
        findings.append({"id": "wx_sections", "severity": "medium",
                         "title": "Writable + executable section(s)", "count": len(wx_secs),
                         "offsets": wx_secs,
                         "why": "W+X section — self-modifying code / in-place unpacking"})

    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 3))
    disasm = _disasm_entry(path) if path else {}
    return {
        "arch": arch,
        "scanned_bytes": len(data),
        "findings": findings,
        "sections": sections,
        "entry_disasm": disasm,
        "counts": {sev: sum(1 for f in findings if f["severity"] == sev)
                   for sev in ("high", "medium", "info")},
    }
