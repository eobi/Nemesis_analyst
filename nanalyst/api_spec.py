"""API breakpoint spec for the dynamic unpacking tracer (defensive analysis).

Reference data: for each watched API, the entry-time argument locations
(x86 = ESP offsets; x64 = rcx/rdx/r8/r9 then stack) and what memory the tracer
captures so a decoded payload is recovered for the report.

Each entry: (symbol, category, priority, capture, x86_args, x64_argnames)
  x86_args     : list of (argname, esp_offset_at_entry)
  x64_argnames : names of the first four args (rcx,rdx,r8,r9), rest on stack
  capture      : alloc_ret | protect_wx | write_src | decompress_out | map_ret
                 | str:<argname> | None
"""
from __future__ import annotations

_RAW = [
    ("kernel32.VirtualAlloc", "alloc", 1, "alloc_ret",
     [("lpAddress", 0x4), ("dwSize", 0x8), ("flType", 0xC), ("flProtect", 0x10)],
     ["lpAddress", "dwSize", "flType", "flProtect"]),
    ("kernel32.VirtualAllocEx", "alloc-remote", 1, "alloc_ret",
     [("hProcess", 0x4), ("lpAddress", 0x8), ("dwSize", 0xC), ("flType", 0x10), ("flProtect", 0x14)],
     ["hProcess", "lpAddress", "dwSize", "flType"]),
    ("ntdll.NtAllocateVirtualMemory", "alloc", 1, "nt_alloc",
     [("hProc", 0x4), ("pBase", 0x8), ("zBits", 0xC), ("pSize", 0x10), ("flType", 0x14), ("flProtect", 0x18)],
     ["hProc", "pBase", "zBits", "pSize"]),
    ("kernel32.VirtualProtect", "protect", 1, "protect_wx",
     [("lpAddress", 0x4), ("dwSize", 0x8), ("flNewProtect", 0xC), ("lpOld", 0x10)],
     ["lpAddress", "dwSize", "flNewProtect", "lpOld"]),
    ("kernel32.VirtualProtectEx", "protect-remote", 1, None,
     [("hProcess", 0x4), ("lpAddress", 0x8), ("dwSize", 0xC), ("flNewProtect", 0x10), ("lpOld", 0x14)],
     ["hProcess", "lpAddress", "dwSize", "flNewProtect"]),
    ("ntdll.NtProtectVirtualMemory", "protect", 1, "nt_protect_wx",
     [("hProc", 0x4), ("pBase", 0x8), ("pSize", 0xC), ("newProt", 0x10), ("pOld", 0x14)],
     ["hProc", "pBase", "pSize", "newProt"]),
    ("kernel32.WriteProcessMemory", "write-remote", 1, "write_src",
     [("hProcess", 0x4), ("lpBase", 0x8), ("lpBuffer", 0xC), ("nSize", 0x10), ("lpWritten", 0x14)],
     ["hProcess", "lpBase", "lpBuffer", "nSize"]),
    ("ntdll.NtWriteVirtualMemory", "write-remote", 2, "write_src",
     [("hProc", 0x4), ("lpBase", 0x8), ("lpBuffer", 0xC), ("nSize", 0x10), ("lpWritten", 0x14)],
     ["hProc", "lpBase", "lpBuffer", "nSize"]),
    ("kernel32.CreateRemoteThread", "thread-remote", 1, None,
     [("hProcess", 0x4), ("lpSec", 0x8), ("stack", 0xC), ("lpStart", 0x10), ("lpParam", 0x14), ("flags", 0x18)],
     ["hProcess", "lpSec", "stack", "lpStart"]),
    ("ntdll.NtCreateThreadEx", "thread-remote", 2, None,
     [("pThread", 0x4), ("access", 0x8), ("objAttr", 0xC), ("hProc", 0x10), ("lpStart", 0x14)],
     ["pThread", "access", "objAttr", "hProc"]),
    ("kernel32.LoadLibraryA", "load", 1, "str:lpName",
     [("lpName", 0x4)], ["lpName"]),
    ("kernel32.LoadLibraryW", "load", 1, "str:lpName",
     [("lpName", 0x4)], ["lpName"]),
    ("kernel32.LoadLibraryExA", "load", 1, "str:lpName",
     [("lpName", 0x4), ("hFile", 0x8), ("flags", 0xC)], ["lpName", "hFile", "flags"]),
    ("kernel32.GetProcAddress", "resolve", 1, "str:lpProc",
     [("hModule", 0x4), ("lpProc", 0x8)], ["hModule", "lpProc"]),
    ("kernel32.CreateProcessW", "spawn", 1, "str:lpCmd",
     [("lpApp", 0x4), ("lpCmd", 0x8), ("pSec", 0xC), ("tSec", 0x10), ("inherit", 0x14), ("flags", 0x18)],
     ["lpApp", "lpCmd", "pSec", "tSec"]),
    ("kernel32.WinExec", "spawn", 1, "str:lpCmd",
     [("lpCmd", 0x4), ("show", 0x8)], ["lpCmd", "show"]),
    ("ntdll.RtlDecompressBuffer", "decompress", 2, "decompress_out",
     [("fmt", 0x4), ("outBuf", 0x8), ("outCap", 0xC), ("inBuf", 0x10), ("inSize", 0x14), ("pOutSize", 0x18)],
     ["fmt", "outBuf", "outCap", "inBuf"]),
    ("kernel32.MapViewOfFile", "map", 2, "map_ret",
     [("hMap", 0x4), ("access", 0x8), ("offHi", 0xC), ("offLo", 0x10), ("size", 0x14)],
     ["hMap", "access", "offHi", "offLo"]),
    ("kernel32.FlushInstructionCache", "cache", 2, None,
     [("hProcess", 0x4), ("lpBase", 0x8), ("dwSize", 0xC)], ["hProcess", "lpBase", "dwSize"]),
    # ---- crypto (CryptoAPI) — recover the key material used to decrypt config/C2 ----
    ("advapi32.CryptImportKey", "crypto", 1, "keyblob",
     [("hProv", 0x4), ("pbData", 0x8), ("dwDataLen", 0xC), ("hPubKey", 0x10), ("flags", 0x14)],
     ["hProv", "pbData", "dwDataLen", "hPubKey"]),
    ("advapi32.CryptDeriveKey", "crypto", 1, None,
     [("hProv", 0x4), ("Algid", 0x8), ("hBaseData", 0xC), ("flags", 0x10), ("phKey", 0x14)],
     ["hProv", "Algid", "hBaseData", "flags"]),
    ("advapi32.CryptDecrypt", "crypto", 1, None,
     [("hKey", 0x4), ("hHash", 0x8), ("Final", 0xC), ("flags", 0x10), ("pbData", 0x14), ("pdwDataLen", 0x18)],
     ["hKey", "hHash", "Final", "flags"]),
    ("advapi32.CryptHashData", "crypto", 2, "write_src",
     [("hHash", 0x4), ("lpBuffer", 0x8), ("nSize", 0xC), ("flags", 0x10)],
     ["hHash", "lpBuffer", "nSize", "flags"]),
]

API_SPEC = [
    {"sym": s, "cat": c, "prio": p, "capture": cap, "x86": x86, "x64": x64}
    for (s, c, p, cap, x86, x64) in _RAW
]

EXIT_APIS = ["kernel32.ExitProcess", "ntdll.NtTerminateProcess",
             "ntdll.RtlExitUserProcess", "kernel32.TerminateProcess"]
