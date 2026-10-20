"""PE profiler, the "PE Studio" data layer.

Uses pefile to extract the facts an analyst reads first: architecture, sections
with entropy, imports (and the suspicious ones), exports, TLS callbacks,
resources, digital signature, and overlay. Pure parsing, no execution.
"""
from __future__ import annotations

import pefile
from ..audit import audited

# APIs that, when imported, hint at capability. Grouped so the report and the
# AI brain can reason about *why* something is suspicious, not just that it is.
SUSPICIOUS_APIS = {
    "injection": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "SetThreadContext", "GetThreadContext",
        "QueueUserAPC", "RtlCreateUserThread", "MapViewOfFile",
    ],
    "dynamic_resolution": [
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress",
        "LdrLoadDll", "LdrGetProcedureAddress",
    ],
    "execution": [
        "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA",
        "ShellExecuteW", "CreateProcessInternalW", "system",
    ],
    "anti_analysis": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA", "GetTickCount",
        "QueryPerformanceCounter", "NtSetInformationThread",
    ],
    "network": [
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "HttpOpenRequestA",
        "URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpen", "connect",
        "send", "recv", "WSAStartup", "socket", "gethostbyname",
    ],
    "persistence": [
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "CreateServiceA", "CreateServiceW", "SetWindowsHookExA",
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "BCryptEncrypt",
        "CryptGenKey", "CryptHashData",
    ],
}

# Standard section names; anything else is noteworthy (packer stubs rename them).
_COMMON_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata",
    ".rsrc", ".reloc", ".tls", ".debug", ".CRT", ".gfids", ".didat",
}


@audited("pefile", category="static")
def profile(path: str) -> dict:
    """Return a structured PE profile, or {'error': ...} if it won't parse."""
    try:
        pe = pefile.PE(path, fast_load=False)
    except pefile.PEFormatError as exc:
        return {"error": f"not a valid PE: {exc}"}

    try:
        return _profile(pe, path)
    finally:
        pe.close()


def _profile(pe: "pefile.PE", path: str) -> dict:
    machine = pe.FILE_HEADER.Machine
    arch = {0x14C: "x86", 0x8664: "x64", 0x1C0: "arm", 0xAA64: "arm64"}.get(
        machine, f"0x{machine:x}"
    )
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)

    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_base = pe.OPTIONAL_HEADER.ImageBase

    sections = []
    ep_section = None
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("latin-1", "replace")
        ent = sec.get_entropy()
        execd = bool(sec.Characteristics & 0x20000000)  # MEM_EXECUTE
        writ = bool(sec.Characteristics & 0x80000000)   # MEM_WRITE
        contains_ep = sec.VirtualAddress <= ep_rva < sec.VirtualAddress + max(
            sec.Misc_VirtualSize, sec.SizeOfRawData
        )
        if contains_ep:
            ep_section = name
        sections.append({
            "name": name,
            "vsize": sec.Misc_VirtualSize,
            "rawsize": sec.SizeOfRawData,
            "entropy": round(ent, 2),
            "exec": execd,
            "write": writ,
            "uncommon_name": name not in _COMMON_SECTIONS,
            "contains_ep": contains_ep,
            "w_and_x": execd and writ,
        })

    imports, import_count = _imports(pe)
    suspicious = _match_suspicious(imports)

    has_tls = hasattr(pe, "DIRECTORY_ENTRY_TLS")
    tls_callbacks = _tls_callbacks(pe, image_base) if has_tls else []
    signed = hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and bool(
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress
    )
    exports = _exports(pe)
    overlay_off = pe.get_overlay_data_start_offset()
    overlay = (len(pe.__data__) - overlay_off) if overlay_off else 0

    return {
        "arch": arch,
        "kind": "dll" if is_dll else "exe",
        "entrypoint_rva": ep_rva,
        "entrypoint_section": ep_section,
        "image_base": image_base,
        "sections": sections,
        "import_dll_count": len(imports),
        "import_func_count": import_count,
        "imports": imports,
        "suspicious_apis": suspicious,
        "exports": exports,
        "has_tls": has_tls,
        "tls_callbacks": tls_callbacks,
        "signed": signed,
        "overlay_bytes": overlay,
    }


def _imports(pe) -> tuple[dict, int]:
    out: dict[str, list[str]] = {}
    count = 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("latin-1", "replace") if entry.dll else "?"
        funcs = []
        for imp in entry.imports:
            if imp.name:
                funcs.append(imp.name.decode("latin-1", "replace"))
            elif imp.ordinal is not None:
                funcs.append(f"ordinal_{imp.ordinal}")
        out[dll] = funcs
        count += len(funcs)
    return out, count


def _match_suspicious(imports: dict) -> dict:
    flat = {f for funcs in imports.values() for f in funcs}
    hits: dict[str, list[str]] = {}
    for category, apis in SUSPICIOUS_APIS.items():
        found = sorted(a for a in apis if a in flat)
        if found:
            hits[category] = found
    return hits


def _exports(pe) -> list[str]:
    out = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                out.append(exp.name.decode("latin-1", "replace"))
    return out


def _tls_callbacks(pe, image_base) -> list[int]:
    cbs = []
    try:
        addr = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        if addr:
            rva = addr - image_base
            while True:
                cb = pe.get_dword_at_rva(rva)
                if not cb:
                    break
                cbs.append(cb)
                rva += 4
    except Exception:
        pass
    return cbs
