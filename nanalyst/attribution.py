"""Author / build-environment reconnaissance.

The PE file leaks a surprising amount about WHO built it and on WHAT machine.
This module mines those artifacts for the Proof of Compromise:

  - compile timestamp (IMAGE_FILE_HEADER.TimeDateStamp) + sanity flags
  - PDB path from the debug directory -> build-machine USERNAME, drive, project name
  - Rich header -> MSVC toolchain fingerprint (@comp.id build IDs) = a per-build
    signature useful for clustering samples from the same author/environment
  - version-info resource -> CompanyName / Author / OriginalFilename / Comments
  - resource LANGUAGE / codepage -> the author's likely locale (e.g. ru=0x419,
    zh-CN=0x804) — a classic attribution hint
  - debug timestamp, linker version, overlay author strings

Everything here is STATIC (no execution). Findings are hints, not proof — stated
as such.
"""
from __future__ import annotations

import datetime

try:
    import pefile
except Exception:  # pragma: no cover
    pefile = None

# resource language IDs that commonly hint at author locale
LANG_HINTS = {
    0x0409: "English (US)", 0x0809: "English (UK)",
    0x0419: "Russian", 0x0422: "Ukrainian", 0x0423: "Belarusian",
    0x0804: "Chinese (PRC)", 0x0404: "Chinese (Taiwan)",
    0x0412: "Korean", 0x0411: "Japanese",
    0x0407: "German", 0x040C: "French", 0x0410: "Italian",
    0x040A: "Spanish", 0x0416: "Portuguese (Brazil)",
    0x041F: "Turkish", 0x0401: "Arabic", 0x040E: "Hungarian",
    0x0415: "Polish", 0x0418: "Romanian", 0x0419419: "Russian",
}

# TimeDateStamps known to be compiler-faked (not real build times)
FAKE_STAMPS = {0x2A425E19}  # Delphi fixed stamp (1992-06-19)


def _ts(val: int) -> dict:
    out = {"raw": val, "utc": None, "suspicious": None}
    if not val:
        out["suspicious"] = "zero (stripped/zeroed timestamp)"
        return out
    if val in FAKE_STAMPS:
        out["suspicious"] = "known compiler-faked stamp (e.g. Delphi)"
    try:
        dt = datetime.datetime.utcfromtimestamp(val)
        out["utc"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        now = datetime.datetime.utcnow()
        if dt > now:
            out["suspicious"] = "timestamp is in the FUTURE (forged)"
        elif dt.year < 2000:
            out["suspicious"] = out["suspicious"] or f"implausibly old ({dt.year})"
    except Exception:
        out["suspicious"] = "unparseable"
    return out


def _pdb(pe) -> dict | None:
    try:
        for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
            ent = getattr(dbg, "entry", None)
            if ent is None:
                continue
            path = getattr(ent, "PdbFileName", None)
            if path:
                p = path.rstrip(b"\x00").decode("latin-1", "replace") if isinstance(path, bytes) else str(path).rstrip("\x00")
                info = {"pdb_path": p}
                # mine the path: C:\Users\<name>\...\project\x64\Release\foo.pdb
                low = p.replace("/", "\\")
                parts = low.split("\\")
                if "users" in [x.lower() for x in parts]:
                    i = [x.lower() for x in parts].index("users")
                    if i + 1 < len(parts):
                        info["build_username"] = parts[i + 1]
                proj = [x for x in parts if x and x.lower() not in
                        ("c:", "users", info.get("build_username", "").lower(),
                         "release", "debug", "x64", "x86", "bin", "obj")]
                if proj:
                    info["project_hint"] = proj[-1].rsplit(".", 1)[0]
                return info
    except Exception:
        pass
    return None


def _rich(pe) -> dict | None:
    try:
        rh = pe.parse_rich_header()
        if not rh:
            return None
        ids = []
        vals = rh.get("values", [])
        # values are flat [compid, count, compid, count, ...]
        for i in range(0, len(vals) - 1, 2):
            comp = vals[i]
            prodid = comp >> 16
            build = comp & 0xFFFF
            ids.append({"prodid": prodid, "build": build, "count": vals[i + 1]})
        return {"xor_key": hex(rh.get("checksum", 0)), "entries": ids[:20],
                "toolchain_builds": sorted({e["build"] for e in ids})}
    except Exception:
        return None


def _versioninfo(pe) -> dict:
    out = {}
    try:
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in (fi if isinstance(fi, list) else [fi]):
                if getattr(entry, "Key", b"") == b"StringFileInfo":
                    for st in entry.StringTable:
                        for k, v in st.entries.items():
                            key = k.decode("latin-1", "replace") if isinstance(k, bytes) else str(k)
                            val = v.decode("latin-1", "replace") if isinstance(v, bytes) else str(v)
                            if val.strip():
                                out[key] = val.strip()
    except Exception:
        pass
    return out


def _languages(pe) -> list:
    langs = set()
    try:
        for rt in getattr(pe, "DIRECTORY_ENTRY_RESOURCE", {}).entries:
            for rid in getattr(rt, "directory", {}).entries:
                for lang in getattr(rid, "directory", {}).entries:
                    lid = getattr(lang, "id", None)
                    if lid:
                        langs.add(lid & 0x3FF if lid > 0x3FF else lid)
    except Exception:
        pass
    named = []
    for l in sorted(langs):
        named.append({"id": hex(l), "name": LANG_HINTS.get(l, LANG_HINTS.get(l & 0x3FF, "unknown"))})
    return named


def analyze(path: str) -> dict:
    """Mine author/build artifacts from the PE. Returns a dict of hints."""
    if pefile is None:
        return {"available": False, "error": "pefile not installed"}
    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception as exc:
        return {"available": False, "error": str(exc)}

    res = {"available": True}
    res["compile_timestamp"] = _ts(getattr(pe.FILE_HEADER, "TimeDateStamp", 0))
    try:
        res["linker_version"] = (f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}."
                                 f"{pe.OPTIONAL_HEADER.MinorLinkerVersion}")
    except Exception:
        pass
    pdb = _pdb(pe)
    if pdb:
        res["pdb"] = pdb
    rich = _rich(pe)
    if rich:
        res["rich_header"] = rich
    vi = _versioninfo(pe)
    if vi:
        res["version_info"] = vi
    langs = _languages(pe)
    if langs:
        res["resource_languages"] = langs

    # a short attribution summary for the report
    res["summary"] = _summarize(res)
    pe.close()
    return res


_AUTHOR_KEYS = ("CompanyName", "LegalCopyright", "Author", "Comments",
                "OriginalFilename", "ProductName", "InternalName")


def _summarize(res: dict) -> list:
    bits = []
    ts = res.get("compile_timestamp", {})
    if ts.get("utc"):
        s = f"Compiled {ts['utc']}"
        if ts.get("suspicious"):
            s += f" (!{ts['suspicious']})"
        bits.append(s)
    elif ts.get("suspicious"):
        bits.append(f"Compile timestamp {ts['suspicious']}")
    pdb = res.get("pdb", {})
    if pdb.get("pdb_path"):
        extra = []
        if pdb.get("build_username"):
            extra.append(f"build user '{pdb['build_username']}'")
        if pdb.get("project_hint"):
            extra.append(f"project '{pdb['project_hint']}'")
        bits.append(f"PDB path leaks: {pdb['pdb_path']}" + (f" ({', '.join(extra)})" if extra else ""))
    vi = res.get("version_info", {})
    authorish = {k: vi[k] for k in _AUTHOR_KEYS if vi.get(k)}
    if authorish:
        bits.append("Version info: " + ", ".join(f"{k}={v}" for k, v in authorish.items()))
    langs = res.get("resource_languages", [])
    hint_langs = [l["name"] for l in langs if l["name"] not in ("unknown", "English (US)")]
    if hint_langs:
        bits.append(f"Resource language hint: {', '.join(sorted(set(hint_langs)))} "
                    "(possible author locale)")
    rh = res.get("rich_header", {})
    if rh.get("toolchain_builds"):
        bits.append(f"MSVC toolchain build IDs {rh['toolchain_builds']} "
                    "(Rich-header fingerprint for same-author clustering)")
    return bits
