"""Framework-aware decompiler router.

Some malware is built with a framework/runtime — AutoIt, PyInstaller, py2exe,
AutoHotkey, NSIS or Inno Setup installers, .NET. The compiled EXE is just the
framework's interpreter stub with the REAL script/bytecode bundled inside, so a
general disassembler (Ghidra/IDA) only shows you the stub. A framework-specific
extractor recovers the ORIGINAL, structured source (e.g. clean .au3 / .py), which
is far more readable and is where the actual logic + IOCs live.

This module (1) DETECTS the framework from file signatures + the triage verdict,
and (2) ROUTES to the matching extractor on the guest over SSH. It is additive:
Ghidra still runs; when a framework is recovered we ALSO get its source and prefer
it in the report. New frameworks are added by extending HANDLERS.

Two execution modes per handler (mirrors how x64dbg is driven in this system):
  - "cli"         : a headless command-line extractor -> fully automated.
  - "interactive" : a GUI tool (e.g. exe2aut) the operator runs on the VM desktop;
                    we stage the input, tell them where to save, then pull + parse.
"""
from __future__ import annotations

import ntpath
import re

from .audit import audited
from pathlib import Path

# ---- detection signatures (scanned in the raw file bytes) ----
SIGNATURES = [
    ("autoit", [b"AU3!EA06", b"AU3!EA05", b">>>AUTOIT SCRIPT<<<",
                b"This is a third-party compiled AutoIt script"]),
    ("autohotkey", [b">AUTOHOTKEY SCRIPT<", b">AHK WITH ", b"AutoHotkeyGUI"]),
    ("pyinstaller", [b"PyInstaller", b"pyiboot01", b"_MEIPASS", b"pyi-runtime"]),
    ("py2exe", [b"PYTHONSCRIPT", b"py2exe"]),
    ("nsis", [b"Nullsoft.NSIS", b"NullsoftInst", b"Nullsoft Install System"]),
    ("innosetup", [b"Inno Setup Setup Data", b"JR.Inno.Setup", b"rDlPtS92"]),
]

# human-readable + whether we have a wired extractor
HANDLERS = {
    "autoit":      {"label": "AutoIt3 compiled script", "source_ext": ".au3", "wired": True},
    "autohotkey":  {"label": "AutoHotkey compiled script", "source_ext": ".ahk", "wired": False},
    "pyinstaller": {"label": "PyInstaller-frozen Python", "source_ext": ".py", "wired": False},
    "py2exe":      {"label": "py2exe-frozen Python", "source_ext": ".py", "wired": False},
    "nsis":        {"label": "Nullsoft NSIS installer", "source_ext": ".nsi", "wired": False},
    "innosetup":   {"label": "Inno Setup installer", "source_ext": ".iss", "wired": False},
}

# guest-side tool locations (checked in order; first present wins)
AUTOIT_CLI_CANDIDATES = [
    r"C:\Tools\UnAutoIt.exe",
    r"C:\Tools\myAut2Exe\myAut2Exe.exe",
]
AUTOIT_GUI = r"C:\Users\Administrator\Desktop\Malware Analysis Tools\exe2aut.exe"

URL = re.compile(r"(?i)\b(?:https?|ftp)://[\w.\-/%?=&:#@~+]+")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# AutoIt / scripting commands that matter for triage
SCRIPT_KW = ["RunWait", "Run(", "ShellExecute", "FileInstall", "FileWrite",
             "RegWrite", "RegRead", "InetGet", "InetRead", "TCPConnect",
             "DllCall", "BinaryToString", "Execute(", "Call(", "EnvSet",
             "ProcessClose", "@startupdir", "@tempdir", "powershell",
             "cmd.exe", "schtasks", "bitsadmin", "certutil", "VirtualAlloc"]


def detect(path: str) -> dict:
    """Identify the build framework from the file's bytes. Returns
    {framework, label, evidence, extractable} or {framework: None}."""
    data = Path(path).read_bytes()
    for fw, sigs in SIGNATURES:
        hits = [s.decode("latin-1", "replace") for s in sigs if s in data]
        if hits:
            h = HANDLERS[fw]
            return {"framework": fw, "label": h["label"], "evidence": hits[:3],
                    "source_ext": h["source_ext"], "extractable": h["wired"]}
    return {"framework": None}


def _guest_exists(guest, win_path: str) -> bool:
    rc, _, _ = guest.run(f'cmd /c "if exist \"{win_path}\" (exit 0) else (exit 1)"', timeout=30)
    return rc == 0


HEXLIT = re.compile(r"0x([0-9A-Fa-f]{8,})")
ASCII_RUN = re.compile(rb"[\x20-\x7e]{5,}")


def _decode_hex_literals(text: str, cap: int = 400) -> dict:
    """AutoIt malware hides payloads/commands in 0x.. hex literals. Decode them,
    keep printable strings, and flag any that look like x86 shellcode."""
    strings, shellcode = [], 0
    for m in list(HEXLIT.finditer(text))[:cap]:
        try:
            raw = bytes.fromhex(m.group(1))
        except ValueError:
            continue
        printable = [s.decode("latin-1") for s in ASCII_RUN.findall(raw)]
        if printable:
            strings += printable
        else:
            # non-printable blob => likely shellcode/compiled bytes
            if len(raw) >= 16:
                shellcode += 1
    seen, uniq = set(), []
    for s in strings:
        if s not in seen:
            seen.add(s); uniq.append(s)
    return {"decoded_strings": uniq[:120], "shellcode_blobs": shellcode}


def _parse_source(text: str) -> dict:
    """Pull IOCs/behaviour out of recovered plain-text source, INCLUDING content
    hidden in hex literals (very common in AutoIt droppers)."""
    hexinfo = _decode_hex_literals(text)
    searchable = text + "\n" + "\n".join(hexinfo["decoded_strings"])
    urls = sorted(set(URL.findall(searchable)))
    ips = sorted({i for i in IP.findall(searchable)
                  if not i.startswith(("0.", "127.", "255.")) and i != "0.0.0.0"})
    low = searchable.lower()
    cmds = [k for k in SCRIPT_KW if k.lower() in low]
    return {"line_count": text.count("\n") + 1, "char_count": len(text),
            "urls": urls[:60], "ips": ips[:60], "commands": sorted(set(cmds)),
            "decoded_hex_strings": hexinfo["decoded_strings"][:40],
            "shellcode_blob_count": hexinfo["shellcode_blobs"]}


@audited("framework.host_extract", category="framework")
def host_extract(framework: str, local_path: str, out_dir: Path, log=print) -> dict:
    """PRIMARY path: extract on the HOST from the file bytes (static, host-safe,
    no VM/GUI). Currently AutoIt via autoit-ripper (EA05/EA06). Returns a stage
    dict; status 'no_host_tool' means fall back to the guest path."""
    if framework == "autoit":
        try:
            from autoit_ripper import extract as ar_extract, AutoItVersion
        except Exception:
            return {"framework": "autoit", "status": "no_host_tool",
                    "hint": "pip install --user autoit-ripper (then host extraction is automatic)"}
        data = Path(local_path).read_bytes()
        res = None
        for ver in (AutoItVersion.EA06, AutoItVersion.EA05, None):
            try:
                res = ar_extract(data=data, version=ver)
            except Exception:
                res = None
            if res:
                break
        if not res:
            return {"framework": "autoit", "status": "extract_failed",
                    "hint": "autoit-ripper found no embedded script"}
        # res = [(name, bytes), ...]; keep the .au3 script(s)
        out_dir.mkdir(parents=True, exist_ok=True)
        saved, combined = [], []
        for name, content in res:
            safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name) or "script.au3"
            fp = out_dir / safe
            fp.write_bytes(content)
            saved.append(str(fp))
            combined.append(content.decode("latin-1", "replace"))
        parsed = _parse_source("\n".join(combined))
        log(f"[autoit] host-side autoit-ripper -> {saved[0]} "
            f"({parsed['line_count']} lines, {len(parsed['urls'])} URLs, "
            f"{len(parsed['commands'])} notable commands, "
            f"{parsed['shellcode_blob_count']} shellcode blob(s))")
        return {"framework": "autoit", "label": HANDLERS["autoit"]["label"],
                "status": "extracted", "mode": "host_autoit_ripper",
                "source_file": saved[0], "source_files": saved, **parsed}
    return {"framework": framework, "status": "no_host_tool",
            "hint": _TOOL_HINTS.get(framework, "no host extractor")}


@audited("framework.guest_extract", category="framework")
def extract(guest, framework: str, guest_sample: str, out_dir: Path, log=print) -> dict:
    """GUEST fallback path. Returns a stage dict (always, even on
    'needs_interactive' or 'tool_missing', so the pipeline/report can explain)."""
    if framework == "autoit":
        return _extract_autoit(guest, guest_sample, out_dir, log)
    h = HANDLERS.get(framework, {})
    return {"framework": framework, "label": h.get("label"),
            "status": "not_wired",
            "hint": _TOOL_HINTS.get(framework, "no extractor wired yet")}


_TOOL_HINTS = {
    "pyinstaller": "pyinstxtractor.py -> decompile .pyc (decompyle3/pycdc). Add as a CLI handler.",
    "py2exe": "unpy2exe.py -> .pyc -> decompile. Add as a CLI handler.",
    "nsis": "7-Zip (`7z x`) extracts NSIS scripts/files. Add as a CLI handler.",
    "innosetup": "innounp (`innounp -x`) extracts Inno Setup scripts/files. Add as a CLI handler.",
    "autohotkey": "AHK decompilers vary by version; extract the RCDATA>AUTOHOTKEY resource.",
}


def _stage_au3_name(guest_sample: str) -> str:
    base = ntpath.basename(guest_sample) or "sample"
    stem = base.rsplit(".", 1)[0]
    return stem


def _extract_autoit(guest, guest_sample: str, out_dir: Path, log) -> dict:
    stem = _stage_au3_name(guest_sample)
    work = r"C:\nemesis"
    staged = f"{work}\\{stem}.exe"
    guest.run(f'cmd /c "if not exist {work} mkdir {work}"', timeout=30)
    guest.run(f"powershell -NoProfile -Command \"Copy-Item -LiteralPath '{guest_sample}' "
              f"-Destination '{staged}' -Force\"", timeout=120)
    out_au3 = f"{work}\\{stem}.au3"

    # 1) headless CLI decompiler, if one is installed
    cli = next((c for c in AUTOIT_CLI_CANDIDATES if _guest_exists(guest, c)), None)
    if cli:
        log(f"[autoit] using CLI decompiler {cli}")
        if "unautoit" in cli.lower():
            cmd = f'cmd /c ""{cli}" extract-all "{staged}" --output-dir {work}"'
        else:  # myAut2Exe CLI
            cmd = f'cmd /c ""{cli}" /input "{staged}" /output "{out_au3}""'
        guest.run(cmd, timeout=180)
        return _pull_au3(guest, out_au3, out_dir, stem, log, mode="cli")

    # 2) GUI tool (exe2aut) -> interactive on the VM desktop
    if _guest_exists(guest, AUTOIT_GUI):
        log("[autoit] exe2aut is GUI-only; needs an interactive decompile")
        return {
            "framework": "autoit", "label": HANDLERS["autoit"]["label"],
            "status": "needs_interactive",
            "tool": AUTOIT_GUI,
            "staged_input": staged,
            "expected_output": out_au3,
            "instructions": [
                "On the VM desktop open exe2aut (Tiny AutoIt3 Decompiler).",
                f"Open the staged input: {staged}",
                f"Save the decompiled script as: {out_au3}",
                "Then re-run the pipeline / pull step to integrate the source.",
            ],
        }
    return {"framework": "autoit", "status": "tool_missing",
            "hint": "No AutoIt decompiler found. Install UnAutoIt (CLI, headless) at "
                    r"C:\Tools\UnAutoIt.exe for fully-automated extraction."}


def _pull_au3(guest, out_au3: str, out_dir: Path, stem: str, log, mode: str) -> dict:
    local = out_dir / f"{stem}.au3"
    # UnAutoIt writes <name>.au3 (or an .a3x alongside) into the output dir
    if not _guest_exists(guest, out_au3):
        # UnAutoIt may name it differently; grab any .au3 it produced
        rc, listing, _ = guest.run(r'cmd /c "dir /b C:\nemesis\*.au3 2>nul"', timeout=30)
        cand = [l.strip() for l in listing.splitlines() if l.strip().endswith(".au3")]
        if cand:
            out_au3 = f"C:\\nemesis\\{cand[0]}"
        else:
            return {"framework": "autoit", "status": "extract_failed",
                    "hint": "decompiler produced no .au3"}
    if not guest.pull(out_au3.replace("\\", "/"), str(local)):
        return {"framework": "autoit", "status": "pull_failed", "guest_output": out_au3}
    text = local.read_text(errors="replace")
    parsed = _parse_source(text)
    log(f"[autoit] recovered source -> {local} ({parsed['line_count']} lines, "
        f"{len(parsed['urls'])} URLs, {len(parsed['commands'])} notable commands)")
    return {"framework": "autoit", "label": HANDLERS["autoit"]["label"],
            "status": "extracted", "mode": mode,
            "source_file": str(local), **parsed}


def integrate_pull(guest, stage: dict, out_dir: Path, log=print) -> dict:
    """After an operator saves the .au3 from the GUI tool, call this to pull +
    parse it. Takes the prior 'needs_interactive' stage dict."""
    if stage.get("framework") != "autoit" or not stage.get("expected_output"):
        return stage
    stem = Path(stage["expected_output"]).stem
    return _pull_au3(guest, stage["expected_output"], out_dir, stem, log, mode="interactive")
