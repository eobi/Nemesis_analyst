"""Run log + phase checklist — the audit spine.

Every command we send (host or guest), every input, and every artifact is
appended to a per-case run log (human-readable run.log + structured run.jsonl).
A phase checklist tracks the full pipeline so no step is ever skipped: each phase
is pending -> running -> done/failed/skipped, persisted to checklist.json.

Secrets (e.g. the guest password) are redacted from anything logged.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

# Canonical ordered pipeline — static + dynamic + detonation + recovery.
# Keeping it here means every case carries the full to-do list and we can see
# at a glance what still needs doing.
PHASES = [
    ("triage", "DIE + PE profile"),
    ("attribution", "author/build recon: compile time, PDB, Rich header, version info"),
    ("upx_unpack", "auto-unpack UPX (upx -d) + re-triage"),
    ("verify_unpack", "verify the dump/unpacked file is the real payload"),
    ("framework_extract", "recover framework source (AutoIt/PyInstaller/NSIS/...)"),
    ("static_ghidra", "Ghidra static: functions, strings, anomalies, hints"),
    ("guest_deobfuscation", "guest DIE + de4dot .NET deobfuscation"),
    ("sandbox_boot", "boot disposable isolated VM, confirm guest control"),
    ("fakenet_start", "start FakeNet-NG (network capture begins)"),
    ("regshot_1", "Regshot baseline BEFORE running malware"),
    ("procmon_start", "start Procmon capture"),
    ("detonate", "run the malware, start timer"),
    ("observe", "let it run 3-4 min (network + system activity)"),
    ("procmon_stop", "finalize Procmon, export CSV"),
    ("regshot_2_diff", "Regshot shot 2, compare, export diff"),
    ("fakenet_stop", "stop FakeNet, collect pcap + HTTP logs"),
    ("memory_dump", "dump unpacked payload / key material from memory"),
    ("pcap_analysis", "tshark: HTTP streams, WebSocket, DNS, conversations -> IOCs"),
    ("behavior_parse", "parse Procmon + Regshot diff -> files/registry/persistence"),
    ("re_static", "re-run static on reconstructed dump (reveal hidden code/URLs)"),
    ("recovery_assess", "assess ransomware recoverability; emit decryptor if possible"),
    ("crypto_recovery", "detect encryption + generate decryptor where recoverable"),
    ("classification", "behavioral family classification"),
    ("proof_of_compromise", "assemble the final report"),
]


class RunLog:
    def __init__(self, case_dir: str | Path, redact: list[str] | None = None):
        self.dir = Path(case_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.dir / "run.log"
        self.jsonl = self.dir / "run.jsonl"
        self.redact = [r for r in (redact or []) if r]

    def _scrub(self, text: str) -> str:
        for secret in self.redact:
            text = text.replace(secret, "***")
        return text

    def log(self, phase: str, event: str, detail: str = "", data: dict | None = None) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        line = self._scrub(f"{ts} [{phase}] {event}" + (f" :: {detail}" if detail else ""))
        with open(self.log_file, "a") as f:
            f.write(line + "\n")
        rec = {"ts": ts, "phase": phase, "event": event, "detail": self._scrub(detail)}
        if data is not None:
            rec["data"] = data
        with open(self.jsonl, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")

    def command(self, where: str, phase: str, argv: list[str] | str) -> None:
        """Log a command being sent host-side or to the guest."""
        cmd = argv if isinstance(argv, str) else " ".join(argv)
        self.log(phase, f"CMD[{where}]", self._scrub(cmd))

    def artifact(self, phase: str, path: str, note: str = "") -> None:
        self.log(phase, "ARTIFACT", f"{path} {note}".strip())

    def input(self, phase: str, source: str, value: str) -> None:
        self.log(phase, "INPUT", f"{source}={value}")


class Checklist:
    def __init__(self, case_dir: str | Path):
        self.path = Path(case_dir) / "checklist.json"
        if self.path.exists():
            self.items = json.loads(self.path.read_text())
        else:
            self.items = [
                {"phase": p, "desc": d, "status": "pending", "note": "", "ts": ""}
                for p, d in PHASES
            ]
            self._save()

    def _save(self) -> None:
        self.path.write_text(json.dumps(self.items, indent=2))

    def _set(self, phase: str, status: str, note: str = "") -> None:
        for it in self.items:
            if it["phase"] == phase:
                it["status"] = status
                it["note"] = note
                it["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._save()

    def start(self, phase: str) -> None:
        self._set(phase, "running")

    def done(self, phase: str, note: str = "") -> None:
        self._set(phase, "done", note)

    def fail(self, phase: str, note: str = "") -> None:
        self._set(phase, "failed", note)

    def skip(self, phase: str, note: str = "") -> None:
        self._set(phase, "skipped", note)

    def remaining(self) -> list[str]:
        return [it["phase"] for it in self.items if it["status"] in ("pending", "running")]

    def render(self) -> str:
        glyph = {"pending": "[ ]", "running": "[~]", "done": "[x]",
                 "failed": "[!]", "skipped": "[-]"}
        return "\n".join(
            f"  {glyph.get(it['status'], '[ ]')} {it['phase']:<18} {it['desc']}"
            + (f"  ({it['note']})" if it["note"] else "")
            for it in self.items
        )
