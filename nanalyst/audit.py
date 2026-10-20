"""Per-tool audit ledger — the productization backbone.

This platform orchestrates MANY subtools (DIE, pefile, Ghidra, de4dot, autoit-ripper,
upx, every SSH command on the guest, every x64dbg-MCP call, pe-sieve, FakeNet, ...).
When something misbehaves in the field you must be able to answer, per call:
  - WHICH tool ran, and in which category/phase
  - the exact INPUT(s) it was given
  - the OUTPUT it produced (summarized; full output saved as an artifact if large)
  - WHEN it ran and how LONG it took
  - whether it SUCCEEDED or FAILED, and the error if it failed

Every call appends one structured record to cases/<sha>/tool_audit.jsonl and a
one-line human entry to tool_audit.log. A global "active" ledger lets tool adapters
self-audit via the @audited decorator without threading the ledger through every
signature. Secrets are redacted.
"""
from __future__ import annotations

import json
import time
from functools import wraps
from pathlib import Path

_ACTIVE: "ToolAudit | None" = None


def activate(ledger: "ToolAudit | None") -> None:
    """Install the ledger that @audited adapters and bare tool calls record to."""
    global _ACTIVE
    _ACTIVE = ledger


def active() -> "ToolAudit | None":
    return _ACTIVE


def _iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _jsonable(x):
    try:
        json.dumps(x, default=str)
        return x
    except Exception:
        return str(x)


def summarize_output(out) -> dict:
    """Compact, loggable view of any tool output (never dumps megabytes)."""
    import subprocess
    if isinstance(out, subprocess.CompletedProcess):
        return {"type": "CompletedProcess", "returncode": out.returncode,
                "stdout_len": len(out.stdout or ""), "stderr_len": len(out.stderr or ""),
                "stdout_preview": (out.stdout or "")[:400],
                "stderr_preview": (out.stderr or "")[:200]}
    if isinstance(out, tuple) and len(out) == 3 and isinstance(out[0], int):
        rc, so, se = out                         # Guest.run() -> (rc, stdout, stderr)
        return {"type": "ssh_result", "returncode": rc,
                "stdout_len": len(so or ""), "stderr_len": len(se or ""),
                "stdout_preview": (so or "")[:400], "stderr_preview": (se or "")[:200]}
    if isinstance(out, (dict, list)):
        s = json.dumps(out, default=str)
        return {"type": type(out).__name__, "size": len(s), "preview": s[:700]}
    if isinstance(out, bytes):
        return {"type": "bytes", "size": len(out)}
    if isinstance(out, bool) or out is None:
        return {"type": type(out).__name__, "value": out}
    s = str(out)
    return {"type": type(out).__name__, "size": len(s), "preview": s[:700]}


def _is_failure(out) -> tuple[bool, str | None]:
    """Detect a failure even when a tool returns an error value instead of raising."""
    import subprocess
    if isinstance(out, subprocess.CompletedProcess) and out.returncode != 0:
        return True, f"returncode={out.returncode}"
    if isinstance(out, tuple) and len(out) == 3 and isinstance(out[0], int) and out[0] != 0:
        return True, f"ssh returncode={out[0]}"
    if isinstance(out, dict):
        if out.get("error"):
            return True, str(out.get("error"))[:200]
        if out.get("success") is False:
            return True, str(out.get("message") or out.get("error") or "success=false")[:200]
        if out.get("available") is False and out.get("error"):
            return True, str(out.get("error"))[:200]
    if out is False:
        return True, "returned False"
    return False, None


class ToolAudit:
    def __init__(self, case_dir, redact=None, category: str = "general"):
        self.dir = Path(case_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.jsonl = self.dir / "tool_audit.jsonl"
        self.log = self.dir / "tool_audit.log"
        self.redact = [r for r in (redact or []) if r]
        self._seq = 0
        self._default_category = category
        self._records: list[dict] = []

    def _scrub(self, obj):
        s = json.dumps(obj, default=str)
        for secret in self.redact:
            s = s.replace(secret, "***")
        return json.loads(s)

    def _scrub_text(self, text: str) -> str:
        for secret in self.redact:
            text = text.replace(secret, "***")
        return text

    def run(self, tool: str, inputs: dict, fn, category: str | None = None,
            phase: str | None = None):
        """Execute fn() while recording tool/inputs/output/timing/status. Re-raises
        any exception AFTER logging it, so callers keep their existing behavior."""
        self._seq += 1
        seq = self._seq
        t0 = time.time()
        ts_start = _iso()
        status, err, out = "ok", None, None
        try:
            out = fn()
            failed, why = _is_failure(out)
            if failed:
                status, err = "error", why
            return out
        except Exception as exc:
            status, err = "error", repr(exc)
            raise
        finally:
            rec = {
                "seq": seq,
                "tool": tool,
                "category": category or self._default_category,
                "phase": phase,
                "ts_start": ts_start,
                "ts_end": _iso(),
                "duration_ms": int((time.time() - t0) * 1000),
                "status": status,
                "error": err,
                "inputs": self._scrub(_jsonable(inputs)),
                "output": self._scrub(summarize_output(out)) if status != "error" or out is not None else None,
            }
            self._records.append(rec)
            with open(self.jsonl, "a") as f:
                f.write(json.dumps(rec, default=str) + "\n")
            line = (f"{rec['ts_start']} #{seq:03d} [{rec['category']}] {tool} "
                    f"{rec['duration_ms']}ms {status.upper()}"
                    + (f" :: {err}" if err else ""))
            with open(self.log, "a") as f:
                f.write(self._scrub_text(line) + "\n")

    def record(self, tool: str, inputs: dict, output, status: str = "ok",
               duration_ms: int = 0, category: str | None = None, error: str | None = None):
        """Manually log a call whose execution you timed yourself (e.g. MCP calls)."""
        self._seq += 1
        rec = {"seq": self._seq, "tool": tool, "category": category or self._default_category,
               "phase": None, "ts_start": _iso(), "ts_end": _iso(),
               "duration_ms": duration_ms, "status": status, "error": error,
               "inputs": self._scrub(_jsonable(inputs)),
               "output": self._scrub(summarize_output(output))}
        self._records.append(rec)
        with open(self.jsonl, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        with open(self.log, "a") as f:
            f.write(self._scrub_text(
                f"{rec['ts_start']} #{rec['seq']:03d} [{rec['category']}] {tool} "
                f"{duration_ms}ms {status.upper()}" + (f" :: {error}" if error else "")) + "\n")
        return rec

    # ---- reporting ----
    def records(self) -> list[dict]:
        if self._records:
            return self._records
        if self.jsonl.exists():
            return [json.loads(l) for l in self.jsonl.read_text().splitlines() if l.strip()]
        return []

    def summary(self) -> dict:
        recs = self.records()
        ok = sum(1 for r in recs if r["status"] == "ok")
        err = [r for r in recs if r["status"] == "error"]
        total_ms = sum(r.get("duration_ms", 0) for r in recs)
        by_tool: dict[str, dict] = {}
        for r in recs:
            b = by_tool.setdefault(r["tool"], {"calls": 0, "errors": 0, "ms": 0})
            b["calls"] += 1
            b["ms"] += r.get("duration_ms", 0)
            if r["status"] == "error":
                b["errors"] += 1
        return {"total_calls": len(recs), "ok": ok, "errors": len(err),
                "total_ms": total_ms, "by_tool": by_tool,
                "failures": [{"seq": r["seq"], "tool": r["tool"], "error": r["error"]}
                             for r in err]}

    def render(self, full: bool = False) -> str:
        """Console view: a by-tool summary + every failure (the per-call detail,
        with inputs/outputs, lives in tool_audit.jsonl). full=True lists every call."""
        recs = self.records()
        s = self.summary()
        out = ["  tool                           calls  errs   total_ms   avg_ms",
               "  -----------------------------  -----  ----  ---------  -------"]
        for tool, b in sorted(s["by_tool"].items(), key=lambda kv: -kv[1]["ms"]):
            avg = b["ms"] // max(b["calls"], 1)
            out.append(f"  {tool[:29]:<29}  {b['calls']:>5}  {b['errors']:>4}  "
                       f"{b['ms']:>9}  {avg:>7}")
        out.append(f"  -- {s['total_calls']} calls, {s['ok']} ok, {s['errors']} failed, "
                   f"{s['total_ms']}ms total --")
        if s["failures"]:
            out.append("  FAILURES (trace these):")
            for fl in s["failures"]:
                out.append(f"    #{fl['seq']} {fl['tool']} :: {fl['error']}")
        if full:
            out.append("  --- every call ---")
            for r in recs:
                flag = "OK " if r["status"] == "ok" else "FAIL"
                out.append(f"  #{r['seq']:>3} {r['tool'][:28]:<28} {r.get('duration_ms',0):>5}ms {flag}"
                           + (f" {r['error']}" if r.get("error") else ""))
        return "\n".join(out)


def audited(tool: str, category: str | None = None, skip_self: bool = False):
    """Decorator: record this adapter call on the active ledger (no-op if none).
    skip_self=True for instance methods (don't log `self`)."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            au = active()
            if au is None:
                return fn(*args, **kwargs)
            logargs = args[1:] if skip_self and args else args
            inputs = {"args": _jsonable(list(logargs)), "kwargs": _jsonable(kwargs)}
            return au.run(tool, inputs, lambda: fn(*args, **kwargs), category=category)
        return wrapper
    return deco
