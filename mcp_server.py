#!/usr/bin/env python3
"""Nemesis Analyst — MCP server (the brain's hands).

Exposes the analysis workers as MCP tools so an LLM client (Claude Code, Claude
Desktop, or a Pentagon agent) acts as the orchestrating brain: it calls these
tools, reads the results, decides the next step, and assembles the Proof of
Compromise.

All tools here are STATIC and host-safe — they never execute the sample.
Dynamic/detonation tools will live in a separate worker that runs inside the
isolated VM and is reached over the network.

Run:  python3 mcp_server.py           (stdio transport)
Wire it into a client via .mcp.json (see README).
"""
from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from nanalyst.triage import triage as _triage
from nanalyst.tools import ghidra_worker
from nanalyst.case import Case
from nanalyst import proof

PROJECT = Path(__file__).resolve().parent
CASES = str(PROJECT / "cases")

mcp = FastMCP("nemesis-analyst")


@mcp.tool()
def triage_sample(path: str) -> dict:
    """Fast static triage of a PE sample (Detect It Easy + PE profile).

    Returns architecture, compiler, sections+entropy, imports, capabilities by
    API, and a packing assessment. STATIC — does not execute the sample.
    """
    t = _triage(path)
    case = Case(path, workroot=CASES)
    case.add("triage", t, state="triaged")
    return t


@mcp.tool()
def ghidra_static(path: str) -> dict:
    """Deep static analysis with Ghidra (headless).

    Returns functions, categorized strings (URLs/IPs/registry/paths), suspicious
    API xrefs, control-flow ANOMALIES (indirect-register calls/jmps, push-ret),
    and DYNAMIC HINTS telling the dynamic stage where to break. STATIC.
    Slower (runs Ghidra analysis). Call after triage_sample.
    """
    g = ghidra_worker.analyze(path)
    case = Case(path, workroot=CASES)
    case.add("static_ghidra", g, state="static_done")
    return g


@mcp.tool()
def analyze_sample(path: str) -> dict:
    """Full static pipeline: triage + Ghidra + Proof of Compromise.

    Runs both static workers, builds/updates the case, and returns the Proof of
    Compromise (verdict, capabilities, MITRE ATT&CK, IOCs, obfuscation
    anomalies, and the dynamic analysis plan). STATIC — safe on the host.
    Use this for a one-shot analysis; use the individual tools to drive the
    pipeline step by step.
    """
    case = Case(path, workroot=CASES)
    t = _triage(path)
    case.add("triage", t, state="triaged")
    if not t.get("error"):
        g = ghidra_worker.analyze(path)
        case.add("static_ghidra", g, state="static_done")
    poc = proof.generate(case.data)
    md = proof.to_markdown(poc)
    (case.dir / "proof_of_compromise.md").write_text(md)
    case.add("proof_of_compromise", poc, state="reported")
    return {"proof_of_compromise": poc, "markdown": md, "case_dir": str(case.dir)}


@mcp.tool()
def get_proof_of_compromise(sha256_or_path: str) -> str:
    """Return the Proof of Compromise (Markdown) for an already-analyzed case.

    Accepts a sha256 or a path to a case.json.
    """
    p = Path(sha256_or_path)
    if not p.exists():
        p = Path(CASES) / sha256_or_path / "case.json"
    if not p.exists():
        return f"case not found: {sha256_or_path}"
    case = json.loads(p.read_text())
    return proof.to_markdown(proof.generate(case))


@mcp.tool()
def list_cases() -> list[dict]:
    """List analyzed cases: sha256, sample name, state, and verdict if available."""
    out = []
    root = Path(CASES)
    if not root.exists():
        return out
    for d in sorted(root.iterdir()):
        cj = d / "case.json"
        if not cj.exists():
            continue
        try:
            c = json.loads(cj.read_text())
        except json.JSONDecodeError:
            continue
        verdict = c.get("stages", {}).get("proof_of_compromise", {}).get("verdict", {})
        out.append({
            "sha256": c.get("sha256"),
            "name": c.get("name"),
            "state": c.get("state"),
            "verdict": verdict.get("label"),
            "confidence": verdict.get("confidence"),
        })
    return out


if __name__ == "__main__":
    mcp.run()
