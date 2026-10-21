"""Summarise a Procmon CSV for the sample's process tree: what it DID, not only what it changed.

The detonation parser reports changes (registry writes, files created). A sample that only reads, such as
one enumerating the registry hundreds of thousands of times, shows 0 changes but is still doing something
an analyst needs to see. This streams the CSV (hundreds of MB) and reports operation counts, the busiest
registry keys, files touched, processes created, and network operations. Facts only.
"""
from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path

csv.field_size_limit(sys.maxsize)


def summarize(csv_path: str, image_name: str = "malware.exe", top: int = 12) -> dict:
    p = Path(csv_path)
    if not p.exists():
        return {"available": False}
    ops, regq, files_w, files_r, procs, net = Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    pids = set()
    total = 0
    name = image_name.lower()
    with p.open(newline="", encoding="utf-8-sig", errors="replace") as fh:
        rd = csv.reader(fh)
        next(rd, None)
        for row in rd:
            if len(row) < 7:
                continue
            _, proc, pid, op, path, result, detail = row[:7]
            if proc.lower() != name and pid not in pids:
                continue
            if proc.lower() == name:
                pids.add(pid)
            total += 1
            ops[op] += 1
            if op in ("RegQueryValue", "RegOpenKey", "RegEnumKey", "RegEnumValue", "RegQueryKey"):
                regq[path.rsplit("\\", 1)[0] if op == "RegQueryValue" else path] += 1
            elif op in ("RegSetValue", "RegCreateKey"):
                files_w["REG " + path] += 1
            elif op == "CreateFile":
                d = detail.lower()
                creates = any(f"disposition: {x}" in d for x in ("create", "overwriteif", "supersede", "overwrite", "openif"))
                writes = any(x in d for x in ("generic write", "write data", "append data"))
                (files_w if ((creates or writes) and result == "SUCCESS") else files_r)[path] += 1
            elif op in ("WriteFile", "SetDispositionInformationFile", "SetRenameInformationFile"):
                files_w[path] += 1
            elif op == "Process Create":
                procs[path + " " + detail[:120]] += 1
            elif op.startswith(("TCP", "UDP")):
                net[f"{op} {path}"] += 1
    return {"available": True, "events": total, "pids": sorted(pids)[:10], "image": image_name,
            "operations": ops.most_common(top), "busiest_registry": regq.most_common(top),
            "writes": files_w.most_common(top), "reads": files_r.most_common(top),
            "processes_created": procs.most_common(top), "network": net.most_common(top)}


def to_markdown(s: dict) -> list:
    if not s or not s.get("available"):
        return []
    L = [f"### 4a. What the sample did under Procmon ({s['events']:,} events from `{s['image']}`)", ""]
    if s["operations"]:
        L += ["| Operation | Count |", "|---|---|"] + [f"| {o} | {c:,} |" for o, c in s["operations"]] + [""]
    if s["busiest_registry"]:
        L += ["Busiest registry locations (reads):", ""] + [f"- `{k}` ({c:,}x)" for k, c in s["busiest_registry"][:8]] + [""]
    L.append("Writes / creates: " + (", ".join(f"`{k}`" for k, _ in s["writes"][:8]) if s["writes"] else "none observed") + "  ")
    L.append("Processes created: " + (", ".join(f"`{k[:90]}`" for k, _ in s["processes_created"][:5]) if s["processes_created"] else "none observed") + "  ")
    L.append("Network operations: " + (", ".join(f"`{k}`" for k, _ in s["network"][:6]) if s["network"] else "none observed") + "")
    L.append("")
    return L
