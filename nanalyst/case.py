"""Case model — the spine of the pipeline.

A Case tracks one sample through every stage. Workers write their results into
it; dynamic hints accumulate across stages so the dynamic phase knows where to
look. Persisted as JSON under cases/<sha256>/case.json.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


# one self-contained folder per analysis, organized into subfolders
SUBDIRS = ("logs", "dumps", "source", "decryptor", "artifacts")


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:40] or "sample"


class Case:
    def __init__(self, sample_path: str, workroot: str = "cases", unique: bool = False, run_id: str | None = None):
        self.sample_path = str(Path(sample_path).resolve())
        data = Path(self.sample_path).read_bytes()
        self.sha256 = hashlib.sha256(data).hexdigest()
        # human-readable, self-contained per-analysis folder: <name>_<sha12>
        if unique:
            # one folder per RUN: <uuid>_<malware folder name>, so repeated runs of the same sample never mix
            import uuid
            label = Path(self.sample_path).parent.name or Path(self.sample_path).name
            self.run_id = run_id or str(uuid.uuid4())
            self.dir = Path(workroot) / f"{self.run_id}_{_safe(label)}"
        else:
            self.dir = Path(workroot) / f"{_safe(Path(self.sample_path).name)}_{self.sha256[:12]}"
        self.dir.mkdir(parents=True, exist_ok=True)
        for sub in SUBDIRS:
            (self.dir / sub).mkdir(exist_ok=True)
        self.data = {
            "sample": self.sample_path,
            "name": Path(self.sample_path).name,
            "dir": str(self.dir),          # case folder, so the report can verify artifacts exist
            "sha256": self.sha256,
            "size": len(data),
            "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "run_id": getattr(self, "run_id", None),
            "stages": {},     # stage name -> worker result
            "hints": [],      # accumulated dynamic hints
            "state": "new",
        }

    # ---- organized subfolders (every artifact has a home) ----
    @property
    def logs_dir(self) -> Path: return self.dir / "logs"
    @property
    def dumps_dir(self) -> Path: return self.dir / "dumps"
    @property
    def source_dir(self) -> Path: return self.dir / "source"
    @property
    def decryptor_dir(self) -> Path: return self.dir / "decryptor"
    @property
    def artifacts_dir(self) -> Path: return self.dir / "artifacts"

    def add(self, stage: str, result: dict, state: str | None = None) -> None:
        """Record a worker's result and harvest any dynamic hints it produced."""
        self.data["stages"][stage] = result
        for h in result.get("dynamic_hints", []) or []:
            h = dict(h)
            h["source"] = stage
            self.data["hints"].append(h)
        if state:
            self.data["state"] = state
        self.save()

    def load(self) -> "Case":
        """Merge an existing case.json (prior stages + hints) into this case, so a
        later tool (e.g. the dynamic unpacker) can build on earlier static results
        instead of overwriting them."""
        p = self.dir / "case.json"
        if p.exists():
            try:
                prior = json.loads(p.read_text())
                self.data["stages"].update(prior.get("stages", {}) or {})
                have = {id(h): h for h in self.data["hints"]}
                for h in prior.get("hints", []) or []:
                    if h not in self.data["hints"]:
                        self.data["hints"].append(h)
            except Exception:
                pass
        return self

    def save(self) -> None:
        self.data["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")      # heartbeat: shows a run is alive/where it stopped
        (self.dir / "case.json").write_text(json.dumps(self.data, indent=2))

    def stage(self, name: str) -> dict:
        return self.data["stages"].get(name, {})

    @property
    def path(self) -> Path:
        return self.dir / "case.json"

    def write_manifest(self) -> Path:
        """Index every artifact in the analysis folder (what's here + where)."""
        man = {"name": self.data["name"], "sha256": self.sha256,
               "created": self.data["created"], "folder": str(self.dir),
               "stages_completed": list(self.data["stages"].keys()), "files": {}}
        for p in sorted(self.dir.rglob("*")):
            if p.is_file():
                man["files"][str(p.relative_to(self.dir))] = p.stat().st_size
        (self.dir / "manifest.json").write_text(json.dumps(man, indent=2))
        return self.dir / "manifest.json"


def find_case_json(workroot: str, sha256: str):
    """Newest case.json under `workroot` whose sample sha256 matches (folder names no longer contain the full hash)."""
    best = None
    for cj in Path(workroot).glob("*/case.json"):
        try:
            d = json.loads(cj.read_text())
        except Exception:
            continue
        if d.get("sha256") == sha256.lower() and (best is None or cj.stat().st_mtime > best.stat().st_mtime):
            best = cj
    return best
