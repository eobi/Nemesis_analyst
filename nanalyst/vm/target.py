"""Analysis target — a user-powered instance reached over SSH.

The user runs their own VM/host (UTM, VirtualBox, VMware, cloud, bare metal),
enables SSH, and describes it here. The pipeline connects and drives it; it never
boots or manages the instance.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path

from .guest import Guest

TARGETS_FILE = Path("targets.json")


@dataclass
class Target:
    host: str
    port: int = 22
    user: str = "analyst"
    password: str | None = None
    key: str | None = None          # path to a private key (cloud instances)
    os: str = "windows"             # windows | linux
    name: str = "default"

    def guest(self) -> Guest:
        return Guest(self.host, self.port, self.user, self.password, self.key)


def save(target: Target, path: Path = TARGETS_FILE) -> None:
    data = {}
    if path.exists():
        data = json.loads(path.read_text())
    data[target.name] = asdict(target)
    path.write_text(json.dumps(data, indent=2))


def load(name: str = "default", path: Path = TARGETS_FILE) -> Target | None:
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    if name not in data:
        return None
    return Target(**data[name])
