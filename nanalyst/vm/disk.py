"""Disk manager — immutable clean base + disposable copy-on-write overlays.

Each detonation runs on a throwaway qcow2 overlay backed by a read-only clean
base. Boot the overlay, collect artifacts, delete the overlay. The base is never
written, so every run starts pristine and many can run in parallel.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

QEMU_IMG = "/opt/homebrew/bin/qemu-img"


def _run(args: list[str], timeout: int = 1800) -> tuple[bool, str]:
    try:
        p = subprocess.run([QEMU_IMG, *args], capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, (p.stderr or p.stdout).strip()
    except Exception as exc:
        return False, str(exc)


def prepare_base(source_disk: Path, snapshot: str, base_out: Path) -> tuple[bool, str]:
    """One-time: flatten an internal snapshot of the live disk into an immutable base.

    Heavy (copies the allocated image). Run once; afterwards overlays are instant.
        qemu-img convert -O qcow2 -l snapshot.name=<snap> <source> <base_out>
    """
    base_out.parent.mkdir(parents=True, exist_ok=True)
    if base_out.exists():
        return True, f"base already exists: {base_out}"
    ok, msg = _run([
        "convert", "-O", "qcow2",
        "-l", f"snapshot.name={snapshot}",
        str(source_disk), str(base_out),
    ])
    return ok, msg if not ok else f"base created: {base_out}"


def create_overlay(base: Path, overlay: Path) -> tuple[bool, str]:
    """Instant copy-on-write overlay backed by the immutable base."""
    overlay.parent.mkdir(parents=True, exist_ok=True)
    if overlay.exists():
        overlay.unlink()
    ok, msg = _run([
        "create", "-f", "qcow2",
        "-b", str(base), "-F", "qcow2",
        str(overlay),
    ], timeout=60)
    return ok, msg if not ok else f"overlay: {overlay}"


def destroy_overlay(overlay: Path) -> None:
    try:
        overlay.unlink()
    except OSError:
        pass


def info(image: Path) -> str:
    ok, msg = _run(["info", "-U", str(image)], timeout=60)
    return msg
