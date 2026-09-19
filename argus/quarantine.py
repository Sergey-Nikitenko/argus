"""Quarantine (move, never delete) + rollback + process-tree kill."""
from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path


def quarantine_file(
    path: str,
    quarantine_dir: Path,
    reason: str = "",
    manifest_path: Path | None = None,
) -> str:
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(f"not found: {src}")
    qdir = Path(quarantine_dir)
    qdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    dest = qdir / f"{src.name}.{stamp}.quarantine"
    shutil.move(str(src), str(dest))
    _write_manifest(manifest_path or (qdir / "manifest.jsonl"), src, dest, reason)
    return str(dest)


def restore_file(quarantined: str, original: str) -> str:
    """Roll back a quarantined file to its original location (move, reversible)."""
    src = Path(quarantined)
    if not src.exists():
        raise FileNotFoundError(f"not found: {src}")
    dest = Path(original)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    return str(dest)


def _write_manifest(manifest_path: Path, src: Path, dest: Path, reason: str) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "original": str(src),
        "quarantined": str(dest),
        "reason": reason,
    }
    with open(manifest_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def kill_process_tree(pid: int) -> None:
    subprocess.run(
        ["taskkill", "/PID", str(pid), "/T", "/F"],
        capture_output=True,
        timeout=30,
        check=False,
    )
