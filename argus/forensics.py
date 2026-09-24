"""Volatile memory capture — dump a process's memory before killing it.

When a detection crosses the critical threshold, Argus captures the process's
volatile memory (a MiniDump) BEFORE terminating it, so transient evidence — the
decrypted payload, an in-memory C2 config, injected shellcode — survives even
though the process itself is about to die.

Uses the built-in ``comsvcs.dll`` MiniDump export via ``rundll32``, so there are
no external dependencies. The caller owns the ordering guarantee: dump first,
kill second.
"""
from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path

_MINIDUMP_CMD = ["rundll32.exe", r"C:\Windows\System32\comsvcs.dll", "MiniDump"]


def dump_process_memory(pid: int, out_dir: Path, image: str = "") -> str:
    """Dump ``pid``'s memory to a MiniDump file. Returns the path, or raises.

    ``out_dir`` is created if needed; the file is named ``<basename>_<pid>_<ts>.dmp``.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = Path(image or "").name or "process"
    dump_path = out_dir / f"{base}_{pid}_{ts}.dmp"

    cmd = _MINIDUMP_CMD + [str(pid), str(dump_path), "full"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"memory dump failed to run: {exc}") from exc

    if not dump_path.exists() or dump_path.stat().st_size == 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"memory dump produced no file: {detail}")
    return str(dump_path)
