"""WSL delegation — drive the Linux hypervisor host from the Windows Argus console.

Argus core runs on Windows, where the ``libvirt`` Python binding does not exist;
the sandbox host controller (libvirt/KVM) runs inside WSL2 Ubuntu. This module
translates Windows paths to their WSL mounts (``C:\\x -> /mnt/c/x``) and builds
the ``wsl.exe -d <distro> -- python3 ...`` command, so one Windows command

    py run.py --sandbox --sandbox-sample C:\\samples\\evil.exe --sandbox-live --sandbox-host wsl

detonates on the local hypervisor without leaving the Windows console. The heavy
lifting is PURE path/argv logic, unit-tested on Windows; only ``delegate`` runs
a subprocess.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time

DEFAULT_DISTRO = "Ubuntu"
_PATH_FIELDS = ("work_dir", "pcap_dir", "telemetry_dir", "artifacts_dir")


def windows_to_wsl_path(p) -> str:
    """'C:\\dir\\file' -> '/mnt/c/dir/file'; a non-Windows path passes through."""
    p = str(p)
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", p)
    if not m:
        return p
    return f"/mnt/{m.group(1).lower()}/{m.group(2).replace(chr(92), '/')}"


def translate_config_paths(overrides: dict) -> dict:
    """Translate the sandbox config's four path fields to WSL mounts (copy)."""
    out = dict(overrides or {})
    for k in _PATH_FIELDS:
        if k in out and isinstance(out[k], str):
            out[k] = windows_to_wsl_path(out[k])
    return out


def repo_entry_wsl_path(repo_dir: str, entry: str = "run.py") -> str:
    return windows_to_wsl_path(os.path.join(repo_dir, entry))


def prepare_config_for_wsl(src: str, tmp_dir: str | None = None) -> str:
    """Read a Windows config JSON, translate its path fields, write a copy, return
    the copy's path (a WSL mount passes through). Tolerates a UTF-8 BOM."""
    tmp_dir = tmp_dir or tempfile.gettempdir()
    with open(src, encoding="utf-8-sig") as f:
        data = json.load(f)
    data = translate_config_paths(data)
    out = os.path.join(tmp_dir, f"argus-sandbox-wsl-{int(time.time())}.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return out


def build_wsl_command(*, repo_dir: str, sample: str, config: str | None = None,
                      live: bool = True, no_llm: bool = False,
                      distro: str = DEFAULT_DISTRO) -> list[str]:
    """The wsl.exe argv that runs the live sandbox pipeline inside WSL."""
    cmd = ["wsl.exe", "-d", distro, "--", "python3", repo_entry_wsl_path(repo_dir),
           "--sandbox", "--sandbox-sample", windows_to_wsl_path(sample)]
    if config:
        cmd += ["--sandbox-config", windows_to_wsl_path(config)]
    if live:
        cmd += ["--sandbox-live"]
    if no_llm:
        cmd += ["--no-llm"]
    return cmd


def delegate(repo_dir: str, sample: str, config: str | None = None,
             live: bool = True, no_llm: bool = False,
             distro: str = DEFAULT_DISTRO) -> int:
    """Run the sandbox inside WSL and return the exit code.

    Captures + replays the child's output explicitly: wsl.exe can drop or truncate
    relayed output when it exits as a non-interactive child, so inherit-stdio is
    unreliable here.
    """
    import sys
    cmd = build_wsl_command(repo_dir=repo_dir, sample=sample, config=config,
                            live=live, no_llm=no_llm, distro=distro)
    print(f"[sandbox] delegating to WSL: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    return proc.returncode
