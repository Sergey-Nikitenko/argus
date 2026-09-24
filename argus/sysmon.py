"""Sysmon install / status helpers.

Argus gets its richest telemetry from Sysmon:

* Event ID 1 (ProcessCreate)  — process creation with full command line, hashes,
  parent image, and integrity level.
* Event ID 3 (NetworkConnect) — process -> destination IP:port edges, which is
  what populates Argus's process graph and campaign/blast-radius analysis.

This module ships a canonical Sysmon config (``SYSMON_CONFIG``) that enables
exactly those events with no exclusions, plus stdlib-only helpers to install,
reconfigure, uninstall, and health-check Sysmon.

Installing / updating / uninstalling Sysmon loads a kernel driver and therefore
REQUIRES an elevated (administrator) shell. The read-only ``status`` path needs
no elevation.
"""
from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

# ---------------------------------------------------------------------------
# Canonical config
# ---------------------------------------------------------------------------
SYSMON_CONFIG = """<?xml version="1.0" encoding="UTF-8"?>
<Sysmon schemaversion="4.30">
  <!-- Argus canonical Sysmon config.
       Enables exactly the events Argus consumes, with NO exclusions so the
       process graph and network map are fully populated:
         Event ID 1 (ProcessCreate)  -> process-creation + lineage graph
         Event ID 3 (NetworkConnect) -> process -> endpoint edges
       Add <ProcessCreate> / <NetworkConnect> onmatch="exclude" rules below to
       trim noise on busy hosts. -->
  <HashAlgorithms>SHA256,IMPHASH,MD5</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="exclude">
    </ProcessCreate>
    <NetworkConnect onmatch="exclude">
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
"""


def write_config(path) -> Path:
    """Write the canonical config to *path* and return it."""
    p = Path(path)
    p.write_text(SYSMON_CONFIG, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Sandbox config — the RICHER telemetry set the detonation chamber needs
# ---------------------------------------------------------------------------
SANDBOX_SYSMON_CONFIG = """<?xml version="1.0" encoding="UTF-8"?>
<Sysmon schemaversion="4.30">
  <!-- Argus sandbox Sysmon config. The detonation chamber logs MORE than the live
       host: process creation (1), network (3), driver load (6), image load (7),
       raw disk access (9), file create (11), registry object/value/rename
       (12/13/14), file-create-stream-hash (15), and DNS query (22). -->
  <HashAlgorithms>SHA256,IMPHASH,MD5</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="exclude"></ProcessCreate>
    <NetworkConnect onmatch="exclude"></NetworkConnect>
    <DriverLoad onmatch="exclude"></DriverLoad>
    <ImageLoad onmatch="exclude"></ImageLoad>
    <RawAccessRead onmatch="exclude"></RawAccessRead>
    <FileCreate onmatch="exclude"></FileCreate>
    <RegistryEvent onmatch="exclude"></RegistryEvent>
    <FileCreateStreamHash onmatch="exclude"></FileCreateStreamHash>
    <DnsQuery onmatch="exclude"></DnsQuery>
  </EventFiltering>
</Sysmon>
"""


def write_sandbox_config(path) -> Path:
    """Write the sandbox (richer-telemetry) config to *path* and return it."""
    p = Path(path)
    p.write_text(SANDBOX_SYSMON_CONFIG, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Command builders (pure, unit-tested)
# ---------------------------------------------------------------------------
def build_install_command(sysmon_exe, config_path) -> list[str]:
    """Sysmon64.exe -accepteula -i config.xml"""
    return [str(sysmon_exe), "-accepteula", "-i", str(config_path)]


def build_update_command(sysmon_exe, config_path) -> list[str]:
    """Sysmon64.exe -accepteula -c config.xml  (reload config on a live install)"""
    return [str(sysmon_exe), "-accepteula", "-c", str(config_path)]


def build_uninstall_command(sysmon_exe) -> list[str]:
    """Sysmon64.exe -u"""
    return [str(sysmon_exe), "-u"]


# ---------------------------------------------------------------------------
# Status helpers
# ---------------------------------------------------------------------------
def _parse_sc_query(returncode: int, text: str) -> str:
    """Map ``sc query <svc>`` (returncode + output) to a state token."""
    if returncode != 0:
        return "not found"
    if "RUNNING" in text:
        return "RUNNING"
    if "STOP_PENDING" in text or "STOPPED" in text:
        return "STOPPED"
    return "unknown"


def _sc_state(service: str) -> str:
    try:
        proc = subprocess.run(
            ["sc", "query", service], capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return _parse_sc_query(proc.returncode, (proc.stdout or "") + (proc.stderr or ""))


_SERVICE_NAMES = ("Sysmon64", "Sysmon")


def _pick_service_state(states: dict[str, str]) -> str:
    """Choose the state of whichever Sysmon service name exists.

    Sysmon 15.x registers the x64 build as ``Sysmon64``; the x86 build (and
    older releases) use ``Sysmon``. Pick the first name that resolves.
    """
    for name in _SERVICE_NAMES:
        state = states.get(name, "not found")
        if state != "not found":
            return state
    return "not found"


def service_state() -> str:
    """State of the Sysmon *service* (RUNNING / STOPPED / not found / unknown)."""
    return _pick_service_state({name: _sc_state(name) for name in _SERVICE_NAMES})


def driver_state() -> str:
    """State of the Sysmon *driver* (RUNNING / STOPPED / not found / unknown)."""
    return _sc_state("SysmonDrv")


def is_installed() -> bool:
    return service_state() != "not found"


def has_process_events() -> bool:
    """True if the Sysmon operational log has at least one Event ID 1."""
    from argus.events import read_sysmon_events
    try:
        return bool(read_sysmon_events(1))
    except Exception:  # noqa: BLE001 — log unreadable counts as "none"
        return False


def has_network_events() -> bool:
    """True if the Sysmon operational log has at least one Event ID 3."""
    from argus.events import read_sysmon_network_events
    try:
        return bool(read_sysmon_network_events(1))
    except Exception:  # noqa: BLE001
        return False


def status() -> dict:
    svc = service_state()
    return {
        "installed": svc != "not found",
        "service": svc,
        "driver": driver_state(),
        "has_process_events": has_process_events(),
        "has_network_events": has_network_events(),
    }


def format_status(d: dict) -> str:
    return "\n".join([
        "Argus Sysmon status",
        f"  installed:          {'yes' if d['installed'] else 'no'}",
        f"  service:            {d['service']}",
        f"  driver (SysmonDrv): {d['driver']}",
        f"  process events (1): {'present' if d['has_process_events'] else 'none'}",
        f"  network events (3): {'present' if d['has_network_events'] else 'none'}",
    ])


# ---------------------------------------------------------------------------
# Side-effecting install / update / uninstall (require elevation)
# ---------------------------------------------------------------------------
def install(sysmon_exe, config_path) -> int:
    return subprocess.run(build_install_command(sysmon_exe, config_path)).returncode


def update_config(sysmon_exe, config_path) -> int:
    return subprocess.run(build_update_command(sysmon_exe, config_path)).returncode


def uninstall(sysmon_exe) -> int:
    return subprocess.run(build_uninstall_command(sysmon_exe)).returncode
