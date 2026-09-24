"""Guest telemetry harvest — turn raw Sysmon XML into Argus-structured events.

The detonation chamber runs a RICHER Sysmon config than the live host: process
creation (1), network connect (3), driver load (6), raw disk access (9), file
create (11), registry object/value/rename (12/13/14), and DNS query (22). This
module parses a dumped run of ``<Event>`` blocks into a :class:`SandboxTelemetry`
bag of typed records, reusing argus.events' proven parsers for 1 and 3, then
derives the execution chain, dropped artifacts, and a plaintext summary for the
Argus AI dissection prompt.

Everything is PURE and deterministic — no live Windows, no wevtutil, no network.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from argus.events import (
    NetworkEvent,
    ProcessEvent,
    _data_dict,
    _system_fields,
    _to_int,
    parse_sysmon_event,
    parse_sysmon_network_event,
)
from argus.process_tree import build_tree


# --------------------------------------------------------------------------- types
@dataclass
class DnsEvent:
    timestamp: str
    pid: int
    image: str
    query_name: str = ""
    query_results: str = ""


@dataclass
class FileCreateEvent:
    timestamp: str
    pid: int
    image: str
    target_filename: str = ""


@dataclass
class RegistryEvent:
    timestamp: str
    pid: int
    image: str
    target_object: str = ""
    details: str = ""
    event_id: int = 13


@dataclass
class DriverLoadEvent:
    timestamp: str
    pid: int
    image: str
    image_loaded: str = ""
    signature: str = ""
    signed: bool = False


@dataclass
class RawAccessEvent:
    timestamp: str
    pid: int
    image: str
    device: str = ""


@dataclass
class DroppedFile:
    path: str
    source_image: str = ""
    sha256: str = ""


@dataclass
class SandboxTelemetry:
    process_events: list[ProcessEvent] = field(default_factory=list)
    network_events: list[NetworkEvent] = field(default_factory=list)
    dns_queries: list[DnsEvent] = field(default_factory=list)
    file_creates: list[FileCreateEvent] = field(default_factory=list)
    registry_events: list[RegistryEvent] = field(default_factory=list)
    driver_loads: list[DriverLoadEvent] = field(default_factory=list)
    raw_accesses: list[RawAccessEvent] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(
            self.process_events or self.network_events or self.dns_queries
            or self.file_creates or self.registry_events or self.driver_loads
            or self.raw_accesses
        )


# --------------------------------------------------------------------------- parsers
def parse_dns_event(xml_text: str) -> DnsEvent | None:
    eid, ts = _system_fields(xml_text)
    if eid != 22:
        return None
    d = _data_dict(xml_text)
    return DnsEvent(
        timestamp=ts, pid=_to_int(d.get("ProcessId", "")), image=d.get("Image", ""),
        query_name=d.get("QueryName", ""), query_results=d.get("QueryResults", ""),
    )


def parse_file_create_event(xml_text: str) -> FileCreateEvent | None:
    eid, ts = _system_fields(xml_text)
    if eid != 11:
        return None
    d = _data_dict(xml_text)
    return FileCreateEvent(
        timestamp=ts, pid=_to_int(d.get("ProcessId", "")), image=d.get("Image", ""),
        target_filename=d.get("TargetFilename", ""),
    )


def parse_registry_event(xml_text: str) -> RegistryEvent | None:
    eid, ts = _system_fields(xml_text)
    if eid not in (12, 13, 14):
        return None
    d = _data_dict(xml_text)
    return RegistryEvent(
        timestamp=ts, pid=_to_int(d.get("ProcessId", "")), image=d.get("Image", ""),
        target_object=d.get("TargetObject", ""), details=d.get("Details", ""),
        event_id=eid,
    )


def parse_driver_load_event(xml_text: str) -> DriverLoadEvent | None:
    eid, ts = _system_fields(xml_text)
    if eid != 6:
        return None
    d = _data_dict(xml_text)
    signed = (d.get("Signed", "").strip().lower() == "true")
    return DriverLoadEvent(
        timestamp=ts, pid=_to_int(d.get("ProcessId", "")), image=d.get("Image", ""),
        image_loaded=d.get("ImageLoaded", ""), signature=d.get("Signature", ""),
        signed=signed,
    )


def parse_raw_access_event(xml_text: str) -> RawAccessEvent | None:
    eid, ts = _system_fields(xml_text)
    if eid != 9:
        return None
    d = _data_dict(xml_text)
    return RawAccessEvent(
        timestamp=ts, pid=_to_int(d.get("ProcessId", "")), image=d.get("Image", ""),
        device=d.get("Device", ""),
    )


def _split_events(xml_text: str) -> list[str]:
    return re.findall(r"<Event\b.*?</Event>", xml_text or "", flags=re.DOTALL)


def parse_sysmon_batch(xml_text: str) -> SandboxTelemetry:
    """Parse a run of Sysmon ``<Event>`` blocks into a typed telemetry bag."""
    tel = SandboxTelemetry()
    for block in _split_events(xml_text):
        eid, _ts = _system_fields(block)
        if eid == 1:
            ev = parse_sysmon_event(block)
            if ev:
                tel.process_events.append(ev)
        elif eid == 3:
            ev = parse_sysmon_network_event(block)
            if ev:
                tel.network_events.append(ev)
        elif eid == 22:
            ev = parse_dns_event(block)
            if ev:
                tel.dns_queries.append(ev)
        elif eid == 11:
            ev = parse_file_create_event(block)
            if ev:
                tel.file_creates.append(ev)
        elif eid in (12, 13, 14):
            ev = parse_registry_event(block)
            if ev:
                tel.registry_events.append(ev)
        elif eid == 6:
            ev = parse_driver_load_event(block)
            if ev:
                tel.driver_loads.append(ev)
        elif eid == 9:
            ev = parse_raw_access_event(block)
            if ev:
                tel.raw_accesses.append(ev)
    return tel


# --------------------------------------------------------------------------- derivation
_PE_EXTENSIONS = {".exe", ".dll", ".scr", ".sys", ".bat", ".cmd", ".ps1", ".vbs",
                  ".js", ".jse", ".hta", ".msi", ".com", ".pif"}
_WRITABLE_DIRS = ("\\users\\public\\", "\\windows\\temp\\", "\\temp\\", "\\programdata\\")
_RUN_KEYS = ("currentversion\\run", "\\runonce", "\\runservices", "winlogon\\shell",
             "windows\\load")


def execution_chain(events: list[ProcessEvent]) -> list[str]:
    """Parent->child chains, oldest ancestor first, e.g. ['WINWORD.EXE -> cmd.exe'].

    One string per ROOT->LEAF path in the process tree (deterministic DFS order).
    """
    tree = build_tree(events)
    roots = [e for e in events if e.parent_pid == 0 or e.parent_pid not in {x.pid for x in events}]
    chains: list[str] = []

    def walk(e: ProcessEvent, path: list[str]):
        path = path + [_basename(e.image)]
        kids = tree.get(e.pid, [])
        if not kids:
            chains.append(" -> ".join(path))
        for k in kids:
            walk(k, path)

    for r in roots:
        walk(r, [])
    # a cycle-safe fallback: if nothing rooted, just name every process once
    if not chains and events:
        chains.append(" -> ".join(_basename(e.image) for e in events))
    return chains


def _basename(image: str) -> str:
    try:
        return Path(image).name.upper() or image
    except Exception:  # noqa: BLE001
        return image


def _is_writable_dir(path: str) -> bool:
    p = path.lower()
    return any(d in p for d in _WRITABLE_DIRS)


def detect_dropped_files(file_creates: Iterable[FileCreateEvent]) -> list[DroppedFile]:
    """FileCreate events that wrote an executable/script or landed in a writable dir."""
    out: list[DroppedFile] = []
    seen: set[str] = set()
    for f in file_creates:
        path = f.target_filename or ""
        ext = Path(path).suffix.lower()
        if not path or path in seen:
            continue
        if ext in _PE_EXTENSIONS or _is_writable_dir(path):
            seen.add(path)
            out.append(DroppedFile(path=path, source_image=_basename(f.image)))
    return out


def detect_persistence(registry_events: Iterable[RegistryEvent]) -> list[str]:
    """Registry writes that touch an auto-start location (Run keys, Winlogon shell)."""
    out = []
    for r in registry_events:
        obj = (r.target_object or "").lower()
        if any(k in obj for k in _RUN_KEYS):
            out.append(r.target_object)
    return out


def _chain_text(chains: list[str]) -> str:
    return " | ".join(chains) if chains else "(none)"


def summarize(tel: SandboxTelemetry, attachment_name: str = "sample") -> str:
    """The plaintext telemetry summary fed into the Argus AI dissection prompt."""
    chains = execution_chain(tel.process_events)
    dropped = detect_dropped_files(tel.file_creates)
    persistence = detect_persistence(tel.registry_events)
    net = []
    for n in tel.network_events:
        net.append(f"{n.image or '?'} -> {n.endpoint()} ({n.protocol or 'tcp'})")
    for d in tel.dns_queries:
        net.append(f"{d.image or '?'} DNS query {d.query_name or '?'}")
    lines = [
        "Telemetry Summary:",
        f"- Attachment File: {attachment_name}",
        f"- Spawned Processes: {_chain_text(chains)}",
    ]
    if net:
        lines.append("- Network Requests: " + "; ".join(net))
    else:
        lines.append("- Network Requests: (none captured)")
    if dropped:
        lines.append("- Dropped Artifacts: " + ", ".join(d.path for d in dropped))
    if persistence:
        lines.append("- Persistence (auto-start): " + ", ".join(persistence))
    if tel.driver_loads:
        unsigned = [d.image_loaded for d in tel.driver_loads if not d.signed]
        if unsigned:
            lines.append("- Unsigned Drivers Loaded: " + ", ".join(unsigned))
    if tel.raw_accesses:
        lines.append("- Raw Disk Access: " + ", ".join(f"{r.image}->{r.device}" for r in tel.raw_accesses))
    return "\n".join(lines)
