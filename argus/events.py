"""Windows process-creation events: model, parsers, and a live reader.

Parsers normalize two event shapes into one :class:`ProcessEvent`:

* Windows Security ``4688`` (process creation, via built-in auditing)
* Sysmon ``Event ID 1`` (process creation)

The ``wevtutil``-based reader is a thin, stdlib-only adapter; parsing itself is
pure and unit-tested against fixture XML.
"""
from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass
class ProcessEvent:
    source: str          # "security" (4688) or "sysmon" (Event ID 1)
    event_id: int
    timestamp: str       # ISO-8601 string, may be empty
    pid: int
    parent_pid: int
    image: str
    command_line: str = ""
    user: str = ""
    hashes: str = ""
    integrity: str = ""
    parent_image: str = ""

    def sha256(self) -> str:
        """Extract the SHA256 from the Sysmon Hashes field, else empty string."""
        m = re.search(r"SHA256=([0-9A-Fa-f]{64})", self.hashes or "")
        return m.group(1).upper() if m else ""


def _data_dict(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    out = {}
    for el in root.iter():
        if el.tag.endswith("Data"):
            name = el.get("Name")
            if name:
                out[name] = (el.text or "").strip()
    return out


def _system_fields(xml_text: str):
    root = ET.fromstring(xml_text)
    event_id = 0
    timestamp = ""
    for el in root.iter():
        if el.tag.endswith("EventID"):
            try:
                event_id = int((el.text or "0").strip())
            except ValueError:
                event_id = 0
        elif el.tag.endswith("TimeCreated"):
            timestamp = el.get("SystemTime", "")
    return event_id, timestamp


def _to_int(value: str) -> int:
    if not value:
        return 0
    value = value.strip()
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except ValueError:
        return 0


def parse_security_event(xml_text: str) -> ProcessEvent | None:
    """Parse a Windows Security 4688 (process creation) event.

    Note the 4688 field-name gotcha: ``NewProcessId`` is the child, ``ProcessId``
    is the PARENT, and ``NewProcessName`` is the child image.
    """
    eid, ts = _system_fields(xml_text)
    if eid != 4688:
        return None
    d = _data_dict(xml_text)
    return ProcessEvent(
        source="security",
        event_id=eid,
        timestamp=ts,
        pid=_to_int(d.get("NewProcessId", "")),
        parent_pid=_to_int(d.get("ProcessId", "")),
        image=d.get("NewProcessName", ""),
        command_line=d.get("CommandLine", ""),
        user=d.get("SubjectUserName", ""),
        parent_image=d.get("ParentProcessName", ""),
    )


def parse_sysmon_event(xml_text: str) -> ProcessEvent | None:
    """Parse a Sysmon Event ID 1 (process creation) event."""
    eid, ts = _system_fields(xml_text)
    if eid != 1:
        return None
    d = _data_dict(xml_text)
    return ProcessEvent(
        source="sysmon",
        event_id=eid,
        timestamp=ts,
        pid=_to_int(d.get("ProcessId", "")),
        parent_pid=_to_int(d.get("ParentProcessId", "")),
        image=d.get("Image", ""),
        command_line=d.get("CommandLine", ""),
        user=d.get("User", ""),
        hashes=d.get("Hashes", ""),
        integrity=d.get("IntegrityLevel", ""),
        parent_image=d.get("ParentImage", ""),
    )


def parse_event(xml_text: str) -> ProcessEvent | None:
    ev = parse_security_event(xml_text)
    if ev is not None:
        return ev
    return parse_sysmon_event(xml_text)


def _split_events(xml_text: str) -> list[str]:
    # wevtutil /f:xml emits a run of <Event>…</Event> blocks with no single root.
    return re.findall(r"<Event\b.*?</Event>", xml_text, flags=re.DOTALL)


def _wevtutil(log: str, query: str, count: int) -> str:
    cmd = ["wevtutil", "qe", log, "/q:" + query, "/c:" + str(count), "/rd:true", "/f:xml"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout or ""


def read_security_events(count: int = 200) -> list[ProcessEvent]:
    """Read recent process-creation (4688) events from the Security log."""
    query = "*[System[(EventID=4688)]]"
    events = []
    for block in _split_events(_wevtutil("Security", query, count)):
        ev = parse_security_event(block)
        if ev is not None:
            events.append(ev)
    return events


def read_sysmon_events(count: int = 200) -> list[ProcessEvent]:
    """Read recent process-creation (Event ID 1) events from Sysmon."""
    query = "*[System[(EventID=1)]]"
    events = []
    for block in _split_events(_wevtutil("Microsoft-Windows-Sysmon/Operational", query, count)):
        ev = parse_sysmon_event(block)
        if ev is not None:
            events.append(ev)
    return events


@dataclass
class NetworkEvent:
    """Sysmon Event ID 3 — a network connection (process -> endpoint)."""
    source: str
    event_id: int
    timestamp: str
    pid: int
    image: str
    user: str = ""
    protocol: str = ""
    destination_ip: str = ""
    destination_port: int = 0
    destination_hostname: str = ""
    source_ip: str = ""
    initiated: bool = True

    def endpoint(self) -> str:
        """Stable endpoint key for the graph — 'ip:port', or just 'ip'."""
        if self.destination_ip and self.destination_port:
            return f"{self.destination_ip}:{self.destination_port}"
        return self.destination_ip


def parse_sysmon_network_event(xml_text: str) -> NetworkEvent | None:
    """Parse a Sysmon Event ID 3 (network connection) event."""
    eid, ts = _system_fields(xml_text)
    if eid != 3:
        return None
    d = _data_dict(xml_text)
    return NetworkEvent(
        source="sysmon",
        event_id=eid,
        timestamp=ts,
        pid=_to_int(d.get("ProcessId", "")),
        image=d.get("Image", ""),
        user=d.get("User", ""),
        protocol=d.get("Protocol", ""),
        destination_ip=d.get("DestinationIp", ""),
        destination_port=_to_int(d.get("DestinationPort", "")),
        destination_hostname=d.get("DestinationHostname", ""),
        source_ip=d.get("SourceIp", ""),
        initiated=(d.get("Initiated", "").strip().lower() != "false"),
    )


def read_sysmon_network_events(count: int = 200) -> list[NetworkEvent]:
    """Read recent network-connection (Event ID 3) events from Sysmon."""
    query = "*[System[(EventID=3)]]"
    events = []
    for block in _split_events(_wevtutil("Microsoft-Windows-Sysmon/Operational", query, count)):
        ev = parse_sysmon_network_event(block)
        if ev is not None:
            events.append(ev)
    return events
