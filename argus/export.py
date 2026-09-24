"""Telemetry standardization — export detections as OCSF / STIX 2.1.

Lets Argus hand findings to SIEMs, data lakes, and threat-intel platforms in
standard shapes instead of its own JSONL. Pure and deterministic (no I/O). Takes
a detection dict (``Report.to_dict()``) so both the CLI and the server can use it.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import PureWindowsPath

# Argus severity -> OCSF severity_id (0 unknown, 1 info, 2 low, 3 medium, 4 high, 5 critical)
_SEV_OCSF = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _iso_ts(ts: str) -> str:
    return ts or datetime.now(timezone.utc).isoformat()


def _base(path: str) -> str:
    return PureWindowsPath(path or "").name


def to_ocsf(det: dict) -> dict:
    """A single OCSF Process Activity (class_uid 1007) event."""
    return {
        "category_uid": 1,                       # System Activity
        "class_uid": 1007,                       # Process Activity
        "activity_id": 1,                        # Launch
        "time": _iso_ts(det.get("timestamp", "")),
        "severity_id": _SEV_OCSF.get(det.get("severity", ""), 1),
        "process": {
            "pid": det.get("pid"),
            "cmd_line": det.get("command_line", ""),
            "file": {"name": _base(det.get("image", "")), "path": det.get("image", "")},
            "parent_process": {
                "pid": det.get("parent_pid"),
                "file": {"name": _base(det.get("parent_image", "")), "path": det.get("parent_image", "")},
            },
        },
        "actor": {"user": {"name": det.get("user", "")}},
        "unmapped": {
            "score": det.get("score", 0),
            "decision": det.get("decision", ""),
            "techniques": [t["id"] for t in det.get("techniques", [])],
            "reasons": det.get("reasons", []),
            "sha256": det.get("sha256", ""),
            "memory_id": det.get("memory_id", ""),
        },
    }


def to_stix(det: dict) -> dict:
    """A STIX 2.1 bundle: an observed-data SDO, plus a malware + indicator when MALICIOUS."""
    now = datetime.now(timezone.utc).isoformat()
    ts = _iso_ts(det.get("timestamp", ""))
    objects = []

    objects.append({
        "type": "observed-data",
        "id": f"observed-data--{uuid.uuid4()}",
        "created": now, "modified": now,
        "first_observed": ts, "last_observed": ts, "number_observed": 1,
        "objects": {
            "0": {"type": "process", "pid": det.get("pid"),
                  "command_line": det.get("command_line", "")},
            "1": {"type": "file", "name": _base(det.get("image", ""))},
        },
        "x_argus_score": det.get("score", 0),
        "x_argus_decision": det.get("decision", ""),
        "x_argus_techniques": [t["id"] for t in det.get("techniques", [])],
    })

    if det.get("decision") == "quarantine":
        mal_id = f"malware--{uuid.uuid4()}"
        objects.append({
            "type": "malware",
            "id": mal_id,
            "created": now, "modified": now,
            "name": _base(det.get("image", "")) or "unknown",
            "is_family": False,
        })
        objects.append({
            "type": "indicator",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now, "modified": now,
            "name": f"Argus detection: {det.get('score', 0)}",
            "pattern": f"[process:command_line = '{det.get('command_line', '')}']",
            "valid_from": now,
            "malware_ref": mal_id,
        })

    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
