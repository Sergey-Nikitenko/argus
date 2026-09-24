"""Investigation tools the local model can call during adjudication (SOAR).

Each tool is a name + JSON-schema + callable. The agent loop hands these to the
model; when the model emits a tool call, Argus runs the real query and feeds the
result back. Tools return JSON strings so the model gets structured evidence.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Callable


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict
    run: Callable[..., str]   # returns a JSON string

    def schema(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


def _process_lineage(graph, image: str) -> str:
    """Cross-session lineage: who spawned it, what it spawned, what it reached."""
    if graph is None:
        return json.dumps({"image": image, "error": "lineage graph unavailable"})
    return json.dumps({
        "image": image,
        "parents": [{"image": e.parent, "count": e.count} for e in graph.parents(image)],
        "children": [{"image": e.child, "count": e.count} for e in graph.children(image)],
        "endpoints": [{"endpoint": e.child, "count": e.count} for e in graph.connections(image)],
    })


def _binary_signature(image: str) -> str:
    """Authenticode signature status via PowerShell Get-AuthenticodeSignature."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-AuthenticodeSignature -LiteralPath '{image}').Status"],
            capture_output=True, text=True, timeout=25,
        )
        status = (r.stdout or "").strip() or (r.stderr or "").strip()
        return json.dumps({"image": image, "signature_status": status})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"image": image, "error": str(exc)})


def _virustotal(api_key: str, sha256: str) -> str:
    from .verdict import lookup_sha256
    return json.dumps({"sha256": sha256, "reputation": lookup_sha256(sha256, api_key)})


def make_tools(graph=None, vt_api_key: str = "") -> list[Tool]:
    """Build the investigation tools available to the adjudication agent."""
    return [
        Tool(
            "process_lineage",
            "Query the cross-session lineage graph for a process image: its parents, "
            "children, and the network endpoints it has contacted.",
            {"type": "object", "properties": {"image": {"type": "string"}}, "required": ["image"]},
            lambda image: _process_lineage(graph, image),
        ),
        Tool(
            "binary_signature",
            "Check the Windows Authenticode digital-signature status of a binary path.",
            {"type": "object", "properties": {"image": {"type": "string"}}, "required": ["image"]},
            _binary_signature,
        ),
        Tool(
            "virustotal",
            "Look up a SHA256 hash reputation on VirusTotal.",
            {"type": "object", "properties": {"sha256": {"type": "string"}}, "required": ["sha256"]},
            lambda sha256: _virustotal(vt_api_key, sha256),
        ),
        Tool(
            "blast_radius",
            "Compute the hosts, users, and edge counts touching a process image (scope assessment).",
            {"type": "object", "properties": {"image": {"type": "string"}}, "required": ["image"]},
            lambda image: json.dumps(graph.blast_radius(image)) if graph is not None
            else json.dumps({"error": "lineage graph unavailable"}),
        ),
    ]
