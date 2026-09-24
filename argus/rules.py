"""Sigma rule review queue — propose, list, approve.

Novel MALICIOUS patterns become PROPOSED rules; the analyst reviews and approves
them, which writes the YAML to ``sigma_rules/`` for SIEM deployment. Backed by
the same append-only JSONL substrate as the rest of Argus.
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path

from .rulegen import to_yaml
from .store import append_jsonl, read_jsonl


def propose_rule(cfg, rule: dict, techniques: list, source: str = "sigma") -> str:
    """Append a PROPOSED rule. Returns its id."""
    rid = uuid.uuid4().hex[:12]
    append_jsonl(cfg.rules_path, {
        "id": rid, "source": source, "status": "proposed",
        "rule": rule, "techniques": techniques, "ts": time.time(),
    })
    return rid


def list_rules(cfg, limit: int = 100) -> list[dict]:
    """Latest record per rule id (approve appends a new record, so keep the last)."""
    rows = read_jsonl(cfg.rules_path, 2000)
    latest: dict[str, dict] = {}
    for r in rows:
        latest[r.get("id", "")] = r
    return list(latest.values())[-limit:]


def approve_rule(cfg, rule_id: str) -> str:
    """Write a proposed rule's YAML to ``sigma_rules/`` and mark it approved."""
    for rec in reversed(read_jsonl(cfg.rules_path, 2000)):
        if rec.get("id") == rule_id and rec.get("status") == "proposed":
            out_dir = Path(cfg.sigma_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            path = out_dir / f"{rule_id}.yml"
            path.write_text(to_yaml(rec["rule"]), encoding="utf-8")
            append_jsonl(cfg.rules_path, {**rec, "status": "approved", "approved_ts": time.time()})
            return str(path)
    raise KeyError(f"no proposed rule {rule_id}")
