"""Dead-letter review queue + analyst signature proposal (analyst-in-the-loop).

Missed patterns — replay labels a record "malicious" but Argus scored it "allow" —
land in ``review.jsonl``. The analyst promotes one into a new detection rule that
is appended to the hot-reloadable rule store: no rebuild, picked up on the next
poll (within the 5s reload throttle).
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import PureWindowsPath

from .ruleset import dump_rules


def _review_path(cfg):
    return cfg.data_dir / "review.jsonl"


def append_review(cfg, ev, score, decision, label="") -> None:
    from .store import append_jsonl
    append_jsonl(_review_path(cfg), {
        "time": datetime.now().isoformat(timespec="seconds"),
        "image": ev.image, "parent_image": ev.parent_image,
        "command_line": ev.command_line, "user": ev.user,
        "score": score, "decision": decision, "label": label,
    })


def read_review(cfg) -> list:
    from .store import read_jsonl
    return read_jsonl(_review_path(cfg), 500)


def propose_rule(image, command_line, points=45,
                 technique="T1059", technique_name="Command and Scripting Interpreter"):
    """Extract a signature rule from a missed event.

    Takes the distinctive command-line tokens (everything after the image name),
    regex-escapes them and joins with ``.*``, gated to the exact binary basename —
    a deterministic, reviewable signature rather than a guess."""
    base = PureWindowsPath(image or "").name.lower()
    cl = (command_line or "").strip()
    if not base or not cl:
        return None
    tokens = cl.split()
    while tokens and tokens[0].lower().strip('"') in (base, base + ".exe"):
        tokens = tokens[1:]
    if not tokens:
        return None
    pattern = r".*".join(re.escape(t) for t in tokens)
    hid = hashlib.md5(cl.encode("utf-8")).hexdigest()[:10]
    return {
        "id": f"proposed_{base}_{hid}",
        "pattern": pattern,
        "points": points,
        "reason": f"analyst-proposed ({base})",
        "technique": technique,
        "technique_name": technique_name,
        "binary": base,
        "gate": "",
    }


def promote_to_rule(cfg, image, command_line, points=45) -> dict | None:
    """Append a proposed rule (from a reviewed event) to the active rule store."""
    rule = propose_rule(image, command_line, points=points)
    if rule is None:
        return None
    p = cfg.detection_rules_path
    raw = []
    if p.exists():
        try:
            raw = json.loads(p.read_text(encoding="utf-8")).get("rules", [])
        except (json.JSONDecodeError, OSError):
            raw = []
    raw.append(rule)
    dump_rules(raw, p)
    return rule
