"""Dynamic detection-rule store — decouple deterministic patterns from code.

The reloadable PATTERN rules (command-line regex + score + MITRE technique + a
binary/gate) live in a JSON file (data-dir ``detection_rules.json``) and can be
hot-reloaded without a restart or rebuild. Heuristic scoring (dropper paths,
LOLBin detection, entropy, dropped-script execution) stays in ``score.py``.

Stdlib only. A rule dict is::

    {"id", "pattern", "points", "reason", "technique", "technique_name",
     "binary" ("", or an exact basename gate), "gate" ("shell_lolbin" |
     "shell_script" | "")}

``compile_rules`` turns those into ready-to-match dicts with a compiled ``rx``.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path


def compile_rules(raw: list) -> list:
    """Compile raw rule dicts into match-ready dicts (skipping malformed ones)."""
    out = []
    for d in raw:
        try:
            rx = re.compile(d.get("pattern", "") or "", re.I)
        except (re.error, TypeError):
            continue
        out.append({
            "id": d.get("id", ""),
            "rx": rx,
            "points": int(d.get("points", 0)),
            "reason": d.get("reason", ""),
            "technique": d.get("technique", ""),
            "technique_name": d.get("technique_name", ""),
            "binary": (d.get("binary", "") or "").lower(),
            "gate": d.get("gate", "") or "",
        })
    return out


def load_rules(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    data = json.loads(p.read_text(encoding="utf-8"))
    return compile_rules(data.get("rules", []))


def dump_rules(raw: list, path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"version": 1, "rules": raw}, indent=2), encoding="utf-8")


class RuleEngine:
    """Loads rules from JSON and hot-reloads on file mtime change (throttled).

    ``reload_if_changed()`` is cheap and throttled, so it can be called once per
    ingestion poll without hurting throughput. A changed file re-compiles the rule
    set in place; the caller swaps it into the scorer via ``set_active_rules``.
    """

    def __init__(self, path, check_interval: float = 5.0):
        self.path = Path(path)
        self.check_interval = check_interval
        self.rules: list = []
        self._mtime = 0.0
        self._last_check = 0.0
        self.reload_if_changed(force=True)

    def reload_if_changed(self, force: bool = False) -> bool:
        now = time.time()
        if not force and now - self._last_check < self.check_interval:
            return False
        self._last_check = now
        if not self.path.exists():
            return False
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return False
        if not force and mtime <= self._mtime:
            return False
        try:
            self.rules = load_rules(self.path)
        except (json.JSONDecodeError, OSError):
            return False
        self._mtime = mtime
        return True
