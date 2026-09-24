"""Sigma rule generation — turn novel attack patterns into reviewable rules.

When Argus adjudicates a novel, MALICIOUS pattern, it drafts a Sigma rule from
the detection's signals (a deterministic baseline), optionally enriched by the
local model. Rules land in a PROPOSED state for analyst review; approving one
writes it to ``sigma_rules/`` for deployment to a SIEM.
"""
from __future__ import annotations

import json
from pathlib import PureWindowsPath

from .score import SUSPICIOUS_CMDLINE_PATTERNS


def _cmdline_tokens(cmdline: str) -> list[str]:
    """Stable detection tokens from the suspicious-command-line patterns that matched."""
    low = (cmdline or "").lower()
    out = []
    for pattern, _reason, _pts, _tech in SUSPICIOUS_CMDLINE_PATTERNS:
        m = pattern.search(low)
        if m:
            out.append(m.group(0))
    return out


def sigma_rule_from_detection(ev, score) -> dict:
    """Deterministic Sigma process_creation rule from a detection's signals."""
    base = PureWindowsPath(ev.image or "").name
    selection: dict = {}
    if base:
        selection["Image|endswith"] = "\\" + base
    tokens = _cmdline_tokens(ev.command_line)
    if tokens:
        selection["CommandLine|contains|all"] = tokens
    if not selection:
        selection["Image|endswith"] = "*"
    techniques = [t["id"] for t in score.techniques_deduped()]
    title = (score.reasons[0] if score.reasons else "suspicious process activity")[:90]
    return {
        "title": title,
        "status": "experimental",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"selection": selection, "condition": "selection"},
        "tags": [f"attack.{t.lower().replace('.', '_')}" for t in techniques],
    }


def to_yaml(rule: dict) -> str:
    """Serialize a Sigma rule dict to YAML (dependency-free; covers dicts, lists,
    strings — enough for the Sigma schema)."""
    return "\n".join(_emit(rule))


def _emit(node, indent: int = 0) -> list[str]:
    pad = "  " * indent
    if isinstance(node, dict):
        lines = []
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{pad}{k}:")
                lines.extend(_emit(v, indent + 1))
            else:
                lines.append(f"{pad}{k}: {_scalar(v)}")
        return lines
    if isinstance(node, list):
        lines = []
        for item in node:
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}-")
                lines.extend(_emit(item, indent + 1))
            else:
                lines.append(f"{pad}- {_scalar(item)}")
        return lines
    return [f"{pad}{_scalar(node)}"]


def _scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    return json.dumps(s)  # safe-quote strings


def draft_rule_with_model(ev, score, model, url, timeout: int = 600, post_fn=None) -> dict:
    """Ask the local model to draft a richer Sigma rule (JSON). Falls back to the
    deterministic rule if the model is absent or the reply is unusable."""
    import urllib.request

    prompt = (
        "Draft a Sigma rule (process_creation) that detects this pattern. Reply with "
        "ONLY a JSON object matching the Sigma schema: {\"title\", \"status\", "
        "\"logsource\": {\"category\", \"product\"}, \"detection\": {\"selection\", "
        "\"condition\"}, \"tags\"}.\n\n"
        f"Image: {ev.image}\nCommandLine: {ev.command_line}\n"
        f"Techniques: {[t['id'] for t in score.techniques_deduped()]}\n"
        f"Reasons: {score.reasons}"
    )
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a Sigma detection-rule author. Output JSON only."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0, "max_tokens": 512,
    }).encode("utf-8")
    post = post_fn or (lambda u, p, t: _http_post(u, p, t))
    try:
        data = post(url, {"payload": payload}, timeout)
    except Exception:
        return sigma_rule_from_detection(ev, score)
    try:
        text = data["choices"][0]["message"]["content"]
        obj = json.loads(text)
        return obj if isinstance(obj, dict) and "detection" in obj else sigma_rule_from_detection(ev, score)
    except Exception:
        return sigma_rule_from_detection(ev, score)


def _http_post(url, payload, timeout):
    import urllib.request
    req = urllib.request.Request(url, data=payload["payload"],
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))
