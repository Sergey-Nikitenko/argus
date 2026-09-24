"""LLM adjudication — the "sensory guidance system."

Heuristics flag, a local model judges, and Argus only quarantines/kills what the model
confirms MALICIOUS. Speaks the OpenAI-compatible chat API (LM Studio / llama.cpp server),
so it works with any local model runner. A model that is absent, slow, or unsure yields
UNCERTAIN — fail-safe: when in doubt, do not kill.
"""
from __future__ import annotations

import json
import re
import urllib.request

from .events import ProcessEvent
from .score import ScoreResult

DEFAULT_URL = "http://localhost:1234/v1/chat/completions"  # LM Studio / llama.cpp server
DEFAULT_MODEL = "google/gemma-4-e4b"


def _prompt_for(ev: ProcessEvent, score: ScoreResult, history=None) -> str:
    reasons = "; ".join(score.reasons) or "(none)"
    hist_block = ""
    if history:
        lines = []
        for rec, sim in history:
            when = rec.timestamp[:19] if rec.timestamp else "past"
            lines.append(
                f"- {when} — {rec.signature.text()} — was {rec.verdict} "
                f"({rec.outcome}, confidence={rec.confidence})"
            )
        hist_block = (
            "\n\nHistorical Context (Retrieved Memory):\n" + "\n".join(lines) +
            "\n\nUse this memory to judge whether the current alert matches a known "
            "pattern (recurring false positive or a known incident) or is an anomalous "
            "deviation. Do NOT let it overrule clear evidence in the current event."
        )
    return (
        "A process was flagged with score %d. Decide whether it is MALICIOUS (a real threat "
        "that should be quarantined) or BENIGN (a false positive that should be allowed).\n\n"
        "Image: %s\n"
        "Command line: %s\n"
        "Parent: %s\n"
        "User: %s\n"
        "Heuristic reasons: %s%s\n\n"
        "How to read the signals: an encoded PowerShell command (-enc / -EncodedCommand) is how "
        "attackers obfuscate code, and combined with -nop (no profile) or a cmd.exe parent it is a "
        "classic malware pattern (e.g. an IEX download cradle). A bare powershell.exe with a normal "
        "command is benign. Judge the ACTUAL command, not just the executable's name.\n\n"
        "Reply with ONLY a JSON object and nothing else, with no markdown fences:\n"
        '{"verdict": "MALICIOUS" or "BENIGN" or "UNCERTAIN", "confidence": 0.0, "reason": "one short sentence"}'
    ) % (score.points, ev.image or "(unknown)", ev.command_line or "(empty)",
         ev.parent_image or "(unknown)", ev.user or "(unknown)", reasons, hist_block)


def parse_verdict(text: str) -> dict:
    """Parse the model's reply into {"verdict", "confidence", "reason"}.

    Prefers strict JSON (the schema we asked for); falls back to a regex scan of
    the raw text if the model ignored it. Never raises — always returns a sane
    UNCERTAIN on garbage."""
    verdict, confidence, reason = "UNCERTAIN", 0.5, ""
    try:
        obj = json.loads(text or "")
    except (json.JSONDecodeError, ValueError):
        obj = None
    if isinstance(obj, dict):
        verdict = (obj.get("verdict", "") or "").upper()
        try:
            confidence = float(obj.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        reason = str(obj.get("reason", ""))
    else:
        m = re.search(r"\b(MALICIOUS|BENIGN|UNCERTAIN)\b", text or "", re.IGNORECASE)
        verdict = m.group(1).upper() if m else "UNCERTAIN"
        reason = (text or "").strip()
    if verdict not in ("MALICIOUS", "BENIGN", "UNCERTAIN"):
        verdict = "UNCERTAIN"
    confidence = max(0.0, min(1.0, confidence))
    return {"verdict": verdict, "confidence": confidence, "reason": reason}


def adjudicate(ev: ProcessEvent, score: ScoreResult, *, history=None,
               model: str = DEFAULT_MODEL, url: str = DEFAULT_URL, timeout: int = 600,
               api_key: str = "") -> dict:
    """Ask the local model: MALICIOUS / BENIGN / UNCERTAIN. Never raises — any failure is UNCERTAIN.

    ``history`` is an optional list of ``(MemoryRecord, similarity)`` retrieved from the
    memory store; when present it is injected into the prompt as historical context."""
    prompt = _prompt_for(ev, score, history)
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system",
             "content": "You are a strict endpoint-threat adjudicator. Judge the command, not the executable name. Output JSON only."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
        "max_tokens": 256,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data["choices"][0]["message"]["content"]
    except Exception as exc:  # noqa: BLE001
        return {"verdict": "UNCERTAIN", "reason": f"model unavailable: {exc}", "model": model}

    # Prefer strict JSON ({"verdict", "confidence", "reason"}); fall back to a
    # regex scan of the raw text if the model ignored the schema.
    parsed = parse_verdict(text)
    parsed["model"] = model
    return parsed


def check_llm(url: str = DEFAULT_URL, timeout: int = 4) -> bool:
    """Cheap TCP reachability check for the local model endpoint."""
    import socket
    from urllib.parse import urlparse
    try:
        p = urlparse(url)
        s = socket.create_connection((p.hostname or "localhost", p.port or 80), timeout=timeout)
        s.close()
        return True
    except Exception:  # noqa: BLE001
        return False
