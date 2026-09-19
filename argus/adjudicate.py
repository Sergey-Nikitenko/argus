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


def _prompt_for(ev: ProcessEvent, score: ScoreResult) -> str:
    reasons = "; ".join(score.reasons) or "(none)"
    return (
        "A process was flagged with score %d. Decide whether it is MALICIOUS (a real threat "
        "that should be quarantined) or BENIGN (a false positive that should be allowed).\n\n"
        "Image: %s\n"
        "Command line: %s\n"
        "Parent: %s\n"
        "User: %s\n"
        "Heuristic reasons: %s\n\n"
        "How to read the signals: an encoded PowerShell command (-enc / -EncodedCommand) is how "
        "attackers obfuscate code, and combined with -nop (no profile) or a cmd.exe parent it is a "
        "classic malware pattern (e.g. an IEX download cradle). A bare powershell.exe with a normal "
        "command is benign. Judge the ACTUAL command, not just the executable's name.\n\n"
        "Reply with exactly one word first — MALICIOUS, BENIGN, or UNCERTAIN — then a one-sentence reason."
    ) % (score.points, ev.image or "(unknown)", ev.command_line or "(empty)",
         ev.parent_image or "(unknown)", ev.user or "(unknown)", reasons)


def adjudicate(ev: ProcessEvent, score: ScoreResult, *,
               model: str = DEFAULT_MODEL, url: str = DEFAULT_URL, timeout: int = 600) -> dict:
    """Ask the local model: MALICIOUS / BENIGN / UNCERTAIN. Never raises — any failure is UNCERTAIN."""
    prompt = _prompt_for(ev, score)
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system",
             "content": "You are a strict endpoint-threat adjudicator. Judge the command, not the executable name."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
        "max_tokens": 2048,
    }).encode("utf-8")
    req = urllib.request.Request(url, data=payload,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data["choices"][0]["message"]["content"]
    except Exception as exc:  # noqa: BLE001
        return {"verdict": "UNCERTAIN", "reason": f"model unavailable: {exc}", "model": model}

    m = re.search(r"\b(MALICIOUS|BENIGN|UNCERTAIN)\b", text or "", re.IGNORECASE)
    verdict = m.group(1).upper() if m else "UNCERTAIN"
    return {"verdict": verdict, "reason": (text or "").strip(), "model": model}
