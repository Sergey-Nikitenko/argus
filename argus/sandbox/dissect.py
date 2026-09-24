"""Argus AI Dissection — stage 5: turn harvested telemetry into a structured verdict.

After the guest is killed and reverted, the collected Sysmon telemetry, network
summary, and dropped-file signatures are handed to the local model with a prompt
that asks for the THREE things an analyst needs next: primary intent, the
execution chain, and concrete mitigation steps. Mirrors argus.adjudicate's
OpenAI-compatible chat call and fail-safe parse (any failure -> UNCERTAIN, never
raise).
"""
from __future__ import annotations

import json
import re
import urllib.request

DEFAULT_MODEL = "google/gemma-4-e4b"
DEFAULT_URL = "http://localhost:1234/v1/chat/completions"

_SYSTEM = (
    "You are Argus Sandbox Dissection Engine. Analyze the execution log of this "
    "attachment and produce a structured threat assessment."
)


def build_dissection_prompt(summary: str, attachment_name: str = "sample") -> str:
    """The user prompt for the dissection model, from the telemetry summary."""
    return (
        f"{summary}\n\n"
        f"Task: Provide a structured JSON analysis detailing:\n"
        f"1. Primary Intent (e.g., Ransomware, Infostealer, Downloader, Keylogger)\n"
        f"2. Execution Chain (Parent/Child relationships)\n"
        f"3. Mitigation Steps (concrete containment + remediation actions)\n\n"
        f"Reply with ONLY a JSON object and nothing else, no markdown fences:\n"
        f'{{"primary_intent": "<intent>", "execution_chain": ["<parent> -> <child>", ...], '
        f'"mitigation_steps": ["<step>", ...], "verdict": "MALICIOUS|BENIGN|UNCERTAIN", '
        f'"confidence": 0.0}}'
    )


def parse_dissection(text: str) -> dict:
    """Parse the model's JSON into a sane dissection dict. Never raises."""
    out = {
        "primary_intent": "",
        "execution_chain": [],
        "mitigation_steps": [],
        "verdict": "UNCERTAIN",
        "confidence": 0.5,
        "reason": "",
    }
    try:
        obj = json.loads(text or "")
    except (json.JSONDecodeError, ValueError):
        obj = None
    if isinstance(obj, dict):
        out["primary_intent"] = str(obj.get("primary_intent", "") or "")
        chain = obj.get("execution_chain", [])
        if isinstance(chain, str):
            chain = [chain]
        out["execution_chain"] = [str(c) for c in chain if c] if isinstance(chain, list) else []
        steps = obj.get("mitigation_steps", [])
        if isinstance(steps, str):
            steps = [steps]
        out["mitigation_steps"] = [str(s) for s in steps if s] if isinstance(steps, list) else []
        v = (obj.get("verdict", "") or "").upper()
        out["verdict"] = v if v in ("MALICIOUS", "BENIGN", "UNCERTAIN") else "UNCERTAIN"
        try:
            out["confidence"] = float(obj.get("confidence", 0.5))
        except (TypeError, ValueError):
            out["confidence"] = 0.5
        out["reason"] = str(obj.get("reason", "") or "")
    else:
        m = re.search(r"\b(MALICIOUS|BENIGN|UNCERTAIN)\b", text or "", re.IGNORECASE)
        out["verdict"] = m.group(1).upper() if m else "UNCERTAIN"
        out["reason"] = (text or "").strip()
    out["confidence"] = max(0.0, min(1.0, out["confidence"]))
    return out


def dissect(summary: str, *, attachment_name: str = "sample",
            model: str = DEFAULT_MODEL, url: str = DEFAULT_URL,
            api_key: str = "", timeout: int = 600) -> dict:
    """Ask the local model to dissect the run. Any failure -> UNCERTAIN, never raise."""
    prompt = build_dissection_prompt(summary, attachment_name)
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
        "max_tokens": 512,
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
        return {"verdict": "UNCERTAIN", "confidence": 0.5, "primary_intent": "",
                "execution_chain": [], "mitigation_steps": [],
                "reason": f"model unavailable: {exc}", "model": model}
    parsed = parse_dissection(text)
    parsed["model"] = model
    return parsed
