"""Agentic adjudication — the OpenAI tool-call loop.

Turns the local model from a passive judge into an active investigator: it is
given investigation tools (process lineage, signature check, VirusTotal) and may
call them before returning a final verdict. Stdlib-only; speaks the OpenAI tools
API that LM Studio / llama.cpp expose.
"""
from __future__ import annotations

import json
import urllib.request

from .adjudicate import DEFAULT_MODEL, DEFAULT_URL, _prompt_for, parse_verdict
from .events import ProcessEvent
from .score import ScoreResult
from .tools import Tool

SYSTEM = (
    "You are a strict endpoint-threat adjudicator. You may call the provided "
    "investigation tools to gather evidence before deciding. When done, output "
    'ONLY a JSON object: {"verdict": "MALICIOUS" or "BENIGN" or "UNCERTAIN", '
    '"confidence": 0.0, "reason": "one short sentence"}.'
)


def _post(url: str, payload: dict, timeout: int) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run_agent(messages: list, tools: list[Tool], model: str, url: str,
              timeout: int = 600, max_rounds: int = 4, post_fn=None) -> dict:
    """Run the tool-call loop. Returns a parsed verdict dict. Never raises."""
    post = post_fn or _post
    tool_map = {t.name: t for t in tools}
    schemas = [t.schema() for t in tools]
    try:
        for _ in range(max_rounds):
            data = post(url, {"model": model, "messages": messages, "tools": schemas,
                              "temperature": 0.0, "max_tokens": 256}, timeout)
            msg = data["choices"][0]["message"]
            tool_calls = msg.get("tool_calls")
            if not tool_calls:
                return parse_verdict(msg.get("content", ""))
            messages.append(msg)  # assistant message carrying tool_calls
            for tc in tool_calls:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                try:
                    args = json.loads(fn.get("arguments", "{}") or "{}")
                except json.JSONDecodeError:
                    args = {}
                tool = tool_map.get(name)
                if tool is None:
                    result = json.dumps({"error": f"unknown tool {name}"})
                else:
                    try:
                        result = tool.run(**args)
                    except Exception as exc:  # noqa: BLE001
                        result = json.dumps({"error": str(exc)})
                messages.append({"role": "tool", "tool_call_id": tc.get("id", ""),
                                 "content": result})
    except Exception as exc:  # noqa: BLE001
        return {"verdict": "UNCERTAIN", "confidence": 0.0, "reason": f"agent failed: {exc}"}
    return {"verdict": "UNCERTAIN", "confidence": 0.0, "reason": "agent did not reach a verdict"}


def adjudicate_agent(ev: ProcessEvent, score: ScoreResult, history=None, tools=None,
                     model: str = DEFAULT_MODEL, url: str = DEFAULT_URL,
                     timeout: int = 600, max_rounds: int = 4, post_fn=None) -> dict:
    """Investigate-then-judge: give the model tools, then parse the final verdict."""
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": _prompt_for(ev, score, history)},
    ]
    result = run_agent(messages, tools or [], model, url, timeout, max_rounds, post_fn=post_fn)
    result["model"] = model
    return result
