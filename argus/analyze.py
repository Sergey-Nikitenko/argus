"""Batch AI analysis of the session log — the self-training loop.

Runs the local model over recent session-log *signatures* (deduplicated behavioral
patterns, not raw events), classifies each as MALICIOUS / BENIGN / UNCERTAIN, and
ingests the verdicts into memory so the watcher learns from what it has seen.

Verdicts are ingested at MEDIUM confidence ("model_only") — they land in the episodic
tier and inform future adjudication, but only an analyst (or the dashboard's FP/TP
buttons) promotes them to high-confidence ground truth. This preserves the
poisoning guard: a model's opinion never becomes the baseline on its own.
"""
from __future__ import annotations

import time

from .adjudicate import adjudicate
from .events import ProcessEvent
from .memory import MemoryRecord
from .score import score_event
from .signature import BehaviorSignature, signature_id
from .store import read_jsonl


def analyze_recent(cfg, memory, model=None, url=None, limit: int = 40):
    """Classify recent session-log signatures via the model and ingest verdicts.

    Returns a list of dicts: {memory_id, verdict, image, command_line, score}.
    """
    entries = read_jsonl(cfg.session_log_path, limit)
    results = []
    seen = set()
    for e in entries:
        ev = ProcessEvent(
            source="session", event_id=1, timestamp=e.get("ts", ""),
            pid=int(e.get("pid", 0) or 0), parent_pid=0,
            image=e.get("image", ""), command_line=e.get("command_line", ""),
            user=e.get("user", ""), parent_image=e.get("parent_image", ""),
        )
        score = score_event(ev)
        sig = BehaviorSignature.from_event(ev, score, host=cfg.hostname)
        sid = signature_id(sig)
        if sid in seen:
            continue
        seen.add(sid)
        try:
            verdict = adjudicate(
                ev, score, history=[],
                model=model or cfg.llm_model, url=url or cfg.llm_url,
                api_key=getattr(cfg, "llm_api_key", ""),
            ).get("verdict", "UNCERTAIN")
        except Exception:  # noqa: BLE001 — model down means UNCERTAIN, never raise
            verdict = "UNCERTAIN"
        if memory is not None and verdict in ("BENIGN", "MALICIOUS"):
            memory.ingest(MemoryRecord(
                id=sid, signature=sig, verdict=verdict,
                outcome="confirmed_false_positive" if verdict == "BENIGN" else "verified_incident",
                confidence="medium",  # model_only — analyst still promotes to ground truth
                timestamp=e.get("ts", ""), ts=time.time(), score=score.points,
                image=e.get("image", ""), host=cfg.hostname, user=e.get("user", ""),
            ))
        results.append({
            "memory_id": sid, "verdict": verdict,
            "image": e.get("image", ""), "command_line": e.get("command_line", ""),
            "score": score.points,
        })
    if memory is not None:
        memory.save()
    return results
