"""The 5-stage sandbox pipeline, wired into Argus's score/decide/LLM flow.

  1. Host Orchestrator   revert clean snapshot + power on the guest
  2. Isolated Guest VM   inject + detonate the sample (guest agent + Sysmon)
  3. Fake Network Sink   tcpdump the isolated bridge; FakeDNS/INetSim answer
  4. Snapshot Revert     hard-kill the guest, harvest telemetry, revert clean
  5. Argus AI Dissection score every process event, trace the execution chain,
                         and ask the local model for intent + mitigation

Stages 1-4 are delegated to :class:`ArgusSandboxManager.detonate_attachment`
(already fail-safe about the final revert). Stage 5 is pure: score process
events through ``score_event``, fold in dropped artifacts / persistence / DNS
C2 signals into a summary, and hand that summary to the dissection model.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from argus.config import Config
from argus.sandbox.config import SandboxConfig
from argus.sandbox.dissect import dissect as _default_dissect
from argus.sandbox.orchestrator import ArgusSandboxManager
from argus.sandbox.telemetry import (
    SandboxTelemetry,
    detect_dropped_files,
    detect_persistence,
    execution_chain,
    summarize,
)


@dataclass
class SandboxReport:
    """The structured result of one detonation, ready for the analyst + dashboard."""
    sample: str = ""
    verdict: str = "UNCERTAIN"           # the dissection model's call
    confidence: float = 0.5
    primary_intent: str = ""
    decision: str = "allow"              # Argus heuristic decision (score -> decide)
    score: int = 0
    severity: str = "low"
    execution_chain: list[str] = field(default_factory=list)
    network_endpoints: list[str] = field(default_factory=list)
    dns_queries: list[str] = field(default_factory=list)
    dropped_files: list[str] = field(default_factory=list)
    persistence: list[str] = field(default_factory=list)
    mitigation_steps: list[str] = field(default_factory=list)
    dissection: dict = field(default_factory=dict)
    summary: str = ""
    pcap: str = ""
    report_path: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "sample": self.sample,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "primary_intent": self.primary_intent,
            "decision": self.decision,
            "score": self.score,
            "severity": self.severity,
            "execution_chain": self.execution_chain,
            "network_endpoints": self.network_endpoints,
            "dns_queries": self.dns_queries,
            "dropped_files": self.dropped_files,
            "persistence": self.persistence,
            "mitigation_steps": self.mitigation_steps,
            "pcap": self.pcap,
        }


def _max_process_score(tel: SandboxTelemetry, score_fn) -> tuple[int, object]:
    """Highest heuristic score across harvested process events (and the ScoreResult)."""
    best, best_score = None, 0
    for ev in tel.process_events:
        s = score_fn(ev)
        if s.points > best_score:
            best, best_score = s, s.points
    return best_score, best


def run_pipeline(
    cfg: Config,
    sandbox: SandboxConfig,
    manager: ArgusSandboxManager,
    sample_path,
    *,
    dissect_fn: Optional[Callable] = None,
    score_fn: Optional[Callable] = None,
    decide_fn: Optional[Callable] = None,
    severity_fn: Optional[Callable] = None,
    dry_run: bool = True,
) -> SandboxReport:
    """Run all five stages for one sample and return a :class:`SandboxReport`.

    ``dry_run`` (default True) skips the detonation lifecycle (stages 1-4) and
    reuses any telemetry already dumped to the telemetry dir — the safe default
    for tests and for re-analysis of a prior run. Set False to actually detonate.
    """
    if score_fn is None:
        from argus.score import score_event as score_fn
    if decide_fn is None:
        from argus.engine import decide as decide_fn
    if severity_fn is None:
        from argus.engine import severity as severity_fn
    if dissect_fn is None:
        dissect_fn = _default_dissect

    sample = str(sample_path)
    if dry_run:
        tel = manager.harvest_telemetry()
        pcap = ""
    else:
        run = manager.detonate_attachment(sample_path)
        tel = run["telemetry"]
        pcap = run.get("pcap", "")

    # ---- stage 5a: deterministic scoring + structure ------------------------
    score_pts, best_score = _max_process_score(tel, score_fn)
    decision = decide_fn(best_score, cfg) if best_score is not None else "allow"
    severity_label = severity_fn(score_pts)
    chains = execution_chain(tel.process_events)
    dropped = [d.path for d in detect_dropped_files(tel.file_creates)]
    persistence = detect_persistence(tel.registry_events)
    endpoints = [n.endpoint() for n in tel.network_events]
    dns = [d.query_name for d in tel.dns_queries if d.query_name]
    summary = summarize(tel, attachment_name=_basename(sample))

    # ---- stage 5b: AI dissection -------------------------------------------
    if cfg.llm_enabled:
        dissection = dissect_fn(
            summary,
            model=cfg.llm_model, url=cfg.llm_url, api_key=cfg.llm_api_key,
        )
    else:
        dissection = {"verdict": "UNCERTAIN", "confidence": 0.5, "primary_intent": "",
                      "execution_chain": [], "mitigation_steps": [],
                      "reason": "llm disabled (--no-llm)"}

    rep = SandboxReport(
        sample=sample,
        verdict=dissection.get("verdict", "UNCERTAIN"),
        confidence=float(dissection.get("confidence", 0.5)),
        primary_intent=dissection.get("primary_intent", ""),
        decision=decision,
        score=score_pts,
        severity=severity_label,
        execution_chain=chains,
        network_endpoints=endpoints,
        dns_queries=dns,
        dropped_files=dropped,
        persistence=persistence,
        mitigation_steps=dissection.get("mitigation_steps", []),
        dissection=dissection,
        summary=summary,
        pcap=pcap,
    )

    # ---- persist the report alongside the detections log --------------------
    try:
        from argus.store import append_jsonl
        sandbox.ensure_dirs()
        report_path = sandbox.work_dir / f"report_{_basename(sample)}_{int(time.time())}.jsonl"
        append_jsonl(report_path, rep.to_dict())
        rep.report_path = str(report_path)
    except Exception:  # noqa: BLE001 — reporting must never crash a detonation
        pass

    return rep


def _basename(path: str) -> str:
    import os
    return os.path.basename(path) or path
