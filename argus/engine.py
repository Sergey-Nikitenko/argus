"""Decision + response pipeline.

Turns a scored event into an ``allow`` / ``flag`` / ``quarantine`` decision plus a
severity tier, and (when not in dry-run) performs the configured side effects.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from .config import Config
from .events import ProcessEvent
from .memory import MemoryRecord
from .score import SUSPICIOUS_PATH_FRAGMENTS, ScoreResult, score_event
from .signature import BehaviorSignature, signature_id


HARD_EVIDENCE = 90  # stacked independent signals — a weak model cannot veto a kill this strong


def is_quarantinable(image: str) -> bool:
    """True only when the flagged binary lives in a dropper-friendly path.

    We move (quarantine) a *dropped payload*, never the trusted interpreter or
    system tool that was abused to run it — moving python.exe/powershell.exe off
    the box is a self-inflicted wound, not a remediation.
    """
    img = (image or "").lower()
    return any(frag in img for frag in SUSPICIOUS_PATH_FRAGMENTS)


def severity(points: int) -> str:
    if points >= 80:
        return "critical"
    if points >= 60:
        return "high"
    if points >= 40:
        return "medium"
    if points >= 20:
        return "low"
    return "info"


@dataclass
class Report:
    event: ProcessEvent
    score: ScoreResult
    decision: str  # "allow" | "flag" | "quarantine"
    severity: str = "info"
    sha256: str = ""
    vt: str = ""
    actions: list = field(default_factory=list)
    adjudication: dict = field(default_factory=dict)
    memory_id: str = ""   # stable behavioral-signature id (feedback/promotion key)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.event.timestamp,
            "pid": self.event.pid,
            "parent_pid": self.event.parent_pid,
            "image": self.event.image,
            "parent_image": self.event.parent_image,
            "command_line": self.event.command_line,
            "user": self.event.user,
            "score": self.score.points,
            "severity": self.severity,
            "reasons": self.score.reasons,
            "techniques": self.score.techniques_deduped(),
            "decision": self.decision,
            "sha256": self.sha256,
            "virus_total": self.vt,
            "actions": self.actions,
            "adjudication": self.adjudication,
            "memory_id": self.memory_id,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def decide(score: ScoreResult, cfg: Config) -> str:
    if score.points >= cfg.contain_threshold:
        return "quarantine"     # auto-contain — no approval
    if score.points >= cfg.kill_threshold:
        return "propose"        # containment candidate — needs analyst approval
    if score.points >= cfg.flag_threshold:
        return "flag"
    return "allow"


def process_event(
    ev: ProcessEvent,
    cfg: Config,
    quarantine_fn=None,
    kill_fn=None,
    verdict_fn=None,
    adjudicate_fn=None,
    memory=None,
    graph=None,
    dump_fn=None,
) -> Report:
    score = score_event(ev)
    adjudication = {}

    # Relational memory: a never-before-seen parent->child spawn or a never-seen
    # binary are deviations from the learned baseline; record the edge either way
    # so the graph warms up and learns what "normal" looks like.
    if graph is not None:
        if ev.image and not graph.seen(ev.image):
            score.add(cfg.novel_process_points, "novel process (first observed on this host)")
        if ev.parent_image and ev.image:
            if graph.novel(ev.parent_image, ev.image):
                score.add(cfg.novel_edge_points, "novel parent->child relationship (first observed)")
            graph.record(ev.parent_image, ev.image, host=cfg.hostname, user=ev.user, timestamp=ev.timestamp)

    sig = BehaviorSignature.from_event(ev, score, host=cfg.hostname)
    sig_id = signature_id(sig)
    decision = decide(score, cfg)

    # Tiered pipeline: the vector lookup + local model are reserved for events that
    # actually reach adjudication. Everything below kill_threshold is short-circuited
    # so ingestion latency stays near zero.
    history = []
    known_benign = False
    if memory is not None and decision in ("quarantine", "propose"):
        history = memory.query(sig, k=cfg.memory_k)
        # Analyst ground-truth veto: if this EXACT behavioral signature (including
        # the decoded payload, when obfuscated) was already confirmed a false
        # positive, a would-be containment downgrades to a flag. Human ground truth
        # outranks the heuristic score — never re-propose destroying a behavior an
        # analyst already cleared.
        known_benign = any(
            r.confidence == "high" and r.verdict == "BENIGN" and r.id == sig_id
            for r, _ in history
        )
        if known_benign:
            decision = "flag"

    # Sensory guidance, two-speed: HARD EVIDENCE (>= 90) kills immediately — several
    # independent signals are stacked, so we do NOT block on a slow local model. Only a
    # BORDERLINE kill (kill_threshold .. 90) consults the model, and a non-MALICIOUS verdict
    # downgrades it to flag (fail-safe: when in doubt, do not destroy).
    if decision in ("quarantine", "propose") and adjudicate_fn is not None:
        if score.points >= HARD_EVIDENCE:
            adjudication = {"verdict": "MALICIOUS",
                            "reason": f"hard-evidence override (score {score.points} >= {HARD_EVIDENCE})",
                            "skipped_llm": True}
        else:
            try:
                adjudication = adjudicate_fn(ev, score, history)
            except Exception as exc:  # noqa: BLE001
                adjudication = {"verdict": "UNCERTAIN", "reason": f"adjudication failed: {exc}"}
            if adjudication.get("verdict") != "MALICIOUS":
                decision = "flag"

    report = Report(event=ev, score=score, decision=decision, severity=severity(score.points),
                    sha256=ev.sha256(), adjudication=adjudication, memory_id=sig_id)

    if known_benign:
        report.actions.append("known-benign signature (analyst-confirmed false positive) — downgraded to flag")

    # Quarantine the DROPPED SCRIPT itself — the malicious artifact — even when the
    # interpreter running it is only flagged (not killed). We move the payload, not
    # python.exe/powershell.exe. This is what fills the vault for a script-based op.
    if not cfg.dry_run and not known_benign and score.dropped_script and quarantine_fn is not None:
        try:
            dest = quarantine_fn(score.dropped_script, cfg.quarantine_dir, "; ".join(score.reasons))
            report.actions.append(f"quarantined dropped script -> {dest}")
        except Exception as exc:  # noqa: BLE001
            report.actions.append(f"dropped-script quarantine failed: {exc}")

    if decision == "quarantine" and not cfg.dry_run:
        # Move only a dropper (temp/downloads/roaming/…); kill the process tree for a
        # trusted/system binary instead of yanking the tool itself off the system.
        if quarantine_fn is not None and ev.image and is_quarantinable(ev.image):
            try:
                dest = quarantine_fn(ev.image, cfg.quarantine_dir, "; ".join(score.reasons))
                report.actions.append(f"quarantined -> {dest}")
            except Exception as exc:  # noqa: BLE001
                report.actions.append(f"quarantine failed: {exc}")
        elif ev.image:
            report.actions.append(f"quarantine skipped (trusted binary): {ev.image}")
        # Capture volatile memory BEFORE terminating, so transient evidence survives.
        if dump_fn is not None and ev.pid:
            try:
                dump = dump_fn(ev.pid, ev.image)
                report.actions.append(f"memory dumped -> {dump}")
            except Exception as exc:  # noqa: BLE001
                report.actions.append(f"memory dump failed: {exc}")
        if kill_fn is not None and ev.pid:
            try:
                kill_fn(ev.pid)
                report.actions.append(f"killed process tree {ev.pid}")
            except Exception as exc:  # noqa: BLE001
                report.actions.append(f"kill failed: {exc}")

    if decision == "propose":
        report.actions.append(f"proposed containment: quarantine {ev.image} — awaiting analyst approval")

    if report.sha256 and verdict_fn is not None:
        try:
            report.vt = verdict_fn(report.sha256)
        except Exception as exc:  # noqa: BLE001
            report.vt = f"lookup error: {exc}"

    # Ingest into memory. Model verdicts land in the EPISODIC tier at medium/low
    # confidence; only analyst verification (dashboard feedback) promotes them to
    # the SEMANTIC long-term baseline. Events below the flag threshold are noise
    # and never stored.
    if memory is not None and score.points >= cfg.flag_threshold and not known_benign:
        verdict = adjudication.get("verdict") or ("MALICIOUS" if decision == "quarantine" else "UNCERTAIN")
        confidence = "medium" if verdict in ("MALICIOUS", "BENIGN") else "low"
        memory.ingest(MemoryRecord(
            id=signature_id(sig),
            signature=sig,
            verdict=verdict,
            outcome="model_only",
            confidence=confidence,
            timestamp=ev.timestamp,
            ts=time.time(),
            score=score.points,
            image=ev.image,
            host=cfg.hostname,
            user=ev.user,
        ))

    return report
