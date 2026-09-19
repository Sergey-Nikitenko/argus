"""Decision + response pipeline.

Turns a scored event into an ``allow`` / ``flag`` / ``quarantine`` decision plus a
severity tier, and (when not in dry-run) performs the configured side effects.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .config import Config
from .events import ProcessEvent
from .score import SUSPICIOUS_PATH_FRAGMENTS, ScoreResult, score_event


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

    def to_dict(self) -> dict:
        return {
            "timestamp": self.event.timestamp,
            "pid": self.event.pid,
            "parent_pid": self.event.parent_pid,
            "image": self.event.image,
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
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def decide(score: ScoreResult, cfg: Config) -> str:
    if score.points >= cfg.kill_threshold:
        return "quarantine"
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
) -> Report:
    score = score_event(ev)
    decision = decide(score, cfg)
    adjudication = {}

    # Sensory guidance: a local model adjudicates every would-be quarantine. Only a
    # confirmed MALICIOUS verdict keeps the kill; BENIGN/UNCERTAIN (or model down) downgrade
    # to flag -- fail-safe: when in doubt, do not destroy.
    if decision == "quarantine" and adjudicate_fn is not None:
        try:
            adjudication = adjudicate_fn(ev, score)
        except Exception as exc:  # noqa: BLE001
            adjudication = {"verdict": "UNCERTAIN", "reason": f"adjudication failed: {exc}"}
        # A weak model can downgrade a BORDERLINE kill to flag, but not HARD EVIDENCE: a score
        # this high is multiple independent signals stacked, which no small model may veto.
        if adjudication.get("verdict") != "MALICIOUS" and score.points < HARD_EVIDENCE:
            decision = "flag"

    report = Report(event=ev, score=score, decision=decision, severity=severity(score.points),
                    sha256=ev.sha256(), adjudication=adjudication)

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
        if kill_fn is not None and ev.pid:
            try:
                kill_fn(ev.pid)
                report.actions.append(f"killed process tree {ev.pid}")
            except Exception as exc:  # noqa: BLE001
                report.actions.append(f"kill failed: {exc}")

    if report.sha256 and verdict_fn is not None:
        try:
            report.vt = verdict_fn(report.sha256)
        except Exception as exc:  # noqa: BLE001
            report.vt = f"lookup error: {exc}"

    return report
