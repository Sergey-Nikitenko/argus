"""Layered kill-switches — a tripwire at every sandbox layer that pulls the sandbox dead.

The detonation chamber is disposable (revert-to-clean every run), but "disposable"
only helps if the chamber is killed the INSTANT a boundary is crossed — not when
the timer happens to expire. This module is the kill plane: one master primitive
(``pull_dead``) that hard-destroys the guest and reverts to the clean snapshot, and
a tripwire predicate per isolation layer:

  L1 egress        the guest tried to reach anything but the sink host (firewall counter)
  L2 injection     the guest wrote back through the one-way sample channel
  L3 device        an unexpected device appeared (hotplug / passthrough attempt)
  L4 hypervisor    the guest entered an unexpected domain state (QEMU anomaly)
  L5 timeout       the detonation timer expired

Every tripwire is a PURE predicate (a probe is injected), so the whole kill plane
unit-tests against a fake backend with no hypervisor. ``pull_dead`` is idempotent:
the caller may fire it mid-run and the orchestrator's ``finally``-revert still backs
it up — two hard walls over the same action.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

# The isolation layers, in the order a guard should poll them (cheapest first).
LAYERS = ("l1_egress", "l2_injection", "l3_device", "l4_hypervisor", "l5_timeout")


@dataclass
class KillEvent:
    layer: str
    reason: str
    at: str = ""


@dataclass
class Tripwire:
    layer: str
    check: Callable[[], Optional[str]]   # returns a reason str, or None = clear


# --------------------------------------------------------------------------- tripwire predicates (pure)
def timeout_tripwire(deadline: float, now: Callable[[], float] = time.time) -> Callable[[], Optional[str]]:
    """L5: fire once the detonation timer expires."""
    def check() -> Optional[str]:
        return "detonation timeout" if now() >= deadline else None
    return check


def egress_tripwire(read_counter: Callable[[], int]) -> Callable[[], Optional[str]]:
    """L1: fire if the host firewall has dropped any guest egress attempt."""
    def check() -> Optional[str]:
        n = int(read_counter() or 0)
        return f"egress violation ({n} blocked)" if n > 0 else None
    return check


def injection_tripwire(check_writeback: Callable[[], bool]) -> Callable[[], Optional[str]]:
    """L2: fire if the guest wrote back through the read-only injection channel."""
    def check() -> Optional[str]:
        return "injection write-back" if check_writeback() else None
    return check


def device_tripwire(check_devices: Callable[[], list]) -> Callable[[], Optional[str]]:
    """L3: fire if any UNEXPECTED device is present (returns the offending names)."""
    def check() -> Optional[str]:
        extra = [str(d) for d in (check_devices() or [])]
        return f"unexpected device: {', '.join(extra)}" if extra else None
    return check


def hypervisor_tripwire(check_state: Callable[[], str]) -> Callable[[], Optional[str]]:
    """L4: fire if the guest left the expected 'running' state mid-detonation."""
    def check() -> Optional[str]:
        state = str(check_state() or "")
        return f"guest state '{state}'" if state and state != "running" else None
    return check


# --------------------------------------------------------------------------- the kill switch
class SandboxKillSwitch:
    """The master kill primitive. ``pull_dead`` destroys + reverts NOW and records
    the event; it never raises — a kill must never be allowed to fail silently OR
    to block the revert."""

    def __init__(self, manager, kill_log_path=None):
        self.manager = manager
        self.kill_log_path = kill_log_path
        self.events: list[KillEvent] = []

    def pull_dead(self, layer: str, reason: str) -> KillEvent:
        ev = KillEvent(layer=layer, reason=reason,
                       at=time.strftime("%Y-%m-%dT%H:%M:%S"))
        self.events.append(ev)
        try:
            from pathlib import Path
            from argus.store import append_jsonl
            if self.kill_log_path:
                append_jsonl(Path(self.kill_log_path),
                             {"layer": layer, "reason": reason, "at": ev.at})
        except Exception:  # noqa: BLE001 — logging must never block the kill
            pass
        # pull the sandbox dead: hard power-off, then revert. The revert is in a
        # finally so a destroy failure can never leave the chamber dirty.
        try:
            self.manager.destroy_guest()
        finally:
            self.manager.revert_to_clean_state()
        return ev


def poll_tripwires(kill: SandboxKillSwitch, tripwires, now: Callable[[], float] = time.time) -> bool:
    """Evaluate tripwires once; pull dead on the FIRST trigger. Returns True if killed."""
    for tw in tripwires:
        reason = tw.check()
        if reason:
            kill.pull_dead(tw.layer, reason)
            return True
    return False
