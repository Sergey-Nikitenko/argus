"""Argus dynamic malware sandbox — a CAPE/Cuckoo-style detonation branch.

Three coordinated environments, five stages:

  Host Controller      (argus.sandbox.orchestrator) — KVM/libvirt lifecycle,
                       sample injection, network capture, telemetry harvest.
  Guest VM             (argus.sandbox.agent + sysmon) — instrumented Windows
                       guest where the payload executes; Sysmon + a silent agent
                       simulate user activity and auto-enable Office content.
  Isolated Bridge      (argus.sandbox.sinkhole) — FakeDNS + INetSim fake internet;
                       every domain resolves to the host, every service answers
                       with a capture, so the payload believes it phoned home.

Pipeline (argus.sandbox.pipeline): orchestrator -> guest detonation -> sinkhole
capture -> snapshot revert + artifact dump -> Argus AI dissection, feeding each
harvested process/network event through Argus's existing score/decide flow.

The core is stdlib-only and deterministic; libvirt and tcpdump are external,
Linux-only seams behind an injectable backend so the whole subsystem unit-tests
without a hypervisor.
"""
from __future__ import annotations

from .config import SandboxConfig
from .pipeline import SandboxReport, run_pipeline
from .orchestrator import ArgusSandboxManager, LibvirtBackend, FakeBackend
from .killswitch import SandboxKillSwitch, Tripwire, poll_tripwires

__all__ = [
    "SandboxConfig",
    "SandboxReport",
    "ArgusSandboxManager",
    "LibvirtBackend",
    "FakeBackend",
    "run_pipeline",
    "SandboxKillSwitch",
    "Tripwire",
    "poll_tripwires",
]
