"""Host orchestrator — the Argus side of the CAPE/Cuckoo host controller.

Manages the guest VM lifecycle (revert to clean snapshot, power on, hard
power-off, revert again), captures the isolated bridge to a PCAP, injects the
sample, and harvests the dumped Sysmon telemetry. The libvirt connection is
wrapped in an injectable backend so the lifecycle logic unit-tests with a fake
— the module imports cleanly WITHOUT libvirt installed (Windows Argus core
never needs it; only the Linux hypervisor host does).
"""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from argus.sandbox.config import SandboxConfig
from argus.sandbox.telemetry import SandboxTelemetry, parse_sysmon_batch


# --------------------------------------------------------------------------- backends
class LibvirtBackend:
    """Thin wrapper over the ``libvirt`` Python binding (imported lazily)."""

    def __init__(self, uri: str):
        self.uri = uri
        self.conn = None

    def open(self):
        try:
            import libvirt  # imported here: only the hypervisor host has it
        except ImportError as e:
            raise RuntimeError(
                "libvirt Python binding not installed — on the hypervisor host run: "
                "sudo apt install -y python3-libvirt libvirt-daemon-system libvirt-clients"
            ) from e
        self.conn = libvirt.open(self.uri)
        if self.conn is None:
            raise RuntimeError(f"libvirt.open({self.uri}) failed")
        return self.conn

    def domain(self, name: str):
        if self.conn is None:
            self.open()
        dom = self.conn.lookupByName(name)
        if dom is None:
            raise RuntimeError(f"no libvirt domain named {name!r}")
        return dom

    def revert(self, name: str, snapshot: str) -> None:
        dom = self.domain(name)
        snap = dom.snapshotLookupByName(snapshot)
        dom.revertToSnapshot(snap)

    def create(self, name: str) -> None:
        self.domain(name).create()

    def destroy(self, name: str) -> None:
        self.domain(name).destroy()

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None


class FakeBackend:
    """In-memory libvirt for tests: records every lifecycle call, no hypervisor."""

    def __init__(self):
        self.calls: list[str] = []
        self.running = False
        self.snapshots: dict[str, bool] = {}

    def revert(self, name: str, snapshot: str) -> None:
        self.calls.append(f"revert:{snapshot}")
        self.snapshots[snapshot] = True
        self.running = False

    def create(self, name: str) -> None:
        self.calls.append(f"create:{name}")
        self.running = True

    def destroy(self, name: str) -> None:
        self.calls.append(f"destroy:{name}")
        self.running = False

    def close(self) -> None:
        self.calls.append("close")


# --------------------------------------------------------------------------- capture
@dataclass
class CaptureHandle:
    pcap_path: Path
    proc: object = None      # a Popen when live, a sentinel under tests
    stop_fn: Callable[[], None] = lambda: None

    def stop(self):
        self.stop_fn()


# --------------------------------------------------------------------------- manager
class ArgusSandboxManager:
    """The host controller: VM lifecycle + capture + injection + harvest."""

    def __init__(self, cfg: SandboxConfig, backend=None):
        self.cfg = cfg
        self.backend = backend if backend is not None else LibvirtBackend(cfg.hypervisor_uri)

    # -- lifecycle -----------------------------------------------------------
    def revert_to_clean_state(self) -> None:
        self.backend.revert(self.cfg.vm_name, self.cfg.clean_snapshot)

    def start_guest(self) -> None:
        self.backend.create(self.cfg.vm_name)

    def destroy_guest(self) -> None:
        """Hard power-off. Best-effort: destroying an already-dead guest is the
        desired end state, not an error — this is what "pull the sandbox dead" calls."""
        try:
            self.backend.destroy(self.cfg.vm_name)
        except Exception:  # noqa: BLE001 — already gone = success for a kill
            pass

    # -- capture -------------------------------------------------------------
    def pcap_path_for(self, sample_stem: str) -> Path:
        return self.cfg.pcap_dir / f"{sample_stem}.pcap"

    def start_capture(self, sample_stem: str) -> CaptureHandle:
        self.cfg.pcap_dir.mkdir(parents=True, exist_ok=True)
        path = self.pcap_path_for(sample_stem)
        proc = subprocess.Popen(
            ["tcpdump", "-i", self.cfg.bridge, "-w", str(path), "-s", "0", "-n"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return CaptureHandle(pcap_path=path, proc=proc, stop_fn=lambda: _terminate(proc))

    def stop_capture(self, handle: CaptureHandle) -> None:
        handle.stop()

    # -- injection -----------------------------------------------------------
    def inject_sample(self, sample_path) -> None:
        """Deliver + detonate the sample inside the guest (via guest agent / shared
        folder). The default here is a documented no-op seam — a real deployment
        drives qemu-guest-agent or a shared folder; tests replace this."""
        raise NotImplementedError(
            "inject_sample is a deployment seam: drive qemu-guest-agent / a shared "
            "folder to drop + execute the sample, or inject a fake in tests")

    # -- harvest -------------------------------------------------------------
    def harvest_telemetry(self) -> SandboxTelemetry:
        """Read the dumped Sysmon XML from the telemetry dir into a typed bag."""
        tel = SandboxTelemetry()
        self.cfg.telemetry_dir.mkdir(parents=True, exist_ok=True)
        for p in sorted(self.cfg.telemetry_dir.glob("*.xml")):
            tel = _merge(tel, parse_sysmon_batch(p.read_text(encoding="utf-8", errors="replace")))
        return tel

    def process_telemetry(self, log_path) -> SandboxTelemetry:
        """Parse ONE telemetry file into the structured schema (the user's stage-4 verb)."""
        return parse_sysmon_batch(Path(log_path).read_text(encoding="utf-8", errors="replace"))

    # -- full lifecycle (stages 1-4) -----------------------------------------
    def detonate_attachment(self, sample_path, *, sleep_fn: Callable[[float], None] = time.sleep,
                            inject_fn: Optional[Callable[[str], None]] = None,
                            capture_fn: Optional[Callable[[str], CaptureHandle]] = None,
                            tripwires: Optional[list] = None,
                            kill=None, poll_interval: float = 1.0,
                            now_fn: Callable[[], float] = time.time) -> dict:
        """Run the sandbox lifecycle for one sample and return the harvest.

        Order: revert -> start -> capture -> inject -> [poll tripwires] -> stop
        capture -> harvest -> destroy -> (finally) revert. The detonation window is
        polled in *poll_interval* steps so an L1-L4 tripwire pulls the sandbox dead
        the INSTANT a boundary is crossed (the L5 timeout is the outer bound). A
        tripwire kill is recorded on the result as ``killed``; the final revert is
        in a ``finally`` so a crashed detonation never leaves the chamber dirty.
        """
        sample = Path(sample_path)
        stem = sample.stem or "sample"
        self.cfg.ensure_dirs()
        capture = (capture_fn or self.start_capture)(stem)
        inject = inject_fn or self.inject_sample
        killed = None
        try:
            self.revert_to_clean_state()
            self.start_guest()
            inject(str(sample))
            deadline = now_fn() + float(self.cfg.detonation_timeout)
            while now_fn() < deadline:
                for tw in (tripwires or []):
                    reason = tw.check()
                    if reason:
                        killed = {"layer": tw.layer, "reason": reason}
                        if kill is not None:
                            kill.pull_dead(tw.layer, reason)
                        break
                if killed:
                    break
                sleep_fn(float(poll_interval))
            telemetry = self.harvest_telemetry()
        finally:
            try:
                self.stop_capture(capture)
            finally:
                try:
                    self.destroy_guest()
                finally:
                    self.revert_to_clean_state()
        result = {"sample": str(sample), "pcap": str(capture.pcap_path),
                  "telemetry": telemetry}
        if killed:
            result["killed"] = killed
        return result


def _terminate(proc) -> None:
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception:  # noqa: BLE001 — a dead sniffer must never break a detonation
        pass


def _merge(a: SandboxTelemetry, b: SandboxTelemetry) -> SandboxTelemetry:
    a.process_events.extend(b.process_events)
    a.network_events.extend(b.network_events)
    a.dns_queries.extend(b.dns_queries)
    a.file_creates.extend(b.file_creates)
    a.registry_events.extend(b.registry_events)
    a.driver_loads.extend(b.driver_loads)
    a.raw_accesses.extend(b.raw_accesses)
    return a
