"""Sandbox configuration — the hypervisor-host side of the detonation branch.

Mirrors argus.config.Config in spirit (stdlib-only, safe defaults, paths derived in
``__post_init__``) but describes the SANDBOX, not the live host: where the
hypervisor lives, which clean snapshot to revert to, which isolated bridge to
sniff, and how long a payload gets to run before the host pulls the plug.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SandboxConfig:
    """Runtime configuration for the sandbox host controller + pipeline."""

    # --- hypervisor ---------------------------------------------------------
    hypervisor_uri: str = "qemu:///system"     # libvirt connection (Linux host)
    vm_name: str = "argus-det"                 # the detonation-chamber guest
    clean_snapshot: str = "argus-clean"        # pristine pre-instrumented snapshot

    # --- isolated bridge / fake internet -----------------------------------
    bridge: str = "virbr1"                     # isolated sinkhole bridge (no real net)
    sink_ip: str = "10.0.0.1"                  # fake-internet host (INetSim/FakeDNS)
    guest_ip: str = "10.0.0.2"                 # the guest's static address on the bridge
    netmask: str = "255.255.255.0"
    fakedns_domains: list[str] = field(default_factory=lambda: ["*"])
    sinkhole_services: list[str] = field(
        default_factory=lambda: ["dns", "http", "https", "smtp", "ftp", "irc", "tftp"])

    # --- detonation ---------------------------------------------------------
    detonation_timeout: int = 120              # seconds before the host hard-kills
    user_simulation: bool = True               # guest agent fakes mouse/clicks
    auto_enable_content: bool = True           # click "Enable Content" in Office

    # --- hardening ----------------------------------------------------------
    mac_prefix: str = "00:14:22"               # Dell OUI — a real NIC vendor, not a hypervisor OUI
    cpu_mode: str = "host-passthrough"         # hide virtual CPU flags
    hide_kvm: bool = True                      # <kvm><hidden state='on'/></kvm>

    # --- harvest paths (hypervisor host) ------------------------------------
    work_dir: Path = field(default_factory=lambda: Path("/tmp/argus-sandbox"))
    pcap_dir: Path = field(default_factory=lambda: Path("/tmp/argus-sandbox/pcaps"))
    telemetry_dir: Path = field(default_factory=lambda: Path("/tmp/argus-sandbox/telemetry"))
    artifacts_dir: Path = field(default_factory=lambda: Path("/tmp/argus-sandbox/artifacts"))

    def __post_init__(self):
        self.normalize()

    def normalize(self) -> None:
        """Re-coerce the path fields after a JSON override (which arrives as str)."""
        self.work_dir = Path(self.work_dir)
        self.pcap_dir = Path(self.pcap_dir)
        self.telemetry_dir = Path(self.telemetry_dir)
        self.artifacts_dir = Path(self.artifacts_dir)

    def ensure_dirs(self) -> None:
        for d in (self.work_dir, self.pcap_dir, self.telemetry_dir, self.artifacts_dir):
            d.mkdir(parents=True, exist_ok=True)
