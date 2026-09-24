"""The isolated network bridge — the "fake internet" (FakeNet/INetSim/FakeDNS).

A detonation chamber must never touch the real internet: a second-stage payload
that cannot phone home is a payload that never reveals its C2. This module
generates the sinkhole configuration so every DNS name resolves to the sandbox
host and every service answers with a captured, fake response:

  * dnsmasq (FakeDNS)  — resolve *any* domain to the sink IP
  * INetSim             — fake HTTP/HTTPS/SMTP/... services that log + reply
  * bridge + tcpdump    — isolate the guest NIC and capture every packet

Everything is PURE config/command generation (string or argv) so it unit-tests
without root or a Linux box; the orchestrator runs the returned commands.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

DEFAULT_SERVICES = ("dns", "http", "https", "smtp", "ftp", "irc", "tftp", "pop3")


def build_dnsmasq_config(sink_ip: str, domains: Iterable[str] = ("*",)) -> str:
    """dnsmasq config that resolves every requested domain to *sink_ip* (FakeDNS)."""
    lines = [
        "# Argus FakeDNS — every domain resolves to the sink host (no real internet).",
        "port=53",
        "listen-address=%s" % sink_ip,
        "bind-interfaces",
        "no-resolv",
        "no-hosts",
        "log-queries",
        "log-facility=-",
    ]
    for d in domains:
        d = (d or "").strip()
        if d == "*":
            lines.append("address=/#/%s" % sink_ip)
        elif d:
            lines.append("address=/%s/%s" % (d, sink_ip))
    return "\n".join(lines) + "\n"


def build_inetsim_config(sink_ip: str, bind_port: int = 80, services: Iterable[str] = DEFAULT_SERVICES) -> str:
    """INetSim directives: bind the sink host and enable the fake services."""
    lines = [
        "# Argus INetSim — fake services that log every connection and answer.",
        "start_services = %s" % " ".join(services),
        "service_bind_address = %s" % sink_ip,
        "dns_bind_port = 53",
        "http_bind_port = %d" % bind_port,
        "https_bind_port = 443",
        "smtp_bind_port = 25",
        "ftp_bind_port = 21",
        "log_dir = /var/log/inetsim",
        "report_dir = /var/log/inetsim/report",
    ]
    return "\n".join(lines) + "\n"


def build_bridge_commands(bridge: str, sink_ip: str, netmask: str = "255.255.255.0") -> list[str]:
    """Shell commands to stand up an ISOLATED bridge (no uplink = no real internet).

    The bridge gets an IP (so the sink services can bind it) but no physical
    uplink is enslaved, so a guest on it can only reach the sink host.
    """
    return [
        f"ip link add name {bridge} type bridge",
        f"ip addr add {sink_ip}/{_cidr(netmask)} dev {bridge}",
        f"ip link set {bridge} up",
        # no `ip link set {bridge} master <physical>` — isolation by omission
    ]


def build_tcpdump_command(bridge: str, pcap_path) -> list[str]:
    """tcpdump argv: capture every packet on the isolated bridge to a PCAP file."""
    return ["tcpdump", "-i", bridge, "-w", str(pcap_path), "-s", "0", "-n"]


def default_sinkhole_services() -> list[str]:
    return list(DEFAULT_SERVICES)


def _cidr(netmask: str) -> str:
    """'255.255.255.0' -> '24' (fallback 24 on anything unparseable)."""
    try:
        bits = sum(bin(int(o)).count("1") for o in netmask.split("."))
        return str(bits) if 0 <= bits <= 32 else "24"
    except Exception:  # noqa: BLE001
        return "24"


def build_hosts_map(sink_ip: str, domains: Iterable[str]) -> dict[str, str]:
    """domain -> sink_ip map (the FakeDNS truth table), for tests and reporting."""
    return {d: sink_ip for d in domains}


# --------------------------------------------------------------------------- L1 egress wall
def build_egress_firewall(
    bridge: str = "virbr1",
    allow_tcp_ports=(53, 80, 443, 25, 21, 110, 23, 143, 587),
    allow_udp_ports=(53, 67, 68),
) -> list[str]:
    """The L1 hard wall: iptables commands that let the guest reach ONLY the sink
    services on the host and DROP everything else from the bridge. The DROP rule in
    the ARGUS_SINK chain doubles as the tripwire counter (see build_egress_counter)."""
    tcp = ",".join(str(p) for p in allow_tcp_ports)
    udp = ",".join(str(p) for p in allow_udp_ports)
    return [
        "iptables -N ARGUS_SINK",
        "iptables -F ARGUS_SINK",
        f"iptables -A ARGUS_SINK -p tcp -m multiport --dports {tcp} -j ACCEPT",
        f"iptables -A ARGUS_SINK -p udp -m multiport --dports {udp} -j ACCEPT",
        "iptables -A ARGUS_SINK -j DROP",
        f"iptables -A INPUT -i {bridge} -j ARGUS_SINK",
    ]


def build_egress_counter_command(chain: str = "ARGUS_SINK") -> str:
    """Shell command printing the number of packets the egress wall dropped (0 = clear)."""
    return f"iptables -L {chain} -v -n -x 2>/dev/null | awk '/DROP/{{s+=$1}} END{{print s+0}}'"


def build_egress_flush_command(bridge: str = "virbr1") -> list[str]:
    """Remove the egress wall (for teardown/tests). Idempotent."""
    return [
        f"iptables -D INPUT -i {bridge} -j ARGUS_SINK",
        "iptables -F ARGUS_SINK",
        "iptables -X ARGUS_SINK",
    ]
