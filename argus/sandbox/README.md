# Argus Dynamic Malware Sandbox

A CAPE/Cuckoo-style detonation branch for Argus. It coordinates three environments
through a five-stage pipeline, then feeds the result into Argus's existing
score/decide/LLM flow.

## Three environments

| Environment | Module | Job |
|---|---|---|
| **Host Controller** (Argus core) | `orchestrator.py` | KVM/libvirt VM lifecycle, sample injection, PCAP capture, telemetry harvest |
| **Guest VM** (detonation chamber) | `agent.py` + `argus/sysmon.py` | Instrumented Windows guest; Sysmon + a silent agent simulate the user and detonate the sample |
| **Isolated Network Bridge** (fake internet) | `sinkhole.py` | FakeDNS (dnsmasq) + INetSim; every domain resolves to the sink, every service answers with a capture |

## Five stages

```
1. Host Orchestrator   revert clean snapshot, power on the guest
2. Isolated Guest VM   inject + detonate the sample (guest agent + Sysmon)
3. Fake Network Sink   tcpdump the isolated bridge; FakeDNS/INetSim answer
4. Snapshot Revert     hard-kill the guest, harvest telemetry, revert clean
5. Argus AI Dissection score process events, trace the chain, ask the model
```

`pipeline.run_pipeline` drives all five and returns a `SandboxReport`; stages 1–4
live in `orchestrator.ArgusSandboxManager.detonate_attachment` (fail-safe about the
final revert), and stage 5 is pure (`score_event` + `execution_chain` + `dissect`).

## Usage

```powershell
# Dry-run re-analysis: score + dissect the Sysmon XML already dumped to the
# telemetry dir (no hypervisor, no detonation — safe default).
py run.py --sandbox --sandbox-sample invoice.docm

# Override sandbox paths/hypervisor via a JSON file:
py run.py --sandbox --sandbox-sample invoice.docm --sandbox-config sandbox.json

# Live detonation on the KVM/libvirt hypervisor (requires libvirt on the host
# and the injection seam wired — see below).
py run.py --sandbox --sandbox-sample invoice.docm --sandbox-live

# On this machine: drive the WSL2 Ubuntu hypervisor from the Windows console.
# WSL2 Ubuntu exposes /dev/kvm (AMD-V nested), so it is the local KVM host.
py run.py --sandbox --sandbox-sample C:\samples\invoice.docm --sandbox-live --sandbox-host wsl
```

## WSL2 (this machine)

This host runs **WSL2 Ubuntu 24.04** with `/dev/kvm` exposed, so it is the local
KVM hypervisor for the detonation chamber. `--sandbox-host wsl` translates
`C:\...` paths to `/mnt/c/...` and runs `python3 run.py --sandbox-live` inside
Ubuntu. One-time setup (needs your sudo password, run it in a WSL terminal):

```bash
sudo apt update && sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients \
    virtinst bridge-utils tcpdump dnsmasq python3-libvirt
sudo usermod -aG kvm,libvirt "$USER"
# then restart WSL so the kvm group takes effect:  wsl --shutdown
```

INetSim is Debian/Kali-only (not in Ubuntu); dnsmasq's FakeDNS is the load-bearing
sinkhole, and INetSim's fake HTTP/SMTP services can be added later from its .deb.

## Deployment notes (what `--sandbox-live` needs)

1. **Hypervisor host**: Linux with KVM/QEMU + `libvirt` (Python binding) + `tcpdump`.
2. **Guest image**: Windows 10/11 with Office + Sysmon installed using the sandbox
   config (`argus.sysmon.write_sandbox_config`), the guest agent
   (`argus.sandbox.agent.write_guest_agent`) pre-installed, and a clean snapshot
   named per `SandboxConfig.clean_snapshot`.
3. **Hardening**: generate the domain with `argus.sandbox.harden` (host CPU
   passthrough, hidden KVM, non-VirtualBox MAC OUI, SMBIOS/OEM vendor strings).
4. **Sinkhole**: stand up the bridge with `sinkhole.build_bridge_commands`, run
   dnsmasq with `build_dnsmasq_config` and INetSim with `build_inetsim_config`.
5. **Injection seam**: `orchestrator.ArgusSandboxManager.inject_sample` is a
   documented no-op seam — wire it to qemu-guest-agent or a shared folder that
   drops the sample into the guest agent's drop dir (`C:\Users\Public\argus-drop`).

The core is stdlib-only and deterministic; `libvirt`/`tcpdump` are Linux-only
seams behind an injectable backend, so everything unit-tests without a hypervisor.
