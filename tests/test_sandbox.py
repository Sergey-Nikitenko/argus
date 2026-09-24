"""Pins for the Argus dynamic malware sandbox (CAPE/Cuckoo-style detonation branch).

Covers the five stages' pure core without a hypervisor: VM hardening, the fake
network sinkhole config, Sysmon telemetry parsing + derivation, the AI dissection
prompt/parse, the orchestrator lifecycle (fake backend), and the end-to-end
pipeline (dry-run re-analysis). stdlib-only, deterministic, no network, no libvirt.

Run: py -m pytest tests/test_sandbox.py -q
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argus.sandbox import (
    ArgusSandboxManager,
    FakeBackend,
    SandboxConfig,
    SandboxReport,
    run_pipeline,
)
from argus.sandbox import dissect as dissect_mod
from argus.sandbox import harden, sinkhole, telemetry
from argus.sandbox.orchestrator import CaptureHandle


# --------------------------------------------------------------------------- fixtures
def _sysmon_event(event_id: int, **fields) -> str:
    data = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in fields.items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System><EventID>{event_id}</EventID>"
        "<TimeCreated SystemTime='2023-01-01T00:00:00.000000000Z'/></System>"
        f"<EventData>{data}</EventData></Event>"
    )


def _batch(*blocks) -> str:
    return "\n".join(blocks)


PROC_WORD = _sysmon_event(1, Image=r"C:\Program Files\Microsoft Office\WINWORD.EXE",
                          ProcessId="100", ParentProcessId="0",
                          CommandLine="WINWORD.EXE invoice.docm",
                          User="sandbox\\user", Hashes="SHA256=AAA", ParentImage="-")
PROC_CMD = _sysmon_event(1, Image=r"C:\Windows\System32\cmd.exe",
                         ProcessId="200", ParentProcessId="100",
                         CommandLine="cmd.exe /c powershell -enc ...",
                         User="sandbox\\user", Hashes="SHA256=BBB",
                         ParentImage=r"C:\Program Files\Microsoft Office\WINWORD.EXE")
PROC_PS = _sysmon_event(1, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        ProcessId="300", ParentProcessId="200",
                        CommandLine="powershell.exe -nop -enc SQBFAFgA...",
                        User="sandbox\\user", Hashes="SHA256=CCC",
                        ParentImage=r"C:\Windows\System32\cmd.exe")
NET = _sysmon_event(3, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    ProcessId="300", Protocol="tcp", DestinationIp="10.0.0.1",
                    DestinationPort="80", DestinationHostname="malicious-domain.local",
                    Initiated="true")
DNS = _sysmon_event(22, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    ProcessId="300", QueryName="c2.malicious-domain.local", QueryResults="10.0.0.1")
FILE = _sysmon_event(11, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     ProcessId="300", TargetFilename=r"C:\Users\Public\update.exe")
REG = _sysmon_event(13, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    ProcessId="300",
                    TargetObject=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\updater",
                    Details="C:\\Users\\Public\\update.exe")
DRV = _sysmon_event(6, Image="System", ProcessId="4",
                    ImageLoaded=r"C:\Windows\System32\drivers\evil.sys",
                    Signed="false", Signature="-")


# --------------------------------------------------------------------------- harden
def test_hardened_domain_hides_hypervisor():
    xml = harden.build_hardened_domain_xml()
    assert "host-passthrough" in xml
    assert "<hidden state='on'/>" in xml
    assert "08:00:27" not in xml.lower()
    assert "vbox" not in xml.lower() and "qemu harddisk" not in xml.lower()
    assert "Dell Inc." in xml


def test_harden_existing_xml_strips_artifacts():
    base = (
        "<domain type='kvm'><devices>"
        "<emulator>/usr/bin/qemu-system-x86_64</emulator>"
        "<disk><driver name='qemu' type='qcow2'/>"
        "<target dev='vda' bus='virtio'/></disk>"
        "<interface type='bridge'><mac address='08:00:27:aa:bb:cc'/><model type='virtio'/></interface>"
        "</devices></domain>"
    )
    out = harden.harden_existing_xml(base, mac_prefix="00:14:22")
    assert "08:00:27" not in out.lower()
    # the fix: technical 'qemu' strings are PRESERVED, only SMBIOS/MAC are hardened
    assert "qemu-system-x86_64" in out
    assert "name='qemu'" in out
    assert "<sysinfo" in out and "Dell Inc." in out
    assert harden.has_vm_artifacts(out) == []


def test_harden_existing_xml_does_not_mangle_real_virtinstall_xml():
    # mirrors the shape libvirt's `virt-install --print-xml` actually emits
    base = (
        "<domain type='kvm'><devices>"
        "<emulator>/usr/bin/qemu-system-x86_64</emulator>"
        "<disk type='file' device='disk'><driver name='qemu' type='qcow2'/>"
        "<target dev='vda' bus='virtio'/></disk>"
        "<controller type='usb' model='qemu-xhci' ports='15'/>"
        "</devices></domain>"
    )
    out = harden.harden_existing_xml(base)
    assert "qemu-system-x86_64" in out
    assert "name='qemu'" in out and "qemu-xhci" in out
    assert harden.has_vm_artifacts(out) == []


def test_harden_notes_are_complete():
    notes = "\n".join(harden.hardening_notes())
    for token in ("host-passthrough", "SMBIOS", "MAC", "ACPI"):
        assert token in notes


# --------------------------------------------------------------------------- sinkhole
def test_fakedns_resolves_wildcard_to_sink():
    cfg = sinkhole.build_dnsmasq_config("10.0.0.1", ["*"])
    assert "address=/#/10.0.0.1" in cfg
    assert "no-resolv" in cfg


def test_inetsim_enables_fake_services():
    cfg = sinkhole.build_inetsim_config("10.0.0.1")
    assert "start_services" in cfg and "http" in cfg


def test_bridge_commands_isolate_by_omission():
    cmds = sinkhole.build_bridge_commands("virbr1", "10.0.0.1")
    joined = "\n".join(cmds)
    assert "master" not in joined, "an isolated bridge must enslave no uplink"
    assert "virbr1" in joined


def test_tcpdump_command_captures_bridge():
    argv = sinkhole.build_tcpdump_command("virbr1", "/tmp/x.pcap")
    assert argv[:2] == ["tcpdump", "-i"] and argv[1 + 1] == "virbr1"
    assert "-w" in argv


# --------------------------------------------------------------------------- telemetry
def test_parse_sysmon_batch_dispatch():
    tel = telemetry.parse_sysmon_batch(_batch(PROC_WORD, PROC_CMD, PROC_PS, NET, DNS,
                                              FILE, REG, DRV))
    assert len(tel.process_events) == 3
    assert len(tel.network_events) == 1
    assert len(tel.dns_queries) == 1
    assert len(tel.file_creates) == 1
    assert len(tel.registry_events) == 1
    assert len(tel.driver_loads) == 1


def test_execution_chain_walks_parent_child():
    tel = telemetry.parse_sysmon_batch(_batch(PROC_WORD, PROC_CMD, PROC_PS))
    chains = telemetry.execution_chain(tel.process_events)
    joined = " ".join(chains)
    assert "WINWORD.EXE -> CMD.EXE -> POWERSHELL.EXE" in joined


def test_dropped_files_and_persistence():
    tel = telemetry.parse_sysmon_batch(_batch(FILE, REG))
    dropped = telemetry.detect_dropped_files(tel.file_creates)
    assert any("update.exe" in d.path for d in dropped)
    assert telemetry.detect_persistence(tel.registry_events) == [
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\updater"
    ]


def test_summarize_names_attachment_network_drop():
    tel = telemetry.parse_sysmon_batch(_batch(PROC_WORD, PROC_CMD, PROC_PS, NET, FILE))
    s = telemetry.summarize(tel, attachment_name="invoice_10492.docm")
    assert "invoice_10492.docm" in s
    assert "WINWORD.EXE -> CMD.EXE -> POWERSHELL.EXE" in s
    assert "malicious-domain.local" in s or "10.0.0.1" in s
    assert "update.exe" in s


# --------------------------------------------------------------------------- dissect
def test_dissection_prompt_asks_the_three_things():
    p = dissect_mod.build_dissection_prompt("Telemetry Summary:\n- x", "a.docm")
    assert "Primary Intent" in p and "Execution Chain" in p and "Mitigation Steps" in p


def test_parse_dissection_strict_and_fallback():
    good = dissect_mod.parse_dissection(
        '{"primary_intent":"Downloader","execution_chain":["A -> B"],'
        '"mitigation_steps":["isolate"],"verdict":"MALICIOUS","confidence":0.9}')
    assert good["primary_intent"] == "Downloader"
    assert good["verdict"] == "MALICIOUS"
    assert good["mitigation_steps"] == ["isolate"]
    fallback = dissect_mod.parse_dissection("the verdict is BENIGN here")
    assert fallback["verdict"] == "BENIGN"


# --------------------------------------------------------------------------- orchestrator
def _manager(tmp_path, telemetry_xml: str = ""):
    sc = SandboxConfig(work_dir=tmp_path, pcap_dir=tmp_path / "pcaps",
                       telemetry_dir=tmp_path / "telemetry", artifacts_dir=tmp_path / "artifacts")
    sc.ensure_dirs()
    if telemetry_xml:
        (sc.telemetry_dir / "sysmon.xml").write_text(telemetry_xml, encoding="utf-8")
    return sc, ArgusSandboxManager(sc, backend=FakeBackend())


def test_detonate_lifecycle_order_and_revert(tmp_path):
    sc, mgr = _manager(tmp_path, _batch(PROC_WORD, PROC_CMD))
    stopped, injected = [], []
    clock = {"t": 0.0}

    def cap(stem):
        return CaptureHandle(pcap_path=sc.pcap_dir / f"{stem}.pcap",
                             stop_fn=lambda: stopped.append(stem))

    def inject(path):
        injected.append(path)

    def fake_sleep(s):
        clock["t"] += s

    run = mgr.detonate_attachment(tmp_path / "invoice.docm", sleep_fn=fake_sleep,
                                  now_fn=lambda: clock["t"],
                                  inject_fn=inject, capture_fn=cap, poll_interval=1.0)
    assert injected == [str(tmp_path / "invoice.docm")]
    assert stopped == ["invoice"]
    assert mgr.backend.calls == ["revert:argus-clean", "create:argus-det",
                                 "destroy:argus-det", "revert:argus-clean"]
    assert len(run["telemetry"].process_events) == 2


def test_detonate_reverts_even_on_injection_failure(tmp_path):
    sc, mgr = _manager(tmp_path)

    def boom(path):
        raise RuntimeError("guest agent down")

    try:
        mgr.detonate_attachment(tmp_path / "x.exe", sleep_fn=lambda s: None,
                                inject_fn=boom, capture_fn=lambda stem: CaptureHandle(
                                    pcap_path=sc.pcap_dir / "x.pcap"))
        raised = False
    except RuntimeError:
        raised = True
    assert raised
    assert mgr.backend.calls[-1] == "revert:argus-clean", "the finally must still revert"


# --------------------------------------------------------------------------- pipeline
def test_pipeline_dry_run_scores_and_dissects(tmp_path):
    from argus.config import Config
    sc, mgr = _manager(tmp_path, _batch(PROC_WORD, PROC_CMD, PROC_PS, NET, DNS, FILE, REG))
    cfg = Config(data_dir=tmp_path / "data")

    class FakeScore:
        points = 71
        reasons = ["encoded powershell"]

    def score_fn(ev):
        return FakeScore()

    def decide_fn(score, cfg):
        return "quarantine" if score.points >= 70 else "allow"

    def severity_fn(points):
        return "high" if points >= 70 else "low"

    def dissect_fn(summary, **kw):
        return {"verdict": "MALICIOUS", "confidence": 0.9, "primary_intent": "Downloader",
                "execution_chain": ["WINWORD.EXE -> powershell.exe"],
                "mitigation_steps": ["isolate", "block c2.malicious-domain.local"]}

    rep = run_pipeline(cfg, sc, mgr, "invoice.docm", dissect_fn=dissect_fn,
                       score_fn=score_fn, decide_fn=decide_fn, severity_fn=severity_fn,
                       dry_run=True)
    assert isinstance(rep, SandboxReport)
    assert rep.verdict == "MALICIOUS"
    assert rep.decision == "quarantine"
    assert rep.score == 71
    assert rep.severity == "high"
    assert "WINWORD.EXE -> CMD.EXE -> POWERSHELL.EXE" in rep.execution_chain
    assert any("update.exe" in d for d in rep.dropped_files)
    assert rep.dns_queries == ["c2.malicious-domain.local"]
    d = rep.to_dict()
    assert set(d) >= {"sample", "verdict", "decision", "score", "execution_chain",
                      "dropped_files", "mitigation_steps"}


# --------------------------------------------------------------------------- wsl delegation
def test_windows_to_wsl_path():
    from argus.sandbox import wsl as wsl_mod
    assert wsl_mod.windows_to_wsl_path(r"C:\workspace\argus\run.py") == "/mnt/c/workspace/argus/run.py"
    assert wsl_mod.windows_to_wsl_path(r"D:\samples\evil.exe") == "/mnt/d/samples/evil.exe"
    assert wsl_mod.windows_to_wsl_path("/tmp/x") == "/tmp/x"  # linux path passes through


def test_translate_config_paths():
    from argus.sandbox import wsl as wsl_mod
    d = wsl_mod.translate_config_paths({"telemetry_dir": r"C:\argus\tel", "vm_name": "argus-det"})
    assert d["telemetry_dir"] == "/mnt/c/argus/tel"
    assert d["vm_name"] == "argus-det"


def test_build_wsl_command():
    from argus.sandbox import wsl as wsl_mod
    cmd = wsl_mod.build_wsl_command(repo_dir=r"C:\workspace\argus",
                                    sample=r"C:\samples\evil.exe", no_llm=True)
    assert cmd[:3] == ["wsl.exe", "-d", "Ubuntu"]
    assert "/mnt/c/samples/evil.exe" in cmd
    assert "/mnt/c/workspace/argus/run.py" in cmd
    assert "--sandbox-live" in cmd and "--no-llm" in cmd


# --------------------------------------------------------------------------- kill-switch
def test_killswitch_pull_dead_records_and_reverts(tmp_path):
    from argus.sandbox import SandboxKillSwitch, FakeBackend
    sc, mgr = _manager(tmp_path)
    ks = SandboxKillSwitch(mgr, kill_log_path=str(tmp_path / "kills.jsonl"))
    ev = ks.pull_dead("l1_egress", "egress violation")
    assert ev.layer == "l1_egress" and ev.reason == "egress violation"
    assert len(ks.events) == 1
    assert "destroy:argus-det" in mgr.backend.calls
    assert mgr.backend.calls[-1] == "revert:argus-clean"
    assert (tmp_path / "kills.jsonl").exists()


def test_egress_tripwire_fires_only_on_counter():
    from argus.sandbox.killswitch import egress_tripwire
    assert egress_tripwire(lambda: 0)() is None
    assert egress_tripwire(lambda: 3)() == "egress violation (3 blocked)"


def test_timeout_and_hypervisor_tripwires():
    from argus.sandbox.killswitch import timeout_tripwire, hypervisor_tripwire
    assert timeout_tripwire(100.0, now=lambda: 99.0)() is None
    assert timeout_tripwire(100.0, now=lambda: 101.0)() == "detonation timeout"
    assert hypervisor_tripwire(lambda: "running")() is None
    assert hypervisor_tripwire(lambda: "shut off")() == "guest state 'shut off'"


def test_poll_tripwires_pulls_dead_on_first_trigger(tmp_path):
    from argus.sandbox import SandboxKillSwitch, Tripwire, poll_tripwires
    sc, mgr = _manager(tmp_path)
    ks = SandboxKillSwitch(mgr)
    tripwires = [Tripwire("l1_egress", lambda: None),
                 Tripwire("l3_device", lambda: "unexpected device: usb")]
    assert poll_tripwires(ks, tripwires) is True
    assert ks.events[0].layer == "l3_device"
    assert "destroy:argus-det" in mgr.backend.calls


def test_detonate_pulls_dead_on_tripwire(tmp_path):
    from argus.sandbox import SandboxKillSwitch, Tripwire
    sc, mgr = _manager(tmp_path, _batch(PROC_WORD))

    def cap(stem):
        return CaptureHandle(pcap_path=sc.pcap_dir / f"{stem}.pcap")

    kill = SandboxKillSwitch(mgr)
    run = mgr.detonate_attachment(
        tmp_path / "evil.exe", sleep_fn=lambda s: None,
        inject_fn=lambda p: None, capture_fn=cap,
        tripwires=[Tripwire("l2_injection", lambda: "injection write-back")],
        kill=kill, poll_interval=0.0)
    assert run["killed"] == {"layer": "l2_injection", "reason": "injection write-back"}
    assert kill.events[0].layer == "l2_injection"
    assert mgr.backend.calls[-1] == "revert:argus-clean"


# --------------------------------------------------------------------------- L1/L3 surfaces
def test_strip_management_devices_keeps_qemu_and_console():
    from argus.sandbox.harden import strip_management_devices
    xml = (
        "<domain type='kvm'><devices>"
        "<emulator>/usr/bin/qemu-system-x86_64</emulator>"
        "<disk><driver name='qemu' type='qcow2'/></disk>"
        "<graphics type='vnc' port='-1'/>"
        "<channel type='unix'><source mode='bind'/></channel>"
        "<redirdev bus='usb' type='spicevmc'/>"
        "<sound model='ich9'/>"
        "<console type='pty'/>"
        "</devices></domain>"
    )
    out = strip_management_devices(xml)
    for gone in ("<graphics", "<channel", "<redirdev", "<sound"):
        assert gone not in out
    assert "<console" in out            # the injection channel survives
    assert "qemu-system-x86_64" in out  # technical qemu preserved


def test_build_egress_firewall_wall_and_counter():
    cmds = sinkhole.build_egress_firewall()
    joined = "\n".join(cmds)
    assert "-j DROP" in joined and "-j ACCEPT" in joined
    assert "-i virbr1" in joined
    assert "DROP" in sinkhole.build_egress_counter_command()


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
