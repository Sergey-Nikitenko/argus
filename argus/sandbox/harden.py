"""VM hardening — make the detonation chamber look like real hardware.

Malware frequently checks for virtualization before it detonates: the QEMU/VBOX
SMBIOS strings, a VirtualBox ``08:00:27`` / VMware / Hyper-V / Xen MAC OUI, the
``hypervisor`` CPU flag, and well-known driver/device names. This module emits a
hardened libvirt domain and surgically hardens an existing one.

The SMBIOS/OEM fields and the MAC OUI are the only virtualization markers the
guest can actually OBSERVE, so hardening touches exactly those — it deliberately
does NOT rewrite the technical ``qemu`` occurrences (``driver name='qemu'``, the
``qemu-system-x86_64`` emulator path, ``qemu-xhci``) because those never surface
to the guest as "this is a VM". Everything is PURE (string in -> string out) so it
unit-tests without libvirt or a hypervisor.
"""
from __future__ import annotations

import re

# A REAL NIC vendor OUI (Dell), not a hypervisor OUI. The ones malware checks:
# VirtualBox 08:00:27, VMware 00:0C:29 / 00:50:56, Hyper-V 00:15:5D, Xen 00:16:3E.
_DEFAULT_MAC_PREFIX = "00:14:22"
_DEFAULT_MAC = "00:14:22:00:00:00"

_BAD_OUIS = ("08:00:27", "00:0c:29", "00:50:56", "00:15:5d", "00:16:3e")
_BAD_SMBIOS = ("vbox", "virtualbox", "vmware", "bochs", "seabios", "innotek",
               "parallels", "xensource", "qemu")


def hardening_notes() -> list[str]:
    """The anti-analysis checklist, in the order a hardening pass should apply it."""
    return [
        "CPU: <cpu mode='host-passthrough'> hides the virtual 'hypervisor' flag",
        "KVM: <kvm><hidden state='on'/></kvm> hides the KVM cpuid leaf",
        "SMBIOS: replace QEMU/VBOX/VirtualBox/VMWARE vendor + product strings",
        "BIOS: replace SeaBIOS/Bochs vendor with a plausible OEM",
        "MAC: use a REAL NIC vendor OUI (00:14:22 Dell), never 08:00:27/00:0C:29/00:16:3E",
        "Devices: virtio disk/nic so 'QEMU HARDDISK'/'QEMU DVD-ROM' names never appear",
        "ACPI: patch table vendor IDs away from BOCHS/QEMU/VBOX",
        "Timing: keep an unthrottled TSC so rdtsc-based checks pass",
    ]


def build_hardened_domain_xml(
    name: str = "argus-det",
    memory_mb: int = 4096,
    vcpus: int = 2,
    mac: str = _DEFAULT_MAC,
    cpu_mode: str = "host-passthrough",
    hide_kvm: bool = True,
    bios_vendor: str = "American Megatrends Inc.",
    system_manufacturer: str = "Dell Inc.",
    system_product: str = "OptiPlex 7090",
    disk_path: str = "/var/lib/libvirt/images/argus-det.qcow2",
) -> str:
    """Emit a full, hardened libvirt domain XML (see module docstring)."""
    kvm_block = "    <kvm>\n      <hidden state='on'/>\n    </kvm>\n" if hide_kvm else ""
    return (
        f"<domain type='kvm'>\n"
        f"  <name>{name}</name>\n"
        f"  <memory unit='MiB'>{memory_mb}</memory>\n"
        f"  <vcpu placement='static'>{vcpus}</vcpu>\n"
        f"  <os>\n"
        f"    <type arch='x86_64' machine='pc-q35-8.0'>hvm</type>\n"
        f"    <boot dev='hd'/>\n"
        f"  </os>\n"
        f"  <features>\n"
        f"    <acpi/>\n"
        f"    <apic/>\n"
        f"{kvm_block}"
        f"  </features>\n"
        f"  <cpu mode='{cpu_mode}' check='none' migratable='off'>\n"
        f"    <topology sockets='1' dies='1' cores='{vcpus}' threads='1'/>\n"
        f"  </cpu>\n"
        f"  <clock offset='localtime'/>\n"
        f"  <on_poweroff>destroy</on_poweroff>\n"
        f"  <on_reboot>destroy</on_reboot>\n"
        f"  <on_crash>destroy</on_crash>\n"
        f"  <devices>\n"
        f"    <emulator>/usr/bin/qemu-system-x86_64</emulator>\n"
        f"    <disk type='file' device='disk'>\n"
        f"      <driver name='qemu' type='qcow2'/>\n"
        f"      <source file='{disk_path}'/>\n"
        f"      <target dev='vda' bus='virtio'/>\n"
        f"    </disk>\n"
        f"    <interface type='bridge'>\n"
        f"      <mac address='{mac}'/>\n"
        f"      <model type='virtio'/>\n"
        f"    </interface>\n"
        f"    <graphics type='none'/>\n"
        f"  </devices>\n"
        f"{_smbios_block(bios_vendor, system_manufacturer, system_product)}"
        f"</domain>\n"
    )


def build_install_domain_xml(
    name: str = "argus-det",
    memory_mb: int = 8192,
    vcpus: int = 4,
    mac: str = "00:14:22:00:00:02",
    disk_path: str = "/var/lib/libvirt/images/argus-det.qcow2",
    win_iso: str = "/var/lib/libvirt/images/Win11_24H2.iso",
    autounattend_iso: str = "/mnt/c/workspace/argus/sandbox-staging/autounattend.iso",
    network: str = "argus-sink",
    bios_vendor: str = "American Megatrends Inc.",
    system_manufacturer: str = "Dell Inc.",
    system_product: str = "OptiPlex 7090",
) -> str:
    """The INSTALL-phase detonation domain (boot the Windows ISO, install clean).

    Windows-native drivers throughout — a SATA disk and an Intel e1000e NIC — so
    Windows setup can see both without a virtio driver ISO. Explicit boot order
    (Win11 CD-ROM first, disk second) so OVMF boots the installer instead of
    dropping to its firmware menu, and ``on_reboot=restart`` so the installer's
    own reboots don't power the VM off mid-install. Hardening (host-passthrough,
    hidden KVM, Dell SMBIOS, real-vendor MAC) is baked in. VNC is kept for the
    install; the PRODUCTION domain strips it (see strip_management_devices).
    """
    return (
        f"<domain type='kvm'>\n"
        f"  <name>{name}</name>\n"
        f"  <memory unit='MiB'>{memory_mb}</memory>\n"
        f"  <vcpu placement='static'>{vcpus}</vcpu>\n"
        f"  <os firmware='efi'>\n"
        f"    <type arch='x86_64' machine='q35'>hvm</type>\n"
        f"  </os>\n"
        f"  <features>\n"
        f"    <acpi/>\n"
        f"    <apic/>\n"
        f"    <smm state='off'/>\n"
        f"    <kvm><hidden state='on'/></kvm>\n"
        f"    <hyperv>\n"
        f"      <relaxed state='on'/>\n"
        f"      <vapic state='on'/>\n"
        f"      <spinlocks state='on' retries='8191'/>\n"
        f"    </hyperv>\n"
        f"  </features>\n"
        f"  <cpu mode='host-passthrough'/>\n"
        f"  <clock offset='localtime'>\n"
        f"    <timer name='rtc' tickpolicy='catchup'/>\n"
        f"    <timer name='pit' tickpolicy='delay'/>\n"
        f"    <timer name='hpet' present='no'/>\n"
        f"    <timer name='hypervclock' present='yes'/>\n"
        f"  </clock>\n"
        f"  <on_poweroff>destroy</on_poweroff>\n"
        f"  <on_reboot>restart</on_reboot>\n"
        f"  <on_crash>destroy</on_crash>\n"
        f"  <devices>\n"
        f"    <emulator>/usr/bin/qemu-system-x86_64</emulator>\n"
        f"    <disk type='file' device='disk'>\n"
        f"      <driver name='qemu' type='qcow2'/>\n"
        f"      <source file='{disk_path}'/>\n"
        f"      <target dev='sdc' bus='sata'/>\n"
        f"      <boot order='2'/>\n"
        f"    </disk>\n"
        f"    <disk type='file' device='cdrom'>\n"
        f"      <driver name='qemu' type='raw'/>\n"
        f"      <source file='{win_iso}'/>\n"
        f"      <target dev='sda' bus='sata'/>\n"
        f"      <boot order='1'/>\n"
        f"      <readonly/>\n"
        f"    </disk>\n"
        f"    <disk type='file' device='cdrom'>\n"
        f"      <driver name='qemu' type='raw'/>\n"
        f"      <source file='{autounattend_iso}'/>\n"
        f"      <target dev='sdb' bus='sata'/>\n"
        f"      <readonly/>\n"
        f"    </disk>\n"
        f"    <interface type='network'>\n"
        f"      <source network='{network}'/>\n"
        f"      <mac address='{mac}'/>\n"
        f"      <model type='e1000e'/>\n"
        f"    </interface>\n"
        f"    <graphics type='vnc' port='-1' listen='127.0.0.1'/>\n"
        f"    <video>\n"
        f"      <model type='qxl'/>\n"
        f"    </video>\n"
        f"  </devices>\n"
        f"{_smbios_block(bios_vendor, system_manufacturer, system_product)}"
        f"</domain>\n"
    )


def _smbios_block(bios_vendor: str, manufacturer: str, product: str) -> str:
    return (
        f"  <sysinfo type='smbios'>\n"
        f"    <bios><entry name='vendor'>{bios_vendor}</entry></bios>\n"
        f"    <system><entry name='manufacturer'>{manufacturer}</entry>"
        f"<entry name='product'>{product}</entry></system>\n"
        f"  </sysinfo>\n"
    )


def _rewrite_macs(xml: str, prefix: str) -> str:
    return re.sub(
        r"(<mac\s+address=')[0-9a-fA-F:]{17}(')",
        lambda m: m.group(1) + _expand_prefix(prefix) + m.group(2),
        xml,
    )


def _expand_prefix(prefix: str) -> str:
    parts = prefix.split(":")
    while len(parts) < 6:
        parts.append("00")
    return ":".join(p[:2] for p in parts[:6])


def harden_existing_xml(
    xml: str,
    mac_prefix: str = _DEFAULT_MAC_PREFIX,
    bios_vendor: str = "American Megatrends Inc.",
    system_manufacturer: str = "Dell Inc.",
    system_product: str = "OptiPlex 7090",
) -> str:
    """Surgically harden an EXISTING libvirt domain XML.

    (1) drop any prior SMBIOS block, (2) rewrite every MAC away from a hypervisor
    OUI, (3) emit a clean SMBIOS block with plausible OEM vendor/product strings.
    Technical ``qemu`` strings (driver/emulator/controller) are left untouched —
    they are not virtualization markers the guest can observe.
    """
    out = xml
    out = re.sub(r"<sysinfo\b.*?</sysinfo>", "", out, flags=re.DOTALL)
    out = _rewrite_macs(out, mac_prefix)
    if "<domain" in out:
        out = out.replace(
            "</domain>",
            _smbios_block(bios_vendor, system_manufacturer, system_product) + "</domain>",
            1,
        )
    return out


def _strip_elements(xml: str, tags: list[str]) -> str:
    for tag in tags:
        xml = re.sub(rf"<{tag}\b[^>]*/>", "", xml, flags=re.DOTALL)          # self-closing
        xml = re.sub(rf"<{tag}\b[^>]*>.*?</{tag}>", "", xml, flags=re.DOTALL)  # with children
    return xml


def strip_management_devices(
    xml: str,
    remove_graphics: bool = True,   # VNC/SPICE remote console — a control channel to wall
    remove_channel: bool = True,    # spice/qemu-guest-agent channels — an escape + injection surface
    remove_redirdev: bool = True,   # USB redirection — passthrough doorway
    remove_sound: bool = True,
    remove_audio: bool = True,
    remove_console: bool = False,   # keep the serial console: it is the L2 injection channel
) -> str:
    """L3: shrink the device surface to virtio disk + virtio NIC only.

    Every emulated device is a QEMU attack surface a payload could target; this
    strips the management/display/audio/USB-redirection devices for a production
    detonation domain. The serial console is kept by default because it is the
    one-way injection channel. Pure string surgery.
    """
    tags = []
    if remove_graphics:
        tags.append("graphics")
    if remove_channel:
        tags.append("channel")
    if remove_redirdev:
        tags.append("redirdev")
    if remove_sound:
        tags.append("sound")
    if remove_audio:
        tags.append("audio")
    if remove_console:
        tags.append("console")
    return _strip_elements(xml, tags)


def has_vm_artifacts(xml: str) -> list[str]:
    """Hypervisor-identifying signals in what the guest can actually observe:
    the SMBIOS block (missing = libvirt's QEMU defaults apply) and the MAC OUI."""
    found: list[str] = []
    m = re.search(r"<sysinfo\b.*?</sysinfo>", xml or "", flags=re.DOTALL)
    if not m:
        found.append("qemu (default SMBIOS)")
    else:
        sysinfo = m.group(0).lower()
        for b in _BAD_SMBIOS:
            if b in sysinfo:
                found.append(b)
    lower = (xml or "").lower()
    for oui in _BAD_OUIS:
        if oui in lower:
            found.append("mac:" + oui)
    return found
