"""Scoring heuristics for process-creation events.

Pure and deterministic. Each rule carries a MITRE ATT&CK technique so the
dashboard can show technique chips next to every reason.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PureWindowsPath

from .events import ProcessEvent

SUSPICIOUS_PATH_FRAGMENTS = (
    "\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\appdata\\roaming\\",
    "\\programdata\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\public\\",
)

LOLBINS = {
    "powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe",
    "cscript.exe", "wscript.exe", "mshta.exe", "certutil.exe",
    "regsvr32.exe", "rundll32.exe", "msiexec.exe", "bitsadmin.exe",
    "schtasks.exe", "wmic.exe", "reg.exe", "sc.exe", "net.exe",
    "net1.exe", "at.exe", "msbuild.exe", "csc.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "cmstp.exe", "odbcconf.exe",
    "esentutl.exe", "forfiles.exe", "pcalua.exe", "msdt.exe",
}

# per-LOLBin MITRE technique; fallback T1218 (System Binary Proxy Execution)
LOLBIN_TECHNIQUES = {
    "powershell.exe": ("T1059.001", "PowerShell"),
    "powershell_ise.exe": ("T1059.001", "PowerShell"),
    "pwsh.exe": ("T1059.001", "PowerShell"),
    "cmd.exe": ("T1059.003", "Windows Command Shell"),
    "cscript.exe": ("T1059.005", "Visual Basic"),
    "wscript.exe": ("T1059.005", "Visual Basic"),
    "mshta.exe": ("T1218.005", "Mshta"),
    "certutil.exe": ("T1140", "Deobfuscate/Decode Files"),
    "regsvr32.exe": ("T1218.010", "Regsvr32"),
    "rundll32.exe": ("T1218.011", "Rundll32"),
    "msiexec.exe": ("T1218.007", "Msiexec"),
    "bitsadmin.exe": ("T1197", "BITS Jobs"),
    "schtasks.exe": ("T1053.005", "Scheduled Task"),
    "wmic.exe": ("T1047", "Windows Management Instrumentation"),
    "msbuild.exe": ("T1127.001", "Trusted Developer Utilities"),
    "reg.exe": ("T1112", "Modify Registry"),
    "sc.exe": ("T1569.002", "Service Execution"),
    "regasm.exe": ("T1218.009", "Regasm/Regsvcs"),
    "regsvcs.exe": ("T1218.009", "Regasm/Regsvcs"),
    "cmstp.exe": ("T1218.003", "CMSTP"),
    "forfiles.exe": ("T1202", "Indirect Command Execution"),
}

SUSPICIOUS_CMDLINE_PATTERNS = (
    (re.compile(r"-enc(odedcommand)?\b", re.I), "encoded PowerShell command", 45, ("T1059.001", "PowerShell")),
    (re.compile(r"-nop\b|--noprofile", re.I), "no-profile PowerShell", 10, ("T1059.001", "PowerShell")),
    (re.compile(r"-w(in\dowstyle)?\s+hidden|--windowstyle\s+hidden", re.I), "hidden window", 20, ("T1564.003", "Hidden Window")),
    (re.compile(r"-ex(ec(utionpolicy)?)?\s+bypass|--executionpolicy\s+bypass", re.I), "execution-policy bypass", 25, ("T1059.001", "PowerShell")),
    (re.compile(r"iex\s*\(|invoke-expression", re.I), "invoke-expression", 35, ("T1059.001", "PowerShell")),
    (re.compile(r"downloadstring|new-object\s+net\.webclient|webclient", re.I), "download cradle", 35, ("T1105", "Ingress Tool Transfer")),
    (re.compile(r"frombase64string|\[convert\]::frombase64string", re.I), "base64 decode", 30, ("T1027", "Obfuscated Files")),
    (re.compile(r"certutil\s+.*-urlcache", re.I), "certutil download", 40, ("T1105", "Ingress Tool Transfer")),
    (re.compile(r"regsvr32\s+/[ius]:", re.I), "regsvr32 remote", 40, ("T1218.010", "Regsvr32")),
)

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}


@dataclass
class ScoreResult:
    points: int = 0
    reasons: list = field(default_factory=list)
    techniques: list = field(default_factory=list)  # list of {"id","name"}

    def add(self, pts: int, reason: str, technique: tuple | None = None) -> "ScoreResult":
        self.points += pts
        self.reasons.append(reason)
        if technique:
            self.techniques.append({"id": technique[0], "name": technique[1]})
        return self

    def techniques_deduped(self) -> list:
        seen, out = set(), []
        for t in self.techniques:
            if t["id"] not in seen:
                seen.add(t["id"])
                out.append(t)
        return out


def score_event(ev: ProcessEvent) -> ScoreResult:
    s = ScoreResult()
    image = (ev.image or "").lower()
    cmdline = (ev.command_line or "").lower()
    base = PureWindowsPath(ev.image).name.lower() if ev.image else ""

    # 1. Runs from a user-writable / dropper-friendly path
    for frag in SUSPICIOUS_PATH_FRAGMENTS:
        if frag in image:
            s.add(35, f"runs from suspicious path ({frag.strip(chr(92))})", ("T1204.002", "User Execution: Malicious File"))
            break

    # 2. LOLBin / script host
    if base in LOLBINS:
        tech = LOLBIN_TECHNIQUES.get(base, ("T1218", "System Binary Proxy Execution"))
        s.add(20, f"LOLBin/script host: {base}", tech)

    # 3. Suspicious command-line patterns
    for pattern, reason, pts, tech in SUSPICIOUS_CMDLINE_PATTERNS:
        if pattern.search(cmdline):
            s.add(pts, reason, tech)

    # 4. Low integrity (Sysmon only)
    if ev.integrity.lower() == "low":
        s.add(15, "low integrity process", ("T1548", "Abuse Elevation Control Mechanism"))

    # 5. Office app / browser spawning a shell (macro-ish / drive-by)
    parent = PureWindowsPath(ev.parent_image).name.lower() if ev.parent_image else ""
    if parent in OFFICE and base in SHELLS:
        s.add(35, f"Office -> shell: {parent} -> {base}", ("T1204.002", "User Execution: Malicious File"))
    elif parent in BROWSERS and base in SHELLS:
        s.add(25, f"browser -> shell: {parent} -> {base}", ("T1189", "Drive-by Compromise"))

    return s
