"""Scoring heuristics for process-creation events.

Pure and deterministic. Each rule carries a MITRE ATT&CK technique so the
dashboard can show technique chips next to every reason.
"""
from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, field
from pathlib import PureWindowsPath

from .events import ProcessEvent
from .ruleset import compile_rules

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

# Specific LOLBin misuse behaviors. The generic LOLBin +20 is not enough: a
# binary doing its *specific* malicious thing scores much higher, and each rule is
# gated to the exact binary that performs it (so cmd.exe echoing "vssadmin delete
# shadows" as text does NOT inherit the ransomware score).
LOLBIN_MISUSE = {
    "vssadmin.exe": [
        (re.compile(r"delete\s+shadow", re.I), 55, "shadow copy deletion (ransomware)", ("T1490", "Inhibit System Recovery")),
    ],
    "wmic.exe": [
        (re.compile(r"shadowcopy\s+delete", re.I), 55, "shadow copy deletion (ransomware)", ("T1490", "Inhibit System Recovery")),
        (re.compile(r"/node:", re.I), 50, "remote WMI execution", ("T1047", "Windows Management Instrumentation")),
        (re.compile(r"os\s+get\s+/format:", re.I), 45, "WMI XSL script download", ("T1220", "XSL Script Processing")),
    ],
    "cipher.exe": [
        (re.compile(r"/w:", re.I), 50, "disk wipe (cipher)", ("T1485", "Data Destruction")),
    ],
    "bcdedit.exe": [
        (re.compile(r"recoveryenabled\s+no", re.I), 50, "disable recovery (ransomware)", ("T1490", "Inhibit System Recovery")),
    ],
    "schtasks.exe": [
        (re.compile(r"/create", re.I), 50, "scheduled task persistence", ("T1053.005", "Scheduled Task")),
    ],
    "reg.exe": [
        (re.compile(r"save\s+HKLM\\(SAM|SECURITY|SYSTEM)", re.I), 60, "registry hive dump (credential access)", ("T1003.002", "Security Account Manager")),
        (re.compile(r"add\s+.*\\run\b", re.I), 50, "Run key persistence", ("T1547.001", "Registry Run Keys")),
    ],
    "bitsadmin.exe": [
        (re.compile(r"/transfer", re.I), 45, "bitsadmin download", ("T1105", "Ingress Tool Transfer")),
    ],
    "mshta.exe": [
        (re.compile(r"https?://", re.I), 45, "mshta remote content", ("T1218.005", "Mshta")),
    ],
    "rundll32.exe": [
        (re.compile(r"comsvcs.*MiniDump|MiniDump.*comsvcs", re.I), 60, "LSASS dump (comsvcs)", ("T1003.001", "LSASS Memory")),
    ],
    "procdump.exe": [
        (re.compile(r"-ma.*lsass|lsass.*-ma", re.I), 60, "LSASS dump (procdump)", ("T1003.001", "LSASS Memory")),
    ],
    "procdump64.exe": [
        (re.compile(r"-ma.*lsass|lsass.*-ma", re.I), 60, "LSASS dump (procdump)", ("T1003.001", "LSASS Memory")),
    ],
}

# Keylogger signatures — script hosts running input-capture code in a one-liner.
KEYLOGGER_PATTERNS = (
    (re.compile(r"SetWindowsHookEx|WH_KEYBOARD|GetAsyncKeyState|RegisterRawInputDevices", re.I),
     "keyboard hook (keylogger)", 50, ("T1056.004", "Input Capture")),
)


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

# Script interpreters that are NOT LOLBins but can execute dropped code. The
# interpreter binary itself lives in a trusted path, so the image check is blind
# to them — the DROPPED SCRIPT they run is the payload.
SCRIPT_HOSTS = {
    "python.exe", "python3.exe", "pythonw.exe", "py.exe",
    "node.exe", "ruby.exe", "perl.exe", "php.exe", "java.exe", "javaw.exe",
}
SCRIPT_HOST_TECH = {
    "python.exe": ("T1059.006", "Python"),
    "python3.exe": ("T1059.006", "Python"),
    "pythonw.exe": ("T1059.006", "Python"),
    "py.exe": ("T1059.006", "Python"),
    "node.exe": ("T1059.007", "JavaScript"),
}
_SCRIPT_EXT_RE = re.compile(r"\.(?:py|pyw|js|mjs|cjs|jsx|vbs|ps1|psm1|hta|wsf|bat|cmd|vbe|jar)\b", re.I)

_DROPPED_SCRIPT_PATH_RE = re.compile(
    r'([A-Za-z]:[\\/][^"\'\s]*\.(?:py|pyw|js|mjs|cjs|jsx|vbs|ps1|psm1|hta|wsf|bat|cmd|vbe|jar))\b',
    re.I,
)


def dropped_script_path(command_line: str) -> str:
    """Extract the path of a dropped script referenced in a command line, or "".

    Used to quarantine the DROPPED payload itself — not the trusted interpreter
    running it — a script file (by extension) whose path lies in a dropper
    location (temp/downloads/programdata/...)."""
    if not command_line:
        return ""
    for m in _DROPPED_SCRIPT_PATH_RE.finditer(command_line):
        path = m.group(1)
        if any(frag in path.lower() for frag in SUSPICIOUS_PATH_FRAGMENTS):
            return path
    return ""


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char). High entropy (~5.5+) is the signature of
    base64/randomized obfuscated payloads; normal commands sit around ~4."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


@dataclass
class ScoreResult:
    points: int = 0
    reasons: list = field(default_factory=list)
    techniques: list = field(default_factory=list)  # list of {"id","name"}
    dropped_script: str = ""   # path of a dropped payload script, when detected

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


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_") or "rule"


def default_rule_dicts() -> list:
    """The built-in detection rules as JSON-able dicts (seed for the rule store)."""
    rules = []
    for pat, reason, pts, (tid, tname) in SUSPICIOUS_CMDLINE_PATTERNS:
        rules.append({"id": _slug(reason), "pattern": pat.pattern, "points": pts,
                      "reason": reason, "technique": tid, "technique_name": tname,
                      "binary": "", "gate": "shell_lolbin"})
    for base, pats in LOLBIN_MISUSE.items():
        for pat, pts, reason, (tid, tname) in pats:
            rules.append({"id": f"{_slug(base)}_{_slug(reason)}", "pattern": pat.pattern,
                          "points": pts, "reason": reason, "technique": tid,
                          "technique_name": tname, "binary": base, "gate": ""})
    for pat, reason, pts, (tid, tname) in KEYLOGGER_PATTERNS:
        rules.append({"id": _slug(reason), "pattern": pat.pattern, "points": pts,
                      "reason": reason, "technique": tid, "technique_name": tname,
                      "binary": "", "gate": "shell_script"})
    return rules


_rules = compile_rules(default_rule_dicts())


def set_active_rules(rules: list) -> None:
    """Swap in a new compiled rule list (the hot-reload path)."""
    global _rules
    _rules = rules


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

    # 3. Dynamic pattern rules — shell/LOLBin misuse, keyloggers, downloads, etc.
    # Loaded from the JSON rule store (hot-reloadable). Each rule carries a gate:
    #   binary="vssadmin.exe"  -> only that exact binary
    #   gate="shell_lolbin"    -> base in SHELLS or LOLBINS
    #   gate="shell_script"    -> base in SHELLS or SCRIPT_HOSTS
    #   (no gate)              -> any process
    for rule in _rules:
        binary = rule["binary"]
        if binary:
            if base != binary:
                continue
        else:
            gate = rule["gate"]
            if gate == "shell_lolbin" and not (base in SHELLS or base in LOLBINS):
                continue
            if gate == "shell_script" and not (base in SHELLS or base in SCRIPT_HOSTS):
                continue
        if rule["rx"].search(cmdline):
            s.add(rule["points"], rule["reason"], (rule["technique"], rule["technique_name"]))

    # 4. Low integrity (Sysmon only)
    if ev.integrity.lower() == "low":
        s.add(15, "low integrity process", ("T1548", "Abuse Elevation Control Mechanism"))

    # 5. Office app / browser spawning a shell (macro-ish / drive-by)
    parent = PureWindowsPath(ev.parent_image).name.lower() if ev.parent_image else ""
    if parent in OFFICE and base in SHELLS:
        s.add(35, f"Office -> shell: {parent} -> {base}", ("T1204.002", "User Execution: Malicious File"))
    elif parent in BROWSERS and base in SHELLS:
        s.add(25, f"browser -> shell: {parent} -> {base}", ("T1189", "Drive-by Compromise"))

    # 6. Script interpreter executing a DROPPED script — a python/node/etc binary
    # (trusted path) whose command line points at a script in a dropper location
    # (temp/downloads/programdata/...). This is the operator running, not arriving.
    # The dropper path and the script extension must be in the SAME path (via
    # dropped_script_path) — merely mentioning "C:\ProgramData\..." as a data dir
    # elsewhere in argv must NOT trigger this.
    dropped = dropped_script_path(ev.command_line or "")
    if base in SCRIPT_HOSTS and dropped:
        tech = SCRIPT_HOST_TECH.get(base, ("T1059", "Command and Scripting Interpreter"))
        s.add(40, f"script host runs dropped file ({base})", tech)
        s.dropped_script = dropped

    # 7. High-entropy command line — obfuscated/encoded payload
    if len(cmdline) >= 48:
        ent = shannon_entropy(cmdline)
        if ent >= 5.0:
            s.add(20, f"high-entropy command line (entropy {ent:.1f})", ("T1027", "Obfuscated Files"))

    return s


def is_remote_ip(ip: str) -> bool:
    """True for a globally-routable (public internet) IP address."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def score_network_event(nev, graph=None) -> ScoreResult:
    """Score a Sysmon Event ID 3 network connection for beacon-like behavior.

    The operator's C2 loop is silent at the process level, so it's caught at the
    NETWORK level instead: a script interpreter (python/powershell/node/…) making
    an OUTBOUND connection to a NOVEL (never-before-seen on this host) PUBLIC
    endpoint. That is the callback signature of a beacon (T1071)."""
    s = ScoreResult()
    if not getattr(nev, "initiated", True):
        return s
    ip = getattr(nev, "destination_ip", "") or ""
    if not is_remote_ip(ip):
        return s
    base = PureWindowsPath(nev.image).name.lower() if nev.image else ""
    if base not in SCRIPT_HOSTS and base not in SHELLS:
        return s
    endpoint = nev.endpoint()
    if graph is not None and not graph.novel_endpoint(nev.image, endpoint):
        return s
    s.add(45, f"script host beaconing to novel endpoint {endpoint} ({base})",
          ("T1071", "Application Layer Protocol"))
    return s
