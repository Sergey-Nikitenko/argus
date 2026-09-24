"""Behavioral signature abstraction — the memory system's stable key.

Raw command lines change constantly (paths, timestamps, randomized filenames), so
the memory system never stores or compares them directly. Instead each event is
abstracted into a STABLE :class:`BehaviorSignature` — the set of MITRE techniques
that fired plus structural context (what kind of binary, where it lives, who its
parent is). That is the "Execution of encoded PowerShell command launching child
network process" idea from the design brief, made deterministic.

The signature also produces a deterministic feature vector (one-hot over
techniques + structural tokens) so similarity is a plain cosine — no embedding
model, no vector database, fully unit-testable.
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import PureWindowsPath

from .events import ProcessEvent
from .score import (BROWSERS, LOLBINS, OFFICE, SHELLS, SUSPICIOUS_PATH_FRAGMENTS,
                    ScoreResult)


def _image_class(image: str) -> str:
    base = PureWindowsPath(image).name.lower() if image else ""
    if base in OFFICE:
        return "office"
    if base in BROWSERS:
        return "browser"
    if base in SHELLS:
        return "shell"
    if base in LOLBINS:
        return "lolbin"
    return "other"


def _path_class(image: str) -> str:
    img = (image or "").lower()
    if any(frag in img for frag in SUSPICIOUS_PATH_FRAGMENTS):
        return "dropper"
    if "\\windows\\" in img or "\\program files" in img or "\\system32\\" in img:
        return "system"
    if "\\users\\" in img or "\\appdata\\" in img:
        return "user"
    return "other"


def _b64decode(s: str, utf16_first: bool = False) -> str:
    """Decode a base64 blob, trying the encodings PowerShell actually uses."""
    s = s.strip()
    if not s:
        return ""
    pad = (-len(s)) % 4
    try:
        raw = base64.b64decode(s + "=" * pad)
    except Exception:  # noqa: BLE001 — malformed base64 is just "no payload"
        return ""
    encs = ("utf-16-le", "utf-8") if utf16_first else ("utf-8", "utf-16-le")
    for enc in encs:
        try:
            text = raw.decode(enc)
        except Exception:  # noqa: BLE001
            continue
        text = text.replace("\x00", "")
        text = re.sub(r"\s+", " ", text).strip()
        if text:
            return text
    return ""


def _fp(s: str) -> str:
    norm = re.sub(r"\s+", " ", s.strip().lower())
    return hashlib.sha1(norm.encode("utf-8")).hexdigest()[:12]


def payload_fingerprint(command_line: str) -> str:
    """Fingerprint of an obfuscated payload, or "" for plaintext commands.

    Encoded/obfuscated commands are fingerprinted by their DECODED content, so a
    benign demo (``-enc Write-Output hi``) never shares a memory signature with a
    real encoded attack (``-enc <c2 beacon>``). Plaintext commands return "" and
    keep the coarse behavioral signature, preserving cross-run baseline learning.
    """
    if not command_line:
        return ""
    cl = command_line
    m = re.search(r"-enc(?:odedcommand)?\b\s*[:\s]?\s*[\"']?([A-Za-z0-9+/=]+)", cl, re.I)
    if m:
        decoded = _b64decode(m.group(1), utf16_first=True)
        return "enc:" + (_fp(decoded) if decoded else _fp(cl))
    m = re.search(r"frombase64string\s*\(\s*[\"']([^\"']+)[\"']", cl, re.I)
    if m:
        decoded = _b64decode(m.group(1), utf16_first=False)
        return "b64:" + (_fp(decoded) if decoded else _fp(cl))
    if re.search(r"iex\s*\(|invoke-expression", cl, re.I):
        return "iex:" + _fp(cl)
    return ""


@dataclass
class BehaviorSignature:
    """The stable, comparable essence of a process-creation event."""
    techniques: frozenset = field(default_factory=frozenset)   # MITRE IDs, e.g. T1059.001
    structural: frozenset = field(default_factory=frozenset)   # "image:shell", "path:dropper", ...
    image: str = ""          # raw lowercased image (entity/display, not embedded)
    image_base: str = ""     # basename only — the stable entity name
    parent_image: str = ""
    user: str = ""
    host: str = ""
    payload: str = ""        # decoded-obfuscation fingerprint; "" when plaintext

    @classmethod
    def from_event(cls, ev: ProcessEvent, score: ScoreResult, host: str = "") -> "BehaviorSignature":
        techniques = frozenset(t["id"] for t in score.techniques_deduped())
        iclass = _image_class(ev.image)
        pclass = _image_class(ev.parent_image)
        structural = {f"image:{iclass}", f"path:{_path_class(ev.image)}"}
        if ev.parent_image:
            structural.add(f"parent:{pclass}")
        else:
            structural.add("no_parent")
        if (ev.integrity or "").lower() == "low":
            structural.add("low_integrity")
        image = (ev.image or "").lower()
        return cls(
            techniques=techniques,
            structural=frozenset(structural),
            image=image,
            image_base=PureWindowsPath(image).name if image else "",
            parent_image=(ev.parent_image or "").lower(),
            user=(ev.user or "").lower(),
            host=host,
            payload=payload_fingerprint(ev.command_line or ""),
        )

    def features(self) -> dict:
        """Deterministic one-hot feature vector (techniques + structural tokens)."""
        vec: dict = {}
        for t in self.techniques:
            vec[f"tech:{t}"] = 1.0
        for s in self.structural:
            vec[f"struct:{s}"] = 1.0
        if self.payload:
            vec[f"payload:{self.payload}"] = 1.0
        return vec

    def text(self) -> str:
        """Human-readable abstraction, used in prompts and summaries."""
        bits = []
        if self.techniques:
            bits.append("techniques " + ", ".join(sorted(self.techniques)))
        ctx = sorted(s for s in self.structural
                     if s.startswith("image:") or s.startswith("parent:") or s.startswith("path:"))
        if ctx:
            bits.append(", ".join(ctx))
        if self.image_base:
            bits.append(self.image_base)
        return "; ".join(bits) or "unremarkable process"


def signature_id(sig: BehaviorSignature) -> str:
    """Stable dedup key: behavior + entity name (basename), NOT raw path/time.

    Two "updater.exe" spawns with the same technique stack collapse to one memory
    record (updated in place), which is what lets a recurring deployment tool be
    learned once and recognized forever after.
    """
    key = "|".join(sorted(sig.techniques)) + "||" + "|".join(sorted(sig.structural)) + "||" + sig.image_base
    if sig.payload:
        key += "||" + sig.payload
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
