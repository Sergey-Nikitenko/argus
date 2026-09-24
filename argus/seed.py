"""Semantic-memory seeding — abstracted behavioral profiles.

The two-tier memory starts empty, so its similarity recall has nothing to compare
against until real incidents accumulate. Seeding plants ABSTRACTED profiles (MITRE
techniques + structural context + a verdict) — not raw command strings — so the
memory can recognize a novel ransomware/credential/persistence variant by *shape*
before it has ever seen that exact binary. Seeds are idempotent and never overwrite
an analyst's later verdict on the same id.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .memory import MemoryRecord, MemoryStore
from .signature import BehaviorSignature


def default_seeds() -> list:
    """The built-in seed bank: abstracted attack profiles + a benign baseline."""
    return [
        {"id": "seed_ransomware_shadow_delete", "verdict": "MALICIOUS", "category": "ransomware",
         "techniques": ["T1490"], "structural": ["image:other", "path:system"], "image_base": "vssadmin.exe"},
        {"id": "seed_ransomware_wipe", "verdict": "MALICIOUS", "category": "ransomware",
         "techniques": ["T1485"], "structural": ["image:other", "path:system"], "image_base": "cipher.exe"},
        {"id": "seed_credential_sam", "verdict": "MALICIOUS", "category": "credential",
         "techniques": ["T1003.002"], "structural": ["image:lolbin", "path:system"], "image_base": "reg.exe"},
        {"id": "seed_credential_lsass", "verdict": "MALICIOUS", "category": "credential",
         "techniques": ["T1003.001"], "structural": ["image:other", "path:other"], "image_base": "procdump.exe"},
        {"id": "seed_persistence_runkey", "verdict": "MALICIOUS", "category": "persistence",
         "techniques": ["T1547.001"], "structural": ["image:lolbin", "path:system"], "image_base": "reg.exe"},
        {"id": "seed_persistence_schtasks", "verdict": "MALICIOUS", "category": "persistence",
         "techniques": ["T1053.005"], "structural": ["image:lolbin", "path:system"], "image_base": "schtasks.exe"},
        {"id": "seed_keylogger", "verdict": "MALICIOUS", "category": "keylogger",
         "techniques": ["T1056.004"], "structural": ["image:shell", "path:system"], "image_base": "powershell.exe"},
        {"id": "seed_download_cradle", "verdict": "MALICIOUS", "category": "download",
         "techniques": ["T1105"], "structural": ["image:shell", "path:system"], "image_base": "powershell.exe"},
        {"id": "seed_download_certutil", "verdict": "MALICIOUS", "category": "download",
         "techniques": ["T1105"], "structural": ["image:lolbin", "path:system"], "image_base": "certutil.exe"},
        {"id": "seed_lateral_wmi", "verdict": "MALICIOUS", "category": "lateral",
         "techniques": ["T1047"], "structural": ["image:lolbin", "path:system"], "image_base": "wmic.exe"},
        {"id": "seed_obfuscation_b64", "verdict": "MALICIOUS", "category": "obfuscation",
         "techniques": ["T1027"], "structural": ["image:shell", "path:system"], "image_base": "powershell.exe"},
        {"id": "seed_benign_chrome", "verdict": "BENIGN", "category": "baseline",
         "techniques": [], "structural": ["image:browser", "path:system"], "image_base": "chrome.exe"},
        {"id": "seed_benign_explorer", "verdict": "BENIGN", "category": "baseline",
         "techniques": [], "structural": ["image:other", "path:system"], "image_base": "explorer.exe"},
    ]


def seed_memory(store: MemoryStore, seeds: list) -> int:
    """Ingest seed profiles into the semantic tier (high confidence), idempotently.

    Skips any id already present so an analyst's later verdict is never clobbered
    by a re-seed on startup. Returns the number newly seeded."""
    now = time.time()
    existing = {r.id for r in store.semantic + store.episodic}
    n = 0
    for d in seeds:
        rid = d.get("id", "")
        if not rid or rid in existing:
            continue
        sig = BehaviorSignature(
            techniques=frozenset(d.get("techniques", [])),
            structural=frozenset(d.get("structural", [])),
            image_base=d.get("image_base", ""),
        )
        store.ingest(MemoryRecord(
            id=rid, signature=sig,
            verdict=d.get("verdict", "MALICIOUS"),
            outcome="seed", confidence="high",
            timestamp="", ts=now,
            image=d.get("image_base", ""),
        ))
        existing.add(rid)
        n += 1
    return n


def load_seeds(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("seeds", [])
    except (json.JSONDecodeError, OSError):
        return []
