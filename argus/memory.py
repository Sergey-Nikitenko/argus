"""Two-tier detection memory: episodic (short-term) + semantic (long-term).

Built on the akashic-aurora house pattern — a durable JSONL substrate with an
in-memory index, a learn/recall split, and salience-gated promotion:

* Every incident is stored in the EPISODIC tier (recent, all verdicts).
* Only HIGH-confidence (analyst-verified) verdicts are PROMOTED into the SEMANTIC
  tier — the "benign baseline" / "known incident" ground truth. A model-only or
  UNCERTAIN verdict never becomes ground truth, which is the poisoning/drift guard.
* Retrieval is top-k cosine over the deterministic behavioral feature vector,
  multiplied by a time-decay factor so stale, non-recurring alerts fade.

Stdlib-only: cosine is hand-rolled over small dict vectors, and the "vector store"
is just an in-memory list persisted to JSONL — plenty for single-host EDR scale.
"""
from __future__ import annotations

import json
import math
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from .signature import BehaviorSignature


@dataclass
class MemoryRecord:
    id: str
    signature: BehaviorSignature
    verdict: str        # MALICIOUS / BENIGN / UNCERTAIN
    outcome: str        # verified_incident / confirmed_false_positive / model_only
    confidence: str     # high / medium / low
    timestamp: str = ""  # ISO-8601 (display)
    ts: float = 0.0     # epoch seconds (decay)
    score: int = 0
    image: str = ""
    host: str = ""
    user: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "verdict": self.verdict,
            "outcome": self.outcome,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "ts": self.ts,
            "score": self.score,
            "image": self.image,
            "host": self.host,
            "user": self.user,
            "techniques": sorted(self.signature.techniques),
            "structural": sorted(self.signature.structural),
            "payload": self.signature.payload,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MemoryRecord":
        sig = BehaviorSignature(
            techniques=frozenset(d.get("techniques", [])),
            structural=frozenset(d.get("structural", [])),
            image=d.get("image", ""),
            image_base=Path(d.get("image", "")).name if d.get("image") else "",
            user=d.get("user", ""),
            host=d.get("host", ""),
            payload=d.get("payload", ""),
        )
        return cls(
            id=d["id"], signature=sig,
            verdict=d.get("verdict", "UNCERTAIN"),
            outcome=d.get("outcome", "model_only"),
            confidence=d.get("confidence", "low"),
            timestamp=d.get("timestamp", ""),
            ts=d.get("ts", 0.0), score=d.get("score", 0),
            image=d.get("image", ""), host=d.get("host", ""), user=d.get("user", ""),
        )


def cosine(a: dict, b: dict) -> float:
    """Cosine similarity over sparse {feature: weight} vectors."""
    if not a or not b:
        return 0.0
    keys = set(a) | set(b)
    dot = sum(a.get(k, 0.0) * b.get(k, 0.0) for k in keys)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class MemoryStore:
    """Durable two-tier memory. ``semantic`` is long-term ground truth (high
    confidence only); ``episodic`` is the recent working set."""

    def __init__(self, path: Path, max_episodic: int = 2000, max_semantic: int = 1000,
                 half_life_days: float = 30.0, cache_size: int = 256):
        self.path = Path(path)
        self.max_episodic = max_episodic
        self.max_semantic = max_semantic
        self.half_life = half_life_days * 86400.0
        self.episodic: list[MemoryRecord] = []
        self.semantic: list[MemoryRecord] = []
        self._cache: OrderedDict = OrderedDict()
        self._cache_size = cache_size
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        except OSError:
            return
        for line in lines:
            if not line.strip():
                continue
            try:
                rec = MemoryRecord.from_dict(json.loads(line))
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
            if rec.confidence == "high":
                self.semantic.append(rec)
            else:
                self.episodic.append(rec)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            for rec in self.semantic + self.episodic:
                fh.write(json.dumps(rec.to_dict(), default=str) + "\n")

    def ingest(self, rec: MemoryRecord) -> None:
        """Store a record, upserting by stable id, and gate promotion.

        Promotion gate: only high-confidence (analyst-verified) records enter the
        semantic tier. This is the poisoning/drift guard — nothing an attacker can
        induce (low-severity noise) is ever stored as a "benign" baseline.
        Promotion is a *move*: when a low-confidence record is later verified, its
        episodic copy is removed so there is exactly one canonical copy."""
        if rec.confidence == "high":
            self._upsert(self.semantic, rec, self.max_semantic)
            self.episodic = [r for r in self.episodic if r.id != rec.id]
        else:
            self._upsert(self.episodic, rec, self.max_episodic)
        self._cache.clear()   # new memory invalidates cached retrievals

    def _upsert(self, tier: list, rec: MemoryRecord, cap: int) -> None:
        for i, existing in enumerate(tier):
            if existing.id == rec.id:
                tier[i] = rec
                return
        tier.append(rec)
        if len(tier) > cap:
            tier.sort(key=lambda r: r.ts or 0.0)
            del tier[: len(tier) - cap]

    def verify(self, rec_id: str, verdict: str, outcome: str) -> bool:
        """Analyst feedback: mark an existing record as high-confidence ground truth.

        Finds the record by id (episodic or semantic), sets the analyst's verdict
        and outcome, and re-ingests it — which PROMOTES it into the semantic tier.
        Returns True if a record was found and updated."""
        for tier in (self.episodic, self.semantic):
            for rec in tier:
                if rec.id == rec_id:
                    rec.verdict = verdict
                    rec.outcome = outcome
                    rec.confidence = "high"
                    self.ingest(rec)
                    return True
        return False

    def query(self, sig: BehaviorSignature, k: int = 5, include_episodic: bool = True):
        """Return up to ``k`` (record, score) ranked by cosine * time-decay.

        Cached by signature (LRU, invalidated on ingest) so repeated queries —
        e.g. a respawn storm of the same behavior — don't re-run vector search."""
        key = (frozenset(sig.features().items()), k, include_episodic)
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        result = self._query(sig, k, include_episodic)
        self._cache[key] = result
        if len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)
        return result

    def _query(self, sig: BehaviorSignature, k: int, include_episodic: bool):
        vec = sig.features()
        now = time.time()
        scored = []
        tiers = [self.semantic, self.episodic] if include_episodic else [self.semantic]
        for tier in tiers:
            for rec in tier:
                if not self._overlaps(sig, rec.signature):
                    continue   # zero-overlap => cosine 0, skip the arithmetic
                sim = cosine(vec, rec.signature.features())
                age = max(0.0, now - (rec.ts or 0.0))
                decay = math.exp(-age / self.half_life) if self.half_life else 1.0
                scored.append((rec, sim * decay))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]

    @staticmethod
    def _overlaps(a: BehaviorSignature, b: BehaviorSignature) -> bool:
        """Categorical pre-filter: two one-hot signatures can only have cosine > 0
        if they share at least one technique or structural token."""
        return bool((a.techniques & b.techniques) or (a.structural & b.structural))

    def stats(self) -> dict:
        return {"semantic": len(self.semantic), "episodic": len(self.episodic)}
