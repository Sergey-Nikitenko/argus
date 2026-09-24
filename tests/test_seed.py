import tempfile
import unittest
from pathlib import Path

from argus.memory import MemoryStore
from argus.seed import default_seeds, seed_memory
from argus.signature import BehaviorSignature


class TestSeed(unittest.TestCase):
    def test_seed_adds_semantic_records(self):
        with tempfile.TemporaryDirectory() as d:
            store = MemoryStore(Path(d) / "mem.jsonl")
            n = seed_memory(store, default_seeds())
            self.assertEqual(n, len(default_seeds()))
            self.assertEqual(store.stats()["semantic"], len(default_seeds()))

    def test_seed_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            store = MemoryStore(Path(d) / "mem.jsonl")
            seed_memory(store, default_seeds())
            n2 = seed_memory(store, default_seeds())
            self.assertEqual(n2, 0)  # already seeded

    def test_seed_recalled_for_similar_signature(self):
        with tempfile.TemporaryDirectory() as d:
            store = MemoryStore(Path(d) / "mem.jsonl")
            seed_memory(store, default_seeds())
            sig = BehaviorSignature(techniques=frozenset({"T1490"}),
                                    structural=frozenset({"image:other", "path:system"}),
                                    image_base="vssadmin.exe")
            hits = store.query(sig, k=5)
            self.assertTrue(hits)
            self.assertTrue(any(r.id == "seed_ransomware_shadow_delete" for r, _ in hits))


if __name__ == "__main__":
    unittest.main()
