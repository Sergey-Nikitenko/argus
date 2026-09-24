import tempfile
import time
import unittest
from pathlib import Path

from argus.memory import MemoryRecord, MemoryStore, cosine
from argus.signature import BehaviorSignature


def sig(techniques=(), structural=(), image=""):
    return BehaviorSignature(
        techniques=frozenset(techniques), structural=frozenset(structural),
        image=image, image_base=Path(image).name if image else "",
    )


class TestCosine(unittest.TestCase):
    def test_identical_is_one(self):
        self.assertAlmostEqual(cosine({"a": 1, "b": 1}, {"a": 1, "b": 1}), 1.0)

    def test_disjoint_is_zero(self):
        self.assertEqual(cosine({"a": 1}, {"b": 1}), 0.0)

    def test_empty_is_zero(self):
        self.assertEqual(cosine({}, {"a": 1}), 0.0)


class TestMemoryStore(unittest.TestCase):
    def test_promotion_gate(self):
        with tempfile.TemporaryDirectory() as d:
            store = MemoryStore(Path(d) / "mem.jsonl")
            hi = MemoryRecord(id="a", signature=sig(structural={"image:shell"}),
                              verdict="BENIGN", outcome="confirmed_false_positive",
                              confidence="high", ts=time.time())
            lo = MemoryRecord(id="b", signature=sig(structural={"image:lolbin"}),
                              verdict="BENIGN", outcome="model_only",
                              confidence="low", ts=time.time())
            store.ingest(hi)
            store.ingest(lo)
            self.assertEqual(store.stats(), {"semantic": 1, "episodic": 1})

    def test_query_ranks_similar_first(self):
        with tempfile.TemporaryDirectory() as d:
            store = MemoryStore(Path(d) / "mem.jsonl")
            now = time.time()
            store.ingest(MemoryRecord(
                id="sim", signature=sig(techniques={"T1059.001", "T1105"}, structural={"image:shell"}),
                verdict="BENIGN", outcome="confirmed_false_positive", confidence="high", ts=now))
            store.ingest(MemoryRecord(
                id="diff", signature=sig(techniques={"T1059.001"}, structural={"image:other"}),
                verdict="BENIGN", outcome="confirmed_false_positive", confidence="high", ts=now))
            results = store.query(sig(techniques={"T1059.001", "T1105"}, structural={"image:shell"}))
            self.assertEqual(results[0][0].id, "sim")
            self.assertGreater(results[0][1], results[1][1])

    def test_upsert_by_id(self):
        with tempfile.TemporaryDirectory() as d:
            store = MemoryStore(Path(d) / "mem.jsonl")
            r1 = MemoryRecord(id="x", signature=sig(structural={"image:shell"}), verdict="BENIGN",
                              outcome="model_only", confidence="low", ts=1.0)
            r2 = MemoryRecord(id="x", signature=sig(structural={"image:shell"}), verdict="MALICIOUS",
                              outcome="verified_incident", confidence="high", ts=2.0)
            store.ingest(r1)
            store.ingest(r2)   # same id, now high confidence -> promoted
            self.assertEqual(store.stats(), {"semantic": 1, "episodic": 0})

    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "mem.jsonl"
            store = MemoryStore(p)
            store.ingest(MemoryRecord(
                id="y", signature=sig(structural={"image:shell"}), verdict="MALICIOUS",
                outcome="verified_incident", confidence="high", ts=123.0))
            store.save()
            store2 = MemoryStore(p)
            self.assertEqual(store2.stats(), {"semantic": 1, "episodic": 0})
            self.assertEqual(store2.semantic[0].id, "y")
            self.assertEqual(store2.semantic[0].ts, 123.0)


    def test_verify_promotes_to_semantic(self):
        with tempfile.TemporaryDirectory() as d:
            store = MemoryStore(Path(d) / "mem.jsonl")
            store.ingest(MemoryRecord(id="z", signature=sig(structural={"image:shell"}),
                                      verdict="BENIGN", outcome="model_only", confidence="low", ts=1.0))
            self.assertEqual(store.stats()["episodic"], 1)
            self.assertTrue(store.verify("z", "BENIGN", "confirmed_false_positive"))
            self.assertEqual(store.stats(), {"semantic": 1, "episodic": 0})
            self.assertEqual(store.semantic[0].confidence, "high")
            self.assertFalse(store.verify("nope", "BENIGN", "confirmed_false_positive"))


    def test_query_cache_and_prefilter(self):
        with tempfile.TemporaryDirectory() as d:
            store = MemoryStore(Path(d) / "mem.jsonl")
            now = time.time()
            store.ingest(MemoryRecord(id="sim", signature=sig(techniques={"T1059.001"}, structural={"image:shell"}),
                                      verdict="BENIGN", outcome="confirmed_false_positive", confidence="high", ts=now))
            store.ingest(MemoryRecord(id="diff", signature=sig(structural={"image:office"}),
                                      verdict="BENIGN", outcome="confirmed_false_positive", confidence="high", ts=now))
            q = sig(techniques={"T1059.001"}, structural={"image:shell"})
            r1 = store.query(q)
            self.assertEqual([x[0].id for x in r1], ["sim"])   # zero-overlap "diff" is pre-filtered out
            r2 = store.query(q)
            self.assertEqual([x[0].id for x in r1], [x[0].id for x in r2])  # cached
            # ingest invalidates the cache so new memory shows up immediately
            store.ingest(MemoryRecord(id="sim2", signature=q, verdict="MALICIOUS",
                                      outcome="verified_incident", confidence="high", ts=now))
            self.assertIn("sim2", [x[0].id for x in store.query(q)])


if __name__ == "__main__":
    unittest.main()
