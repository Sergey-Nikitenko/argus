import tempfile
import unittest
from pathlib import Path

from argus.graph import ProcessGraph


class TestProcessGraph(unittest.TestCase):
    def test_novel_then_known(self):
        with tempfile.TemporaryDirectory() as d:
            g = ProcessGraph(Path(d) / "graph.jsonl")
            self.assertTrue(g.novel(r"C:\Windows\explorer.exe", r"C:\Program Files\chrome.exe"))
            g.record(r"C:\Windows\explorer.exe", r"C:\Program Files\chrome.exe")
            self.assertFalse(g.novel(r"C:\Windows\explorer.exe", r"C:\Program Files\chrome.exe"))

    def test_basename_folding_ignores_path(self):
        with tempfile.TemporaryDirectory() as d:
            g = ProcessGraph(Path(d) / "graph.jsonl")
            g.record(r"C:\Windows\explorer.exe", r"C:\Program Files\chrome.exe")
            # same basenames, different paths -> NOT novel
            self.assertFalse(g.novel(r"C:\Windows\explorer.exe", r"D:\Other\chrome.exe"))

    def test_children_and_parents(self):
        with tempfile.TemporaryDirectory() as d:
            g = ProcessGraph(Path(d) / "graph.jsonl")
            g.record("explorer.exe", "chrome.exe")
            g.record("explorer.exe", "notepad.exe")
            g.record("cmd.exe", "chrome.exe")
            self.assertEqual({c.child for c in g.children("explorer.exe")},
                             {"chrome.exe", "notepad.exe"})
            self.assertEqual({p.parent for p in g.parents("chrome.exe")},
                             {"explorer.exe", "cmd.exe"})

    def test_count_and_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "graph.jsonl"
            g = ProcessGraph(p)
            g.record("a.exe", "b.exe", host="HOST", user="bob", timestamp="t1")
            g.record("a.exe", "b.exe", timestamp="t2")
            self.assertEqual(g.edges[("a.exe", "b.exe")].count, 2)
            g.save()
            g2 = ProcessGraph(p)
            self.assertEqual(g2.stats()["edges"], 1)
            self.assertFalse(g2.novel("a.exe", "b.exe"))
            self.assertEqual(g2.edges[("a.exe", "b.exe")].count, 2)
            self.assertIn("HOST", g2.edges[("a.exe", "b.exe")].hosts)


    def test_endpoint_tracking_and_connections(self):
        with tempfile.TemporaryDirectory() as d:
            g = ProcessGraph(Path(d) / "graph.jsonl")
            self.assertTrue(g.novel_endpoint("payload.exe", "203.0.113.7:443"))
            g.record_endpoint(r"C:\Users\x\payload.exe", "203.0.113.7:443", host="H", user="alice")
            self.assertFalse(g.novel_endpoint(r"C:\Users\x\payload.exe", "203.0.113.7:443"))
            self.assertEqual([c.child for c in g.connections("payload.exe")], ["203.0.113.7:443"])

    def test_blast_radius(self):
        with tempfile.TemporaryDirectory() as d:
            g = ProcessGraph(Path(d) / "graph.jsonl")
            g.record("a.exe", "b.exe", host="H1", user="u1")
            g.record_endpoint("b.exe", "1.2.3.4:80", host="H1", user="u1")
            br = g.blast_radius("b.exe")
            self.assertIn("H1", br["hosts"])
            self.assertIn("u1", br["users"])
            self.assertEqual(br["spawn_edges"], 1)
            self.assertEqual(br["endpoint_edges"], 1)

    def test_endpoint_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "graph.jsonl"
            g = ProcessGraph(p)
            g.record_endpoint("x.exe", "9.9.9.9:443", host="H")
            g.save()
            g2 = ProcessGraph(p)
            self.assertEqual(g2.stats()["endpoints"], 1)
            self.assertFalse(g2.novel_endpoint("x.exe", "9.9.9.9:443"))

    def test_campaign_correlates_chain(self):
        with tempfile.TemporaryDirectory() as d:
            g = ProcessGraph(Path(d) / "graph.jsonl")
            # day 1: a.exe spawns b.exe; later: b.exe spawns c.exe and calls out
            g.record("a.exe", "b.exe")
            g.record("b.exe", "c.exe")
            g.record_endpoint("b.exe", "203.0.113.7:443")
            camp = g.campaign("a.exe")
            self.assertEqual(camp["root"], "a.exe")
            self.assertIn("b.exe", camp["processes"])
            self.assertIn("c.exe", camp["processes"])
            self.assertEqual(len(camp["endpoints"]), 1)
            self.assertEqual(camp["endpoints"][0]["endpoint"], "203.0.113.7:443")

    def test_seen(self):
        with tempfile.TemporaryDirectory() as d:
            g = ProcessGraph(Path(d) / "graph.jsonl")
            self.assertFalse(g.seen("x.exe"))
            g.record("a.exe", "x.exe")
            self.assertTrue(g.seen("x.exe"))


if __name__ == "__main__":
    unittest.main()
