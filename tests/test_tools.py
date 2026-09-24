import json
import tempfile
import unittest
from pathlib import Path

from argus.graph import ProcessGraph
from argus.tools import Tool, _process_lineage, make_tools


class TestTools(unittest.TestCase):
    def test_schema_shape(self):
        t = Tool("x", "desc", {"type": "object", "properties": {}}, lambda: "{}")
        s = t.schema()
        self.assertEqual(s["type"], "function")
        self.assertEqual(s["function"]["name"], "x")
        self.assertIn("parameters", s["function"])

    def test_make_tools_has_four(self):
        self.assertEqual({t.name for t in make_tools()},
                         {"process_lineage", "binary_signature", "virustotal", "blast_radius"})

    def test_process_lineage(self):
        with tempfile.TemporaryDirectory() as d:
            g = ProcessGraph(Path(d) / "g.jsonl")
            g.record("a.exe", "evil.exe")
            g.record_endpoint("evil.exe", "1.2.3.4:443")
            out = json.loads(_process_lineage(g, "evil.exe"))
            self.assertEqual(out["parents"][0]["image"], "a.exe")
            self.assertEqual(out["endpoints"][0]["endpoint"], "1.2.3.4:443")

    def test_process_lineage_no_graph(self):
        out = json.loads(_process_lineage(None, "x.exe"))
        self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()
