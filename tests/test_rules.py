import tempfile
import unittest
from pathlib import Path

from argus.config import Config
from argus.rules import approve_rule, list_rules, propose_rule


RULE = {
    "title": "test rule", "status": "experimental",
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {"selection": {"Image|endswith": "\\x.exe"}, "condition": "selection"},
    "tags": ["attack.t1059_001"],
}


class TestRules(unittest.TestCase):
    def test_propose_list_approve(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(data_dir=Path(d))
            rid = propose_rule(cfg, RULE, ["T1059.001"])
            rules = list_rules(cfg)
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0]["status"], "proposed")
            path = approve_rule(cfg, rid)
            self.assertTrue(Path(path).exists())
            self.assertEqual(list_rules(cfg)[0]["status"], "approved")

    def test_approve_unknown_raises(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(data_dir=Path(d))
            with self.assertRaises(KeyError):
                approve_rule(cfg, "nope")


if __name__ == "__main__":
    unittest.main()
