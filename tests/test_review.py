import json
import re
import tempfile
import unittest
from pathlib import Path

from argus.config import Config
from argus.review import propose_rule, promote_to_rule
from argus.ruleset import dump_rules
from argus.score import default_rule_dicts


class TestReview(unittest.TestCase):
    def test_propose_rule_extracts_pattern_and_binary(self):
        rule = propose_rule(r"C:\Windows\System32\foo.exe", "foo.exe --steal --upload http://x")
        self.assertIsNotNone(rule)
        self.assertEqual(rule["binary"], "foo.exe")
        self.assertIn("steal", rule["pattern"])

    def test_proposed_rule_matches_original_cmdline(self):
        cmd = "foo.exe --steal --upload http://x"
        rule = propose_rule(r"C:\Windows\System32\foo.exe", cmd)
        self.assertTrue(re.compile(rule["pattern"], re.I).search(cmd))

    def test_promote_appends_to_rule_store(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(data_dir=Path(d))
            dump_rules(default_rule_dicts(), cfg.detection_rules_path)
            before = len(default_rule_dicts())
            rule = promote_to_rule(cfg, r"C:\Windows\System32\foo.exe", "foo.exe --steal")
            self.assertIsNotNone(rule)
            data = json.loads(cfg.detection_rules_path.read_text(encoding="utf-8"))
            self.assertEqual(len(data["rules"]), before + 1)


if __name__ == "__main__":
    unittest.main()
