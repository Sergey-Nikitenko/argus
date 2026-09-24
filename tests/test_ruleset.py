import tempfile
import unittest
from pathlib import Path

from argus.ruleset import RuleEngine, compile_rules, dump_rules, load_rules
from argus.score import default_rule_dicts


class TestRuleStore(unittest.TestCase):
    def test_default_rules_cover_categories(self):
        raw = default_rule_dicts()
        self.assertGreater(len(raw), 20)
        gates = {r.get("gate") for r in raw}
        binaries = {r.get("binary") for r in raw if r.get("binary")}
        self.assertIn("shell_lolbin", gates)
        self.assertIn("shell_script", gates)
        self.assertIn("vssadmin.exe", binaries)
        self.assertIn("procdump.exe", binaries)

    def test_roundtrip_dump_load(self):
        raw = default_rule_dicts()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "rules.json"
            dump_rules(raw, p)
            loaded = load_rules(p)
            self.assertEqual(len(loaded), len(raw))
            self.assertTrue(all(r["rx"] for r in loaded))  # compiled to a regex

    def test_rule_engine_hot_reload(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "rules.json"
            dump_rules(default_rule_dicts(), p)
            eng = RuleEngine(p)
            n0 = len(eng.rules)
            self.assertGreater(n0, 0)
            raw = default_rule_dicts() + [{"id": "x", "pattern": "ZZZZ", "points": 1,
                                           "reason": "x", "technique": "T1000",
                                           "technique_name": "X", "binary": "", "gate": ""}]
            dump_rules(raw, p)
            self.assertTrue(eng.reload_if_changed(force=True))
            self.assertEqual(len(eng.rules), n0 + 1)

    def test_malformed_rule_is_skipped(self):
        self.assertEqual(compile_rules([{"id": "bad", "pattern": "(", "points": 1}]), [])


if __name__ == "__main__":
    unittest.main()
