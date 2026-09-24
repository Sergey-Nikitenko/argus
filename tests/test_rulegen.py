import unittest

from argus.events import ProcessEvent
from argus.rulegen import draft_rule_with_model, sigma_rule_from_detection, to_yaml
from argus.score import score_event


def ev(image="", command_line=""):
    return ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=1, parent_pid=0,
                        image=image, command_line=command_line)


class TestRuleGen(unittest.TestCase):
    def test_sigma_rule_shape(self):
        e = ev(image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
               command_line="powershell -enc ZA==")
        r = sigma_rule_from_detection(e, score_event(e))
        self.assertIn("title", r)
        self.assertEqual(r["logsource"]["category"], "process_creation")
        self.assertIn("selection", r["detection"])
        self.assertTrue(any("t1059_001" in t for t in r["tags"]))

    def test_to_yaml_has_key_fields(self):
        e = ev(image=r"C:\Temp\evil.exe", command_line="evil.exe -enc X")
        y = to_yaml(sigma_rule_from_detection(e, score_event(e)))
        self.assertIn("title:", y)
        self.assertIn("logsource:", y)
        self.assertIn("detection:", y)

    def test_draft_rule_falls_back_on_bad_reply(self):
        def post_fn(u, p, t):
            raise RuntimeError("no model")

        e = ev(image=r"C:\Temp\evil.exe", command_line="evil.exe -enc X")
        r = draft_rule_with_model(e, score_event(e), "m", "http://x", post_fn=post_fn)
        self.assertIn("detection", r)


if __name__ == "__main__":
    unittest.main()
