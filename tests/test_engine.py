import unittest

from argus.config import Config
from argus.engine import decide, process_event
from argus.events import ProcessEvent
from argus.score import ScoreResult


def suspicious_event():
    return ProcessEvent(
        source="sysmon", event_id=1, timestamp="", pid=42, parent_pid=0,
        image=r"C:\Temp\evil.exe", command_line="evil.exe -enc X",
    )


class TestDecide(unittest.TestCase):
    def test_thresholds(self):
        cfg = Config(flag_threshold=40, kill_threshold=70)
        self.assertEqual(decide(ScoreResult(points=0), cfg), "allow")
        self.assertEqual(decide(ScoreResult(points=40), cfg), "flag")
        self.assertEqual(decide(ScoreResult(points=69), cfg), "flag")
        self.assertEqual(decide(ScoreResult(points=70), cfg), "quarantine")


class TestProcessEvent(unittest.TestCase):
    def test_dry_run_takes_no_action(self):
        cfg = Config(dry_run=True, flag_threshold=40, kill_threshold=70)
        called = []
        rep = process_event(
            suspicious_event(),
            cfg,
            quarantine_fn=lambda p, q, r="": called.append("q") or "dest",
            kill_fn=lambda pid: called.append("k"),
        )
        self.assertEqual(rep.decision, "quarantine")
        self.assertEqual(called, [])  # dry-run => no side effects

    def test_act_quarantines_and_kills(self):
        cfg = Config(dry_run=False, flag_threshold=40, kill_threshold=70)
        called = []
        rep = process_event(
            suspicious_event(),
            cfg,
            quarantine_fn=lambda p, q, r="": called.append("q") or "dest",
            kill_fn=lambda pid: called.append("k"),
        )
        self.assertEqual(rep.decision, "quarantine")
        self.assertIn("q", called)
        self.assertIn("k", called)

    def test_flag_takes_no_action_even_when_acting(self):
        cfg = Config(dry_run=False, flag_threshold=40, kill_threshold=70)
        called = []
        rep = process_event(
            ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=1, parent_pid=0,
                         image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         command_line="powershell.exe -nop -w hidden"),
            cfg,
            quarantine_fn=lambda p, q, r="": called.append("q"),
            kill_fn=lambda pid: called.append("k"),
        )
        self.assertEqual(rep.decision, "flag")
        self.assertEqual(called, [])

    def test_verdict_looked_up_when_sha_and_fn_present(self):
        cfg = Config(dry_run=True)
        rep = process_event(
            ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=1, parent_pid=0,
                         image=r"C:\x.exe", hashes="SHA256=" + "A" * 64),
            cfg,
            verdict_fn=lambda h: "5/70 malicious",
        )
        self.assertEqual(rep.vt, "5/70 malicious")

    def test_no_verdict_without_sha(self):
        cfg = Config(dry_run=True)
        rep = process_event(
            ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=1, parent_pid=0, image=r"C:\x.exe"),
            cfg,
            verdict_fn=lambda h: "5/70 malicious",
        )
        self.assertEqual(rep.vt, "")

    def test_report_json(self):
        cfg = Config(dry_run=True)
        rep = process_event(suspicious_event(), cfg)
        self.assertIn('"decision"', rep.to_json())

    def test_severity_tiers(self):
        cfg = Config(dry_run=True)
        self.assertEqual(process_event(suspicious_event(), cfg).severity, "critical")
        mid = ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=1, parent_pid=0,
                           image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                           command_line="powershell.exe -nop -w hidden")
        self.assertEqual(process_event(mid, cfg).severity, "medium")


if __name__ == "__main__":
    unittest.main()
