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

    def test_hard_evidence_kills_immediately_without_llm(self):
        # score >= HARD_EVIDENCE must kill now and never block on the local model.
        cfg = Config(dry_run=False, flag_threshold=40, kill_threshold=70)
        calls = {"adjudicate": 0, "kill": 0}

        def adjudicate_fn(e, s):
            calls["adjudicate"] += 1
            return {"verdict": "BENIGN", "reason": "model says no"}

        ev = ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=42, parent_pid=0,
                          image=r"C:\Temp\evil.exe",
                          command_line="evil.exe -enc X -nop -w hidden -exec bypass")
        rep = process_event(ev, cfg, adjudicate_fn=adjudicate_fn,
                            kill_fn=lambda pid: calls.__setitem__("kill", calls["kill"] + 1))
        self.assertEqual(rep.decision, "quarantine")
        self.assertEqual(calls["adjudicate"], 0)   # LLM never consulted
        self.assertEqual(calls["kill"], 1)         # killed immediately
        self.assertTrue(rep.adjudication.get("skipped_llm"))

    def test_borderline_kill_still_asks_llm_and_downgrades(self):
        # score in [kill_threshold, HARD_EVIDENCE) still consults the model; a BENIGN
        # verdict downgrades to flag (fail-safe).
        cfg = Config(dry_run=False, flag_threshold=40, kill_threshold=70)
        calls = {"adjudicate": 0}

        def adjudicate_fn(e, s):
            calls["adjudicate"] += 1
            return {"verdict": "BENIGN", "reason": "model says no"}

        rep = process_event(suspicious_event(), cfg, adjudicate_fn=adjudicate_fn)  # score 80
        self.assertEqual(rep.decision, "flag")      # downgraded
        self.assertEqual(calls["adjudicate"], 1)    # model WAS consulted

    def test_act_kills_but_never_quarantines_trusted_binary(self):
        # A System32 LOLBin that scores >= kill_threshold must be killed, but its
        # executable must NOT be moved — quarantining python.exe/powershell.exe is a
        # self-inflicted wound, not a remediation. Regression guard.
        cfg = Config(dry_run=False, flag_threshold=40, kill_threshold=70)
        called = []
        rep = process_event(
            ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=42, parent_pid=0,
                         image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         command_line="powershell.exe -nop -w hidden -enc X"),
            cfg,
            quarantine_fn=lambda p, q, r="": called.append("q") or "dest",
            kill_fn=lambda pid: called.append("k"),
        )
        self.assertEqual(rep.decision, "quarantine")
        self.assertNotIn("q", called)                # never moved
        self.assertIn("k", called)                   # still killed
        self.assertTrue(any("skipped" in a for a in rep.actions))

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
