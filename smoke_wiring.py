"""End-to-end wiring smoke test: one event through the full pipeline.

Exercises score -> graph (novel edge) -> memory retrieval -> adjudication ->
response (dump before kill) -> rule proposal, plus graph campaign/blast-radius.
Uses a temp data dir and mocks, so no real processes or system logs are touched.
"""
import tempfile
import time
from pathlib import Path

from argus.config import Config
from argus.engine import process_event
from argus.events import ProcessEvent
from argus.graph import ProcessGraph
from argus.memory import MemoryStore
from argus.rules import approve_rule, list_rules, propose_rule
from argus.rulegen import sigma_rule_from_detection

with tempfile.TemporaryDirectory() as d:
    cfg = Config(data_dir=Path(d), dry_run=False)
    mem = MemoryStore(cfg.memory_path)
    graph = ProcessGraph(cfg.graph_path)

    order = []

    def adjudicate_fn(ev, score, history=None):
        return {"verdict": "MALICIOUS", "confidence": 0.9, "reason": "novel"}

    def dump_fn(pid, image=""):
        order.append("dump")
        return r"C:\dumps\x.dmp"

    def kill_fn(pid):
        order.append("kill")

    ev = ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=42, parent_pid=2,
                      image=r"C:\Temp\evil.exe", command_line="evil.exe -enc X -nop -w hidden",
                      parent_image=r"C:\Windows\explorer.exe")

    rep = process_event(ev, cfg, adjudicate_fn=adjudicate_fn, dump_fn=dump_fn,
                        kill_fn=kill_fn, memory=mem, graph=graph)

    # rule proposal
    rid = propose_rule(cfg, sigma_rule_from_detection(ev, rep.score), ["T1059.001"])
    approve_rule(cfg, rid)

    # graph correlation + blast radius
    graph.record_endpoint("evil.exe", "9.9.9.9:443", host="H", user="u")
    camp = graph.campaign("evil.exe")
    blast = graph.blast_radius("evil.exe")

    checks = {
        "decision == quarantine": rep.decision == "quarantine",
        "order dump-then-kill": order == ["dump", "kill"],
        "memory ingested (episodic=1)": mem.stats()["episodic"] == 1,
        "graph has spawn edge": graph.stats()["edges"] >= 1,
        "graph has endpoint edge": graph.stats()["endpoints"] == 1,
        "rule approved": list_rules(cfg)[0]["status"] == "approved",
        "campaign root correct": camp["root"] == "evil.exe",
        "campaign has endpoint": any(e["endpoint"] == "9.9.9.9:443" for e in camp["endpoints"]),
        "blast radius has host": "H" in blast["hosts"],
    }
    for name, ok in checks.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    assert all(checks.values()), "one or more wiring checks failed"
    print("\nSMOKE OK — full pipeline is wired end-to-end")
