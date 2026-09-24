"""Argus CLI.

Examples
--------
Dry-run one pass over the last 500 process-creation events::

    py run.py --once

Act for real (quarantine + kill high scorers)::

    py run.py --once --act

Poll continuously (with VirusTotal lookups)::

    py run.py --watch --interval 60 --act --vt-api-key YOUR_KEY

Serve the command-center dashboard::

    py run.py --serve --port 8899

Running with **no mode flag** (e.g. double-clicking ``Argus.exe``) opens the
command-center dashboard and keeps running, so the console window stays open.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from argus.adjudicate import adjudicate
from argus.agent import adjudicate_agent
from argus.async_judge import AsyncAdjudicator
from argus.config import Config, from_env
from argus.engine import decide, is_quarantinable, process_event, severity
from argus.events import ProcessEvent, read_security_events, read_sysmon_events, read_sysmon_network_events
from argus.forensics import dump_process_memory
from argus.graph import ProcessGraph
from argus.memory import MemoryRecord, MemoryStore
from argus.quarantine import kill_process_tree, quarantine_file
from argus.rulegen import sigma_rule_from_detection
from argus.rules import propose_rule
from argus.ruleset import RuleEngine, dump_rules
from argus.score import default_rule_dicts, score_event, score_network_event, set_active_rules
from argus.server import serve
from argus.signature import BehaviorSignature, signature_id
from argus.store import append_jsonl, read_jsonl
from argus import sysmon
from argus.tools import make_tools
from argus.verdict import lookup_sha256
from argus.watcher import detect_watcher_pairs


_rule_engine = None   # dynamic detection-rule store (hot-reloaded per poll)


def collect_events(cfg: Config):
    events = []
    try:
        events.extend(read_security_events(cfg.max_events_per_poll))
    except Exception as exc:  # noqa: BLE001
        print(f"[argus] security log read failed: {exc}", file=sys.stderr)
    try:
        events.extend(read_sysmon_events(cfg.max_events_per_poll))
    except Exception as exc:  # noqa: BLE001
        print(f"[argus] sysmon read failed: {exc}", file=sys.stderr)
    return events


def maybe_propose_rule(cfg: Config, ev, score):
    """Draft a Sigma rule from a novel MALICIOUS pattern and queue it for review."""
    rule = sigma_rule_from_detection(ev, score)
    techniques = [t["id"] for t in score.techniques_deduped()]
    rid = propose_rule(cfg, rule, techniques)
    print(f"[argus] proposed sigma rule {rid}: {rule['title']}")


def make_finalizer(cfg: Config, memory):
    """Build the callback that applies an async adjudication verdict: finalize the
    decision, run containment if warranted, write the detection, and ingest memory."""
    def finalize(ev, score, verdict):
        final = decide(score, cfg)
        if verdict.get("verdict") != "MALICIOUS":
            final = "flag"
        if verdict.get("verdict") == "MALICIOUS":
            maybe_propose_rule(cfg, ev, score)
        actions = []
        if final == "quarantine" and not cfg.dry_run:
            if ev.image and is_quarantinable(ev.image):
                try:
                    dest = quarantine_file(ev.image, cfg.quarantine_dir, "; ".join(score.reasons), cfg.manifest_path)
                    actions.append(f"quarantined -> {dest}")
                except Exception as exc:  # noqa: BLE001
                    actions.append(f"quarantine failed: {exc}")
            if ev.pid:
                try:
                    dump = dump_process_memory(ev.pid, cfg.dump_dir, ev.image)
                    actions.append(f"memory dumped -> {dump}")
                except Exception as exc:  # noqa: BLE001
                    actions.append(f"memory dump failed: {exc}")
                try:
                    kill_process_tree(ev.pid)
                    actions.append(f"killed process tree {ev.pid}")
                except Exception as exc:  # noqa: BLE001
                    actions.append(f"kill failed: {exc}")
        sig = BehaviorSignature.from_event(ev, score, host=cfg.hostname)
        append_jsonl(cfg.detections_path, {
            "timestamp": ev.timestamp, "pid": ev.pid, "parent_pid": ev.parent_pid,
            "image": ev.image, "parent_image": ev.parent_image,
            "command_line": ev.command_line, "user": ev.user,
            "score": score.points, "severity": severity(score.points),
            "reasons": score.reasons, "techniques": score.techniques_deduped(),
            "decision": final, "actions": actions, "adjudication": verdict,
            "memory_id": signature_id(sig),
        })
        if memory is not None:
            v = verdict.get("verdict", "UNCERTAIN")
            memory.ingest(MemoryRecord(
                id=signature_id(sig), signature=sig, verdict=v,
                outcome="model_only", confidence="medium" if v in ("MALICIOUS", "BENIGN") else "low",
                timestamp=ev.timestamp, ts=time.time(), score=score.points,
                image=ev.image, host=cfg.hostname, user=ev.user,
            ))
        print(f"[argus] async adjudication: {final} ({verdict.get('verdict')})")
    return finalize


def run_once(cfg: Config, memory=None, graph=None, adjudicator=None):
    global _rule_engine
    if _rule_engine is not None and _rule_engine.reload_if_changed():
        set_active_rules(_rule_engine.rules)
        print(f"[argus] hot-reloaded {len(_rule_engine.rules)} detection rules")
    events = collect_events(cfg)
    print(f"[argus] read {len(events)} process-creation events (dry-run={cfg.dry_run})")

    def do_quarantine(path, qdir, reason=""):
        return quarantine_file(path, qdir, reason, cfg.manifest_path)

    def do_dump(pid, image=""):
        return dump_process_memory(pid, cfg.dump_dir, image)

    verdict_fn = (lambda h: lookup_sha256(h, cfg.vt_api_key)) if cfg.vt_api_key else None
    tools = make_tools(graph=graph, vt_api_key=cfg.vt_api_key) if cfg.agentic else []
    adjudicate_fn = None
    if cfg.llm_enabled and adjudicator is None:
        if cfg.agentic:
            adjudicate_fn = (lambda ev, score, history=None: adjudicate_agent(
                ev, score, history=history, tools=tools, model=cfg.llm_model, url=cfg.llm_url))
        else:
            adjudicate_fn = (lambda ev, score, history=None: adjudicate(
                ev, score, history=history, model=cfg.llm_model, url=cfg.llm_url,
                api_key=cfg.llm_api_key))

    # Dedup BEFORE scoring/adjudication: the watcher re-reads a sliding window of recent
    # events every poll, so an already-seen (timestamp, pid, image) key must be skipped
    # entirely. Otherwise a would-be-kill event is re-adjudicated on every cycle — each call
    # blocks on the local model for minutes, wedging the whole watch loop.
    seen = {(str(d.get("timestamp")), str(d.get("pid")), str(d.get("image")))
            for d in read_jsonl(cfg.detections_path, 10000)}
    # also skip events already recorded in the session log, so the append-only watch
    # log doesn't re-log the same event every poll
    seen |= {(str(d.get("ts")), str(d.get("pid")), str(d.get("image")))
             for d in read_jsonl(cfg.session_log_path, 10000)}

    reports = []
    for ev in events:
        key = (ev.timestamp, str(ev.pid), ev.image)
        if key in seen:
            continue
        rep = process_event(ev, cfg, quarantine_fn=do_quarantine, kill_fn=kill_process_tree,
                            verdict_fn=verdict_fn, adjudicate_fn=adjudicate_fn, memory=memory,
                            graph=graph, dump_fn=do_dump)
        reports.append(rep)
        seen.add(key)
        # Session log: append-only record of everything the watch sees (allow too).
        append_jsonl(cfg.session_log_path, {
            "ts": ev.timestamp,
            "time": datetime.now().isoformat(timespec="seconds"),
            "pid": ev.pid,
            "image": ev.image,
            "parent_image": ev.parent_image,
            "command_line": ev.command_line,
            "user": ev.user,
            "score": rep.score.points,
            "severity": rep.severity,
            "decision": rep.decision,
        })
        if rep.decision != "allow":
            print(rep.to_json())
            append_jsonl(cfg.detections_path, rep.to_dict())
        if rep.decision == "quarantine" or rep.adjudication.get("verdict") == "MALICIOUS":
            maybe_propose_rule(cfg, ev, rep.score)
        # Decoupled adjudication: hand would-be-kill events to the background pool
        # so the watch loop never blocks on the local model.
        if adjudicator is not None and rep.decision in ("propose", "quarantine"):
            sig = BehaviorSignature.from_event(ev, rep.score, host=cfg.hostname)
            history = memory.query(sig, k=cfg.memory_k) if memory is not None else []
            adjudicator.submit(ev, rep.score, history)

    flagged = sum(1 for r in reports if r.decision == "flag")
    quarantined = sum(1 for r in reports if r.decision == "quarantine")
    print(f"[argus] flagged {flagged}, quarantine {quarantined}")

    findings = detect_watcher_pairs(events, cfg.watcher_window_seconds, cfg.watcher_spawn_limit)
    for f in findings:
        print(f"[argus] watcher-pair: {f.image} ({f.reason}, count={f.count})")
        append_jsonl(cfg.watcher_path, {
            "time": datetime.now().isoformat(timespec="seconds"),
            "image": f.image,
            "count": f.count,
            "reason": f.reason,
        })

    # Network layer (Sysmon Event ID 3): record process -> endpoint edges AND score
    # beacon-like connections (script host -> novel public endpoint) so the quiet C2
    # callback isn't invisible just because it isn't a process-creation event.
    if graph is not None:
        try:
            for nev in read_sysmon_network_events(cfg.max_events_per_poll):
                nscore = score_network_event(nev, graph)
                graph.record_endpoint(nev.image, nev.endpoint(), host=cfg.hostname,
                                      user=nev.user, timestamp=nev.timestamp)
                if nscore.points > 0:
                    decision = decide(nscore, cfg)
                    append_jsonl(cfg.detections_path, {
                        "timestamp": nev.timestamp, "pid": nev.pid, "parent_pid": 0,
                        "image": nev.image, "parent_image": "",
                        "command_line": f"network {nev.protocol} to {nev.endpoint()}",
                        "user": nev.user, "score": nscore.points,
                        "severity": severity(nscore.points),
                        "reasons": nscore.reasons,
                        "techniques": nscore.techniques_deduped(),
                        "decision": decision, "sha256": "", "virus_total": "",
                        "actions": [], "adjudication": {}, "memory_id": "",
                    })
                    print(f"[argus] beacon: {nev.image} -> {nev.endpoint()} (score {nscore.points}, {decision})")
        except Exception as exc:  # noqa: BLE001
            print(f"[argus] network log read failed: {exc}", file=sys.stderr)

    if memory is not None:
        memory.save()
    if graph is not None:
        graph.save()


def run_watch(cfg: Config, interval: int, memory=None, graph=None):
    adjudicator = None
    if cfg.llm_enabled:
        tools = make_tools(graph=graph, vt_api_key=cfg.vt_api_key) if cfg.agentic else []

        def adjudicate_fn(ev, score, history=None):
            if cfg.agentic:
                return adjudicate_agent(ev, score, history=history, tools=tools,
                                        model=cfg.llm_model, url=cfg.llm_url)
            return adjudicate(ev, score, history=history, model=cfg.llm_model, url=cfg.llm_url,
                              api_key=cfg.llm_api_key)

        adjudicator = AsyncAdjudicator(adjudicate_fn, make_finalizer(cfg, memory), workers=2)
        adjudicator.start()
    print(f"[argus] watching (interval={interval}s, dry-run={cfg.dry_run}, async_llm={adjudicator is not None}, agentic={cfg.agentic})")
    while True:
        run_once(cfg, memory, graph, adjudicator)
        time.sleep(interval)


def run_replay(cfg: Config, path: str) -> None:
    """Replay a JSONL bank of ProcessEvent records (synthetic / OTRF / BOTS) through
    the scoring pipeline and report coverage — safe testing without executing anything."""
    p = Path(path)
    if not p.exists():
        print(f"[replay] file not found: {p}", file=sys.stderr)
        return
    total = caught = 0
    by_decision = {}
    label_stats = {}
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        ev = ProcessEvent(
            source=d.get("source", "replay"), event_id=int(d.get("event_id", 1)),
            timestamp=d.get("timestamp", ""), pid=int(d.get("pid", 0)),
            parent_pid=int(d.get("parent_pid", 0)), image=d.get("image", ""),
            command_line=d.get("command_line", ""), user=d.get("user", ""),
            hashes=d.get("hashes", ""), integrity=d.get("integrity", ""),
            parent_image=d.get("parent_image", ""),
        )
        score = score_event(ev)
        decision = decide(score, cfg)
        total += 1
        if decision != "allow":
            caught += 1
        by_decision[decision] = by_decision.get(decision, 0) + 1
        label = d.get("label", "")
        if label:
            bucket = "caught" if decision != "allow" else "missed"
            label_stats.setdefault(label, {"caught": 0, "missed": 0})[bucket] += 1
        if label == "malicious" and decision == "allow":
            from argus.review import append_review
            append_review(cfg, ev, score.points, decision, label)
    print(f"[replay] {total} events, {caught} flagged: {by_decision}")
    for label, c in sorted(label_stats.items()):
        print(f"[replay]   {label}: caught={c['caught']} missed={c['missed']}")


def run_sandbox_cli(cfg: Config, args) -> int:
    """The CAPE/Cuckoo-style detonation branch: 5-stage pipeline on one sample.

    Default is a DRY-RUN re-analysis (stages 1-4 skipped; the dumped Sysmon XML in
    the telemetry dir is scored + dissected). ``--sandbox-live`` actually detonates
    on the KVM/libvirt hypervisor — that path needs libvirt on the host and the
    injection seam wired (see argus/sandbox/orchestrator.inject_sample)."""
    import json
    from argus.sandbox import (
        ArgusSandboxManager, FakeBackend, LibvirtBackend, SandboxConfig, run_pipeline,
    )
    sc = SandboxConfig()
    if args.sandbox_config:
        # utf-8-sig tolerates a PowerShell/editor-written BOM, which otherwise makes
        # json.loads raise "Unexpected UTF-8 BOM" on an otherwise-fine config file.
        overrides = json.loads(Path(args.sandbox_config).read_text(encoding="utf-8-sig"))
        for k, v in overrides.items():
            if hasattr(sc, k):
                setattr(sc, k, v)
        sc.normalize()   # JSON paths arrive as str; re-coerce to Path
    if not args.sandbox_sample:
        print("[sandbox] --sandbox-sample is required with --sandbox", file=sys.stderr)
        return 2
    if getattr(args, "sandbox_host", "local") == "wsl":
        # Windows console -> WSL2 Ubuntu hypervisor host (libvirt lives there).
        from argus.sandbox.wsl import delegate, prepare_config_for_wsl
        repo_dir = str(Path(__file__).resolve().parent)
        config_path = None
        if args.sandbox_config:
            config_path = prepare_config_for_wsl(args.sandbox_config)
        return delegate(repo_dir, args.sandbox_sample, config=config_path,
                        live=bool(args.sandbox_live), no_llm=not cfg.llm_enabled)
    backend = FakeBackend() if not args.sandbox_live else LibvirtBackend(sc.hypervisor_uri)
    manager = ArgusSandboxManager(sc, backend=backend)
    try:
        rep = run_pipeline(cfg, sc, manager, args.sandbox_sample, dry_run=not args.sandbox_live)
    finally:
        try:
            backend.close()
        except Exception:  # noqa: BLE001
            pass
    print(json.dumps(rep.to_dict(), indent=2, default=str))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="argus", description="Windows process-creation watchdog")
    parser.add_argument("--once", action="store_true", help="single pass, then exit")
    parser.add_argument("--watch", action="store_true", help="poll continuously")
    parser.add_argument("--serve", action="store_true", help="run the command-center dashboard")
    parser.add_argument("--replay", default=None, metavar="JSONL", help="replay a JSONL bank of ProcessEvent records (synthetic/OTRF/BOTS)")
    parser.add_argument("--interval", type=int, default=60, help="poll interval seconds (--watch)")
    parser.add_argument("--fast", action="store_true", help="near-real-time watch: 2s poll, smaller window")
    parser.add_argument("--port", type=int, default=None, help="dashboard port (--serve)")
    parser.add_argument("--act", action="store_true", help="actually quarantine/kill (default is dry-run)")
    parser.add_argument("--flag-threshold", type=int, default=None)
    parser.add_argument("--kill-threshold", type=int, default=None)
    parser.add_argument("--vt-api-key", default="")
    parser.add_argument("--no-llm", action="store_true", help="disable the local-model adjudication")
    parser.add_argument("--llm-model", default=None, help="override the adjudication model name")
    parser.add_argument("--agent", action="store_true", help="give the model investigation tools (function calling)")
    parser.add_argument("--sysmon-status", action="store_true", help="check Sysmon install/events and exit")
    parser.add_argument("--sysmon-config", nargs="?", const="sysmon-config.xml", default=None,
                        help="write the bundled Sysmon config to PATH (default sysmon-config.xml) and exit")
    parser.add_argument("--sysmon-config-path", default="sysmon-config.xml",
                        help="config file used by --install-sysmon / --update-sysmon-config")
    parser.add_argument("--install-sysmon", default=None, metavar="SYSMON64.EXE",
                        help="install Sysmon from this exe with the Argus config (needs admin)")
    parser.add_argument("--update-sysmon-config", default=None, metavar="SYSMON64.EXE",
                        help="reload the Argus config into an existing Sysmon install (needs admin)")
    parser.add_argument("--uninstall-sysmon", default=None, metavar="SYSMON64.EXE",
                        help="uninstall Sysmon (needs admin)")
    parser.add_argument("--sandbox", action="store_true",
                        help="run the dynamic-malware-sandbox pipeline on a sample")
    parser.add_argument("--sandbox-sample", default=None, metavar="PATH",
                        help="sample to detonate/analyze (required with --sandbox)")
    parser.add_argument("--sandbox-config", default=None, metavar="JSON",
                        help="sandbox config overrides (JSON file)")
    parser.add_argument("--sandbox-live", action="store_true",
                        help="actually detonate on the KVM/libvirt hypervisor (default: "
                             "dry-run re-analysis of the dumped telemetry dir)")
    parser.add_argument("--sandbox-host", choices=("local", "wsl"), default="local",
                        help="where the hypervisor lives: 'local' (in-process libvirt) or "
                             "'wsl' (delegate to WSL2 Ubuntu via wsl.exe)")
    args = parser.parse_args(argv)

    cfg = from_env()
    if args.flag_threshold is not None:
        cfg.flag_threshold = args.flag_threshold
    if args.kill_threshold is not None:
        cfg.kill_threshold = args.kill_threshold
    if args.vt_api_key:
        cfg.vt_api_key = args.vt_api_key
    if args.act:
        cfg.dry_run = False
    if args.no_llm:
        cfg.llm_enabled = False
    if args.llm_model:
        cfg.llm_model = args.llm_model
    if args.agent:
        cfg.agentic = True
    if args.port is not None:
        cfg.port = args.port

    # Sysmon maintenance — install/update/uninstall load a kernel driver and
    # therefore need an elevated shell; the status/config paths are read-only.
    if args.sysmon_status:
        print(sysmon.format_status(sysmon.status()))
        return 0
    if args.sysmon_config is not None:
        path = sysmon.write_config(args.sysmon_config)
        print(f"[argus] wrote sysmon config -> {path}")
        return 0
    if args.uninstall_sysmon:
        rc = sysmon.uninstall(args.uninstall_sysmon)
        print(f"[argus] sysmon uninstall exit={rc}")
        return rc
    if args.install_sysmon or args.update_sysmon_config:
        config_path = Path(args.sysmon_config_path)
        if not config_path.exists():
            sysmon.write_config(config_path)
            print(f"[argus] wrote sysmon config -> {config_path}")
        if args.install_sysmon:
            rc = sysmon.install(args.install_sysmon, config_path)
            label = "install"
        else:
            rc = sysmon.update_config(args.update_sysmon_config, config_path)
            label = "update-config"
        print(f"[argus] sysmon {label} exit={rc}")
        return rc

    # Seed + load the dynamic detection-rule store (hot-reloadable JSON).
    global _rule_engine
    try:
        if not cfg.detection_rules_path.exists():
            dump_rules(default_rule_dicts(), cfg.detection_rules_path)
        _rule_engine = RuleEngine(cfg.detection_rules_path)
        set_active_rules(_rule_engine.rules)
    except Exception as exc:  # noqa: BLE001
        print(f"[argus] rule store init failed: {exc}", file=sys.stderr)

    memory = MemoryStore(cfg.memory_path) if cfg.memory_enabled else None
    graph = ProcessGraph(cfg.graph_path) if cfg.graph_enabled else None

    # Seed semantic memory with abstracted behavioral profiles (baseline for
    # similarity recall). Idempotent — never clobbers an analyst's later verdict.
    if memory is not None:
        try:
            from argus.seed import default_seeds, seed_memory
            if seed_memory(memory, default_seeds()):
                memory.save()
        except Exception as exc:  # noqa: BLE001
            print(f"[argus] memory seed failed: {exc}", file=sys.stderr)

    # The command center runs the detection loop in a background thread so the
    # dashboard's Watch/Act selector controls a live, single-process watcher.
    def background_watch():
        try:
            run_watch(cfg, 5, memory, graph)
        except Exception as exc:  # noqa: BLE001
            print(f"[argus] background watch stopped: {exc}", file=sys.stderr)

    if args.sandbox:
        return run_sandbox_cli(cfg, args)
    elif args.replay:
        run_replay(cfg, args.replay)
    elif args.serve:
        serve(cfg, memory, graph, watch_runner=background_watch)
    elif args.watch:
        interval = args.interval
        if args.fast:
            interval = 2
            cfg.max_events_per_poll = 100
        run_watch(cfg, interval, memory, graph)
    elif args.once:
        run_once(cfg, memory, graph)
    else:
        # No mode flag given (e.g. double-clicked the .exe): open the command
        # center + watcher and stay alive so the window doesn't just flicker and vanish.
        print("[argus] no mode flag given - starting the command center + watch (Ctrl+C to stop)")
        try:
            serve(cfg, memory, graph, watch_runner=background_watch)
        except Exception as exc:  # noqa: BLE001 — keep the window open on failure
            print(f"[argus] failed to start: {exc}", file=sys.stderr)
            try:
                input("Press Enter to close...")
            except EOFError:
                pass
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
