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
"""
from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime

from argus.adjudicate import adjudicate
from argus.config import Config, from_env
from argus.engine import process_event
from argus.events import read_security_events, read_sysmon_events
from argus.quarantine import kill_process_tree, quarantine_file
from argus.server import serve
from argus.store import append_jsonl, read_jsonl
from argus.verdict import lookup_sha256
from argus.watcher import detect_watcher_pairs


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


def run_once(cfg: Config):
    events = collect_events(cfg)
    print(f"[argus] read {len(events)} process-creation events (dry-run={cfg.dry_run})")

    def do_quarantine(path, qdir, reason=""):
        return quarantine_file(path, qdir, reason, cfg.manifest_path)

    verdict_fn = (lambda h: lookup_sha256(h, cfg.vt_api_key)) if cfg.vt_api_key else None
    adjudicate_fn = adjudicate if cfg.llm_enabled else None

    # Dedup: the watcher re-reads a sliding window of recent events every poll, so the SAME
    # event would otherwise be re-flagged each cycle. Track already-detected (timestamp, pid,
    # image) keys and skip re-appends.
    seen = {(str(d.get("timestamp")), str(d.get("pid")), str(d.get("image")))
            for d in read_jsonl(cfg.detections_path, 10000)}

    reports = [
        process_event(ev, cfg, quarantine_fn=do_quarantine, kill_fn=kill_process_tree,
                      verdict_fn=verdict_fn, adjudicate_fn=adjudicate_fn)
        for ev in events
    ]

    for rep in reports:
        if rep.decision != "allow":
            key = (rep.event.timestamp, str(rep.event.pid), rep.event.image)
            if key in seen:
                continue
            seen.add(key)
            print(rep.to_json())
            append_jsonl(cfg.detections_path, rep.to_dict())

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


def run_watch(cfg: Config, interval: int):
    print(f"[argus] watching (interval={interval}s, dry-run={cfg.dry_run})")
    while True:
        run_once(cfg)
        time.sleep(interval)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="argus", description="Windows process-creation watchdog")
    parser.add_argument("--once", action="store_true", help="single pass, then exit")
    parser.add_argument("--watch", action="store_true", help="poll continuously")
    parser.add_argument("--serve", action="store_true", help="run the command-center dashboard")
    parser.add_argument("--interval", type=int, default=60, help="poll interval seconds (--watch)")
    parser.add_argument("--port", type=int, default=None, help="dashboard port (--serve)")
    parser.add_argument("--act", action="store_true", help="actually quarantine/kill (default is dry-run)")
    parser.add_argument("--flag-threshold", type=int, default=None)
    parser.add_argument("--kill-threshold", type=int, default=None)
    parser.add_argument("--vt-api-key", default="")
    parser.add_argument("--no-llm", action="store_true", help="disable the local-model adjudication")
    parser.add_argument("--llm-model", default=None, help="override the adjudication model name")
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
    if args.port is not None:
        cfg.port = args.port

    if args.serve:
        serve(cfg)
    elif args.watch:
        run_watch(cfg, args.interval)
    else:
        run_once(cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
