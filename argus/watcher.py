"""Dual-process watchdog ("watcher-pair") detection.

Two cheap, deterministic signatures over recent process-creation events:

1. **Respawn storm** — the same image is spawned more than ``spawn_limit`` times
   inside ``window_seconds`` (a killed process being re-created by a watcher).
2. **Mutual spawn** — process A spawned B *and* B spawned A (each watching the
   other).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from .events import ProcessEvent


def _parse_ts(ts: str):
    if not ts:
        return None
    t = ts.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(t)
    except ValueError:
        try:
            return datetime.strptime(t, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            return None


@dataclass
class WatcherFinding:
    image: str
    count: int
    reason: str


# Read-only system utilities that legitimately spawn often (event-log readers,
# process listers, the console host) and are never the attack payload — excluded
# from respawn-storm detection so the watcher doesn't flag its own plumbing.
WATCHER_IGNORE = {
    "wevtutil.exe",
    "conhost.exe",
    "tasklist.exe",
}


def _basename(image: str) -> str:
    return image.replace("/", "\\").rsplit("\\", 1)[-1]


def detect_watcher_pairs(
    events: list[ProcessEvent],
    window_seconds: int = 60,
    spawn_limit: int = 3,
) -> list[WatcherFinding]:
    findings: list[WatcherFinding] = []

    # (a) respawn storm
    by_image = defaultdict(list)
    for e in events:
        ts = _parse_ts(e.timestamp)
        if ts is not None and e.image:
            by_image[e.image.lower()].append(ts)

    for image, times in by_image.items():
        if _basename(image) in WATCHER_IGNORE:
            continue
        times = sorted(times)
        for i in range(len(times)):
            window = times[i] + timedelta(seconds=window_seconds)
            count = 0
            for j in range(i, len(times)):
                if times[j] <= window:
                    count += 1
                else:
                    break
            if count > spawn_limit:
                findings.append(WatcherFinding(image=image, count=count, reason="respawn storm"))
                break  # report each image once

    # (b) mutual parent<->child spawn
    edges = set()
    for e in events:
        if e.image and e.parent_image:
            edges.add((e.parent_image.lower(), e.image.lower()))
    mutual = {a for (a, b) in edges if (b, a) in edges and a != b}
    for image in sorted(mutual):
        findings.append(WatcherFinding(image=image, count=0, reason="mutual parent<->child spawn"))

    return findings
