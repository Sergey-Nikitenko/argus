"""Process-tree / attack-chain helpers.

Given a batch of process-creation events, build parent→child relationships and
trace an ancestry chain (the "storyline" view premium EDR consoles show).
"""
from __future__ import annotations

from collections import defaultdict

from .events import ProcessEvent


def build_tree(events: list[ProcessEvent]) -> dict[int, list[ProcessEvent]]:
    """parent_pid -> list of child events (children in event order)."""
    tree: dict[int, list[ProcessEvent]] = defaultdict(list)
    for e in events:
        tree[e.parent_pid].append(e)
    return dict(tree)


def ancestry(events: list[ProcessEvent], pid: int) -> list[ProcessEvent]:
    """Walk pid -> parent_pid up to the root. Oldest ancestor first."""
    by_pid = {e.pid: e for e in events}
    chain = []
    seen = set()
    cur = pid
    while cur in by_pid and cur not in seen and cur != 0:
        seen.add(cur)
        e = by_pid[cur]
        chain.append(e)
        cur = e.parent_pid
    return list(reversed(chain))


def descendants(events: list[ProcessEvent], pid: int) -> list[ProcessEvent]:
    """All events whose ancestry passes through pid (transitive children)."""
    tree = build_tree(events)
    out = []
    stack = list(tree.get(pid, []))
    while stack:
        e = stack.pop()
        out.append(e)
        stack.extend(tree.get(e.pid, []))
    return out
