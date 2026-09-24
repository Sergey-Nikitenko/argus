"""Cross-session process-lineage graph — the relational half of detection memory.

Where the vector memory remembers *what behavior looked like*, the graph remembers
*who spawned whom* — "Process A spawned Process B" — accumulated across sessions.
That powers two things:

* **Novel-edge detection**: a parent->child relationship that has never been seen
  before is a deviation from the learned baseline.
* **Chain reconstruction**: trace ancestry/descendants across time.

Stdlib-only: an in-memory dict persisted to JSONL. Nodes are image basenames
(case-folded) so path/timestamp churn doesn't fragment the graph; host and user
are recorded per edge for entity attribution.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath


def _base(image: str) -> str:
    return PureWindowsPath(image or "").name.lower()


@dataclass
class Edge:
    parent: str
    child: str
    count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    hosts: set = field(default_factory=set)
    users: set = field(default_factory=set)
    kind: str = "spawn"   # "spawn" (parent->child image) or "endpoint" (process->ip:port)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "parent": self.parent, "child": self.child, "count": self.count,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "hosts": sorted(self.hosts), "users": sorted(self.users),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Edge":
        return cls(
            parent=d["parent"], child=d["child"], count=d.get("count", 0),
            first_seen=d.get("first_seen", ""), last_seen=d.get("last_seen", ""),
            hosts=set(d.get("hosts", [])), users=set(d.get("users", [])),
            kind=d.get("kind", "spawn"),
        )


class ProcessGraph:
    def __init__(self, path: Path, max_edges: int = 20000):
        self.path = Path(path)
        self.max_edges = max_edges
        self.edges: dict[tuple[str, str], Edge] = {}          # spawn edges
        self.endpoints: dict[tuple[str, str], Edge] = {}      # process -> ip:port
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        except OSError:
            return
        for line in lines:
            if not line.strip():
                continue
            try:
                e = Edge.from_dict(json.loads(line))
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
            if e.kind == "endpoint":
                self.endpoints[(e.parent, e.child)] = e
            else:
                self.edges[(e.parent, e.child)] = e

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            for e in self.edges.values():
                fh.write(json.dumps(e.to_dict(), default=str) + "\n")
            for e in self.endpoints.values():
                fh.write(json.dumps(e.to_dict(), default=str) + "\n")

    def record(self, parent_image: str, child_image: str, host: str = "",
               user: str = "", timestamp: str = "") -> None:
        """Record one parent->child spawn (full image paths; basename-folded)."""
        parent = _base(parent_image)
        child = _base(child_image)
        if not parent or not child:
            return
        key = (parent, child)
        e = self.edges.get(key)
        if e is None:
            e = Edge(parent=parent, child=child, first_seen=timestamp, last_seen=timestamp)
            self.edges[key] = e
        else:
            e.last_seen = timestamp
        e.count += 1
        if host:
            e.hosts.add(host)
        if user:
            e.users.add(user)
        if len(self.edges) > self.max_edges:
            oldest = sorted(self.edges.values(), key=lambda x: x.last_seen or "")[
                : len(self.edges) - self.max_edges
            ]
            for e in oldest:
                self.edges.pop((e.parent, e.child), None)

    def novel(self, parent_image: str, child_image: str) -> bool:
        """True when this parent->child edge has never been observed."""
        return (_base(parent_image), _base(child_image)) not in self.edges

    def children(self, image: str) -> list[Edge]:
        """Every distinct child ``image`` has ever spawned."""
        base = _base(image)
        return sorted((e for (p, _c), e in self.edges.items() if p == base),
                      key=lambda e: -e.count)

    def parents(self, image: str) -> list[Edge]:
        """Every distinct process that has ever spawned ``image``."""
        base = _base(image)
        return sorted((e for (_p, c), e in self.edges.items() if c == base),
                      key=lambda e: -e.count)

    def record_endpoint(self, image: str, endpoint: str, host: str = "",
                        user: str = "", timestamp: str = "") -> None:
        """Record a process -> network-endpoint (ip:port) connection."""
        base = _base(image)
        if not base or not endpoint:
            return
        key = (base, endpoint)
        e = self.endpoints.get(key)
        if e is None:
            e = Edge(parent=base, child=endpoint, kind="endpoint",
                     first_seen=timestamp, last_seen=timestamp)
            self.endpoints[key] = e
        else:
            e.last_seen = timestamp
        e.count += 1
        if host:
            e.hosts.add(host)
        if user:
            e.users.add(user)

    def novel_endpoint(self, image: str, endpoint: str) -> bool:
        """True when this process has never contacted this endpoint."""
        return (_base(image), endpoint) not in self.endpoints

    def connections(self, image: str) -> list[Edge]:
        """Every endpoint ``image`` has ever contacted."""
        base = _base(image)
        return sorted((e for (i, _ep), e in self.endpoints.items() if i == base),
                      key=lambda e: -e.count)

    def blast_radius(self, image: str) -> dict:
        """Hosts, users, and edge counts for every node touching ``image``."""
        base = _base(image)
        hosts: set = set()
        users: set = set()
        spawns = 0
        for (p, c), e in self.edges.items():
            if p == base or c == base:
                hosts |= e.hosts
                users |= e.users
                spawns += 1
        endpoints = 0
        for (i, _ep), e in self.endpoints.items():
            if i == base:
                hosts |= e.hosts
                users |= e.users
                endpoints += 1
        return {"hosts": sorted(hosts), "users": sorted(users),
                "spawn_edges": spawns, "endpoint_edges": endpoints}

    def seen(self, image: str) -> bool:
        """True when ``image`` has ever appeared in the spawn graph (parent or child)."""
        base = _base(image)
        return any(p == base or c == base for (p, c) in self.edges)

    def campaign(self, image: str, max_depth: int = 5) -> dict:
        """Reconstruct a multi-stage chain: image -> descendants -> endpoints.

        Correlates the slow-and-low pattern — a process that spawned a child which
        later opened an outbound connection — into one story, even across sessions."""
        base = _base(image)
        seen_nodes = {base}
        spawn_edges = []
        frontier = [base]
        for _ in range(max_depth):
            nxt = []
            for node in frontier:
                for (p, c), e in self.edges.items():
                    if p == node and c not in seen_nodes:
                        seen_nodes.add(c)
                        nxt.append(c)
                        spawn_edges.append({"parent": p, "child": c, "count": e.count,
                                            "first_seen": e.first_seen, "last_seen": e.last_seen})
            frontier = nxt
            if not frontier:
                break
        endpoints = []
        for node in seen_nodes:
            for (i, ep), e in self.endpoints.items():
                if i == node:
                    endpoints.append({"process": i, "endpoint": ep, "count": e.count,
                                      "first_seen": e.first_seen, "last_seen": e.last_seen})
        return {"root": base, "processes": sorted(seen_nodes),
                "spawn_edges": spawn_edges, "endpoints": endpoints}

    def stats(self) -> dict:
        return {"edges": len(self.edges), "endpoints": len(self.endpoints)}
