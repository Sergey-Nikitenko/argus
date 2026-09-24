"""Argus configuration."""
from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    """Runtime configuration. Safe defaults: dry-run until you pass --act."""

    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("ARGUS_DATA_DIR", r"C:\ProgramData\Argus")))
    flag_threshold: int = 40        # >= this score -> flag (log/alert)
    kill_threshold: int = 70        # >= this score -> propose containment (HITL)
    contain_threshold: int = 85     # >= this score -> auto quarantine + kill (no approval)
    watcher_window_seconds: int = 60
    watcher_spawn_limit: int = 3
    max_events_per_poll: int = 500
    dry_run: bool = True            # True = report only, no destructive action
    vt_api_key: str = ""
    webhook_url: str = ""
    llm_enabled: bool = True        # local model adjudicates every would-be kill
    llm_model: str = "google/gemma-4-e4b"
    llm_url: str = "http://localhost:1234/v1/chat/completions"
    llm_api_key: str = ""           # for hosted/cloud models (OpenAI-compatible), optional
    agentic: bool = False           # give the model investigation tools (function calling)
    memory_enabled: bool = True     # correlate alerts against historical patterns
    memory_k: int = 5               # top-k similar incidents injected into the model prompt
    graph_enabled: bool = True      # remember parent->child process lineage across sessions
    novel_edge_points: int = 10     # score added for a never-before-seen parent->child spawn
    novel_process_points: int = 5   # score added for a binary never seen on this host before
    hostname: str = field(default_factory=socket.gethostname)
    host: str = "127.0.0.1"
    port: int = 8899

    def __post_init__(self):
        self.data_dir = Path(self.data_dir)
        self.quarantine_dir = self.data_dir / "quarantine"
        self.dump_dir = self.data_dir / "dumps"
        self.manifest_path = self.data_dir / "manifest.jsonl"
        self.detections_path = self.data_dir / "detections.jsonl"
        self.watcher_path = self.data_dir / "watcher.jsonl"
        self.memory_path = self.data_dir / "memory.jsonl"
        self.graph_path = self.data_dir / "graph.jsonl"
        self.rules_path = self.data_dir / "rules.jsonl"
        self.sigma_dir = self.data_dir / "sigma_rules"
        self.session_log_path = self.data_dir / "session_log.jsonl"
        self.mode_path = self.data_dir / "mode.json"
        self.detection_rules_path = self.data_dir / "detection_rules.json"


def from_env() -> Config:
    cfg = Config()
    cfg.flag_threshold = int(os.environ.get("ARGUS_FLAG_THRESHOLD", cfg.flag_threshold))
    cfg.kill_threshold = int(os.environ.get("ARGUS_KILL_THRESHOLD", cfg.kill_threshold))
    cfg.watcher_window_seconds = int(os.environ.get("ARGUS_WATCHER_WINDOW", cfg.watcher_window_seconds))
    cfg.watcher_spawn_limit = int(os.environ.get("ARGUS_WATCHER_SPAWN_LIMIT", cfg.watcher_spawn_limit))
    cfg.dry_run = os.environ.get("ARGUS_DRY_RUN", "1") not in ("0", "false", "False")
    cfg.vt_api_key = os.environ.get("ARGUS_VT_API_KEY", "")
    cfg.webhook_url = os.environ.get("ARGUS_WEBHOOK_URL", "")
    cfg.port = int(os.environ.get("ARGUS_PORT", cfg.port))
    cfg.llm_api_key = os.environ.get("ARGUS_LLM_API_KEY", "")
    # persisted LLM selection (set via the dashboard's AI selector)
    try:
        llm_json = cfg.data_dir / "llm.json"
        if llm_json.exists():
            d = json.loads(llm_json.read_text(encoding="utf-8"))
            if d.get("url"):
                cfg.llm_url = d["url"]
            if d.get("model"):
                cfg.llm_model = d["model"]
            if d.get("api_key"):
                cfg.llm_api_key = d["api_key"]
    except Exception:  # noqa: BLE001 — never let a corrupt llm.json break startup
        pass
    # persisted response mode (set via the dashboard's Watch / Act selector)
    try:
        mode_json = cfg.data_dir / "mode.json"
        if mode_json.exists():
            d = json.loads(mode_json.read_text(encoding="utf-8"))
            if d.get("mode") == "act":
                cfg.dry_run = False
            elif d.get("mode") == "watch":
                cfg.dry_run = True
    except Exception:  # noqa: BLE001 — never let a corrupt mode.json break startup
        pass
    return cfg
