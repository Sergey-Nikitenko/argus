"""Argus configuration."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    """Runtime configuration. Safe defaults: dry-run until you pass --act."""

    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("ARGUS_DATA_DIR", r"C:\ProgramData\Argus")))
    flag_threshold: int = 40        # >= this score -> flag (log/alert)
    kill_threshold: int = 70        # >= this score -> quarantine + kill
    watcher_window_seconds: int = 60
    watcher_spawn_limit: int = 3
    max_events_per_poll: int = 500
    dry_run: bool = True            # True = report only, no destructive action
    vt_api_key: str = ""
    webhook_url: str = ""
    llm_enabled: bool = True        # local model adjudicates every would-be kill
    llm_model: str = "google/gemma-4-e4b"
    llm_url: str = "http://localhost:1234/v1/chat/completions"
    host: str = "127.0.0.1"
    port: int = 8899

    def __post_init__(self):
        self.data_dir = Path(self.data_dir)
        self.quarantine_dir = self.data_dir / "quarantine"
        self.manifest_path = self.data_dir / "manifest.jsonl"
        self.detections_path = self.data_dir / "detections.jsonl"
        self.watcher_path = self.data_dir / "watcher.jsonl"


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
    return cfg
