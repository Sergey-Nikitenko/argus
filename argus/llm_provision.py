"""One-click local model provisioning (Option A — the default).

Detects Ollama; if absent, downloads + silently installs it; pulls a recommended
model; then points Argus at ``http://localhost:11434/v1/chat/completions``. Runs in
a background thread so the dashboard can poll progress.

Stdlib-only. Installer/pull failures are reported through the status dict, never
raised — a user can always fall back to the manual selector (Option C cloud, or a
hand-rolled local endpoint).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
import urllib.request
from pathlib import Path

OLLAMA_URL = "http://localhost:11434/v1/chat/completions"
DEFAULT_MODEL = "llama3.2"
INSTALLER_URL = "https://ollama.com/download/OllamaSetup.exe"

_state = {"status": "idle", "message": "", "done": False, "ok": False}
_lock = threading.Lock()


def _set(status: str, message: str = "", done: bool = False, ok: bool = False):
    with _lock:
        _state.update({"status": status, "message": message, "done": done, "ok": ok})


def ollama_installed() -> bool:
    if shutil.which("ollama"):
        return True
    base = os.environ.get("LOCALAPPDATA", "")
    if base and os.path.exists(os.path.join(base, "Programs", "Ollama", "ollama.exe")):
        return True
    return os.path.exists(r"C:\Program Files\Ollama\ollama.exe")


def _download_installer(dest: Path) -> bool:
    try:
        urllib.request.urlretrieve(INSTALLER_URL, dest)
        return dest.exists() and dest.stat().st_size > 0
    except Exception:  # noqa: BLE001
        return False


def _run_setup(cfg, model: str):
    _set("checking", "Looking for Ollama...")
    if not ollama_installed():
        _set("installing", "Ollama not found — downloading + installing (a few minutes)...")
        dest = Path(cfg.data_dir) / "OllamaSetup.exe"
        try:
            cfg.data_dir.mkdir(parents=True, exist_ok=True)
        except Exception:  # noqa: BLE001
            pass
        if not _download_installer(dest):
            _set("error", "Could not download Ollama. Install it manually and use the AI selector.", done=True)
            return
        try:
            subprocess.run([str(dest), "/VERYSILENT", "/NORESTART"], timeout=900)
        except Exception as exc:  # noqa: BLE001
            _set("error", f"Ollama installer failed (may need admin): {exc}", done=True)
            return
    _set("pulling", f"Pulling model {model} (one-time download)...")
    try:
        subprocess.run(["ollama", "pull", model], timeout=3600)
    except Exception as exc:  # noqa: BLE001
        _set("error", f"Model pull failed: {exc}", done=True)
        return
    # configure Argus to use it
    cfg.llm_url = OLLAMA_URL
    cfg.llm_model = model
    try:
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        (cfg.data_dir / "llm.json").write_text(
            '{"url": "%s", "model": "%s", "api_key": ""}' % (OLLAMA_URL, model), encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    _set("done", f"AI ready — {model} on Ollama", done=True, ok=True)


def start_setup(cfg, model: str = DEFAULT_MODEL) -> bool:
    with _lock:
        if _state["status"] in ("checking", "installing", "pulling"):
            return False
        _state.update({"status": "checking", "message": "", "done": False, "ok": False})
    threading.Thread(target=_run_setup, args=(cfg, model), daemon=True).start()
    return True


def setup_status() -> dict:
    with _lock:
        return dict(_state)
