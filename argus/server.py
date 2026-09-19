"""Argus command-center web server (stdlib only, no dependencies).

Serves the dashboard UI and a small JSON API over the detection + quarantine
stores. Runs in the same process that owns the data, so there is no auth
surface by default — it binds to 127.0.0.1 unless you say otherwise.
"""
from __future__ import annotations

import json
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .config import Config
from .quarantine import restore_file
from .store import read_jsonl


def _resource_path(rel: str) -> Path:
    """Resolve bundled data in both dev and PyInstaller-frozen modes."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / rel
    return Path(__file__).resolve().parent.parent / rel


DASHBOARD = _resource_path("dashboard")


def _json(handler, obj, status=200):
    body = json.dumps(obj).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _static(handler, path: Path, ctype: str):
    if not path.exists():
        handler.send_error(404)
        return
    data = path.read_bytes()
    handler.send_response(200)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def make_handler(cfg: Config):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence request logging
            pass

        def do_GET(self):
            url = urlparse(self.path)
            path = url.path

            if path in ("/", "/index.html"):
                return _static(self, DASHBOARD / "index.html", "text/html; charset=utf-8")
            if path == "/icon.svg":
                return _static(self, DASHBOARD / "icon.svg", "image/svg+xml")
            if path == "/icon.jpg":
                return _static(self, DASHBOARD / "icon.jpg", "image/jpeg")

            if path == "/api/status":
                det = read_jsonl(cfg.detections_path, 10000)
                quar = read_jsonl(cfg.manifest_path, 10000)
                wat = read_jsonl(cfg.watcher_path, 1000)
                return _json(self, {
                    "version": __version__,
                    "dry_run": cfg.dry_run,
                    "flag_threshold": cfg.flag_threshold,
                    "kill_threshold": cfg.kill_threshold,
                    "detections": len(det),
                    "flagged": sum(1 for d in det if d.get("decision") == "flag"),
                    "quarantined": len(quar),
                    "watcher_findings": len(wat),
                })
            if path == "/api/detections":
                return _json(self, read_jsonl(cfg.detections_path, 300))
            if path == "/api/quarantine":
                return _json(self, read_jsonl(cfg.manifest_path, 300))
            if path == "/api/watcher":
                return _json(self, read_jsonl(cfg.watcher_path, 300))

            return self.send_error(404)

        def do_POST(self):
            url = urlparse(self.path)
            if url.path == "/api/restore":
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                quarantined = body.get("quarantined", "")
                original = body.get("original", "")
                try:
                    dest = restore_file(quarantined, original)
                    return _json(self, {"ok": True, "restored": dest})
                except Exception as exc:  # noqa: BLE001
                    return _json(self, {"ok": False, "error": str(exc)}, 400)
            return self.send_error(404)

    return Handler


def serve(cfg: Config) -> None:
    handler = make_handler(cfg)
    httpd = ThreadingHTTPServer((cfg.host, cfg.port), handler)
    url = f"http://{cfg.host}:{cfg.port}"
    print(f"[argus] command center: {url}")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
