"""Argus command-center web server (stdlib only, no dependencies).

Serves the dashboard UI and a small JSON API over the detection + quarantine
stores. Runs in the same process that owns the data, so there is no auth
surface by default — it binds to 127.0.0.1 unless you say otherwise.
"""
from __future__ import annotations

import json
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .config import Config
from .engine import is_quarantinable
from .export import to_ocsf, to_stix
from .quarantine import kill_process_tree, quarantine_file, restore_file
from .rules import approve_rule, list_rules
from .store import read_jsonl


def _resource_path(rel: str) -> Path:
    """Resolve bundled data in both dev and PyInstaller-frozen modes."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / rel
    return Path(__file__).resolve().parent.parent / rel


DASHBOARD = _resource_path("dashboard")


_llm_cache = {"t": 0.0, "reachable": False}


def _llm_reachable(cfg: Config) -> bool:
    """Cached (30s) reachability of the local model endpoint."""
    if time.time() - _llm_cache["t"] < 30:
        return _llm_cache["reachable"]
    from .adjudicate import check_llm
    _llm_cache["reachable"] = check_llm(cfg.llm_url, timeout=2)
    _llm_cache["t"] = time.time()
    return _llm_cache["reachable"]


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


def _memory_list(memory):
    """Serialize the two-tier memory for the dashboard (semantic first)."""
    if memory is None:
        return []
    out = []
    for rec in memory.semantic:
        d = rec.to_dict()
        d["tier"] = "semantic"
        out.append(d)
    for rec in memory.episodic:
        d = rec.to_dict()
        d["tier"] = "episodic"
        out.append(d)
    return out


def _graph_list(graph):
    """Serialize the process-lineage graph (spawn + endpoint edges) for the dashboard."""
    if graph is None:
        return []
    spawns = [e.to_dict() for e in graph.edges.values()]
    endpoints = [e.to_dict() for e in graph.endpoints.values()]
    return sorted(spawns + endpoints, key=lambda e: -e["count"])


def make_handler(cfg: Config, memory=None, graph=None):
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
            if path.startswith("/assets/"):
                rel = path[len("/assets/"):]
                if ".." not in rel and "/" not in rel and "\\" not in rel:
                    ext = rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
                    ctype = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
                             "svg": "image/svg+xml", "webp": "image/webp", "ico": "image/x-icon",
                             "css": "text/css"}.get(ext, "application/octet-stream")
                    return _static(self, DASHBOARD / "assets" / rel, ctype)
                return self.send_error(404)

            if path == "/api/status":
                det = read_jsonl(cfg.detections_path, 10000)
                quar = read_jsonl(cfg.manifest_path, 10000)
                wat = read_jsonl(cfg.watcher_path, 1000)
                mem = memory.stats() if memory is not None else {"semantic": 0, "episodic": 0}
                return _json(self, {
                    "version": __version__,
                    "dry_run": cfg.dry_run,
                    "mode": "watch" if cfg.dry_run else "act",
                    "flag_threshold": cfg.flag_threshold,
                    "kill_threshold": cfg.kill_threshold,
                    "detections": len(det),
                    "flagged": sum(1 for d in det if d.get("decision") == "flag"),
                    "quarantined": len(quar),
                    "killed": sum(1 for d in det if any(a.startswith("killed") for a in (d.get("actions") or []))),
                    "watcher_findings": len(wat),
                    "memory_semantic": mem["semantic"],
                    "memory_episodic": mem["episodic"],
                    "graph_edges": graph.stats()["edges"] if graph is not None else 0,
                    "graph_endpoints": graph.stats()["endpoints"] if graph is not None else 0,
                })
            if path == "/api/detections":
                return _json(self, read_jsonl(cfg.detections_path, 300))
            if path == "/api/quarantine":
                return _json(self, read_jsonl(cfg.manifest_path, 300))
            if path == "/api/watcher":
                return _json(self, read_jsonl(cfg.watcher_path, 300))
            if path == "/api/memory":
                return _json(self, _memory_list(memory))
            if path == "/api/rules":
                return _json(self, list_rules(cfg))
            if path == "/api/graph":
                return _json(self, _graph_list(graph))
            if path == "/api/sessionlog":
                return _json(self, read_jsonl(cfg.session_log_path, 500))
            if path == "/api/mode":
                return _json(self, {"mode": "watch" if cfg.dry_run else "act", "dry_run": cfg.dry_run})
            if path == "/api/llm":
                return _json(self, {"url": cfg.llm_url, "model": cfg.llm_model, "reachable": _llm_reachable(cfg), "has_key": bool(cfg.llm_api_key)})
            if path == "/api/llm/setup":
                from .llm_provision import setup_status
                return _json(self, setup_status())
            if path == "/api/campaign":
                from urllib.parse import parse_qs
                image = (parse_qs(url.query).get("image") or [""])[0]
                return _json(self, graph.campaign(image) if graph is not None else {})
            if path == "/api/blast":
                from urllib.parse import parse_qs
                image = (parse_qs(url.query).get("image") or [""])[0]
                return _json(self, graph.blast_radius(image) if graph is not None else {})
            if path == "/api/export":
                from urllib.parse import parse_qs
                fmt = (parse_qs(url.query).get("format") or ["ocsf"])[0]
                dets = read_jsonl(cfg.detections_path, 200)
                if fmt == "stix":
                    return _json(self, [to_stix(d) for d in dets])
                return _json(self, [to_ocsf(d) for d in dets])
            if path == "/api/review":
                from .review import read_review
                return _json(self, read_review(cfg))

            return self.send_error(404)

        def do_POST(self):
            url = urlparse(self.path)
            if url.path == "/api/mode":
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                mode = (body.get("mode") or "").strip().lower()
                if mode not in ("watch", "act"):
                    return _json(self, {"ok": False, "error": "mode must be watch or act"}, 400)
                cfg.dry_run = (mode == "watch")
                try:
                    cfg.data_dir.mkdir(parents=True, exist_ok=True)
                    (cfg.data_dir / "mode.json").write_text(
                        json.dumps({"mode": mode}), encoding="utf-8")
                except Exception as exc:  # noqa: BLE001
                    return _json(self, {"ok": False, "error": str(exc)}, 500)
                return _json(self, {"ok": True, "mode": mode, "dry_run": cfg.dry_run})
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
            if url.path == "/api/adjudicate":
                # Analyst feedback: promote a detection to high-confidence ground truth.
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                memory_id = body.get("memory_id", "")
                verdict = (body.get("verdict", "") or "").upper()
                if memory is None:
                    return _json(self, {"ok": False, "error": "memory disabled"}, 400)
                if verdict not in ("BENIGN", "MALICIOUS"):
                    return _json(self, {"ok": False, "error": "verdict must be BENIGN or MALICIOUS"}, 400)
                outcome = "confirmed_false_positive" if verdict == "BENIGN" else "verified_incident"
                updated = memory.verify(memory_id, verdict, outcome)
                if not updated:
                    return _json(self, {"ok": False, "error": "memory id not found"}, 404)
                memory.save()
                return _json(self, {"ok": True, "promoted": memory_id, "verdict": verdict})
            if url.path == "/api/approve":
                # Human-in-the-loop: approve a proposed containment and execute it.
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                image = body.get("image", "")
                pid = int(body.get("pid", 0) or 0)
                actions = []
                if image and is_quarantinable(image):
                    try:
                        dest = quarantine_file(image, cfg.quarantine_dir, "analyst-approved", cfg.manifest_path)
                        actions.append(f"quarantined -> {dest}")
                    except Exception as exc:  # noqa: BLE001
                        actions.append(f"quarantine failed: {exc}")
                elif image:
                    actions.append(f"quarantine skipped (trusted binary): {image}")
                if pid:
                    try:
                        kill_process_tree(pid)
                        actions.append(f"killed process tree {pid}")
                    except Exception as exc:  # noqa: BLE001
                        actions.append(f"kill failed: {exc}")
                return _json(self, {"ok": True, "actions": actions})
            if url.path == "/api/rules/approve":
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                rid = body.get("id", "")
                try:
                    path = approve_rule(cfg, rid)
                    return _json(self, {"ok": True, "approved": path})
                except KeyError:
                    return _json(self, {"ok": False, "error": "rule not found"}, 404)
            if url.path == "/api/llm/config":
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                u = (body.get("url") or "").strip()
                m = (body.get("model") or "").strip()
                k = (body.get("api_key") or "").strip()
                if u:
                    cfg.llm_url = u
                if m:
                    cfg.llm_model = m
                if k:
                    cfg.llm_api_key = k
                try:
                    cfg.data_dir.mkdir(parents=True, exist_ok=True)
                    (cfg.data_dir / "llm.json").write_text(
                        json.dumps({"url": cfg.llm_url, "model": cfg.llm_model, "api_key": cfg.llm_api_key}), encoding="utf-8")
                    _llm_cache["t"] = 0.0  # force a fresh reachability check
                    return _json(self, {"ok": True, "url": cfg.llm_url, "model": cfg.llm_model, "has_key": bool(cfg.llm_api_key)})
                except Exception as exc:  # noqa: BLE001
                    return _json(self, {"ok": False, "error": str(exc)}, 500)
            if url.path == "/api/llm/setup":
                from .llm_provision import start_setup
                started = start_setup(cfg)
                return _json(self, {"ok": True, "started": started})
            if url.path == "/api/analyze":
                from .analyze import analyze_recent
                try:
                    results = analyze_recent(cfg, memory, cfg.llm_model, cfg.llm_url, 40)
                    summary = {
                        "total": len(results),
                        "benign": sum(1 for r in results if r["verdict"] == "BENIGN"),
                        "malicious": sum(1 for r in results if r["verdict"] == "MALICIOUS"),
                        "uncertain": sum(1 for r in results if r["verdict"] not in ("BENIGN", "MALICIOUS")),
                    }
                    return _json(self, {"ok": True, "summary": summary, "results": results})
                except Exception as exc:  # noqa: BLE001
                    return _json(self, {"ok": False, "error": str(exc)}, 500)
            if url.path == "/api/review":
                # Promote a reviewed (missed) event into a hot-reloadable rule.
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                image = body.get("image", "")
                command_line = body.get("command_line", "")
                if not image or not command_line:
                    return _json(self, {"ok": False, "error": "image and command_line required"}, 400)
                from .review import promote_to_rule
                rule = promote_to_rule(cfg, image, command_line)
                if rule is None:
                    return _json(self, {"ok": False, "error": "could not extract a rule"}, 400)
                return _json(self, {"ok": True, "rule": rule})
            return self.send_error(404)

    return Handler


def serve(cfg: Config, memory=None, graph=None, watch_runner=None) -> None:
    if watch_runner is not None:
        # Run the detection loop in a daemon thread so the command center and the
        # watcher coexist in one process — the Watch/Act selector then flips
        # cfg.dry_run live and the loop picks it up on the next poll.
        threading.Thread(target=watch_runner, daemon=True, name="argus-watch").start()
        print("[argus] background watch started")
    handler = make_handler(cfg, memory, graph)
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
