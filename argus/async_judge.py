"""Asynchronous adjudication pool — decouple ingestion from heavy AI reasoning.

The watch loop must never block on the local model (a single LLM call can take
minutes). It scores synchronously (fast) and hands would-be-kill events to this
pool, which runs the model on worker threads and invokes ``on_result`` with the
verdict. Stdlib-only: a ``queue.Queue`` plus ``threading`` workers.
"""
from __future__ import annotations

import queue
import threading


class AsyncAdjudicator:
    def __init__(self, adjudicate_fn, on_result, workers: int = 2):
        self.adjudicate_fn = adjudicate_fn   # (ev, score, history) -> verdict dict
        self.on_result = on_result           # (ev, score, verdict) -> None
        self._q: queue.Queue = queue.Queue()
        self._workers = [threading.Thread(target=self._work, daemon=True)
                         for _ in range(max(1, workers))]
        self._lock = threading.Lock()
        self.submitted = 0
        self.finished = 0

    def start(self) -> None:
        for w in self._workers:
            w.start()

    def submit(self, ev, score, history) -> None:
        """Enqueue an event for background adjudication. Returns immediately."""
        self._q.put((ev, score, history))
        with self._lock:
            self.submitted += 1

    def _work(self) -> None:
        while True:
            ev, score, history = self._q.get()
            try:
                verdict = self.adjudicate_fn(ev, score, history)
            except Exception as exc:  # noqa: BLE001
                verdict = {"verdict": "UNCERTAIN", "reason": f"adjudication failed: {exc}"}
            try:
                self.on_result(ev, score, verdict)
            except Exception:  # noqa: BLE001
                pass
            finally:
                with self._lock:
                    self.finished += 1
                self._q.task_done()

    def stats(self) -> dict:
        with self._lock:
            return {"submitted": self.submitted, "finished": self.finished,
                    "pending": self._q.qsize()}
