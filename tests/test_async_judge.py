import threading
import time
import unittest

from argus.async_judge import AsyncAdjudicator


class TestAsyncAdjudicator(unittest.TestCase):
    def test_submit_runs_worker_and_callback(self):
        results = []
        done = threading.Event()

        def adjudicate_fn(ev, score, history):
            return {"verdict": "MALICIOUS", "confidence": 0.9, "reason": "yes"}

        def on_result(ev, score, verdict):
            results.append(verdict["verdict"])
            if len(results) >= 2:
                done.set()

        j = AsyncAdjudicator(adjudicate_fn, on_result, workers=2)
        j.start()
        j.submit("ev1", "score1", [])
        j.submit("ev2", "score2", [])
        self.assertTrue(done.wait(timeout=2.0))
        self.assertEqual(sorted(results), ["MALICIOUS", "MALICIOUS"])
        self.assertEqual(j.stats()["finished"], 2)

    def test_submit_is_nonblocking(self):
        started = threading.Event()

        def slow_fn(ev, score, history):
            started.set()
            time.sleep(0.3)
            return {"verdict": "BENIGN", "reason": ""}

        j = AsyncAdjudicator(slow_fn, lambda e, s, v: None, workers=1)
        j.start()
        t0 = time.time()
        j.submit("ev", "score", [])
        self.assertLess(time.time() - t0, 0.1)   # returned without waiting for the model

    def test_worker_survives_adjudicate_exception(self):
        got = []

        def boom(ev, score, history):
            raise RuntimeError("model down")

        def on_result(ev, score, verdict):
            got.append(verdict["verdict"])

        j = AsyncAdjudicator(boom, on_result, workers=1)
        j.start()
        j.submit("ev", "score", [])
        deadline = time.time() + 2.0
        while not got and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(got, ["UNCERTAIN"])    # fail-safe, never raises


if __name__ == "__main__":
    unittest.main()
