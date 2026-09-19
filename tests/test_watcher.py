import unittest

from argus.events import ProcessEvent
from argus.watcher import detect_watcher_pairs


def ev(ts, image, parent_image="", pid=1, parent_pid=0):
    return ProcessEvent(
        source="sysmon", event_id=1, timestamp=ts, pid=pid, parent_pid=parent_pid,
        image=image, parent_image=parent_image,
    )


class TestWatcher(unittest.TestCase):
    def test_respawn_storm(self):
        events = [ev("2026-09-18T22:30:0%dZ" % i, r"C:\Temp\svc.exe") for i in range(6)]
        findings = detect_watcher_pairs(events, window_seconds=60, spawn_limit=3)
        self.assertTrue(any("respawn" in f.reason for f in findings))

    def test_spread_out_spawns_are_not_a_storm(self):
        events = [ev("2026-09-18T22:%02d:00Z" % (i * 5), r"C:\Temp\svc.exe") for i in range(4)]
        findings = detect_watcher_pairs(events, window_seconds=60, spawn_limit=3)
        # 4 spawns, but 5 minutes apart -> never more than 1 within a 60s window
        self.assertFalse(any("respawn" in f.reason for f in findings))

    def test_mutual_spawn(self):
        events = [
            ev("2026-09-18T22:30:00Z", r"C:\a.exe", parent_image=r"C:\b.exe", pid=1, parent_pid=2),
            ev("2026-09-18T22:30:01Z", r"C:\b.exe", parent_image=r"C:\a.exe", pid=2, parent_pid=1),
        ]
        findings = detect_watcher_pairs(events, window_seconds=60, spawn_limit=3)
        self.assertTrue(any("mutual" in f.reason for f in findings))

    def test_quiet(self):
        events = [ev("2026-09-18T22:30:00Z", r"C:\Windows\System32\svchost.exe")]
        self.assertEqual(detect_watcher_pairs(events), [])


if __name__ == "__main__":
    unittest.main()
