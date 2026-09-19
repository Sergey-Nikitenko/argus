import unittest

from argus.events import ProcessEvent
from argus.process_tree import ancestry, build_tree, descendants


def ev(pid, parent_pid, image=""):
    return ProcessEvent(source="sysmon", event_id=1, timestamp="", pid=pid,
                        parent_pid=parent_pid, image=image or f"img{pid}")


class TestProcessTree(unittest.TestCase):
    def test_ancestry(self):
        events = [ev(1, 0), ev(2, 1), ev(3, 2)]
        chain = ancestry(events, 3)
        self.assertEqual([e.pid for e in chain], [1, 2, 3])

    def test_ancestry_breaks_on_cycle(self):
        events = [ev(1, 2), ev(2, 1)]
        self.assertEqual(len(ancestry(events, 1)), 2)  # no infinite loop

    def test_descendants(self):
        events = [ev(1, 0), ev(2, 1), ev(3, 1), ev(4, 2)]
        kids = descendants(events, 1)
        self.assertEqual(sorted(e.pid for e in kids), [2, 3, 4])

    def test_build_tree(self):
        events = [ev(1, 0), ev(2, 1), ev(3, 1)]
        tree = build_tree(events)
        self.assertEqual([e.pid for e in tree[1]], [2, 3])


if __name__ == "__main__":
    unittest.main()
