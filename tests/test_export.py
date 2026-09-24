import unittest

from argus.export import to_ocsf, to_stix


def det(**kw):
    d = {
        "timestamp": "2026-01-01T00:00:00Z", "pid": 1, "parent_pid": 0,
        "image": r"C:\Windows\System32\cmd.exe", "command_line": "cmd.exe /c whoami",
        "user": "alice", "score": 80, "severity": "critical", "reasons": [],
        "techniques": [{"id": "T1059.003", "name": "Windows Command Shell"}],
        "decision": "quarantine", "sha256": "", "memory_id": "abc",
    }
    d.update(kw)
    return d


class TestExport(unittest.TestCase):
    def test_ocsf_shape(self):
        o = to_ocsf(det())
        self.assertEqual(o["class_uid"], 1007)
        self.assertEqual(o["activity_id"], 1)
        self.assertEqual(o["process"]["file"]["name"], "cmd.exe")
        self.assertEqual(o["unmapped"]["score"], 80)
        self.assertEqual(o["unmapped"]["techniques"], ["T1059.003"])

    def test_stix_bundle_has_malware_when_malicious(self):
        types = [o["type"] for o in to_stix(det(decision="quarantine"))["objects"]]
        self.assertIn("observed-data", types)
        self.assertIn("malware", types)
        self.assertIn("indicator", types)

    def test_stix_no_malware_when_benign(self):
        types = [o["type"] for o in to_stix(det(decision="flag"))["objects"]]
        self.assertIn("observed-data", types)
        self.assertNotIn("malware", types)
        self.assertNotIn("indicator", types)


if __name__ == "__main__":
    unittest.main()
