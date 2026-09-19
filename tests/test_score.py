import unittest

from argus.events import ProcessEvent
from argus.score import score_event


def ev(image="", command_line="", parent_image="", integrity=""):
    return ProcessEvent(
        source="sysmon",
        event_id=1,
        timestamp="",
        pid=1,
        parent_pid=0,
        image=image,
        command_line=command_line,
        parent_image=parent_image,
        integrity=integrity,
    )


class TestScoring(unittest.TestCase):
    def test_temp_path_scores(self):
        s = score_event(ev(image=r"C:\Users\N\AppData\Local\Temp\evil.exe"))
        self.assertGreaterEqual(s.points, 35)
        self.assertTrue(any("path" in r for r in s.reasons))

    def test_roaming_path_scores(self):
        s = score_event(ev(image=r"C:\Users\N\AppData\Roaming\payload.exe"))
        self.assertGreaterEqual(s.points, 35)

    def test_benign_system_exe_scores_zero(self):
        s = score_event(ev(image=r"C:\Windows\System32\svchost.exe", command_line="svchost.exe -k netsvcs"))
        self.assertEqual(s.points, 0)
        self.assertEqual(s.reasons, [])

    def test_encoded_powershell_scores_high(self):
        s = score_event(ev(
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -nop -w hidden -enc SQBFAFgA",
        ))
        self.assertGreaterEqual(s.points, 45)

    def test_office_spawning_shell(self):
        s = score_event(ev(
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        ))
        self.assertGreaterEqual(s.points, 35)
        self.assertTrue(any("Office" in r for r in s.reasons))

    def test_browser_spawning_shell(self):
        s = score_event(ev(
            image=r"C:\Windows\System32\cmd.exe",
            parent_image=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        ))
        self.assertGreaterEqual(s.points, 25)
        self.assertTrue(any("browser" in r for r in s.reasons))

    def test_low_integrity_scores(self):
        s = score_event(ev(image=r"C:\Windows\System32\notepad.exe", integrity="Low"))
        self.assertGreaterEqual(s.points, 15)

    def test_techniques_populated(self):
        s = score_event(ev(image=r"C:\Users\N\AppData\Local\Temp\evil.exe", command_line="evil.exe -enc X"))
        ids = [t["id"] for t in s.techniques_deduped()]
        self.assertIn("T1204.002", ids)
        self.assertIn("T1059.001", ids)


if __name__ == "__main__":
    unittest.main()
