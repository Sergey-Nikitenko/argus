import unittest

from argus.events import parse_event, parse_security_event, parse_sysmon_event

SECURITY_XML = r"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{11111111-1111-1111-1111-111111111111}" />
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-09-18T22:30:00.0000000Z" />
  </System>
  <EventData>
    <Data Name="SubjectUserName">Nikit</Data>
    <Data Name="NewProcessId">0x1a2b</Data>
    <Data Name="NewProcessName">C:\Users\Nikit\AppData\Local\Temp\evil.exe</Data>
    <Data Name="ProcessId">0x1234</Data>
    <Data Name="CommandLine">C:\Users\Nikit\AppData\Local\Temp\evil.exe -enc SQBFAFgA</Data>
    <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
  </EventData>
</Event>"""

SYSMON_XML = r"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{22222222-2222-2222-2222-222222222222}" />
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-09-18T22:31:00.0000000Z" />
  </System>
  <EventData>
    <Data Name="UtcTime">2026-09-18 22:31:00.000</Data>
    <Data Name="ProcessId">6698</Data>
    <Data Name="Image">C:\Users\Nikit\AppData\Roaming\payload.exe</Data>
    <Data Name="CommandLine">payload.exe --hidden</Data>
    <Data Name="ParentProcessId">4488</Data>
    <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data>
    <Data Name="User">NIKIT-PC\Nikit</Data>
    <Data Name="Hashes">SHA256=ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890</Data>
    <Data Name="IntegrityLevel">Medium</Data>
  </EventData>
</Event>"""


class TestSecurityParsing(unittest.TestCase):
    def test_fields(self):
        ev = parse_security_event(SECURITY_XML)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.source, "security")
        self.assertEqual(ev.event_id, 4688)
        self.assertEqual(ev.pid, 0x1A2B)
        self.assertEqual(ev.parent_pid, 0x1234)
        self.assertEqual(ev.image, r"C:\Users\Nikit\AppData\Local\Temp\evil.exe")
        self.assertIn("-enc", ev.command_line)
        self.assertEqual(ev.user, "Nikit")
        self.assertEqual(ev.parent_image, r"C:\Windows\explorer.exe")

    def test_wrong_event_id_returns_none(self):
        self.assertIsNone(parse_security_event(SECURITY_XML.replace("4688", "4689")))


class TestSysmonParsing(unittest.TestCase):
    def test_fields(self):
        ev = parse_sysmon_event(SYSMON_XML)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.source, "sysmon")
        self.assertEqual(ev.pid, 6698)
        self.assertEqual(ev.parent_pid, 4488)
        self.assertEqual(ev.image, r"C:\Users\Nikit\AppData\Roaming\payload.exe")
        self.assertEqual(ev.parent_image, r"C:\Windows\System32\cmd.exe")
        self.assertEqual(ev.integrity, "Medium")

    def test_sha256_extracted(self):
        ev = parse_sysmon_event(SYSMON_XML)
        self.assertEqual(ev.sha256(), "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890")

    def test_wrong_event_id_returns_none(self):
        self.assertIsNone(parse_sysmon_event(SYSMON_XML.replace("<EventID>1</EventID>", "<EventID>3</EventID>")))


class TestDispatch(unittest.TestCase):
    def test_parse_event_dispatch(self):
        self.assertEqual(parse_event(SECURITY_XML).source, "security")
        self.assertEqual(parse_event(SYSMON_XML).source, "sysmon")


if __name__ == "__main__":
    unittest.main()
