import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from argus import sysmon


class TestSysmonConfig(unittest.TestCase):
    def test_config_is_valid_xml(self):
        root = ET.fromstring(sysmon.SYSMON_CONFIG)
        self.assertEqual(root.tag, "Sysmon")

    def test_config_enables_process_create_and_network_connect(self):
        root = ET.fromstring(sysmon.SYSMON_CONFIG)
        tags = {el.tag for el in root.iter()}
        self.assertIn("ProcessCreate", tags)
        self.assertIn("NetworkConnect", tags)

    def test_config_sets_hash_algorithms(self):
        root = ET.fromstring(sysmon.SYSMON_CONFIG)
        el = root.find("HashAlgorithms")
        self.assertIsNotNone(el)
        self.assertIn("SHA256", el.text or "")

    def test_write_config_writes_matching_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "sysmon-config.xml"
            out = sysmon.write_config(target)
            self.assertEqual(out, target)
            self.assertEqual(target.read_text(encoding="utf-8"), sysmon.SYSMON_CONFIG)


class TestCommandBuilders(unittest.TestCase):
    def test_build_install_command(self):
        self.assertEqual(
            sysmon.build_install_command("Sysmon64.exe", "cfg.xml"),
            ["Sysmon64.exe", "-accepteula", "-i", "cfg.xml"],
        )

    def test_build_update_command(self):
        self.assertEqual(
            sysmon.build_update_command("Sysmon64.exe", "cfg.xml"),
            ["Sysmon64.exe", "-accepteula", "-c", "cfg.xml"],
        )

    def test_build_uninstall_command(self):
        self.assertEqual(sysmon.build_uninstall_command("Sysmon64.exe"), ["Sysmon64.exe", "-u"])


class TestParseScQuery(unittest.TestCase):
    def test_running(self):
        self.assertEqual(sysmon._parse_sc_query(0, "STATE : 4 RUNNING"), "RUNNING")

    def test_stopped(self):
        self.assertEqual(sysmon._parse_sc_query(0, "STATE : 1 STOPPED"), "STOPPED")

    def test_stop_pending(self):
        self.assertEqual(sysmon._parse_sc_query(0, "STATE : 3 STOP_PENDING"), "STOPPED")

    def test_not_found(self):
        self.assertEqual(sysmon._parse_sc_query(1060, ""), "not found")

    def test_unknown(self):
        self.assertEqual(sysmon._parse_sc_query(0, "weird state"), "unknown")


class TestPickServiceState(unittest.TestCase):
    def test_prefers_sysmon64(self):
        self.assertEqual(
            sysmon._pick_service_state({"Sysmon64": "RUNNING", "Sysmon": "not found"}),
            "RUNNING",
        )

    def test_falls_back_to_sysmon(self):
        self.assertEqual(
            sysmon._pick_service_state({"Sysmon64": "not found", "Sysmon": "STOPPED"}),
            "STOPPED",
        )

    def test_not_found_when_neither(self):
        self.assertEqual(
            sysmon._pick_service_state({"Sysmon64": "not found", "Sysmon": "not found"}),
            "not found",
        )


class TestFormatStatus(unittest.TestCase):
    def test_renders_fields(self):
        d = {
            "installed": True, "service": "RUNNING", "driver": "RUNNING",
            "has_process_events": True, "has_network_events": True,
        }
        text = sysmon.format_status(d)
        for field in ("installed", "RUNNING", "process events (1)", "network events (3)"):
            self.assertIn(field, text)


if __name__ == "__main__":
    unittest.main()
