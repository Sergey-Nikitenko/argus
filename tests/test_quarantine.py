import json
import tempfile
import unittest
from pathlib import Path

from argus.quarantine import quarantine_file, restore_file


class TestQuarantine(unittest.TestCase):
    def test_moves_not_deletes_and_writes_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "evil.exe"
            src.write_bytes(b"MZ-fake-pe")
            qdir = root / "quarantine"
            manifest = qdir / "manifest.jsonl"

            dest = quarantine_file(str(src), qdir, "test reason", manifest)

            self.assertFalse(src.exists())          # moved, not deleted-in-place
            self.assertTrue(Path(dest).exists())    # still recoverable
            self.assertTrue(dest.endswith(".quarantine"))

            lines = manifest.read_text().strip().splitlines()
            self.assertEqual(len(lines), 1)
            rec = json.loads(lines[0])
            self.assertEqual(rec["original"], str(src))
            self.assertEqual(rec["quarantined"], dest)
            self.assertIn("test reason", rec["reason"])

    def test_missing_file_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                quarantine_file(str(Path(tmp) / "nope.exe"), Path(tmp) / "q")

    def test_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "evil.exe"
            src.write_bytes(b"MZ-fake")
            qdir = root / "q"
            dest = quarantine_file(str(src), qdir, "reason", qdir / "manifest.jsonl")
            restored = restore_file(dest, str(src))
            self.assertEqual(restored, str(src))
            self.assertTrue(src.exists())
            self.assertFalse(Path(dest).exists())


if __name__ == "__main__":
    unittest.main()
