import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vm"))

from manual_verification import (  # noqa: E402
    HELPER, PASS_LINE, SerialVerificationGate,
)


class ManualVerificationTests(unittest.TestCase):
    def test_requires_exact_complete_serial_line(self):
        gate = SerialVerificationGate()
        gate.feed(("noise\r\n" + PASS_LINE[:20]).encode())
        self.assertFalse(gate.passed)
        gate.feed((PASS_LINE[20:] + "\r\n").encode())
        self.assertTrue(gate.passed)

    def test_rejects_near_miss_and_echoed_helper_command(self):
        gate = SerialVerificationGate()
        gate.feed(f"$ sudo {HELPER}\r\n".encode())
        gate.feed((PASS_LINE + " maybe\r\n").encode())
        with self.assertRaisesRegex(RuntimeError, "not observed"):
            gate.require_pass()

    def test_ignores_ansi_decoration(self):
        gate = SerialVerificationGate()
        gate.feed(b"\x1b[32m" + PASS_LINE.encode() + b"\x1b[0m\n")
        self.assertTrue(gate.passed)

    def test_writes_private_machine_readable_receipt(self):
        gate = SerialVerificationGate()
        gate.feed((PASS_LINE + "\n").encode())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manual.json"
            gate.write_receipt(path)
            document = json.loads(path.read_text())
            self.assertEqual(document["helper"], HELPER)
            self.assertEqual(document["observed_line"], PASS_LINE)
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_refuses_receipt_without_observed_pass(self):
        gate = SerialVerificationGate()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manual.json"
            with self.assertRaisesRegex(RuntimeError, "not observed"):
                gate.write_receipt(path)
            self.assertFalse(path.exists())

    def test_receipt_rejects_symlink_without_touching_target(self):
        gate = SerialVerificationGate()
        gate.feed((PASS_LINE + "\n").encode())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim"
            victim.write_text("keep")
            path = root / "manual.json"
            path.symlink_to(victim)
            with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                gate.write_receipt(path)
            self.assertEqual(victim.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
