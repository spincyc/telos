"""Tests for durable, private simulation evidence."""

import json
import stat
import tempfile
import unittest
from pathlib import Path

from homelab.vm.simulation_evidence import (
    RedactedLog, private_directory, private_file, redact, write_result,
    write_serial_events,
)


class SimulationEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "run"

    def assert_mode(self, path, expected):
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected)

    def test_evidence_directory_and_files_are_private(self):
        private_directory(self.root)
        private_file(self.root / "gateway.log", b"ready\n")
        self.assert_mode(self.root, 0o700)
        self.assert_mode(self.root / "gateway.log", 0o600)

    def test_log_redacts_values_but_keeps_password_prompt(self):
        with RedactedLog(self.root / "serial.log") as stream:
            self.assertGreaterEqual(stream.fileno(), 0)
            stream.write(
                b"Password: \npassword=hunter2\nTOKEN: abc123\nlogin: ")
        content = (self.root / "serial.log").read_bytes()
        self.assertIn(b"Password: \n", content)
        self.assertIn(b"password=[REDACTED]", content)
        self.assertIn(b"TOKEN: [REDACTED]", content)
        self.assertIn(b"login: ", content)
        self.assertNotIn(b"hunter2", content)
        self.assertNotIn(b"abc123", content)

    def test_sudo_prompt_without_echoed_input_is_safe(self):
        output = b"[sudo] password for local-rescue: \r\nRESULT PASS\r\n"
        self.assertNotIn(b"[REDACTED]", redact(output))
        with RedactedLog(self.root / "serial.log") as stream:
            stream.write(output)
        self.assertEqual((self.root / "serial.log").read_bytes(), output)

    def test_result_is_private_and_machine_readable(self):
        target = write_result(
            self.root, status="pass", run_id="run-1",
            checks={"host_unchanged": True})
        document = json.loads(target.read_text())
        self.assertEqual(document["status"], "pass")
        self.assertTrue(document["checks"]["host_unchanged"])
        self.assert_mode(target, 0o600)

    def test_failure_result_redacts_secret_and_replaces_prior_result(self):
        write_result(self.root, status="pass", run_id="run-1")
        target = write_result(
            self.root, status="fail", run_id="run-1",
            error=RuntimeError("token: do-not-store"))
        content = target.read_text()
        self.assertNotIn("do-not-store", content)
        self.assertIn("[REDACTED]", content)
        self.assertEqual(json.loads(content)["status"], "fail")

    def test_serial_evidence_contains_no_console_or_input(self):
        target = write_serial_events(
            self.root, qemu_exit_code=0, helper_passed=True)
        document = json.loads(target.read_text())
        self.assertFalse(document["input_captured"])
        self.assertFalse(document["console_output_captured"])
        self.assertNotIn("password", target.read_text().lower())
        self.assert_mode(target, 0o600)

    def test_refuses_final_symlink_for_log_file(self):
        private_directory(self.root)
        outside = self.root.parent / "outside"
        outside.write_bytes(b"keep")
        (self.root / "serial.log").symlink_to(outside)
        with self.assertRaises(OSError):
            private_file(self.root / "serial.log", b"replace")
        self.assertEqual(outside.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
