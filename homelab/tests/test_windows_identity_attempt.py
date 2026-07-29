import json
import os
from pathlib import Path
import tempfile
import unittest

from homelab.vm.windows_identity_attempt import (
    STATE_NAME,
    TEARDOWN_NAME,
    claim,
    terminalize,
)


class WindowsIdentityAttemptTests(unittest.TestCase):
    def prepared(self, root: Path) -> Path:
        attempt = root / "attempt"
        attempt.mkdir(mode=0o700)
        (attempt / "authorization.json").write_text(
            '{"status":"prepared"}\n', encoding="utf-8")
        (attempt / "qemu-command.json").write_text(
            '{"schema":1,"argv":[]}\n', encoding="utf-8")
        return attempt

    def test_claim_is_private_durable_and_one_use(self):
        with tempfile.TemporaryDirectory() as name:
            attempt = self.prepared(Path(name))
            claim_digest = claim(attempt)
            marker = attempt / STATE_NAME
            self.assertEqual(0o600, marker.stat().st_mode & 0o777)
            document = json.loads(marker.read_text(encoding="utf-8"))
            self.assertEqual("windows-identity-attempt-consumed",
                             document["kind"])
            self.assertEqual(64, len(claim_digest))
            with self.assertRaises(RuntimeError):
                claim(attempt)

    def test_terminal_receipt_is_closed_and_secret_free(self):
        with tempfile.TemporaryDirectory() as name:
            attempt = self.prepared(Path(name))
            claim_digest = claim(attempt)
            facts = {
                "processes_reaped": True,
                "qmp_closed": True,
                "runtime_quiescent": True,
                "owned_media_closed": True,
                "dependencies_released": True,
            }
            terminalize(
                attempt,
                claim_sha256=claim_digest,
                outcome="failed",
                teardown=facts,
            )
            receipt = attempt / TEARDOWN_NAME
            self.assertEqual(0o600, receipt.stat().st_mode & 0o777)
            document = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual(
                {
                    "claim_sha256", "kind", "outcome", "schema",
                    "teardown", "teardown_complete",
                },
                set(document),
            )
            self.assertTrue(document["teardown_complete"])
            self.assertNotIn("password", receipt.read_text(encoding="utf-8"))

    def test_parent_directory_is_fsynced_for_both_publications(self):
        with tempfile.TemporaryDirectory() as name:
            attempt = self.prepared(Path(name))
            real_fsync = os.fsync
            calls = []

            def observed(descriptor):
                calls.append(os.fstat(descriptor).st_mode)
                return real_fsync(descriptor)

            from unittest import mock
            with mock.patch(
                "homelab.vm.windows_identity_attempt.os.fsync",
                side_effect=observed,
            ):
                digest = claim(attempt)
                terminalize(
                    attempt,
                    claim_sha256=digest,
                    outcome="succeeded",
                    teardown={
                        "processes_reaped": True,
                        "qmp_closed": True,
                        "runtime_quiescent": True,
                        "owned_media_closed": True,
                        "dependencies_released": True,
                    },
                )
            self.assertEqual(4, len(calls))


if __name__ == "__main__":
    unittest.main()
