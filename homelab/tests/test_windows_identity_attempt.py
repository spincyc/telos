import json
import os
import fcntl
from pathlib import Path
import tempfile
import threading
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
            capability = claim(attempt)
            marker = attempt / STATE_NAME
            self.assertEqual(0o600, marker.stat().st_mode & 0o777)
            document = json.loads(marker.read_text(encoding="utf-8"))
            self.assertEqual("windows-identity-attempt-consumed",
                             document["kind"])
            self.assertEqual(64, len(capability.digest))
            with self.assertRaises(RuntimeError):
                claim(attempt)
            self.assertTrue(capability.verify(attempt))
            descriptors = [
                os.open(attempt / "authorization.json", os.O_RDONLY)
                for _ in range(8)
            ]
            try:
                self.assertTrue(capability.verify(attempt))
                competing = os.open(marker, os.O_RDONLY)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(
                            competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(competing)
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
                capability.close()

    def test_terminal_receipt_is_closed_and_secret_free(self):
        with tempfile.TemporaryDirectory() as name:
            attempt = self.prepared(Path(name))
            capability = claim(attempt)
            facts = {
                "processes_reaped": True,
                "qmp_closed": True,
                "runtime_quiescent": True,
                "owned_media_closed": True,
                "dependencies_released": True,
            }
            terminalize(
                attempt,
                claim=capability,
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
            capability.close()

    def test_concurrent_claim_has_exactly_one_owner(self):
        with tempfile.TemporaryDirectory() as name:
            attempt = self.prepared(Path(name))
            barrier = threading.Barrier(2)
            results = []

            def contender():
                barrier.wait()
                try:
                    results.append(claim(attempt))
                except (FileExistsError, RuntimeError):
                    results.append(None)

            threads = [threading.Thread(target=contender) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            owners = [result for result in results if result is not None]
            self.assertEqual(1, len(owners))
            self.assertTrue(owners[0].verify(attempt))
            owners[0].close()

    def test_mutated_claim_or_prepared_source_cannot_terminalize(self):
        for target in ("attempt-consumed.json", "authorization.json"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as name:
                attempt = self.prepared(Path(name))
                capability = claim(attempt)
                (attempt / target).write_text("changed\n", encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "claim changed"):
                    terminalize(
                        attempt,
                        claim=capability,
                        outcome="failed",
                        teardown={
                            "processes_reaped": True,
                            "qmp_closed": True,
                            "runtime_quiescent": True,
                            "owned_media_closed": True,
                            "dependencies_released": True,
                        },
                    )
                capability.close()

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
                capability = claim(attempt)
                terminalize(
                    attempt,
                    claim=capability,
                    outcome="succeeded",
                    teardown={
                        "processes_reaped": True,
                        "qmp_closed": True,
                        "runtime_quiescent": True,
                        "owned_media_closed": True,
                        "dependencies_released": True,
                    },
                )
                capability.close()
            self.assertEqual(4, len(calls))

    def test_post_link_sync_failure_retains_reconcilable_capability(self):
        from homelab.vm import windows_identity_attempt as subject
        with tempfile.TemporaryDirectory() as name:
            attempt = self.prepared(Path(name))
            real_fsync = os.fsync
            count = 0

            def fail_directory_sync(descriptor):
                nonlocal count
                count += 1
                if count == 2:
                    raise OSError("private")
                return real_fsync(descriptor)

            from unittest import mock
            with mock.patch.object(
                subject.os, "fsync", side_effect=fail_directory_sync,
            ):
                with self.assertRaises(subject._ClaimPublicationError) as caught:
                    claim(attempt)
            self.assertTrue(caught.exception.claim.verify(attempt))
            terminalize(
                attempt,
                claim=caught.exception.claim,
                outcome="failed",
                teardown={
                    "processes_reaped": True,
                    "qmp_closed": True,
                    "runtime_quiescent": True,
                    "owned_media_closed": True,
                    "dependencies_released": True,
                },
            )
            caught.exception.claim.close()
            self.assertTrue((attempt / TEARDOWN_NAME).is_file())


if __name__ == "__main__":
    unittest.main()
