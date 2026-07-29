import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from homelab.tests.windows_identity_fixture import (
    write_prepared_authorization,
)
from homelab.vm import windows_identity_cli
from homelab.vm.windows_identity_run import (
    NativeProcessBoundary,
    WindowsIdentityRunError,
)


class WindowsIdentityAttemptCompositionTests(unittest.TestCase):
    def private_attempt(self, root: Path) -> tuple[Path, Path]:
        attempt = root / "attempt"
        controller = root / "controller"
        attempt.mkdir(mode=0o700)
        controller.mkdir(mode=0o700)
        for path in (
            attempt / "windows.qcow2",
            attempt / "OVMF_VARS.fd",
            controller / "bootstrap-dc.qcow2",
            controller / "OVMF_VARS.fd",
        ):
            path.write_bytes(b"fixture")
            path.chmod(0o600)
        write_prepared_authorization(attempt, controller)
        return attempt, controller

    def test_cli_claim_is_accepted_once_by_its_boundary_and_replay_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as name:
            attempt, controller = self.private_attempt(Path(name))
            configuration = mock.Mock()
            for field in (
                "rotation_plan", "publication", "private_root", "evidence",
                "realm", "callbacks", "stage_principals",
                "destroy_principals", "stage_join_principal",
                "destroy_join_principal",
            ):
                setattr(configuration, field, mock.sentinel.configuration)
            factory = mock.Mock(return_value=configuration)

            def acceptance(**arguments):
                owner = arguments["boundary"]
                claim = attempt / "attempt-consumed.json"
                claim_sha256 = hashlib.sha256(claim.read_bytes()).hexdigest()
                self.assertEqual(claim_sha256, owner.attempt_claim.digest)

                # This is the first operation performed by start_switch().
                owner._validate()

                # Before a terminal receipt exists, the same durable claim
                # rejects a fresh boundary that has no ownership capability.
                self.assertFalse(
                    (attempt / "terminal-teardown.json").exists())
                replay = NativeProcessBoundary(attempt, controller)
                with self.assertRaisesRegex(
                    WindowsIdentityRunError, "already consumed",
                ):
                    replay._validate()

            argv = [
                "--attempt", str(attempt),
                "--controller-state", str(controller),
                "--apply",
            ]
            with mock.patch.object(
                windows_identity_cli,
                "execute_windows_identity_acceptance",
                side_effect=acceptance,
            ) as execute:
                first_stdout = io.StringIO()
                first_stderr = io.StringIO()
                with contextlib.redirect_stdout(first_stdout), (
                    contextlib.redirect_stderr(first_stderr)
                ):
                    first = windows_identity_cli.main(
                        argv, acceptance_factory=factory)

                claim_bytes = (
                    attempt / "attempt-consumed.json").read_bytes()
                terminal_bytes = (
                    attempt / "terminal-teardown.json").read_bytes()
                terminal = json.loads(terminal_bytes)

                second_stdout = io.StringIO()
                second_stderr = io.StringIO()
                with contextlib.redirect_stdout(second_stdout), (
                    contextlib.redirect_stderr(second_stderr)
                ):
                    second = windows_identity_cli.main(
                        argv, acceptance_factory=factory)
                replay_claim_bytes = (
                    attempt / "attempt-consumed.json").read_bytes()
                replay_terminal_bytes = (
                    attempt / "terminal-teardown.json").read_bytes()

        self.assertEqual(0, first)
        self.assertEqual("", first_stderr.getvalue())
        self.assertEqual(2, second)
        self.assertEqual("", second_stdout.getvalue())
        self.assertEqual(
            "windows identity run: identity attempt was already consumed\n",
            second_stderr.getvalue(),
        )
        factory.assert_called_once()
        execute.assert_called_once()
        self.assertEqual(
            hashlib.sha256(claim_bytes).hexdigest(),
            terminal["claim_sha256"],
        )
        self.assertEqual("succeeded", terminal["outcome"])
        self.assertTrue(terminal["teardown_complete"])
        self.assertEqual(claim_bytes, replay_claim_bytes)
        self.assertEqual(terminal_bytes, replay_terminal_bytes)


if __name__ == "__main__":
    unittest.main()
