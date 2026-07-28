from pathlib import Path
import tempfile
import unittest
from unittest import mock

from homelab.vm import windows_identity_cli
from homelab.tests.windows_identity_fixture import (
    write_prepared_authorization,
)
from homelab.vm.windows_identity_run import IdentityReceipt


class WindowsIdentityCliTests(unittest.TestCase):
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

    def test_default_is_validating_dry_run(self):
        with tempfile.TemporaryDirectory() as name:
            attempt, controller = self.private_attempt(Path(name))
            with mock.patch("builtins.print") as output:
                result = windows_identity_cli.main([
                    "--attempt", str(attempt),
                    "--controller-state", str(controller),
                ])
        self.assertEqual(0, result)
        self.assertIn(
            "dry run; repeat with --apply",
            " ".join(str(call) for call in output.call_args_list),
        )

    def test_apply_delegates_to_core_lifecycle(self):
        with tempfile.TemporaryDirectory() as name:
            attempt, controller = self.private_attempt(Path(name))
            operations = mock.sentinel.operations
            factory = mock.Mock(return_value=operations)
            with mock.patch.object(
                windows_identity_cli, "run_lifecycle",
                return_value=IdentityReceipt(),
            ) as lifecycle:
                result = windows_identity_cli.main(
                    [
                        "--attempt", str(attempt),
                        "--controller-state", str(controller),
                        "--apply",
                    ],
                    operations_factory=factory,
                )
        self.assertEqual(0, result)
        factory.assert_called_once()
        lifecycle.assert_called_once_with(operations)

    def test_apply_without_live_adapter_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            attempt, controller = self.private_attempt(Path(name))
            result = windows_identity_cli.main([
                "--attempt", str(attempt),
                "--controller-state", str(controller),
                "--apply",
            ])
        self.assertEqual(2, result)


if __name__ == "__main__":
    unittest.main()
