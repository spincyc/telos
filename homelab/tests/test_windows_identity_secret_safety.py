import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm import windows_identity_receipt
from homelab.vm.windows_identity_run import (
    IdentityOperations,
    NativeProcessBoundary,
    PrivateIdentityMaterial,
    WindowsIdentityRunError,
    run_lifecycle,
)
from homelab.tests.windows_identity_fixture import (
    write_prepared_authorization,
)


SECRETS = (
    "RecoveredLocal-DoNotDisclose-47!",
    "ReplacementLocal-DoNotDisclose-48!",
    "Student-DoNotDisclose-49!",
    "Operator-DoNotDisclose-50!",
    "DirectoryAdmin-DoNotDisclose-51!",
)


def assert_secret_free(test: unittest.TestCase, value: object) -> None:
    encoded = value if isinstance(value, bytes) else str(value).encode()
    for secret in SECRETS:
        test.assertNotIn(secret.encode(), encoded)


class SecretBearingOperation:
    """A hostile adapter whose failure and representation contain a secret."""

    def __init__(self, secret: str, *, fail: bool = False) -> None:
        self.secret = secret
        self.fail = fail

    def __repr__(self) -> str:
        return f"SecretBearingOperation(secret={self.secret!r})"

    def __call__(self) -> None:
        if self.fail:
            raise RuntimeError(f"adapter rejected {self.secret}")


class WindowsIdentitySecretSafetyTests(unittest.TestCase):
    def operations(self, *, failing: str | None = None) -> IdentityOperations:
        names = (
            "start_switch",
            "start_controller",
            "start_windows",
            "authenticate_qmp",
            "rotate_local_credential",
            "destroy_private_publication",
            "stage_controller_principals",
            "run_acceptance_phases",
            "destroy_controller_principals",
            "stop_windows",
            "stop_controller",
            "stop_switch",
        )
        return IdentityOperations(**{
            name: SecretBearingOperation(
                SECRETS[index % len(SECRETS)], fail=name == failing)
            for index, name in enumerate(names)
        })

    def private_boundary(self, root: Path) -> NativeProcessBoundary:
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
            path.write_bytes(b"public fixture")
            path.chmod(0o600)
        write_prepared_authorization(attempt, controller)
        return NativeProcessBoundary(attempt, controller)

    def test_errors_and_operation_reprs_never_echo_adapter_secrets(self):
        operations = self.operations(failing="run_acceptance_phases")
        assert_secret_free(self, repr(operations))
        with self.assertRaises(WindowsIdentityRunError) as caught:
            run_lifecycle(operations)
        assert_secret_free(self, str(caught.exception))
        assert_secret_free(self, repr(caught.exception))

    def test_material_repr_and_receipt_never_retain_supplied_secrets(self):
        recovered = mock.MagicMock()
        recovered.__enter__.return_value = SECRETS[0]
        generated = iter(SECRETS[1:])
        observed: list[object] = []
        with mock.patch(
                "homelab.vm.windows_identity_run.RecoveredLocalCredential",
                return_value=recovered), mock.patch.object(
                    PrivateIdentityMaterial, "_credential",
                    side_effect=lambda: next(generated)):
            material = PrivateIdentityMaterial(
                Path("/private/publication.iso"),
                Path("/private"),
                rotate_guest=lambda old, new: observed.append((old, new)),
                stage_principals=lambda principals: observed.append(
                    dict(principals)),
                destroy_principals=lambda names: observed.append(tuple(names)),
            )
            material.rotate_local_credential()
            material.destroy_private_publication()
            material.stage_controller_principals()
            assert_secret_free(self, repr(material))
            material.destroy_controller_principals()
            material.close()

        receipt = run_lifecycle(self.operations())
        assert_secret_free(self, repr(receipt))
        assert_secret_free(self, windows_identity_receipt.serialize(receipt))
        self.assertTrue(observed)

    def test_native_commands_and_retained_artifacts_are_secret_free(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            boundary = self.private_boundary(root)
            commands: list[list[str]] = []

            def popen(command, **_kwargs):
                commands.append([str(part) for part in command])
                process = mock.MagicMock()
                process.pid = 4242
                process.poll.return_value = None
                return process

            overlay = mock.MagicMock()
            overlay.disk = root / "controller-overlay.raw"
            overlay.vars = root / "controller-vars.fd"
            overlay.disk.write_bytes(b"public overlay")
            overlay.vars.write_bytes(b"public variables")
            factory = mock.Mock()
            factory.output = root / "factory.iso"
            factory.password = "private"
            factory.build.side_effect = lambda: factory.output.write_bytes(
                b"private factory media")
            factory.close.side_effect = lambda: factory.output.unlink(
                missing_ok=True)
            with mock.patch(
                    "homelab.vm.windows_identity_run.subprocess.Popen",
                    side_effect=popen), mock.patch(
                    "homelab.vm.windows_identity_run.wait_for_switch_port"), \
                    mock.patch(
                        "homelab.vm.windows_identity_run.audit_live_process"), \
                    mock.patch(
                        "homelab.vm.windows_identity_run.SerialAutomation"), \
                    mock.patch(
                        "homelab.vm.windows_identity_run.FactoryBundle",
                        return_value=factory), \
                    mock.patch(
                        "homelab.vm.windows_identity_run.QmpClient.connect"), \
                    mock.patch.object(
                        boundary, "_process_holds_inode",
                        side_effect=(True, False, True, False, True)), \
                    mock.patch(
                        "homelab.vm.windows_identity_run.DisposableBootDisk"
                    ) as boot_disk:
                boot_disk.return_value.prepare.return_value = overlay
                boundary.start_switch()
                boundary.start_controller()
                boundary.start_windows()

            try:
                assert_secret_free(self, commands)
                for artifact in root.rglob("*"):
                    if artifact.is_file():
                        assert_secret_free(self, artifact.read_bytes())
            finally:
                boundary.processes.clear()
                boundary._cleanup_qmp_root()


if __name__ == "__main__":
    unittest.main()
