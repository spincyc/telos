import unittest
import json
import tempfile
from pathlib import Path
from unittest import mock

from homelab.vm import windows_identity_run
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


class Recorder:
    def __init__(self, failure=None):
        self.events = []
        self.failure = failure

    def operation(self, name):
        def invoke():
            self.events.append(name)
            if self.failure == name:
                raise RuntimeError("private failure")
        return invoke

    def operations(self):
        names = (
            "start_switch", "start_controller", "start_windows",
            "authenticate_qmp", "rotate_local_credential",
            "destroy_private_publication", "stage_controller_principals",
            "run_acceptance_phases", "destroy_controller_principals",
            "stop_windows", "stop_controller", "stop_switch",
        )
        return IdentityOperations(**{
            name: self.operation(name) for name in names})


class WindowsIdentityRunTests(unittest.TestCase):
    def native_boundary(self, root):
        attempt = root / "attempt"
        state = root / "controller"
        attempt.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        for path in (
                attempt / "windows.qcow2",
                attempt / "OVMF_VARS.fd",
                state / "bootstrap-dc.qcow2",
                state / "OVMF_VARS.fd",
        ):
            path.write_bytes(path.name.encode())
            path.chmod(0o600)
        write_prepared_authorization(attempt, state)
        return NativeProcessBoundary(attempt, state)

    def test_native_boundary_requires_private_prepared_isolation(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            boundary = self.native_boundary(root)
            boundary._validate()
            authorization = boundary.attempt / "authorization.json"
            value = json.loads(authorization.read_text(encoding="utf-8"))
            value["pxe_boot_enabled"] = True
            authorization.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(
                    WindowsIdentityRunError, "native isolation"):
                boundary._validate()

    def test_native_boundary_rejects_nonprivate_attempt(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.native_boundary(Path(name))
            boundary.attempt.chmod(0o755)
            with self.assertRaisesRegex(
                    WindowsIdentityRunError, "private real directory"):
                boundary._validate()

    def test_private_material_rotates_before_destroying_and_staging(self):
        events = []
        recovery = mock.MagicMock()
        recovery.__enter__.return_value = "old-private-value"
        with mock.patch.object(
                windows_identity_run, "RecoveredLocalCredential",
                return_value=recovery):
            material = PrivateIdentityMaterial(
                Path("/private/publication.iso"), Path("/private"),
                rotate_guest=lambda old, new: events.append(
                    ("rotate", old, new)),
                stage_principals=lambda values: events.append(
                    ("stage", dict(values))),
                destroy_principals=lambda names: events.append(
                    ("destroy", names)),
            )
            material.rotate_local_credential()
            old, new = events[0][1:]
            self.assertEqual("old-private-value", old)
            self.assertNotEqual(old, new)
            material.destroy_private_publication()
            recovery.destroy_publication.assert_called_once_with()
            self.assertIsNone(material._old_local)
            self.assertIsNone(material._new_local)
            self.assertIsNone(material._recovery_context)
            material.stage_controller_principals()
            staged = events[1][1]
            self.assertEqual(
                {"student", "operator", "directory-admin"}, set(staged))
            self.assertEqual(3, len(set(staged.values())))
            self.assertNotIn(old, staged.values())
            self.assertNotIn(new, staged.values())
            material.destroy_controller_principals()
            self.assertEqual(
                ("student", "operator", "directory-admin"), events[2][1])
            material.close()

    def test_private_material_preserves_publication_when_rotation_fails(self):
        recovery = mock.MagicMock()
        recovery.__enter__.return_value = "old-private-value"
        with mock.patch.object(
                windows_identity_run, "RecoveredLocalCredential",
                return_value=recovery):
            material = PrivateIdentityMaterial(
                Path("/private/publication.iso"), Path("/private"),
                rotate_guest=mock.Mock(side_effect=RuntimeError("failed")),
                stage_principals=mock.Mock(),
                destroy_principals=mock.Mock(),
            )
            with self.assertRaises(RuntimeError):
                material.rotate_local_credential()
            recovery.destroy_publication.assert_not_called()
            recovery.__exit__.assert_called_once()

    def test_cleanup_only_failure_preserves_safe_diagnostic(self):
        diagnostic = windows_identity_run.IdentityFailureDiagnostic.static_probe(
            "controller-ready",
            "controller-readiness",
            OSError("private-cleanup-message"),
            phase="outcome-receive",
        )
        material = PrivateIdentityMaterial(
            Path("/private/publication.iso"),
            Path("/private"),
            rotate_guest=mock.Mock(),
            stage_principals=mock.Mock(),
            destroy_principals=mock.Mock(side_effect=WindowsIdentityRunError(
                "private-cleanup-message", diagnostic=diagnostic)),
        )
        material._new_local = "replacement"
        with self.assertRaises(WindowsIdentityRunError) as caught:
            material.run_scoped_acceptance(
                material._new_local, lambda _local, _principals: None)
        self.assertIs(diagnostic, caught.exception.diagnostic)
        self.assertIn(diagnostic.render(), str(caught.exception))
        self.assertNotIn("private-cleanup-message", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_secret_and_destruction_boundaries_have_one_order(self):
        recorder = Recorder()
        receipt = run_lifecycle(recorder.operations())
        self.assertEqual([
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
        ], recorder.events)
        self.assertTrue(receipt.private_publication_destroyed)
        self.assertTrue(receipt.controller_principals_destroyed)
        self.assertTrue(receipt.teardown_complete)

    def test_rotation_failure_never_destroys_publication_or_stages_principals(self):
        recorder = Recorder("rotate_local_credential")
        with self.assertRaisesRegex(
                WindowsIdentityRunError, "lifecycle: RuntimeError"):
            run_lifecycle(recorder.operations())
        self.assertNotIn("destroy_private_publication", recorder.events)
        self.assertNotIn("stage_controller_principals", recorder.events)
        self.assertEqual(
            ["stop_windows", "stop_controller", "stop_switch"],
            recorder.events[-3:])

    def test_staged_principals_are_destroyed_after_acceptance_failure(self):
        recorder = Recorder("run_acceptance_phases")
        with self.assertRaises(WindowsIdentityRunError):
            run_lifecycle(recorder.operations())
        self.assertIn("destroy_controller_principals", recorder.events)
        self.assertEqual(
            ["stop_windows", "stop_controller", "stop_switch"],
            recorder.events[-3:])

    def test_cleanup_failure_is_not_hidden(self):
        recorder = Recorder("stop_controller")
        with self.assertRaisesRegex(
                WindowsIdentityRunError, "controller teardown"):
            run_lifecycle(recorder.operations())


if __name__ == "__main__":
    unittest.main()
