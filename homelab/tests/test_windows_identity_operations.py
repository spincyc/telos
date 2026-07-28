import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm import windows_identity_operations
from homelab.vm.windows_identity_operations import (
    execute_production_identity_acceptance,
)
from homelab.vm.windows_identity_progressive import (
    ProgressiveRotationReceipt,
)
from homelab.vm.windows_identity_run import (
    IdentityFailureDiagnostic,
    PrivateIdentityMaterial,
    WindowsIdentityRunError,
)


class WindowsIdentityOperationsTests(unittest.TestCase):
    def material(self, events):
        return PrivateIdentityMaterial(
            Path("/private/publication.iso"),
            Path("/private"),
            rotate_guest=mock.Mock(),
            stage_principals=lambda values: events.append(
                ("stage", dict(values))),
            destroy_principals=lambda names: events.append(
                ("destroy", names)),
        )

    def test_scoped_acceptance_retains_then_releases_credentials(self):
        events = []
        material = self.material(events)
        replacement = material.generate_replacement_credential()

        def acceptance(local, principals):
            self.assertIs(local, replacement)
            self.assertEqual(
                {"student", "operator", "directory-admin"}, set(principals))
            with self.assertRaises(TypeError):
                principals["student"] = "replacement"
            self.assertIs(material._new_local, replacement)
            events.append(("accept", local, dict(principals)))

        material.run_scoped_acceptance(replacement, acceptance)
        self.assertEqual(["stage", "accept", "destroy"], [
            event[0] for event in events])
        self.assertIsNone(material._new_local)
        self.assertEqual({}, material._principals)

    def test_scoped_acceptance_retains_ownership_when_destroy_fails(self):
        material = PrivateIdentityMaterial(
            Path("/private/publication.iso"),
            Path("/private"),
            rotate_guest=mock.Mock(),
            stage_principals=mock.Mock(),
            destroy_principals=mock.Mock(
                side_effect=RuntimeError("private credential value")),
        )
        replacement = material.generate_replacement_credential()
        with self.assertRaisesRegex(
                WindowsIdentityRunError,
                "principal destruction: RuntimeError"):
            material.run_scoped_acceptance(
                replacement, lambda _local, _principals: None)
        self.assertIs(material._new_local, replacement)
        self.assertTrue(material._principals)

    def test_scoped_acceptance_preserves_validated_non_run_error_diagnostic(self):
        class CarrierError(RuntimeError):
            def __init__(self, diagnostic):
                super().__init__("private carrier message")
                self.diagnostic = diagnostic

        diagnostic = IdentityFailureDiagnostic.join_guest(
            "marker-receive", "TimeoutError")
        material = self.material([])
        replacement = material.generate_replacement_credential()
        with self.assertRaises(WindowsIdentityRunError) as caught:
            material.run_scoped_acceptance(
                replacement,
                lambda _local, _principals: (
                    _ for _ in ()).throw(CarrierError(diagnostic)),
            )
        self.assertIs(caught.exception.diagnostic, diagnostic)
        self.assertIn(diagnostic.render(), str(caught.exception))
        self.assertNotIn("private carrier message", str(caught.exception))

    def test_composition_runs_acceptance_inside_progressive_callback(self):
        boundary = mock.Mock()
        plan = mock.Mock()
        events = []

        def progressive(**kwargs):
            replacement = kwargs["generate_credential"]()
            events.append("rotation")
            kwargs["after_rotation"](replacement)
            events.append("rotation-return")
            return ProgressiveRotationReceipt(
                phases=("replacement-credential-sign-in-proved",),
                publication_destroyed=True,
                replacement_sign_in_proved=True,
            )

        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            windows_identity_operations,
            "execute_progressive_rotation",
            side_effect=progressive,
        ), mock.patch.object(
            windows_identity_operations,
            "NativeBoundaryRotationSession",
            return_value=mock.Mock(),
        ):
            receipt = execute_production_identity_acceptance(
                boundary=boundary,
                plan=plan,
                publication=Path(name) / "publication.iso",
                private_parent=Path(name),
                stage_principals=lambda _values: events.append("stage"),
                destroy_principals=lambda _names: events.append("destroy"),
                run_acceptance=lambda local, principals: events.append(
                    ("accept", bool(local), tuple(principals))),
            )

        self.assertEqual(
            ["rotation", "stage", "accept", "destroy", "rotation-return"],
            [event[0] if isinstance(event, tuple) else event
             for event in events],
        )
        self.assertTrue(receipt.acceptance_complete)
        self.assertTrue(receipt.credentials_released)

    def test_production_composition_preserves_typed_join_diagnostic(self):
        diagnostic = IdentityFailureDiagnostic.join_material(
            "stage", "shell-prompt", "TimeoutError")

        def progressive(**kwargs):
            replacement = kwargs["generate_credential"]()
            kwargs["after_rotation"](replacement)

        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            windows_identity_operations,
            "execute_progressive_rotation",
            side_effect=progressive,
        ), mock.patch.object(
            windows_identity_operations,
            "NativeBoundaryRotationSession",
            return_value=mock.Mock(),
        ), self.assertRaises(WindowsIdentityRunError) as caught:
            execute_production_identity_acceptance(
                boundary=mock.Mock(
                    controller_overlay=None, processes={}),
                plan=mock.Mock(),
                publication=Path(name) / "publication.iso",
                private_parent=Path(name),
                stage_principals=mock.Mock(),
                destroy_principals=mock.Mock(),
                run_acceptance=lambda _local, _principals: (
                    _ for _ in ()).throw(WindowsIdentityRunError(
                        "private join message", diagnostic=diagnostic)),
            )

        error = caught.exception
        self.assertIs(error.diagnostic, diagnostic)
        self.assertIn(diagnostic.render(), str(error))
        self.assertNotIn("private join message", str(error))
        self.assertIsNone(error.__cause__)


if __name__ == "__main__":
    unittest.main()
