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


if __name__ == "__main__":
    unittest.main()
