import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from homelab.vm.windows_identity_reference import (
    GuestProvenance,
    WindowsIdentityReferenceError,
    load_identity_reference,
    verify_reference_sources,
)


REFERENCE_ROOT = (
    Path(__file__).parents[1]
    / "vm/windows_identity_references/windows-11-25h2-en-us-1280x800"
)


class WindowsIdentityReferenceTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(
            (REFERENCE_ROOT / "sign-in.json").read_text())
        self.image = (REFERENCE_ROOT / "sign-in.ppm").read_bytes()

    def staged(self, mutate=lambda _: None):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        manifest = copy.deepcopy(self.manifest)
        mutate(manifest)
        (root / "sign-in.json").write_text(json.dumps(manifest))
        (root / "sign-in.ppm").write_bytes(self.image)
        self.addCleanup(temporary.cleanup)
        return root / "sign-in.json"

    def test_checked_in_sign_in_reference_validates(self):
        reference = load_identity_reference(REFERENCE_ROOT / "sign-in.json")

        self.assertEqual((1280, 800), reference.geometry)
        self.assertEqual((460, 150, 360, 360), reference.crop)
        self.assertEqual((360, 360), (
            reference.image.width, reference.image.height))
        self.assertIn("telosadmin", reference.state)
        self.assertEqual("sign-in", reference.state_kind)
        self.assertFalse(reference.captured_after_private_input)
        self.assertFalse(reference.contains_private_material)
        self.assertEqual("Windows 11 25H2", reference.guest.release)

    def test_checked_in_navigation_references_are_public_and_guest_bound(self):
        expected_kinds = {
            "desktop": "desktop",
            "security-options": "security-options",
            "change-password": "change-password",
        }
        sign_in = load_identity_reference(REFERENCE_ROOT / "sign-in.json")
        for name, kind in expected_kinds.items():
            with self.subTest(name=name):
                reference = load_identity_reference(
                    REFERENCE_ROOT / f"{name}.json",
                    expected_guest=sign_in.guest,
                )
                self.assertEqual(kind, reference.state_kind)
                self.assertTrue(reference.captured_after_private_input)
                self.assertFalse(reference.contains_private_material)

    def test_operational_load_binds_reference_to_expected_guest(self):
        expected = GuestProvenance(
            release="Windows 11 25H2",
            language="en-US",
            architecture="x86_64",
            installer_iso_sha256=(
                "768984706b909479417b2368438909440f2967ff05c6a9195ed2667254e465e3"
            ),
            source_disk_sha256=(
                "eb002be58d216908e5724512682523f70f4f1afeaa6d93ad9de9c942dc11977d"
            ),
        )
        reference = load_identity_reference(
            REFERENCE_ROOT / "sign-in.json", expected_guest=expected)
        self.assertEqual(expected, reference.guest)

        # A DIFFERENT install disk is accepted: the GUI is version-determined,
        # so references are portable across fresh installs of the same Windows
        # version (the disk sha is capture provenance, not a runtime gate).
        other_disk = GuestProvenance(
            **{**expected.__dict__, "source_disk_sha256": "0" * 64})
        portable = load_identity_reference(
            REFERENCE_ROOT / "sign-in.json", expected_guest=other_disk)
        self.assertEqual(reference.image, portable.image)

        # A different Windows VERSION (installer ISO) is still rejected.
        wrong_version = GuestProvenance(
            **{**expected.__dict__, "installer_iso_sha256": "1" * 64})
        with self.assertRaisesRegex(
                WindowsIdentityReferenceError, "does not match prepared guest"):
            load_identity_reference(
                REFERENCE_ROOT / "sign-in.json",
                expected_guest=wrong_version,
            )

    def test_rejects_reference_hash_or_path_substitution(self):
        manifest = self.staged(
            lambda value: value["reference"].update({"sha256": "0" * 64}))
        with self.assertRaisesRegex(
                WindowsIdentityReferenceError, "hash mismatch"):
            load_identity_reference(manifest)

        manifest = self.staged(
            lambda value: value["reference"].update({"file": "../sign-in.ppm"}))
        with self.assertRaisesRegex(
                WindowsIdentityReferenceError, "unsafe reference filename"):
            load_identity_reference(manifest)

    def test_rejects_credential_bearing_or_unstable_capture_claims(self):
        manifest = self.staged(
            lambda value: value.update({"credential_entered": True}))
        with self.assertRaisesRegex(
                WindowsIdentityReferenceError, "precede credential entry"):
            load_identity_reference(manifest)

        manifest = self.staged(
            lambda value: value["capture"][
                "stable_source_frame_sha256"].__setitem__(1, "0" * 64))
        with self.assertRaisesRegex(
                WindowsIdentityReferenceError, "not byte-stable"):
            load_identity_reference(manifest)

    def test_navigation_schema_distinguishes_timing_from_private_content(self):
        manifest = self.staged()
        document = json.loads(manifest.read_text())
        document.pop("credential_entered")
        document.update({
            "schema": 2,
            "state": "focused local change-password form",
            "state_kind": "change-password",
            "captured_after_private_input": True,
            "contains_private_material": False,
        })
        manifest.write_text(json.dumps(document))

        reference = load_identity_reference(manifest)
        self.assertEqual("change-password", reference.state_kind)
        self.assertTrue(reference.captured_after_private_input)
        self.assertFalse(reference.contains_private_material)

        document["contains_private_material"] = True
        manifest.write_text(json.dumps(document))
        with self.assertRaisesRegex(
                WindowsIdentityReferenceError, "private material"):
            load_identity_reference(manifest)

    def test_navigation_schema_accepts_public_run_dialog_reference(self):
        manifest = self.staged()
        document = json.loads(manifest.read_text())
        document.pop("credential_entered")
        document.update({
            "schema": 2,
            "state": "focused Windows Run dialog",
            "state_kind": "run-dialog",
            "captured_after_private_input": True,
            "contains_private_material": False,
        })
        manifest.write_text(json.dumps(document))

        reference = load_identity_reference(manifest)

        self.assertEqual("run-dialog", reference.state_kind)
        self.assertFalse(reference.contains_private_material)

    def test_rejects_geometry_or_reference_drift(self):
        manifest = self.staged(
            lambda value: value["capture"].update(
                {"crop": [1100, 700, 360, 360]}))
        with self.assertRaisesRegex(
                WindowsIdentityReferenceError, "outside its geometry"):
            load_identity_reference(manifest)

        manifest = self.staged()
        image = manifest.parent / "sign-in.ppm"
        image.write_bytes(self.image[:-1] + bytes([self.image[-1] ^ 1]))
        with self.assertRaisesRegex(
                WindowsIdentityReferenceError, "hash mismatch"):
            load_identity_reference(manifest)

    def test_source_verification_requires_exact_full_frame_and_crop(self):
        reference = load_identity_reference(REFERENCE_ROOT / "sign-in.json")
        header = f"P6\n1280 800\n255\n".encode()
        rows = bytearray(1280 * 800 * 3)
        for row in range(reference.image.height):
            source_start = ((150 + row) * 1280 + 460) * 3
            crop_start = row * reference.image.width * 3
            crop_end = crop_start + reference.image.width * 3
            rows[source_start:source_start + reference.image.width * 3] = (
                reference.image.pixels[crop_start:crop_end])
        frame = header + rows
        digest = hashlib.sha256(frame).hexdigest()
        source_reference = copy.deepcopy(self.manifest)
        source_reference["capture"]["stable_source_frame_sha256"] = [
            digest, digest, digest,
        ]
        source_reference["reference"]["sha256"] = hashlib.sha256(
            self.image).hexdigest()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sign-in.json").write_text(json.dumps(source_reference))
            (root / "sign-in.ppm").write_bytes(self.image)
            frames = []
            for index in range(3):
                path = root / f"source-{index}.ppm"
                path.write_bytes(frame)
                frames.append(path)
            verify_reference_sources(
                load_identity_reference(root / "sign-in.json"), frames)
            frames[-1].write_bytes(frame[:-1] + b"\x01")
            with self.assertRaisesRegex(
                    WindowsIdentityReferenceError, "source frame hash mismatch"):
                verify_reference_sources(
                    load_identity_reference(root / "sign-in.json"), frames)


if __name__ == "__main__":
    unittest.main()
