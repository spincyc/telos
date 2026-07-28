from pathlib import Path
import unittest

from homelab.vm.windows_identity_calibration import (
    CalibrationStage,
    TrustedIdentityReferences,
    WindowsIdentityCalibrationError,
)


class WindowsIdentityCalibrationTests(unittest.TestCase):
    def test_empty_set_authorizes_only_public_sign_in_capture(self):
        references = TrustedIdentityReferences()

        self.assertEqual(
            CalibrationStage.CAPTURE_SIGN_IN,
            references.stage(),
        )
        with self.assertRaisesRegex(
                WindowsIdentityCalibrationError, "do not authorize rotation"):
            references.rotation_reference_paths()

    def test_reviewed_sign_in_unlocks_navigation_calibration(self):
        references = TrustedIdentityReferences(sign_in=Path("sign-in.ppm"))

        self.assertEqual(
            CalibrationStage.CAPTURE_NAVIGATION,
            references.stage(),
        )

    def test_partial_navigation_promotion_fails_closed(self):
        references = TrustedIdentityReferences(
            sign_in=Path("sign-in.ppm"),
            desktop=Path("desktop.ppm"),
        )

        with self.assertRaisesRegex(
                WindowsIdentityCalibrationError, "one reviewed set"):
            references.stage()

    def test_navigation_cannot_precede_sign_in_authority(self):
        references = TrustedIdentityReferences(
            desktop=Path("desktop.ppm"),
            security_options=Path("security-options.ppm"),
            change_password=Path("change-password.ppm"),
        )

        with self.assertRaisesRegex(
                WindowsIdentityCalibrationError, "precede sign-in"):
            references.stage()

    def test_four_pre_rotation_references_authorize_rotation(self):
        references = TrustedIdentityReferences(
            sign_in=Path("sign-in.ppm"),
            desktop=Path("desktop.ppm"),
            security_options=Path("security-options.ppm"),
            change_password=Path("change-password.ppm"),
        )

        self.assertEqual(
            CalibrationStage.ROTATE_AND_PROVE,
            references.stage(),
        )
        self.assertEqual(
            (
                Path("sign-in.ppm"),
                Path("desktop.ppm"),
                Path("security-options.ppm"),
                Path("change-password.ppm"),
            ),
            references.rotation_reference_paths(),
        )
        self.assertEqual(
            Path("desktop.ppm"),
            references.final_desktop_reference(),
        )


if __name__ == "__main__":
    unittest.main()
