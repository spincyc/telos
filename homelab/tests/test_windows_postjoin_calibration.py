#!/usr/bin/env python3

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from homelab.vm.windows_identity_reference import GuestProvenance
from homelab.vm.windows_postjoin_calibration import (
    CALIBRATION_FRAME_NAME,
    CALIBRATION_RECORD_NAME,
    CALIBRATION_SAMPLE_COUNT,
    MAX_CALIBRATION_FRAME_BYTES,
    WindowsPostJoinCalibrationError,
    capture_post_join_calibration,
    retain_post_join_calibration,
    sample_post_join_calibration,
)


PPM = (
    b"P6\n320 200\n255\n"
    + bytes((0, 0, 0, 255, 255, 255) * (320 * 200 // 2))
)


class FakeQmp:
    def __init__(self, payload: bytes = PPM) -> None:
        self.payload = payload
        self.paths: list[Path] = []

    def screenshot(self, path: Path) -> None:
        self.paths.append(path)
        path.write_bytes(self.payload)


class PostJoinCalibrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "evidence"
        self.root.mkdir(mode=0o700)
        self.guest = GuestProvenance(
            release="Windows 11",
            language="en-US",
            architecture="x86_64",
            installer_iso_sha256="a" * 64,
            source_disk_sha256="b" * 64,
        )

    def test_retains_one_private_frame_and_public_provenance(self):
        qmp = FakeQmp()
        frame, record = capture_post_join_calibration(
            qmp, self.root, self.guest)

        self.assertEqual(frame.name, CALIBRATION_FRAME_NAME)
        self.assertEqual(record.name, CALIBRATION_RECORD_NAME)
        self.assertEqual(frame.read_bytes(), PPM)
        self.assertEqual(frame.stat().st_mode & 0o777, 0o600)
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        document = json.loads(record.read_text())
        self.assertEqual(
            document["phase"],
            "post-join-reauthentication.calibration-required.generic-prompt",
        )
        self.assertEqual(document["state"], "generic-prompt")
        self.assertEqual(document["purpose"], "forensic-review-only")
        self.assertFalse(document["reference_promotion_authorized"])
        self.assertFalse(document["secret_input_since_post_join_reboot"])
        self.assertEqual(document["frame"]["bytes"], len(PPM))
        self.assertEqual(document["frame"]["width"], 320)
        self.assertEqual(document["frame"]["height"], 200)
        self.assertEqual(
            document["frame"]["samples"], CALIBRATION_SAMPLE_COUNT)
        self.assertEqual(document["frame"]["stability_samples"], 1)
        self.assertEqual(len(qmp.paths), CALIBRATION_SAMPLE_COUNT)
        self.assertEqual(document["guest"]["source_disk_sha256"], "b" * 64)
        self.assertFalse(any(path.name.startswith(".") for path in self.root.iterdir()))

    def test_rejects_invalid_stability_sample_count_before_retention(self):
        sampled = sample_post_join_calibration(FakeQmp(), self.root)

        with self.assertRaisesRegex(
            WindowsPostJoinCalibrationError,
            "stability sample count is invalid",
        ):
            retain_post_join_calibration(
                sampled,
                self.root,
                self.guest,
                state="generic-prompt",
                stability_samples=0,
            )

        self.assertEqual(tuple(self.root.iterdir()), ())

    def test_refuses_existing_or_symlink_destination_without_following(self):
        outside = Path(self.temporary.name) / "outside"
        outside.write_bytes(b"unchanged")
        (self.root / CALIBRATION_FRAME_NAME).symlink_to(outside)

        with self.assertRaisesRegex(
            WindowsPostJoinCalibrationError, "already exists"
        ) as caught:
            capture_post_join_calibration(FakeQmp(), self.root, self.guest)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(outside.read_bytes(), b"unchanged")

    def test_rejects_oversize_frame_and_cleans_staging(self):
        qmp = FakeQmp(b"x" * (MAX_CALIBRATION_FRAME_BYTES + 1))
        with self.assertRaisesRegex(
            WindowsPostJoinCalibrationError, "exceeds"
        ):
            capture_post_join_calibration(qmp, self.root, self.guest)
        self.assertEqual(tuple(self.root.iterdir()), ())

    def test_capture_failure_cleans_staging_and_final_evidence(self):
        qmp = mock.Mock()
        qmp.screenshot.side_effect = OSError("backend detail")
        with self.assertRaisesRegex(
            WindowsPostJoinCalibrationError,
            "post-join calibration capture failed",
        ) as caught:
            capture_post_join_calibration(qmp, self.root, self.guest)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(tuple(self.root.iterdir()), ())

    def test_parse_failure_has_no_backend_cause_or_context(self):
        with self.assertRaisesRegex(
            WindowsPostJoinCalibrationError, "not binary PPM"
        ) as caught:
            capture_post_join_calibration(
                FakeQmp(b"backend-private-path"), self.root, self.guest)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("backend-private-path", str(caught.exception))

    def test_write_failure_has_no_backend_cause_or_context(self):
        with mock.patch(
            "homelab.vm.windows_postjoin_calibration.os.write",
            side_effect=OSError("backend-private-path"),
        ):
            with self.assertRaisesRegex(
                WindowsPostJoinCalibrationError,
                "calibration evidence write failed",
            ) as caught:
                capture_post_join_calibration(
                    FakeQmp(), self.root, self.guest)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("backend-private-path", str(caught.exception))
        self.assertEqual(tuple(self.root.iterdir()), ())

    def test_retention_filesystem_failure_is_sanitized_and_cleans_outputs(self):
        with mock.patch(
            "homelab.vm.windows_postjoin_calibration.os.fsync",
            side_effect=(None, None, OSError("backend-private-path")),
        ):
            with self.assertRaisesRegex(
                WindowsPostJoinCalibrationError,
                "post-join calibration capture failed",
            ) as caught:
                capture_post_join_calibration(
                    FakeQmp(), self.root, self.guest)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("backend-private-path", str(caught.exception))
        self.assertEqual(tuple(self.root.iterdir()), ())

    def test_rejects_backend_replacement_of_exclusive_staging_inode(self):
        qmp = FakeQmp()

        def replace(path):
            path.unlink()
            path.write_bytes(PPM)

        qmp.screenshot = replace
        with self.assertRaisesRegex(
            WindowsPostJoinCalibrationError, "staging identity changed"
        ):
            capture_post_join_calibration(qmp, self.root, self.guest)
        self.assertEqual(tuple(self.root.iterdir()), ())

    def test_password_target_uses_distinct_exclusive_evidence_names(self):
        frame, record = capture_post_join_calibration(
            FakeQmp(), self.root, self.guest, state="password-target")
        self.assertEqual(frame.name, "post-join-password-target.ppm")
        self.assertEqual(record.name, "post-join-password-target.json")
        self.assertEqual(json.loads(record.read_text())["state"], "password-target")

    def test_operator_targets_use_distinct_exclusive_evidence_names(self):
        for state in (
            "operator-generic-prompt",
            "operator-password-target",
        ):
            with self.subTest(state=state):
                state_root = self.root / state
                state_root.mkdir(mode=0o700)
                frame, record = capture_post_join_calibration(
                    FakeQmp(), state_root, self.guest, state=state)
                self.assertEqual(frame.name, f"post-join-{state}.ppm")
                self.assertEqual(record.name, f"post-join-{state}.json")
                document = json.loads(record.read_text())
                self.assertEqual(document["state"], state)
                self.assertEqual(
                    document["phase"],
                    "post-join-reauthentication.calibration-required."
                    f"{state}",
                )
                self.assertFalse(
                    document["secret_input_since_post_join_reboot"])

    def test_rejects_unallowlisted_state_before_retention(self):
        sampled = sample_post_join_calibration(FakeQmp(), self.root)

        with self.assertRaisesRegex(
            WindowsPostJoinCalibrationError,
            "calibration state is not allowlisted",
        ):
            retain_post_join_calibration(
                sampled,
                self.root,
                self.guest,
                state="operator-arbitrary-target",
            )

        self.assertEqual(tuple(self.root.iterdir()), ())

    def test_requires_exact_private_real_directory(self):
        os.chmod(self.root, 0o755)
        with self.assertRaisesRegex(
            WindowsPostJoinCalibrationError, "private real directory"
        ):
            capture_post_join_calibration(FakeQmp(), self.root, self.guest)


if __name__ == "__main__":
    unittest.main()
