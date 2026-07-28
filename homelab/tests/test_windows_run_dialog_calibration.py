import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.tests.test_windows_identity_navigation import ppm
from homelab.tests.test_windows_identity_reference import REFERENCE_ROOT
from homelab.vm import windows_run_dialog_calibration_cli
from homelab.vm.windows_gui import crop_image, read_ppm
from homelab.vm.windows_identity_reference import GuestProvenance
from homelab.vm.windows_run_dialog_calibration import (
    RunDialogCalibrationPlan,
    WindowsRunDialogCalibrationError,
    capture_run_dialog,
)


class Qmp:
    def __init__(self, frames):
        self.frames = iter(frames)
        self.events = []

    def screenshot(self, path):
        self.events.append(("screenshot", path.name))
        path.write_bytes(next(self.frames))

    def chord(self, *keys):
        self.events.append(("chord", keys))

    def type_text(self, value):
        self.events.append(("private-text", value))

    def key(self, value):
        self.events.append(("key", value))


class Boundary:
    def __init__(self, attempt, qmp, fail=None):
        self.attempt = attempt
        self.qmp = qmp
        self.fail = fail
        self.events = []

    def _event(self, name):
        self.events.append(name)
        if name == self.fail:
            raise RuntimeError("failed")

    def start_switch(self): self._event("start-switch")
    def start_controller(self): self._event("start-controller")
    def start_windows(self): self._event("start-windows")
    def authenticate_qmp(self): self._event("authenticate-qmp")
    def stop_windows(self): self._event("stop-windows")
    def stop_controller(self): self._event("stop-controller")
    def stop_switch(self): self._event("stop-switch")


def desktop_full():
    reference = read_ppm(REFERENCE_ROOT / "desktop.ppm")
    full = read_ppm_bytes(ppm((2, 3, 4)))
    pixels = bytearray(full.pixels)
    for row in range(reference.height):
        target = ((row * full.width) * 3)
        source = row * reference.width * 3
        pixels[target:target + reference.width * 3] = (
            reference.pixels[source:source + reference.width * 3])
    return (
        f"P6\n{full.width} {full.height}\n255\n".encode() + bytes(pixels))


def reference_full(name, color=(2, 3, 4)):
    manifest = json.loads((REFERENCE_ROOT / f"{name}.json").read_text())
    reference = read_ppm(REFERENCE_ROOT / manifest["reference"]["file"])
    geometry = manifest["capture"]["geometry"]
    crop = manifest["capture"]["crop"]
    full = read_ppm_bytes(ppm(color))
    pixels = bytearray(full.pixels)
    x, y, width, height = crop
    for row in range(height):
        target = ((y + row) * geometry[0] + x) * 3
        source = row * reference.width * 3
        pixels[target:target + width * 3] = (
            reference.pixels[source:source + width * 3])
    return (
        f"P6\n{full.width} {full.height}\n255\n".encode() + bytes(pixels))


def read_ppm_bytes(value):
    with tempfile.NamedTemporaryFile() as stream:
        stream.write(value)
        stream.flush()
        return read_ppm(Path(stream.name))


def guest():
    document = json.loads((REFERENCE_ROOT / "desktop.json").read_text())
    return GuestProvenance(**document["guest"])


class RunDialogCalibrationTests(unittest.TestCase):
    def run_capture(self, root, frames, *, recover=None):
        publication = root / "publication.iso"
        publication.write_bytes(b"unchanged private publication")
        publication.chmod(0o600)
        secret = "Transient-Old-47"
        if recover is None:
            from contextlib import contextmanager

            @contextmanager
            def recover():
                yield secret
        attempt = root / "attempt-20260728T160000Z-abcdef123456"
        attempt.mkdir(mode=0o700)
        qmp = Qmp(frames)
        boundary = Boundary(attempt, qmp)
        receipt = capture_run_dialog(
            boundary,
            sign_in_manifest=REFERENCE_ROOT / "sign-in.json",
            desktop_manifest=REFERENCE_ROOT / "desktop.json",
            expected_guest=guest(),
            recover_credential=recover,
            publication=publication,
            evidence_root=root / "evidence",
            plan=RunDialogCalibrationPlan(
                crop=(300, 200, 600, 300),
                sign_in_delay=0, interval=0.01),
            pause=lambda _: None,
        )
        return receipt, boundary, qmp, secret, publication

    def test_double_proof_precedes_only_win_r_and_three_stable_frames(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            run = ppm((40, 70, 90))
            frames = [
                reference_full("sign-in"), reference_full("sign-in"),
                desktop_full(), desktop_full(), desktop_full(),
                run, run, run,
            ]
            receipt, boundary, qmp, secret, publication = self.run_capture(
                root, frames)
            chord_index = qmp.events.index(("chord", ("meta_l", "r")))
            self.assertEqual(1, len([
                event for event in qmp.events[:chord_index]
                if event == ("private-text", secret)]))
            self.assertEqual(b"unchanged private publication",
                             publication.read_bytes())
            self.assertEqual(3, len(receipt.source_frames))
            self.assertTrue(receipt.credential_submitted)
            self.assertTrue(receipt.publication_unchanged)
            self.assertTrue(receipt.teardown_complete)
            self.assertEqual(
                ["stop-windows", "stop-controller", "stop-switch"],
                boundary.events[-3:])
            provenance = json.loads(receipt.candidate_manifest.read_text())
            self.assertEqual("candidate", provenance["review_status"])
            self.assertFalse(provenance["contains_private_material"])
            self.assertEqual(
                1, len(set(provenance["capture"]["stable_crop_pixel_sha256"])))
            self.assertGreaterEqual(
                provenance["capture"]["baseline_image_distance"], 6.0)

    def test_unstable_run_frames_fail_and_teardown(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            frames = [
                reference_full("sign-in"), reference_full("sign-in"),
                desktop_full(), desktop_full(), desktop_full(),
            ]
            frames.extend(ppm((i, i + 1, i + 2)) for i in range(1, 8))
            with self.assertRaisesRegex(
                    WindowsRunDialogCalibrationError, "calibration failed"):
                self.run_capture(root, frames)

    def test_private_sign_in_failure_is_collapsed_and_tears_down(self):
        from contextlib import contextmanager

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            publication = root / "publication.iso"
            publication.write_bytes(b"unchanged private publication")
            publication.chmod(0o600)
            attempt = root / "attempt-20260728T160000Z-abcdef123456"
            attempt.mkdir(mode=0o700)
            secret = "Transient-Old-47"
            qmp = Qmp([
                reference_full("sign-in"), reference_full("sign-in")])

            def reject(value):
                raise RuntimeError(f"backend echoed {value}")

            qmp.type_text = reject
            boundary = Boundary(attempt, qmp)

            @contextmanager
            def recover():
                yield secret

            with self.assertRaises(
                    WindowsRunDialogCalibrationError) as caught:
                capture_run_dialog(
                    boundary,
                    sign_in_manifest=REFERENCE_ROOT / "sign-in.json",
                    desktop_manifest=REFERENCE_ROOT / "desktop.json",
                    expected_guest=guest(),
                    recover_credential=recover,
                    publication=publication,
                    evidence_root=root / "evidence",
                    plan=RunDialogCalibrationPlan(
                        crop=(300, 200, 600, 300),
                        sign_in_delay=0, interval=0.01),
                    pause=lambda _: None,
                )
            self.assertNotIn(secret, str(caught.exception))
            self.assertEqual("stop-switch", boundary.events[-1])
            self.assertEqual(
                b"unchanged private publication", publication.read_bytes())
            retained = b"".join(
                path.read_bytes()
                for path in (root / "evidence").glob("*")
                if path.is_file())
            self.assertNotIn(secret.encode(), retained)

    def test_unchanged_stable_wallpaper_is_not_a_run_candidate(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            unchanged = desktop_full()
            frames = [
                reference_full("sign-in"), reference_full("sign-in"),
                desktop_full(), desktop_full(),
                unchanged, unchanged, unchanged, unchanged,
            ]
            with self.assertRaisesRegex(
                    WindowsRunDialogCalibrationError, "calibration failed"):
                self.run_capture(root, frames)

    def test_guest_mismatch_fails_before_start(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            attempt = root / "attempt-20260728T160000Z-abcdef123456"
            attempt.mkdir(mode=0o700)
            expected = guest()
            wrong = GuestProvenance(
                expected.release, expected.language, expected.architecture,
                expected.installer_iso_sha256, "0" * 64)
            boundary = Boundary(attempt, Qmp([]))
            with self.assertRaisesRegex(
                    WindowsRunDialogCalibrationError, "reference is invalid"):
                capture_run_dialog(
                    boundary,
                    sign_in_manifest=REFERENCE_ROOT / "sign-in.json",
                    desktop_manifest=REFERENCE_ROOT / "desktop.json",
                    expected_guest=wrong,
                    recover_credential=lambda: None,
                    publication=root / "missing.iso",
                    evidence_root=root / "evidence",
                    plan=RunDialogCalibrationPlan(
                        crop=(300, 200, 600, 300)),
                )
            self.assertEqual([], boundary.events)


class RunDialogCalibrationCliTests(unittest.TestCase):
    def arguments(self, root):
        provenance = root / "guest.json"
        provenance.write_text(json.dumps(guest().__dict__))
        return [
            "--attempt", str(root / "attempt"),
            "--controller-state", str(root / "controller"),
            "--desktop-reference", str(REFERENCE_ROOT / "desktop.json"),
            "--sign-in-reference", str(REFERENCE_ROOT / "sign-in.json"),
            "--guest-provenance", str(provenance),
            "--publication", str(root / "publication.iso"),
            "--recovery-parent", str(root),
            "--evidence-root", str(root / "evidence"),
            "--crop", "300,200,600,300",
        ]

    def test_dry_run_validates_boundary_without_starting_calibration(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            boundary = mock.Mock()
            with (
                mock.patch.object(
                    windows_run_dialog_calibration_cli,
                    "NativeProcessBoundary",
                    return_value=boundary,
                ),
                mock.patch.object(
                    windows_run_dialog_calibration_cli,
                    "capture_run_dialog",
                ) as capture,
            ):
                result = windows_run_dialog_calibration_cli.main(
                    self.arguments(root))
        self.assertEqual(0, result)
        boundary._validate.assert_called_once_with()
        capture.assert_not_called()

    def test_apply_exposes_review_candidates_only(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            boundary = mock.Mock()
            receipt = mock.Mock(
                candidate_image=root / "candidate.ppm",
                candidate_manifest=root / "candidate.json",
            )
            with (
                mock.patch.object(
                    windows_run_dialog_calibration_cli,
                    "NativeProcessBoundary",
                    return_value=boundary,
                ),
                mock.patch.object(
                    windows_run_dialog_calibration_cli,
                    "capture_run_dialog",
                    return_value=receipt,
                ) as capture,
            ):
                result = windows_run_dialog_calibration_cli.main(
                    [*self.arguments(root), "--apply"])
        self.assertEqual(0, result)
        capture.assert_called_once()


if __name__ == "__main__":
    unittest.main()
