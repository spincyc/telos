import hashlib
import json
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from homelab.tests.test_windows_identity_reference import REFERENCE_ROOT
from homelab.vm.windows_identity_navigation import (
    NavigationCalibrationPlan,
    WindowsIdentityNavigationError,
    capture_navigation,
)
from homelab.vm.windows_identity_reference import GuestProvenance


class FakeQmp:
    def __init__(self, frames):
        self.frames = iter(frames)
        self.events = []

    def screenshot(self, path):
        self.events.append(("screenshot", path.name))
        path.write_bytes(next(self.frames))

    def type_text(self, value):
        self.events.append(("private-text", value))

    def key(self, name):
        self.events.append(("key", name))

    def chord(self, *names):
        self.events.append(("chord", names))


class Boundary:
    def __init__(self, qmp, fail=None):
        self.qmp = qmp
        self.fail = fail
        self.events = []

    def _event(self, name):
        self.events.append(name)
        if self.fail == name:
            raise RuntimeError("adapter secret must not appear")

    def start_switch(self):
        self._event("start-switch")

    def start_controller(self):
        self._event("start-controller")

    def start_windows(self):
        self._event("start-windows")

    def authenticate_qmp(self):
        self._event("authenticate-qmp")

    def stop_windows(self):
        self._event("stop-windows")

    def stop_controller(self):
        self._event("stop-controller")

    def stop_switch(self):
        self._event("stop-switch")


def ppm(color):
    pixels = bytes(color) * (1280 * 800)
    return b"P6\n1280 800\n255\n" + pixels


def expected_guest():
    document = json.loads((REFERENCE_ROOT / "sign-in.json").read_text())
    return GuestProvenance(**document["guest"])


def plan():
    return NavigationCalibrationPlan(
        desktop_crop=(0, 0, 320, 200),
        security_options_crop=(0, 0, 320, 200),
        change_password_crop=(0, 0, 320, 200),
        change_password_keys=("down", "ret"),
        timeout=20,
        interval=1,
    )


class WindowsIdentityNavigationTests(unittest.TestCase):
    def frames(self):
        reference = (REFERENCE_ROOT / "sign-in.ppm").read_bytes()
        full = bytearray(ppm((1, 2, 3)))
        header = len(b"P6\n1280 800\n255\n")
        image = reference.split(b"\n", 3)[3]
        for row in range(360):
            target = header + ((150 + row) * 1280 + 460) * 3
            source = row * 360 * 3
            full[target:target + 360 * 3] = image[source:source + 360 * 3]
        return [
            bytes(full), bytes(full),
            *(ppm(color) for color in (
                (10, 20, 40), (10, 20, 40), (10, 20, 40),
                (30, 60, 90), (30, 60, 90), (30, 60, 90),
                (50, 80, 110), (50, 80, 110), (50, 80, 110),
            )),
        ]

    def run_capture(self, root, *, fail=None, guest=None):
        secret = "Recovered-Private-47!"
        qmp = FakeQmp(self.frames())
        boundary = Boundary(qmp, fail=fail)

        @contextmanager
        def recover():
            yield secret

        receipt = capture_navigation(
            boundary,
            sign_in_manifest=REFERENCE_ROOT / "sign-in.json",
            expected_guest=guest or expected_guest(),
            recover_credential=recover,
            evidence_root=root / "evidence",
            plan=plan(),
            clock=_Clock(),
            pause=lambda _: None,
        )
        return receipt, boundary, qmp, secret

    def test_sign_in_is_proved_before_transient_credential_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt, boundary, qmp, secret = self.run_capture(
                Path(temporary))
            events = qmp.events
            private_index = events.index(("private-text", secret))
            self.assertEqual(
                2,
                len([event for event in events[:private_index]
                     if event[0] == "screenshot"]),
            )
            self.assertTrue(receipt.credential_submitted)
            self.assertTrue(receipt.teardown_complete)
            self.assertEqual(
                ["stop-windows", "stop-controller", "stop-switch"],
                boundary.events[-3:],
            )
            retained = b"".join(
                path.read_bytes()
                for path in (Path(temporary) / "evidence").rglob("*")
                if path.is_file()
            )
            self.assertNotIn(secret.encode(), retained)

    def test_captures_three_stable_frames_for_each_public_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt, _, qmp, _ = self.run_capture(Path(temporary))
            self.assertEqual(3, len(receipt.desktop))
            self.assertEqual(3, len(receipt.security_options))
            self.assertEqual(3, len(receipt.change_password))
            self.assertIn(("chord", ("ctrl", "alt", "delete")), qmp.events)
            self.assertIn(("key", "down"), qmp.events)
            self.assertIn(("key", "ret"), qmp.events)

    def test_guest_mismatch_fails_before_process_or_private_input(self):
        wrong = expected_guest()
        wrong = GuestProvenance(
            wrong.release,
            wrong.language,
            wrong.architecture,
            wrong.installer_iso_sha256,
            "0" * 64,
        )
        with tempfile.TemporaryDirectory() as temporary:
            secret = "Recovered-Private-47!"
            qmp = FakeQmp(self.frames())
            boundary = Boundary(qmp)
            called = []

            @contextmanager
            def recover():
                called.append(secret)
                yield secret

            with self.assertRaisesRegex(
                    WindowsIdentityNavigationError, "reference is invalid"):
                capture_navigation(
                    boundary,
                    sign_in_manifest=REFERENCE_ROOT / "sign-in.json",
                    expected_guest=wrong,
                    recover_credential=recover,
                    evidence_root=Path(temporary) / "evidence",
                    plan=plan(),
                )
        self.assertEqual([], boundary.events)
        self.assertEqual([], called)

    def test_failure_after_partial_start_unconditionally_tears_down(self):
        with tempfile.TemporaryDirectory() as temporary:
            qmp = FakeQmp(self.frames())
            boundary = Boundary(qmp, fail="start-controller")

            @contextmanager
            def recover():
                yield "Recovered-Private-47!"

            with self.assertRaisesRegex(
                    WindowsIdentityNavigationError, "navigation"):
                capture_navigation(
                    boundary,
                    sign_in_manifest=REFERENCE_ROOT / "sign-in.json",
                    expected_guest=expected_guest(),
                    recover_credential=recover,
                    evidence_root=Path(temporary) / "evidence",
                    plan=plan(),
                )
        self.assertEqual([
            "start-switch", "start-controller",
            "stop-controller", "stop-switch",
        ], boundary.events)

    def test_error_and_receipt_repr_do_not_retain_private_value(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt, _, _, secret = self.run_capture(Path(temporary))
        self.assertNotIn(secret, repr(receipt))
        self.assertNotIn(secret, str(receipt))

    def test_private_backend_error_is_collapsed_without_secret_echo(self):
        secret = "Recovered-Private-47!"
        qmp = FakeQmp(self.frames())

        def reject(value):
            raise RuntimeError(f"backend echoed {value}")

        qmp.type_text = reject
        boundary = Boundary(qmp)

        @contextmanager
        def recover():
            yield secret

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(
                    WindowsIdentityNavigationError) as caught:
                capture_navigation(
                    boundary,
                    sign_in_manifest=REFERENCE_ROOT / "sign-in.json",
                    expected_guest=expected_guest(),
                    recover_credential=recover,
                    evidence_root=Path(temporary) / "evidence",
                    plan=plan(),
                    clock=_Clock(),
                    pause=lambda _: None,
                )
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn("backend echoed", str(caught.exception))
        self.assertEqual(
            ["stop-windows", "stop-controller", "stop-switch"],
            boundary.events[-3:],
        )


class _Clock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        self.value += 0.1
        return self.value


if __name__ == "__main__":
    unittest.main()
