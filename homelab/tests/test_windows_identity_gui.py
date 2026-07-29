import tempfile
import unittest
from pathlib import Path

from homelab.vm.windows_gui import Checkpoint, WindowsGuiError
from homelab.vm.windows_identity_gui import (
    CredentialRotationPlan,
    WindowsCredentialRotationDriver,
    WindowsIdentityGuiError,
)


class FakeQmp:
    def __init__(self):
        self.actions = []

    def key(self, name):
        self.actions.append(("key", name))

    def chord(self, *names):
        self.actions.append(("chord", names))

    def type_text(self, value):
        self.actions.append(("text", value))

    def screenshot(self, path):
        self.actions.append(("screenshot", path.name))


def plan(root):
    checkpoints = [
        Checkpoint(name, root / f"{name}.ppm", ())
        for name in (
            "sign-in", "desktop", "security-options", "change-password",
            "password-changed", "final-desktop",
        )
    ]
    return CredentialRotationPlan(
        *checkpoints,
        change_password_keys=("down", "ret"),
    )


class WindowsIdentityGuiTests(unittest.TestCase):
    def driver(self, root):
        qmp = FakeQmp()
        driver = WindowsCredentialRotationDriver(
            qmp, root, pause=lambda _: None)
        observed = []
        driver._observe = lambda checkpoint: observed.append(checkpoint.name)
        return qmp, driver, observed

    def test_observes_each_state_before_private_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            qmp, driver, observed = self.driver(root)
            events = driver.rotate("Old-private-47!", "New-private-83!", plan(root))

        self.assertEqual([
            "sign-in", "desktop", "security-options", "change-password",
            "password-changed", "final-desktop",
        ], observed)
        self.assertEqual([
            ("text", "Old-private-47!"),
            ("key", "ret"),
            ("chord", ("ctrl", "alt", "delete")),
            ("key", "down"),
            ("key", "ret"),
            ("text", "Old-private-47!"),
            ("key", "tab"),
            ("text", "New-private-83!"),
            ("key", "tab"),
            ("text", "New-private-83!"),
            ("key", "ret"),
            ("key", "ret"),
        ], qmp.actions)
        self.assertEqual("observed:final-desktop", events[-1])

    def test_never_types_when_initial_state_is_unproved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            qmp, driver, _ = self.driver(root)
            driver._observe = lambda checkpoint: (
                (_ for _ in ()).throw(WindowsGuiError("screen mismatch")))
            with self.assertRaisesRegex(
                    WindowsIdentityGuiError, "GUI proof failed"):
                driver.rotate("Old-private-47!", "New-private-83!", plan(root))
        self.assertEqual([], qmp.actions)

    def test_failure_never_echoes_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            qmp, driver, _ = self.driver(root)

            def reject(value):
                raise RuntimeError(f"backend echoed {value}")

            qmp.type_text = reject
            old = "Old-private-47!"
            new = "New-private-83!"
            with self.assertRaises(WindowsIdentityGuiError) as caught:
                driver.rotate(old, new, plan(root))
        message = str(caught.exception)
        self.assertNotIn(old, message)
        self.assertNotIn(new, message)
        self.assertNotIn("backend echoed", message)

    def test_rejects_invalid_or_reused_credentials_before_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            qmp, driver, observed = self.driver(root)
            for old, new in (
                ("", "New-private-83!"),
                ("Old\nprivate", "New-private-83!"),
                ("same-private-47!", "same-private-47!"),
            ):
                with self.assertRaises(WindowsIdentityGuiError):
                    driver.rotate(old, new, plan(root))
        self.assertEqual([], qmp.actions)
        self.assertEqual([], observed)

    def test_rejects_unbounded_navigation_before_using_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            qmp, driver, _ = self.driver(root)
            unsafe = CredentialRotationPlan(
                *[
                    Checkpoint(name, root / f"{name}.ppm", ())
                    for name in (
                        "sign-in", "desktop", "security-options",
                        "change-password", "password-changed",
                        "final-desktop",
                    )
                ],
                change_password_keys=("a",),
            )
            with self.assertRaisesRegex(
                    WindowsIdentityGuiError, "unsafe.*navigation"):
                driver.rotate(
                    "Old-private-47!", "New-private-83!", unsafe)
        self.assertNotIn(("key", "a"), qmp.actions)

    def test_rejects_nonprivate_evidence_and_unsafe_checkpoint_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            with self.assertRaisesRegex(
                    WindowsIdentityGuiError, "root must be private"):
                WindowsCredentialRotationDriver(
                    FakeQmp(), root, pause=lambda _: None)
            root.chmod(0o700)
            qmp, driver, observed = self.driver(root)
            unsafe = plan(root)
            object.__setattr__(unsafe.sign_in, "name", "../private")
            with self.assertRaisesRegex(
                    WindowsIdentityGuiError, "checkpoint name"):
                driver.rotate(
                    "Old-private-47!", "New-private-83!", unsafe)
        self.assertEqual([], qmp.actions)
        self.assertEqual([], observed)

    def test_requires_consecutive_useful_matching_crops(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reference = root / "reference.ppm"
            pixels = (
                bytes([20, 40, 60, 180, 200, 220])
                * (320 * 200 // 2)
            )
            reference.write_bytes(b"P6\n320 200\n255\n" + pixels)
            frames = [
                reference.read_bytes(),
                b"P6\n320 200\n255\n" + bytes([200, 20, 20]) * 320 * 200,
                reference.read_bytes(),
                reference.read_bytes(),
            ]
            qmp = FakeQmp()

            def screenshot(path):
                qmp.actions.append(("screenshot", path.name))
                path.write_bytes(frames.pop(0))

            qmp.screenshot = screenshot
            ticks = iter(range(20))
            driver = WindowsCredentialRotationDriver(
                qmp, root, interval=0, clock=lambda: next(ticks),
                pause=lambda _: None)
            driver._observe(Checkpoint(
                "focused", reference, (), timeout=10, threshold=0,
                crop=(0, 0, 32, 32)))
        self.assertEqual(4, len([
            action for action in qmp.actions if action[0] == "screenshot"]))

    def test_accepts_a_pre_cropped_checkpoint_reference(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reference = root / "reference.ppm"
            pattern = (
                bytes([20, 40, 60, 180, 200, 220])
                * (320 * 200 // 2)
            )
            reference.write_bytes(b"P6\n320 200\n255\n" + pattern)
            rows = []
            for row in range(400):
                if row < 200:
                    rows.append(
                        pattern[row * 320 * 3:(row + 1) * 320 * 3]
                        + bytes([1, 2, 3]) * 320)
                else:
                    rows.append(bytes([1, 2, 3]) * 640)
            frame = b"P6\n640 400\n255\n" + b"".join(rows)
            qmp = FakeQmp()

            def screenshot(path):
                qmp.actions.append(("screenshot", path.name))
                path.write_bytes(frame)

            qmp.screenshot = screenshot
            ticks = iter(range(10))
            driver = WindowsCredentialRotationDriver(
                qmp, root, interval=0, clock=lambda: next(ticks),
                pause=lambda _: None)
            driver._observe(Checkpoint(
                "sign-in", reference, (), timeout=6, threshold=0,
                crop=(0, 0, 320, 200)))
        self.assertEqual(2, len([
            action for action in qmp.actions if action[0] == "screenshot"]))

    def test_rejects_matching_crop_from_wrong_full_frame_geometry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reference = root / "reference.ppm"
            pattern = bytes([20, 40, 60]) * 320 * 200
            reference.write_bytes(b"P6\n320 200\n255\n" + pattern)
            rows = []
            for row in range(400):
                if row < 200:
                    rows.append(
                        pattern[row * 320 * 3:(row + 1) * 320 * 3]
                        + bytes([1, 2, 3]) * 320)
                else:
                    rows.append(bytes([1, 2, 3]) * 640)
            frame = b"P6\n640 400\n255\n" + b"".join(rows)
            qmp = FakeQmp()
            qmp.screenshot = lambda path: path.write_bytes(frame)
            ticks = iter(range(10))
            driver = WindowsCredentialRotationDriver(
                qmp, root, interval=0, clock=lambda: next(ticks),
                pause=lambda _: None)
            with self.assertRaisesRegex(
                    WindowsIdentityGuiError, "best image distance inf"):
                driver._observe(Checkpoint(
                    "sign-in", reference, (), timeout=3, threshold=0,
                    crop=(0, 0, 320, 200),
                    expected_geometry=(1280, 800)))


if __name__ == "__main__":
    unittest.main()
