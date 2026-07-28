import tempfile
import unittest
from pathlib import Path

from homelab.vm.windows_gui import Image
from homelab.vm.windows_identity_reference import (
    GuestProvenance,
    ValidatedIdentityReference,
)
from homelab.vm.windows_public_command import (
    MAX_PUBLIC_COMMAND_CHARS,
    PublicPowerShellLaunchPlan,
    WindowsPublicCommandError,
    WindowsPublicCommandLauncher,
)


WIDTH = 430
HEIGHT = 230
PIXEL_BYTES = WIDTH * HEIGHT * 3
PIXELS = (bytes(range(256)) * ((PIXEL_BYTES + 255) // 256))[:PIXEL_BYTES]
FRAME = f"P6\n{WIDTH} {HEIGHT}\n255\n".encode() + PIXELS
OTHER_FRAME = (
    f"P6\n{WIDTH} {HEIGHT}\n255\n".encode()
    + bytes((value + 67) % 256 for value in PIXELS)
)
INPUT_ONLY_CHANGED_FRAME = (
    f"P6\n{WIDTH} {HEIGHT}\n255\n".encode()
    + PIXELS[:WIDTH * 110 * 3]
    + bytes(
        (value + 67) % 256
        for value in PIXELS[WIDTH * 110 * 3:]
    )
)


class FakeQmp:
    def __init__(self, frames):
        self.frames = list(frames)
        self.actions = []

    def screenshot(self, path):
        self.actions.append(("screenshot", path.name))
        path.write_bytes(self.frames.pop(0))

    def chord(self, *names):
        self.actions.append(("chord", names))

    def type_text(self, value):
        self.actions.append(("text", value))

    def key(self, name):
        self.actions.append(("key", name))


def reference(kind, *, guest=None):
    guest = guest or GuestProvenance(
        "windows-11-25h2", "en-US", "x86_64", "1" * 64, "2" * 64)
    return ValidatedIdentityReference(
        state=kind,
        state_kind=kind,
        captured_after_private_input=True,
        contains_private_material=False,
        guest=guest,
        path=Path(f"{kind}.ppm"),
        image=Image(WIDTH, HEIGHT, PIXELS),
        geometry=(WIDTH, HEIGHT),
        crop=(0, 0, WIDTH, HEIGHT),
        source_frame_sha256=("3" * 64,) * 3,
    )


class WindowsPublicCommandTests(unittest.TestCase):
    def launcher(self, root, frames):
        qmp = FakeQmp(frames)
        launcher = WindowsPublicCommandLauncher(
            qmp, root, interval=0, pause=lambda _: None)
        return qmp, launcher

    def test_proves_stable_desktop_and_run_dialog_before_typing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            qmp, launcher = self.launcher(
                root, [FRAME] * 4 + [OTHER_FRAME] * 2)
            command = "powershell.exe -NoProfile -File C:\\Telos\\probe.ps1"
            events = launcher.launch(
                command,
                PublicPowerShellLaunchPlan(
                    reference("desktop"), reference("run-dialog"),
                    threshold=0, max_frames_per_state=2),
            )
        self.assertEqual(("chord", ("meta_l", "r")), qmp.actions[2])
        self.assertEqual("text", qmp.actions[5][0])
        self.assertEqual(
            command,
            "".join(action[1] for action in qmp.actions if action[0] == "text"))
        enter = qmp.actions.index(("key", "ret"))
        self.assertTrue(all(
            action[0] == "screenshot" for action in qmp.actions[enter + 1:]))
        self.assertEqual("observed:run-dialog-departed", events[-1])
        self.assertFalse(any(root.glob("*run-dialog-departed.ppm")))

    def test_never_types_when_desktop_or_run_dialog_is_unproved(self):
        bad = b"P6\n320 200\n255\n" + bytes([255, 0, 0]) * 320 * 200
        for frames, expected_chord in (
            ([bad, bad], False),
            ([FRAME, FRAME, bad, bad], True),
        ):
            with self.subTest(expected_chord=expected_chord):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    root.chmod(0o700)
                    qmp, launcher = self.launcher(root, frames)
                    with self.assertRaisesRegex(
                            WindowsPublicCommandError, "within 2 frames"):
                        launcher.launch(
                            "powershell -NoProfile",
                            PublicPowerShellLaunchPlan(
                                reference("desktop"),
                                reference("run-dialog"),
                                threshold=0, max_frames_per_state=2),
                        )
                self.assertEqual(
                    expected_chord,
                    ("chord", ("meta_l", "r")) in qmp.actions)
                self.assertFalse(any(a[0] == "text" for a in qmp.actions))

    def test_rejects_non_powershell_and_unbounded_input_before_qmp(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            qmp, launcher = self.launcher(root, [])
            for command in (
                "cmd.exe /c whoami",
                "powershell\nwhoami",
                "powershell " + "p" * (MAX_PUBLIC_COMMAND_CHARS - 10),
            ):
                with self.assertRaises(WindowsPublicCommandError):
                    launcher.launch(
                        command,
                        PublicPowerShellLaunchPlan(
                            reference("desktop"), reference("run-dialog")),
                    )
        self.assertEqual([], qmp.actions)

    def test_accepts_exact_public_command_character_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            qmp, launcher = self.launcher(
                root, [FRAME] * 4 + [OTHER_FRAME] * 2)
            command = "powershell " + "p" * (
                MAX_PUBLIC_COMMAND_CHARS - len("powershell "))
            launcher.launch(
                command,
                PublicPowerShellLaunchPlan(
                    reference("desktop"), reference("run-dialog"),
                    threshold=0, max_frames_per_state=2),
            )
        self.assertEqual(
            command,
            "".join(a[1] for a in qmp.actions if a[0] == "text"))

    def test_rejects_mismatched_or_wrong_reference_authority(self):
        other = GuestProvenance(
            "windows-11-25h2", "en-US", "x86_64", "4" * 64, "5" * 64)
        plans = (
            PublicPowerShellLaunchPlan(
                reference("run-dialog"), reference("run-dialog")),
            PublicPowerShellLaunchPlan(
                reference("desktop"), reference("desktop")),
            PublicPowerShellLaunchPlan(
                reference("desktop"), reference("run-dialog", guest=other)),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            qmp, launcher = self.launcher(root, [])
            for plan in plans:
                with self.assertRaises(WindowsPublicCommandError):
                    launcher.launch("powershell -NoProfile", plan)
        self.assertEqual([], qmp.actions)

    def test_backend_failure_does_not_echo_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            qmp, launcher = self.launcher(root, [FRAME] * 4)
            command = "powershell -NoProfile -Command Get-Date"

            def reject(value):
                raise RuntimeError(f"echoed {value}")

            qmp.type_text = reject
            with self.assertRaises(WindowsPublicCommandError) as caught:
                launcher.launch(
                    command,
                    PublicPowerShellLaunchPlan(
                        reference("desktop"), reference("run-dialog"),
                        threshold=0, max_frames_per_state=2),
                )
        self.assertNotIn(command, str(caught.exception))
        self.assertNotIn("echoed", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_public_typing_cadence_prevents_transport_overlap_drops(self):
        class Clock:
            now = 0.0

            def pause(self, duration):
                self.now += duration

        class DroppingQmp(FakeQmp):
            def __init__(self, frames, clock):
                super().__init__(frames)
                self.clock = clock
                self.last_key_at = -1.0

            def type_text(self, value):
                if self.clock.now - self.last_key_at >= 0.060:
                    self.actions.append(("text", value))
                self.last_key_at = self.clock.now

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            clock = Clock()
            qmp = DroppingQmp(
                [FRAME] * 4 + [OTHER_FRAME] * 2, clock)
            launcher = WindowsPublicCommandLauncher(
                qmp,
                root,
                interval=0,
                public_key_interval=0.060,
                pause=clock.pause,
            )
            command = "powershell -NoProfile -File C:\\Telos\\long-probe.ps1"

            launcher.launch(
                command,
                PublicPowerShellLaunchPlan(
                    reference("desktop"), reference("run-dialog"),
                    threshold=0, max_frames_per_state=2),
            )

        self.assertEqual(
            command,
            "".join(action[1] for action in qmp.actions if action[0] == "text"))

    def test_submit_failure_is_redacted_and_does_not_observe_departure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            qmp, launcher = self.launcher(root, [FRAME] * 4)

            def reject(_name):
                raise RuntimeError("arbitrary guest input context")

            qmp.key = reject
            with self.assertRaises(WindowsPublicCommandError) as caught:
                launcher.launch(
                    "powershell -NoProfile",
                    PublicPowerShellLaunchPlan(
                        reference("desktop"), reference("run-dialog"),
                        threshold=0, max_frames_per_state=2),
                )

        self.assertEqual("public command launch failed", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertFalse(any(
            "run-dialog-departed" in action[1]
            for action in qmp.actions if action[0] == "screenshot"))

    def test_departure_backend_failure_retains_no_context_or_frame(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            qmp, launcher = self.launcher(root, [FRAME] * 4)
            screenshot_calls = 0
            original_screenshot = qmp.screenshot

            def reject_departure(path):
                nonlocal screenshot_calls
                screenshot_calls += 1
                if screenshot_calls > 4:
                    path.write_bytes(b"arbitrary guest console context")
                    raise RuntimeError("arbitrary guest console context")
                original_screenshot(path)

            qmp.screenshot = reject_departure
            with self.assertRaises(WindowsPublicCommandError) as caught:
                launcher.launch(
                    "powershell -NoProfile",
                    PublicPowerShellLaunchPlan(
                        reference("desktop"), reference("run-dialog"),
                        threshold=0, max_frames_per_state=2),
                )

            self.assertEqual(
                "public command launch failed", str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)
            self.assertFalse(any(root.glob("*run-dialog-departed.ppm")))

    def test_departure_failure_retains_no_post_submit_frames_or_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            qmp, launcher = self.launcher(root, [FRAME] * 6)
            with self.assertRaisesRegex(
                    WindowsPublicCommandError,
                    "failed to prove Run dialog departed within 2 frames"):
                launcher.launch(
                    "powershell -NoProfile",
                    PublicPowerShellLaunchPlan(
                        reference("desktop"), reference("run-dialog"),
                        threshold=0, max_frames_per_state=2),
                )

            departure_names = [
                action[1] for action in qmp.actions
                if action[0] == "screenshot"
                and "run-dialog-departed" in action[1]
            ]
            self.assertEqual(2, len(departure_names))
            self.assertFalse(any(root.glob("*run-dialog-departed.ppm")))

    def test_editable_field_change_does_not_prove_run_dialog_departed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            qmp, launcher = self.launcher(
                root, [FRAME] * 4 + [INPUT_ONLY_CHANGED_FRAME] * 2)

            with self.assertRaisesRegex(
                    WindowsPublicCommandError,
                    "failed to prove Run dialog departed within 2 frames"):
                launcher.launch(
                    "powershell -NoProfile",
                    PublicPowerShellLaunchPlan(
                        reference("desktop"), reference("run-dialog"),
                        threshold=0, max_frames_per_state=2),
                )

            self.assertFalse(any(root.glob("*run-dialog-departed.ppm")))


if __name__ == "__main__":
    unittest.main()
