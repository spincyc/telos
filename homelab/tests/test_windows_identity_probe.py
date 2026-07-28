import signal
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm.signal_cleanup import RunInterrupted
from homelab.vm.windows_identity_probe import (
    WindowsIdentityProbeError,
    probe_screen,
)


def ppm(useful=True):
    size = 320 * 200 * 3
    pixels = (bytes(size // 2) + bytes([255]) * (size // 2)
              if useful else bytes(size))
    return b"P6\n320 200\n255\n" + pixels


class FakeQmp:
    def __init__(self, events, *, useful=True, failure=None):
        self.events = events
        self.useful = useful
        self.failure = failure

    def screenshot(self, path):
        self.events.append(("screenshot", path.name))
        if self.failure is not None:
            raise self.failure
        path.write_bytes(ppm(self.useful))

    def key(self, name):
        self.events.append(("key", name))


class Boundary:
    def __init__(self, root, *, fail_start=None, fail_stop=None, qmp=None):
        self.runtime = root / "runtime"
        self.events = []
        self.fail_start = fail_start
        self.fail_stop = fail_stop
        self.qmp = qmp or FakeQmp(self.events)

    def _start(self, name):
        self.events.append(name)
        self.runtime.mkdir(mode=0o700, exist_ok=True)
        if self.fail_start == name:
            raise RuntimeError("partial start")

    def start_switch(self):
        self._start("start_switch")

    def start_windows(self):
        self._start("start_windows")

    def authenticate_qmp(self):
        self.events.append("authenticate_qmp")
        if self.fail_start == "authenticate_qmp":
            raise RuntimeError("QMP failure")

    def stop_windows(self):
        self.events.append("stop_windows")
        if self.fail_stop == "stop_windows":
            raise RuntimeError("cleanup failure")

    def stop_controller(self):
        self.events.append("stop_controller")
        if self.fail_stop == "stop_controller":
            raise RuntimeError("cleanup failure")

    def stop_switch(self):
        self.events.append("stop_switch")
        if self.fail_stop == "stop_switch":
            raise RuntimeError("cleanup failure")


class WindowsIdentityProbeTests(unittest.TestCase):
    def test_captures_private_useful_frame_and_tears_down(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = Boundary(Path(name))
            ticks = iter((0.0, 0.0, 1.0, 1.0))
            receipt = probe_screen(
                boundary, duration=1, interval=1,
                clock=lambda: next(ticks), pause=lambda _: None)
            self.assertEqual(1, receipt.useful_screenshots)
            self.assertTrue(receipt.teardown_complete)
            self.assertEqual(0o600, receipt.screenshots[0].stat().st_mode & 0o777)
            self.assertEqual(
                ["stop_windows", "stop_controller", "stop_switch"],
                boundary.events[-3:])

    def test_partial_start_is_unconditionally_cleaned_up(self):
        for phase in ("start_switch", "start_windows", "authenticate_qmp"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                boundary = Boundary(Path(name), fail_start=phase)
                with self.assertRaisesRegex(
                        WindowsIdentityProbeError, "probe: RuntimeError"):
                    probe_screen(boundary)
                self.assertEqual(
                    ["stop_windows", "stop_controller", "stop_switch"],
                    boundary.events[-3:])

    def test_screenshot_failure_is_cleaned_up(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = Boundary(Path(name))
            boundary.qmp = FakeQmp(
                boundary.events, failure=RuntimeError("screendump"))
            with self.assertRaisesRegex(
                    WindowsIdentityProbeError, "probe: RuntimeError"):
                probe_screen(boundary, duration=1)
            self.assertEqual(
                ["stop_windows", "stop_controller", "stop_switch"],
                boundary.events[-3:])

    def test_signal_interruption_is_cleaned_up(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = Boundary(Path(name))

            def interrupt(_duration):
                signal.raise_signal(signal.SIGTERM)

            with self.assertRaisesRegex(
                    WindowsIdentityProbeError, "probe: RunInterrupted"):
                probe_screen(
                    boundary, duration=2, interval=1,
                    clock=mock.Mock(side_effect=(0.0, 0.0, 1.0)),
                    pause=interrupt)
            self.assertEqual(
                ["stop_windows", "stop_controller", "stop_switch"],
                boundary.events[-3:])

    def test_blank_frame_is_rejected_after_teardown(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = Boundary(Path(name))
            boundary.qmp = FakeQmp(boundary.events, useful=False)
            ticks = iter((0.0, 0.0, 1.0, 1.0))
            with self.assertRaisesRegex(
                    WindowsIdentityProbeError, "no useful frame"):
                probe_screen(
                    boundary, duration=1, interval=1,
                    clock=lambda: next(ticks), pause=lambda _: None)
            self.assertEqual(
                ["stop_windows", "stop_controller", "stop_switch"],
                boundary.events[-3:])

    def test_cleanup_failure_does_not_skip_remaining_cleanup(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = Boundary(Path(name), fail_start="start_switch",
                                fail_stop="stop_windows")
            with self.assertRaisesRegex(
                    WindowsIdentityProbeError, "teardown windows"):
                probe_screen(boundary)
            self.assertEqual(
                ["stop_windows", "stop_controller", "stop_switch"],
                boundary.events[-3:])

    def test_public_wake_key_is_sent_once_after_the_bounded_delay(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = Boundary(Path(name))
            ticks = iter((0.0, 0.0, 1.0, 1.0, 2.0, 2.0, 3.0))
            probe_screen(
                boundary, duration=3, interval=1, wake_after=1,
                clock=lambda: next(ticks), pause=lambda _: None)
            self.assertEqual(
                [("key", "spc")],
                [event for event in boundary.events if isinstance(event, tuple)
                 and event[0] == "key"])


if __name__ == "__main__":
    unittest.main()
