"""Tests for bounded simulation-runner interruption and cleanup."""

import signal
import subprocess
import unittest
from unittest import mock

from homelab.vm.signal_cleanup import (
    RunInterrupted,
    SignalGuard,
    terminate_children,
)


class Child:
    def __init__(self, pid, events, *, stubborn=False):
        self.pid = pid
        self.events = events
        self.running = True
        self.stubborn = stubborn

    def poll(self):
        return None if self.running else 0

    def terminate(self):
        self.events.append(("terminate", self.pid))
        if not self.stubborn:
            self.running = False

    def kill(self):
        self.events.append(("kill", self.pid))
        self.running = False

    def wait(self, timeout=None):
        self.events.append(("wait", self.pid, timeout))
        if self.running:
            raise subprocess.TimeoutExpired("child", timeout)
        return 0


class SignalCleanupTests(unittest.TestCase):
    def test_guard_raises_structured_interruption_and_restores_handler(self):
        prior = signal.getsignal(signal.SIGTERM)
        with self.assertRaises(RunInterrupted) as caught:
            with SignalGuard():
                signal.raise_signal(signal.SIGTERM)
        self.assertEqual(caught.exception.signum, signal.SIGTERM)
        self.assertEqual(caught.exception.exit_code, 128 + signal.SIGTERM)
        self.assertEqual(signal.getsignal(signal.SIGTERM), prior)

    def test_repeated_signal_does_not_interrupt_cleanup(self):
        guard = SignalGuard()
        with guard:
            with self.assertRaises(RunInterrupted):
                signal.raise_signal(signal.SIGTERM)
            signal.raise_signal(signal.SIGTERM)

    def test_children_are_stopped_in_reverse_order(self):
        events = []
        children = [Child(1, events), Child(2, events)]
        self.assertEqual(terminate_children(children), [])
        self.assertEqual(events[:2], [("terminate", 2), ("terminate", 1)])

    def test_stubborn_child_has_two_bounded_waits(self):
        events = []
        child = Child(3, events, stubborn=True)
        self.assertEqual(
            terminate_children(
                [child], terminate_timeout=0.25, kill_timeout=0.5),
            [])
        self.assertIn(("wait", 3, 0.25), events)
        self.assertIn(("kill", 3), events)
        self.assertIn(("wait", 3, 0.5), events)

    def test_unreapable_child_is_reported(self):
        child = mock.Mock(pid=4)
        child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired("child", 0.1)
        diagnostics = terminate_children(
            [child], terminate_timeout=0.1, kill_timeout=0.1)
        self.assertEqual(
            diagnostics, ["child 4 survived SIGKILL for 0.1s"])
        child.terminate.assert_called_once_with()
        child.kill.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
