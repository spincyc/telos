"""Tests for the installation sequence and its failure model.

The property worth proving here is negative: that a destructive step cannot run
without an authorization token, and that the token cannot be forged, reused for
a different disk, or obtained by answering anything except the disk's serial.
"""

import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import steps  # noqa: E402
from steps import (  # noqa: E402
    Authorization, NotAuthorized, Runner, Step, StepFailed, authorize,
)

SERIAL = "S7YANJ0Y405056D"
DISK = "/dev/nvme0n1"


def noop_step(name, destructive=False, log=None):
    def run():
        if log is not None:
            log.append(name)
    return Step(name, f"do {name}", run, destructive=destructive)


def failing_step(name, destructive=False, exc=None):
    def run():
        raise exc or RuntimeError("boom")
    return Step(name, f"do {name}", run, destructive=destructive)


class TestAuthorization(unittest.TestCase):
    def test_correct_serial_produces_a_token(self):
        token = authorize(SERIAL, disk_path=DISK, disk_serial=SERIAL, clock=lambda: 1.0)
        self.assertIsInstance(token, Authorization)
        self.assertEqual(token.disk_path, DISK)

    def test_yes_produces_nothing(self):
        for reflex in ("y", "yes", "YES", ""):
            with self.subTest(reflex=reflex):
                self.assertIsNone(authorize(reflex, disk_path=DISK, disk_serial=SERIAL))

    def test_a_disk_without_a_serial_cannot_be_authorized(self):
        self.assertIsNone(authorize("", disk_path=DISK, disk_serial=""))
        self.assertIsNone(authorize("anything", disk_path=DISK, disk_serial=""))


class TestDestructiveGate(unittest.TestCase):
    def test_destructive_step_refuses_without_a_token(self):
        log = []
        runner = Runner([noop_step("wipe", destructive=True, log=log)], emit=lambda _: None)
        with self.assertRaises(NotAuthorized):
            runner.run(target_disk=DISK)
        self.assertEqual(log, [], "the step body must not have run")

    def test_non_destructive_steps_run_without_a_token(self):
        log = []
        runner = Runner([noop_step("inspect", log=log)], emit=lambda _: None)
        outcome = runner.run(target_disk=DISK)
        self.assertTrue(outcome.succeeded)
        self.assertEqual(log, ["inspect"])

    def test_refusal_happens_before_the_step_body(self):
        # The gate is checked ahead of execution, so a destructive step never
        # begins and then gets stopped partway.
        log = []
        runner = Runner(
            [noop_step("probe", log=log), noop_step("wipe", destructive=True, log=log)],
            emit=lambda _: None)
        with self.assertRaises(NotAuthorized):
            runner.run(target_disk=DISK)
        self.assertEqual(log, ["probe"])

    def test_token_for_one_disk_does_not_authorize_another(self):
        token = authorize(SERIAL, disk_path="/dev/sda", disk_serial=SERIAL)
        runner = Runner([noop_step("wipe", destructive=True)],
                        authorization=token, emit=lambda _: None)
        with self.assertRaisesRegex(NotAuthorized, "granted for /dev/sda"):
            runner.run(target_disk=DISK)

    def test_authorized_destructive_step_runs(self):
        log = []
        token = authorize(SERIAL, disk_path=DISK, disk_serial=SERIAL)
        runner = Runner([noop_step("wipe", destructive=True, log=log)],
                        authorization=token, emit=lambda _: None)
        self.assertTrue(runner.run(target_disk=DISK).succeeded)
        self.assertEqual(log, ["wipe"])


class TestFailureModel(unittest.TestCase):
    def build(self):
        self.log = []
        token = authorize(SERIAL, disk_path=DISK, disk_serial=SERIAL)
        sequence = [
            noop_step("partition", destructive=True, log=self.log),
            failing_step("encrypt", destructive=True),
            noop_step("format", destructive=True, log=self.log),
        ]
        return Runner(sequence, authorization=token, emit=lambda _: None)

    def test_stops_at_the_first_failure(self):
        outcome = self.build().run(target_disk=DISK)
        self.assertFalse(outcome.succeeded)
        self.assertEqual(outcome.failed.name, "encrypt")

    def test_later_steps_do_not_run(self):
        self.build().run(target_disk=DISK)
        self.assertEqual(self.log, ["partition"], "format must not have run")

    def test_completed_steps_are_recorded(self):
        outcome = self.build().run(target_disk=DISK)
        self.assertEqual([s.name for s in outcome.completed], ["partition"])

    def test_no_rollback_is_attempted(self):
        # ADR 0059. There should be no cleanup hook of any kind on the runner.
        for attribute in ("rollback", "cleanup", "undo", "resume"):
            with self.subTest(attribute=attribute):
                self.assertFalse(hasattr(Runner, attribute))

    def test_an_unexpected_exception_is_reported_not_swallowed(self):
        token = authorize(SERIAL, disk_path=DISK, disk_serial=SERIAL)
        runner = Runner([failing_step("boom", destructive=True, exc=ValueError("odd"))],
                        authorization=token, emit=lambda _: None)
        outcome = runner.run(target_disk=DISK)
        self.assertFalse(outcome.succeeded)
        self.assertIn("ValueError", outcome.error.detail)


class TestCommandSteps(unittest.TestCase):
    def test_non_zero_exit_becomes_a_step_failure(self):
        def fake(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="no such device")
        body = steps.command("wipefs", ["wipefs", "-a", DISK], runner=fake)
        with self.assertRaises(StepFailed) as caught:
            body()
        self.assertEqual(caught.exception.returncode, 1)
        self.assertIn("no such device", caught.exception.output)

    def test_zero_exit_is_silent(self):
        def fake(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")
        steps.command("wipefs", ["wipefs", "-a", DISK], runner=fake)()


class TestReports(unittest.TestCase):
    def report(self):
        token = authorize(SERIAL, disk_path=DISK, disk_serial=SERIAL)
        def failing():
            raise StepFailed(Step("encrypt", "set up LUKS2", lambda: None),
                             "command exited 1",
                             command=["cryptsetup", "luksFormat", DISK],
                             returncode=1, output="Device is in use.")
        sequence = [noop_step("partition", destructive=True),
                    Step("encrypt", "set up LUKS2", failing, destructive=True)]
        outcome = Runner(sequence, authorization=token, emit=lambda _: None).run(target_disk=DISK)
        return "\n".join(steps.failure_report(outcome, target_disk=DISK))

    def test_names_the_failing_step_and_the_command(self):
        text = self.report()
        self.assertIn("Failed at:  encrypt", text)
        self.assertIn("cryptsetup luksFormat", text)

    def test_includes_the_command_output(self):
        self.assertIn("Device is in use.", self.report())

    def test_lists_what_completed(self):
        self.assertIn("done   partition", self.report())

    def test_states_the_disk_will_not_boot(self):
        text = self.report()
        self.assertIn("WILL NOT BOOT", text)
        self.assertIn("run the installer again", text)

    def test_says_nothing_was_written_when_failure_was_pre_destructive(self):
        runner = Runner([failing_step("probe")], emit=lambda _: None)
        outcome = runner.run(target_disk=DISK)
        text = "\n".join(steps.failure_report(outcome, target_disk=DISK))
        self.assertIn("No disk was written", text)
        self.assertNotIn("WILL NOT BOOT", text)

    def test_success_report_says_it_powers_off(self):
        # ADR 0010: a successful install ends in poweroff, never a reboot.
        token = authorize(SERIAL, disk_path=DISK, disk_serial=SERIAL)
        outcome = Runner([noop_step("install", destructive=True)],
                         authorization=token, emit=lambda _: None).run(target_disk=DISK)
        text = "\n".join(steps.success_report(outcome, target_disk=DISK, hostname="polycarp"))
        self.assertIn("power off", text)
        self.assertIn("powered off", text)


if __name__ == "__main__":
    unittest.main()
