"""Acceptance tests: drive the real installer through a pseudo-terminal.

This is ADR 0058's mechanism, working today against fixtures and a dry run. The
same driver will later attach to a QEMU guest's serial console under ADR 0056 --
the installer does not know the difference, which is the point.

Every test here runs the genuine `bin/homelab-install`. Nothing is stubbed, no
code path is special-cased for testing, and the authorization gate is answered
by typing a serial exactly as a person would.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "qemu"))

import pty_driver  # noqa: E402
from pty_driver import Conversation, DriverError  # noqa: E402

INSTALLER = [sys.executable, str(ROOT / "bin/homelab-install"), "--dry-run", "--fixture"]
UEFI_MACHINE = str(ROOT / "tests/fixtures/workstation-usb-plus-nvme.json")
BIOS_MACHINE = str(ROOT / "tests/fixtures/legacy-bios-awkward-disks.json")

NVME_SERIAL = "S7YANJ0Y405056D"

CONTROLLER_ANSWERS = {
    "profile": "controller",
    "hostname": "polycarp",
    "target_disk": "1",
    "managed_interface": "1",
    "network_services": "yes",
    "managed_ipv4_cidr": "10.0.7.0/24",
    "controller_ipv4_address": "10.0.7.2",
    "dhcp_pool_start": "10.0.7.100",
    "dhcp_pool_end": "10.0.7.200",
}


def install(answers=None, confirmation=NVME_SERIAL, machine=UEFI_MACHINE, timeout=60):
    conversation = Conversation(answers or CONTROLLER_ANSWERS, confirmation=confirmation)
    return pty_driver.drive(INSTALLER + [machine], conversation, timeout=timeout)


class TestSuccessfulRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transcript = install()

    def test_it_completes(self):
        self.assertEqual(self.transcript.exit_status, 0, self.transcript.tail())
        self.assertIn("INSTALLATION COMPLETE", self.transcript.text)

    def test_every_scripted_question_was_asked(self):
        asked = {identifier for identifier, _ in self.transcript.answered}
        self.assertEqual(asked, set(CONTROLLER_ANSWERS) | {"__confirmation__"})

    def test_authorization_was_required(self):
        pty_driver.assert_authorization_was_required(self.transcript)

    def test_the_usb_stick_was_never_offered(self):
        # The single most destructive available mistake.
        self.assertIn("excluded: removable device", self.transcript.text)

    def test_the_summary_named_the_disk_by_serial(self):
        self.assertIn(NVME_SERIAL, self.transcript.text)
        self.assertIn("COMPLETELY ERASED", self.transcript.text)

    def test_the_derived_network_plan_was_shown(self):
        # ADR 0045 requires entered and derived values in the summary.
        self.assertIn("none advertised", self.transcript.text)
        self.assertIn("255.255.255.0", self.transcript.text)

    def test_it_was_labelled_development_proof(self):
        # ADR 0043.
        self.assertIn("NOT A PRODUCTION INSTALLATION", self.transcript.text)

    def test_the_manifest_is_recoverable_from_the_console(self):
        # ADR 0060: this is how the matrix captures it without mounting a disk.
        document = pty_driver.manifest_from(self.transcript)
        self.assertEqual(document["hostname"], "polycarp")
        self.assertEqual(document["target_disk"]["serial"], NVME_SERIAL)
        self.assertIs(document["development_proof"], True)
        self.assertEqual(document["managed_interface"]["stable_name"], "lan0")
        self.assertEqual(document["network"]["derived"]["dns_server"], "10.0.7.2")

    def test_it_powers_off_rather_than_rebooting(self):
        # ADR 0010: relocation while powered off is the DHCP-conflict boundary.
        self.assertIn("power off", self.transcript.text)


class TestRefusals(unittest.TestCase):
    def test_typing_yes_does_not_authorize(self):
        transcript = install(confirmation="yes")
        self.assertNotEqual(transcript.exit_status, 0)
        pty_driver.assert_no_destruction(transcript)
        self.assertNotIn("INSTALLATION COMPLETE", transcript.text)

    def test_an_empty_confirmation_does_not_authorize(self):
        transcript = install(confirmation="")
        self.assertNotEqual(transcript.exit_status, 0)
        pty_driver.assert_no_destruction(transcript)

    def test_a_near_miss_serial_does_not_authorize(self):
        transcript = install(confirmation=NVME_SERIAL[:-1])
        self.assertNotEqual(transcript.exit_status, 0)
        pty_driver.assert_no_destruction(transcript)

    def test_legacy_bios_is_refused_before_any_question_about_disks(self):
        # ADR 0019. The run must stop before the destructive path is reachable.
        conversation = Conversation({"profile": "controller"}, confirmation=None)
        transcript = pty_driver.drive(INSTALLER + [BIOS_MACHINE], conversation)
        self.assertEqual(transcript.exit_status, 2)
        self.assertIn("CANNOT INSTALL ON THIS MACHINE", transcript.text)
        self.assertIn("requires UEFI", transcript.text)
        pty_driver.assert_no_destruction(transcript)

    def test_a_controller_in_the_pool_is_rejected_then_accepted_when_fixed(self):
        # The rule that matters most: dnsmasq must never be able to lease the
        # address its own DNS answers on. Answer badly, then correctly.
        answers = dict(CONTROLLER_ANSWERS,
                       controller_ipv4_address=["10.0.7.150", "10.0.7.2"])
        transcript = install(answers=answers, confirmation=NVME_SERIAL, timeout=30)
        self.assertIn("not accepted", transcript.text)
        self.assertIn("DHCP pool", transcript.text)
        self.assertEqual(transcript.exit_status, 0)
        self.assertEqual(
            pty_driver.manifest_from(transcript)["network"]["entered"]
                ["controller_ipv4_address"], "10.0.7.2")

    def test_a_bad_hostname_is_rejected_then_accepted(self):
        answers = dict(CONTROLLER_ANSWERS, hostname=["polycarp.home.arpa", "polycarp"])
        transcript = install(answers=answers, timeout=30)
        self.assertIn("short hostname", transcript.text)
        self.assertEqual(transcript.exit_status, 0)


class TestDriverSafety(unittest.TestCase):
    """The harness itself must not be able to authorize something unscripted."""

    def test_it_refuses_to_invent_a_confirmation(self):
        conversation = Conversation(CONTROLLER_ANSWERS, confirmation=None)
        with self.assertRaises(DriverError) as caught:
            pty_driver.drive(INSTALLER + [UEFI_MACHINE], conversation, timeout=20)
        self.assertIn("Refusing to invent one", str(caught.exception))

    def test_an_unscripted_question_is_an_error(self):
        incomplete = {k: v for k, v in CONTROLLER_ANSWERS.items() if k != "hostname"}
        conversation = Conversation(incomplete, confirmation=NVME_SERIAL)
        with self.assertRaises(DriverError) as caught:
            pty_driver.drive(INSTALLER + [UEFI_MACHINE], conversation, timeout=20)
        self.assertIn("hostname", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
