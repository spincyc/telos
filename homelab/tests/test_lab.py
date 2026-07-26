"""Tests for the QEMU acceptance lab.

The lab needs QEMU and OVMF, which may not be installed. Everything that can be
checked without them -- the command line, the topology, the per-run firmware
isolation -- is checked here; the rest skips with a message naming exactly what
to install rather than failing obscurely.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "qemu"))

import lab  # noqa: E402


class TestRequirements(unittest.TestCase):
    def test_missing_requirements_name_the_package(self):
        # A developer who has not installed QEMU should be told the pacman
        # command, not shown a FileNotFoundError.
        for requirement in lab.missing_requirements():
            self.assertIn("pacman -S", requirement)


@unittest.skipUnless(lab.available(),
                     "QEMU/OVMF not installed: " + "; ".join(lab.missing_requirements()))
class TestLabCommandLine(unittest.TestCase):
    def setUp(self):
        self.lab = lab.Lab()
        self.addCleanup(self.lab.close)
        self.controller = self.lab.add(lab.Machine("controller", listens=True))
        self.client = self.lab.add(lab.Machine("client", mac="52:54:00:00:00:02"))

    def test_boots_uefi_not_bios(self):
        # ADR 0019. A BIOS-booted guest would only reach a refusal slowly.
        argv = " ".join(self.lab.argv(self.controller))
        self.assertIn("if=pflash", argv)
        self.assertIn("OVMF_CODE", argv)

    def test_each_machine_gets_its_own_firmware_variables(self):
        # Otherwise a passing run could depend on boot entries left by a
        # previous one.
        self.assertNotEqual(self.controller.vars_path, self.client.vars_path)
        self.assertTrue(self.controller.vars_path.exists())

    def test_serial_is_stdio_so_the_pty_driver_can_attach(self):
        argv = self.lab.argv(self.controller)
        self.assertIn("-serial", argv)
        self.assertEqual(argv[argv.index("-serial") + 1], "stdio")

    def test_there_is_no_route_off_the_lab_segment(self):
        # ADR 0011's no-routing boundary is enforced by topology: no user
        # networking, no default NIC, nothing but the socket segment.
        argv = " ".join(self.lab.argv(self.controller))
        self.assertIn("-nodefaults", argv)
        self.assertNotIn("-netdev user", argv)
        self.assertNotIn("type=user", argv)

    def test_one_machine_listens_and_the_others_connect(self):
        self.assertIn(f"listen=:{lab.LAB_SOCKET_PORT}",
                      " ".join(self.lab.argv(self.controller)))
        self.assertIn(f"connect=127.0.0.1:{lab.LAB_SOCKET_PORT}",
                      " ".join(self.lab.argv(self.client)))

    def test_machines_have_distinct_macs(self):
        self.assertNotEqual(self.controller.mac, self.client.mac)

    def test_the_plan_is_printable_without_running_anything(self):
        text = "\n".join(lab.describe_plan(self.lab))
        self.assertIn("controller", text)
        self.assertIn("No route off the lab segment", text)


if __name__ == "__main__":
    unittest.main()


class TestMatrixReport(unittest.TestCase):
    """The report must make a pending stage impossible to read as a pass.

    A matrix that quietly skips what it cannot run reports green while testing
    nothing, which is worse than no matrix: it converts an unknown into a
    false assurance.
    """

    def setUp(self):
        import matrix
        self.matrix = matrix

    def test_a_pending_stage_is_not_a_failure_but_is_reported(self):
        outcome = self.matrix.Outcome("boot-chain", "pending", "waits",
                                      waiting_for="an image")
        self.assertTrue(outcome.ok)
        text = "\n".join(self.matrix.report([outcome]))
        self.assertIn("[wait]", text)
        self.assertIn("needs an image", text)
        self.assertIn("0 passed, 0 failed, 1 pending", text)
        self.assertIn("not green until they run", text)

    def test_a_failed_stage_fails_the_run(self):
        outcomes = [self.matrix.Outcome("firmware", "passed", "up"),
                    self.matrix.Outcome("install", "failed", "no")]
        self.assertFalse(all(outcome.ok for outcome in outcomes))

    def test_escape_sequences_are_stripped_before_assertions(self):
        # Firmware draws its console with ANSI sequences; asserting on raw
        # bytes would make the check depend on how OVMF happens to redraw.
        drawn = "\x1b[2J\x1b[001;001H>>Start PXE over IPv4."
        self.assertEqual(self.matrix.strip_escapes(drawn), ">>Start PXE over IPv4.")

    def test_the_pending_stages_name_the_artifact_they_need(self):
        for stage in (self.matrix.stage_boot_chain, self.matrix.stage_install,
                      self.matrix.stage_activation, self.matrix.stage_converge):
            with self.subTest(stage=stage.__name__):
                outcome = stage()
                self.assertEqual(outcome.state, "pending")
                self.assertTrue(outcome.waiting_for)
