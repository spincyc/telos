"""Tests for hardware collection and preflight judgement.

These run against fixtures captured from real machines rather than invented
ones, so they exercise the same parsers the installer uses on metal. The
`workstation-usb-plus-nvme` fixture is this development machine: a USB stick and
an NVMe drive, which is exactly the arrangement where offering the wrong disk
would destroy the installer's own boot medium.
"""

import sys
import unittest
from pathlib import Path

LIB = Path(__file__).resolve().parents[1] / "lib"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(LIB))

import preflight  # noqa: E402
from hardware import Disk, FixtureCollector, Firmware, Interface, parse_lsblk  # noqa: E402


def load(name):
    return FixtureCollector.from_file(FIXTURES / f"{name}.json")


class TestParsing(unittest.TestCase):
    def test_only_whole_disks_are_returned(self):
        # Real lsblk output nests partitions under their disk. A partition is
        # never an installation target and offering one would be permanent.
        payload = {"blockdevices": [
            {"path": "/dev/sda", "type": "disk", "size": 100 * 2**30, "serial": "A"},
            {"path": "/dev/sda1", "type": "part", "size": 1 * 2**30, "serial": None},
            {"path": "/dev/loop0", "type": "loop", "size": 1, "serial": None},
        ]}
        disks = parse_lsblk(payload)
        self.assertEqual([d.path for d in disks], ["/dev/sda"])

    def test_missing_fields_do_not_raise(self):
        # lsblk reports null for model and serial on plenty of devices.
        disks = parse_lsblk({"blockdevices": [
            {"name": "sdz", "type": "disk", "size": None, "model": None, "serial": None}]})
        self.assertEqual(disks[0].path, "/dev/sdz")
        self.assertEqual(disks[0].serial, "")
        self.assertEqual(disks[0].size_bytes, 0)

    def test_real_fixture_parses(self):
        disks = load("workstation-usb-plus-nvme").disks()
        paths = {d.path for d in disks}
        self.assertIn("/dev/nvme0n1", paths)
        self.assertIn("/dev/sda", paths)


class TestDiskEligibility(unittest.TestCase):
    def test_the_usb_boot_stick_is_never_offered(self):
        # The most destructive available mistake: wiping the installer's own
        # medium. It must not appear as a choice at all.
        collector = load("workstation-usb-plus-nvme")
        result = preflight.assess(collector, "controller")
        offered = {d.path for d in result.eligible_disks}
        self.assertNotIn("/dev/sda", offered)
        self.assertIn("/dev/nvme0n1", offered)

    def test_the_exclusion_reason_is_stated(self):
        collector = load("workstation-usb-plus-nvme")
        result = preflight.assess(collector, "controller")
        excluded = {c.item.path: c.reason for c in result.disks if not c.eligible}
        self.assertIn("removable", excluded["/dev/sda"])

    def test_a_disk_without_a_serial_is_refused(self):
        # ADR 0058 confirms the wipe by typing the serial, so a disk with no
        # serial cannot be confirmed and must not be offered.
        disk = Disk("/dev/sdc", "HGST", "", 4000 * 10**9, False, True, "sata")
        candidate = preflight.assess_disk(disk)
        self.assertFalse(candidate.eligible)
        self.assertIn("no serial", candidate.reason)

    def test_a_disk_below_the_minimum_is_refused(self):
        disk = Disk("/dev/sdb", "TS32GSSD", "TS-A99", 32 * 2**30, False, False, "sata")
        candidate = preflight.assess_disk(disk)
        self.assertFalse(candidate.eligible)
        self.assertIn("64 GiB minimum", candidate.reason)

    def test_a_plausible_disk_is_accepted(self):
        disk = Disk("/dev/nvme0n1", "Samsung", "S7YANJ", 4000 * 10**9, False, False, "nvme")
        self.assertTrue(preflight.assess_disk(disk).eligible)

    def test_awkward_fixture_leaves_exactly_one_usable_disk(self):
        # Four disks: a USB stick, a too-small SSD, a serial-less drive, and one
        # good one. Only the last may be offered.
        collector = load("legacy-bios-awkward-disks")
        result = preflight.assess(collector, "controller")
        self.assertEqual([d.path for d in result.eligible_disks], ["/dev/sdd"])


class TestInterfaceEligibility(unittest.TestCase):
    def test_wireless_is_not_offered(self):
        collector = load("legacy-bios-awkward-disks")
        result = preflight.assess(collector, "controller")
        names = {i.name for i in result.eligible_interfaces}
        self.assertNotIn("wlp5s0", names)

    def test_an_unplugged_wired_interface_is_still_offered(self):
        # ADR 0010 relocates the Controller while powered off, so the managed
        # interface is often unplugged during provisioning. Absence of carrier
        # is noted, not disqualifying.
        interface = Interface("eno2", "60:cf:84:77:c6:6e", False, None, False)
        candidate = preflight.assess_interface(interface)
        self.assertTrue(candidate.eligible)
        self.assertIn("no link", candidate.reason)

    def test_an_interface_without_a_mac_is_refused(self):
        candidate = preflight.assess_interface(Interface("dummy0", "", True, None, False))
        self.assertFalse(candidate.eligible)

    def test_real_machine_offers_both_wired_ports(self):
        result = preflight.assess(load("workstation-usb-plus-nvme"), "controller")
        self.assertEqual({i.name for i in result.eligible_interfaces}, {"eno1", "eno2"})


class TestRefusals(unittest.TestCase):
    def test_legacy_bios_refuses_the_install(self):
        # ADR 0019. This must stop before any destructive action is offered.
        result = preflight.assess(load("legacy-bios-awkward-disks"), "controller")
        self.assertFalse(result.may_proceed)
        self.assertTrue(any("UEFI" in r for r in result.refusals))

    def test_uefi_machine_may_proceed(self):
        result = preflight.assess(load("workstation-usb-plus-nvme"), "controller")
        self.assertTrue(result.may_proceed)
        self.assertEqual(result.refusals, [])

    def test_no_usable_disk_refuses(self):
        class OnlyUsb:
            def disks(self):
                return [Disk("/dev/sda", "Stick", "X", 64 * 2**30, True, True, "usb")]
            def interfaces(self):
                return [Interface("eno1", "aa:bb:cc:dd:ee:ff", True, 1000, False)]
            def firmware(self):
                return Firmware(True, "disabled", True)
        result = preflight.assess(OnlyUsb(), "controller")
        self.assertFalse(result.may_proceed)
        self.assertTrue(any("No disk" in r for r in result.refusals))

    def test_a_workstation_does_not_need_an_interface(self):
        class NoNic:
            def disks(self):
                return [Disk("/dev/sda", "SSD", "S1", 500 * 2**30, False, False, "sata")]
            def interfaces(self):
                return []
            def firmware(self):
                return Firmware(True, "enabled", True)
        self.assertTrue(preflight.assess(NoNic(), "workstation").may_proceed)
        self.assertFalse(preflight.assess(NoNic(), "controller").may_proceed)


class TestSummary(unittest.TestCase):
    def build(self, development_proof=True):
        result = preflight.assess(load("workstation-usb-plus-nvme"), "controller")
        target = result.eligible_disks[0]
        return preflight.summary_lines(
            preflight=result, profile="controller", hostname="polycarp",
            target=target, interface=result.eligible_interfaces[0],
            network_rows=[("Managed subnet", "10.0.7.0/24 (255.255.255.0)"),
                          ("Default router", "none advertised")],
            development_proof=development_proof), target

    def test_names_the_disk_by_serial(self):
        lines, target = self.build()
        text = "\n".join(lines)
        self.assertIn(target.serial, text)
        self.assertIn(target.path, text)

    def test_states_the_destruction_plainly(self):
        lines, _ = self.build()
        text = "\n".join(lines)
        self.assertIn("COMPLETELY ERASED", text)
        self.assertIn("not recoverable", text)

    def test_carries_the_derived_network_plan(self):
        # ADR 0045 requires the entered and derived plan in this summary.
        text = "\n".join(self.build()[0])
        self.assertIn("none advertised", text)

    def test_labels_development_proof(self):
        # ADR 0043 requires the proof mode to be displayed and recorded.
        self.assertIn("NOT A PRODUCTION INSTALLATION", "\n".join(self.build(True)[0]))
        self.assertNotIn("NOT A PRODUCTION INSTALLATION", "\n".join(self.build(False)[0]))

    def test_excluded_disks_are_explained(self):
        result = preflight.assess(load("workstation-usb-plus-nvme"), "controller")
        text = "\n".join(preflight.excluded_lines(result.disks, "Disks"))
        self.assertIn("/dev/sda", text)
        self.assertIn("excluded:", text)


if __name__ == "__main__":
    unittest.main()
