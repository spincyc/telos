"""Preflight judgement across the shapes real hardware actually takes.

A fixture captured from one machine only proves the installer works on that
machine, and the machines this will run on are not that machine. What
generalises is the *shape*: how the disk is named, whether it reports a serial,
whether it is removable, whether the only network interface is wireless. Those
are what preflight has to judge, and they are what these fixtures vary.

Each fixture is one shape, and each test states the judgement that shape must
receive. If a real machine later behaves in a way none of these describe, the
right response is a new shape here, not a special case in the installer.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT / "lib"))

import disks as disks_module  # noqa: E402
import hardware               # noqa: E402
import preflight              # noqa: E402


def assess(name, profile="controller"):
    collector = hardware.FixtureCollector.from_file(FIXTURES / f"{name}.json")
    return preflight.assess(collector, profile)


def eligible_disks(result):
    return [candidate.item for candidate in result.disks if candidate.eligible]


def excluded(result):
    return {candidate.item.path: candidate.reason
            for candidate in result.disks if not candidate.eligible}


class TestOrdinaryModernMachine(unittest.TestCase):
    def test_a_single_nvme_and_one_wired_nic_installs(self):
        result = assess("uefi-single-nvme")
        self.assertEqual(result.refusals, [])
        self.assertEqual([disk.path for disk in eligible_disks(result)],
                         ["/dev/nvme0n1"])

    def test_the_nvme_partition_suffix_is_correct(self):
        # /dev/nvme0n1 partitions are nvme0n1p1, not nvme0n11. Getting this
        # wrong targets a device that does not exist -- or one that does.
        layout = disks_module.Layout("/dev/nvme0n1")
        self.assertEqual(layout.esp_partition, "/dev/nvme0n1p1")
        self.assertEqual(layout.luks_partition, "/dev/nvme0n1p2")


class TestSeveralEligibleDisks(unittest.TestCase):
    def test_every_large_fixed_disk_with_a_serial_is_offered(self):
        result = assess("uefi-mixed-nvme-sata")
        self.assertEqual([disk.path for disk in eligible_disks(result)],
                         ["/dev/nvme0n1", "/dev/sda", "/dev/sdb"])

    def test_the_partition_suffix_differs_per_family_on_one_machine(self):
        # The same machine yields both naming conventions, which is exactly
        # where a single hard-coded suffix would go wrong.
        self.assertEqual(disks_module.Layout("/dev/nvme0n1").esp_partition,
                         "/dev/nvme0n1p1")
        self.assertEqual(disks_module.Layout("/dev/sda").esp_partition,
                         "/dev/sda1")

    def test_an_unplugged_wired_interface_is_still_offered(self):
        # ADR 0010: the Controller is routinely installed on one network and
        # carried to another while powered off, so the managed interface is
        # often disconnected during installation. Carrier is required at first
        # boot instead.
        result = assess("uefi-mixed-nvme-sata")
        offered = [candidate.item.name for candidate in result.interfaces
                   if candidate.eligible]
        self.assertIn("enp4s0", offered)


class TestEmbeddedStorage(unittest.TestCase):
    def test_emmc_takes_the_p_separator(self):
        self.assertEqual(disks_module.Layout("/dev/mmcblk0").esp_partition,
                         "/dev/mmcblk0p1")

    def test_a_small_emmc_is_excluded_and_the_ssd_is_offered(self):
        result = assess("uefi-emmc-plus-ssd")
        self.assertEqual([disk.path for disk in eligible_disks(result)],
                         ["/dev/sda"])
        self.assertIn("/dev/mmcblk0", excluded(result))

    def test_absent_tpm_does_not_prevent_installation(self):
        # Milestone A requires the LUKS2 passphrase at every boot. TPM unlock is
        # deliberately deferred, so a machine without one installs normally.
        self.assertEqual(assess("uefi-emmc-plus-ssd").refusals, [])


class TestLabGuest(unittest.TestCase):
    """The acceptance matrix installs onto this shape, so it must be installable."""

    def test_the_virtual_disk_is_offered(self):
        result = assess("uefi-virtio-lab-guest")
        self.assertEqual(result.refusals, [])
        self.assertEqual([disk.path for disk in eligible_disks(result)],
                         ["/dev/vda"])

    def test_it_reports_the_serial_the_harness_must_type(self):
        result = assess("uefi-virtio-lab-guest")
        self.assertEqual(eligible_disks(result)[0].serial, "LAB-CONTROLLER-0001")

    def test_the_fixture_matches_what_the_lab_actually_builds(self):
        # If lab.py stops setting a serial, this fixture stops describing the
        # guest and the matrix would fail with "no eligible disk" instead.
        sys.path.insert(0, str(ROOT / "qemu"))
        import lab
        self.assertEqual(lab.serial_for("controller"), "LAB-CONTROLLER-0001")

    def test_a_virtual_disk_with_no_serial_would_be_refused(self):
        # Which is what QEMU does by default, and why lab.py sets one. Kept as a
        # test so the reason survives the next person reading that argv.
        collector = hardware.FixtureCollector({
            "lsblk": {"blockdevices": [{
                "path": "/dev/vda", "type": "disk", "model": "", "serial": "",
                "size": 80 * 1024 ** 3, "rm": False, "rota": False,
                "tran": "virtio"}]},
            "interfaces": [{"name": "enp0s2", "mac": "52:54:00:00:00:01",
                            "carrier": True, "speed": 1000, "wireless": False}],
            "firmware": {"uefi": True, "secure_boot": False, "tpm2": False}})
        result = preflight.assess(collector, "controller")
        self.assertTrue(result.refusals)


class TestNothingInstallable(unittest.TestCase):
    def test_each_disk_is_excluded_for_its_own_stated_reason(self):
        reasons = excluded(assess("uefi-no-eligible-disk"))
        self.assertIn("removable", reasons["/dev/sda"])
        self.assertIn("64 GiB minimum", reasons["/dev/sdb"])
        self.assertIn("no serial", reasons["/dev/sdc"])

    def test_the_machine_is_refused_rather_than_offered_a_bad_choice(self):
        self.assertTrue(assess("uefi-no-eligible-disk").refusals)

    def test_the_exclusions_are_printed_not_merely_applied(self):
        # An operator who cannot see why their disk is missing concludes the
        # installer is broken and reaches for something more dangerous.
        result = assess("uefi-no-eligible-disk")
        printed = "\n".join(preflight.excluded_lines(result.disks, "Disks"))
        for path in ("/dev/sda", "/dev/sdb", "/dev/sdc"):
            self.assertIn(path, printed)


class TestWirelessOnly(unittest.TestCase):
    def test_a_controller_is_refused(self):
        result = assess("uefi-wireless-only", "controller")
        self.assertTrue(result.refusals)

    def test_the_same_machine_installs_as_a_workstation(self):
        # A Workstation chooses no managed interface, so having only wireless
        # is not a problem for it.
        result = assess("uefi-wireless-only", "workstation")
        self.assertEqual(result.refusals, [])


if __name__ == "__main__":
    unittest.main()
