"""Tests for the disk layout commands and per-machine package selection.

ADR 0062 removed the layer that re-read a device to prove the layout; in the
QEMU matrix a wrong layout presents as a machine that does not boot. What is
still worth testing here is pure and cheap: partition naming across device
families, and microcode selection, which is a real correctness bug on
heterogeneous hardware rather than a stylistic one.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import disks  # noqa: E402


class TestPartitionNaming(unittest.TestCase):
    def test_sata_and_scsi_have_no_separator(self):
        layout = disks.Layout("/dev/sda")
        self.assertEqual(layout.esp_partition, "/dev/sda1")
        self.assertEqual(layout.luks_partition, "/dev/sda2")

    def test_nvme_takes_a_p_separator(self):
        # /dev/nvme0n11 would be a different device entirely.
        layout = disks.Layout("/dev/nvme0n1")
        self.assertEqual(layout.esp_partition, "/dev/nvme0n1p1")
        self.assertEqual(layout.luks_partition, "/dev/nvme0n1p2")

    def test_mmc_and_loop_take_a_p_separator(self):
        self.assertEqual(disks.Layout("/dev/mmcblk0").esp_partition, "/dev/mmcblk0p1")
        self.assertEqual(disks.Layout("/dev/loop3").esp_partition, "/dev/loop3p1")


class TestLayoutCommands(unittest.TestCase):
    def test_partitioning_writes_esp_then_luks(self):
        commands = disks.plan_partition("/dev/nvme0n1")
        self.assertIn(f"1:0:+{disks.ESP_SIZE_GIB}G", commands[0])
        self.assertIn(f"1:{disks.ESP_TYPE}", commands[0])
        self.assertIn("2:0:0", commands[1])
        self.assertIn(f"2:{disks.LUKS_TYPE}", commands[1])

    def test_kernel_is_told_to_reread_the_table(self):
        self.assertIn(["partprobe", "/dev/sda"], disks.plan_partition("/dev/sda"))

    def test_luks_is_version_2(self):
        argv = disks.plan_luks_format("/dev/sda2", "/run/key")[0]
        self.assertIn("--type", argv)
        self.assertEqual(argv[argv.index("--type") + 1], "luks2")

    def test_passphrase_never_appears_in_argv(self):
        # A keyfile path is passed, not a passphrase: argv is visible in the
        # process table and in any log of the commands run.
        argv = disks.plan_luks_format("/dev/sda2", "/run/installer.key")[0]
        self.assertIn("/run/installer.key", argv)
        self.assertNotIn("--key-file", argv)

    def test_every_adr_0027_subvolume_is_created(self):
        commands = disks.plan_subvolumes("/mnt")
        created = {argv[-1].rsplit("/", 1)[-1] for argv in commands}
        self.assertEqual(created, {name for name, _, _ in disks.SUBVOLUMES})

    def test_snapshot_store_is_its_own_subvolume(self):
        # It cannot live inside the thing it snapshots.
        names = {name for name, _, _ in disks.SUBVOLUMES}
        self.assertIn("@snapshots", names)
        self.assertIn("@log", names)


class TestMicrocode(unittest.TestCase):
    """Heterogeneous hardware: getting this wrong is silent."""

    def test_amd(self):
        self.assertEqual(disks.microcode_package("AuthenticAMD"), "amd-ucode")

    def test_intel(self):
        self.assertEqual(disks.microcode_package("GenuineIntel"), "intel-ucode")

    def test_unknown_vendor_gets_none_rather_than_a_guess(self):
        for vendor in ("", "  ", "SomeOtherVendor", None):
            with self.subTest(vendor=vendor):
                self.assertIsNone(disks.microcode_package(vendor))

    def test_reads_the_vendor_from_real_cpuinfo(self):
        sample = ("processor\t: 0\n"
                  "vendor_id\t: GenuineIntel\n"
                  "cpu family\t: 6\n"
                  "model name\t: Intel(R) Xeon(R) CPU\n")
        self.assertEqual(disks.read_cpu_vendor(sample), "GenuineIntel")

    def test_missing_vendor_line_is_empty_not_an_error(self):
        self.assertEqual(disks.read_cpu_vendor("processor\t: 0\n"), "")

    def test_base_packages_include_the_right_microcode(self):
        self.assertIn("amd-ucode", disks.base_packages("AuthenticAMD"))
        self.assertNotIn("intel-ucode", disks.base_packages("AuthenticAMD"))

    def test_base_packages_carry_both_kernels(self):
        # ADR 0017 and ADR 0018.
        packages = disks.base_packages("GenuineIntel")
        self.assertIn("linux-lts", packages)
        self.assertIn("linux", packages)

    def test_base_packages_stay_minimal(self):
        # Services and Controller roles do not leak into Workstation policy.
        packages = disks.base_packages("GenuineIntel")
        for required in ("python", "openssh", "sssd", "networkmanager"):
            self.assertIn(required, packages)
        for unwanted in ("nvidia", "gnome", "dnsmasq", "nginx", "ansible-core"):
            self.assertNotIn(unwanted, packages)


if __name__ == "__main__":
    unittest.main()
