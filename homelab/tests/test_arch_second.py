import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workstations.arch_second import (
    ESP, LINUX_ROOT_X86_64, MSR, WINDOWS, WINDOWS_RECOVERY,
    Disk, InstallContractError, Partition, parse_lsblk, render_installer,
    validate_windows_first,
)
from lib.package_contract import PROFILE_OVERLAYS, load_registry, merge_contract

MIB = 1024**2
SIZES = (1024, 16, 300 * 1024, 100 * 1024, 2048)
GUIDS = (ESP, MSR, WINDOWS, LINUX_ROOT_X86_64, WINDOWS_RECOVERY)
FILESYSTEMS = ("vfat", None, "ntfs", None, "ntfs")


def good_disk():
    return Disk("/dev/nvme0n1", "LAPTOP-1", "gpt", tuple(
        Partition(number, f"/dev/nvme0n1p{number}", guid, size * MIB, filesystem)
        for number, (guid, size, filesystem)
        in enumerate(zip(GUIDS, SIZES, FILESYSTEMS), 1)
    ))

def unallocated_disk(*, arch_mib=SIZES[3], extra_gap_mib=0):
    sector = 512
    start = MIB // sector
    parts = []
    # Windows creates ESP, MSR, OS, and Recovery; partition numbering and
    # physical order are not used as identities.
    for number, role_index in enumerate((0, 1, 2, 4), 1):
        guid = GUIDS[role_index]
        size_mib = SIZES[role_index]
        parts.append(Partition(
            number, f"/dev/nvme0n1p{number}", guid, size_mib * MIB,
            FILESYSTEMS[role_index], start,
        ))
        start += size_mib * MIB // sector
    disk_mib = 2 + sum(part.size_bytes // MIB for part in parts) + arch_mib
    if extra_gap_mib:
        # Move Recovery right, producing a second material gap.
        recovery = parts[-1]
        parts[-1] = Partition(
            recovery.number, recovery.path, recovery.type_guid,
            recovery.size_bytes, recovery.filesystem,
            recovery.start_sector + extra_gap_mib * MIB // sector,
        )
        disk_mib += extra_gap_mib
    return Disk(
        "/dev/nvme0n1", "LAPTOP-1", "gpt", tuple(parts),
        disk_mib * MIB, sector,
    )


class ArchSecondTests(unittest.TestCase):
    def test_installer_packages_are_the_workstation_contract(self):
        script = render_installer(
            disk_path="/dev/nvme0n1", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        required = merge_contract(
            load_registry(
                Path(__file__).resolve().parents[1] / "package-contract.json"
            ),
            PROFILE_OVERLAYS["workstation-install"],
        ).packages
        pacstrap = next(
            line for line in script.splitlines()
            if line.startswith("pacstrap -K ")
        )
        self.assertEqual(
            tuple(pacstrap.split()[3:]),
            required,
        )

    def test_accepts_exact_windows_first_shape(self):
        roles = validate_windows_first(
            good_disk(), required_serial="LAPTOP-1", expected_sizes_mib=SIZES
        )
        self.assertEqual(roles["esp"], "/dev/nvme0n1p1")
        self.assertEqual(roles["arch"], "/dev/nvme0n1p4")

    def test_accepts_one_exact_unallocated_arch_extent(self):
        roles = validate_windows_first(
            unallocated_disk(), required_serial="LAPTOP-1",
            expected_sizes_mib=SIZES,
        )
        self.assertNotIn("arch", roles)
        self.assertEqual(int(roles["_arch_size_sectors"]), SIZES[3] * 2048)

    def test_partition_numbers_are_not_role_identities(self):
        disk = good_disk()
        renumbered = tuple(
            Partition(8 - part.number, part.path.replace(
                f"p{part.number}", f"p{8 - part.number}"
            ), part.type_guid, part.size_bytes, part.filesystem)
            for part in disk.partitions
        )
        roles = validate_windows_first(
            Disk(disk.path, disk.serial, "gpt", renumbered),
            required_serial=disk.serial, expected_sizes_mib=SIZES,
        )
        self.assertEqual(roles["esp"], "/dev/nvme0n1p7")

    def test_refuses_ambiguous_or_wrong_sized_free_space(self):
        with self.assertRaisesRegex(InstallContractError, "exactly one"):
            validate_windows_first(
                unallocated_disk(arch_mib=SIZES[3] - 20),
                required_serial="LAPTOP-1", expected_sizes_mib=SIZES,
            )
        with self.assertRaisesRegex(InstallContractError, "exactly one"):
            validate_windows_first(
                unallocated_disk(extra_gap_mib=10),
                required_serial="LAPTOP-1", expected_sizes_mib=SIZES,
            )

    def test_refuses_wrong_disk_before_partition_access(self):
        with self.assertRaisesRegex(InstallContractError, "serial mismatch"):
            validate_windows_first(
                good_disk(), required_serial="OTHER", expected_sizes_mib=SIZES
            )

    def test_refuses_missing_extra_reordered_or_retyped_partition(self):
        base = good_disk()
        cases = (
            base.partitions[:-1],
            base.partitions + (Partition(6, "/dev/nvme0n1p6", WINDOWS, MIB, "ntfs"),),
            tuple(reversed(base.partitions)),
            base.partitions[:3] + (
                Partition(4, "/dev/nvme0n1p4", WINDOWS, SIZES[3] * MIB, None),
            ) + base.partitions[4:],
        )
        # Reverse JSON order remains safe because GPT role GUIDs identify shape.
        validate_windows_first(
            Disk(base.path, base.serial, base.partition_table, cases[2]),
            required_serial=base.serial, expected_sizes_mib=SIZES,
        )
        for parts in (cases[0], cases[1], cases[3]):
            with self.assertRaises(InstallContractError):
                validate_windows_first(
                    Disk(base.path, base.serial, base.partition_table, parts),
                    required_serial=base.serial, expected_sizes_mib=SIZES,
                )

    def test_refuses_size_drift_and_non_gpt(self):
        base = good_disk()
        changed = base.partitions[:3] + (
            Partition(4, "/dev/nvme0n1p4", LINUX_ROOT_X86_64,
                      (SIZES[3] - 10) * MIB, None),
        ) + base.partitions[4:]
        with self.assertRaisesRegex(InstallContractError, "size mismatch"):
            validate_windows_first(
                Disk(base.path, base.serial, "gpt", changed),
                required_serial=base.serial, expected_sizes_mib=SIZES,
            )
        with self.assertRaisesRegex(InstallContractError, "GPT"):
            validate_windows_first(
                Disk(base.path, base.serial, "dos", base.partitions),
                required_serial=base.serial, expected_sizes_mib=SIZES,
            )

    def test_requires_windows_filesystems_and_unformatted_arch_slot(self):
        base = good_disk()
        formatted_arch = base.partitions[:3] + (
            Partition(4, "/dev/nvme0n1p4", LINUX_ROOT_X86_64,
                      SIZES[3] * MIB, "ext4"),
        ) + base.partitions[4:]
        with self.assertRaisesRegex(InstallContractError, "filesystem mismatch"):
            validate_windows_first(
                Disk(base.path, base.serial, "gpt", formatted_arch),
                required_serial=base.serial, expected_sizes_mib=SIZES,
            )

    def test_parses_nvme_lsblk_json(self):
        document = {"blockdevices": [{
            "path": "/dev/nvme0n1", "type": "disk", "serial": "LAPTOP-1",
            "pttype": "gpt",
            "children": [
                {"path": f"/dev/nvme0n1p{i}", "type": "part",
                 "parttype": guid.lower(), "size": size * MIB,
                 "fstype": filesystem}
                for i, (guid, size, filesystem)
                in enumerate(zip(GUIDS, SIZES, FILESYSTEMS), 1)
            ],
        }]}
        self.assertEqual(
            parse_lsblk(json.loads(json.dumps(document)), "/dev/nvme0n1"),
            good_disk(),
        )

    def test_installer_never_repartitions_or_formats_windows(self):
        script = render_installer(
            disk_path="/dev/nvme0n1", disk_serial="LAPTOP-1",
            hostname="stephen", expected_sizes_mib=SIZES,
        )
        self.assertEqual(script.count("sfdisk"), 1)
        self.assertIn("sfdisk --append", script)
        self.assertNotIn("parted", script)
        self.assertNotIn("wipefs", script)
        self.assertNotIn("mkfs.fat", script)
        self.assertEqual(script.count("mkfs."), 1)
        self.assertIn('mkfs.ext4 -F -L ARCH_ROOT "$ARCH_PART"', script)
        self.assertIn('mount "$ESP_PART" /mnt/boot', script)
        self.assertIn("default auto-windows", script)
        self.assertIn("bootctl --root=/mnt set-default auto-windows", script)
        self.assertNotIn("adcli", script)
        self.assertNotIn("oddjob", script)
        self.assertIn("sssd", script)
        self.assertIn("samba", script)

    def test_rejects_injection_in_machine_identifiers(self):
        with self.assertRaises(InstallContractError):
            render_installer(
                disk_path="/dev/nvme0n1;reboot", disk_serial="LAPTOP-1",
                hostname="stephen", expected_sizes_mib=SIZES,
            )
        with self.assertRaises(InstallContractError):
            render_installer(
                disk_path="/dev/nvme0n1", disk_serial="LAPTOP-1",
                hostname="bad;reboot", expected_sizes_mib=SIZES,
            )


if __name__ == "__main__":
    unittest.main()
