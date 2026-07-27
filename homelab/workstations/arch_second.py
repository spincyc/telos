"""Plan and render a fail-closed Arch-after-Windows installation.

The emitted installer is intentionally boring.  Windows has already authored
the GPT.  Arch may use either an existing, unformatted Linux-root partition or
the sole free extent whose measured size exactly matches the approved plan.
It mounts the existing ESP without formatting it and never resizes, deletes,
or recreates a Windows partition.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence


ESP = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
MSR = "E3C9E316-0B5C-4DB8-817D-F92DF00215AE"
WINDOWS = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
LINUX_ROOT_X86_64 = "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709"
WINDOWS_RECOVERY = "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC"

EXPECTED = (
    ("esp", ESP),
    ("msr", MSR),
    ("windows", WINDOWS),
    ("arch", LINUX_ROOT_X86_64),
    ("recovery", WINDOWS_RECOVERY),
)
SAFE_HOSTNAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
SAFE_SERIAL = re.compile(r"^[A-Za-z0-9_.:+-]{1,128}$")
SAFE_DISK = re.compile(r"^/dev/[A-Za-z0-9._+-]{1,128}$")


class InstallContractError(ValueError):
    """A disk or setting cannot satisfy the non-destructive install contract."""


@dataclass(frozen=True)
class Partition:
    number: int
    path: str
    type_guid: str
    size_bytes: int
    filesystem: str | None = None
    start_sector: int | None = None


@dataclass(frozen=True)
class Disk:
    path: str
    serial: str
    partition_table: str
    partitions: tuple[Partition, ...]
    size_bytes: int | None = None
    logical_sector_bytes: int | None = None


def _partition_number(path: str, disk_path: str) -> int:
    suffix = path[len(disk_path):]
    if suffix.startswith("p"):
        suffix = suffix[1:]
    if not suffix.isdigit():
        raise InstallContractError(f"cannot determine partition number: {path}")
    return int(suffix)


def parse_lsblk(document: Mapping[str, Any], disk_path: str) -> Disk:
    """Parse one lsblk JSON disk without guessing which disk is intended."""
    devices = document.get("blockdevices")
    if not isinstance(devices, list):
        raise InstallContractError("lsblk JSON has no blockdevices array")
    matches = [
        item for item in devices
        if isinstance(item, dict) and item.get("path") == disk_path
    ]
    if len(matches) != 1:
        raise InstallContractError(f"expected exactly one disk at {disk_path}")
    item = matches[0]
    if item.get("type") != "disk":
        raise InstallContractError(f"{disk_path} is not a disk")
    children = item.get("children")
    if not isinstance(children, list):
        raise InstallContractError(f"{disk_path} has no partitions")
    partitions = []
    for child in children:
        if not isinstance(child, dict) or child.get("type") != "part":
            raise InstallContractError(f"{disk_path} has an unexpected child")
        path = child.get("path")
        guid = child.get("parttype")
        size = child.get("size")
        filesystem = child.get("fstype")
        start = child.get("start")
        if not isinstance(path, str) or not isinstance(guid, str):
            raise InstallContractError("partition path or type GUID is missing")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise InstallContractError(f"{path} has an invalid size")
        partitions.append(Partition(
            _partition_number(path, disk_path), path, guid.upper(), size,
            filesystem if isinstance(filesystem, str) and filesystem else None,
            start if isinstance(start, int) and not isinstance(start, bool) else None,
        ))
    serial = item.get("serial")
    pttype = item.get("pttype")
    if not isinstance(serial, str) or not serial:
        raise InstallContractError(f"{disk_path} has no stable serial")
    if not isinstance(pttype, str):
        raise InstallContractError(f"{disk_path} has no partition-table type")
    disk_size = item.get("size")
    sector_size = item.get("log-sec")
    return Disk(
        disk_path, serial, pttype.lower(), tuple(partitions),
        disk_size if isinstance(disk_size, int) else None,
        sector_size if isinstance(sector_size, int) else None,
    )


def validate_windows_first(
    disk: Disk,
    *,
    required_serial: str,
    expected_sizes_mib: Sequence[int],
    tolerance_mib: int = 2,
) -> dict[str, str]:
    """Return role-to-device mapping only for the exact approved GPT shape."""
    if not SAFE_SERIAL.fullmatch(required_serial):
        raise InstallContractError("required disk serial is not safely representable")
    if disk.serial != required_serial:
        raise InstallContractError(
            f"disk serial mismatch: expected {required_serial}, found {disk.serial}"
        )
    if disk.partition_table != "gpt":
        raise InstallContractError("Windows-first disk must use GPT")
    if len(expected_sizes_mib) != len(EXPECTED):
        raise InstallContractError("five expected partition sizes are required")
    if len({part.number for part in disk.partitions}) != len(disk.partitions):
        raise InstallContractError("disk contains duplicate partition numbers")
    by_guid: dict[str, list[Partition]] = {}
    for part in disk.partitions:
        by_guid.setdefault(part.type_guid, []).append(part)
    known_guids = {guid for _, guid in EXPECTED}
    if any(part.type_guid not in known_guids for part in disk.partitions):
        raise InstallContractError("disk contains an unexpected partition type")
    if len(disk.partitions) not in {4, 5}:
        raise InstallContractError("disk must contain four Windows roles and optional Arch")
    roles: dict[str, str] = {}
    expected_filesystems = {
        "esp": "vfat",
        "msr": None,
        "windows": "ntfs",
        "arch": None,
        "recovery": "ntfs",
    }
    for (role, guid), expected_mib in zip(EXPECTED, expected_sizes_mib):
        matches = by_guid.get(guid, [])
        if role == "arch" and not matches:
            continue
        if len(matches) != 1:
            raise InstallContractError(f"expected exactly one {role} partition")
        part = matches[0]
        actual_mib = part.size_bytes // 1024**2
        if abs(actual_mib - expected_mib) > tolerance_mib:
            raise InstallContractError(
                f"partition {part.number} ({role}) size mismatch: "
                f"expected {expected_mib} MiB, found {actual_mib} MiB"
            )
        if part.filesystem != expected_filesystems[role]:
            expected = expected_filesystems[role] or "unformatted"
            found = part.filesystem or "unformatted"
            raise InstallContractError(
                f"partition {part.number} ({role}) filesystem mismatch: "
                f"expected {expected}, found {found}"
            )
        roles[role] = part.path
    required_windows_roles = {"esp", "msr", "windows", "recovery"}
    if not required_windows_roles.issubset(roles):
        raise InstallContractError("one or more Windows partition roles are missing")
    if "arch" not in roles:
        start, sectors = _find_arch_gap(
            disk, expected_sizes_mib[3], tolerance_mib=tolerance_mib
        )
        roles["_arch_start_sector"] = str(start)
        roles["_arch_size_sectors"] = str(sectors)
    return roles


def _find_arch_gap(
    disk: Disk, expected_mib: int, *, tolerance_mib: int
) -> tuple[int, int]:
    """Find the sole planned free extent; reject unknown or ambiguous space."""
    if not disk.size_bytes or not disk.logical_sector_bytes:
        raise InstallContractError("disk geometry is required for an unallocated Arch slot")
    sector = disk.logical_sector_bytes
    if sector <= 0 or disk.size_bytes % sector:
        raise InstallContractError("disk has invalid logical-sector geometry")
    if any(part.start_sector is None for part in disk.partitions):
        raise InstallContractError("partition starts are required for free-space proof")
    # Reserve the conventional first and last MiB for GPT/alignment metadata.
    margin = 1024**2 // sector
    disk_sectors = disk.size_bytes // sector
    extents = sorted(
        (part.start_sector, part.start_sector + part.size_bytes // sector)
        for part in disk.partitions
    )
    cursor = margin
    gaps = []
    for start, end in extents:
        if start < cursor or end <= start or end > disk_sectors - margin:
            raise InstallContractError("partition extents overlap or exceed the safe disk area")
        if start > cursor:
            gaps.append((cursor, start - cursor))
        cursor = end
    if cursor < disk_sectors - margin:
        gaps.append((cursor, disk_sectors - margin - cursor))
    tolerance_sectors = tolerance_mib * 1024**2 // sector
    expected_sectors = expected_mib * 1024**2 // sector
    material = [
        gap for gap in gaps
        if gap[1] > tolerance_sectors
    ]
    candidates = [
        gap for gap in material
        if abs(gap[1] - expected_sectors) <= tolerance_sectors
    ]
    if len(candidates) != 1 or len(material) != 1:
        raise InstallContractError(
            "disk does not contain exactly one planned unallocated Arch extent"
        )
    return candidates[0]


def render_installer(
    *,
    disk_path: str,
    disk_serial: str,
    hostname: str,
    expected_sizes_mib: Sequence[int],
) -> str:
    """Render the destructive stage with its validation embedded before mkfs."""
    if not SAFE_DISK.fullmatch(disk_path):
        raise InstallContractError("disk path must be a simple /dev path")
    if not SAFE_SERIAL.fullmatch(disk_serial):
        raise InstallContractError("disk serial is not safely representable")
    if not SAFE_HOSTNAME.fullmatch(hostname):
        raise InstallContractError("hostname is invalid")
    if len(expected_sizes_mib) != 5 or any(
        isinstance(size, bool) or not isinstance(size, int) or size <= 0
        for size in expected_sizes_mib
    ):
        raise InstallContractError("five positive integer sizes are required")
    sizes = ",".join(str(size) for size in expected_sizes_mib)
    return f"""#!/usr/bin/env bash
set -euo pipefail
disk={disk_path!r}
required_serial={disk_serial!r}
hostname={hostname!r}
expected_sizes={sizes!r}

[[ $(id -u) -eq 0 ]] || {{ echo "run as root" >&2; exit 1; }}
[[ $(lsblk -dnro TYPE "$disk") == disk ]] || {{ echo "target is not a disk" >&2; exit 1; }}
[[ $(lsblk -dnro SERIAL "$disk") == "$required_serial" ]] || {{
  echo "disk serial mismatch" >&2; exit 1;
}}
python3 /usr/local/lib/telos/arch-second-verify.py \
  --disk "$disk" --serial "$required_serial" --sizes-mib "$expected_sizes"

# Assignments are emitted only after proving every Windows role and either the
# existing Arch slot or the sole planned free extent.
eval "$(python3 /usr/local/lib/telos/arch-second-verify.py \
  --disk "$disk" --serial "$required_serial" --sizes-mib "$expected_sizes" \
  --shell)"
if [[ -z "$ARCH_PART" ]]; then
  printf '%s,%s,%s\\n' "$ARCH_START" "$ARCH_SECTORS" \
    {LINUX_ROOT_X86_64!r} | sfdisk --append "$disk"
  partprobe "$disk"
  udevadm settle
  eval "$(python3 /usr/local/lib/telos/arch-second-verify.py \
    --disk "$disk" --serial "$required_serial" --sizes-mib "$expected_sizes" \
    --shell)"
fi
[[ -n "$ARCH_PART" && -n "$ESP_PART" ]] || exit 1
if findmnt -rn -S "$ARCH_PART" >/dev/null || \
   findmnt -rn -S "$ESP_PART" >/dev/null; then
  echo "target partition is already mounted" >&2; exit 1;
fi

# This is the sole filesystem creation in the second-OS install.
mkfs.ext4 -F -L ARCH_ROOT "$ARCH_PART"
mount "$ARCH_PART" /mnt
mkdir -p /mnt/boot
mount "$ESP_PART" /mnt/boot
pacstrap -K /mnt base linux-lts linux-firmware networkmanager sssd \
  krb5 samba sudo
genfstab -U /mnt >> /mnt/etc/fstab
printf '%s\\n' "$hostname" > /mnt/etc/hostname
arch-chroot /mnt systemctl enable NetworkManager
arch-chroot /mnt bootctl install
root_uuid=$(blkid -s UUID -o value "$ARCH_PART")
cat > /mnt/boot/loader/entries/arch-linux-lts.conf <<EOF
title Arch Linux LTS
linux /vmlinuz-linux-lts
initrd /initramfs-linux-lts.img
options root=UUID=$root_uuid rw
EOF
cat > /mnt/boot/loader/loader.conf <<'EOF'
default auto-windows
timeout 5
editor no
EOF
bootctl --root=/mnt set-default auto-windows
sync
echo "Arch installed; Windows partitions and filesystems were not modified."
"""


def main() -> int:
    import argparse
    import subprocess

    parser = argparse.ArgumentParser()
    parser.add_argument("--disk", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--sizes-mib", required=True)
    parser.add_argument("--shell", action="store_true")
    args = parser.parse_args()
    sizes = tuple(int(value) for value in args.sizes_mib.split(","))
    output = subprocess.run(
        ("lsblk", "--bytes", "--json", "-o",
         "PATH,TYPE,SERIAL,PTTYPE,PARTTYPE,SIZE,FSTYPE,START,LOG-SEC", args.disk),
        check=True, text=True, capture_output=True,
    )
    disk = parse_lsblk(json.loads(output.stdout), args.disk)
    roles = validate_windows_first(
        disk, required_serial=args.serial, expected_sizes_mib=sizes
    )
    if args.shell:
        print(f"ESP_PART={roles['esp']!r}")
        print(f"ARCH_PART={roles.get('arch', '')!r}")
        print(f"ARCH_START={roles.get('_arch_start_sector', '')!r}")
        print(f"ARCH_SECTORS={roles.get('_arch_size_sectors', '')!r}")
    else:
        print("PASS: Windows-first GPT matches the approved Arch install contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
