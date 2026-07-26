"""Disk layout: the steps that actually write, and the checks that read back.

ADR 0051 fixes the Controller layout: a 2 GiB EFI System Partition and a LUKS2
container filling the rest, with Btrfs inside it. ADR 0027 fixes what belongs in
the checkpointed root and what must be excluded from it. Every step takes a
device path and nothing else, so nothing here discovers what to erase.

Every operation is a `plan_*` function returning the exact argv to run, so the
commands can be reviewed without being executed and printed in a dry run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

GIB = 1024 ** 3

# ADR 0051. Deliberate headroom, not a measurement: three UKIs, one carrying a
# full rescue userspace, plus room to stage a complete new set during an update
# before switching to it. The ESP cannot be grown later without moving
# everything behind it, which is why it is oversized on purpose.
ESP_SIZE_GIB = 2
MINIMUM_DISK_GIB = 64

ESP_TYPE = "ef00"          # EFI System
LUKS_TYPE = "8309"         # Linux LUKS
ESP_LABEL = "HL_ESP"
LUKS_LABEL = "HL_ROOT"

# ADR 0027. The root subvolume is the operating system and travels with the
# package database; everything that must survive a rollback, or that would make
# a checkpoint enormous and meaningless, is carved out of it.
SUBVOLUMES = (
    ("@",          "/",              "checkpointed: the operating system and /etc"),
    ("@home",      "/home",          "excluded: user data outlives an OS rollback"),
    ("@root",      "/root",          "excluded: the operator's own home"),
    ("@log",       "/var/log",       "excluded: a rollback must not erase the record of why"),
    ("@cache",     "/var/cache",     "excluded: disposable"),
    ("@srv",       "/srv",           "excluded: service data has its own restore point"),
    ("@snapshots", "/.snapshots",    "excluded: the snapshot store cannot live inside what it snapshots"),
    ("@swap",      "/swap",          "excluded: swapfile needs nodatacow and no compression"),
)


@dataclass(frozen=True)
class Layout:
    device: str

    @property
    def esp_partition(self) -> str:
        return _partition_path(self.device, 1)

    @property
    def luks_partition(self) -> str:
        return _partition_path(self.device, 2)


def _partition_path(device: str, number: int) -> str:
    """Partition naming differs between /dev/sda1 and /dev/nvme0n1p1.

    Getting this wrong targets a device that does not exist, or worse, one that
    does. NVMe, MMC and loop devices all take the 'p' separator.
    """
    if re.search(r"(nvme\d+n\d+|mmcblk\d+|loop\d+)$", device):
        return f"{device}p{number}"
    return f"{device}{number}"


# --------------------------------------------------------------------------
# Planning: exact commands, so they can be reviewed without being run
# --------------------------------------------------------------------------


def plan_wipe(device: str) -> list[list[str]]:
    """Remove existing signatures so a stale one cannot be picked up later."""
    return [
        ["wipefs", "--all", "--force", device],
        ["sgdisk", "--zap-all", device],
    ]


def plan_partition(device: str) -> list[list[str]]:
    """ADR 0051's two partitions, in one sgdisk invocation per partition."""
    return [
        ["sgdisk",
         "--new", f"1:0:+{ESP_SIZE_GIB}G",
         "--typecode", f"1:{ESP_TYPE}",
         "--change-name", f"1:{ESP_LABEL}",
         device],
        ["sgdisk",
         "--new", "2:0:0",
         "--typecode", f"2:{LUKS_TYPE}",
         "--change-name", f"2:{LUKS_LABEL}",
         device],
        # Make the kernel re-read the table before anything tries to use it.
        ["partprobe", device],
    ]


def plan_format_esp(esp_partition: str) -> list[list[str]]:
    return [["mkfs.fat", "-F", "32", "-n", ESP_LABEL, esp_partition]]


def plan_luks_format(luks_partition: str, keyfile: str) -> list[list[str]]:
    """LUKS2 with explicit parameters rather than whatever the defaults are.

    The keyfile is a path the caller creates and destroys; the passphrase never
    appears in argv, where it would be visible in the process table and in any
    log of the commands run.
    """
    return [[
        "cryptsetup", "luksFormat",
        "--type", "luks2",
        "--cipher", "aes-xts-plain64",
        "--key-size", "512",
        "--pbkdf", "argon2id",
        "--label", LUKS_LABEL,
        "--batch-mode",
        luks_partition,
        keyfile,
    ]]


def plan_luks_open(luks_partition: str, mapping: str, keyfile: str) -> list[list[str]]:
    return [["cryptsetup", "open", "--key-file", keyfile, luks_partition, mapping]]


def plan_btrfs(mapping_path: str) -> list[list[str]]:
    return [["mkfs.btrfs", "--force", "--label", LUKS_LABEL, mapping_path]]


def plan_subvolumes(mountpoint: str) -> list[list[str]]:
    return [["btrfs", "subvolume", "create", f"{mountpoint}/{name}"]
            for name, _, _ in SUBVOLUMES]


# ADR 0062: the verify_* helpers that re-read and parsed sgdisk, cryptsetup and
# btrfs output were removed. In the QEMU matrix a wrong layout presents as a
# machine that does not boot, which is a better signal and arrives sooner.


def describe_layout(device: str) -> list[str]:
    """The layout as it will be written, for the preflight summary."""
    layout = Layout(device)
    lines = [
        f"  {layout.esp_partition:<20} {ESP_SIZE_GIB} GiB   FAT32, EFI System, label {ESP_LABEL}",
        f"  {layout.luks_partition:<20} rest    LUKS2, Btrfs inside, label {LUKS_LABEL}",
        "",
        "  Btrfs subvolumes:",
    ]
    for name, mountpoint, note in SUBVOLUMES:
        lines.append(f"    {name:<12} {mountpoint:<14} {note}")
    return lines


# --------------------------------------------------------------------------
# Per-machine package selection
# --------------------------------------------------------------------------

def microcode_package(vendor_id: str) -> str | None:
    """The microcode package this CPU needs.

    Controller and Workstation hardware is heterogeneous, so this cannot be a
    constant in a profile. Installing the wrong one, or neither, means the
    machine silently never receives CPU errata updates -- a failure with no
    symptom until there is one.
    """
    vendor = (vendor_id or "").strip()
    if vendor == "AuthenticAMD":
        return "amd-ucode"
    if vendor == "GenuineIntel":
        return "intel-ucode"
    return None


def read_cpu_vendor(cpuinfo_text: str) -> str:
    for line in cpuinfo_text.splitlines():
        if line.startswith("vendor_id"):
            return line.split(":", 1)[1].strip()
    return ""


def base_packages(vendor_id: str) -> list[str]:
    """Everything the installer installs, and nothing else.

    Anything beyond this -- drivers, desktop, services -- belongs to Ansible
    convergence under ADR 0053, where it can differ per machine without
    changing the installer.
    """
    packages = [
        "base", "linux-lts", "linux", "linux-firmware",
        "btrfs-progs", "cryptsetup", "dosfstools",
        "systemd-ukify", "openssh", "sudo",
    ]
    microcode = microcode_package(vendor_id)
    if microcode:
        packages.append(microcode)
    return packages
