"""Plan and render a fail-closed Arch-after-Windows installation.

The emitted installer is intentionally boring.  Windows has already authored
the GPT.  Arch may use either an existing, unformatted Linux-root partition or
the sole free extent whose measured size exactly matches the approved plan.
It mounts the existing ESP without formatting it and never resizes, deletes,
or recreates a Windows partition.

Beyond the base install the script provisions the synthetic-realm identity
client that gate 8 (``vm/arch_identity_run.py``) accepts: Kerberos, Samba and
SSSD configuration mirroring ``ansible/roles/identity_client/templates``, the
``net ads`` domain join, PAM/NSS wiring, a serial getty, the ``local-rescue``
break-glass administrator mirroring the Controller seed, and the secret-free
identity probe helper.  The machine-join credential never appears in this
module, in the rendered script, or on the installed disk: the script reads it
from a one-use removable volume (the same shape ``vm/windows_join_iso.py``
builds) into tmpfs, joins, and removes it.

Because gate 8 provisions a brand-new domain on every run, the disk ships a
join-*capable* identity client rather than a permanently joined one: the same
one-use-media consumption is also installed as an enabled one-shot boot unit
(``JOIN_ONCE_UNIT_NAME``) that re-joins before sssd and before user sessions,
which is what makes the gate-8 login possible at all.  A second one-shot unit
(``DOMAIN_ONLINE_UNIT_NAME``) then holds user sessions -- and therefore the
ttyS0 login prompt -- until SSSD's AD backend is actually *usable*, which
``sssd.service`` reaching active does not prove.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

HOMELAB_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HOMELAB_ROOT))

from lib.package_contract import (  # noqa: E402
    PROFILE_OVERLAYS,
    load_registry,
    merge_contract,
)
from lib.workstation_repo import (  # noqa: E402
    REPO_NAME as WORKSTATION_REPO_NAME,
)


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
SAFE_DOMAIN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
SAFE_WORKGROUP = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,14}$")
SAFE_LABEL = re.compile(r"^[A-Z0-9_]{1,32}$")
SAFE_PRINCIPAL = re.compile(r"^[a-z][a-z0-9-]{0,31}$")

# Synthetic factory realm defaults.  These mirror vm.controller_factory
# FactorySpec (domain/netbios); the runner may override them, and the test
# suite pins this module's defaults to FactorySpec so they cannot drift.
SYNTHETIC_DOMAIN = "ad.factory.test"
SYNTHETIC_WORKGROUP = "FACTORY"

# The disposable Controller's fixed fabric address.  It mirrors
# vm.controller_factory FactorySpec.address (test-pinned) and is the same
# literal address every PXE fetch of the publication already proves: the
# published bootstrap chains http://10.1.31.2/... (vm/factory_publication)
# and archiso pulled its root filesystem from it before this script ran.
CONTROLLER_ADDRESS = "10.1.31.2"
# The disposable Controller's DNS label inside the synthetic realm, so
# ``{CONTROLLER_HOSTNAME}.{realm_dns_domain}`` is the one domain controller this
# fabric ever has.  It mirrors vm.controller_factory FactorySpec.hostname
# (test-pinned, and the same value that spec writes into the Controller's own
# /etc/hostname and /etc/hosts), and the live gate-8 run of 2026-08-14 printed
# it back from the guest as ``net ads info``'s "LDAP server name:
# bootstrap-dc.ad.factory.test".  It is a synthetic name in a reserved
# ``.test`` domain, never a real host: real instance data lives only in the
# gitignored overlay.  SSSD's ``ad_server`` needs the NAME and not
# CONTROLLER_ADDRESS above, because libsss_ad warns "ad_server [%s] is detected
# as IP address, this can cause GSSAPI/GSS-SPNEGO problems" -- a bare address
# gives it no principal to ask the KDC for.
CONTROLLER_HOSTNAME = "bootstrap-dc"
# The stable www path vm.factory_publication stages the offline workstation
# pacman repository under (WORKSTATION_REPO_WWW); nginx serves the staged
# tree rooted at "/", so the guest-visible repository URL is fixed.
WORKSTATION_REPO_URL = (
    f"http://{CONTROLLER_ADDRESS}/arch/workstation-repo")
# A quote-free, heredoc-safe absolute http URL: pacman config values take no
# quoting, so the grammar refuses spaces, quotes, and control characters.
SAFE_REPO_URL = re.compile(
    r"^http://[A-Za-z0-9][A-Za-z0-9.-]{0,127}(?::[0-9]{1,5})?"
    r"(?:/[A-Za-z0-9._-]+)*$")

# One-use machine-join credential media.  The label matches the volume id the
# Windows lane's vm.windows_join_iso.build_join_iso emits, so the same private
# ISO shape (join.json with at least username and password) serves both lanes.
JOIN_MEDIA_LABEL = "TELOS_JOIN"
JOIN_MEDIA_CONSUMED_MARKER = "TELOS ARCH JOIN MEDIA CONSUMED"
JOIN_VERIFIED_MARKER = "TELOS ARCH JOIN VERIFIED"

# Boot-time one-shot re-join (the gate-8 in-run join contract).
#
# Why a boot unit exists at all: every gate-8 run (vm/arch_identity_run.py)
# provisions a BRAND-NEW synthetic domain.  The canonical bootstrap-dc image
# carries no provisioned AD, so ansible/roles/domain_controller re-runs
# ``samba-tool domain provision`` whenever ``sam.ldb`` is absent, so that
# run's directory has a fresh domain SID, a fresh krbtgt and an empty SAM.
# The machine account this installer's install-time ``net ads join`` created
# does not exist in it, so SSSD (``id_provider = ad``, GSSAPI host-keytab bind)
# cannot authenticate, goes offline, and the operator login is refused with no
# cached credential that could ever exist on a fresh overlay.  The live run of
# 2026-08-14 proved exactly that: the whole boot chain worked and ``operator``
# was refused three times.  The Windows lane does not have the bug because it
# joins during its own run (``windows_identity_orchestrator._execute_join``).
#
# Why the GUEST performs it: there is no pre-login shell on this disk.
# ``local-rescue`` is installed with a disabled password and the loader.conf
# below sets ``editor no``, so neither a console login nor a boot-cmdline edit
# can reach root before the getty.  The join must therefore be driven by the
# guest itself, early in boot, from one-use media the runner hot-attaches.
JOIN_ONCE_SCRIPT_PATH = "/usr/local/sbin/telos-arch-join-once"
JOIN_ONCE_UNIT_NAME = "telos-arch-join-once.service"
JOIN_ONCE_UNIT_PATH = f"/etc/systemd/system/{JOIN_ONCE_UNIT_NAME}"
# The units the one-shot join is ordered before.  Both orderings are
# load-bearing, not cosmetic: sssd must never start against the previous run's
# domain SID, and -- because ``serial-getty@ttyS0`` is
# ``After=systemd-user-sessions.service`` (visible in the 2026-08-14 failing
# transcript, where "Finished Permit User Sessions" precedes "Started Serial
# Getty on ttyS0") -- ordering before user sessions is what makes the ttyS0
# login prompt appear only after the join has finished.  Gate 8's
# ``login_operator`` consequently needs no readiness logic and no sleeps.
JOIN_ONCE_BEFORE_UNITS = ("sssd.service", "systemd-user-sessions.service")
# The stale SSSD cache from the install-time join.  It was primed against the
# PREVIOUS domain's SID, so it is wiped while sssd is still stopped.
SSSD_CACHE_GLOB = "/var/lib/sss/db/*"
# Bounded loop shape shared by every wait in the identity boot path: 60 tries,
# 2s apart.
JOIN_WAIT_TRIES = 60
JOIN_WAIT_SECONDS = 2

# Boot-time SSSD domain-online gate (the gate-8 login-readiness contract).
#
# Why this exists, from the live run of 2026-08-14 (bundle
# run-20260814T124858Z-0ac6c279561b): the boot-time re-join above worked in
# full -- ``join_media_consumed``, ``join_verified`` and
# ``join_principal_destroyed`` are all true in that run's
# ``evidence/workstation-boot.json``, and the serial transcript shows
# ``TELOS ARCH JOIN VERIFIED`` (so ``net ads testjoin`` passed in-guest against
# the fresh directory) -- and ``operator`` was STILL refused on the getty.
#
# The reason is that ``sssd.service`` is ``Type=notify`` and its monitor sends
# READY=1 once the ``nss``/``pam`` responders are up, NOT when the AD provider
# has finished its DNS/LDAP/GSSAPI connection to the freshly provisioned
# Controller.  In that transcript "Started System Security Services Daemon" is
# followed within a second by "Started Serial Getty on ttyS0" and the login
# prompt, and the harness types the credential immediately.  ``pam_sss`` then
# finds the domain still offline, and offline authentication needs a cached
# credential that CANNOT exist here: the join unit has just wiped the identity
# cache (``SSSD_CACHE_GLOB``) and the operator password is generated fresh per
# run, so nothing was ever cached.  The refusal is deterministic and no retry
# count or ``LOGIN_ATTEMPTS`` bump can fix it.
#
# So a second one-shot unit waits, bounded, for the backend to be usable and
# fails closed otherwise.  Ordering it before ``systemd-user-sessions.service``
# is what makes this a gate rather than a hint: ``serial-getty@ttyS0`` is
# ``After=systemd-user-sessions.service``, so the login prompt cannot render
# until this unit has finished, and gate 8 needs no readiness logic or sleeps.
DOMAIN_ONLINE_SCRIPT_PATH = "/usr/local/sbin/telos-arch-domain-online"
DOMAIN_ONLINE_UNIT_NAME = "telos-arch-domain-online.service"
DOMAIN_ONLINE_UNIT_PATH = f"/etc/systemd/system/{DOMAIN_ONLINE_UNIT_NAME}"
# Ordering, and why it cannot cycle.  Checked against the exact unit files this
# install ships: ``sssd.service`` from the offline workstation repository's
# sssd-2.13.1-1 package declares only ``Before=systemd-user-sessions.service
# nss-user-lookup.target`` plus ``Wants=nss-user-lookup.target``, and systemd's
# ``systemd-user-sessions.service`` declares only ``After=remote-fs.target
# nss-user-lookup.target network.target home.mount`` with no ``Before=`` at
# all.  Adding sssd -> this unit -> systemd-user-sessions therefore adds two
# edges that both run in the same direction as every existing edge, and nothing
# reachable from ``systemd-user-sessions.service`` is ordered before sssd, so
# the graph stays acyclic.  This unit deliberately does NOT order itself
# against ``nss-user-lookup.target``: that target is pulled in by sssd's own
# ``Wants=`` and other units (``systemd-logind.service``) order after it, so
# inserting a new edge there is exactly how a silent ordering cycle -- and a
# silently dropped job -- would be created.
DOMAIN_ONLINE_AFTER_UNITS = ("sssd.service",)
DOMAIN_ONLINE_BEFORE_UNITS = ("systemd-user-sessions.service",)
DOMAIN_ONLINE_MARKER = "TELOS ARCH DOMAIN ONLINE"
# Printed with a secret-free reason when the bounded wait gives up, so a boot
# that stops here says where it stopped on the only channel gate 8 reads.
DOMAIN_ONLINE_FAILURE_MARKER = "TELOS ARCH DOMAIN NOT ONLINE"
# The probe helper's own domain-state wait keeps its established 30 x 2s bound:
# gate 8 allows PROBE_TIMEOUT (90s) per probe, so the 60-try installer idiom
# would let a single check outlive its own console bound.
PROBE_DOMAIN_WAIT_TRIES = 30

# Failure diagnostics for the domain-online gate.
#
# Why they exist: the live run of 2026-08-14 (bundle
# run-20260814T131951Z-83e2612decf0) spent a whole install-plus-boot cycle to
# learn one sentence -- "the directory login principal never resolved through
# SSSD" -- with the machine join fully proven in the same transcript
# (``join_verified`` true, ``net ads testjoin`` passed in-guest).  A reason
# without evidence cannot say WHICH layer failed, so the gate now prints a
# compact, bounded, secret-free field set before it exits.  It prints only from
# the failure path, so a converging boot pays nothing for it.
#
# The marker is deliberately not a prefix of, and does not contain, either gate
# marker: vm/arch_identity_run.await_domain_online waits on a bare substring
# match for DOMAIN_ONLINE_MARKER, so a diagnostic line that contained it would
# forge success.
DOMAIN_ONLINE_DIAGNOSTIC_MARKER = "TELOS ARCH DOMAIN DIAGNOSTIC"
# Per-field bound.  A diagnostic that hung would replace the named failure it
# exists to explain, so every field is timeout-bound and flattened to one line.
DIAGNOSTIC_COMMAND_SECONDS = 10
# One line per field, capped so a 115200-baud transcript stays readable.  The
# cap was 200 for exactly one live run, and 200 ate the evidence: the
# 2026-08-14 transcript (run-20260814T140142Z-587985cdf83f) truncated
# ``domain-status`` at "Discovered AD Domain Controller servers: " -- the single
# field that would have said whether SSSD found a DC at all -- and also cut
# ``sssd-config`` mid-way through its second validator finding and
# ``keytab-principals`` before the host principals.  512 covers the longest of
# those three in full (the flattened domain-status runs about 210 characters, a
# two-finding config-check about 370) and still costs under 5 ms of serial time
# per field, and only on the failure path.  A field whose whole purpose is to
# name a layer must not be cut off before it names it.
DIAGNOSTIC_LINE_COLUMNS = 512
# What a field prints when its command answered nothing at all.  An unresolved
# getent and an unprinted field must not look alike on the console.
DIAGNOSTIC_EMPTY_FIELD = "(no output)"
# SSSD's own account of the failure.  Level 7 is 'trace function': it records
# the backend's decisions and the LDAP filters it sent, which is what names the
# layer.  Higher levels add wire detail without adding a reason.  Nothing in
# this gate authenticates, so no credential exists in the process to reach the
# log at any level.
DIAGNOSTIC_SSSD_DEBUG_LEVEL = 7
DIAGNOSTIC_SSSD_LOG_LINES = 40
DIAGNOSTIC_SSSD_LOG_DIR = "/var/log/sssd"
# The log is read from BOTH ends, and the head is the half that names a layer.
# Raising the debug level here cannot recover a decision the backend already
# took: the AD provider chooses its servers when sssd starts, which is two
# minutes before this gate gives up, and everything after that is retry noise.
# The 2026-08-14 transcript proved it -- all forty tailed lines were the same
# "SSSD is offline"/"Backend is offline!" pair repeating at the wait loop's own
# 2-second cadence, and the startup decisions had scrolled out of the window.
# So the first lines of the domain log are printed too, under their own field
# name, because that is where "which server did you try, and what happened" is
# written.
DIAGNOSTIC_SSSD_LOG_HEAD_LINES = 40
# The host keytab and the SSSD helper children that can read it.  Arch's
# sssd-2.13.1-1 runs the daemon as ``User=sssd`` and grants
# ``cap_dac_read_search`` to individual helper binaries in its post_install
# scriptlet, while ``net ads join`` writes the keytab mode 0600 root:root.  So
# whether a GSSAPI bind was ever possible is a property of these files, not of
# the directory, and a failing gate should say so rather than leave it inferred.
HOST_KEYTAB_PATH = "/etc/krb5.keytab"
SSSD_CHILD_BINARIES = (
    "/usr/lib/sssd/sssd/ldap_child",
    "/usr/lib/sssd/sssd/gpo_child",
)
# The two directory groups this disk names, defined once and used by both the
# acceptance probe and the gate's diagnostics.  The primary group is evidence
# rather than decoration: with ``ldap_id_mapping = False`` a user whose primary
# group carries no ``gidNumber`` cannot resolve even when the user object is
# complete, so "the user is missing" and "its primary group is missing" are
# different faults that must not look alike.  vm/controller_principals stages
# ``gidNumber`` on both (POSIX_ALLOCATION).
DIRECTORY_PRIMARY_GROUP = "domain users"
DIRECTORY_ADMIN_GROUP = "domain admins"

# systemd-boot menu titles the gate-10 acceptance keys on.  The Arch title is
# authored by this installer's loader entry below; the Windows title is what
# systemd-boot's auto-detection renders for the gate-5 image's
# \EFI\Microsoft\Boot\bootmgfw.efi (calibrated against the live gate-10
# boot-1 serial transcript of 2026-08-11, which listed "Arch Linux LTS",
# "Windows 11", and the firmware-recovery entry).
MENU_ARCH_TITLE = "Arch Linux LTS"
MENU_WINDOWS_TITLE = "Windows 11"

# UEFI NVRAM boot entries the installer authors from the live archiso, where
# efivarfs is writable (the gate-7 post-step efibootmgr proved it; the chroot
# cannot write EFI variables).  Authoring "Windows Boot Manager" before the
# first Windows boot is what preserves the five-second systemd-boot menu:
# Windows self-promotes to BootOrder first only when its first boot has to
# CREATE that entry (the live gate-10 boot-2 booted it directly, menuless);
# finding the entry already present leaves BootOrder alone.  The markers
# print from inside the heredoc-delivered installer script, so the serial
# echo of a dispatched command can never fake them.
NVRAM_LINUX_LABEL = "Linux Boot Manager"
NVRAM_WINDOWS_LABEL = "Windows Boot Manager"
NVRAM_LINUX_LOADER = "\\EFI\\systemd\\systemd-bootx64.efi"
NVRAM_WINDOWS_LOADER = "\\EFI\\Microsoft\\Boot\\bootmgfw.efi"
NVRAM_ENTRIES_MARKER = "TELOS ARCH NVRAM ENTRIES AUTHORED"
NVRAM_ORDER_MARKER = "TELOS ARCH NVRAM LINUX FIRST"

# Windows Boot Manager recognizes a Boot#### entry as its own by this
# optional-data blob — the "WINDOWS" signature plus the well-known
# {bootmgr} object reference "BCDOBJECT={9dea862c-5cdd-4e70-acc1-
# f32b344d4795}" — not by the device path alone.  The 2026-08-11 gate-10 v2
# live run proved the consequence of omitting it: our authored entry had a
# byte-identical device path but no blob, so Windows' first boot created
# its own entry in the first free slot and promoted it ahead of Linux,
# leaving the second cold boot menuless.  The blob below was extracted
# verbatim from that run's Windows-authored entry; every field is
# install-independent (the GUID is the fixed {bootmgr} BCD object), so
# authoring it makes Windows adopt the pre-created entry and leave
# BootOrder alone.
NVRAM_WINDOWS_OPTIONAL_DATA = bytes.fromhex(
    "57494e444f5753000100000088000000780000004200430044004f0042004a00"
    "4500430054003d007b00390064006500610038003600320063002d0035006300"
    "640064002d0034006500370030002d0061006300630031002d00660033003200"
    "6200330034003400640034003700390035007d00000000000100000010000000"
    "040000007fff0400")

# Gate 8 invokes this fixed, secret-free helper for every Arch lifecycle
# check (vm.arch_identity_run.PROBE_HELPER).
PROBE_HELPER_PATH = "/usr/local/sbin/homelab-arch-identity-probe"

# The lifecycle checks the probe helper answers; gate 8's drive sends exactly
# these names (vm/arch_identity_run.py, workstations/identity_lifecycle.json).
PROBE_CHECKS = (
    "arch-joined",
    "arch-standard-online",
    "arch-daily-admin",
    "domain-admin-separate",
    "arch-cached-login",
    "arch-uncached-denied",
    "arch-local-rescue",
    "arch-identity-restored",
    "arch-storage-attached",
    "arch-storage-denied",
    "arch-storage-absent-login",
)

# Gate 9: optional per-user UNAS SMB storage.  The storage authority has its
# own stable DNS label inside the synthetic domain so the gate-8 runner can
# toggle reachability in DNS alone (samba-tool dns update on the Controller
# serial) while Kerberos, LDAP, and DNS identity services stay online.
STORAGE_HOST_LABEL = "unas"
# Where the durable, never-login-blocking automount attaches a user's share.
STORAGE_MOUNT_ROOT = "/srv/unas"
# Where the acceptance probe performs its own explicit, bounded mounts.
STORAGE_PROBE_ROOT = "/run/telos-storage-probe"
# The extra data marker the storage-absent check prints before its verdict so
# the gate-8 drive can record the measured login duration as evidence.
STORAGE_LOGIN_SECONDS_MARKER = "__TELOS_ARCH_STORAGE_LOGIN_SECONDS_"


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
    # lsblk nests partitions under ``children`` only when the NAME column is
    # selected; with an explicit ``-o`` list omitting NAME (as the verify
    # invocation does) every partition is a flat sibling row. Accept both
    # shapes — the live installer sees the flat one.
    children = item.get("children")
    if not isinstance(children, list):
        children = [
            sibling for sibling in devices
            if isinstance(sibling, dict)
            and sibling is not item
            and isinstance(sibling.get("path"), str)
            and sibling["path"].startswith(disk_path)
        ]
    if not children:
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


def _identity_principals() -> dict[str, str]:
    """Read the acceptance principals from the identity-lifecycle contract."""
    contract = json.loads(
        Path(__file__).with_name("identity_lifecycle.json").read_text(
            encoding="utf-8"))
    principals = contract["principals"]
    names = {
        "standard": principals["standard_user"]["name"],
        "daily_admin": principals["daily_administrator"]["name"],
        "domain_admin": principals["domain_administrator"]["name"],
        "local_rescue": principals["local_rescue"]["name"],
    }
    for name in names.values():
        if not isinstance(name, str) or not SAFE_PRINCIPAL.fullmatch(name):
            raise InstallContractError(
                "identity-lifecycle principal name is not safely representable")
    return names


def _identity_login_bound() -> int:
    """Read the login duration bound from the identity-lifecycle contract."""
    contract = json.loads(
        Path(__file__).with_name("identity_lifecycle.json").read_text(
            encoding="utf-8"))
    bound = contract.get("login_bound_seconds")
    if isinstance(bound, bool) or not isinstance(bound, int) \
            or not 1 <= bound <= 600:
        raise InstallContractError(
            "identity-lifecycle login bound is not a sane bounded integer")
    return bound


def _render_krb5(realm: str) -> str:
    """Mirror ansible/roles/identity_client/templates/krb5.conf.j2."""
    return f"""# Managed by Telos gate 7 (workstations/arch_second.py).
[libdefaults]
    default_realm = {realm}
    dns_lookup_realm = false
    dns_lookup_kdc = true
    rdns = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true"""


def _render_smb(realm: str, workgroup: str) -> str:
    """Mirror ansible/roles/identity_client/templates/smb.conf.j2."""
    return f"""# Managed by Telos gate 7 (workstations/arch_second.py).
[global]
    security = ADS
    realm = {realm}
    workgroup = {workgroup}
    kerberos method = secrets and keytab"""


# The SSSD responders this client runs.  ``nss`` and ``pam`` are the login
# path and mirror the ansible template; ``ifp`` is required *here* and not
# there because gate 8's acceptance probe is the only consumer of
# ``sssctl domain-status``, and that command answers over the InfoPipe
# responder alone.  Verified against the very sssctl this install ships
# (sssd-2.13.1-1 in the offline workstation repository), whose own diagnostic
# reads "InfoPipe operation failed. Check that SSSD is running and the
# InfoPipe responder is enabled. Make sure 'ifp' is listed in the 'services'
# option in sssd.conf."  Without it, D-Bus activation of sssd-ifp.service is
# the only thing that could answer, which is an undeclared unit and an
# unproven path; nine of the eleven lifecycle checks wait for Online first, so
# leaving it to chance would make them fail closed for a reason that has
# nothing to do with identity.
SSSD_SERVICES = ("nss", "pam", "ifp")


def _render_sssd(
    domain: str, realm: str, *, controller_fqdn: str, client_fqdn: str,
) -> str:
    """Mirror ansible/roles/identity_client/templates/sssd.conf.j2."""
    return f"""# Managed by Telos gate 7 (workstations/arch_second.py).
[sssd]
domains = {domain}
# ifp answers sssctl domain-status, which every gate-8 Online wait depends on.
services = {", ".join(SSSD_SERVICES)}

# offline_credentials_expiration is a PAM responder option, not a domain one.
# It sat in [domain/...] for one live run and SSSD silently ignored it there:
# the 2026-08-14 gate-8 transcript printed `sssctl config-check` saying
# "[rule/allowed_domain_options]: Attribute 'offline_credentials_expiration' is
# not allowed", and /usr/share/sssd/cfg_rules.ini in the sssd-2.13.1-1 package
# this disk installs lists the option under [rule/allowed_pam_options] alone.
# ADR 0071's whole point is that the value is stated rather than inherited, so
# it has to be stated in the section that reads it.  Zero means no expiration:
# a machine away at college may be offline indefinitely, and phase 2 owns
# stronger revocation than a cache lifetime.
[pam]
offline_credentials_expiration = 0

[domain/{domain}]
id_provider = ad
access_provider = ad
# Discovery, pinned rather than discovered.  SSSD's AD provider locates a
# domain controller ONLY by DNS SRV lookup (_ldap._tcp.<ad_domain>, plus the
# site-specific variants it derives from a CLDAP netlogon ping); with no
# ad_server it logs "No AD server set, will use service discovery!" and has no
# other way to find one.  Samba's `net ads` does not share that constraint --
# it falls back to a NetBIOS <1C> broadcast for the workgroup, which this flat
# simulated segment floods -- so `net ads info` and `net ads join` can succeed
# on a fabric where SSSD's discovery does not, and the 2026-08-14 gate-8 run
# showed exactly that asymmetry: the join verified in eight seconds and SSSD
# then sat Offline for two minutes with "AD Domain Controller: not connected".
# This fabric has exactly one domain controller and the factory already knows
# its name, so naming it removes SRV discovery, CLDAP site discovery and the
# whole failover-plugin path from the login gate's critical section.  The name
# and not the address: libsss_ad warns "ad_server [%s] is detected as IP
# address, this can cause GSSAPI/GSS-SPNEGO problems", because the SASL bind
# needs a principal to ask the KDC for.
ad_server = {controller_fqdn}
# The client's own fully qualified name, for the same reason.  /etc/hostname
# carries the short name, so without this SSSD calls gethostname(), gets
# "telos-ws1", and has to expand it by resolving it back -- "The hostname [%s]
# has been expanded to FQDN [%s]. If sssd should really use the short hostname,
# please set ad_hostname explicitly."  That expansion depends on the A record
# `net ads join` may or may not have registered for this machine, which nothing
# in this project verifies.  sssd-ad(5) says ad_hostname "must match the
# hostname for which the keytab was issued", and `net ads join` issues
# host/<short>.<realm dns domain>, which is exactly this.
ad_hostname = {client_fqdn}
# Samba-AD interop, read off the packages this install ships (2026-08-14).
# SSSD defaults ad_gpo_access_control to "enforcing", which makes every
# interactive login depend on fetching GPOs from SYSVOL over SMB.  That fetch
# is done by /usr/lib/sssd/sssd/gpo_child, which reads the host keytab to
# authenticate -- and on this disk it cannot: Arch's sssd-2.13.1-1 runs the
# daemon as User=sssd and its post_install scriptlet grants
# cap_dac_read_search to ldap_child, krb5_child and sssd_pam only, while
# net ads join writes /etc/krb5.keytab mode 0600 root:root.  Enforcing mode
# would therefore refuse every login for a reason that has nothing to do with
# identity.  Permissive keeps the evaluation and SSSD's syslog warning ("user
# would have been denied GPO-based logon access...") while letting the login
# through, and it also covers the site-autodiscovery failure SSSD reports as
# "GPO will not work".  Nothing in this project authors a GPO and
# ad_gpo_implicit_deny stays at its False default, so enforcing mode could
# never grant less than this -- only deny everything.
ad_gpo_access_control = permissive
ad_domain = {domain}
krb5_realm = {realm}
realmd_tags = manages-system joined-with-samba
cache_credentials = True
# ADR 0071: the offline lifetime itself is stated in [pam] above, where SSSD
# reads it.  This is the domain half of the same decision -- keep the Kerberos
# password so an offline login can happen at all.
krb5_store_password_if_offline = True
# UID and GID come from the directory (ADR 0055), not from a local mapping.
ldap_id_mapping = False
# Which follows directly from the line above, against a Samba AD DC.  Reading
# ids from the directory means every user lookup must return uidNumber and
# gidNumber, and by default SSSD asks the AD Global Catalog (port 3268) FIRST.
# The AD schema Samba ships (setup/ad-schema/MS-AD_Schema_2K8_R2_Attributes)
# defines UidNumber and GidNumber with no isMemberOfPartialAttributeSet -- that
# is, deliberately not replicated to the Global Catalog -- so a GC answer can
# never carry a POSIX identity.  SSSD 2.13 probes that very attribute and
# disables the GC itself, but the probe runs inside its subdomain refresh: a
# lookup that arrives first, or a refresh that Samba's incomplete Global
# Catalog fails outright, still queries the GC and finds no POSIX identity.
# State it here instead of racing that probe.  Nothing is lost: this is a
# single-domain forest with no trusts, and sssd-ad(5) needs the Global Catalog
# only for trusted-domain users and cross-domain group memberships.
ad_enable_gc = False
fallback_homedir = /home/%u
default_shell = /bin/bash
use_fully_qualified_names = False
enumerate = False"""


# Complete deterministic /etc/pam.d/system-auth: the stock Arch file with
# pam_sss added (no authselect on Arch).  pam_mkhomedir goes into
# system-login, mirroring roles/identity_client/tasks/main.yml.
_PAM_SYSTEM_AUTH = """\
#%PAM-1.0
# Managed by Telos gate 7 (workstations/arch_second.py): the stock Arch
# system-auth stack with pam_sss for the joined synthetic realm.
auth       required                                     pam_faillock.so      preauth
auth       [success=3 default=ignore]                   pam_unix.so          try_first_pass nullok
auth       [success=2 default=ignore]                   pam_sss.so           use_first_pass
auth       [default=die]                                pam_faillock.so      authfail
auth       optional                                     pam_permit.so
auth       required                                     pam_env.so
auth       required                                     pam_faillock.so      authsucc

account    [default=bad success=ok user_unknown=ignore] pam_sss.so
account    required                                     pam_unix.so
account    optional                                     pam_permit.so
account    required                                     pam_time.so

password   [success=1 default=ignore]                   pam_sss.so
password   required                                     pam_unix.so          try_first_pass nullok shadow
password   optional                                     pam_permit.so

session    required                                     pam_limits.so
session    required                                     pam_unix.so
session    optional                                     pam_sss.so
session    optional                                     pam_permit.so"""


# The one SSSD domain-state implementation on the installed disk.  It is
# rendered into BOTH the guest probe helper below and the boot-time
# domain-online gate, so those two can never drift apart: one definition of
# what "online" means, one bounded-loop shape, and one place to change if
# SSSD's reporting ever does.  Each caller supplies ``DOMAIN`` and its own
# ``DOMAIN_WAIT_TRIES`` bound (see PROBE_DOMAIN_WAIT_TRIES).
_DOMAIN_STATE_FUNCTIONS = f"""domain_state() {{
  sssctl domain-status "$DOMAIN" 2>/dev/null | grep -qi "Online status: $1"
}}

await_domain_state() {{
  for _ in $(seq 1 "$DOMAIN_WAIT_TRIES"); do
    # A lookup no cache can serve forces SSSD to test the backend.
    getent passwd "telos-probe-trigger-$$" >/dev/null 2>&1 || true
    domain_state "$1" && return 0
    sleep {JOIN_WAIT_SECONDS}
  done
  return 1
}}"""


# The guest-side lifecycle probe.  @TOKENS@ are substituted at render time
# with validated, quote-free values.  Every check is answered honestly from
# what a credential-free root session can observe; anything unprovable is a
# FAIL, never a fabricated PASS.
_PROBE_TEMPLATE = """\
#!/usr/bin/env bash
# Managed by Telos gate 7 (workstations/arch_second.py).  Secret-free
# identity probe for gate 8 (vm/arch_identity_run.py): runs exactly one
# lifecycle check and prints __TELOS_ARCH_<CHECK>_<token>=PASS|FAIL.  The
# storage-absent check additionally prints one token-scoped
# __TELOS_ARCH_STORAGE_LOGIN_SECONDS_<token>=<n> data line before its
# verdict.  It never reads or carries a credential, so each proof is
# bounded to what a credential-free session can honestly observe;
# unprovable means FAIL.
set -u

DOMAIN='@DOMAIN@'
ADMIN_GROUP='@ADMIN_GROUP@'
STANDARD_USER='@STANDARD_USER@'
DAILY_ADMIN='@DAILY_ADMIN@'
DOMAIN_ADMIN='@DOMAIN_ADMIN@'
RESCUE_USER='@RESCUE_USER@'
STORAGE_HOST='@STORAGE_HOST@'
STORAGE_PROBE_ROOT='@STORAGE_PROBE_ROOT@'
LOGIN_BOUND_SECONDS='@LOGIN_BOUND@'
DOMAIN_WAIT_TRIES='@DOMAIN_WAIT_TRIES@'

usage() {
  echo 'usage: homelab-arch-identity-probe <check> <token>' >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
check="$1"
token="$2"
case "$check" in
  arch-joined|arch-standard-online|arch-daily-admin|domain-admin-separate|\\
  arch-cached-login|arch-uncached-denied|arch-local-rescue|\\
  arch-identity-restored|arch-storage-attached|arch-storage-denied|\\
  arch-storage-absent-login) ;;
  *) usage ;;
esac
printf '%s' "$token" | grep -Eq '^[A-Za-z0-9]{8,64}$' || usage

if [ "$(id -u)" -ne 0 ] && sudo -n true 2>/dev/null; then
  exec sudo -n -- "$0" "$check" "$token"
fi

key=$(printf '%s' "$check" | tr 'a-z-' 'A-Z_')

verdict() {
  printf '__TELOS_ARCH_%s_%s=%s\\n' "$key" "$token" "$1"
}

@DOMAIN_STATE_FUNCTIONS@

resolved_by_sssd() {
  getent passwd "$1" >/dev/null 2>&1 &&
    ! getent -s files passwd "$1" >/dev/null 2>&1
}

in_wheel() {
  id -nG "$1" 2>/dev/null | tr ' ' '\\n' | grep -qx wheel
}

has_full_sudo() {
  sudo -l -U "$1" 2>/dev/null |
    grep -Eq '\\(ALL([ \\t]*:[ \\t]*ALL)?\\)[ \\t]+ALL'
}

admin_group_gid() {
  getent group "$ADMIN_GROUP" 2>/dev/null | cut -d: -f3 | grep -E '^[0-9]+$'
}

admin_group_members() {
  getent group "$ADMIN_GROUP" 2>/dev/null | cut -d: -f4 | tr ',' '\\n'
}

check_arch_joined() {
  await_domain_state Online || return 1
  net ads testjoin >/dev/null 2>&1
}

check_arch_standard_online() {
  await_domain_state Online || return 1
  resolved_by_sssd "$STANDARD_USER" || return 1
  # Unelevated: no wheel membership and no sudo grant.
  in_wheel "$STANDARD_USER" && return 1
  has_full_sudo "$STANDARD_USER" && return 1
  return 0
}

check_arch_daily_admin() {
  await_domain_state Online || return 1
  resolved_by_sssd "$DAILY_ADMIN" || return 1
  has_full_sudo "$DAILY_ADMIN" || return 1
  # Local administrator, yet not a directory administrator.
  gid=$(admin_group_gid) || return 1
  id -G "$DAILY_ADMIN" 2>/dev/null | tr ' ' '\\n' | grep -qx "$gid" && return 1
  return 0
}

check_domain_admin_separate() {
  await_domain_state Online || return 1
  [ "$DAILY_ADMIN" != "$DOMAIN_ADMIN" ] || return 1
  # Proved from the group's member list on purpose: resolving the directory
  # administrator as a user here would prime the identity cache and falsify
  # arch-uncached-denied.
  admin_group_members | grep -qx "$DOMAIN_ADMIN" || return 1
  admin_group_members | grep -qx "$DAILY_ADMIN" && return 1
  return 0
}

check_arch_cached_login() {
  await_domain_state Offline || return 1
  # The primed identity is still served from the SSSD cache while the
  # Controller is down.
  getent passwd "$STANDARD_USER" >/dev/null 2>&1 || return 1
  return 0
}

check_arch_uncached_denied() {
  await_domain_state Offline || return 1
  # The directory administrator was deliberately never resolved on this
  # workstation, so its offline lookup must be denied.
  getent passwd "$DOMAIN_ADMIN" >/dev/null 2>&1 && return 1
  return 0
}

check_arch_local_rescue() {
  getent -s files passwd "$RESCUE_USER" >/dev/null 2>&1 || return 1
  in_wheel "$RESCUE_USER" || return 1
  has_full_sudo "$RESCUE_USER" || return 1
  # A usable break-glass login needs a set password; the install-time
  # default is disabled and only an authorized console session sets it.
  [ "$(passwd -S "$RESCUE_USER" 2>/dev/null | awk '{print $2}')" = P ] ||
    return 1
  return 0
}

check_arch_identity_restored() {
  await_domain_state Online || return 1
  # A lookup no cache can serve proves the directory answers again.
  getent passwd "$DOMAIN_ADMIN" >/dev/null 2>&1 || return 1
  return 0
}

storage_reachable() {
  # Bounded reachability probe: a dead or absent NAS costs at most 5s.
  timeout 5 bash -c "exec 3<>/dev/tcp/$STORAGE_HOST/445" 2>/dev/null
}

storage_mount() {
  # Mount share $1 with user $2's Kerberos identity.  Credential-free by
  # construction: sec=krb5 can only succeed from a ticket a real login
  # already obtained; the probe never holds or types a secret.  mount.cifs
  # comes from cifs-utils; if the package contract does not ship it the
  # attempt honestly fails closed.
  command -v mount.cifs >/dev/null 2>&1 || return 1
  mount_uid=$(id -u "$2" 2>/dev/null) || return 1
  mkdir -p "$STORAGE_PROBE_ROOT/$1" || return 1
  timeout 20 mount.cifs "//$STORAGE_HOST/$1" "$STORAGE_PROBE_ROOT/$1" \\
    -o "sec=krb5,cruid=$mount_uid,uid=$mount_uid,soft,echo_interval=10" \\
    >/dev/null 2>&1
}

storage_unmount() {
  umount "$STORAGE_PROBE_ROOT/$1" 2>/dev/null
  rmdir "$STORAGE_PROBE_ROOT/$1" 2>/dev/null
  return 0
}

fstab_never_blocks_login() {
  # Structural login independence: every cifs fstab entry (if any exists)
  # must be a nofail systemd automount with a bounded mount timeout, so
  # systemd-fstab-generator can only emit a Wants= automount that no boot
  # or login unit ever waits on; and no mount or automount unit may be
  # administratively enabled.  The optional attach path is therefore
  # incapable of gating login, rather than merely observed not to.
  while IFS= read -r options; do
    case ",$options," in
      *,nofail,*) ;;
      *) return 1 ;;
    esac
    case "$options" in
      *x-systemd.automount*) ;;
      *) return 1 ;;
    esac
    case "$options" in
      *x-systemd.mount-timeout=*) ;;
      *) return 1 ;;
    esac
  done < <(grep -Ev '^[[:space:]]*#' /etc/fstab 2>/dev/null |
           awk '$3 == "cifs" {print $4}')
  systemctl list-unit-files --state=enabled --no-legend \\
      '*.mount' '*.automount' 2>/dev/null | grep -q . && return 1
  return 0
}

check_arch_storage_attached() {
  # The mounting identity is the daily administrator: the gate-8 drive's
  # real getty login primes that principal's Kerberos ticket, and sec=krb5
  # can only ever succeed from such a real login's ticket.
  await_domain_state Online || return 1
  storage_reachable || return 1
  storage_mount "$DAILY_ADMIN" "$DAILY_ADMIN" || return 1
  fstype=$(findmnt -rn -M "$STORAGE_PROBE_ROOT/$DAILY_ADMIN" \\
    -o FSTYPE 2>/dev/null)
  listed=0
  ls "$STORAGE_PROBE_ROOT/$DAILY_ADMIN" >/dev/null 2>&1 && listed=1
  storage_unmount "$DAILY_ADMIN"
  [ "$fstype" = cifs ] || return 1
  [ "$listed" = 1 ] || return 1
  return 0
}

check_arch_storage_denied() {
  await_domain_state Online || return 1
  storage_reachable || return 1
  # Fail-closed: the same identity must first mount its own share so a
  # broken mount path can never masquerade as an authorization denial.
  storage_mount "$DAILY_ADMIN" "$DAILY_ADMIN" || return 1
  storage_unmount "$DAILY_ADMIN"
  if storage_mount "$STANDARD_USER" "$DAILY_ADMIN"; then
    storage_unmount "$STANDARD_USER"
    return 1
  fi
  storage_unmount "$STANDARD_USER"
  return 0
}

check_arch_storage_absent_login() {
  # The target must actually be absent, proven by the bounded probe.
  storage_reachable && return 1
  fstab_never_blocks_login || return 1
  # A root su -l runs the real PAM account and session stacks for the
  # domain user without a credential; with the NAS absent it must still
  # complete inside the contract bound.
  SECONDS=0
  timeout "$LOGIN_BOUND_SECONDS" su -l "$STANDARD_USER" -c true \\
    >/dev/null 2>&1 || return 1
  elapsed=$SECONDS
  printf '__TELOS_ARCH_STORAGE_LOGIN_SECONDS_%s=%s\\n' "$token" "$elapsed"
  [ "$elapsed" -le "$LOGIN_BOUND_SECONDS" ]
}

result=FAIL
case "$check" in
  arch-joined) check_arch_joined && result=PASS ;;
  arch-standard-online) check_arch_standard_online && result=PASS ;;
  arch-daily-admin) check_arch_daily_admin && result=PASS ;;
  domain-admin-separate) check_domain_admin_separate && result=PASS ;;
  arch-cached-login) check_arch_cached_login && result=PASS ;;
  arch-uncached-denied) check_arch_uncached_denied && result=PASS ;;
  arch-local-rescue) check_arch_local_rescue && result=PASS ;;
  arch-identity-restored) check_arch_identity_restored && result=PASS ;;
  arch-storage-attached) check_arch_storage_attached && result=PASS ;;
  arch-storage-denied) check_arch_storage_denied && result=PASS ;;
  arch-storage-absent-login) check_arch_storage_absent_login && result=PASS ;;
esac
verdict "$result"
[ "$result" = PASS ]"""


def _render_probe(
    *,
    domain: str,
    principals: Mapping[str, str],
    storage_host: str,
    login_bound: int,
) -> str:
    """Substitute validated, quote-free values into the probe template."""
    replacements = {
        "@DOMAIN@": domain,
        # One definition of the privilege group's name on this disk, shared
        # with the boot gate's diagnostics.
        "@ADMIN_GROUP@": DIRECTORY_ADMIN_GROUP,
        "@STANDARD_USER@": principals["standard"],
        "@DAILY_ADMIN@": principals["daily_admin"],
        "@DOMAIN_ADMIN@": principals["domain_admin"],
        "@RESCUE_USER@": principals["local_rescue"],
        "@STORAGE_HOST@": storage_host,
        "@STORAGE_PROBE_ROOT@": STORAGE_PROBE_ROOT,
        "@LOGIN_BOUND@": str(login_bound),
        "@DOMAIN_WAIT_TRIES@": str(PROBE_DOMAIN_WAIT_TRIES),
        # Shared with the boot-time domain-online gate, never re-implemented.
        "@DOMAIN_STATE_FUNCTIONS@": _DOMAIN_STATE_FUNCTIONS,
    }
    text = _PROBE_TEMPLATE
    for token, value in replacements.items():
        text = text.replace(token, value)
    return text


def _render_join_media_stage(join_media_label: str) -> str:
    """Turn one-use *join_media_label* media into a mode-0600 tmpfs credential.

    Shared verbatim by the install-time join below and by the boot-time
    one-shot join unit, so the two can never drift: the same bounded wait for
    the media, the same fail-closed absence check, the same read-only mount,
    the same ``join.json`` -> ``net ads`` authentication-file conversion under
    ``umask 077``, and the same unmount.  The credential exists only on the
    media and in the mode-0600 tmpfs file; it never reaches argv, a unit file,
    the journal, or the serial transcript.
    """
    return f"""join_dev="/dev/disk/by-label/{join_media_label}"
for _ in $(seq 1 {JOIN_WAIT_TRIES}); do
  [[ -e "$join_dev" ]] && break
  sleep {JOIN_WAIT_SECONDS}
done
[[ -e "$join_dev" ]] || {{ echo "join credential media is absent" >&2; exit 1; }}
mkdir -p -m 700 /run/telos-join /run/telos-join/media
mount -o ro "$join_dev" /run/telos-join/media
(
  umask 077
  python3 - > /run/telos-join/credentials <<'TELOS_JOIN_CRED_EOF'
import json
with open("/run/telos-join/media/join.json", encoding="utf-8") as source:
    values = json.load(source)
username = values["username"]
password = values["password"]
for item in (username, password):
    if (not isinstance(item, str) or not item
            or any(ord(character) < 32 for character in item)):
        raise SystemExit("join credential is invalid")
print("username = " + username)
print("password = " + password)
TELOS_JOIN_CRED_EOF
)
chmod 600 /run/telos-join/credentials
umount /run/telos-join/media"""


def _render_join_once_script(
    *, join_media_label: str, realm_dns_domain: str,
) -> str:
    """Emit the root-only boot-time re-join script the one-shot unit runs.

    Fail-closed throughout: media that never appears, a conversion that fails,
    a refused join, or a join that does not verify all leave the unit failed
    and both markers unprinted, so the gate-8 runner's bounded marker waits
    report the named join failure instead of blaming the later login.
    """
    stage = _render_join_media_stage(join_media_label)
    return f"""#!/usr/bin/env bash
# Managed by Telos gate 7 (workstations/arch_second.py).  One-shot boot-time
# domain join from the one-use {join_media_label} media the gate-8 runner
# hot-attaches.  See JOIN_ONCE_SCRIPT_PATH in that module for why this exists:
# gate 8 provisions a brand-new domain every run, so the machine account the
# install-time join created is absent from that run's directory and the guest
# must re-join itself before any login is possible.
set -euo pipefail

# The credential only ever lives on the one-use media and in a mode-0600
# tmpfs file.  An EXIT trap removes it on every path, including a failed join,
# so a failure can never leave the secret behind on a running guest.
trap 'rm -rf /run/telos-join' EXIT

{stage}
printf '%s\\n' '{JOIN_MEDIA_CONSUMED_MARKER}' > /dev/console

# network-online.target only proves the link is configured; the disposable
# Controller is the realm's KDC and DNS, and it has to answer before a join
# can succeed.  NetworkManager-wait-online is deliberately not enabled (it
# would be an undeclared service in the package contract), which makes
# network-online.target cheap rather than meaningful, so readiness is proven
# here with the same bounded 60 x 2s shape the media wait uses.  The join
# itself stays the fail-closed gate, so this loop can never mask a failure.
for _ in $(seq 1 {JOIN_WAIT_TRIES}); do
  getent hosts '{realm_dns_domain}' >/dev/null 2>&1 && break
  sleep {JOIN_WAIT_SECONDS}
done

net ads join -A /run/telos-join/credentials
net ads testjoin
rm -rf /run/telos-join
printf '%s\\n' '{JOIN_VERIFIED_MARKER}' > /dev/console

# The identity cache was primed against the PREVIOUS domain's SID by the
# install-time join, so serving it would hand sssd identities whose SIDs no
# longer exist.  The unit is ordered before sssd.service precisely so this can
# be a clean wipe rather than a restart-and-hope.
rm -f {SSSD_CACHE_GLOB}
"""


def _render_join_once_unit() -> str:
    """Emit the one-shot join unit; its ordering is the login gate."""
    before = " ".join(JOIN_ONCE_BEFORE_UNITS)
    return f"""# Managed by Telos gate 7 (workstations/arch_second.py).
[Unit]
Description=Telos one-shot domain join from one-use {JOIN_MEDIA_LABEL} media
# The join needs a configured link: the realm's KDC and DNS are the
# disposable Controller, reachable only once DHCP has answered.
Wants=network-online.target
After=network-online.target
# Load-bearing ordering.  sssd must not start against the previous run's
# domain SID, and serial-getty@ttyS0 is After=systemd-user-sessions.service,
# so ordering before user sessions is what makes the ttyS0 login prompt
# appear only after the join finished -- no sleeps anywhere compensate.
Before={before}

[Service]
Type=oneshot
RemainAfterExit=no
ExecStart={JOIN_ONCE_SCRIPT_PATH}

[Install]
WantedBy=multi-user.target
"""


def _render_domain_online_script(
    *, realm_dns_domain: str, realm: str, login_principal: str,
    controller_fqdn: str, client_fqdn: str,
) -> str:
    """Emit the boot-time SSSD domain-online gate the one-shot unit runs.

    Two conditions, both bounded, both fail-closed, and deliberately in this
    order.  Resolving *the* login principal comes first because that is exactly
    what ``pam_sss`` needs and it is honest evidence rather than a warm-up: the
    join unit wiped the identity cache while sssd was still stopped, so a
    successful lookup can only have been served by the live directory.
    ``await_domain_state Online`` -- the shared implementation the acceptance
    probe already uses, so "online" means one thing on this disk -- follows as
    the narrower check: reaching it with the lookup already successful isolates
    an ``sssctl``/InfoPipe fault from an identity fault, which matters because
    nine of the eleven lifecycle checks wait on that same primitive.

    ``set -e`` is deliberately absent: every wait below tests commands that are
    *expected* to fail while it converges, and errexit would turn the first
    such probe into an exit.  Every terminal path instead calls ``fail``.
    """
    # Absolute, space-free paths from a module constant, so this stays one safe
    # shell word list and never needs quoting.
    diagnostic_child_binaries = " ".join(SSSD_CHILD_BINARIES)
    return f"""#!/usr/bin/env bash
# Managed by Telos gate 7 (workstations/arch_second.py).  Boot-time SSSD
# domain-online gate.  See DOMAIN_ONLINE_UNIT_NAME in that module for why the
# ttyS0 login prompt has to wait for this: sssd.service reaching active only
# means its responders answered READY=1, not that the AD backend is usable, and
# the 2026-08-14 live run was refused a login one second after that point with
# an identity cache the join unit had just wiped.
set -uo pipefail

DOMAIN='{realm_dns_domain}'
REALM='{realm}'
DOMAIN_WAIT_TRIES='{JOIN_WAIT_TRIES}'
LOGIN_PRINCIPAL='{login_principal}'
PRIMARY_GROUP='{DIRECTORY_PRIMARY_GROUP}'
ADMIN_GROUP='{DIRECTORY_ADMIN_GROUP}'
HOST_KEYTAB='{HOST_KEYTAB_PATH}'
# The two names sssd.conf now pins (ad_server and ad_hostname).  The gate
# reports on exactly the names SSSD was configured with, so a diagnostic can
# never disagree with the configuration it is diagnosing.
AD_SERVER='{controller_fqdn}'
AD_HOSTNAME='{client_fqdn}'

# One diagnostic field: a bounded command, its output flattened to a single
# length-capped console line, prefixed with the diagnostic marker so a human or
# a later evidence extractor can grep the set out of the ttyS0 transcript.  The
# bound matters as much as the field: a diagnostic that hung would replace the
# named failure it exists to explain.
say() {{
  field="$1"
  shift
  value="$(timeout {DIAGNOSTIC_COMMAND_SECONDS} "$@" 2>&1 |
           tr -s '[:space:]' ' ' | cut -c1-{DIAGNOSTIC_LINE_COLUMNS})"
  # An empty answer is itself a finding, so it is named: "the lookup returned
  # nothing" and "the field was never printed" must not look alike.
  printf '%s %s: %s\\n' '{DOMAIN_ONLINE_DIAGNOSTIC_MARKER}' "$field" \\
    "${{value:-{DIAGNOSTIC_EMPTY_FIELD}}}" > /dev/console
}}

# Why this block exists: the live run of 2026-08-14 stopped here and said only
# that the login principal never resolved, which cost an entire
# install-plus-boot cycle without naming a layer.  These fields walk outward
# from SSSD to the directory, so the next failure names its own layer from the
# transcript alone -- and they run only after a bounded wait has already given
# up, so a converging boot pays nothing for them.
#
# Secret-free by construction, and it is the gate's shape that guarantees it
# rather than a rule to remember: this unit only ever LOOKS UP identities and
# authenticates nothing, so no credential exists in the process to leak.
# klist -k lists principal names and key versions, never key material; getent
# prints POSIX fields, never hashes; net reads the machine credential from
# secrets.tdb without printing it; and the SSSD log is raised only to
# trace-function level, which records LDAP filters and backend decisions.
diagnose() {{
  say sssd-unit systemctl is-active sssd.service
  say sssd-config sssctl config-check
  say domain-status sssctl domain-status "$DOMAIN"
  say login-principal getent passwd "$LOGIN_PRINCIPAL"
  # With ldap_id_mapping = False a user whose primary group carries no
  # gidNumber cannot resolve even when the user object is complete, so these
  # two separate "the user is missing" from "its group is missing".
  say primary-group getent group "$PRIMARY_GROUP"
  say admin-group getent group "$ADMIN_GROUP"
  # Name resolution, which the 2026-08-14 run had to infer and could not.  SSSD
  # reads /etc/resolv.conf through its own c-ares resolver, so what that file
  # says IS what SSSD's discovery had to work with -- and nothing on this disk
  # writes it: NetworkManager fills it in from the DHCP answer.  It carries a
  # nameserver list and a search domain, never a credential.
  say resolver cat /etc/resolv.conf
  # The two A records the pinned configuration now depends on: ad_server's and
  # ad_hostname's.  getent is the right probe and not a shortcut -- it walks the
  # same nsswitch path SSSD's own hostname expansion does.
  say resolver-controller getent hosts "$AD_SERVER"
  say resolver-client getent hosts "$AD_HOSTNAME"
  # Whether SRV discovery was ever possible here, which is the question the
  # ad_server pin routes around rather than answers.  `net lookup` is the only
  # SRV-capable tool the package contract puts on this disk -- bind's host and
  # dig belong to the controller-domain overlay, and neither systemd-resolved
  # nor any resolver library CLI is installed -- and it reads the same
  # /etc/resolv.conf SSSD does.  Read it as a near-probe and not an identical
  # one: net queries _ldap._tcp.dc._msdcs.<domain> and
  # _kerberos._tcp.dc._msdcs.<realm> (verified in the shipped libads strings),
  # while SSSD's AD provider queries _ldap._tcp.<domain>.  Samba's provisioning
  # writes both families into one zone, so an answer here means the zone is
  # reachable and answering SRV at all -- which is the layer this was unable to
  # name in the 2026-08-14 run -- and roles/domain_controller verifies the exact
  # _ldap._tcp.<domain> record SSSD needs, from the client-facing address, at
  # convergence.  A missing record prints "Didn't find the ldap server!" or
  # "Didn't find the kerberos server!".  The KDC field is not decoration either:
  # krb5.conf sets dns_lookup_kdc = true, so a login's Kerberos leg still
  # depends on SRV even with LDAP pinned.
  say discovery-ldap-srv net lookup ldap "$DOMAIN"
  say discovery-kdc-srv net lookup kdc "$REALM"
  # The CLDAP netlogon ping, which is the OTHER half of SSSD's discovery: with
  # ad_enable_dns_sites at its True default the AD provider pings a discovered
  # DC to learn its site and then re-queries the site-specific SRV records.  Its
  # reply names the forest, the domain, the DC and the client site, so this one
  # field separates "DNS answered nothing" from "DNS answered and the netlogon
  # reply was unusable".
  say discovery-netlogon net ads lookup
  # Arch runs sssd as User=sssd, so the root-only host keytab is reachable only
  # through the file capabilities its helper children carry.  Together these
  # three fields say whether a GSSAPI bind was ever possible at all -- a
  # question about local files, not about the directory.
  say host-keytab ls -l "$HOST_KEYTAB"
  say keytab-principals klist -k "$HOST_KEYTAB"
  say sssd-child-caps getcap {diagnostic_child_binaries}
  # The directory's own answer, over LDAP on the DC itself rather than the
  # Global Catalog, authenticated with the machine credential the join already
  # proved.  If these carry uidNumber and gidNumber while the getent fields
  # above did not, the fault is in SSSD and not in the directory.
  say directory-info net ads info
  say directory-user net ads search -P "(sAMAccountName=$LOGIN_PRINCIPAL)" \\
    sAMAccountName uidNumber gidNumber loginShell unixHomeDirectory
  say directory-primary-group net ads search -P \\
    "(sAMAccountName=$PRIMARY_GROUP)" sAMAccountName gidNumber
  # Last, SSSD's own account of it: raise the log level, force one more lookup
  # so the reason is recorded at that level, then print the log from both ends.
  #
  # The raise is reported as a field rather than discarded.  It was discarded for
  # one live run and the forty tailed lines that came back carried no
  # trace-level entry at all, which left "the level never changed" and "the
  # backend had nothing further to say" indistinguishable.  sssctl prints nothing
  # on success, so "(no output)" here means the level took.
  debug_level='{DIAGNOSTIC_SSSD_DEBUG_LEVEL}'
  say sssd-debug-level sssctl debug-level "$debug_level"
  getent passwd "$LOGIN_PRINCIPAL" >/dev/null 2>&1 || true
  domain_log='{DIAGNOSTIC_SSSD_LOG_DIR}/sssd_'"$DOMAIN"'.log'
  if [ -r "$domain_log" ]; then
    # The head first, because that is where the AD provider recorded which
    # servers it resolved and what it did with them -- decisions taken when sssd
    # started, two minutes before this gate gave up and unreachable from any
    # tail.  Then the tail, for the most recent state.  Two field names, so a
    # reader never has to guess which end of the log a line came from.
    head -n {DIAGNOSTIC_SSSD_LOG_HEAD_LINES} "$domain_log" |
      cut -c1-{DIAGNOSTIC_LINE_COLUMNS} |
      while IFS= read -r entry; do
        printf '%s %s: %s\\n' '{DOMAIN_ONLINE_DIAGNOSTIC_MARKER}' \\
          sssd-log-start "$entry" > /dev/console
      done
    tail -n {DIAGNOSTIC_SSSD_LOG_LINES} "$domain_log" |
      cut -c1-{DIAGNOSTIC_LINE_COLUMNS} |
      while IFS= read -r entry; do
        printf '%s %s: %s\\n' '{DOMAIN_ONLINE_DIAGNOSTIC_MARKER}' \\
          sssd-log "$entry" > /dev/console
      done
  else
    say sssd-log ls -l '{DIAGNOSTIC_SSSD_LOG_DIR}'
  fi
}}

# Failures print to /dev/console, not only to the journal: ttyS0 is the only
# channel gate 8 can read, and a readiness stop that said nothing there would
# be exactly the undiagnosable failure this unit exists to end.  The reason
# comes first so the verdict leads the transcript, then the evidence.  Both
# markers are secret-free -- a principal name and a fixed reason, never a
# credential.
fail() {{
  printf '%s: %s\\n' '{DOMAIN_ONLINE_FAILURE_MARKER}' "$1" > /dev/console
  diagnose
  exit 1
}}

{_DOMAIN_STATE_FUNCTIONS}

# The condition pam_sss actually needs, waited on FIRST: this principal has to
# be answerable.  That is proof and not a warm-up, because the join unit wiped
# the identity cache while sssd was still stopped -- so a successful lookup can
# only have been served by the live directory.
resolved=0
for _ in $(seq 1 {JOIN_WAIT_TRIES}); do
  if getent passwd "$LOGIN_PRINCIPAL" >/dev/null 2>&1; then
    resolved=1
    break
  fi
  sleep {JOIN_WAIT_SECONDS}
done
[ "$resolved" -eq 1 ] ||
  fail 'the directory login principal never resolved through SSSD'

# Then the shared domain-state view every gate-8 lifecycle check also waits on.
# It normally converges the instant the lookup above did, so reaching this line
# and failing means something narrower and worth naming: sssctl cannot answer,
# which would make nine of the eleven acceptance checks fail closed for a
# reason that has nothing to do with identity.  Say that on the console now
# rather than hand gate 8 an unexplained arch-joined FAIL later.
await_domain_state Online ||
  fail 'sssctl never reported the SSSD domain Online (is the ifp responder up?)'

printf '%s\\n' '{DOMAIN_ONLINE_MARKER}' > /dev/console
"""


def _render_domain_online_unit() -> str:
    """Emit the domain-online gate unit; its ordering is the login gate."""
    after = " ".join(DOMAIN_ONLINE_AFTER_UNITS)
    before = " ".join(DOMAIN_ONLINE_BEFORE_UNITS)
    return f"""# Managed by Telos gate 7 (workstations/arch_second.py).
[Unit]
Description=Telos SSSD domain-online gate before user sessions
# sssd.service is Type=notify and its monitor answers READY=1 once the nss and
# pam responders are up; the AD provider's DNS, LDAP and Kerberos connection to
# the freshly provisioned Controller completes asynchronously *after* that.  So
# ordering after sssd is not enough on its own -- this unit is what turns
# "started" into "usable".  Requires= makes an sssd that never starts a failure
# here rather than a 120-second wait for a backend that cannot appear.
Requires={after}
After={after}
# The login gate.  serial-getty@ttyS0 is After=systemd-user-sessions.service
# (systemd's own unit; visible in the 2026-08-14 transcript, where "Finished
# Permit User Sessions" precedes "Started Serial Getty on ttyS0"), so ordering
# before user sessions is what keeps the login prompt behind a usable domain.
# No new edge is added against nss-user-lookup.target: sssd already declares
# Before= both it and systemd-user-sessions, and systemd-user-sessions declares
# no Before= at all, so these two edges run with the existing ones and cannot
# close a cycle.
Before={before}

[Service]
Type=oneshot
RemainAfterExit=no
ExecStart={DOMAIN_ONLINE_SCRIPT_PATH}

[Install]
WantedBy=multi-user.target
"""


def render_installer(
    *,
    disk_path: str,
    disk_serial: str,
    hostname: str,
    expected_sizes_mib: Sequence[int],
    realm_dns_domain: str = SYNTHETIC_DOMAIN,
    realm_workgroup: str = SYNTHETIC_WORKGROUP,
    join_media_label: str = JOIN_MEDIA_LABEL,
    package_repo_url: str = WORKSTATION_REPO_URL,
) -> str:
    """Render the destructive stage with its validation embedded before mkfs.

    The synthetic-realm identity provisioning takes no secret: the machine
    join reads a per-run credential (``join.json`` carrying ``username`` and
    ``password``) from one-use removable media labelled *join_media_label*,
    which the runner attaches after archiso is live and destroys after the
    ``TELOS ARCH JOIN MEDIA CONSUMED`` marker.  The credential exists only in
    tmpfs and is removed before the installer finishes.

    ``pacstrap`` never reaches an internet mirror: the script replaces the
    live environment's mirrorlist and pacman.conf so *package_repo_url* —
    by default the disposable Controller's receipt-bound workstation
    repository at the fixed fabric address — is the sole package source.
    """
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
    if not SAFE_DOMAIN.fullmatch(realm_dns_domain):
        raise InstallContractError("realm DNS domain is invalid")
    if not SAFE_WORKGROUP.fullmatch(realm_workgroup):
        raise InstallContractError("realm workgroup is invalid")
    if not SAFE_LABEL.fullmatch(join_media_label):
        raise InstallContractError("join media label is invalid")
    if not SAFE_REPO_URL.fullmatch(package_repo_url):
        raise InstallContractError("package repository URL is invalid")
    realm = realm_dns_domain.upper()
    principals = _identity_principals()
    login_bound = _identity_login_bound()
    storage_host = f"{STORAGE_HOST_LABEL}.{realm_dns_domain}"
    # The realm's one domain controller and this machine, both fully qualified.
    # SSSD is told exactly these two names (ad_server, ad_hostname) and the
    # boot-time gate reports on exactly these two names, so the diagnostic can
    # never disagree with the configuration it is diagnosing.
    controller_fqdn = f"{CONTROLLER_HOSTNAME}.{realm_dns_domain}"
    client_fqdn = f"{hostname}.{realm_dns_domain}"
    sizes = ",".join(str(size) for size in expected_sizes_mib)
    packages = " ".join(_workstation_packages())
    repo_name = WORKSTATION_REPO_NAME
    krb5_conf = _render_krb5(realm)
    smb_conf = _render_smb(realm, realm_workgroup)
    sssd_conf = _render_sssd(
        realm_dns_domain, realm,
        controller_fqdn=controller_fqdn, client_fqdn=client_fqdn)
    probe = _render_probe(
        domain=realm_dns_domain, principals=principals,
        storage_host=storage_host, login_bound=login_bound)
    pam_system_auth = _PAM_SYSTEM_AUTH
    probe_path = PROBE_HELPER_PATH
    windows_optdata_b64 = base64.b64encode(
        NVRAM_WINDOWS_OPTIONAL_DATA).decode("ascii")
    windows_optdata_bytes = len(NVRAM_WINDOWS_OPTIONAL_DATA)
    local_rescue = principals["local_rescue"]
    daily_admin = principals["daily_admin"]
    standard_user = principals["standard"]
    storage_mount_root = STORAGE_MOUNT_ROOT
    # The one-use media consumption is rendered once and used twice: inline
    # below for the install-time join, and inside the boot-time one-shot join
    # script, so the two paths cannot drift apart.
    join_media_stage = _render_join_media_stage(join_media_label)
    join_once_script = _render_join_once_script(
        join_media_label=join_media_label,
        realm_dns_domain=realm_dns_domain)
    join_once_unit = _render_join_once_unit()
    join_once_script_path = JOIN_ONCE_SCRIPT_PATH
    join_once_unit_path = JOIN_ONCE_UNIT_PATH
    join_once_unit_name = JOIN_ONCE_UNIT_NAME
    # The login-readiness gate that follows the join: same one-shot shape, and
    # it reuses the probe helper's own domain-state implementation.
    domain_online_script = _render_domain_online_script(
        realm_dns_domain=realm_dns_domain, realm=realm,
        login_principal=principals["daily_admin"],
        controller_fqdn=controller_fqdn, client_fqdn=client_fqdn)
    domain_online_unit = _render_domain_online_unit()
    domain_online_script_path = DOMAIN_ONLINE_SCRIPT_PATH
    domain_online_unit_path = DOMAIN_ONLINE_UNIT_PATH
    domain_online_unit_name = DOMAIN_ONLINE_UNIT_NAME
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

# ---- Offline package source (factory offline contract) ----
# The isolated fabric resolves no internet mirror, so the stock archiso
# mirrorlist can only fail DNS (proven live: pacstrap died retrieving
# core.db/extra.db).  Replace -- never append to -- both pacman entry
# points so the Controller's receipt-bound workstation repository is the
# sole reachable package source.  The packages are official signed
# archives, so the signature policy stays exactly the Controller seed's
# (homelab/seed/pacman.conf, ADR 0075): SigLevel Required, verified
# against the archiso keyring; only the repo-add database itself is
# unsigned, hence DatabaseOptional.  pacstrap copies this mirrorlist into
# the installed system, which keeps the factory exercise offline;
# provisioning real internet mirrors is a later, online fleet concern.
cat > /etc/pacman.d/mirrorlist <<'TELOS_MIRROR_EOF'
# Managed by Telos gate 7 (workstations/arch_second.py).
# Sole package source: the disposable Controller's workstation repository.
Server = {package_repo_url}
TELOS_MIRROR_EOF
cat > /etc/pacman.conf <<'TELOS_PACMAN_EOF'
# Managed by Telos gate 7 (workstations/arch_second.py).  The stock
# repositories are deliberately absent: the replaced mirrorlist above is
# the only server list, and this is the only repository section.
[options]
Architecture = auto
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Required
ParallelDownloads = 5

[{repo_name}]
Include = /etc/pacman.d/mirrorlist
TELOS_PACMAN_EOF

pacstrap -K /mnt {packages}
genfstab -U /mnt >> /mnt/etc/fstab
printf '%s\\n' "$hostname" > /mnt/etc/hostname

# The install-time boot attaches this disk as virtio-blk, but later boots
# (dual-boot acceptance, gate 8) attach the very same disk as NVMe again.
# mkinitcpio's autodetect would trim the absent transport, so pin both and
# regenerate every preset after the drop-in exists.
install -Dm0644 /dev/stdin /mnt/etc/mkinitcpio.conf.d/telos-transports.conf \\
    <<'TELOS_MKINITCPIO_EOF'
# Managed by Telos gate 7: the disk is attached as virtio-blk at install
# time and as NVMe on later boots; carry both transports unconditionally.
MODULES+=(nvme virtio_blk)
TELOS_MKINITCPIO_EOF
arch-chroot /mnt mkinitcpio -P

arch-chroot /mnt systemctl enable NetworkManager

# ---- Synthetic-realm identity client (gate 7 -> gate 8 contract) ----
# The machine-join credential arrives on one-use removable media; it is read
# into tmpfs only, never echoed, never written to the installed disk, and the
# runner destroys the media after the consumed marker below.
{join_media_stage}
echo "{JOIN_MEDIA_CONSUMED_MARKER}"

install -Dm0644 /dev/stdin /mnt/etc/krb5.conf <<'TELOS_KRB5_EOF'
{krb5_conf}
TELOS_KRB5_EOF
install -Dm0644 /dev/stdin /mnt/etc/samba/smb.conf <<'TELOS_SMB_EOF'
{smb_conf}
TELOS_SMB_EOF
install -Dm0600 /dev/stdin /mnt/etc/sssd/sssd.conf <<'TELOS_SSSD_EOF'
{sssd_conf}
TELOS_SSSD_EOF

# Join as the installed hostname, not the live image's; arch-chroot bind
# mounts /run, so the tmpfs credential file is visible inside the chroot.
printf '%s' "$hostname" > /proc/sys/kernel/hostname
arch-chroot /mnt net ads join -A /run/telos-join/credentials
arch-chroot /mnt net ads testjoin
rm -rf /run/telos-join
echo "{JOIN_VERIFIED_MARKER}"

# NSS and PAM the Arch way (no authselect): sss sits next to files.
sed -i -E 's/^(passwd|group): files/\\1: files sss/' /mnt/etc/nsswitch.conf
grep -q '^passwd: files sss' /mnt/etc/nsswitch.conf
grep -q '^group: files sss' /mnt/etc/nsswitch.conf
install -Dm0644 /dev/stdin /mnt/etc/pam.d/system-auth <<'TELOS_PAM_EOF'
{pam_system_auth}
TELOS_PAM_EOF
printf 'session   optional  pam_mkhomedir.so umask=0077\\n' \\
    >> /mnt/etc/pam.d/system-login

# Local break-glass administrator, mirroring the Controller seed installer:
# created with a disabled password; an authorized console session sets it.
arch-chroot /mnt useradd --create-home --groups wheel --shell /bin/bash \\
    {local_rescue}
install -Dm0440 /dev/stdin /mnt/etc/sudoers.d/10-local-rescue <<'TELOS_SUDO_EOF'
%wheel ALL=(ALL:ALL) ALL
TELOS_SUDO_EOF
install -Dm0440 /dev/stdin /mnt/etc/sudoers.d/20-daily-admin <<'TELOS_DAILY_EOF'
{daily_admin} ALL=(ALL:ALL) ALL
TELOS_DAILY_EOF

install -Dm0755 /dev/stdin /mnt{probe_path} <<'TELOS_PROBE_EOF'
{probe}
TELOS_PROBE_EOF

# ---- Optional per-user UNAS storage (gate 9 contract) ----
# Local profiles and homes stay authoritative for login.  The durable attach
# path below is structurally incapable of blocking login: nofail keeps it a
# Wants= of remote-fs.target, x-systemd.automount defers the network mount to
# first access, and the bounded mount timeout caps any attach attempt.  No
# login-path unit orders after it and the acceptance probe performs its own
# explicit bounded mounts.  mount.cifs is owned by cifs-utils, which the
# package contract does not yet carry; until that contract decision lands the
# automount trigger and the probe both fail closed without hanging.
mkdir -p /mnt{storage_mount_root}/{standard_user}
cat >> /mnt/etc/fstab <<'TELOS_STORAGE_EOF'
# Optional per-user UNAS storage: may attach when reachable, never
# login-blocking (Telos gate 9).
//{storage_host}/{standard_user} {storage_mount_root}/{standard_user} cifs sec=krb5,multiuser,soft,echo_interval=15,_netdev,nofail,x-systemd.automount,x-systemd.mount-timeout=10s,x-systemd.idle-timeout=1min 0 0
TELOS_STORAGE_EOF

# ---- Boot-time one-shot re-join (gate-8 in-run join contract) ----
# The install-time join above is what gate-7 acceptance proves, and it stays
# exactly as it is.  It is not enough for gate 8: that gate boots this disk
# against a FRESHLY PROVISIONED domain whose SAM has never seen this machine
# account, so the installed system re-joins itself once, early in boot, from
# one-use media -- the only shape available, because this disk has no
# pre-login shell to drive a join from.  Root-only script, mode-0644 unit.
install -Dm0700 /dev/stdin /mnt{join_once_script_path} \\
    <<'TELOS_JOIN_ONCE_EOF'
{join_once_script}
TELOS_JOIN_ONCE_EOF
install -Dm0644 /dev/stdin /mnt{join_once_unit_path} <<'TELOS_JOIN_UNIT_EOF'
{join_once_unit}
TELOS_JOIN_UNIT_EOF

# ---- Boot-time SSSD domain-online gate (gate-8 login-readiness contract) ----
# The join above proves the directory knows this machine; it does NOT prove
# SSSD can use it yet.  sssd.service reaching active means only that its nss
# and pam responders answered READY=1, so on 2026-08-14 the login prompt
# rendered about a second later, the harness typed the credential, pam_sss
# found the domain still offline, and offline authentication had no cached
# credential to fall back on -- the join unit had just wiped the cache and the
# operator password is generated fresh every run.  This unit closes that window
# by holding systemd-user-sessions (and therefore the ttyS0 getty) until the
# backend is online AND the login principal resolves.  Root-only script,
# mode-0644 unit, and it fails closed on timeout rather than presenting a login
# prompt nothing can log in to.
install -Dm0700 /dev/stdin /mnt{domain_online_script_path} \\
    <<'TELOS_DOMAIN_ONLINE_EOF'
{domain_online_script}
TELOS_DOMAIN_ONLINE_EOF
install -Dm0644 /dev/stdin /mnt{domain_online_unit_path} \\
    <<'TELOS_DOMAIN_UNIT_EOF'
{domain_online_unit}
TELOS_DOMAIN_UNIT_EOF

arch-chroot /mnt systemctl enable {join_once_unit_name}
arch-chroot /mnt systemctl enable {domain_online_unit_name}
arch-chroot /mnt systemctl enable sssd serial-getty@ttyS0.service

arch-chroot /mnt bootctl install
root_uuid=$(blkid -s UUID -o value "$ARCH_PART")
cat > /mnt/boot/loader/entries/arch-linux-lts.conf <<EOF
title {MENU_ARCH_TITLE}
linux /vmlinuz-linux-lts
initrd /initramfs-linux-lts.img
options root=UUID=$root_uuid rw console=tty0 console=ttyS0,115200
EOF
cat > /mnt/boot/loader/loader.conf <<'EOF'
default auto-windows
timeout 5
editor no
EOF
grep -q '^default auto-windows$' /mnt/boot/loader/loader.conf
# ESP-state proofs.  All markers below print from inside this
# heredoc-delivered script, so the serial echo of a dispatched command can
# never fake them.
[ -f /mnt/boot/EFI/systemd/systemd-bootx64.efi ]
echo "TELOS ARCH BOOTLOADER LINUX PRESENT"
[ -f /mnt/boot/EFI/Microsoft/Boot/bootmgfw.efi ]
echo "TELOS ARCH BOOTLOADER WINDOWS PRESERVED"
echo "TELOS ARCH DEFAULT auto-windows"

# ---- UEFI NVRAM boot entries (gate-10 five-second-menu contract) ----
# Authored here in the live archiso: efivarfs is writable in this
# environment (the gate-7 post-step efibootmgr proved it) and not in the
# chroot.  Windows self-promotes to BootOrder first only when its first
# boot must CREATE its own NVRAM entry; authoring "Windows Boot Manager"
# now, behind "Linux Boot Manager", is what lets the five-second
# systemd-boot menu survive the first Windows boot.  Fail closed: without
# writable efivarfs the install must not pretend the NVRAM was authored.
[[ -d /sys/firmware/efi/efivars ]] || {{
  echo "efivarfs is unavailable; NVRAM boot entries cannot be authored" >&2
  exit 1
}}
mountpoint -q /sys/firmware/efi/efivars || {{
  echo "efivarfs is not mounted; NVRAM boot entries cannot be authored" >&2
  exit 1
}}
command -v efibootmgr >/dev/null || {{
  echo "efibootmgr is unavailable; NVRAM boot entries cannot be authored" >&2
  exit 1
}}
esp_number="${{ESP_PART#"$disk"}}"
esp_number="${{esp_number#p}}"
[[ "$esp_number" =~ ^[0-9]+$ ]] || {{
  echo "cannot derive the ESP partition number from $ESP_PART" >&2
  exit 1
}}
nvram_entry_numbers() {{
  efibootmgr | sed -nE "s/^Boot([0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f])\\*?[[:space:]]+$1([[:space:]].*)?\\$/\\1/p"
}}
# Idempotent: any pre-existing entry carrying a managed label is deleted
# before its replacement is created, so a re-run never accumulates
# duplicates.  The surviving order is captured after those deletions so
# the final BootOrder preserves every unmanaged entry behind the managed
# pair (efibootmgr -B already drops deleted entries from BootOrder).
for label in '{NVRAM_WINDOWS_LABEL}' '{NVRAM_LINUX_LABEL}'; do
  for number in $(nvram_entry_numbers "$label"); do
    efibootmgr -b "$number" -B >/dev/null
  done
done
previous_order=$(efibootmgr | sed -nE 's/^BootOrder:[[:space:]]*//p')
efibootmgr -c -d "$disk" -p "$esp_number" -L '{NVRAM_LINUX_LABEL}' \\
  -l '{NVRAM_LINUX_LOADER}' >/dev/null
# The Windows entry must carry Windows Boot Manager's own optional-data
# blob (WINDOWS signature + fixed BCDOBJECT GUID): without it Windows'
# first boot treats the entry as foreign, creates its own, and promotes
# it ahead of Linux — proven live on 2026-08-11.  Fail closed if the
# constant does not decode to its exact recorded size.
printf '%s' '{windows_optdata_b64}' | base64 -d \\
  > /run/telos-nvram-windows.optdata
[[ "$(wc -c < /run/telos-nvram-windows.optdata)" -eq \\
    {windows_optdata_bytes} ]] || {{
  echo "Windows NVRAM optional data failed to decode" >&2
  exit 1
}}
efibootmgr -c -d "$disk" -p "$esp_number" -L '{NVRAM_WINDOWS_LABEL}' \\
  -l '{NVRAM_WINDOWS_LOADER}' \\
  -@ /run/telos-nvram-windows.optdata >/dev/null
rm -f /run/telos-nvram-windows.optdata
linux_entry=$(nvram_entry_numbers '{NVRAM_LINUX_LABEL}')
windows_entry=$(nvram_entry_numbers '{NVRAM_WINDOWS_LABEL}')
hex4='[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]'
[[ "$linux_entry" == $hex4 && "$windows_entry" == $hex4 ]] || {{
  echo "NVRAM boot entries were not authored exactly once" >&2
  exit 1
}}
echo "{NVRAM_ENTRIES_MARKER}"
order="$linux_entry,$windows_entry"
for number in ${{previous_order//,/ }}; do
  [[ "$number" == $hex4 ]] || continue
  [[ "$number" == "$linux_entry" || "$number" == "$windows_entry" ]] && \\
    continue
  order="$order,$number"
done
efibootmgr -o "$order" >/dev/null
# No -q: grep must drain the pipe, or its early exit would SIGPIPE
# efibootmgr and pipefail would turn a successful write into a failure.
efibootmgr | grep "^BootOrder: $order\\$" >/dev/null || {{
  echo "NVRAM boot order verification failed" >&2
  exit 1
}}
echo "{NVRAM_ORDER_MARKER}"
sync
echo "Arch installed; Windows partitions and filesystems were not modified."
"""


def _workstation_packages() -> tuple[str, ...]:
    """Resolve the checked-in common + Workstation policy deterministically."""
    contract = HOMELAB_ROOT / "package-contract.json"
    return merge_contract(
        load_registry(contract), PROFILE_OVERLAYS["workstation-install"]
    ).packages


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
