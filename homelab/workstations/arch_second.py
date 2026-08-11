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
"""

from __future__ import annotations

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


def _render_sssd(domain: str, realm: str) -> str:
    """Mirror ansible/roles/identity_client/templates/sssd.conf.j2."""
    return f"""# Managed by Telos gate 7 (workstations/arch_second.py).
[sssd]
domains = {domain}
config_file_version = 2
services = nss, pam

[domain/{domain}]
id_provider = ad
access_provider = ad
ad_domain = {domain}
krb5_realm = {realm}
realmd_tags = manages-system joined-with-samba
cache_credentials = True
# ADR 0071: SSSD defines zero as no expiration. A disconnected machine cannot
# learn that an AD account was disabled; phase 2 owns stronger revocation.
krb5_store_password_if_offline = True
offline_credentials_expiration = 0
# UID and GID come from the directory (ADR 0055), not from a local mapping.
ldap_id_mapping = False
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
ADMIN_GROUP='domain admins'
STANDARD_USER='@STANDARD_USER@'
DAILY_ADMIN='@DAILY_ADMIN@'
DOMAIN_ADMIN='@DOMAIN_ADMIN@'
RESCUE_USER='@RESCUE_USER@'
STORAGE_HOST='@STORAGE_HOST@'
STORAGE_PROBE_ROOT='@STORAGE_PROBE_ROOT@'
LOGIN_BOUND_SECONDS='@LOGIN_BOUND@'

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

domain_state() {
  sssctl domain-status "$DOMAIN" 2>/dev/null | grep -qi "Online status: $1"
}

await_domain_state() {
  for _ in $(seq 1 30); do
    # A lookup no cache can serve forces SSSD to test the backend.
    getent passwd "telos-probe-trigger-$$" >/dev/null 2>&1 || true
    domain_state "$1" && return 0
    sleep 2
  done
  return 1
}

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
        "@STANDARD_USER@": principals["standard"],
        "@DAILY_ADMIN@": principals["daily_admin"],
        "@DOMAIN_ADMIN@": principals["domain_admin"],
        "@RESCUE_USER@": principals["local_rescue"],
        "@STORAGE_HOST@": storage_host,
        "@STORAGE_PROBE_ROOT@": STORAGE_PROBE_ROOT,
        "@LOGIN_BOUND@": str(login_bound),
    }
    text = _PROBE_TEMPLATE
    for token, value in replacements.items():
        text = text.replace(token, value)
    return text


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
    sizes = ",".join(str(size) for size in expected_sizes_mib)
    packages = " ".join(_workstation_packages())
    repo_name = WORKSTATION_REPO_NAME
    krb5_conf = _render_krb5(realm)
    smb_conf = _render_smb(realm, realm_workgroup)
    sssd_conf = _render_sssd(realm_dns_domain, realm)
    probe = _render_probe(
        domain=realm_dns_domain, principals=principals,
        storage_host=storage_host, login_bound=login_bound)
    pam_system_auth = _PAM_SYSTEM_AUTH
    probe_path = PROBE_HELPER_PATH
    local_rescue = principals["local_rescue"]
    daily_admin = principals["daily_admin"]
    standard_user = principals["standard"]
    storage_mount_root = STORAGE_MOUNT_ROOT
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
join_dev="/dev/disk/by-label/{join_media_label}"
for _ in $(seq 1 60); do
  [[ -e "$join_dev" ]] && break
  sleep 2
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
umount /run/telos-join/media
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
efibootmgr -c -d "$disk" -p "$esp_number" -L '{NVRAM_WINDOWS_LABEL}' \\
  -l '{NVRAM_WINDOWS_LOADER}' >/dev/null
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
