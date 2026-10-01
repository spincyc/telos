import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workstations.arch_second import (
    CONTROLLER_ADDRESS, CONTROLLER_HOSTNAME,
    DIAGNOSTIC_CHILD_LOG_LINES, DIAGNOSTIC_COMMAND_SECONDS,
    DIAGNOSTIC_EMPTY_FIELD, DIAGNOSTIC_KEYTAB_LINES,
    DIAGNOSTIC_LINE_COLUMNS, DIAGNOSTIC_SSSD_BACKTRACE_END,
    DIAGNOSTIC_SSSD_DEBUG_LEVEL,
    DIAGNOSTIC_SSSD_LOG_DIR, DIAGNOSTIC_SSSD_LOG_HEAD_LINES,
    DIAGNOSTIC_SSSD_LOG_LINES, DIAGNOSTIC_TGT_CACHE_PATH,
    DIRECTORY_ADMIN_GROUP, DIRECTORY_PRIMARY_GROUP,
    DOMAIN_ONLINE_AFTER_UNITS, DOMAIN_ONLINE_BEFORE_UNITS,
    DOMAIN_ONLINE_DIAGNOSTIC_MARKER,
    DOMAIN_ONLINE_FAILURE_MARKER, DOMAIN_ONLINE_MARKER,
    DOMAIN_ONLINE_SCRIPT_PATH, DOMAIN_ONLINE_UNIT_NAME,
    DOMAIN_ONLINE_UNIT_PATH, ESP, HOST_KEYTAB_PATH,
    JOIN_MEDIA_CONSUMED_MARKER, JOIN_MEDIA_LABEL,
    JOIN_ONCE_BEFORE_UNITS, JOIN_ONCE_SCRIPT_PATH, JOIN_ONCE_UNIT_NAME,
    JOIN_ONCE_UNIT_PATH, JOIN_VERIFIED_MARKER, JOIN_WAIT_SECONDS,
    JOIN_WAIT_TRIES, LINUX_ROOT_X86_64,
    MENU_ARCH_TITLE, MENU_WINDOWS_TITLE, MSR, NVRAM_ENTRIES_MARKER,
    NVRAM_LINUX_LABEL, NVRAM_LINUX_LOADER, NVRAM_ORDER_MARKER,
    NVRAM_WINDOWS_LABEL, NVRAM_WINDOWS_LOADER, NVRAM_WINDOWS_OPTIONAL_DATA,
    PROBE_CHECKS, PROBE_DOMAIN_WAIT_TRIES, PROBE_HELPER_PATH,
    PROBE_LOOKUP_WAIT_TRIES, SSSD_CACHE_GLOB,
    SSSD_CHILD_BINARIES, SSSD_CHILD_LOG_NAMES, SSSD_SERVICES,
    STORAGE_ATTACHED_MEASUREMENT_MARKERS, STORAGE_DIAGNOSTIC_MARKER,
    STORAGE_HOST_LABEL, STORAGE_MOUNT_ERROR_PATH,
    STORAGE_LOGIN_SECONDS_MARKER, STORAGE_MOUNT_ROOT, STORAGE_PROBE_ROOT,
    SYNTHETIC_DOMAIN, SYNTHETIC_WORKGROUP, WINDOWS, WINDOWS_RECOVERY,
    WORKSTATION_REPO_NAME, WORKSTATION_REPO_URL, Disk,
    InstallContractError, Partition, _DOMAIN_STATE_FUNCTIONS,
    _machine_principal, _render_join_media_stage, parse_lsblk,
    render_installer, validate_windows_first,
)
from workstations.arch_second import (
    CONTRACT_ROLES, DIRECTORY_ROLES, IdentityRosterError, PROBE_ROSTER_MARKER,
    PROBE_ROSTER_VERB, ROSTER_FINGERPRINT_LENGTH, SAFE_PRINCIPAL,
    SAMACCOUNTNAME_LIMIT,
    identity_contract_path, identity_overlay_path, identity_roster,
    identity_roster_fingerprint, identity_roster_source,
)
from workstations.arch_second import (
    SYNTHETIC_REALM_SOURCE, InstallerRealm, InstallerRealmError,
    durable_installer_realm, installer_realm, synthetic_installer_realm,
)
from workstations.arch_second import (
    JOIN_DEFERRED_MARKER, JOIN_ONCE_SEAL_DIR, JOIN_ONCE_SEAL_PATH,
    _render_join_once_script, _render_join_once_unit,
)
import workstations.arch_second as arch_second
from lib.package_contract import PROFILE_OVERLAYS, load_registry, merge_contract
from lib.workstation_repo import REPO_NAME
from homelab.tests.identity_overlay_pin import (
    overlay_document, pinned_identity_overlay,
)


def setUpModule():
    # HANDOFF section 5: no test reads the owner's private overlay.  The
    # installer renderer resolves the roster from the DEFAULT overlay path, so
    # every test here runs with that path pinned to a private one that does
    # not exist -- the synthetic acceptance roster.  A test that wants an
    # overlay passes one explicitly or pins its own.
    unittest.enterModuleContext(pinned_identity_overlay())

MIB = 1024**2
SIZES = (1024, 16, 300 * 1024, 100 * 1024, 2048)
# The fleet template the installer's rendered sssd.conf deliberately mirrors.
SSSD_TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "ansible/roles/identity_client/templates/sssd.conf.j2")
GUIDS = (ESP, MSR, WINDOWS, LINUX_ROOT_X86_64, WINDOWS_RECOVERY)
FILESYSTEMS = ("vfat", None, "ntfs", None, "ntfs")


def _heredoc_body(script: str, terminator: str) -> str:
    """Return exactly the payload the installer delivers under *terminator*."""
    opener = f"<<'{terminator}'\n"
    start = script.index(opener) + len(opener)
    return script[start:script.index(f"\n{terminator}\n", start)]


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

    def test_parses_flat_lsblk_json_without_name_column(self):
        # The verify invocation selects explicit -o columns without NAME, and
        # lsblk then emits the disk and its partitions as flat sibling rows
        # with no ``children`` nesting — the shape every live installer run
        # actually sees. The parser must accept it identically.
        rows = [{
            "path": "/dev/vda", "type": "disk", "serial": "LAPTOP-1",
            "pttype": "gpt",
        }]
        rows.extend(
            {"path": f"/dev/vda{i}", "type": "part",
             "parttype": guid.lower(), "size": size * MIB,
             "fstype": filesystem}
            for i, (guid, size, filesystem)
            in enumerate(zip(GUIDS, SIZES, FILESYSTEMS), 1)
        )
        document = {"blockdevices": rows}
        parsed = parse_lsblk(json.loads(json.dumps(document)), "/dev/vda")
        self.assertEqual(parsed.serial, "LAPTOP-1")
        self.assertEqual(
            [partition.number for partition in parsed.partitions],
            [1, 2, 3, 4, 5][:len(parsed.partitions)],
        )
        self.assertEqual(len(parsed.partitions), len(SIZES))

    def test_loader_entry_carries_a_serial_console(self):
        # The installed system must render its boot menu and getty on ttyS0:
        # gate 8 drives the login and gate 10 drives the menu over serial.
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="stephen", expected_sizes_mib=SIZES,
        )
        self.assertIn(
            "options root=UUID=$root_uuid rw console=tty0 "
            "console=ttyS0,115200",
            script,
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
        # set-default writes an EFI variable and rejects --root/--image, so
        # the default-boot policy lives solely in loader.conf; the render
        # proves the written line instead of calling an unsupported verb.
        self.assertNotIn("set-default", script)
        self.assertIn("grep -q '^default auto-windows$' "
                      "/mnt/boot/loader/loader.conf", script)
        self.assertNotIn("adcli", script)
        self.assertNotIn("oddjob", script)
        self.assertIn("sssd", script)
        self.assertIn("samba", script)

    def test_installer_provisions_identity_client(self):
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        # Domain join, then its machine-credential verification.
        self.assertIn(
            "arch-chroot /mnt net ads join -A /run/telos-join/credentials",
            script)
        self.assertIn("arch-chroot /mnt net ads testjoin", script)
        self.assertIn("TELOS ARCH JOIN MEDIA CONSUMED", script)
        self.assertIn("TELOS ARCH JOIN VERIFIED", script)
        # Config mirrors ansible/roles/identity_client/templates.
        self.assertIn("install -Dm0644 /dev/stdin /mnt/etc/krb5.conf", script)
        self.assertIn(
            "install -Dm0644 /dev/stdin /mnt/etc/samba/smb.conf", script)
        self.assertIn(
            "install -Dm0600 /dev/stdin /mnt/etc/sssd/sssd.conf", script)
        self.assertIn("security = ADS", script)
        self.assertIn("realm = AD.FACTORY.TEST", script)
        self.assertIn("workgroup = FACTORY", script)
        self.assertIn("default_realm = AD.FACTORY.TEST", script)
        self.assertIn("cache_credentials = True", script)
        # ADR 0071: zero means the offline cache never expires.
        self.assertIn("offline_credentials_expiration = 0", script)
        self.assertIn("ldap_id_mapping = False", script)
        # NSS/PAM wiring the Arch way, and the boot-time services.
        self.assertIn("grep -q '^passwd: files sss'", script)
        self.assertIn("grep -q '^group: files sss'", script)
        self.assertIn("pam_sss.so", script)
        self.assertIn("pam_mkhomedir.so umask=0077", script)
        self.assertIn(
            "arch-chroot /mnt systemctl enable sssd "
            "serial-getty@ttyS0.service", script)

    def test_installer_creates_break_glass_and_daily_admin(self):
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        # Mirrors seed/install-controller: wheel membership plus the %wheel
        # sudoers rule, and no password is ever staged for local-rescue.
        self.assertIn(
            "useradd --create-home --groups wheel --shell /bin/bash", script)
        # Derived, not written out: render_installer bakes the RESOLVED names
        # into the script, so an overlay that renames a role renames these too
        # (RosterLoaderTests pins one).  Here the default path is pinned to no
        # overlay by setUpModule, so this is the synthetic roster.
        roster = identity_roster()
        self.assertIn(roster["local_rescue"], script)
        self.assertIn("%wheel ALL=(ALL:ALL) ALL", script)
        self.assertIn(
            f"{roster['daily_administrator']} ALL=(ALL:ALL) ALL", script)
        self.assertNotIn("passwd local-rescue", script)
        self.assertNotIn("chpasswd", script)
        # Disabled, not empty: useradd with no -p leaves "!" in /etc/shadow,
        # so `passwd -S` reports L and only an authorized console session can
        # turn that into the P the arch-local-rescue probe requires.
        self.assertNotIn("passwd -d", script)
        self.assertNotIn("--password", script)

    def test_password_stack_asks_through_pam_sss_before_pam_unix(self):
        # Load-bearing for gate 8, and it cost a live run to learn: this
        # ordering is what makes `passwd local-rescue` -- a files-only account
        # -- print pam_sss's "New Password:" rather than pam_unix's lowercase
        # "New password:".  pam_sss collects the value BEFORE it discovers the
        # account is not a domain one, and Arch's shadow ships
        # /etc/pam.d/passwd as "password include system-auth", so its wording
        # is what reaches the console.  vm/arch_identity_run's
        # rescue_prompt_pattern accepts both wordings; if this ordering is ever
        # reversed, that comment is what needs rereading, not the pattern.
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        stack = [
            line for line in script.splitlines()
            if line.startswith("password ") and "pam_" in line
        ]
        self.assertTrue(stack)
        sss = next(i for i, line in enumerate(stack) if "pam_sss.so" in line)
        unix = next(i for i, line in enumerate(stack) if "pam_unix.so" in line)
        self.assertLess(sss, unix)
        # And pam_unix is the module that actually writes /etc/shadow, so it
        # must stay required rather than optional.
        self.assertIn("required", stack[unix].split())

    def test_probe_helper_is_installed_and_covers_the_contract(self):
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        self.assertIn(
            f"install -Dm0755 /dev/stdin /mnt{PROBE_HELPER_PATH}", script)
        contract = json.loads(
            (Path(__file__).resolve().parents[1] / "workstations"
             / "identity_lifecycle.json").read_text(encoding="utf-8"))
        expected = tuple(
            check for check in contract["required_checks"]
            if check.startswith("arch-") or check == "domain-admin-separate"
        )
        self.assertEqual(sorted(PROBE_CHECKS), sorted(expected))
        for check in expected:
            self.assertIn(f"{check})", script)
        # The exact marker shape gate 8's drive waits for.
        self.assertIn(
            "printf '__TELOS_ARCH_%s_%s=%s\\n' \"$key\" \"$token\" \"$1\"",
            script)
        # Every principal the resolved roster names is baked in.  Read from the
        # loader rather than written out -- under setUpModule's pin that is the
        # synthetic roster on every machine; the synthetic names themselves
        # are asserted in RosterLoaderTests below.
        for principal in identity_roster().values():
            self.assertIn(principal, script)

    def test_join_secret_never_enters_the_rendered_script(self):
        # The seam is credential-free: the join secret arrives on one-use
        # removable media and only ever exists in guest tmpfs.
        signature = inspect.signature(render_installer)
        for name in signature.parameters:
            self.assertNotRegex(name, r"(?i)password|secret|credential")
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        self.assertIn(f"/dev/disk/by-label/{JOIN_MEDIA_LABEL}", script)
        self.assertIn("/run/telos-join/media/join.json", script)
        self.assertIn("rm -rf /run/telos-join", script)
        # The credential file only ever lives on tmpfs.
        paths = re.findall(r"\S*/credentials\b", script)
        self.assertTrue(paths)
        self.assertEqual(set(paths), {"/run/telos-join/credentials"})
        # Every mention of a password is config, PAM stack, or the tmpfs
        # media reader; no literal secret value can be present.
        allowed = (
            "krb5_store_password_if_offline",
            'values["password"]',
            '"password = " + password',
            "(username, password)",
            "pam_",
        )
        for line in script.splitlines():
            if "password" in line and not line.lstrip().startswith("#"):
                self.assertTrue(
                    any(marker in line for marker in allowed),
                    f"unexpected password reference: {line!r}")

    def test_initramfs_carries_both_disk_transports(self):
        # Installed via virtio-blk, later booted via NVMe: autodetect would
        # trim the absent transport, so both are pinned and images rebuilt.
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        self.assertIn(
            "/mnt/etc/mkinitcpio.conf.d/telos-transports.conf", script)
        self.assertIn("MODULES+=(nvme virtio_blk)", script)
        self.assertIn("arch-chroot /mnt mkinitcpio -P", script)
        # Transport-agnostic: no baked-in device naming beyond the argument.
        self.assertNotIn("/dev/nvme", script)

    def test_synthetic_defaults_match_the_factory_spec(self):
        from vm.controller_factory import FactorySpec

        spec = FactorySpec()
        self.assertEqual(SYNTHETIC_DOMAIN, spec.domain)
        self.assertEqual(SYNTHETIC_WORKGROUP, spec.netbios)
        # sssd.conf's ad_server names this controller, so the label has to be
        # the label the factory actually gives it -- FactorySpec writes the same
        # value into the Controller's /etc/hostname and /etc/hosts, and gate 8
        # printed it back as `net ads info`'s "LDAP server name".
        self.assertEqual(CONTROLLER_HOSTNAME, spec.hostname)
        self.assertEqual(
            f"{CONTROLLER_HOSTNAME}.{SYNTHETIC_DOMAIN}", spec.fqdn)
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        self.assertIn(f"realm = {spec.realm}", script)
        self.assertIn(f"ad_server = {spec.fqdn}", script)

    def test_offline_repo_defaults_match_the_factory_publication(self):
        from vm.controller_factory import FactorySpec
        from vm.factory_publication import WORKSTATION_REPO_WWW

        # The fixed fabric address is the one every PXE fetch of the
        # publication already uses; the URL path is the exact www location
        # factory_publication stages the receipt-bound repository under.
        self.assertEqual(CONTROLLER_ADDRESS, FactorySpec().address)
        self.assertEqual(
            WORKSTATION_REPO_URL,
            f"http://{CONTROLLER_ADDRESS}/{WORKSTATION_REPO_WWW}")
        # The pacman section name is the repo-add database stem; both come
        # from lib.workstation_repo so they cannot drift apart.
        self.assertEqual(WORKSTATION_REPO_NAME, REPO_NAME)

    def test_stock_mirrorlist_is_replaced_never_appended(self):
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        # Replacement, not appending: both pacman entry points are
        # overwritten before pacstrap can consult any internet mirror.
        self.assertIn("cat > /etc/pacman.d/mirrorlist <<", script)
        self.assertIn("cat > /etc/pacman.conf <<", script)
        self.assertNotIn(">> /etc/pacman.d/mirrorlist", script)
        self.assertNotIn(">> /etc/pacman.conf", script)
        server_lines = [
            line for line in script.splitlines()
            if line.startswith("Server = ")
        ]
        self.assertEqual(
            server_lines, [f"Server = {WORKSTATION_REPO_URL}"])
        # Only the Controller repository section exists; the stock internet
        # repositories are gone rather than shadowed.
        self.assertIn(f"[{WORKSTATION_REPO_NAME}]", script)
        self.assertNotIn("[core]", script)
        self.assertNotIn("[extra]", script)
        self.assertNotIn("[multilib]", script)
        # ADR 0075 signed-package policy: exactly the Controller seed's
        # signature levels (homelab/seed/pacman.conf).
        self.assertIn("SigLevel = Required DatabaseOptional", script)
        self.assertIn("LocalFileSigLevel = Required", script)
        # The replacement happens before the sole pacstrap invocation.
        self.assertLess(
            script.index("cat > /etc/pacman.d/mirrorlist"),
            script.index("\npacstrap -K"))
        self.assertLess(
            script.index("cat > /etc/pacman.conf"),
            script.index("\npacstrap -K"))

    def test_repo_url_override_flows_into_both_entry_points(self):
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
            package_repo_url="http://10.1.31.2:8080/other/repo",
        )
        self.assertIn("Server = http://10.1.31.2:8080/other/repo", script)
        self.assertNotIn(WORKSTATION_REPO_URL + "\n", script)

    def test_rejects_invalid_package_repo_urls(self):
        for url in (
            "",
            "https://mirror.example.org/repo",
            "http://10.1.31.2/repo'; rm -rf /",
            "http://10.1.31.2/repo with space",
            "http://10.1.31.2/arch/workstation-repo/",
            "ftp://10.1.31.2/repo",
            "http://10.1.31.2/$repo/$arch",
        ):
            with self.assertRaises(InstallContractError):
                render_installer(
                    disk_path="/dev/vda", disk_serial="LAPTOP-1",
                    hostname="workstation", expected_sizes_mib=SIZES,
                    package_repo_url=url,
                )

    def test_rejects_invalid_join_media_labels(self):
        for label in ("bad label", ""):
            with self.assertRaises(InstallContractError):
                render_installer(
                    disk_path="/dev/vda", disk_serial="LAPTOP-1",
                    hostname="workstation", expected_sizes_mib=SIZES,
                    join_media_label=label,
                )

    def test_probe_covers_the_optional_storage_checks(self):
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        for check in ("arch-storage-attached", "arch-storage-denied",
                      "arch-storage-absent-login"):
            self.assertIn(check, PROBE_CHECKS)
            self.assertIn(f"{check})", script)
        # The storage authority is a stable DNS name inside the synthetic
        # domain so the gate-8 runner can toggle reachability in DNS alone.
        self.assertIn(
            f"STORAGE_HOST='{STORAGE_HOST_LABEL}.{SYNTHETIC_DOMAIN}'", script)
        # Bounded absence probe and a bounded, credential-free mount attempt
        # via the user's Kerberos identity.
        self.assertIn("timeout 5 bash -c", script)
        self.assertIn("/dev/tcp/$STORAGE_HOST/445", script)
        self.assertIn("timeout 20 mount.cifs", script)
        self.assertIn("sec=krb5,cruid=$mount_uid", script)
        # mount.cifs is a contract gap (cifs-utils); the probe must guard on
        # its presence and fail closed instead of assuming it.
        self.assertIn("command -v mount.cifs >/dev/null 2>&1 || return 1",
                      script)
        self.assertIn(STORAGE_PROBE_ROOT, script)
        # The measured login duration is reported as a token-scoped data
        # marker the gate-8 drive records as evidence.  One emitter renders
        # every such marker, so the prefix is asserted on the emitter and the
        # field name on the call.
        self.assertIn(
            "printf '__TELOS_ARCH_%s_%s=%s\\n' \"$1\" \"$token\" \"$2\"",
            script)
        self.assertIn('data STORAGE_LOGIN_SECONDS "$elapsed"', script)
        self.assertEqual(
            STORAGE_LOGIN_SECONDS_MARKER, "__TELOS_ARCH_STORAGE_LOGIN_SECONDS_")
        # The login bound comes from the identity-lifecycle contract.
        contract = json.loads(
            (Path(__file__).resolve().parents[1] / "workstations"
             / "identity_lifecycle.json").read_text(encoding="utf-8"))
        self.assertIn(
            f"LOGIN_BOUND_SECONDS='{contract['login_bound_seconds']}'",
            script)

    def test_storage_denial_first_proves_the_own_share_mounts(self):
        # A broken mount path must never masquerade as authorization denial:
        # the denial check first mounts the caller's own share.
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        denial = script.split("check_arch_storage_denied()")[1].split(
            "check_arch_storage_absent_login()")[0]
        own = denial.index('storage_mount "$DAILY_ADMIN" "$DAILY_ADMIN" || {')
        foreign = denial.index(
            'if storage_mount "$STANDARD_USER" "$DAILY_ADMIN"; then')
        self.assertLess(own, foreign)
        # The own-share failure diagnoses rather than returning silently: a
        # Kerberos fault refuses every share alike and must not be mistaken for
        # the authorization denial this check exists to prove.
        self.assertIn('storage_diagnose "$DAILY_ADMIN" "$DAILY_ADMIN"', denial)

    def test_optional_storage_attach_is_never_login_blocking(self):
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        fstab_lines = [
            line for line in script.splitlines()
            if " cifs " in line and line.startswith("//")
        ]
        self.assertEqual(len(fstab_lines), 1)
        line = fstab_lines[0]
        device, mountpoint, fstype, options = line.split()[:4]
        # The share belongs to whichever principal the resolved roster names as
        # the standard user (under setUpModule's pin, the synthetic one).
        standard = identity_roster()["standard_user"]
        self.assertEqual(
            device, f"//{STORAGE_HOST_LABEL}.{SYNTHETIC_DOMAIN}/{standard}")
        self.assertEqual(mountpoint, f"{STORAGE_MOUNT_ROOT}/{standard}")
        self.assertEqual(fstype, "cifs")
        flags = options.split(",")
        # Structural login independence: the systemd fstab generator can
        # only emit a Wants= automount with a bounded attach.
        for flag in ("nofail", "x-systemd.automount", "_netdev", "soft",
                     "x-systemd.mount-timeout=10s", "sec=krb5"):
            self.assertIn(flag, flags)
        self.assertIn(
            f"mkdir -p /mnt{STORAGE_MOUNT_ROOT}/{standard}", script)
        # No hard dependency shapes: nothing may require, order after, or
        # boot-block on the optional storage.
        self.assertNotIn("x-systemd.requires", script)
        self.assertNotIn("x-systemd.before", script)
        self.assertNotIn("RequiresMountsFor", script)
        for line in script.splitlines():
            if "systemctl enable" in line:
                self.assertNotIn(".mount", line)
                self.assertNotIn(".automount", line)
        # The probe proves the same structure at acceptance time.
        self.assertIn("fstab_never_blocks_login", script)
        self.assertIn(
            "systemctl list-unit-files --state=enabled --no-legend", script)

    def test_sssd_bounds_its_own_return_to_online(self):
        # The 2026-08-14 live run measured SSSD's default recovery schedule:
        # the Controller returned at t+27.3s, the backend went Online near
        # t+96s, and arch-identity-restored -- whose only subject is recovery --
        # gave up at t+89.1s after its full bounded wait.  sssd.conf(5) in the
        # shipped sssd-2.13.1-1 states the arithmetic (60 / 3600 / 30 defaults,
        # doubling per failed attempt), so the first retry alone lands 60-90s
        # out and every further failure doubles it.  Chasing that with a longer
        # probe bound would chase a doubling number; the configuration states
        # the bound instead, and the man page's own "at least 4 times
        # offline_timeout" ratio is respected.
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        self.assertIn("offline_timeout = 5", script)
        self.assertIn("offline_timeout_max = 20", script)
        self.assertIn("offline_timeout_random_offset = 0", script)
        # The bound must be reachable inside the probe's own wait, or the
        # configuration and the check would still disagree.
        self.assertLess(20, PROBE_DOMAIN_WAIT_TRIES * JOIN_WAIT_SECONDS)

    def test_identity_restored_waits_out_the_negative_cache(self):
        # arch-uncached-denied runs moments earlier and its whole subject is
        # that this principal does NOT resolve while the Controller is down, so
        # nss_sss has just cached the miss (entry_negative_timeout, 15s by
        # default).  An unretried lookup inside that window would report "the
        # directory never came back" when it saw only its own negative cache.
        # The retry is bounded and the lookup still has to succeed.
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        body = script.split("check_arch_identity_restored()")[1].split(
            "\n}\n")[0]
        self.assertIn("await_domain_state Online", body)
        self.assertIn('for _ in $(seq 1 "$LOOKUP_WAIT_TRIES"); do', body)
        self.assertIn(
            'getent passwd "$DOMAIN_ADMIN" >/dev/null 2>&1 && return 0', body)
        self.assertIn(f"sleep {JOIN_WAIT_SECONDS}", body)
        self.assertIn(f"LOOKUP_WAIT_TRIES='{PROBE_LOOKUP_WAIT_TRIES}'", script)
        # Long enough to outlast the 15s nss negative-cache default, and
        # deliberately shorter than the domain-state wait it follows.
        self.assertGreater(PROBE_LOOKUP_WAIT_TRIES * JOIN_WAIT_SECONDS, 15)
        self.assertLess(PROBE_LOOKUP_WAIT_TRIES, PROBE_DOMAIN_WAIT_TRIES)
        # Fail-closed: the loop's only exit without a successful lookup is a
        # diagnosed failure.
        self.assertIn("return 1", body)
        self.assertIn("note_domain_state", body)

    def test_storage_attached_proves_a_round_trip_and_measures_it(self):
        # Gate 9's contract for this check is a round trip -- "create, read,
        # and remove a test file", passing only when the contents survive --
        # and the gate-9 row additionally requires UID/GID and timestamp
        # measurements, which the probe did not emit before.
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        body = script.split("check_arch_storage_attached()")[1].split(
            "check_arch_storage_denied()")[0]
        self.assertIn('probe_file="$mount_point/.telos-storage-probe.$$"', body)
        self.assertIn('printf \'%s\\n\' "$written" > "$probe_file"', body)
        self.assertIn('[ "$(cat "$probe_file" 2>/dev/null)" = "$written" ]',
                      body)
        self.assertIn('rm -f "$probe_file"', body)
        for guard in ('[ "$roundtrip" = 1 ] || return 1',
                      '[ "$removed" = 1 ] || return 1'):
            self.assertIn(guard, body)
        # The identifiers come from the directory's resolution of the mounting
        # principal, never from stat on the mount: cifs reports the mount's own
        # uid= option for every inode when the server sends no POSIX ownership,
        # so a stat there would only echo what the mount was told.
        self.assertIn('owner_uid=$(id -u "$DAILY_ADMIN" 2>/dev/null)', body)
        self.assertIn('owner_gid=$(id -g "$DAILY_ADMIN" 2>/dev/null)', body)
        self.assertIn('file_mtime=$(stat -c %Y "$probe_file" 2>/dev/null)',
                      body)
        # Unprovable means FAIL: a non-integer measurement is refused rather
        # than printed, so the drive can never record a fabricated field.
        for name in ("owner_uid", "owner_gid", "file_mtime"):
            self.assertIn(
                f"printf '%s' \"${name}\" | grep -Eq '^[0-9]+$' || return 1",
                body)
        # Every measured field the drive requires is printed under its own
        # token-scoped marker before the verdict.
        for field, marker in STORAGE_ATTACHED_MEASUREMENT_MARKERS.items():
            self.assertTrue(marker.startswith("__TELOS_ARCH_"))
            self.assertTrue(marker.endswith("_"))
            emitter = marker[len("__TELOS_ARCH_"):-1]
            self.assertIn(f'data {emitter} "${field}"', body)

    def test_storage_failures_name_their_layer_on_the_console(self):
        # -ENOKEY (the -126 the 2026-08-14 run recorded) is the kernel's answer
        # to EVERY cifs.spnego upcall failure, so the verdict alone cannot
        # separate "no ticket" from "the KDC does not know this service
        # principal" from "the server rejected the key".  kvno asks this KDC
        # for exactly the principal mount.cifs asks for, which is the field
        # that settles it.  Bounded, and only on the failure path.
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        self.assertIn(f"STORAGE_MOUNT_ERROR='{STORAGE_MOUNT_ERROR_PATH}'",
                      script)
        # The mount's own stderr is kept, not discarded.
        self.assertIn('2>"$STORAGE_MOUNT_ERROR"', script)
        diagnose = script.split("storage_diagnose() {")[1].split("\n}\n")[0]
        self.assertIn('note mount-error cat "$STORAGE_MOUNT_ERROR"', diagnose)
        self.assertIn('note ticket runuser -u "$2" -- klist', diagnose)
        self.assertIn(
            'note service-ticket runuser -u "$2" -- kvno "cifs/$STORAGE_HOST"',
            diagnose)
        # The emitter shares the boot gate's bound, column cap and wording, so
        # a diagnostic can never hang in place of the failure it explains.
        note = script.split("note() {")[1].split("\n}\n")[0]
        self.assertIn(f"timeout {DIAGNOSTIC_COMMAND_SECONDS}", note)
        self.assertIn(f"cut -c1-{DIAGNOSTIC_LINE_COLUMNS}", note)
        self.assertIn(DIAGNOSTIC_EMPTY_FIELD, note)
        self.assertIn(STORAGE_DIAGNOSTIC_MARKER, note)
        # The error file must not live under the mount tree, where a successful
        # mount would hide it.
        self.assertFalse(
            STORAGE_MOUNT_ERROR_PATH.startswith(STORAGE_PROBE_ROOT + "/"))

    def test_workstation_contract_supplies_mount_cifs_for_the_probe(self):
        # cifs-utils owns /usr/bin/mount.cifs; the workstation closure carries
        # it so the storage probes can mount, and the probe still guards
        # command -v mount.cifs so an image built without it fails closed
        # instead of erroring mid-check.
        required = merge_contract(
            load_registry(
                Path(__file__).resolve().parents[1] / "package-contract.json"
            ),
            PROFILE_OVERLAYS["workstation-install"],
        ).packages
        self.assertIn("cifs-utils", required)

    def test_menu_titles_are_the_live_calibrated_exports(self):
        # Gate 10 keys on these exact rendered titles (live boot-1 serial,
        # 2026-08-11): the authored config entry and systemd-boot's
        # auto-detected Windows title.  The loader entry uses the export so
        # installer and acceptance runner cannot drift.
        self.assertEqual("Arch Linux LTS", MENU_ARCH_TITLE)
        self.assertEqual("Windows 11", MENU_WINDOWS_TITLE)
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        self.assertIn(f"title {MENU_ARCH_TITLE}\n", script)

    def _nvram_block(self):
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        return script, script.split(
            "UEFI NVRAM boot entries (gate-10 five-second-menu contract)")[1]

    def test_nvram_entries_are_authored_linux_first(self):
        script, block = self._nvram_block()
        # Both managed entries are created against the verified disk and the
        # ESP partition number derived from the proven $ESP_PART assignment.
        self.assertIn(
            f"efibootmgr -c -d \"$disk\" -p \"$esp_number\" "
            f"-L '{NVRAM_LINUX_LABEL}' \\\n  -l '{NVRAM_LINUX_LOADER}'",
            block)
        self.assertIn(
            f"efibootmgr -c -d \"$disk\" -p \"$esp_number\" "
            f"-L '{NVRAM_WINDOWS_LABEL}' \\\n  -l '{NVRAM_WINDOWS_LOADER}' "
            f"\\\n  -@ /run/telos-nvram-windows.optdata",
            block)
        # The loader paths point at exactly the ESP files the install proved.
        self.assertEqual(
            NVRAM_LINUX_LOADER.replace("\\", "/"),
            "/EFI/systemd/systemd-bootx64.efi")
        self.assertEqual(
            NVRAM_WINDOWS_LOADER.replace("\\", "/"),
            "/EFI/Microsoft/Boot/bootmgfw.efi")
        # BootOrder is Linux, then Windows, then surviving unmanaged entries.
        self.assertIn('order="$linux_entry,$windows_entry"', block)
        self.assertIn('efibootmgr -o "$order"', block)
        self.assertIn('order="$order,$number"', block)

    def test_nvram_authoring_is_idempotent(self):
        _script, block = self._nvram_block()
        # Pre-existing entries carrying the managed labels are deleted before
        # replacements are created, so a re-run never accumulates duplicates,
        # and the surviving order is captured only after those deletions.
        delete = block.index('efibootmgr -b "$number" -B')
        capture = block.index("previous_order=$(efibootmgr")
        create = block.index("efibootmgr -c ")
        self.assertLess(delete, capture)
        self.assertLess(capture, create)
        self.assertIn(
            f"for label in '{NVRAM_WINDOWS_LABEL}' '{NVRAM_LINUX_LABEL}'; do",
            block)
        # Exactly-once verification precedes the entries marker.
        self.assertIn(
            "NVRAM boot entries were not authored exactly once", block)

    def test_nvram_authoring_fails_closed_without_efivarfs(self):
        _script, block = self._nvram_block()
        # Every guard (present, mounted, tool available, ESP number derived)
        # exits nonzero BEFORE any efibootmgr mutation.
        first_mutation = block.index("efibootmgr -b")
        for guard in (
            "[[ -d /sys/firmware/efi/efivars ]] || {",
            "mountpoint -q /sys/firmware/efi/efivars || {",
            "command -v efibootmgr >/dev/null || {",
            '[[ "$esp_number" =~ ^[0-9]+$ ]] || {',
        ):
            with self.subTest(guard=guard):
                self.assertIn(guard, block)
                self.assertLess(block.index(guard), first_mutation)
        self.assertEqual(4, block.count("exit 1\n}", 0, first_mutation))

    def test_windows_entry_carries_the_windows_optional_data(self):
        # Windows Boot Manager adopts a pre-created entry only when it
        # carries the WINDOWS/BCDOBJECT optional-data blob (live-proven
        # 2026-08-11: identical device path without the blob was treated as
        # foreign, Windows recreated its entry and self-promoted, and the
        # second cold boot lost the menu).  The constant must be exactly
        # the recorded 136-byte blob referencing the fixed {bootmgr} GUID.
        blob = NVRAM_WINDOWS_OPTIONAL_DATA
        self.assertEqual(136, len(blob))
        self.assertTrue(blob.startswith(b"WINDOWS\x00"))
        self.assertEqual(len(blob), struct.unpack_from("<I", blob, 12)[0])
        self.assertIn(
            "BCDOBJECT={9dea862c-5cdd-4e70-acc1-f32b344d4795}".encode(
                "utf-16-le"),
            blob)
        script, block = self._nvram_block()
        # The blob travels base64 inside the heredoc-delivered script, is
        # size-verified before use (fail-closed), feeds only the Windows
        # entry, and is removed afterwards.
        encoded = base64.b64encode(blob).decode("ascii")
        self.assertIn(f"printf '%s' '{encoded}' | base64 -d", block)
        self.assertIn(
            "Windows NVRAM optional data failed to decode", block)
        self.assertIn(f"-eq \\\n    {len(blob)} ]]", block)
        self.assertEqual(1, block.count("-@ /run/telos-nvram-windows.optdata"))
        self.assertIn("rm -f /run/telos-nvram-windows.optdata", block)
        decode = block.index("| base64 -d")
        create = block.index("-@ /run/telos-nvram-windows.optdata")
        cleanup = block.index("rm -f /run/telos-nvram-windows.optdata")
        self.assertLess(decode, create)
        self.assertLess(create, cleanup)
        # The Linux entry stays blob-free.
        linux_create = block.index(f"-L '{NVRAM_LINUX_LABEL}'")
        self.assertNotIn(
            "-@", block[linux_create:block.index(f"-l '{NVRAM_LINUX_LOADER}'")])

    def test_nvram_markers_print_only_after_verification(self):
        script, block = self._nvram_block()
        # The markers are script-emitted (heredoc-delivered), never part of a
        # dispatched echo, and each prints only after its verification: the
        # entries marker after the exactly-once check, the order marker after
        # the re-read BootOrder grep.
        entries_marker = block.index(f'echo "{NVRAM_ENTRIES_MARKER}"')
        order_marker = block.index(f'echo "{NVRAM_ORDER_MARKER}"')
        self.assertLess(
            block.index("NVRAM boot entries were not authored exactly once"),
            entries_marker)
        self.assertLess(entries_marker, order_marker)
        self.assertLess(
            block.index("NVRAM boot order verification failed"), order_marker)
        # The order verification re-reads efibootmgr output, and drains the
        # pipe (no grep -q) so pipefail cannot turn success into SIGPIPE.
        verify = block.index('efibootmgr | grep "^BootOrder: $order\\$"')
        self.assertLess(block.index('efibootmgr -o "$order"'), verify)
        self.assertLess(verify, order_marker)
        self.assertEqual(1, script.count(NVRAM_ENTRIES_MARKER))
        self.assertEqual(1, script.count(NVRAM_ORDER_MARKER))

    # ---- Boot-time one-shot re-join (gate-8 in-run join contract) ----

    def test_install_and_boot_join_share_one_media_stage(self):
        # Reuse, not a near-duplicate: the one-use media consumption is
        # rendered once and appears verbatim in both the install-time join and
        # the boot-time join script, so the two can never drift apart.
        stage = _render_join_media_stage(JOIN_MEDIA_LABEL)
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        self.assertEqual(script.count(stage), 2)
        # The install-time join gate-7 acceptance proves is untouched.
        self.assertIn(
            "arch-chroot /mnt net ads join -A /run/telos-join/credentials",
            script)

    def test_boot_time_join_unit_is_installed_and_enabled(self):
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        # Root-only script, world-readable unit, enabled at install time.
        self.assertIn(
            f"install -Dm0700 /dev/stdin /mnt{JOIN_ONCE_SCRIPT_PATH}", script)
        self.assertIn(
            f"install -Dm0644 /dev/stdin /mnt{JOIN_ONCE_UNIT_PATH}", script)
        self.assertIn(
            f"arch-chroot /mnt systemctl enable {JOIN_ONCE_UNIT_NAME}", script)
        unit = _heredoc_body(script, "TELOS_JOIN_UNIT_EOF")
        self.assertIn("Type=oneshot", unit)
        self.assertIn("RemainAfterExit=no", unit)
        self.assertIn("After=network-online.target", unit)
        self.assertIn(f"ExecStart={JOIN_ONCE_SCRIPT_PATH}", unit)
        self.assertIn("WantedBy=multi-user.target", unit)
        # The ordering is the login-readiness proof: sssd must not start
        # against the previous run's domain SID, and serial-getty@ttyS0 is
        # After=systemd-user-sessions.service, so ordering before user
        # sessions is what keeps the login prompt behind the finished join.
        self.assertEqual(JOIN_ONCE_BEFORE_UNITS,
                         ("sssd.service", "systemd-user-sessions.service"))
        self.assertIn(
            "Before=" + " ".join(JOIN_ONCE_BEFORE_UNITS), unit)

    def test_boot_time_join_fails_closed_and_orders_its_proofs(self):
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        body = _heredoc_body(script, "TELOS_JOIN_ONCE_EOF")
        self.assertIn("set -euo pipefail", body)
        # The media wait is bounded and its absence is a hard failure, never
        # a silent skip that would let the login be blamed instead.
        self.assertIn(f"for _ in $(seq 1 {JOIN_WAIT_TRIES}); do", body)
        self.assertIn(f"sleep {JOIN_WAIT_SECONDS}", body)
        self.assertIn(
            '[[ -e "$join_dev" ]] || { echo "join credential media is '
            'absent" >&2; exit 1; }', body)
        # A failure on any path still removes the tmpfs credential.
        self.assertIn("trap 'rm -rf /run/telos-join' EXIT", body)
        consumed = (
            f"printf '%s\\n' '{JOIN_MEDIA_CONSUMED_MARKER}' > /dev/console")
        verified = f"printf '%s\\n' '{JOIN_VERIFIED_MARKER}' > /dev/console"
        ordered = [
            body.index('mount -o ro "$join_dev" /run/telos-join/media'),
            body.index("umount /run/telos-join/media"),
            body.index(consumed),
            body.index(f"rm -f {HOST_KEYTAB_PATH}"),
            body.index("net ads join -A /run/telos-join/credentials"),
            body.index("net ads testjoin"),
            body.index("rm -rf /run/telos-join\n"),
            body.index(verified),
            body.index(f"rm -f {SSSD_CACHE_GLOB}"),
        ]
        self.assertEqual(ordered, sorted(ordered))
        # Each marker is printed exactly once from the guest's own script.
        self.assertEqual(body.count(consumed), 1)
        self.assertEqual(body.count(verified), 1)

    def test_boot_time_join_leaves_no_previous_domains_keytab_behind(self):
        # The install-time join wrote the host keytab against a DIFFERENT domain
        # -- different SID, different krbtgt, different machine password -- and
        # Samba refreshes a keytab per principal and key version rather than
        # replacing the file.  A fresh provision can hand this machine the same
        # key version number as the domain it replaced, and then the stale keys
        # are indistinguishable from the live ones inside the very file SSSD's
        # ldap_child binds with.  Same reason the SSSD cache below is wiped
        # rather than restarted: this run's join is the only thing in it.
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        body = _heredoc_body(script, "TELOS_JOIN_ONCE_EOF")
        self.assertIn(f"rm -f {HOST_KEYTAB_PATH}", body)
        # Removed BEFORE the join, so the join is what recreates it, and the
        # join stays the fail-closed gate: a keytab that did not come back
        # leaves testjoin failing rather than a silent success.
        self.assertLess(body.index(f"rm -f {HOST_KEYTAB_PATH}"),
                        body.index("\nnet ads join -A "))
        # `kerberos method = secrets and keytab` is what makes the join write it,
        # and it is the same smb.conf the install-time join used on a disk that
        # had no keytab at all -- which is the proof that removal is safe.
        self.assertIn("kerberos method = secrets and keytab",
                      _heredoc_body(script, "TELOS_SMB_EOF"))

    def test_boot_join_script_and_unit_carry_no_credential(self):
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        unit = _heredoc_body(script, "TELOS_JOIN_UNIT_EOF")
        body = _heredoc_body(script, "TELOS_JOIN_ONCE_EOF")
        # The unit names only the script; it never touches a secret, so it is
        # safe as a mode-0644 file on the installed disk.
        self.assertNotRegex(unit, r"(?i)password|secret|credential")
        # The script's only credential path is the mode-0600 tmpfs file.
        self.assertEqual(
            set(re.findall(r"\S*/credentials\b", body)),
            {"/run/telos-join/credentials"})
        allowed = (
            'values["password"]',
            '"password = " + password',
            "(username, password)",
        )
        for line in body.splitlines():
            if "password" in line and not line.lstrip().startswith("#"):
                self.assertTrue(
                    any(marker in line for marker in allowed),
                    f"unexpected password reference: {line!r}")
        # No literal of either shape the runner generates can be present.
        self.assertNotIn("Synthetic-Join-", script)
        self.assertNotRegex(script, r"\btj-[0-9a-f]{16}\b")

    # ---- Boot-time domain-online gate (gate-8 login-readiness contract) ----

    def _rendered(self) -> str:
        return render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )

    def test_domain_online_unit_is_installed_and_enabled(self):
        script = self._rendered()
        # Root-only script, world-readable unit, enabled at install time --
        # the same shape as the one-shot join it follows.
        self.assertIn(
            f"install -Dm0700 /dev/stdin /mnt{DOMAIN_ONLINE_SCRIPT_PATH}",
            script)
        self.assertIn(
            f"install -Dm0644 /dev/stdin /mnt{DOMAIN_ONLINE_UNIT_PATH}",
            script)
        self.assertIn(
            f"arch-chroot /mnt systemctl enable {DOMAIN_ONLINE_UNIT_NAME}",
            script)
        unit = _heredoc_body(script, "TELOS_DOMAIN_UNIT_EOF")
        self.assertIn("Type=oneshot", unit)
        self.assertIn("RemainAfterExit=no", unit)
        self.assertIn(f"ExecStart={DOMAIN_ONLINE_SCRIPT_PATH}", unit)
        self.assertIn("WantedBy=multi-user.target", unit)

    def test_domain_online_ordering_is_exactly_as_designed(self):
        # sssd.service reaching active only means its responders answered
        # READY=1; the AD backend connects afterwards.  So this unit orders
        # AFTER sssd (the join unit orders before it) and BEFORE user sessions,
        # which is what holds serial-getty@ttyS0 -- itself
        # After=systemd-user-sessions.service -- behind a usable domain.
        self.assertEqual(DOMAIN_ONLINE_AFTER_UNITS, ("sssd.service",))
        self.assertEqual(
            DOMAIN_ONLINE_BEFORE_UNITS, ("systemd-user-sessions.service",))
        unit = _heredoc_body(self._rendered(), "TELOS_DOMAIN_UNIT_EOF")
        self.assertIn("After=" + " ".join(DOMAIN_ONLINE_AFTER_UNITS), unit)
        self.assertIn("Requires=" + " ".join(DOMAIN_ONLINE_AFTER_UNITS), unit)
        self.assertIn("Before=" + " ".join(DOMAIN_ONLINE_BEFORE_UNITS), unit)
        # The join unit runs before sssd and this gate after it, so the two
        # form a chain rather than a race.
        self.assertIn("sssd.service", JOIN_ONCE_BEFORE_UNITS)
        # No ordering edge is added against nss-user-lookup.target: sssd
        # already declares Before= both it and systemd-user-sessions, and
        # other units (systemd-logind) order AFTER that target, so a new edge
        # there is exactly how an ordering cycle -- and a silently dropped
        # systemd job -- would be introduced.
        directives = [
            line for line in unit.splitlines()
            if line.startswith(
                ("After=", "Before=", "Requires=", "Wants=", "BindsTo="))]
        self.assertEqual(len(directives), 3)
        for line in directives:
            self.assertNotIn("nss-user-lookup.target", line)

    def test_domain_online_gate_fails_closed_on_timeout(self):
        body = _heredoc_body(self._rendered(), "TELOS_DOMAIN_ONLINE_EOF")
        # Both waits are bounded with the installer's 60 x 2s idiom.
        self.assertEqual(
            body.count(f"sleep {JOIN_WAIT_SECONDS}\n"), 2)
        self.assertIn(f"DOMAIN_WAIT_TRIES='{JOIN_WAIT_TRIES}'", body)
        self.assertIn(f"for _ in $(seq 1 {JOIN_WAIT_TRIES}); do", body)
        # Each timeout ends the unit non-zero with its own secret-free reason,
        # so the boot reports where it stopped instead of presenting a login
        # prompt nothing can log in to.
        self.assertIn("exit 1", body)
        reasons = re.findall(r"fail '([^']+)'", body)
        self.assertEqual(len(reasons), 2)
        self.assertEqual(len(set(reasons)), 2)
        # Order is load-bearing: the principal lookup is what pam_sss needs, so
        # it is waited on first and the narrower sssctl check follows.  Reaching
        # the second failure with the first already satisfied isolates an
        # InfoPipe fault from an identity fault.
        self.assertIn("never resolved", reasons[0])
        self.assertIn("Online", reasons[1])
        # The success marker prints only after BOTH waits converged.
        ordered = [
            body.index('[ "$resolved" -eq 1 ] ||'),
            body.index("await_domain_state Online ||"),
            body.index(f"printf '%s\\n' '{DOMAIN_ONLINE_MARKER}'"),
        ]
        self.assertEqual(ordered, sorted(ordered))

    def test_domain_online_markers_are_secret_free_constants(self):
        script = self._rendered()
        body = _heredoc_body(script, "TELOS_DOMAIN_ONLINE_EOF")
        unit = _heredoc_body(script, "TELOS_DOMAIN_UNIT_EOF")
        # Both markers come from module constants and print exactly once each,
        # from the guest's own script -- never from a dispatched echo.
        self.assertEqual(
            body.count(f"printf '%s\\n' '{DOMAIN_ONLINE_MARKER}' "
                       "> /dev/console"), 1)
        self.assertEqual(
            body.count(f"printf '%s: %s\\n' '{DOMAIN_ONLINE_FAILURE_MARKER}' "
                       '"$1" > /dev/console'), 1)
        self.assertEqual(script.count(DOMAIN_ONLINE_MARKER), 1)
        # Neither marker is a prefix of the other, so the runner's bounded
        # wait for success can never match a failure line.
        self.assertFalse(
            DOMAIN_ONLINE_FAILURE_MARKER.startswith(DOMAIN_ONLINE_MARKER))
        self.assertFalse(
            DOMAIN_ONLINE_MARKER.startswith(DOMAIN_ONLINE_FAILURE_MARKER))
        # The gate never reads, holds, or names a credential: it authenticates
        # nothing, it only observes SSSD.  Judged on executable lines, since
        # the comments explain exactly that property.
        for text in (body, unit):
            self.assertNotIn("/run/telos-join", text)
            for line in text.splitlines():
                if line.lstrip().startswith("#") or not line.strip():
                    continue
                self.assertNotRegex(
                    line, r"(?i)password|secret|credential",
                    f"unexpected credential reference: {line!r}")

    def test_probe_and_domain_gate_share_one_domain_state_implementation(self):
        # Reuse, not a near-duplicate: "online" is defined once on the disk and
        # rendered verbatim into both the acceptance probe and the boot gate.
        script = self._rendered()
        self.assertEqual(script.count(_DOMAIN_STATE_FUNCTIONS), 2)
        probe = _heredoc_body(script, "TELOS_PROBE_EOF")
        gate = _heredoc_body(script, "TELOS_DOMAIN_ONLINE_EOF")
        for body in (probe, gate):
            self.assertIn(_DOMAIN_STATE_FUNCTIONS, body)
        # Each caller supplies its own bound: the probe keeps its 30 x 2s (a
        # 60-try wait would outlive gate 8's own per-probe console bound),
        # the boot gate uses the installer idiom.
        self.assertIn(f"DOMAIN_WAIT_TRIES='{PROBE_DOMAIN_WAIT_TRIES}'", probe)
        self.assertIn(f"DOMAIN_WAIT_TRIES='{JOIN_WAIT_TRIES}'", gate)
        self.assertNotEqual(PROBE_DOMAIN_WAIT_TRIES, JOIN_WAIT_TRIES)

    def test_sssd_declares_the_ifp_responder_sssctl_needs(self):
        # Every Online wait on this disk goes through `sssctl domain-status`,
        # which answers over the InfoPipe responder only.  Without ifp in
        # services, sssctl reports "InfoPipe operation failed" and nine of the
        # eleven lifecycle checks could only ever fail closed -- for a reason
        # that has nothing to do with identity.
        self.assertEqual(SSSD_SERVICES, ("nss", "pam", "ifp"))
        script = self._rendered()
        sssd_conf = _heredoc_body(script, "TELOS_SSSD_EOF")
        self.assertIn("services = nss, pam, ifp", sssd_conf)
        self.assertIn('sssctl domain-status "$DOMAIN"', script)

    # ---- Samba-AD interop in sssd.conf (gate-8 identity contract) ----

    def test_sssd_never_asks_the_global_catalog_for_posix_ids(self):
        # Directory-stored ids (ldap_id_mapping = False, ADR 0055) mean every
        # user lookup must return uidNumber and gidNumber, and SSSD asks the AD
        # Global Catalog on port 3268 FIRST by default.  The AD schema Samba
        # ships defines UidNumber and GidNumber without
        # isMemberOfPartialAttributeSet -- not replicated to the Global Catalog
        # -- so a GC answer can never carry a POSIX identity.  SSSD 2.13 detects
        # that itself, but only inside its subdomain refresh, which a first
        # lookup can beat and Samba's incomplete Global Catalog can fail
        # outright.  So it is stated, not raced.
        sssd_conf = _heredoc_body(self._rendered(), "TELOS_SSSD_EOF")
        self.assertIn("\nldap_id_mapping = False\n", sssd_conf)
        self.assertIn("\nad_enable_gc = False\n", sssd_conf)
        # And the reason travels with the option, because a bare "False" reads
        # like a tuning knob somebody may helpfully remove.
        self.assertIn("isMemberOfPartialAttributeSet", sssd_conf)

    def test_sssd_never_lets_gpo_retrieval_deny_every_login(self):
        # access_provider = ad defaults ad_gpo_access_control to enforcing,
        # which makes every login depend on fetching GPOs from SYSVOL over SMB.
        # gpo_child performs that fetch and must read the host keytab, yet
        # Arch's sssd runs as User=sssd and grants cap_dac_read_search to
        # ldap_child, krb5_child and sssd_pam only -- while net ads join writes
        # the keytab mode 0600 root:root.  Enforcing mode would therefore deny
        # every login for a reason unrelated to identity.
        sssd_conf = _heredoc_body(self._rendered(), "TELOS_SSSD_EOF")
        self.assertIn("\naccess_provider = ad\n", sssd_conf)
        self.assertIn("\nad_gpo_access_control = permissive\n", sssd_conf)
        # Permissive, not disabled: the evaluation and SSSD's syslog warning
        # survive, so a future GPO regime can be switched back on knowingly.
        self.assertNotIn("ad_gpo_access_control = disabled", sssd_conf)
        self.assertIn("gpo_child", sssd_conf)

    def test_sssd_pins_the_domain_controller_instead_of_discovering_it(self):
        # The gate-8 asymmetry of 2026-08-14, stated as configuration: SSSD's AD
        # provider can locate a controller ONLY by DNS SRV lookup, while Samba's
        # `net ads` also falls back to a NetBIOS <1C> broadcast that this flat
        # simulated segment floods.  So `net ads join` verified in eight seconds
        # and read the operator out of the directory complete with uidNumber,
        # while SSSD sat Offline for two minutes reporting "AD Domain
        # Controller: not connected".  A join that verifies proves nothing about
        # SSSD's discovery, and this fabric has exactly one controller whose
        # name the factory already knows.
        sssd_conf = _heredoc_body(self._rendered(), "TELOS_SSSD_EOF")
        self.assertIn(
            f"\nad_server = {CONTROLLER_HOSTNAME}.{SYNTHETIC_DOMAIN}\n",
            sssd_conf)
        # The NAME, never CONTROLLER_ADDRESS: libsss_ad warns "ad_server [%s] is
        # detected as IP address, this can cause GSSAPI/GSS-SPNEGO problems",
        # because the SASL bind needs a principal to ask the KDC for.
        self.assertNotIn(f"ad_server = {CONTROLLER_ADDRESS}", sssd_conf)
        # And the reason travels with the option: a bare hostname reads like a
        # convenience somebody may helpfully replace with discovery again.
        self.assertIn("service discovery", sssd_conf)
        self.assertIn("GSS-SPNEGO", sssd_conf)

    def test_sssd_states_this_machines_own_fully_qualified_name(self):
        # /etc/hostname carries the short name, so without ad_hostname SSSD
        # calls gethostname() and then has to expand what it gets by resolving
        # it back -- which depends on an A record `net ads join` may or may not
        # have registered, and which nothing in this project verifies.
        # sssd-ad(5): ad_hostname "must match the hostname for which the keytab
        # was issued", and net ads join issues host/<short>.<domain>.
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="telos-ws1", expected_sizes_mib=SIZES,
        )
        sssd_conf = _heredoc_body(script, "TELOS_SSSD_EOF")
        self.assertIn(f"\nad_hostname = telos-ws1.{SYNTHETIC_DOMAIN}\n",
                      sssd_conf)
        # It tracks the argument, so a differently named machine cannot inherit
        # another machine's principal.
        self.assertNotIn("ad_hostname = workstation.", sssd_conf)

    def test_sssd_does_not_pin_the_bind_principal_it_reads_from_the_keytab(self):
        # A standing invitation to a wrong fix, so it is pinned in both files.
        # The 2026-08-14 keytab carried `HOST/TELOS-WS1.ad.factory.test` in
        # UPPERCASE while ad_hostname is lowercase, which reads like a
        # case-sensitive Kerberos mismatch and is not one: SSSD does not bind as
        # ad_hostname.  libsss_ad hands it to sdap_set_sasl_options, which forks
        # ldap_child to run select_principal_from_keytab, whose second pattern
        # ("%S$") uppercases the short hostname and appends "$" -- so the bind
        # principal comes back OUT of the keytab as the machine account, and its
        # case can never disagree.  Pinning ldap_sasl_authid to the FQDN would
        # only add "Configured SASL auth ID not found in keytab" before SSSD
        # used that same principal anyway.
        sssd_conf = _heredoc_body(self._rendered(), "TELOS_SSSD_EOF")
        template = SSSD_TEMPLATE.read_text(encoding="utf-8")
        for text in (sssd_conf, template):
            with self.subTest(text=text[:40]):
                self.assertNotRegex(text, r"(?m)^ldap_sasl_authid")
                # And the reason travels with the absence, in both files, or the
                # next reader re-derives the keytab-case theory from scratch.
                self.assertIn("ldap_sasl_authid", text)
                self.assertIn("%S$", text)

    def test_sssd_config_carries_only_options_this_sssd_accepts(self):
        # `sssctl config-check` is printed verbatim by the boot-time gate, so a
        # config that always produces findings makes that field unreadable.  The
        # 2026-08-14 transcript reported two, and both were real:
        # config_file_version does not exist in sssd-2.13.1 (absent from
        # sssd.conf(5) and from the shipped /usr/share/sssd/cfg_rules.ini), and
        # offline_credentials_expiration is a PAM responder option that SSSD
        # silently ignored in [domain/...] -- defeating the entire point of ADR
        # 0071 stating it rather than inheriting it.
        sssd_conf = _heredoc_body(self._rendered(), "TELOS_SSSD_EOF")
        self.assertNotRegex(sssd_conf, r"(?m)^config_file_version")
        sections = re.findall(r"^\[([^\]]+)\]$", sssd_conf, re.M)
        self.assertEqual(
            sections, ["sssd", "pam", f"domain/{SYNTHETIC_DOMAIN}"])
        pam = sssd_conf[sssd_conf.index("\n[pam]\n"):
                        sssd_conf.index(f"\n[domain/{SYNTHETIC_DOMAIN}]\n")]
        self.assertIn("\noffline_credentials_expiration = 0\n", pam)
        # Zero is the decision, not a default that happened to agree with it.
        self.assertIn("ADR 0071", sssd_conf)

    def test_sssd_interop_options_match_the_fleet_template(self):
        # The installer and roles/identity_client deliberately mirror each
        # other; 847c400 already had to repair one drift between them.  Both
        # Samba-AD interop options are load-bearing on real hardware too, so
        # neither file may carry them alone.
        sssd_conf = _heredoc_body(self._rendered(), "TELOS_SSSD_EOF")
        template = SSSD_TEMPLATE.read_text(encoding="utf-8")
        for option in ("ad_enable_gc = False",
                       "ad_gpo_access_control = permissive",
                       "ldap_id_mapping = False",
                       "id_provider = ad",
                       "access_provider = ad"):
            with self.subTest(option=option):
                self.assertIn(f"\n{option}\n", sssd_conf)
                self.assertIn(f"\n{option}\n", template)
        # The discovery pins are the same kind of load-bearing option, and the
        # fleet expresses them through role variables rather than literals: a
        # site with several controllers leaves ad_server empty and keeps SRV
        # discovery, which is why the template guards it.
        self.assertIn(
            "ad_server = {{ homelab_identity_domain_controller }}", template)
        self.assertIn(
            "{% if homelab_identity_domain_controller | length > 0 %}",
            template)
        self.assertIn(
            "ad_hostname = {{ ansible_hostname }}."
            "{{ homelab_identity_domain }}", template)
        # And the two config-check findings are fixed in both files, not one.
        # Matched as an assignment, not a substring: the template names the
        # removed option in a comment on purpose, so a reader cannot re-add it
        # believing it was merely forgotten.
        self.assertNotRegex(template, r"(?m)^config_file_version")
        self.assertLess(
            template.index("[pam]"),
            template.index("offline_credentials_expiration"))
        self.assertLess(
            template.index("offline_credentials_expiration"),
            template.index("[domain/{{ homelab_identity_domain }}]"))

    def test_the_privilege_group_name_has_one_definition(self):
        # The acceptance probe resolves it and the boot gate reports on it, so
        # "domain admins" is spelled once in the module and substituted into
        # both -- a rename cannot leave one of them behind.
        self.assertEqual(DIRECTORY_ADMIN_GROUP, "domain admins")
        self.assertEqual(DIRECTORY_PRIMARY_GROUP, "domain users")
        script = self._rendered()
        probe = _heredoc_body(script, "TELOS_PROBE_EOF")
        gate = _heredoc_body(script, "TELOS_DOMAIN_ONLINE_EOF")
        self.assertIn(f"ADMIN_GROUP='{DIRECTORY_ADMIN_GROUP}'", probe)
        self.assertIn(f"ADMIN_GROUP='{DIRECTORY_ADMIN_GROUP}'", gate)
        self.assertNotIn("@ADMIN_GROUP@", script)
        # vm/controller_principals stages a gidNumber on both groups; with
        # ldap_id_mapping = False a primary group without one makes an
        # otherwise complete user unresolvable, which is why the gate reports
        # the primary group as evidence rather than as decoration.
        self.assertIn(f"PRIMARY_GROUP='{DIRECTORY_PRIMARY_GROUP}'", gate)

    # ---- Gate diagnostics (so the next failure names its own layer) ----

    def test_domain_online_failure_prints_bounded_diagnostics(self):
        # The 2026-08-14 run cost a whole install-plus-boot cycle to learn one
        # sentence.  Every bounded wait that gives up now also prints evidence,
        # and every field is itself bounded: a diagnostic that hung would
        # replace the named failure it exists to explain.
        body = _heredoc_body(self._rendered(), "TELOS_DOMAIN_ONLINE_EOF")
        self.assertIn(
            f'value="$(timeout {DIAGNOSTIC_COMMAND_SECONDS} "$@" 2>&1 |',
            body)
        self.assertIn(f"cut -c1-{DIAGNOSTIC_LINE_COLUMNS})", body)
        self.assertIn(f'"${{value:-{DIAGNOSTIC_EMPTY_FIELD}}}"', body)
        fields = re.findall(r"^ +say ([a-z-]+) ", body, re.M)
        self.assertEqual(fields, [
            "sssd-unit", "sssd-config", "domain-status", "login-principal",
            "primary-group", "admin-group",
            "resolver", "resolver-controller", "resolver-client",
            "discovery-ldap-srv", "discovery-kdc-srv", "discovery-netlogon",
            "host-keytab", "sssd-child-caps", "host-tgt",
            "directory-info", "directory-user", "directory-primary-group",
            "sssd-debug-level", "sssd-log",
        ])
        # The fields whose value is a LIST go through the other emitter, and
        # both emitters exist exactly once.
        self.assertEqual(
            re.findall(r"^ +say_lines ([a-z-]+) ", body, re.M),
            ["keytab-principals", "sssd-log-start", "sssd-log"])
        # The three layers a reader has to be able to separate: SSSD's own
        # view, the local keytab the GSSAPI bind needs, and the directory's
        # answer over LDAP on the DC rather than the Global Catalog.
        self.assertIn(f'klist -k "$HOST_KEYTAB"', body)
        self.assertIn(f"HOST_KEYTAB='{HOST_KEYTAB_PATH}'", body)
        self.assertIn("getcap " + " ".join(SSSD_CHILD_BINARIES), body)
        self.assertIn(
            'net ads search -P "(sAMAccountName=$LOGIN_PRINCIPAL)"', body)
        self.assertIn("uidNumber gidNumber", body)
        # SSSD's own account of it, at a level that records decisions and
        # filters, with a bounded tail.
        self.assertIn(f"debug_level='{DIAGNOSTIC_SSSD_DEBUG_LEVEL}'", body)
        self.assertIn(f"tail -n {DIAGNOSTIC_SSSD_LOG_LINES}", body)
        self.assertIn(f"{DIAGNOSTIC_SSSD_LOG_DIR}/sssd_", body)
        # The log tail and the "no log to read" fallback share one field name,
        # so a reader greps one field either way.  Both emitters print under the
        # field name they were given and nothing else.
        self.assertIn('"$field" \\\n        "$entry" > /dev/console', body)
        self.assertIn(f"say sssd-log ls -l '{DIAGNOSTIC_SSSD_LOG_DIR}'", body)

    def test_diagnostics_name_the_resolver_and_the_srv_records(self):
        # The 2026-08-14 field set could not distinguish "SSSD never found a
        # domain controller" from "SSSD found one and could not use it", because
        # it said nothing at all about name resolution -- and SSSD's AD provider
        # finds a controller by DNS SRV lookup and nothing else.  Six fields now
        # cover that layer: what resolver SSSD was handed, whether the two names
        # sssd.conf pins resolve, whether SRV answers at all, and what the CLDAP
        # netlogon ping (the site half of discovery) replies.
        body = _heredoc_body(self._rendered(), "TELOS_DOMAIN_ONLINE_EOF")
        self.assertIn("say resolver cat /etc/resolv.conf", body)
        self.assertIn('say resolver-controller getent hosts "$AD_SERVER"', body)
        self.assertIn('say resolver-client getent hosts "$AD_HOSTNAME"', body)
        # net lookup is the only SRV-capable tool the package contract installs
        # on a workstation: bind (host, dig) is a controller-domain package, and
        # no resolver CLI ships otherwise.
        self.assertIn('say discovery-ldap-srv net lookup ldap "$DOMAIN"', body)
        self.assertIn('say discovery-kdc-srv net lookup kdc "$REALM"', body)
        self.assertIn("say discovery-netlogon net ads lookup", body)
        installed = merge_contract(
            load_registry(
                Path(__file__).resolve().parents[1] / "package-contract.json"
            ),
            PROFILE_OVERLAYS["workstation-install"],
        ).packages
        self.assertNotIn("bind", installed)
        self.assertIn("samba", installed)
        # The gate reports on exactly the names sssd.conf was given, so a
        # diagnostic can never disagree with the configuration it diagnoses.
        sssd_conf = _heredoc_body(self._rendered(), "TELOS_SSSD_EOF")
        for variable, option in (("AD_SERVER", "ad_server"),
                                 ("AD_HOSTNAME", "ad_hostname")):
            with self.subTest(option=option):
                value = re.search(
                    rf"^{variable}='([^']+)'$", body, re.M).group(1)
                self.assertIn(f"\n{option} = {value}\n", sssd_conf)

    def test_diagnostics_read_the_sssd_log_from_the_start_as_well(self):
        # A tail cannot recover a decision the AD provider took at startup, two
        # minutes before this gate gives up.  The 2026-08-14 transcript is the
        # proof: all forty tailed lines were the same "SSSD is offline" pair
        # repeating at the wait loop's own cadence, and every discovery message
        # had scrolled out.  So the head is printed too, under its own field
        # name, and the debug-level raise is reported instead of discarded --
        # that run could not tell "the level never changed" from "the backend
        # had nothing more to say".
        body = _heredoc_body(self._rendered(), "TELOS_DOMAIN_ONLINE_EOF")
        self.assertIn(
            f"say_lines sssd-log-start {DIAGNOSTIC_SSSD_LOG_HEAD_LINES}", body)
        self.assertIn('say sssd-debug-level sssctl debug-level "$debug_level"',
                      body)
        self.assertNotIn("sssctl debug-level \"$debug_level\" \\", body)
        # Head before tail: the startup decisions lead, the current state
        # follows, so the transcript reads in the order the failure happened.
        self.assertLess(
            body.index("sssd-log-start"), body.index("say_lines sssd-log "))

    def test_head_reads_the_whole_backtrace_and_not_a_fixed_window(self):
        # SSSD does not write the reason as a line, it writes it as a backtrace:
        # with debug_backtrace_enabled true and debug_level under 9 it buffers
        # every message at full detail and flushes the lot when it logs its
        # first error.  The 2026-08-14 head therefore held the FIRST QUARTER of
        # the answer -- it stopped at `dp_load_configuration`, before the AD
        # provider had even tried to connect -- and no line count chosen in
        # advance is the right one.  Read to SSSD's own fence instead, with a
        # hard stop behind it for a log that carries no backtrace at all.
        body = _heredoc_body(self._rendered(), "TELOS_DOMAIN_ONLINE_EOF")
        self.assertIn(
            f"sed -n '1,/{DIAGNOSTIC_SSSD_BACKTRACE_END}/p' \"$domain_log\"",
            body)
        # The fence text is the shipped libsss_debug.so's own, so it cannot be
        # paraphrased, and the hard stop has to be able to outrun the 40-line
        # window it replaces or it would reinstate the bug.
        self.assertEqual(DIAGNOSTIC_SSSD_BACKTRACE_END,
                         "BACKTRACE DUMP ENDS HERE")
        self.assertGreater(DIAGNOSTIC_SSSD_LOG_HEAD_LINES,
                           DIAGNOSTIC_SSSD_LOG_LINES * 4)

    def test_diagnostics_follow_sssd_to_its_helper_child_logs(self):
        # The AD provider never reads the host keytab in its own process: it
        # forks ldap_child to select a principal and again to get a TGT, and
        # libsss_ldap_common's own error text points at the child's log ("see
        # ldap_child.log ... for details").  The 2026-08-14 field set read only
        # sssd_<domain>.log, so every keytab and Kerberos error stayed on disk
        # while the transcript said nothing but "Failed to connect".
        body = _heredoc_body(self._rendered(), "TELOS_DOMAIN_ONLINE_EOF")
        self.assertEqual(SSSD_CHILD_LOG_NAMES, ("ldap_child", "krb5_child"))
        for name in SSSD_CHILD_LOG_NAMES:
            field = f"{name.replace('_', '-')}-log"
            with self.subTest(child=name):
                self.assertIn(
                    f"say_log {field}"
                    f" '{DIAGNOSTIC_SSSD_LOG_DIR}/{name}.log'"
                    f" {DIAGNOSTIC_CHILD_LOG_LINES}",
                    body)
        # An absent child log is a finding about a different layer than an empty
        # one -- the child never ran at all -- so say_log reports the reason
        # rather than printing nothing under the same field name.
        self.assertIn('if [ -r "$path" ]; then', body)
        self.assertIn('say "$field" ls -l "$path"', body)
        # Before the domain log, because that is the order the evidence reads
        # in: the child failed, and the backend then reported the consequence.
        self.assertLess(body.index("say_log ldap-child-log"),
                        body.index("say_lines sssd-log-start"))

    def test_diagnostics_prove_whether_the_machine_can_get_a_tgt(self):
        # The fork in the road the 2026-08-14 field set could not take: the
        # keytab existed, the KDC answered, the offset was 0 and the directory
        # returned the user, yet the backend stayed Offline -- and nothing
        # printed separated "these keys do not authenticate this machine" from
        # "they do, and SSSD's use of them is wrong".
        body = _heredoc_body(self._rendered(), "TELOS_DOMAIN_ONLINE_EOF")
        self.assertIn(
            'say host-tgt env KRB5CCNAME="FILE:$TGT_CACHE" \\\n'
            '    kinit -V -k -t "$HOST_KEYTAB" "$MACHINE_PRINCIPAL"',
            body)
        # -k so no password can be involved, -V so success is a statement and
        # not an absence, and the throwaway cache removed as soon as the field
        # has been printed.
        self.assertIn(f"TGT_CACHE='{DIAGNOSTIC_TGT_CACHE_PATH}'", body)
        self.assertTrue(DIAGNOSTIC_TGT_CACHE_PATH.startswith("/run/"))
        self.assertIn('rm -f "$TGT_CACHE"', body)
        # kinit and klist come from the same package the join already needs.
        installed = merge_contract(
            load_registry(
                Path(__file__).resolve().parents[1] / "package-contract.json"
            ),
            PROFILE_OVERLAYS["workstation-install"],
        ).packages
        self.assertIn("krb5", installed)

    def test_machine_principal_is_derived_from_the_shipped_sssd(self):
        # ldap_child's second keytab pattern is "%S$", and sss_krb5_get_primary
        # truncates the hostname at its first dot, uppercases the rest and
        # formats "%.15s$".  That is why ad_hostname's case cannot mismatch the
        # keytab and why ldap_sasl_authid is left unset: the bind principal
        # comes back OUT of the keytab, as the machine account.
        self.assertEqual(
            _machine_principal("telos-ws1.ad.factory.test", "AD.FACTORY.TEST"),
            "TELOS-WS1$@AD.FACTORY.TEST")
        # The 15-character NetBIOS truncation is part of the rule, not padding.
        self.assertEqual(
            _machine_principal("a-very-long-hostname.example.test", "R"),
            "A-VERY-LONG-HOS$@R")
        # The gate is told exactly this, so a diagnostic can never disagree with
        # the configuration it diagnoses.
        body = _heredoc_body(self._rendered(), "TELOS_DOMAIN_ONLINE_EOF")
        client = re.search(r"^AD_HOSTNAME='([^']+)'$", body, re.M).group(1)
        realm = re.search(r"^REALM='([^']+)'$", body, re.M).group(1)
        self.assertIn(
            f"MACHINE_PRINCIPAL='{_machine_principal(client, realm)}'", body)

    def test_diagnostic_line_cap_survives_the_fields_that_matter(self):
        # 200 columns truncated `domain-status` at exactly "Discovered AD Domain
        # Controller servers: " in the 2026-08-14 transcript -- the one field
        # that would have said whether discovery found anything -- and also cut
        # `sssd-config` mid-finding and `keytab-principals` before the host
        # principals.  A cap that eats the evidence is worse than no cap.
        self.assertGreaterEqual(DIAGNOSTIC_LINE_COLUMNS, 512)
        body = _heredoc_body(self._rendered(), "TELOS_DOMAIN_ONLINE_EOF")
        # One cap, applied in both emitters and nowhere else, so no field can be
        # quietly exempted from the bound -- and every field goes through one of
        # the two.
        self.assertEqual(
            body.count(f"cut -c1-{DIAGNOSTIC_LINE_COLUMNS}"), 2)
        # A column cap cannot bound a listing whose LENGTH is the evidence, so
        # the keytab gets a line bound instead: the 2026-08-14 field was cut
        # after the third host principal, which is exactly where a reader would
        # have begun counting whether a previous join's keys were still there.
        self.assertIn(
            f"say_lines keytab-principals {DIAGNOSTIC_KEYTAB_LINES}"
            f' klist -k "$HOST_KEYTAB"',
            body)
        # Room for two full sets of five service principals at three enctypes.
        self.assertGreaterEqual(DIAGNOSTIC_KEYTAB_LINES, 2 * 5 * 3)

    def test_diagnostics_run_only_after_a_failure_and_only_from_fail(self):
        body = _heredoc_body(self._rendered(), "TELOS_DOMAIN_ONLINE_EOF")
        # Exactly one call site, inside fail(), after the reason and before the
        # exit: a converging boot pays nothing, and no path can exit without
        # having printed its evidence.
        calls = re.findall(r"^  diagnose$", body, re.M)
        self.assertEqual(len(calls), 1)
        reason = body.index(
            f"printf '%s: %s\\n' '{DOMAIN_ONLINE_FAILURE_MARKER}'")
        ordered = [
            body.index("fail() {"),
            reason,
            body.index("\n  diagnose\n"),
            body.index("\n  exit 1\n"),
        ]
        self.assertEqual(ordered, sorted(ordered))
        # The success marker never appears inside the diagnostic block.
        self.assertLess(body.index("diagnose() {"), reason)

    def test_diagnostic_marker_can_never_forge_or_shadow_a_gate_marker(self):
        # vm/arch_identity_run.await_domain_online waits on a bare substring
        # match for the success marker, so a diagnostic line that contained it
        # would report a domain that never came online.
        self.assertNotIn(DOMAIN_ONLINE_MARKER, DOMAIN_ONLINE_DIAGNOSTIC_MARKER)
        self.assertNotIn(
            DOMAIN_ONLINE_FAILURE_MARKER, DOMAIN_ONLINE_DIAGNOSTIC_MARKER)
        self.assertNotIn(DOMAIN_ONLINE_DIAGNOSTIC_MARKER, DOMAIN_ONLINE_MARKER)
        self.assertNotIn(
            DOMAIN_ONLINE_DIAGNOSTIC_MARKER, DOMAIN_ONLINE_FAILURE_MARKER)
        script = self._rendered()
        self.assertEqual(script.count(DOMAIN_ONLINE_MARKER), 1)

    def test_diagnostics_are_secret_free_by_construction(self):
        # The gate authenticates nothing, so no credential exists in the
        # process to leak; the executable lines are held to that.  klist -k
        # prints principal names and key versions, never key material, and
        # `net` reads the machine credential without printing it.
        body = _heredoc_body(self._rendered(), "TELOS_DOMAIN_ONLINE_EOF")
        start = body.index("diagnose() {")
        block = body[start:body.index("\nfail() {", start)]
        for line in block.splitlines():
            if line.lstrip().startswith("#") or not line.strip():
                continue
            self.assertNotRegex(
                line, r"(?i)password|secret|credential",
                f"unexpected credential reference: {line!r}")
            self.assertNotIn("-U ", line)
            self.assertNotIn("/run/telos-join", line)
        # klist never dumps keys, and no field reads a key table other than the
        # host keytab.
        self.assertNotIn("klist -e", block)
        self.assertNotIn("-K", block)

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


class RosterLoaderTests(unittest.TestCase):
    """The ONE principal-roster loader: contract defaults, private overlay.

    Real account names are instance data (ADR 0046) and live only in the
    gitignored ``homelab/instance/identity/principals.json``.  Every overlay
    here is written to a temporary directory, so these tests never depend on --
    and never touch -- the owner's real overlay.
    """

    ABSENT = Path("/nonexistent/telos/identity/principals.json")

    def contract_roster(self) -> dict[str, str]:
        return identity_roster(overlay_path=self.ABSENT)

    def overlay(self, document) -> Path:
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        path = Path(root) / "principals.json"
        path.write_text(
            document if isinstance(document, str) else json.dumps(document),
            encoding="utf-8")
        return path

    def named(self, **overrides) -> dict[str, str]:
        return identity_roster(overlay_path=self.overlay({
            "schema_version": 1,
            "principals": {
                role: {"name": name} for role, name in overrides.items()},
        }))

    # ---- No overlay: byte-identical to the pinned acceptance roster ----

    def test_no_overlay_means_the_synthetic_acceptance_roster_exactly(self):
        # Gates 6 and 8 assert these names.  If this needs editing, both gates
        # have to be re-proven and every file written under the old directory
        # UIDs is orphaned (vm/controller_principals POSIX_ALLOCATION).
        self.assertEqual(
            {
                "standard_user": "student",
                "daily_administrator": "operator",
                "domain_administrator": "directory-admin",
                "local_rescue": "local-rescue",
            },
            self.contract_roster(),
        )
        # And the contract file itself still carries them, so the default is a
        # tracked fact and not a Python literal.
        contract = json.loads(
            identity_contract_path().read_text(encoding="utf-8"))
        self.assertEqual(
            self.contract_roster(),
            {role: contract["principals"][role]["name"]
             for role in CONTRACT_ROLES},
        )

    def test_an_empty_overlay_changes_nothing(self):
        # The instance-example template ships exactly this shape, so copying it
        # (make homelab-instance) cannot alter a single name.
        self.assertEqual(
            self.contract_roster(),
            identity_roster(overlay_path=self.overlay(
                {"schema_version": 1, "principals": {}})),
        )
        self.assertEqual(
            self.contract_roster(),
            identity_roster(overlay_path=self.overlay(
                {"schema_version": 1})),
        )

    def test_the_shipped_template_is_inert(self):
        template = (
            Path(__file__).resolve().parents[1]
            / "instance-example" / "identity" / "principals.json")
        self.assertEqual(
            self.contract_roster(), identity_roster(overlay_path=template))
        document = json.loads(template.read_text(encoding="utf-8"))
        self.assertEqual({}, document["principals"])
        # Every placeholder in the worked example is a placeholder, not a name.
        for declaration in document["_example_principals"].values():
            self.assertRegex(declaration["name"], r"^<[a-z-]+>$")

    def test_the_installer_bakes_the_overlay_at_the_default_path(self):
        # render_installer takes no roster: it resolves the DEFAULT overlay
        # path.  With a synthetic overlay pinned there, every renamed name is
        # baked in, and the fingerprint on the disk is the renamed roster's.
        renamed = {
            "standard_user": "roster-a", "daily_administrator": "roster-b",
            "domain_administrator": "roster-c", "local_rescue": "roster-d",
        }
        with pinned_identity_overlay(overlay_document(renamed)):
            self.assertEqual(renamed, identity_roster())
            script = render_installer(
                disk_path="/dev/vda", disk_serial="LAPTOP-1",
                hostname="workstation", expected_sizes_mib=SIZES)
        self.assertIn("roster-b ALL=(ALL:ALL) ALL", script)
        self.assertIn(
            f"ROSTER_FINGERPRINT='{identity_roster_fingerprint(renamed)}'",
            script)
        for name in renamed.values():
            self.assertIn(name, script)
        # And the module's no-overlay pin is back in force.
        self.assertEqual(self.contract_roster(), identity_roster())

    def test_the_overlay_lives_only_in_the_gitignored_instance_tree(self):
        # The test module bound the real function at import; the pin replaced
        # only the module attribute the loader calls, so this is the real path
        # (computed, never read).
        overlay = identity_overlay_path()
        homelab = Path(__file__).resolve().parents[1]
        self.assertEqual(
            homelab / "instance" / "identity" / "principals.json", overlay)
        # /homelab/instance/ is gitignored (ADR 0046); the template beside it is
        # what is tracked.
        ignore = (homelab.parent / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/homelab/instance/", ignore.splitlines())

    # ---- With an overlay: the roster is renamed ----

    def test_an_overlay_renames_the_roster(self):
        renamed = self.named(
            standard_user="roster-a", domain_administrator="roster-c")
        self.assertEqual(
            {
                "standard_user": "roster-a",
                "daily_administrator": "operator",
                "domain_administrator": "roster-c",
                "local_rescue": "local-rescue",
            },
            renamed,
        )
        # All four roles are nameable, independently and optionally.
        self.assertEqual(
            {
                "standard_user": "roster-a",
                "daily_administrator": "roster-b",
                "domain_administrator": "roster-c",
                "local_rescue": "roster-d",
            },
            self.named(
                standard_user="roster-a", daily_administrator="roster-b",
                domain_administrator="roster-c", local_rescue="roster-d"),
        )

    def test_a_renamed_roster_reaches_the_installed_disk(self):
        renamed = self.named(
            standard_user="roster-a", domain_administrator="roster-c")
        script = self.render(renamed)
        for name in renamed.values():
            self.assertIn(name, script)
        self.assertIn("STANDARD_USER='roster-a'", script)
        self.assertIn("DOMAIN_ADMIN='roster-c'", script)
        # The renamed standard user owns the optional per-user share.
        self.assertIn(f"{STORAGE_MOUNT_ROOT}/roster-a", script)
        # The daily administrator's passworded sudoers rule follows the name --
        # and is still passworded: no NOPASSWD is introduced anywhere.
        self.assertIn("operator ALL=(ALL:ALL) ALL", script)
        self.assertNotIn("NOPASSWD", script)
        # Nothing renamed is left behind under its synthetic name.  Checked on
        # the probe's own assignments rather than the whole script, which
        # carries unrelated English prose.
        probe = _heredoc_body(script, "TELOS_PROBE_EOF")
        assignments = re.findall(r"(?m)^([A-Z_]+)='([^']*)'$", probe)
        self.assertEqual(
            {"STANDARD_USER": "roster-a", "DAILY_ADMIN": "operator",
             "DOMAIN_ADMIN": "roster-c", "RESCUE_USER": "local-rescue"},
            {key: value for key, value in assignments
             if key in {"STANDARD_USER", "DAILY_ADMIN", "DOMAIN_ADMIN",
                        "RESCUE_USER"}},
        )
        for role in ("standard_user", "domain_administrator"):
            self.assertNotIn(
                self.contract_roster()[role],
                [value for _, value in assignments])

    def render(self, roster) -> str:
        """Render the installer as if *roster* were the resolved roster."""
        import unittest.mock as mock
        with mock.patch(
            "workstations.arch_second.identity_roster",
            return_value=dict(roster),
        ):
            return render_installer(
                disk_path="/dev/vda", disk_serial="LAPTOP-1",
                hostname="workstation", expected_sizes_mib=SIZES,
            )

    # ---- Refusals: every one of them fail-closed and distinctly named ----

    def test_an_unsafe_name_is_refused(self):
        # These names flow into shell words, sudoers rules, SMB share names and
        # Kerberos principals.  Anything that would need quoting is refused
        # rather than escaped, which is why SAFE_PRINCIPAL exists.
        for unsafe in (
            "who; reboot", "who root", "WHO", "0who", "-who", "who$",
            "who'", 'who"', "who\n", "", "a" * 33, "who.admin", "who_admin",
        ):
            with self.subTest(name=unsafe):
                self.assertIsNone(SAFE_PRINCIPAL.fullmatch(unsafe))
                with self.assertRaisesRegex(
                        IdentityRosterError, "safely representable"):
                    self.named(standard_user=unsafe)
        for wrong_type in (None, 47, True, ["who"], {"name": "who"}):
            with self.subTest(name=wrong_type):
                with self.assertRaisesRegex(
                        IdentityRosterError, "safely representable"):
                    self.named(standard_user=wrong_type)

    def test_a_colliding_name_is_refused(self):
        # Two roles sharing a name collapses the very separation the lifecycle
        # proves (daily administrator vs domain administrator; local rescue vs
        # any directory account) and would collide in the POSIX allocation.
        with self.assertRaisesRegex(IdentityRosterError, "not distinct"):
            self.named(standard_user="operator")
        with self.assertRaisesRegex(IdentityRosterError, "not distinct"):
            self.named(
                daily_administrator="roster-x", domain_administrator="roster-x")
        with self.assertRaisesRegex(IdentityRosterError, "not distinct"):
            self.named(local_rescue="student")

    def test_a_malformed_overlay_is_refused_never_silently_defaulted(self):
        # A file that exists and cannot be understood must stop the build: a
        # fallback to the synthetic names would install accounts the owner did
        # not ask for, under a name they would not recognise.
        cases = (
            ("not json at all", "unreadable JSON"),
            ('["who"]', "not a JSON object"),
            ('{"principals": {}}', "schema_version"),
            ('{"schema_version": 2, "principals": {}}', "schema_version"),
            ('{"schema_version": 1, "principal": {}}', "unknown key"),
            ('{"schema_version": 1, "principals": []}', "not a JSON object"),
            ('{"schema_version": 1, "principals": {"root": {"name": "who"}}}',
             "unknown role"),
            ('{"schema_version": 1, "principals": {"standard_user": "who"}}',
             "not a JSON object"),
            ('{"schema_version": 1, "principals": {"standard_user": '
             '{"name": "who", "domain_role": "administrator"}}}',
             "may only set"),
            ('{"schema_version": 1, "principals": {"standard_user": {}}}',
             "declares no name"),
        )
        for document, message in cases:
            with self.subTest(document=document):
                with self.assertRaisesRegex(IdentityRosterError, message):
                    identity_roster(overlay_path=self.overlay(document))
        # Every refusal is an InstallContractError too, so an installer caller
        # that already handles contract refusals cannot miss one -- but the
        # distinct class means a roster fault never reads as disk geometry.
        self.assertTrue(issubclass(IdentityRosterError, InstallContractError))

    def test_the_break_glass_account_may_not_be_root(self):
        # ADR 0055/0063 make break-glass a SEPARATELY NAMED local account so it
        # is not UID 0.  The loader used to accept it: identity_roster()
        # returned {'local_rescue': 'root'} and the rendered installer would
        # have baked `useradd root` and a sudoers rule for root onto the disk.
        # The Ansible common role refuses it too, but the installer path reads
        # this loader directly and never passes through Ansible.
        with self.assertRaises(IdentityRosterError) as caught:
            self.named(local_rescue="root")
        message = str(caught.exception)
        self.assertIn("local_rescue", message)
        self.assertIn("'root'", message)
        self.assertIn("ADR 0055/0063", message)
        # The refusal names the file the name came from, so the reader of a
        # transcript knows which document to correct.
        self.assertIn("principals.json", message)

    def test_the_break_glass_account_may_not_take_a_system_account(self):
        # Every one of these is already in /etc/passwd on the installed disk
        # and nsswitch resolves local files first, so the name could never
        # mean the account the roster intends.
        for name in ("root", "daemon", "bin", "sys", "nobody",
                     "systemd-network"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                        IdentityRosterError, "reserved for the installed"):
                    self.named(local_rescue=name)
        # Refused, never substituted: nothing resolves to a different name.
        self.assertEqual(
            self.named(local_rescue="rescue")["local_rescue"], "rescue")
        # A name that merely CONTAINS a reserved one is fine; only the account
        # names themselves and systemd's own prefix are reserved.
        for name in ("rootless", "binary-rescue", "system-rescue"):
            with self.subTest(name=name):
                self.assertEqual(
                    self.named(local_rescue=name)["local_rescue"], name)

    def test_the_reservations_bind_the_local_role_and_only_it(self):
        # A DIRECTORY principal that collides with a local account is already
        # refused twice, and better: on the control host before anything is
        # installed, and by the installer's own local-shadow guard, which reads
        # this disk's real /etc/passwd after every package is in place.  That
        # guard exempts the break-glass account by design -- which is exactly
        # the hole the local reservations close -- so the loader's list binds
        # the local role alone rather than becoming a third static copy.
        for role in DIRECTORY_ROLES:
            with self.subTest(role=role):
                self.assertEqual(self.named(**{role: "root"})[role], "root")
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES)
        self.assertIn("local account shadows directory principal", script)
        # And the directory namespace's own reservations stay there: they mean
        # nothing to a local UNIX account, and two files already keep them in
        # step with each other.
        for name in ("administrator", "guest", "krbtgt", "dns-factory"):
            with self.subTest(name=name):
                self.assertEqual(
                    self.named(local_rescue=name)["local_rescue"], name)

    def test_documentation_keys_are_allowed_because_json_has_no_comments(self):
        roster = identity_roster(overlay_path=self.overlay({
            "_documentation": "read me",
            "_example_principals": {"standard_user": {"name": "<who>"}},
            "schema_version": 1,
            "principals": {
                "_note": "ignored",
                "standard_user": {"_why": "the kid", "name": "roster-a"},
            },
        }))
        self.assertEqual("roster-a", roster["standard_user"])
        self.assertEqual("operator", roster["daily_administrator"])

    def test_an_unreadable_overlay_is_a_refusal_never_a_fallback(self):
        # THE fail-open the loader exists to prevent, proved against the real
        # OSError behaviour of the interpreter this suite runs on rather than
        # against a mock: a valid overlay under a directory the process cannot
        # search.  On Python 3.13+ ``Path.exists()`` and ``Path.is_symlink()``
        # swallow EVERY OSError and answer False, so the old
        # ``if not path.exists() and not path.is_symlink(): return {}``
        # reported "no overlay" and handed back the SYNTHETIC roster -- with no
        # exception raised, and on the durable path the resulting SIDs are
        # permanent.
        if os.geteuid() == 0:
            self.skipTest("root bypasses the directory search permission")
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        fenced = root / "identity"
        fenced.mkdir()
        overlay = fenced / "principals.json"
        overlay.write_text(json.dumps({
            "schema_version": 1,
            "principals": {"standard_user": {"name": "roster-a"}},
        }), encoding="utf-8")
        fenced.chmod(0o000)
        self.addCleanup(fenced.chmod, 0o700)
        # The premise, asserted rather than assumed: this really is a stat that
        # fails, and the pathlib predicates really do hide it.
        with self.assertRaises(PermissionError):
            os.lstat(overlay)
        self.assertFalse(overlay.exists())
        self.assertFalse(overlay.is_symlink())
        with self.assertRaisesRegex(
                IdentityRosterError, "could not be examined"):
            identity_roster(overlay_path=overlay)
        # And the refusal names the file, because a transcript is all the
        # reader of a failed provisioning run has.
        with self.assertRaisesRegex(IdentityRosterError, re.escape(str(
                overlay))):
            identity_roster(overlay_path=overlay)

    def test_only_a_genuine_absence_falls_back_to_the_contract(self):
        # ENOENT is the ONE condition that may fall back; every other OSError
        # is refused above.  A path whose PARENT is a regular file raises
        # ENOTDIR, which means the overlay location is misconfigured, not that
        # the owner declined to have one.
        self.assertEqual(self.contract_roster(), identity_roster(
            overlay_path=self.ABSENT))
        regular = self.overlay({"schema_version": 1, "principals": {}})
        with self.assertRaisesRegex(
                IdentityRosterError, "could not be examined"):
            identity_roster(overlay_path=regular / "principals.json")

    def test_a_durable_caller_can_refuse_the_synthetic_fallback(self):
        # An absent overlay is correct for the DISPOSABLE acceptance lane and
        # wrong for a persistent instance: there the SIDs are permanent, so an
        # operator who mistyped an overlay path would mint a directory full of
        # student/operator accounts and be told it succeeded.
        with self.assertRaisesRegex(
                IdentityRosterError, "may not fall back"):
            identity_roster(overlay_path=self.ABSENT, require_overlay=True)
        # The refusal names the exact path that was not there.
        with self.assertRaisesRegex(
                IdentityRosterError, re.escape(str(self.ABSENT))):
            identity_roster(overlay_path=self.ABSENT, require_overlay=True)
        # With an overlay present it changes nothing at all.
        present = self.overlay({
            "schema_version": 1,
            "principals": {"standard_user": {"name": "roster-a"}},
        })
        self.assertEqual(
            identity_roster(overlay_path=present),
            identity_roster(overlay_path=present, require_overlay=True))
        # The acceptance lane keeps its fallback: this is opt-in, and gates 6
        # and 8 never pass require_overlay.
        self.assertEqual(
            self.contract_roster(), identity_roster(overlay_path=self.ABSENT))

    def test_a_durable_caller_can_require_named_roles(self):
        # An overlay is a sparse patch, so "it exists" does not mean "it names
        # the accounts": the inert template names nobody. A durable caller
        # lists the roles it will make permanent, and each must be named by
        # the overlay itself rather than filled from the contract.
        partial = self.overlay({
            "schema_version": 1,
            "principals": {"standard_user": {"name": "roster-a"}},
        })
        self.assertEqual("roster-a", identity_roster(
            overlay_path=partial, require_named=("standard_user",),
        )["standard_user"])
        with self.assertRaisesRegex(
                IdentityRosterError,
                "does not name daily_administrator.*synthetic acceptance "
                "roster.*daily_administrator -> operator"):
            identity_roster(overlay_path=partial, require_named=(
                "standard_user", "daily_administrator"))
        # It implies require_overlay: an absent overlay names nobody.
        with self.assertRaisesRegex(IdentityRosterError, "may not fall back"):
            identity_roster(overlay_path=self.ABSENT,
                            require_named=("standard_user",))
        # A misspelled requirement is a refusal, not a vacuous pass.
        with self.assertRaisesRegex(IdentityRosterError, "unknown role"):
            identity_roster(overlay_path=partial,
                            require_named=("standard-user",))
        # Callers that require nothing are untouched.
        self.assertEqual(identity_roster(overlay_path=partial),
                         identity_roster(overlay_path=partial,
                                         require_named=()))

    def test_every_refusal_names_where_the_roster_came_from(self):
        # A rejected roster used to say only what was wrong with it, never
        # whether the offending name came from the tracked contract or from the
        # owner's private file.
        present = self.overlay({
            "schema_version": 1,
            "principals": {"standard_user": {"name": "operator"}},
        })
        with self.assertRaisesRegex(
                IdentityRosterError, re.escape(str(present))):
            identity_roster(overlay_path=present)
        self.assertIn(
            str(identity_contract_path()),
            identity_roster_source(self.ABSENT))
        self.assertIn(str(self.ABSENT), identity_roster_source(self.ABSENT))
        # The phrase distinguishes the two resolutions rather than hedging.
        self.assertIn("no overlay", identity_roster_source(self.ABSENT))
        self.assertIn("patched by overlay", identity_roster_source(present))

    def test_a_directory_name_over_the_ad_logon_limit_is_refused(self):
        # SAFE_PRINCIPAL admits 32 characters; Active Directory's
        # pre-Windows-2000 logon name (sAMAccountName) caps a USER object at
        # 20, and every directory role becomes one.  A 21..32-character name
        # passed every host-side gate and would have failed at the first
        # Windows logon, inside a VM.
        self.assertEqual(20, SAMACCOUNTNAME_LIMIT)
        too_long = "a" * (SAMACCOUNTNAME_LIMIT + 1)
        self.assertIsNotNone(SAFE_PRINCIPAL.fullmatch(too_long))
        for role in DIRECTORY_ROLES:
            with self.subTest(role=role):
                with self.assertRaisesRegex(
                        IdentityRosterError, "sAMAccountName limit"):
                    self.named(**{role: too_long})
        at_limit = "a" * SAMACCOUNTNAME_LIMIT
        self.assertEqual(
            at_limit, self.named(standard_user=at_limit)["standard_user"])
        # local_rescue is a LOCAL UNIX account (ADR 0055/0063), never an AD
        # user object, so the AD cap does not apply to it.
        self.assertEqual(
            too_long, self.named(local_rescue=too_long)["local_rescue"])
        # And the synthetic roster is nowhere near the cap.
        for role in DIRECTORY_ROLES:
            self.assertLessEqual(
                len(self.contract_roster()[role]), SAMACCOUNTNAME_LIMIT)

    def test_a_symlinked_or_directory_overlay_is_refused(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        real = self.overlay({"schema_version": 1, "principals": {}})
        link = root / "principals.json"
        link.symlink_to(real)
        with self.assertRaisesRegex(IdentityRosterError, "regular file"):
            identity_roster(overlay_path=link)
        directory = root / "as-a-directory.json"
        directory.mkdir()
        with self.assertRaisesRegex(IdentityRosterError, "regular file"):
            identity_roster(overlay_path=directory)

    # ---- The installed disk's local-shadow guard ----

    def test_the_installer_refuses_a_name_a_local_account_holds(self):
        # nsswitch is `passwd: files sss` -- FILES FIRST -- so a LOCAL account
        # sharing a directory principal's name shadows the directory one for
        # every resolution on the installed disk.  For the daily administrator
        # that is a privilege escalation, because the sudoers rule this script
        # writes grants `ALL=(ALL:ALL) ALL` by NAME: an overlay naming the
        # daily administrator `git` or `http` would hand unrestricted sudo to a
        # service account.  Gate 8's probe catches it at test time; the
        # installed disk carries it either way, so the guard runs at install.
        script = self.render(self.named(daily_administrator="http"))
        guard = script[
            script.index("for telos_principal in"):
            script.index("/mnt/etc/sudoers.d/20-daily-admin")]
        self.assertIn("cut -d: -f1 /mnt/etc/passwd | grep -qxF", guard)
        self.assertIn("cut -d: -f1 /mnt/etc/group | grep -qxF", guard)
        self.assertEqual(2, guard.count("exit 1"))
        # It guards every DIRECTORY principal and reads this disk's own
        # databases after every package is installed.
        roster = self.named(daily_administrator="http")
        for role in DIRECTORY_ROLES:
            self.assertIn(roster[role], guard.split(";", 1)[0])
        # The break-glass account is deliberately absent: ADR 0055/0063 make it
        # LOCAL by design, and the loader already proves it shares no name with
        # a directory principal.
        self.assertNotIn(roster["local_rescue"], guard.split(";", 1)[0])
        # And it runs BEFORE the rule it protects, never after.
        self.assertLess(
            script.index("for telos_principal in"),
            script.index("/mnt/etc/sudoers.d/20-daily-admin"))

    # ---- The fingerprint the disk carries ----

    def test_the_fingerprint_identifies_the_roster_and_nothing_else(self):
        contract = self.contract_roster()
        self.assertEqual(
            identity_roster_fingerprint(contract),
            identity_roster_fingerprint(contract))
        self.assertRegex(
            identity_roster_fingerprint(contract),
            f"^[0-9a-f]{{{ROSTER_FINGERPRINT_LENGTH}}}$")
        renamed = dict(contract, standard_user="roster-a")
        self.assertNotEqual(
            identity_roster_fingerprint(contract),
            identity_roster_fingerprint(renamed))
        # It carries no account name: that is the point of using a digest for a
        # value that travels on a retained console transcript.
        for name in contract.values():
            self.assertNotIn(name, identity_roster_fingerprint(contract))

    def test_the_rendered_probe_carries_the_rendered_rosters_fingerprint(self):
        renamed = self.named(standard_user="roster-a")
        script = self.render(renamed)
        self.assertIn(
            f"ROSTER_FINGERPRINT='{identity_roster_fingerprint(renamed)}'",
            script)
        self.assertNotIn("@ROSTER_FINGERPRINT@", script)
        self.assertNotIn("@ROSTER_VERB@", script)
        self.assertNotIn("@ROSTER_MARKER@", script)
        # The verb is accepted before any elevation, and answers with the
        # fingerprint instead of a verdict.
        probe = _heredoc_body(script, "TELOS_PROBE_EOF")
        self.assertLess(
            probe.index(f'if [ "$check" = \'{PROBE_ROSTER_VERB}\' ]; then'),
            probe.index('exec sudo -n --'))
        self.assertIn(f"{PROBE_ROSTER_VERB}|", probe)
        self.assertIn(PROBE_ROSTER_MARKER, probe)
        self.assertNotIn(PROBE_ROSTER_VERB, PROBE_CHECKS)

#: A complete, well-formed ADR 0065 declaration.  Synthetic in every field and
#: deliberately unlike ``FactorySpec()``'s defaults in all of them, so a
#: passing assertion about a durable value can never be a silent fallback to
#: the acceptance one.  The same shape ``test_directory_identity`` uses; a
#: tracked fixture naming the owner's real realm would put an effectively
#: permanent private value into Git, which is what the gitignored overlay
#: exists to prevent.
DURABLE_DOCUMENT = {
    "schema_version": 1,
    "identity": {
        "dns_domain": "ad.example.home.arpa",
        "kerberos_realm": "AD.EXAMPLE.HOME.ARPA",
        "netbios_name": "EXAMPLEAD",
    },
    "services": {
        "bootstrap_dc_fqdn": "bootstrap.ad.example.home.arpa",
        "permanent_dc_fqdn": "dc2.ad.example.home.arpa",
    },
    "network": {"address": "10.1.99.2", "prefix": 28, "gateway": "10.1.99.1"},
}

#: Every line the synthetic render emits that carries the realm, its NetBIOS
#: name or its domain controller -- the complete set, frozen at the commit
#: that made the realm derivable.  This is the acceptance guarantee stated as
#: bytes rather than as arguments: gate 7 installs against the DISPOSABLE
#: Controller, gates 8 through 10 depend on that disk, and nothing about
#: making the realm derivable may move one byte of it.  A new realm-derived
#: line, a moved one, or a changed one fails here.
SYNTHETIC_REALM_LINES = (
    "    default_realm = AD.FACTORY.TEST",
    "    realm = AD.FACTORY.TEST",
    "    workgroup = FACTORY",
    "domains = ad.factory.test",
    "[domain/ad.factory.test]",
    "ad_server = bootstrap-dc.ad.factory.test",
    "ad_hostname = workstation.ad.factory.test",
    "ad_domain = ad.factory.test",
    "krb5_realm = AD.FACTORY.TEST",
    "DOMAIN='ad.factory.test'",
    "STORAGE_HOST='unas.ad.factory.test'",
    "//unas.ad.factory.test/student /srv/unas/student cifs "
    "sec=krb5,multiuser,soft,echo_interval=15,_netdev,nofail,"
    "x-systemd.automount,x-systemd.mount-timeout=10s,"
    "x-systemd.idle-timeout=1min 0 0",
    "  getent hosts 'ad.factory.test' >/dev/null 2>&1 && break",
    "DOMAIN='ad.factory.test'",
    "REALM='AD.FACTORY.TEST'",
    "MACHINE_PRINCIPAL='WORKSTATION$@AD.FACTORY.TEST'",
    "AD_SERVER='bootstrap-dc.ad.factory.test'",
    "AD_HOSTNAME='workstation.ad.factory.test'",
)
_REALM_LINE = re.compile(
    r"ad\.factory\.test|AD\.FACTORY\.TEST|bootstrap-dc|FACTORY\b"
    r"|ad\.example\.home\.arpa|AD\.EXAMPLE\.HOME\.ARPA|EXAMPLEAD")


class InstallerRealmTests(unittest.TestCase):
    """The one realm a disk is built against: derived, or refused.

    ``SYNTHETIC_DOMAIN``/``SYNTHETIC_WORKGROUP`` were the last declaration of
    ADR 0065's permanent identity outside its single document, and the only
    one baked onto an installed disk rather than converged by a role.  Two
    families of test follow, and both matter:

      * acceptance is untouched.  Gate 7 installs against the disposable
        Controller and gates 8 through 10 depend on that disk, so with no
        durable identity requested every rendered byte must be what it was.
      * every refusal fires.  A workstation built against the wrong realm is
        not a wrong run: it is a finished machine joined to a domain that does
        not exist, and the realm is on the disk from ``pacstrap`` onwards.

    Every durable fixture is written into a temporary directory.  Nothing here
    reads ``homelab/instance/``: that is the owner's real declaration, and a
    suite that consulted it would pass or fail depending on whose machine ran
    it.
    """

    def setUp(self):
        # The realm half of a render reads no identity document, but the
        # roster half resolves the principal names through the private
        # overlay -- which the docstring above forbids. Point it at a path
        # that does not exist, so the synthetic bytes are the contract's on
        # every machine, including one whose owner has seeded real names.
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        patcher = mock.patch.object(
            arch_second, "identity_overlay_path",
            return_value=Path(temporary.name) / "no-principals.json")
        patcher.start()
        self.addCleanup(patcher.stop)

    def render(self, realm=None, hostname="workstation"):
        return render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname=hostname, expected_sizes_mib=SIZES, realm=realm)

    def document(self, root: Path, **overrides) -> Path:
        document = json.loads(json.dumps(DURABLE_DOCUMENT))
        for section, patch in overrides.items():
            if patch is None:
                document.pop(section, None)
            elif isinstance(patch, dict):
                document.setdefault(section, {}).update(patch)
            else:
                document[section] = patch
        path = root / "directory.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def durable(self, root: Path, *, controller=None, **overrides):
        return durable_installer_realm(
            self.document(root, **overrides),
            controller_fqdn=(
                controller if controller is not None
                else DURABLE_DOCUMENT["services"]["bootstrap_dc_fqdn"]))

    # ---- Acceptance is untouched -------------------------------------

    def test_the_synthetic_render_pins_every_realm_bearing_byte(self):
        script = self.render()
        self.assertEqual(
            tuple(line for line in script.splitlines()
                  if _REALM_LINE.search(line)),
            SYNTHETIC_REALM_LINES)

    def test_every_route_to_the_synthetic_realm_renders_the_same_bytes(self):
        # Requesting nothing, asking for the synthetic realm by name, going
        # through the one resolver, and handing over an equal realm built by
        # hand are four ways to say the same thing, and the disk may not be
        # able to tell them apart.
        baseline = self.render()
        for realm in (
            synthetic_installer_realm(),
            installer_realm(),
            installer_realm(durable=False),
            InstallerRealm(
                dns_domain=SYNTHETIC_DOMAIN,
                kerberos_realm=SYNTHETIC_DOMAIN.upper(),
                workgroup=SYNTHETIC_WORKGROUP,
                controller_fqdn=f"{CONTROLLER_HOSTNAME}.{SYNTHETIC_DOMAIN}",
                durable=False, source="a hand-built equal realm"),
        ):
            with self.subTest(source=realm.source):
                self.assertEqual(baseline, self.render(realm))
                self.assertFalse(realm.durable)

    def test_the_synthetic_realm_reads_no_identity_document(self):
        # The acceptance realm is a property of the disposable Controller, not
        # of who is running the suite: a developer whose machine carries the
        # private declaration must render exactly what a machine without one
        # renders.  Proved by making the loader unreachable.
        def refuse():
            raise AssertionError(
                "the synthetic realm resolved the durable declaration")

        with mock.patch.object(arch_second, "_directory_identity", refuse):
            self.assertEqual(
                synthetic_installer_realm().dns_domain, SYNTHETIC_DOMAIN)
            self.assertEqual(installer_realm().workgroup, SYNTHETIC_WORKGROUP)
            script = self.render()
        self.assertIn(f"\nad_server = {CONTROLLER_HOSTNAME}."
                      f"{SYNTHETIC_DOMAIN}\n", script)
        self.assertEqual(
            synthetic_installer_realm().source, SYNTHETIC_REALM_SOURCE)

    # ---- The durable realm comes from the document --------------------

    def test_durable_realm_is_taken_from_the_document(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            realm = self.durable(root)
        identity = DURABLE_DOCUMENT["identity"]
        self.assertTrue(realm.durable)
        self.assertEqual(realm.dns_domain, identity["dns_domain"])
        self.assertEqual(realm.kerberos_realm, identity["kerberos_realm"])
        self.assertEqual(realm.workgroup, identity["netbios_name"])
        self.assertEqual(
            realm.controller_fqdn,
            DURABLE_DOCUMENT["services"]["bootstrap_dc_fqdn"])
        # The refusal a reader of a serial transcript needs: which file the
        # realm about to be made permanent was read from.
        self.assertIn("directory.json", realm.source)
        self.assertNotIn(SYNTHETIC_DOMAIN, realm.source)

    def test_durable_realm_reaches_the_rendered_installer(self):
        with tempfile.TemporaryDirectory() as temporary:
            realm = self.durable(Path(temporary))
            script = self.render(realm, hostname="telos-ws1")
        identity = DURABLE_DOCUMENT["identity"]
        for expected in (
            f"    default_realm = {identity['kerberos_realm']}",
            f"    realm = {identity['kerberos_realm']}",
            f"    workgroup = {identity['netbios_name']}",
            f"domains = {identity['dns_domain']}",
            f"[domain/{identity['dns_domain']}]",
            f"ad_server = _srv_, {realm.controller_fqdn}",
            f"ad_hostname = telos-ws1.{identity['dns_domain']}",
            f"REALM='{identity['kerberos_realm']}'",
            f"MACHINE_PRINCIPAL='TELOS-WS1$@{identity['kerberos_realm']}'",
        ):
            self.assertIn(expected, script.splitlines())
        # Nothing synthetic survives anywhere on the disk: not the realm, not
        # the workgroup, not the acceptance Controller.
        for absent in (SYNTHETIC_DOMAIN, SYNTHETIC_DOMAIN.upper(),
                       f"= {SYNTHETIC_WORKGROUP}", CONTROLLER_HOSTNAME):
            self.assertNotIn(absent, script)

    def test_the_workgroup_travels_with_the_realm(self):
        # The NetBIOS name is the second half of the same fact.  A disk that
        # derived the realm and kept FACTORY would present a pre-Windows-2000
        # domain name its own realm does not know.
        with tempfile.TemporaryDirectory() as temporary:
            realm = self.durable(Path(temporary))
            script = self.render(realm)
        self.assertEqual(realm.workgroup, "EXAMPLEAD")
        self.assertIn("    workgroup = EXAMPLEAD", script.splitlines())
        self.assertNotIn(SYNTHETIC_WORKGROUP, script)
        # And there is no route into the renderer that carries one without the
        # other: the two are fields of one object, not two arguments.
        self.assertNotIn(
            "realm_workgroup",
            inspect.signature(render_installer).parameters)
        self.assertNotIn(
            "realm_dns_domain",
            inspect.signature(render_installer).parameters)

    # ---- Every refusal fires ------------------------------------------

    def test_an_absent_document_refuses_rather_than_falling_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "identity" / "directory.json"
            with self.assertRaises(InstallerRealmError) as caught:
                durable_installer_realm(
                    missing, controller_fqdn="bootstrap.ad.example.home.arpa")
        message = str(caught.exception)
        self.assertIn(str(missing), message)
        self.assertIn("does not exist", message)
        self.assertIn("may not fall back", message)

    def test_a_malformed_document_refuses(self):
        cases = {
            "unreadable JSON": {"raw": "{not json"},
            "schema_version": {"raw": json.dumps({"schema_version": 99})},
            "netbios_domain": {"identity": {"netbios_domain": "EXAMPLEAD"}},
            "kerberos_realm": {"identity": {"kerberos_realm": "WRONG.REALM"}},
            "home.arpa": {
                "identity": {
                    "dns_domain": "ad.example.test",
                    "kerberos_realm": "AD.EXAMPLE.TEST",
                },
            },
            "declares no": {"identity": {"netbios_name": None}},
        }
        for expected, patch in cases.items():
            with self.subTest(refusal=expected):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    if "raw" in patch:
                        path = root / "directory.json"
                        path.write_text(patch["raw"], encoding="utf-8")
                    else:
                        path = self.document(root, **patch)
                    with self.assertRaises(InstallerRealmError) as caught:
                        durable_installer_realm(
                            path,
                            controller_fqdn="bootstrap.ad.example.home.arpa")
                self.assertIn(expected, str(caught.exception))
                # Never a fallback, whatever the fault.
                self.assertNotIn(
                    f"resolved {SYNTHETIC_DOMAIN}", str(caught.exception))

    def test_a_restored_instances_recorded_dc_may_be_named(self):
        """TASK-42: a workstation minted after a DR names the restored DC.

        Only when the binding vouches for it as the instance's recorded DC,
        and only as one DC host-name label under the realm's DNS domain.
        """
        domain = DURABLE_DOCUMENT["identity"]["dns_domain"]
        restored = f"dr-2609302105.{domain}"
        with tempfile.TemporaryDirectory() as temporary:
            path = self.document(Path(temporary))
            realm = durable_installer_realm(
                path, controller_fqdn=restored, recorded_dc_fqdn=restored)
            self.assertEqual(realm.controller_fqdn, restored)
            self.assertTrue(realm.durable)
            self.assertEqual(
                installer_realm(durable=True, identity_path=path,
                                controller_fqdn=restored,
                                recorded_dc_fqdn=restored).controller_fqdn,
                restored)
            self.assertEqual(arch_second.ad_server_value(realm),
                             f"_srv_, {restored}")
            refused = (
                # Not vouched for at all: the frozen rule alone applies.
                (restored, None),
                # A different name than the one the instance records.
                (f"dr-other.{domain}", restored),
                (restored, f"dr-other.{domain}"),
                # The record, but outside the realm, or not one DC label.
                (f"dr-2609302105.other.home.arpa",
                 "dr-2609302105.other.home.arpa"),
                (f"a.b.{domain}", f"a.b.{domain}"),
                (f"dr-name-longer-than-15.{domain}",
                 f"dr-name-longer-than-15.{domain}"),
            )
            for controller, recorded in refused:
                with self.subTest(controller=controller, recorded=recorded):
                    with self.assertRaises(InstallerRealmError) as caught:
                        durable_installer_realm(
                            path, controller_fqdn=controller,
                            recorded_dc_fqdn=recorded)
                    self.assertIn("recorded DC of the persistent instance",
                                  str(caught.exception))
                    self.assertIn("dc_hostname", str(caught.exception))
            # The frozen names still need no record.
            for fqdn in DURABLE_DOCUMENT["services"].values():
                self.assertEqual(durable_installer_realm(
                    path, controller_fqdn=fqdn,
                    recorded_dc_fqdn=restored).controller_fqdn, fqdn)
        # The synthetic realm takes no recorded name and stays as frozen.
        with self.assertRaises(InstallerRealmError):
            installer_realm(recorded_dc_fqdn=restored)
        self.assertEqual(installer_realm(), synthetic_installer_realm())
        from homelab.vm import simulation_overlay
        self.assertEqual(arch_second.RECORDED_DC_LABEL.pattern,
                         simulation_overlay.DC_HOSTNAME.pattern)

    def test_a_durable_realm_must_name_a_frozen_controller(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(InstallerRealmError) as unstated:
                durable_installer_realm(self.document(root))
            with self.assertRaises(InstallerRealmError) as foreign:
                self.durable(root, controller="dc3.ad.example.home.arpa")
        services = DURABLE_DOCUMENT["services"]
        # Unstated names both candidates and says why it will not choose.
        for fqdn in services.values():
            self.assertIn(fqdn, str(unstated.exception))
        self.assertIn("ADR 0065", str(unstated.exception))
        self.assertIn("not one of the two", str(foreign.exception))
        # Both frozen names are accepted, and only those two.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for fqdn in services.values():
                self.assertEqual(
                    self.durable(root, controller=fqdn).controller_fqdn, fqdn)

    def test_synthetic_resolution_refuses_durable_arguments(self):
        # A caller who meant the permanent realm and forgot the switch is told
        # so, rather than silently handed ad.factory.test.
        with self.assertRaises(InstallerRealmError):
            installer_realm(controller_fqdn="bootstrap.ad.example.home.arpa")
        with self.assertRaises(InstallerRealmError):
            installer_realm(identity_path=Path("/nonexistent/directory.json"))

    def test_a_realm_object_validates_its_own_fields(self):
        good = dict(
            dns_domain="ad.example.home.arpa",
            kerberos_realm="AD.EXAMPLE.HOME.ARPA",
            workgroup="EXAMPLEAD",
            controller_fqdn="bootstrap.ad.example.home.arpa",
            durable=True, source="a test")
        for field, value in (
            ("dns_domain", "AD.Example.Home.Arpa"),
            ("dns_domain", "single-label"),
            ("workgroup", "exemplead"),
            ("workgroup", "TOO-LONG-WORKGROUP"),
            ("kerberos_realm", "ad.example.home.arpa"),
            ("kerberos_realm", "AD.OTHER.HOME.ARPA"),
            ("controller_fqdn", "bootstrap.ad.other.home.arpa"),
            ("controller_fqdn", "ad.example.home.arpa"),
            ("durable", "yes"),
            ("source", ""),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(InstallContractError):
                    InstallerRealm(**{**good, field: value})

    def test_the_renderer_refuses_anything_but_a_resolved_realm(self):
        for realm in (SYNTHETIC_DOMAIN, ("ad.factory.test", "FACTORY"), 7):
            with self.subTest(realm=realm):
                with self.assertRaises(InstallContractError):
                    self.render(realm)


#: The synthetic render's inputs the golden digests below were taken with: the
#: prepared bundle's own guest disk, disk serial and hostname
#: (``vm/arch_install_prepare``'s ``GUEST_DISK``, ``DISK_SERIAL`` and
#: ``DEFAULT_HOSTNAME``, restated as literals so only the RENDERER can move a
#: digest), this module's partition sizes, and every other argument at its
#: default -- the synthetic realm, the ``TELOS_JOIN`` label, the Controller's
#: workstation repository -- with no roster overlay.
GOLDEN_RENDER_INPUTS = {
    "disk_path": "/dev/vda",
    "disk_serial": "TELOS-WIN-0001",
    "hostname": "telos-ws1",
    "expected_sizes_mib": SIZES,
}
#: SHA-256 of the synthetic installer, computed from the tree at 9db2eeb (the
#: HEAD before the durable render existed, exported with ``git archive`` so no
#: working-tree change could leak in) with the inputs above.  Gate 7 installs
#: this disk and gates 8 through 10 depend on it, so a durable render may not
#: move one of its bytes (DURABLE-WORKSTATION-FLOW.md, step 5).  A DELIBERATE
#: change to the synthetic output -- a package-contract change reaches the
#: ``pacstrap`` line, for one -- re-pins these values in the same commit, after
#: reading the diff of the rendered bytes.
GOLDEN_INSTALLER_SHA256 = (
    "e0e7e67111709814bb4fb65d5b1cc0bfaffb8f6ff5d4692241097e2ceaa22ea7")
#: SHA-256 of every file the synthetic installer writes through a quoted
#: heredoc, keyed by the heredoc's terminator (``#2`` marks the second
#: occurrence: the join-credential conversion appears inline for the
#: install-time join and again inside the boot-time join script).  Same tree,
#: same inputs as the installer digest; it names WHICH file drifted.
GOLDEN_FILE_SHA256 = {
    "TELOS_MIRROR_EOF":
        "8902d61ba8a5999c6addbb6f7109c47c5357ee242639ad415033ff9c69d26b03",
    "TELOS_PACMAN_EOF":
        "b2bcafce9319609e3a59b8e19fbfafeba74e04abea19e86621fc560bf8562145",
    "TELOS_MKINITCPIO_EOF":
        "c3ea4ae5d4116f7c58357645acded946fb7d590391edb14a94425d50a700574b",
    "TELOS_JOIN_CRED_EOF":
        "fac835160e78e5b04bfd7a70a583253c167f156116d00a6b26e68b1955bcdefb",
    "TELOS_KRB5_EOF":
        "0fe6613fc431e510bdec655f9a16db6727319935936cfff749efa3464523260e",
    "TELOS_SMB_EOF":
        "7415e1b22cced912aaa48bfb9b86f31048279e53343f97e58ae8ce8bfc2f344b",
    "TELOS_SSSD_EOF":
        "e176867d938e509f36a5faffad25df6515dbfd906bb154321cfbf7dbf3e960f5",
    "TELOS_PAM_EOF":
        "dfb43e32c9f0bf820daa0777c06b5776436eb140c2c3035f1394333453303bf6",
    "TELOS_SUDO_EOF":
        "9ee69ecd1b378befa0b3f48f5e8d8c52263b7b908b8f602e9cc4e825ab6bf674",
    "TELOS_DAILY_EOF":
        "d49a0704a274d6dda91e6a591e89f386070498ebae8c3d5feb3915718de40b01",
    "TELOS_PROBE_EOF":
        "1b764b3443ca3702e03bbb20d3ced41e414b010029718f7798ff36502e210502",
    "TELOS_STORAGE_EOF":
        "3dc636037571c3bff20fd33d2e8afbeab5d3e43112805b3f2bc812e1021ae7b6",
    "TELOS_JOIN_ONCE_EOF":
        "f5baca8fa72d0366f8d0bc2f18b11d7229832577f9993b3acf86ab413051715b",
    "TELOS_JOIN_CRED_EOF#2":
        "fac835160e78e5b04bfd7a70a583253c167f156116d00a6b26e68b1955bcdefb",
    "TELOS_JOIN_UNIT_EOF":
        "f586a4e84aaead2a47164b6f4fcb3179c4d720accd04ec08e9ca26f225e8b8fe",
    "TELOS_DOMAIN_ONLINE_EOF":
        "ae7d0c69ef1fd05c81ba5ef1bf1d2913b7db76a44be4e2c8f9ce7102509711ee",
    "TELOS_DOMAIN_UNIT_EOF":
        "4137bf9c7badd23d0b05b45af1c487a6b0e80b7dd6d0a658bbb2cbd9ecd3f979",
    "EOF":
        "54dd71343505eb9e8de67600286ade75de54a83660ec868b19c1c99a30c79f40",
}
#: SHA-256 of the bundle's other rendered guest file,
#: ``vm/arch_install_prepare.render_arch_second_verify()``.  It is assembled
#: from this module's own source (``inspect.getsource`` of the partition
#: contract), so an edit here can move it too.  Same tree as above.
GOLDEN_VERIFY_SHA256 = (
    "7bd563f465fb0911209e7e9de6da32541ba9300b51c042456da596ca36bca2a3")
_QUOTED_HEREDOC = re.compile(r"<<'([A-Z0-9_]+)'\n")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _quoted_heredocs(script: str) -> dict[str, str]:
    """Every quoted heredoc body in *script*, keyed by terminator, in order.

    A terminator that recurs gets ``#2``, ``#3``... in order of appearance, so
    the join-credential conversion nested inside the boot-time join script is
    a file of its own and not silently merged with the install-time one.
    """
    bodies: dict[str, str] = {}
    for match in _QUOTED_HEREDOC.finditer(script):
        terminator = match.group(1)
        start = match.end()
        body = script[start:script.index(f"\n{terminator}\n", start)]
        key, occurrence = terminator, 2
        while key in bodies:
            key = f"{terminator}#{occurrence}"
            occurrence += 1
        bodies[key] = body
    return bodies


def _executed_at_install(script: str) -> str:
    """*script* with every heredoc-delivered FILE body removed.

    What is left is what the live archiso executes at install time.  Files the
    installer writes onto the disk -- the boot-time join script, the probe, the
    SSSD configuration -- are cut out, so a command they carry for a LATER
    boot cannot be mistaken for an install-time one.  The nested join
    credential conversion is removed with the file that contains it.
    """
    kept, position = [], 0
    while True:
        match = _QUOTED_HEREDOC.search(script, position)
        if match is None:
            kept.append(script[position:])
            return "".join(kept)
        end = script.index(f"\n{match.group(1)}\n", match.end())
        kept.append(script[position:match.end()])
        position = end + 1


class _PinnedRosterRender(unittest.TestCase):
    """Render with the roster overlay pinned absent, explicitly.

    setUpModule already pins it; this class repeats the pin because a digest
    that could depend on whose machine runs the suite would pin nothing.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        patcher = mock.patch.object(
            arch_second, "identity_overlay_path",
            return_value=Path(temporary.name) / "no-principals.json")
        patcher.start()
        self.addCleanup(patcher.stop)

    def render(self, realm=None) -> str:
        return render_installer(**GOLDEN_RENDER_INPUTS, realm=realm)

    def durable_realm(self) -> InstallerRealm:
        """The permanent realm, by the route a durable bundle takes to it."""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "directory.json"
            path.write_text(json.dumps(DURABLE_DOCUMENT), encoding="utf-8")
            return durable_installer_realm(
                path,
                controller_fqdn=(
                    DURABLE_DOCUMENT["services"]["bootstrap_dc_fqdn"]))


class SyntheticGoldenDigestTests(_PinnedRosterRender):
    """The synthetic installer is byte-identical to the one before step 5.

    ``test_the_synthetic_render_pins_every_realm_bearing_byte`` pins the lines
    that carry the realm; this pins every byte, because the durable render was
    added by threading a switch through the very functions that emit the
    disposable disk's join, and a comment that moved would move nothing a
    realm-line check can see.
    """

    def test_every_rendered_file_is_byte_identical(self):
        files = {
            key: _sha256(body)
            for key, body in _quoted_heredocs(self.render()).items()}
        # The set first: a file the installer newly writes, or no longer
        # writes, is drift even if every surviving file is unchanged.
        self.assertEqual(sorted(files), sorted(GOLDEN_FILE_SHA256))
        for key, expected in GOLDEN_FILE_SHA256.items():
            with self.subTest(file=key):
                self.assertEqual(files[key], expected)

    def test_the_whole_installer_is_byte_identical(self):
        self.assertEqual(_sha256(self.render()), GOLDEN_INSTALLER_SHA256)

    def test_every_route_to_the_synthetic_realm_hits_the_digest(self):
        # The acceptance route asks for nothing; the others must not be able
        # to tell the difference, byte for byte.
        for realm in (synthetic_installer_realm(), installer_realm()):
            with self.subTest(source=realm.source):
                self.assertEqual(
                    _sha256(self.render(realm)), GOLDEN_INSTALLER_SHA256)

    def test_the_synthetic_join_script_and_unit_render_without_a_seal(self):
        # The two renderers the durable switch was threaded through, called
        # the way render_installer calls them for a synthetic realm.
        script = _render_join_once_script(
            join_media_label=JOIN_MEDIA_LABEL,
            realm_dns_domain=SYNTHETIC_DOMAIN)
        self.assertEqual(
            _sha256(script), GOLDEN_FILE_SHA256["TELOS_JOIN_ONCE_EOF"])
        self.assertEqual(
            _sha256(_render_join_once_unit()),
            GOLDEN_FILE_SHA256["TELOS_JOIN_UNIT_EOF"])
        self.assertEqual(
            script, _render_join_once_script(
                join_media_label=JOIN_MEDIA_LABEL,
                realm_dns_domain=SYNTHETIC_DOMAIN, durable=False))
        self.assertEqual(
            _render_join_once_unit(), _render_join_once_unit(durable=False))

    def test_the_synthetic_render_neither_defers_nor_seals(self):
        script = self.render()
        self.assertNotIn(JOIN_DEFERRED_MARKER, script)
        self.assertNotIn(JOIN_ONCE_SEAL_PATH, script)
        self.assertNotIn("ConditionPathExists", script)

    def test_the_bundle_verify_script_is_byte_identical(self):
        # Imported here, not at module scope: the prepare module pulls in the
        # VM runners, and a fault there should fail this test, not the module.
        from homelab.vm.arch_install_prepare import render_arch_second_verify
        self.assertEqual(
            _sha256(render_arch_second_verify()), GOLDEN_VERIFY_SHA256)


class DurableRenderTests(_PinnedRosterRender):
    """A durable render defers the install-time join and seals the boot one.

    DURABLE-WORKSTATION-FLOW.md, step 5.  The disposable Controller that
    serves a durable install does not serve the permanent realm, so a join at
    install time would join a domain that does not exist; the one join happens
    at a later boot, against the persistent Controller, and must never repeat.
    """

    def test_the_marker_neither_contains_nor_is_contained_in_another(self):
        # The install runner matches markers as bare substrings.
        others = (
            JOIN_MEDIA_CONSUMED_MARKER, JOIN_VERIFIED_MARKER,
            DOMAIN_ONLINE_MARKER, DOMAIN_ONLINE_FAILURE_MARKER,
            DOMAIN_ONLINE_DIAGNOSTIC_MARKER, NVRAM_ENTRIES_MARKER,
            NVRAM_ORDER_MARKER, STORAGE_DIAGNOSTIC_MARKER)
        for other in others:
            with self.subTest(other=other):
                self.assertNotIn(JOIN_DEFERRED_MARKER, other)
                self.assertNotIn(other, JOIN_DEFERRED_MARKER)
        self.assertEqual(JOIN_DEFERRED_MARKER, "TELOS ARCH JOIN DEFERRED")

    def test_the_durable_render_prints_the_deferred_marker_once(self):
        script = self.render(self.durable_realm())
        executed = _executed_at_install(script)
        deferred = f'echo "{JOIN_DEFERRED_MARKER}"'
        self.assertEqual(executed.count(deferred), 1)
        # Printed after the configuration the later join needs is written,
        # and before the boot-time join is installed and enabled.
        self.assertLess(
            script.index("<<'TELOS_SSSD_EOF'"), script.index(deferred))
        self.assertLess(
            script.index(deferred),
            script.index(f"arch-chroot /mnt systemctl enable "
                         f"{JOIN_ONCE_UNIT_NAME}"))

    def test_the_durable_install_joins_nothing_and_reads_no_join_media(self):
        synthetic = _executed_at_install(self.render())
        durable = _executed_at_install(self.render(self.durable_realm()))
        forbidden = (
            "net ads",
            "/run/telos-join",
            "join_dev",
            f"/dev/disk/by-label/{JOIN_MEDIA_LABEL}",
            "<<'TELOS_JOIN_CRED_EOF'",
            "/proc/sys/kernel/hostname",
            JOIN_MEDIA_CONSUMED_MARKER,
            JOIN_VERIFIED_MARKER,
        )
        for text in forbidden:
            with self.subTest(text=text):
                # Present in the disposable install, so its absence below is
                # the durable render's doing and not the stripping's.
                self.assertTrue(text in synthetic, "absent from synthetic")
                self.assertFalse(text in durable, "present in durable")
        # The media stage survives exactly once: inside the boot-time script.
        stage = _render_join_media_stage(JOIN_MEDIA_LABEL)
        script = self.render(self.durable_realm())
        self.assertEqual(script.count(stage), 1)
        self.assertIn(stage, _heredoc_body(script, "TELOS_JOIN_ONCE_EOF"))

    def test_the_durable_render_still_ships_the_identity_client(self):
        realm = self.durable_realm()
        script = self.render(realm)
        for terminator in ("TELOS_KRB5_EOF", "TELOS_SMB_EOF",
                           "TELOS_SSSD_EOF"):
            with self.subTest(file=terminator):
                self.assertIn(realm.kerberos_realm,
                              _heredoc_body(script, terminator).upper())
        self.assertIn(f"\nad_server = _srv_, {realm.controller_fqdn}\n",
                      script)
        for unit in (JOIN_ONCE_UNIT_NAME, DOMAIN_ONLINE_UNIT_NAME):
            with self.subTest(unit=unit):
                self.assertIn(
                    f"arch-chroot /mnt systemctl enable {unit}", script)

    def test_a_durable_client_asks_srv_first_and_names_its_fallback(self):
        """ADR 0081's owner decision: SRV first, the recorded name second.

        A restored directory runs a controller with a new name, ADR 0055's
        second controller and ADR 0068's permanent one are other names, and
        none of them may cost a durable workstation its logins.
        """
        realm = self.durable_realm()
        script = self.render(realm)
        sssd_conf = _heredoc_body(script, "TELOS_SSSD_EOF")
        lines = [line for line in sssd_conf.splitlines()
                 if line.startswith("ad_server")]
        self.assertEqual(lines, [f"ad_server = _srv_, {realm.controller_fqdn}"])
        self.assertEqual(arch_second.ad_server_value(realm),
                         f"_srv_, {realm.controller_fqdn}")
        for reason in ("ADR 0081", "ADR 0055", "ADR 0068", "8906d83",
                       "sssd-ad(5)"):
            self.assertIn(reason, sssd_conf)
        # The synthetic render keeps its one pinned name.
        synthetic = _heredoc_body(self.render(), "TELOS_SSSD_EOF")
        self.assertIn(f"\nad_server = {CONTROLLER_HOSTNAME}.{SYNTHETIC_DOMAIN}\n",
                      synthetic)
        self.assertNotIn("_srv_", synthetic)
        self.assertEqual(
            arch_second.ad_server_value(synthetic_installer_realm()),
            f"{CONTROLLER_HOSTNAME}.{SYNTHETIC_DOMAIN}")
        # Kerberos already finds its KDC by SRV in both renders: no static
        # kdc line exists to pin anything.
        krb5 = _heredoc_body(script, "TELOS_KRB5_EOF")
        self.assertIn("dns_lookup_kdc = true", krb5)
        self.assertNotRegex(krb5, r"(?m)^\s*(?:kdc|admin_server)\s*=")
        self.assertNotIn("[realms]", krb5)
        self.assertNotIn(realm.controller_fqdn, krb5)
        # The boot gate's diagnostic still resolves the named fallback, and
        # says that is what it is.
        gate = _heredoc_body(script, "TELOS_DOMAIN_ONLINE_EOF")
        self.assertIn(f"AD_SERVER='{realm.controller_fqdn}'", gate)
        self.assertIn("ad_server lists _srv_ first", gate)
        self.assertNotIn("ad_server lists _srv_ first",
                         _heredoc_body(self.render(), "TELOS_DOMAIN_ONLINE_EOF"))

    def test_the_durable_join_unit_carries_the_seal(self):
        unit = _heredoc_body(
            self.render(self.durable_realm()), "TELOS_JOIN_UNIT_EOF")
        condition = f"ConditionPathExists=!{JOIN_ONCE_SEAL_PATH}"
        self.assertEqual(unit.splitlines().count(condition), 1)
        # A [Unit] directive: after the section opens, before [Service].
        self.assertLess(unit.index("[Unit]"), unit.index(condition))
        self.assertLess(unit.index(condition), unit.index("[Service]"))
        # Everything the login gate relies on is unchanged.
        for line in ("Type=oneshot", "RemainAfterExit=no",
                     "After=network-online.target",
                     f"ExecStart={JOIN_ONCE_SCRIPT_PATH}",
                     "Before=" + " ".join(JOIN_ONCE_BEFORE_UNITS),
                     "WantedBy=multi-user.target"):
            with self.subTest(line=line):
                self.assertIn(line, unit.splitlines())
        self.assertNotRegex(unit, r"(?i)password|secret|credential")

    def test_the_seal_is_written_only_after_testjoin_passes(self):
        realm = self.durable_realm()
        body = _heredoc_body(
            self.render(realm), "TELOS_JOIN_ONCE_EOF")
        lines = body.splitlines()
        commands = [line for line in lines
                    if line.strip() and not line.lstrip().startswith("#")]
        # Every failure before the seal aborts the script: set -e is what
        # makes "after testjoin" mean "after testjoin passed".
        self.assertEqual(commands[0], "set -euo pipefail")
        seal_write = (
            f"  install -m 0600 -o root -g root /dev/stdin "
            f"{JOIN_ONCE_SEAL_PATH}")
        verified = f"printf '%s\\n' '{JOIN_VERIFIED_MARKER}' > /dev/console"
        ordered = [
            lines.index("net ads join -A /run/telos-join/credentials"),
            lines.index("net ads testjoin"),
            lines.index("rm -rf /run/telos-join"),
            lines.index(
                f"install -d -m 0700 -o root -g root {JOIN_ONCE_SEAL_DIR}"),
            lines.index(f"printf '%s\\n' '{realm.dns_domain}' | \\"),
            lines.index(seal_write),
            lines.index("sync"),
            lines.index(verified),
        ]
        self.assertEqual(ordered, sorted(ordered))
        # Nothing but comments and the credential removal stand between the
        # verification and the seal, and nothing else writes the seal.
        between = [line for line in lines[ordered[1] + 1:ordered[3]]
                   if not line.lstrip().startswith("#")]
        self.assertEqual(between, ["rm -rf /run/telos-join"])
        writers = [line for line in commands if JOIN_ONCE_SEAL_PATH in line]
        self.assertEqual(writers, [seal_write])
        # The seal names the realm and nothing secret.
        self.assertTrue(
            JOIN_ONCE_SEAL_PATH.startswith(JOIN_ONCE_SEAL_DIR + "/"))
        self.assertNotRegex(
            "\n".join(lines[ordered[3]:ordered[6] + 1]),
            r"(?i)password|credential|secret")

    def test_the_durable_join_is_the_disposable_join_plus_the_seal(self):
        # Rendered for one domain both ways, so only the switch differs: every
        # command the disposable script runs, in the same order, and exactly
        # the four seal lines added.
        def commands(durable: bool) -> list[str]:
            script = _render_join_once_script(
                join_media_label=JOIN_MEDIA_LABEL,
                realm_dns_domain="ad.example.home.arpa", durable=durable)
            return [line for line in script.splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]

        disposable, durable = commands(False), commands(True)
        seal = [
            f"install -d -m 0700 -o root -g root {JOIN_ONCE_SEAL_DIR}",
            "printf '%s\\n' 'ad.example.home.arpa' | \\",
            f"  install -m 0600 -o root -g root /dev/stdin "
            f"{JOIN_ONCE_SEAL_PATH}",
            "sync",
        ]
        at = durable.index(seal[0])
        self.assertEqual(durable[at:at + len(seal)], seal)
        self.assertEqual(durable[:at] + durable[at + len(seal):], disposable)

    def test_a_durable_render_is_refused_by_the_disposable_runner(self):
        # The existing check, proved against the new bytes: the runner that
        # boots the disposable Controller refuses a durable render whichever
        # way its bundle describes the realm.  Imported here for the reason
        # the verify-script test imports prepare lazily.
        from homelab.vm.arch_install_run import (
            CONTROLLER_SPEC, require_realm_agreement)

        realm = self.durable_realm()
        script = self.render(realm)

        def record(source: InstallerRealm, **overrides) -> dict:
            fields = {
                "dns_domain": source.dns_domain,
                "kerberos_realm": source.kerberos_realm,
                "netbios_name": source.workgroup,
                "controller_fqdn": source.controller_fqdn,
                "durable": source.durable,
            }
            fields.update(overrides)
            return {"realm": fields}

        # Recorded honestly: the permanent realm is refused outright.
        with self.assertRaisesRegex(RuntimeError, "PERMANENT realm"):
            require_realm_agreement(record(realm), script)
        # Recorded as not durable: the realm disagrees with the Controller.
        with self.assertRaisesRegex(
                RuntimeError, "is not the realm the Controller"):
            require_realm_agreement(record(realm, durable=False), script)
        # Recorded as the acceptance realm: the bytes disagree with the record.
        synthetic = synthetic_installer_realm()
        self.assertEqual(synthetic.controller_fqdn, CONTROLLER_SPEC.fqdn)
        with self.assertRaisesRegex(
                RuntimeError, "does not pin the authorized domain controller"):
            require_realm_agreement(record(synthetic), script)
        # And the check is not vacuous: the synthetic render still passes it.
        self.assertFalse(
            require_realm_agreement(record(synthetic), self.render()).durable)


# The owner's requested layout, 2026-09-25, with PLACEHOLDER names (ADR 0046:
# no real name in a tracked file): the domain administrator at 10000, the daily
# administrator at 10001, one additional standard user at 10002 and the
# standard user at 10003.  local_rescue keeps its contract name.
OWNER_LAYOUT = {
    "schema_version": 1,
    "principals": {
        "standard_user": {"name": "roster-a", "uid_number": 10003},
        "daily_administrator": {"name": "roster-b", "uid_number": 10001},
        "domain_administrator": {"name": "roster-c", "uid_number": 10000},
    },
    "additional_standard_users": [
        {"name": "roster-e", "uid_number": 10002},
    ],
}


class DirectoryIdentifierDeclarationTests(unittest.TestCase):
    """Per-role uid_number pins and additional standard users, in the loader.

    ``identity_declaration`` is the ONE loader, so every refusal here is one
    the installer, the acceptance lanes and both durable paths all make.  Every
    overlay is a temporary file; the owner's real overlay is never read.
    """

    ABSENT = Path("/nonexistent/telos/identity/principals.json")
    POSITIONAL = {"standard_user": 10000, "daily_administrator": 10001,
                  "domain_administrator": 10002}

    def overlay(self, document) -> Path:
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        path = Path(root) / "principals.json"
        path.write_text(
            document if isinstance(document, str) else json.dumps(document),
            encoding="utf-8")
        return path

    def declare(self, document):
        return arch_second.identity_declaration(
            overlay_path=self.overlay(document))

    def owner(self, **changes):
        """The owner's layout with some top-level or per-role changes."""
        document = json.loads(json.dumps(OWNER_LAYOUT))
        for role, entry in changes.pop("principals", {}).items():
            if entry is None:
                document["principals"].pop(role, None)
            else:
                document["principals"][role] = entry
        document.update(changes)
        return document

    def refuse(self, document, reason):
        with self.assertRaisesRegex(IdentityRosterError, reason) as raised:
            self.declare(document)
        return str(raised.exception)

    # ---- No pin: exactly today's numbers ------------------------------

    def test_no_overlay_and_an_unpinned_overlay_keep_the_positional_numbers(self):
        absent = arch_second.identity_declaration(overlay_path=self.ABSENT)
        self.assertEqual(self.POSITIONAL, dict(absent.uid_numbers))
        self.assertEqual((), absent.additional_standard_users)
        self.assertEqual(identity_roster(overlay_path=self.ABSENT),
                         dict(absent.roster))
        self.assertEqual(self.POSITIONAL, arch_second.directory_uid_numbers())
        renamed = self.declare({
            "schema_version": 1,
            "principals": {"standard_user": {"name": "roster-a"},
                           "daily_administrator": {"name": "roster-b"}},
        })
        self.assertEqual(self.POSITIONAL, dict(renamed.uid_numbers))
        self.assertEqual((), renamed.additional_standard_users)

    def test_the_shipped_template_is_still_inert(self):
        template = (Path(__file__).resolve().parents[1] / "instance-example"
                    / "identity" / "principals.json")
        declared = arch_second.identity_declaration(overlay_path=template)
        self.assertEqual(self.POSITIONAL, dict(declared.uid_numbers))
        self.assertEqual((), declared.additional_standard_users)
        self.assertEqual(identity_roster(overlay_path=self.ABSENT),
                         dict(declared.roster))
        document = json.loads(template.read_text(encoding="utf-8"))
        # The worked examples are documentation keys, and placeholders.
        self.assertNotIn("additional_standard_users", document)
        for entry in document["_example_additional_standard_users"]:
            self.assertRegex(entry["name"], r"^<[a-z-]+>$")
        # Copied into place, the worked examples are the owner's layout shape
        # and resolve cleanly -- the template does not document a refusal.
        worked = {
            "schema_version": 1,
            "principals": {
                role: dict(entry, name=f"roster-{index}")
                for index, (role, entry) in enumerate(
                    document["_example_pinned_principals"].items())},
            "additional_standard_users": [
                dict(entry, name="roster-x")
                for entry in document["_example_additional_standard_users"]],
        }
        self.assertEqual(
            {"standard_user": 10003, "daily_administrator": 10001,
             "domain_administrator": 10000},
            dict(self.declare(worked).uid_numbers))

    # ---- The owner's layout ------------------------------------------

    def test_the_owners_layout_resolves(self):
        declared = self.declare(OWNER_LAYOUT)
        self.assertEqual(
            {"standard_user": 10003, "daily_administrator": 10001,
             "domain_administrator": 10000},
            dict(declared.uid_numbers))
        self.assertEqual(
            [("roster-e", 10002)],
            [(user.name, user.uid_number)
             for user in declared.additional_standard_users])
        self.assertEqual(
            {"standard_user": "roster-a", "daily_administrator": "roster-b",
             "domain_administrator": "roster-c",
             "local_rescue": "local-rescue"},
            dict(declared.roster))
        # identity_roster is the same resolution's names, and an additional
        # user is never one of them: nothing bakes one onto a disk.
        self.assertEqual(dict(declared.roster), identity_roster(
            overlay_path=self.overlay(OWNER_LAYOUT)))

    def test_a_pin_moves_only_the_role_that_carries_it(self):
        declared = self.declare({
            "schema_version": 1,
            "principals": {"daily_administrator": {
                "name": "roster-b", "uid_number": 10050}},
        })
        self.assertEqual(
            dict(self.POSITIONAL, daily_administrator=10050),
            dict(declared.uid_numbers))

    def test_the_range_bounds_are_inclusive(self):
        for uid in (10000, 60000):
            with self.subTest(uid=uid):
                declared = self.declare(self.owner(principals={
                    "standard_user": {"name": "roster-a", "uid_number": 60000
                                      if uid == 60000 else 10003},
                    "domain_administrator": {"name": "roster-c",
                                             "uid_number": 10000}}))
                self.assertIn(uid, declared.uid_numbers.values())

    def test_the_arch_disk_does_not_depend_on_a_uid(self):
        # Nothing an installed disk carries may depend on a directory UID: the
        # disk resolves every directory account through SSSD at login.  So the
        # installer rendered for a roster must be byte-identical whether or not
        # the same overlay also pins numbers and lists additional users.
        names_only = {
            "schema_version": 1,
            "principals": {
                role: {"name": entry["name"]}
                for role, entry in OWNER_LAYOUT["principals"].items()},
        }
        rendered = []
        for document in (names_only, OWNER_LAYOUT):
            with mock.patch.object(arch_second, "identity_overlay_path",
                                   return_value=self.overlay(document)):
                rendered.append(render_installer(
                    disk_path="/dev/vda", disk_serial="LAPTOP-1",
                    hostname="workstation", expected_sizes_mib=SIZES))
        self.assertEqual(rendered[0], rendered[1])
        # The overlay really was the one rendered from...
        self.assertIn("roster-b", rendered[1])
        # ...and neither a pinned number nor an additional user reached it.
        self.assertNotIn("roster-e", rendered[1])
        self.assertNotIn("10003", rendered[1])
        # The roster fingerprint gate 8 compares is over the four names only.
        self.assertEqual(
            identity_roster_fingerprint(identity_roster(
                overlay_path=self.overlay(names_only))),
            identity_roster_fingerprint(identity_roster(
                overlay_path=self.overlay(OWNER_LAYOUT))))

    # ---- Refusals, each named ------------------------------------------

    def test_a_pin_on_another_roles_default_is_refused_never_shifted(self):
        # domain_administrator pinned to 10000 while standard_user is unpinned
        # and therefore 10000 by default: refused, naming both, rather than
        # quietly moving standard_user somewhere else.
        message = self.refuse(
            self.owner(principals={"standard_user": {"name": "roster-a"}}),
            "claimed by both")
        self.assertIn("uid_number 10000", message)
        self.assertIn("standard_user (positional default)", message)
        self.assertIn("domain_administrator (pinned)", message)
        self.assertIn("pin that role too", message)

    def test_an_additional_user_may_not_take_any_other_accounts_number(self):
        cases = {
            "an unpinned role's positional default": self.owner(
                principals={"domain_administrator": {"name": "roster-c"}}),
            "a pinned role's number": self.owner(
                additional_standard_users=[
                    {"name": "roster-e", "uid_number": 10001}]),
            "another additional user's number": self.owner(
                additional_standard_users=[
                    {"name": "roster-e", "uid_number": 10002},
                    {"name": "roster-f", "uid_number": 10002}]),
        }
        for label, document in cases.items():
            with self.subTest(clash=label):
                self.refuse(document, "claimed by both")

    def test_a_uid_number_must_be_a_json_integer(self):
        for value in (True, False, 10000.0, "10000", None, [10000]):
            with self.subTest(value=value):
                self.refuse(
                    self.owner(principals={"domain_administrator": {
                        "name": "roster-c", "uid_number": value}}),
                    "uid_number must be a JSON integer")
                self.refuse(
                    self.owner(additional_standard_users=[
                        {"name": "roster-e", "uid_number": value}]),
                    r"additional_standard_users\[0\] uid_number must be a "
                    "JSON integer")

    def test_a_uid_number_outside_the_directory_range_is_refused(self):
        for uid in (-1, 0, 1000, 9999, 60001, 65534, 65535, 3000000):
            with self.subTest(uid=uid):
                message = self.refuse(
                    self.owner(additional_standard_users=[
                        {"name": "roster-e", "uid_number": uid}]),
                    "outside the directory range 10000..60000")
                self.assertIn(f"uid_number {uid} ", message)
                self.refuse(
                    self.owner(principals={"standard_user": {
                        "name": "roster-a", "uid_number": uid}}),
                    "outside the directory range")

    def test_a_group_gid_is_never_a_user_uid(self):
        for gid, group in ((10512, "Domain Admins"), (10513, "Domain Users")):
            with self.subTest(gid=gid):
                self.refuse(
                    self.owner(principals={"standard_user": {
                        "name": "roster-a", "uid_number": gid}}),
                    f"is the gidNumber of {group}")
                self.refuse(
                    self.owner(additional_standard_users=[
                        {"name": "roster-e", "uid_number": gid}]),
                    f"is the gidNumber of {group}")
        self.assertEqual({"Domain Users": 10513, "Domain Admins": 10512},
                         arch_second.directory_group_gids())

    def test_the_break_glass_account_may_not_be_pinned(self):
        message = self.refuse(
            self.owner(principals={"local_rescue": {
                "name": "roster-d", "uid_number": 10009}}),
            "pins a uid_number for local_rescue")
        self.assertIn("LOCAL account", message)

    def test_unknown_keys_are_still_refused(self):
        cases = (
            (self.owner(principals={"standard_user": {
                "name": "roster-a", "uid": 10003}}), "may only set"),
            (self.owner(principals={"standard_user": {
                "name": "roster-a", "uid_number": 10003,
                "domain_role": "administrator"}}), "may only set"),
            (self.owner(additional_standard_users=[{
                "name": "roster-e", "uid_number": 10002,
                "role": "administrator"}]),
             r"additional_standard_users\[0\] may only set"),
            (dict(self.owner(), additional_users=[]), "unknown key"),
            (self.owner(additional_standard_users={"roster-e": 10002}),
             "not a JSON array"),
            (self.owner(additional_standard_users=["roster-e"]),
             r"additional_standard_users\[0\] is not a JSON object"),
            (self.owner(additional_standard_users=[{"uid_number": 10002}]),
             r"additional_standard_users\[0\] declares no name"),
            (self.owner(additional_standard_users=[{"name": "roster-e"}]),
             r"declares no uid_number"),
        )
        for document, reason in cases:
            with self.subTest(reason=reason):
                self.refuse(document, reason)

    def test_documentation_keys_stay_allowed_everywhere(self):
        document = self.owner(
            _example_additional_standard_users=[{"name": "<who>"}],
            additional_standard_users=[
                {"_who": "a note", "name": "roster-e", "uid_number": 10002}])
        document["principals"]["standard_user"]["_why"] = "a note"
        self.assertEqual(
            ("roster-e",),
            tuple(user.name for user in
                  self.declare(document).additional_standard_users))

    def test_an_additional_users_name_obeys_the_directory_rules(self):
        def extra(name):
            return self.owner(additional_standard_users=[
                {"name": name, "uid_number": 10002}])

        for unsafe in ("Roster-E", "0roster", "roster e", "roster;e", "",
                       "a" * 33, 47):
            with self.subTest(name=unsafe):
                self.refuse(extra(unsafe), "not safely representable")
        self.refuse(extra("a" * (SAMACCOUNTNAME_LIMIT + 1)),
                    "sAMAccountName limit")
        self.declare(extra("a" * SAMACCOUNTNAME_LIMIT))
        for reserved in ("administrator", "guest", "krbtgt", "dns-factory",
                         "root", "daemon", "bin", "sys", "nobody",
                         "systemd-network"):
            with self.subTest(name=reserved):
                self.refuse(extra(reserved), "reserved directory object")
        # Distinct from every roster name, the break-glass account included --
        # even when the overlay leaves that role at its contract name.
        for role, name in (("standard_user", "roster-a"),
                           ("domain_administrator", "roster-c"),
                           ("local_rescue", "local-rescue")):
            with self.subTest(role=role):
                self.refuse(extra(name), f"is the {role} account's name")
        self.refuse(
            self.owner(additional_standard_users=[
                {"name": "roster-e", "uid_number": 10002},
                {"name": "roster-e", "uid_number": 10004}]),
            r"additional_standard_users\[1\] repeats "
            r"additional_standard_users\[0\]")

    def test_a_refusal_names_an_additional_user_by_position_only(self):
        # A refusal is printed at the operator's terminal and may be retained;
        # the person's name is instance data (ADR 0046).
        message = self.refuse(
            self.owner(additional_standard_users=[
                {"name": "roster-e", "uid_number": 10002},
                {"name": "roster-f", "uid_number": 10001}]),
            "claimed by both")
        self.assertIn("additional_standard_users[1]", message)
        self.assertNotIn("roster-f", message)
        message = self.refuse(
            self.owner(additional_standard_users=[
                {"name": "roster-e", "uid_number": 10002},
                {"name": "roster-e", "uid_number": 10004}]),
            "repeats")
        self.assertNotIn("roster-e", message.split("roster source")[0])

    def test_a_caller_built_declaration_is_judged_by_the_same_rule(self):
        roster = dict(identity_roster(overlay_path=self.ABSENT))
        with self.assertRaisesRegex(IdentityRosterError, "cover exactly"):
            arch_second.validate_directory_identifiers(
                roster, {"standard_user": 10000}, source="a test")
        with self.assertRaisesRegex(IdentityRosterError, "claimed by both"):
            arch_second.validate_directory_identifiers(
                roster, dict(self.POSITIONAL, daily_administrator=10000),
                source="a test")
        arch_second.validate_directory_identifiers(
            roster, self.POSITIONAL,
            (arch_second.AdditionalStandardUser("roster-e", 10003),),
            source="a test")


if __name__ == "__main__":
    unittest.main()
