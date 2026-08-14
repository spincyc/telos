import base64
import inspect
import json
from pathlib import Path
import re
import struct
import sys
import unittest

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
    identity_contract_path, identity_overlay_path, identity_roster,
    identity_roster_fingerprint,
)
from lib.package_contract import PROFILE_OVERLAYS, load_registry, merge_contract
from lib.workstation_repo import REPO_NAME

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
        self.assertIn("local-rescue", script)
        self.assertIn("%wheel ALL=(ALL:ALL) ALL", script)
        self.assertIn("operator ALL=(ALL:ALL) ALL", script)
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
        for principal in ("student", "operator", "directory-admin",
                          "local-rescue"):
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

    def test_rejects_invalid_realm_parameters(self):
        for overrides in (
            {"realm_dns_domain": "AD.Factory.Test"},
            {"realm_dns_domain": "single-label"},
            {"realm_workgroup": "factory"},
            {"realm_workgroup": "TOO-LONG-WORKGROUP"},
            {"join_media_label": "bad label"},
            {"join_media_label": ""},
        ):
            with self.assertRaises(InstallContractError):
                render_installer(
                    disk_path="/dev/vda", disk_serial="LAPTOP-1",
                    hostname="workstation", expected_sizes_mib=SIZES,
                    **overrides,
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
        self.assertEqual(
            device, f"//{STORAGE_HOST_LABEL}.{SYNTHETIC_DOMAIN}/student")
        self.assertEqual(mountpoint, f"{STORAGE_MOUNT_ROOT}/student")
        self.assertEqual(fstype, "cifs")
        flags = options.split(",")
        # Structural login independence: the systemd fstab generator can
        # only emit a Wants= automount with a bounded attach.
        for flag in ("nofail", "x-systemd.automount", "_netdev", "soft",
                     "x-systemd.mount-timeout=10s", "sec=krb5"):
            self.assertIn(flag, flags)
        self.assertIn(f"mkdir -p /mnt{STORAGE_MOUNT_ROOT}/student", script)
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


if __name__ == "__main__":
    unittest.main()
