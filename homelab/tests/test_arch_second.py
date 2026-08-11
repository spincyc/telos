import inspect
import json
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workstations.arch_second import (
    ESP, JOIN_MEDIA_LABEL, LINUX_ROOT_X86_64, MSR, PROBE_CHECKS,
    PROBE_HELPER_PATH, STORAGE_HOST_LABEL, STORAGE_LOGIN_SECONDS_MARKER,
    STORAGE_MOUNT_ROOT, STORAGE_PROBE_ROOT, SYNTHETIC_DOMAIN,
    SYNTHETIC_WORKGROUP, WINDOWS, WINDOWS_RECOVERY, Disk,
    InstallContractError, Partition, parse_lsblk, render_installer,
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
        self.assertIn("bootctl --root=/mnt set-default auto-windows", script)
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
        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES,
        )
        self.assertIn(f"realm = {spec.realm}", script)

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
        # marker the gate-8 drive records as evidence.
        self.assertIn(
            f"printf '{STORAGE_LOGIN_SECONDS_MARKER}%s=%s\\n' "
            '"$token" "$elapsed"', script)
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
        self.assertIn(
            'storage_mount "$DAILY_ADMIN" "$DAILY_ADMIN" || return 1',
            denial)
        self.assertIn(
            'if storage_mount "$STANDARD_USER" "$DAILY_ADMIN"; then', denial)

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
