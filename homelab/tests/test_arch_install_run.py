"""Contracts for the bounded private Arch-second installation lifecycle."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from homelab.vm import arch_install_run
from homelab.vm.arch_install_prepare import (
    DISK_BYTES, INSTALLER_NAME, OVERLAY_NAME, VARS_NAME, VERIFY_NAME)


CONST = "c" * 64


def _digest(command):
    return hashlib.sha256(
        json.dumps(command, separators=(",", ":")).encode()).hexdigest()


GOOD_SERIAL = "\n".join((
    'BdsDxe: loading Boot0005 "UEFI PXEv4 (MAC:525400311212)"',
    'BdsDxe: starting Boot0005 "UEFI PXEv4 (MAC:525400311212)"',
    "TELOS IPXE PRE-BOOT: selected Arch kernel and initramfs loaded",
    "Welcome to Arch Linux",
    "[root@archiso ~]# echo TELOS ARCH INSTALL BEGIN",
    "TELOS ARCH INSTALL BEGIN",
    "PASS: Windows-first GPT matches the approved Arch install contract",
    "Arch installed; Windows partitions and filesystems were not modified.",
    "TELOS ARCH INSTALL COMPLETE",
    "Boot0000* Windows Boot Manager",
    "Boot0001* Linux Boot Manager",
    "/mnt/boot/loader/loader.conf:default auto-windows",
))


class ArchInstallRunTests(unittest.TestCase):
    def bundle(self, root: Path) -> Path:
        root.mkdir(mode=0o700)
        (root / OVERLAY_NAME).write_bytes(b"overlay")
        (root / VARS_NAME).write_bytes(b"vars")
        (root / VERIFY_NAME).write_text("verify")
        (root / INSTALLER_NAME).write_text("installer")
        backing = root / "windows-base.qcow2"
        backing.write_bytes(b"base")
        overlay = root / OVERLAY_NAME
        command = [
            "qemu",
            "-qmp", "unix:/tmp/telos-arch-abc/arch.qmp,server=on,wait=off",
            "-boot", "order=c,once=n,menu=off",
            "-drive",
            f"if=none,id=osdisk,format=qcow2,cache=none,file={overlay.resolve()}",
            "-device", "nvme,drive=osdisk,serial=TELOS-WIN-0001",
            "-netdev", "socket,id=factory,connect=127.0.0.1:31415",
            "-device", "e1000e,netdev=factory,mac=52:54:00:31:12:12",
        ]
        authorization = {
            "schema": 1,
            "authorization": {
                "release_version": "20260727.005",
                "release_manifest_sha256": "a" * 64,
                "disk_serial": "TELOS-WIN-0001",
                "guest_disk": "/dev/nvme0n1",
                "hostname": "telos-workstation",
                "overlay": {
                    "path": str(overlay.resolve()), "format": "qcow2",
                    "backing": str(backing.resolve()), "sha256": CONST,
                },
                "backing_windows_disk": {
                    "path": str(backing.resolve()), "sha256": CONST,
                    "virtual_size": DISK_BYTES,
                },
                "expected_sizes_mib": [1024, 16, 186098, 72956, 2048],
                "qemu_argv_sha256": _digest(command),
                "layout": {},
            },
            "guest_inputs": [
                {"name": INSTALLER_NAME, "sha256": CONST},
                {"name": VERIFY_NAME, "sha256": CONST},
            ],
        }
        (root / "authorization.json").write_text(json.dumps(authorization))
        (root / "qemu-command.json").write_text(
            json.dumps({"schema": 1, "argv": command}))
        return root

    def _overlay(self, backing: Path):
        return {
            "path": "unused", "format": "qcow2",
            "backing": str(backing.resolve()), "sha256": CONST,
        }

    def test_default_is_dry_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            backing = bundle / "windows-base.qcow2"
            with mock.patch.object(
                    arch_install_run, "inspect_overlay",
                    return_value=self._overlay(backing)), \
                    mock.patch.object(
                        arch_install_run, "sha256", return_value=CONST), \
                    mock.patch.object(
                        arch_install_run, "audit_qemu_disk_boundary"):
                self.assertEqual(arch_install_run.run(
                    bundle, controller_state=Path("/state"),
                    releases=Path("/pxe"), seed_iso=Path("/seed.iso"),
                    duration=60, apply=False), 0)
            self.assertFalse((bundle / "evidence").exists())

    def test_duration_bounds_are_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            with self.assertRaisesRegex(RuntimeError, "duration"):
                arch_install_run.run(
                    bundle, controller_state=Path("/state"),
                    releases=Path("/pxe"), seed_iso=Path("/seed.iso"),
                    duration=5, apply=True)

    def test_qmp_socket_path_is_recovered_from_the_authorized_argv(self):
        path = arch_install_run._qmp_socket_path([
            "qemu", "-qmp", "unix:/tmp/telos-arch-abc/arch.qmp,"
            "server=on,wait=off",
        ])
        self.assertEqual(Path("/tmp/telos-arch-abc/arch.qmp"), path)
        for argv in (
            ["qemu"],
            ["qemu", "-qmp"],
            ["qemu", "-qmp", "tcp:127.0.0.1:4444,server=on"],
            ["qemu", "-qmp", "unix:/tmp/x.qmp"],
            ["qemu", "-qmp", "unix:relative.qmp,server=on"],
            ["qemu", "-qmp", "unix:/" + "a" * 120 + ",server=on"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(RuntimeError):
                    arch_install_run._qmp_socket_path(argv)

    def test_switch_port_is_recovered_from_the_authorized_argv(self):
        self.assertEqual(31415, arch_install_run._switch_port([
            "qemu", "-netdev", "socket,id=factory,connect=127.0.0.1:31415",
        ]))
        with self.assertRaises(RuntimeError):
            arch_install_run._switch_port(["qemu", "-netdev", "user,id=n0"])

    def test_lifecycle_accepts_a_windows_preserving_transcript(self):
        arch_install_run._validate_lifecycle(GOOD_SERIAL)

    def test_lifecycle_rejects_more_than_one_pxe_boot(self):
        doubled = GOOD_SERIAL + (
            '\nBdsDxe: starting Boot0006 "UEFI PXEv4 (MAC:525400311212)"')
        with self.assertRaisesRegex(RuntimeError, "exactly one PXE"):
            arch_install_run._validate_lifecycle(doubled)

    def test_lifecycle_rejects_windows_partition_loss(self):
        transcript = "\n".join((
            'BdsDxe: starting Boot0005 "UEFI PXEv4 (MAC:525400311212)"',
            "Welcome to Arch Linux",
            "TELOS ARCH INSTALL BEGIN",
            "partition 3 (windows) filesystem mismatch: "
            "expected ntfs, found unformatted",
            "InstallContractError",
            "TELOS ARCH INSTALL FAIL rc=1",
        ))
        with self.assertRaisesRegex(RuntimeError, "failure"):
            arch_install_run._validate_lifecycle(transcript)

    def test_lifecycle_rejects_missing_preservation_marker(self):
        transcript = GOOD_SERIAL.replace(
            "Arch installed; Windows partitions and filesystems "
            "were not modified.", "")
        with self.assertRaisesRegex(RuntimeError, "markers missing"):
            arch_install_run._validate_lifecycle(transcript)

    def test_bundle_rejects_group_or_world_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            bundle.chmod(0o755)
            backing = bundle / "windows-base.qcow2"
            with mock.patch.object(
                    arch_install_run, "inspect_overlay",
                    return_value=self._overlay(backing)), \
                    mock.patch.object(
                        arch_install_run, "sha256", return_value=CONST), \
                    mock.patch.object(
                        arch_install_run, "audit_qemu_disk_boundary"):
                with self.assertRaisesRegex(RuntimeError, "private"):
                    arch_install_run._bundle(bundle)

    def test_bundle_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            target = self.bundle(temporary / "target")
            link = temporary / "bundle"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "non-symlink"):
                arch_install_run._bundle(link)

    def test_bundle_rejects_changed_command_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            authorization = json.loads(
                (bundle / "authorization.json").read_text())
            authorization["authorization"]["qemu_argv_sha256"] = "0" * 64
            (bundle / "authorization.json").write_text(
                json.dumps(authorization))
            backing = bundle / "windows-base.qcow2"
            with mock.patch.object(
                    arch_install_run, "inspect_overlay",
                    return_value=self._overlay(backing)), \
                    mock.patch.object(
                        arch_install_run, "sha256", return_value=CONST), \
                    mock.patch.object(
                        arch_install_run, "audit_qemu_disk_boundary"):
                with self.assertRaisesRegex(RuntimeError, "command differs"):
                    arch_install_run._bundle(bundle)

    def test_bundle_rejects_backing_disk_swap(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            other = Path(temporary) / "other.qcow2"
            other.write_bytes(b"other")
            with mock.patch.object(
                    arch_install_run, "inspect_overlay",
                    return_value=self._overlay(other)), \
                    mock.patch.object(
                        arch_install_run, "sha256", return_value=CONST), \
                    mock.patch.object(
                        arch_install_run, "audit_qemu_disk_boundary"):
                with self.assertRaisesRegex(RuntimeError, "different disk"):
                    arch_install_run._bundle(bundle)

    def test_bundle_rejects_altered_persistent_windows_disk(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            backing = bundle / "windows-base.qcow2"

            def by_path(path):
                return "z" * 64 if Path(path) == backing else CONST

            with mock.patch.object(
                    arch_install_run, "inspect_overlay",
                    return_value=self._overlay(backing)), \
                    mock.patch.object(
                        arch_install_run, "sha256", side_effect=by_path), \
                    mock.patch.object(
                        arch_install_run, "audit_qemu_disk_boundary"):
                with self.assertRaisesRegex(
                        RuntimeError, "persistent Windows disk differs"):
                    arch_install_run._bundle(bundle)

    def test_sanitize_log_redacts_and_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "serial.log"
            log.write_bytes(b"x" * 100 + b"\npassword: should-not-survive\n")
            arch_install_run._sanitize_log(log, maximum=40)
            self.assertLessEqual(log.stat().st_size, 40)
            self.assertNotIn(b"should-not-survive", log.read_bytes())
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_runtime_publication_destroyed_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            publication = root / "publication.iso"
            publication.write_bytes(b"published arch release")
            self.assertIsNone(
                arch_install_run._destroy_runtime_publication(publication))
            self.assertFalse(publication.exists())
            target = root / "target"
            target.write_bytes(b"preserve")
            publication.symlink_to(target)
            self.assertIn(
                "symlink",
                arch_install_run._destroy_runtime_publication(publication))
            self.assertTrue(target.exists())


if __name__ == "__main__":
    unittest.main()
