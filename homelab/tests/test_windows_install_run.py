"""Contracts for the bounded private Windows installation lifecycle."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from homelab.vm import windows_install_run


class WindowsInstallRunTests(unittest.TestCase):
    def bundle(self, root: Path) -> Path:
        root.mkdir(mode=0o700)
        disk = root / "windows.qcow2"
        for name in ("windows.qcow2", "OVMF_VARS.fd", "publication.iso"):
            (root / name).write_bytes(name.encode())
        command = [
            "qemu", "-drive",
            f"if=none,id=osdisk,file={disk.resolve()}",
            "-device", "nvme,drive=osdisk,serial=TELOS-WIN-0001",
        ]
        import hashlib
        digest = hashlib.sha256(
            json.dumps(command, separators=(",", ":")).encode()).hexdigest()
        (root / "authorization.json").write_text(json.dumps({
            "authorization": {
                "disk": {"disk": "record"},
                "disk_serial": "TELOS-WIN-0001",
                "qemu_argv_sha256": digest,
                "release_version": "20260727.005",
            },
        }))
        (root / "qemu-command.json").write_text(json.dumps({"argv": command}))
        return root

    def test_default_is_dry_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            with mock.patch.object(
                    windows_install_run, "inspect_qcow2",
                    return_value={"disk": "record"}), mock.patch.object(
                        windows_install_run, "audit_qemu_disk_boundary"):
                self.assertEqual(windows_install_run.run(
                    bundle, controller_state=Path("/state"),
                    duration=60, apply=False), 0)
            self.assertFalse((bundle / "evidence").exists())

    def test_long_bounded_run_uses_reduced_screenshot_cadence(self):
        self.assertEqual(windows_install_run.MAX_DURATION, 10800)
        self.assertEqual(windows_install_run._screenshot_interval(3600), 10)
        self.assertEqual(windows_install_run._screenshot_interval(7200), 30)

    def test_bundle_rejects_group_or_world_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            bundle.chmod(0o755)
            with mock.patch.object(
                    windows_install_run, "inspect_qcow2",
                    return_value={"disk": "record"}):
                with self.assertRaisesRegex(RuntimeError, "private"):
                    windows_install_run._bundle(bundle)

    def test_bundle_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            target = self.bundle(temporary / "target")
            link = temporary / "bundle"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "non-symlink"):
                windows_install_run._bundle(link)

    def test_bundle_rejects_changed_command_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            with mock.patch.object(
                    windows_install_run, "inspect_qcow2",
                    return_value={"disk": "record"}), mock.patch.object(
                        windows_install_run, "audit_qemu_disk_boundary"):
                authorization = json.loads(
                    (bundle / "authorization.json").read_text())
                authorization["authorization"]["disk"] = {"disk": "record"}
                authorization["authorization"]["qemu_argv_sha256"] = "0" * 64
                (bundle / "authorization.json").write_text(
                    json.dumps(authorization))
                with self.assertRaisesRegex(RuntimeError, "command differs"):
                    windows_install_run._bundle(bundle)

    def test_sanitize_log_redacts_and_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "serial.log"
            log.write_bytes(
                b"x" * 100 + b"\npassword: should-not-survive\n")
            windows_install_run._sanitize_log(log, maximum=40)
            self.assertLessEqual(log.stat().st_size, 40)
            self.assertNotIn(b"should-not-survive", log.read_bytes())
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_qmp_connection_waits_for_socket_readiness(self):
        client = object()
        with mock.patch.object(
                windows_install_run.QmpClient, "connect",
                side_effect=[FileNotFoundError(), client]) as connect, \
                mock.patch.object(windows_install_run.time, "sleep"):
            self.assertIs(
                windows_install_run._connect_qmp(
                    Path("/private/windows.qmp"), timeout=1),
                client)
        self.assertEqual(connect.call_count, 2)

    def test_lifecycle_requires_overlay_native_marker_and_one_pxe_boot(self):
        serial = "\n".join((
            'BdsDxe: loading Boot0003 "UEFI PXEv4"',
            'BdsDxe: starting Boot0003 "UEFI PXEv4"',
            "http://10.1.31.2/private/run-abc/boot.ipxe",
            "Using install.bat",
            "Using winpeshl.ini",
            "Windows Imaging Format bootloader",
            windows_install_run.NATIVE_READY_MARKER,
        ))
        windows_install_run._validate_lifecycle(serial)

        with self.assertRaisesRegex(RuntimeError, "exactly one PXE"):
            windows_install_run._validate_lifecycle(
                serial + '\nBdsDxe: starting Boot0003 "UEFI PXEv4"')
        with self.assertRaisesRegex(RuntimeError, "native Windows"):
            windows_install_run._validate_lifecycle(
                serial.replace(windows_install_run.NATIVE_READY_MARKER, ""))


if __name__ == "__main__":
    unittest.main()
