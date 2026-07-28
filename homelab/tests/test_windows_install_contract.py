"""Tests for the disposable Windows installation authorization boundary."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from homelab.vm.windows_install_contract import (
    Authorization,
    PrivateRun,
    WindowsInstallContractError,
    audit_qemu_disk_boundary,
    inspect_qcow2,
)


class WindowsInstallContractTests(unittest.TestCase):
    def test_qemu_requires_one_exact_serial_bound_writable_disk(self):
        disk = Path("/run/private/windows.qcow2")
        command = [
            "qemu-system-x86_64",
            "-drive", f"file={disk},if=none,format=qcow2,id=osdisk",
            "-device", "nvme,drive=osdisk,serial=TELOS-WIN-0001",
            "-drive", "file=/run/OVMF_VARS.fd,if=pflash,format=raw",
            "-drive", "file=/run/pxe.iso,media=cdrom,readonly=on",
        ]
        audit_qemu_disk_boundary(
            command, disk=disk, serial="TELOS-WIN-0001")
        with self.assertRaisesRegex(
                WindowsInstallContractError, "exactly one writable"):
            audit_qemu_disk_boundary(
                command + ["-drive", "file=/tmp/other.qcow2"],
                disk=disk, serial="TELOS-WIN-0001")
        with self.assertRaisesRegex(
                WindowsInstallContractError, "authorized synthetic serial"):
            audit_qemu_disk_boundary(
                command, disk=disk, serial="TELOS-WIN-9999")

    def test_qcow2_must_be_standalone_and_large_enough(self):
        with tempfile.TemporaryDirectory() as temporary:
            disk = Path(temporary) / "disk.qcow2"
            disk.write_bytes(b"disk")
            response = subprocess.CompletedProcess(
                [], 0, json.dumps({
                    "format": "qcow2",
                    "virtual-size": 256 * 1024**3,
                    "actual-size": 4096,
                }), "")
            with mock.patch(
                    "homelab.vm.windows_install_contract.subprocess.run",
                    return_value=response):
                self.assertEqual(
                    256 * 1024**3, inspect_qcow2(disk)["virtual_size"])
            small = subprocess.CompletedProcess(
                [], 0, json.dumps({
                    "format": "qcow2", "virtual-size": 40 * 1024**3,
                }), "")
            with mock.patch(
                    "homelab.vm.windows_install_contract.subprocess.run",
                    return_value=small), self.assertRaisesRegex(
                        WindowsInstallContractError, "256 GiB"):
                inspect_qcow2(disk)

    def test_private_inputs_are_mode_limited_and_always_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runs"
            with PrivateRun(root) as run:
                secret = run.write_secret("Autounattend.xml", "synthetic")
                private_path = run.path
                self.assertEqual(root.stat().st_mode & 0o777, 0o700)
                self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
            self.assertIsNotNone(private_path)
            self.assertFalse(private_path.exists())

    def test_failure_also_tears_down_private_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runs"
            private_path = None
            with self.assertRaisesRegex(RuntimeError, "setup failed"):
                with PrivateRun(root) as run:
                    run.write_secret("startup.cmd", "secret")
                    private_path = run.path
                    raise RuntimeError("setup failed")
            self.assertIsNotNone(private_path)
            self.assertFalse(private_path.exists())

    def test_receipt_has_only_generated_digests_and_rejects_secret_evidence(self):
        authorization = Authorization(
            1, "20260727.005", "a" * 64,
            {"path": "/private/disk", "virtual_size": 256 * 1024**3},
            "TELOS-WIN-0001", {"layout": "approved"}, "b" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with PrivateRun(root / "runs") as run:
                password = "synthetic-password-123"
                run.remember_secrets(password)
                answer = run.write_secret("Autounattend.xml", password)
                receipt = run.public_receipt(authorization, [answer])
                serialized = json.dumps(receipt)
                self.assertNotIn(password, serialized)
                self.assertNotIn(str(answer), serialized)
                evidence = root / "evidence.json"
                evidence.write_text('{"status":"pass"}')
                run.assert_secret_free(evidence)
                evidence.write_text(password)
                with self.assertRaisesRegex(
                        WindowsInstallContractError, "known secret"):
                    run.assert_secret_free(evidence)


if __name__ == "__main__":
    unittest.main()
