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
    SyntheticIdentity,
    WindowsInstallContractError,
    audit_qemu_disk_boundary,
    authorize,
    inspect_qcow2,
    qemu_install_command,
    render_diskpart,
    render_ipxe_overlay,
    render_startup,
    render_unattend,
    render_winpeshl,
)


class WindowsInstallContractTests(unittest.TestCase):
    @staticmethod
    def authorization() -> Authorization:
        roles = (
            ("esp", 1024), ("msr", 16), ("basic-data", 180000),
            ("linux-root", 78000), ("windows-recovery", 2048),
        )
        return Authorization(
            1, "20260727.005", "a" * 64,
            {"path": "/private/disk", "virtual_size": 256 * 1024**3},
            "TELOS-WIN-0001",
            {"layout": {"partitions": [
                {"type": role, "size_mib": size} for role, size in roles]}},
            "b" * 64)

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

    @mock.patch(
        "homelab.vm.simulated_topology.ovmf_pair",
        return_value=(Path("/firmware/code.fd"), Path("/firmware/vars.fd")))
    def test_install_command_is_persistent_nvme_e1000e_qmp_and_no_windows_iso(
        self, _pair,
    ):
        command = qemu_install_command(
            disk=Path("/run/private/windows.qcow2"),
            variables=Path("/run/private/OVMF_VARS.fd"),
            qmp_socket=Path("/run/private/windows.qmp"),
            switch_port=31415,
            serial="TELOS-WIN-0001")
        text = " ".join(command)
        self.assertIn(
            "nvme,drive=osdisk,serial=TELOS-WIN-0001,bootindex=2", text)
        self.assertIn("e1000e,netdev=factory", text)
        self.assertIn("connect=127.0.0.1:31415", text)
        self.assertIn("windows.qmp,server=on,wait=off", text)
        self.assertIn("-device VGA", text)
        self.assertNotIn("publication.iso", text)
        self.assertNotIn("media=cdrom", text)
        self.assertNotIn("snapshot=on", text)
        self.assertNotIn("virtio-blk", text)
        self.assertNotIn("Win11", text)

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

    def test_authorization_records_arch_as_unallocated_windows_phase_extent(self):
        layout = {
            "layout": {"partitions": [
                {"type": "esp", "size_mib": 1024},
                {"type": "msr", "size_mib": 16},
                {"type": "basic-data", "size_mib": 180000},
                {"type": "linux-root", "size_mib": 78000},
                {"type": "windows-recovery", "size_mib": 2048},
            ]},
        }
        with mock.patch(
                "homelab.vm.windows_install_contract.inspect_qcow2",
                return_value={
                    "path": "/private/disk", "virtual_size": 256 * 1024**3,
                    "format": "qcow2", "sha256": "c" * 64,
                }), mock.patch(
                    "homelab.vm.windows_install_contract."
                    "audit_qemu_disk_boundary"), mock.patch(
                        "homelab.vm.windows_install_contract.build_record",
                        return_value=layout):
            receipt = authorize(
                disk=Path("/private/disk"), serial="TELOS-WIN-0001",
                command=["qemu"], release_version="20260727.005",
                release_manifest_sha256="a" * 64,
                layout_profile=Path("layout.json"),
                workstation_profile=Path("workstation.json"))
        intermediate = receipt.layout["windows_first_layout"]
        self.assertEqual(
            "unallocated",
            intermediate["reserved_arch_extent"]["state"])
        self.assertNotIn(
            "linux-root",
            {item["role"] for item in intermediate["partitioned_extents"]})

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

    def test_complete_private_input_set_is_rendered_and_digest_only(self):
        identity = SyntheticIdentity(
            "TELOS-WIN-01", "telosadmin", "SynthPass-123",
            r"TELOS\pxe-install", "InstallPass-123")
        with tempfile.TemporaryDirectory() as temporary:
            with PrivateRun(Path(temporary) / "runs") as run:
                generated = run.render_windows_inputs(
                    self.authorization(), identity,
                    install_source_unc=r"\\controller\windows-20260727.005")
                self.assertEqual(
                    {
                        "boot.ipxe", "install.bat", "winpeshl.ini",
                        "windows-layout.txt", "Autounattend.xml",
                        "install-password.txt",
                    },
                    {path.name for path in generated})
                self.assertTrue(all(
                    path.stat().st_mode & 0o777 == 0o600
                    for path in generated))
                password_file = next(
                    path for path in generated
                    if path.name == "install-password.txt")
                self.assertEqual(
                    password_file.read_bytes(),
                    identity.install_password.encode("ascii") + b"\n")
                receipt = run.public_receipt(
                    self.authorization(), generated)
                serialized = json.dumps(receipt)
                self.assertNotIn(identity.local_password, serialized)
                self.assertNotIn(identity.install_password, serialized)

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
        authorization = self.authorization()
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

    def test_diskpart_reserves_arch_gap_and_never_selects_another_disk(self):
        script = render_diskpart(self.authorization())
        self.assertEqual(1, script.count("select disk"))
        self.assertIn("select disk 0", script)
        self.assertIn("create partition efi size=1024", script)
        self.assertIn("create partition msr size=16", script)
        recovery_start_kib = (1 + 1024 + 16 + 180000 + 78000) * 1024
        self.assertIn(
            f"create partition primary offset={recovery_start_kib} size=2048",
            script)
        self.assertNotIn("create partition primary size=78000", script)
        self.assertNotIn("delete partition", script)

    def test_startup_rechecks_one_disk_and_capacity_before_mutation(self):
        script = render_startup(
            self.authorization(),
            install_source_unc=r"\\controller\windows-20260727.005",
            install_user=r"TELOS\pxe-install")
        self.assertEqual(2, script.count("disk_count=0"))
        self.assertEqual(2, script.count('"1" exit /b 20'))
        self.assertEqual(2, script.count('"256 GB" exit /b 22'))
        self.assertNotIn("InstallPass-123", script)
        self.assertIn('net use W: "\\\\controller\\windows-20260727.005" *',
                      script)
        self.assertIn('< "%inputs%install-password.txt"', script)
        self.assertIn("TELOS WINPE FAIL code=%telos_result%", script)
        self.assertIn("TELOS WINPE phase=source-mount", script)
        self.assertIn(
            'if not exist "%inputs%install-password.txt" exit /b 29', script)
        self.assertIn("ipconfig", script)
        self.assertIn("ping -n 1 10.1.31.2 || exit /b 28", script)
        self.assertIn("pause", script)
        self.assertNotIn("findstr", script)
        self.assertIn('if /I "%%A"=="Disk" if /I "%%C"=="Online"', script)
        self.assertLess(
            script.rindex('"256 GB" exit /b 22'),
            script.index('diskpart /s "%inputs%windows-layout.txt"'))

    def test_startup_accepts_unqualified_standalone_smb_user(self):
        script = render_startup(
            self.authorization(),
            install_source_unc=r"\\10.1.31.2\windows-release",
            install_user="pxe-install")
        self.assertIn('/user:"pxe-install"', script)

    def test_unattend_is_explicit_pro_us_partition_three_and_has_no_product_key(self):
        identity = SyntheticIdentity(
            "TELOS-WIN-01", "telosadmin", "SynthPass-123",
            r"TELOS\pxe-install", "InstallPass-123")
        answer = render_unattend(identity)
        self.assertIn("<Value>Windows 11 Pro</Value>", answer)
        self.assertIn("<UILanguage>en-US</UILanguage>", answer)
        self.assertIn("<DiskID>0</DiskID><PartitionID>3</PartitionID>", answer)
        self.assertNotIn("ProductKey", answer)
        self.assertNotIn(identity.install_password, answer)

    def test_private_ipxe_overlay_injects_inputs_without_altering_release(self):
        script = render_ipxe_overlay(
            "20260727.005", "http://10.1.31.2/private/run-abc123")
        immutable = "http://10.1.31.2/windows/20260727.005"
        for artifact in (
                "wimboot", "bootmgr", "boot/BCD", "boot/boot.sdi",
                "sources/boot.wim"):
            self.assertIn(f"{immutable}/{artifact}", script)
        for name in (
                "install.bat", "winpeshl.ini", "windows-layout.txt",
                "Autounattend.xml", "install-password.txt"):
            self.assertIn(
                f"http://10.1.31.2/private/run-abc123/{name} {name}", script)
        self.assertNotIn("InstallPass-123", script)
        self.assertEqual('[LaunchApps]\r\n"install.bat"\r\n', render_winpeshl())

    def test_private_ipxe_overlay_cannot_name_an_external_server(self):
        with self.assertRaisesRegex(
                WindowsInstallContractError, "isolated Controller"):
            render_ipxe_overlay(
                "20260727.005", "https://external.example/private/run")


if __name__ == "__main__":
    unittest.main()
