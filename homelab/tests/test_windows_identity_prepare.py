import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm import windows_identity_prepare as prepare


def private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)


class WindowsIdentityPrepareTests(unittest.TestCase):
    def candidate(self, root: Path) -> Path:
        bundle = root / "bundle"
        bundle.mkdir(mode=0o700)
        private_file(bundle / "windows.qcow2", b"native disk")
        private_file(bundle / "OVMF_VARS.fd", b"native vars")
        private_file(
            bundle / "evidence/workstation-serial.log",
            b"boot\nTELOS WINDOWS NATIVE READY\n")
        return bundle

    @staticmethod
    def qemu(command, **_kwargs):
        if command[1] == "check":
            return subprocess.CompletedProcess(
                command, 0, stdout='{"check-errors": 0}')
        if command[1] == "info":
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({
                "format": "qcow2", "virtual-size": 256 * 1024**3,
                "dirty-flag": False,
            }))
        if command[1] == "create":
            Path(command[-1]).write_bytes(b"overlay")
            return subprocess.CompletedProcess(command, 0)
        raise AssertionError(command)

    @staticmethod
    def control_iso(output):
        output.write_bytes(b"audited static control payload")
        output.chmod(0o444)
        return output

    def test_default_is_a_read_only_plan(self):
        with mock.patch.object(prepare, "prepare") as execute:
            self.assertEqual(0, prepare.main([]))
            execute.assert_not_called()

    def test_apply_creates_private_overlay_and_secret_free_plan(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = self.candidate(root)
            controller = root / "controller"
            controller.mkdir()
            with (
                mock.patch.object(
                    prepare.subprocess, "run", side_effect=self.qemu),
                mock.patch.object(
                    prepare, "build_control_iso",
                    side_effect=self.control_iso),
            ):
                attempt = prepare.prepare(bundle, controller)
            self.assertEqual(0, attempt.stat().st_mode & 0o077)
            for filename in (
                    "windows.qcow2", "OVMF_VARS.fd", "authorization.json",
                    "qemu-command.json"):
                self.assertEqual(
                    0, (attempt / filename).stat().st_mode & 0o077)
            self.assertEqual(0o444, (attempt / "control.iso").stat().st_mode & 0o777)
            plan = json.loads(
                (attempt / "authorization.json").read_text())
            self.assertEqual("prepared", plan["status"])
            self.assertFalse(plan["external_access"])
            self.assertFalse(plan["installation_media_attached"])
            self.assertFalse(plan["pxe_boot_enabled"])
            self.assertEqual(
                str((attempt / "control.iso").resolve()),
                plan["control_media"]["path"])
            self.assertTrue(plan["control_media"]["read_only"])
            self.assertFalse(plan["control_media"]["contains_secrets"])
            self.assertEqual(
                "private-unix-socket-jsonl",
                plan["serial_transport"]["kind"])
            self.assertEqual(
                "windows.serial",
                Path(plan["serial_transport"]["authorized_path"]).name)
            self.assertFalse(
                plan["serial_transport"]["contains_secrets"])
            self.assertEqual(
                str((bundle / "windows.qcow2").resolve()),
                plan["overlay"]["backing_path"])
            self.assertNotIn("password", json.dumps(plan).lower())
            command = json.loads(
                (attempt / "qemu-command.json").read_text())["argv"]
            self.assertIn("order=c,menu=off,strict=on", " ".join(command))
            self.assertNotIn("once=n", " ".join(command))
            self.assertEqual(1, " ".join(command).count("bootindex="))
            self.assertIn(
                "nvme,drive=osdisk,serial=TELOS-WIN-0001,bootindex=1",
                command,
            )
            self.assertIn(",romfile=", " ".join(command))
            self.assertIn("readonly=on", " ".join(command))
            self.assertIn(
                f"file={(attempt / 'control.iso').resolve()}",
                " ".join(command))

    def test_candidate_requires_native_marker_private_files_and_clean_qcow2(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = self.candidate(root)
            (bundle / "evidence/workstation-serial.log").write_text("no marker")
            with self.assertRaisesRegex(
                    prepare.WindowsIdentityPrepareError, "native Windows"):
                prepare.inspect_candidate(bundle)
            private_file(
                bundle / "evidence/workstation-serial.log",
                b"TELOS WINDOWS NATIVE READY\n")
            (bundle / "windows.qcow2").chmod(0o644)
            with self.assertRaisesRegex(
                    prepare.WindowsIdentityPrepareError, "0600"):
                prepare.inspect_candidate(bundle)
            (bundle / "windows.qcow2").chmod(0o600)
            with mock.patch.object(
                    prepare.subprocess, "run",
                    return_value=subprocess.CompletedProcess(
                        ["qemu-img"], 0, stdout='{"check-errors": 1}')):
                with self.assertRaisesRegex(
                        prepare.WindowsIdentityPrepareError, "corrupt"):
                    prepare.inspect_candidate(bundle)

    def test_failure_removes_partial_attempt(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = self.candidate(root)
            controller = root / "controller"
            controller.mkdir()
            def fail_create(command, **kwargs):
                result = self.qemu(command, **kwargs)
                if command[1] == "create":
                    raise subprocess.CalledProcessError(1, command)
                return result
            with (
                mock.patch.object(
                    prepare.subprocess, "run", side_effect=fail_create),
                mock.patch.object(
                    prepare, "build_control_iso",
                    side_effect=self.control_iso),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    prepare.prepare(bundle, controller)
            identity = bundle / "identity"
            self.assertTrue(identity.is_dir())
            self.assertEqual([], list(identity.iterdir()))

    def test_direct_command_help_works(self):
        command = (
            Path(__file__).resolve().parents[1]
            / "bin/homelab-windows-identity-prepare")
        result = subprocess.run(
            ["python3", str(command), "--help"],
            check=False, capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("--apply", result.stdout)


if __name__ == "__main__":
    unittest.main()
