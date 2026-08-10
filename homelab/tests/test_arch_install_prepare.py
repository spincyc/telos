"""Contracts for guarded Arch-second installation bundle preparation."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from homelab.vm import arch_install_prepare


def _digest(command):
    return hashlib.sha256(
        json.dumps(command, separators=(",", ":")).encode()).hexdigest()


LAYOUT_RECORD = {
    "layout": {
        "partitions": [
            {"type": "esp", "size_mib": 1024},
            {"type": "msr", "size_mib": 16},
            {"type": "basic-data", "size_mib": 186098},
            {"type": "linux-root", "size_mib": 72956},
            {"type": "windows-recovery", "size_mib": 2048},
        ]
    }
}


class ArchInstallPrepareTests(unittest.TestCase):
    def test_default_is_read_only_plan(self):
        with mock.patch.object(arch_install_prepare, "prepare") as prepare, \
                mock.patch.object(
                    arch_install_prepare, "ovmf_pair", return_value=None):
            self.assertEqual(arch_install_prepare.main([]), 0)
            prepare.assert_not_called()

    def test_apply_is_the_only_prepare_path(self):
        expected = Path("/private/run")
        with mock.patch.object(
                arch_install_prepare, "prepare",
                return_value=expected) as prepare, \
                mock.patch.object(
                    arch_install_prepare, "ovmf_pair", return_value=None):
            self.assertEqual(arch_install_prepare.main(["--apply"]), 0)
            prepare.assert_called_once()

    def test_direct_command_help_works(self):
        command = (
            Path(__file__).resolve().parents[1]
            / "bin/homelab-arch-install-prepare")
        result = subprocess.run(
            ["python3", str(command), "--help"],
            check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--apply", result.stdout)
        self.assertIn("--windows-disk", result.stdout)

    def test_qemu_command_shape_pins_nvme_e1000e_pxe_and_short_qmp(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            variables = root / "OVMF_VARS.fd"
            variables.write_bytes(b"vars")
            disk = root / "arch.qcow2"
            disk.write_bytes(b"overlay")
            qmp = Path("/tmp/telos-arch-deadbeef/arch.qmp")
            command = arch_install_prepare.qemu_arch_install_command(
                disk=disk, variables=variables, qmp_socket=qmp,
                switch_port=31415, serial=arch_install_prepare.DISK_SERIAL)
            joined = " ".join(command)
            self.assertIn("nvme,drive=osdisk,serial=TELOS-WIN-0001", joined)
            self.assertIn("e1000e,netdev=factory", joined)
            self.assertIn("socket,id=factory,connect=127.0.0.1:31415", joined)
            # The install boot is network-only so PXE deterministically wins
            # and firmware never falls through to the bootable Windows ESP.
            self.assertIn("order=n,menu=off", command)
            self.assertNotIn("order=c,once=n,menu=off", command)
            self.assertNotIn("order=c", command)
            qmp_value = command[command.index("-qmp") + 1]
            self.assertTrue(qmp_value.startswith("unix:/tmp/telos-arch-"))
            self.assertIn(",server=on,wait=off", qmp_value)
            socket_path = qmp_value[len("unix:"):].split(",", 1)[0]
            self.assertLessEqual(len(socket_path.encode()), 100)

    def test_qemu_command_rejects_oversize_qmp_socket(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            variables = root / "OVMF_VARS.fd"
            variables.write_bytes(b"vars")
            with self.assertRaisesRegex(RuntimeError, "AF_UNIX"):
                arch_install_prepare.qemu_arch_install_command(
                    disk=root / "arch.qcow2", variables=variables,
                    qmp_socket=Path("/tmp/" + "a" * 120 + "/arch.qmp"),
                    switch_port=31415,
                    serial=arch_install_prepare.DISK_SERIAL)

    def test_verify_script_is_self_contained_and_runnable(self):
        script = arch_install_prepare.render_arch_second_verify()
        self.assertNotIn("package_contract", script)
        self.assertIn("def validate_windows_first", script)
        self.assertIn("def parse_lsblk", script)
        # Compiles as a standalone module with only the standard library.
        compile(script, "arch-second-verify.py", "exec")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "arch-second-verify.py"
            path.write_text(script, encoding="utf-8")
            result = subprocess.run(
                ["python3", str(path), "--help"],
                check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--sizes-mib", result.stdout)

    def test_run_root_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "real").mkdir()
            link = root / "runs"
            link.symlink_to(root / "real", target_is_directory=True)
            args = argparse.Namespace(
                windows_disk=root / "windows.qcow2", ovmf_vars=None,
                releases=root / "pxe", seed=root / "seed.iso",
                layout=root / "layout.json",
                workstation_profile=root / "wp.json",
                run_root=link, hostname="telos-workstation",
                switch_port=31415)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                arch_install_prepare.prepare(args)

    def test_prepare_requires_a_pristine_ovmf_template(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            windows_disk = root / "windows.qcow2"
            windows_disk.write_bytes(b"disk")
            args = argparse.Namespace(
                windows_disk=windows_disk, ovmf_vars=None,
                releases=root / "pxe", seed=root / "seed.iso",
                layout=root / "layout.json",
                workstation_profile=root / "wp.json", run_root=root / "runs",
                hostname="telos-workstation", switch_port=31415)
            with mock.patch.object(
                    arch_install_prepare, "inspect_base_windows_disk",
                    return_value={"path": str(windows_disk.resolve())}), \
                    mock.patch.object(
                        arch_install_prepare, "ovmf_pair", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "pristine OVMF"):
                    arch_install_prepare.prepare(args)

    def test_apply_overlays_the_disk_and_binds_authorization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases = root / "pxe"
            releases.mkdir()
            (releases / "selected-release-set.json").write_text(json.dumps({
                "schema": 1, "version": "20260727.005",
                "manifest_sha256": "a" * 64,
            }))
            windows_dir = root / "win"
            windows_dir.mkdir()
            windows_disk = windows_dir / "windows.qcow2"
            windows_disk.write_bytes(b"disk")
            # The Windows-installed firmware vars carry a Windows Boot Manager
            # NVRAM entry; the install boot must never inherit them.
            (windows_dir / "OVMF_VARS.fd").write_bytes(
                b"windows-boot-manager-nvram")
            pristine_vars = root / "OVMF_VARS.4m.fd"
            pristine_vars.write_bytes(b"pristine-fresh-vars-no-boot-entries")
            base = {
                "path": str(windows_disk.resolve()),
                "virtual_size": arch_install_prepare.DISK_BYTES,
                "format": "qcow2", "sha256": "b" * 64,
            }
            args = argparse.Namespace(
                windows_disk=windows_disk, ovmf_vars=None, releases=releases,
                seed=root / "seed.iso", layout=root / "layout.json",
                workstation_profile=root / "wp.json", run_root=root / "runs",
                hostname="telos-workstation", switch_port=31415)

            def execute(command, **_kwargs):
                if command[:2] == ["qemu-img", "create"]:
                    Path(command[-1]).write_bytes(b"overlay")
                return subprocess.CompletedProcess(command, 0)

            def overlay(path):
                return {
                    "path": str(Path(path).resolve()), "format": "qcow2",
                    "backing": str(windows_disk.resolve()), "sha256": "c" * 64,
                }

            with mock.patch.object(
                    arch_install_prepare.subprocess, "run",
                    side_effect=execute), \
                    mock.patch.object(
                        arch_install_prepare, "ovmf_pair",
                        return_value=(
                            root / "OVMF_CODE.4m.fd", pristine_vars)), \
                    mock.patch.object(
                        arch_install_prepare, "inspect_base_windows_disk",
                        return_value=base), \
                    mock.patch.object(
                        arch_install_prepare, "inspect_overlay",
                        side_effect=overlay), \
                    mock.patch.object(
                        arch_install_prepare, "build_record",
                        return_value=LAYOUT_RECORD), \
                    mock.patch.object(
                        arch_install_prepare, "sha256", return_value="d" * 64):
                run = arch_install_prepare.prepare(args)

            self.assertTrue(run.is_dir())
            for name in (
                    "arch.qcow2", "OVMF_VARS.fd", "arch-second-verify.py",
                    "arch-install.sh", "authorization.json",
                    "qemu-command.json"):
                self.assertTrue((run / name).is_file(), name)

            # The copied install-boot firmware vars come from the pristine
            # template, never the Windows bundle's boot-entry-bearing vars, so
            # the install boot cannot inherit a Windows Boot Manager entry.
            copied_vars = (run / "OVMF_VARS.fd").read_bytes()
            self.assertEqual(copied_vars, b"pristine-fresh-vars-no-boot-entries")
            self.assertNotIn(b"windows-boot-manager-nvram", copied_vars)

            authorization = json.loads(
                (run / "authorization.json").read_text())["authorization"]
            self.assertEqual(authorization["disk_serial"], "TELOS-WIN-0001")
            self.assertEqual(authorization["overlay"]["sha256"], "c" * 64)
            self.assertEqual(
                authorization["backing_windows_disk"]["sha256"], "b" * 64)
            self.assertEqual(
                authorization["backing_windows_disk"]["path"],
                str(windows_disk.resolve()))
            self.assertEqual(
                authorization["expected_sizes_mib"],
                [1024, 16, 186098, 72956, 2048])

            command = json.loads(
                (run / "qemu-command.json").read_text())["argv"]
            self.assertEqual(
                authorization["qemu_argv_sha256"], _digest(command))
            joined = " ".join(command)
            self.assertIn("nvme,drive=osdisk,serial=TELOS-WIN-0001", joined)
            self.assertIn("e1000e,netdev=factory", joined)
            self.assertIn("order=n,menu=off", command)

            names = {
                entry["name"] for entry in json.loads(
                    (run / "authorization.json").read_text())["guest_inputs"]
            }
            self.assertEqual(
                names, {"arch-install.sh", "arch-second-verify.py"})


if __name__ == "__main__":
    unittest.main()
