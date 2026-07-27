import contextlib
import io
import json
import subprocess
import tempfile
import unittest
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vm import bootstrap_dc


class BootstrapVmTests(unittest.TestCase):
    def test_disk_serial_fits_virtio_limit(self) -> None:
        self.assertLessEqual(len(bootstrap_dc.DISK_SERIAL), 20)

    def test_command_is_isolated_and_has_declared_shape(self):
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))):
            command = bootstrap_dc.qemu_command(Path("/state"), None)
        joined = " ".join(command)
        self.assertIn("-smp 4", joined)
        self.assertIn("-m 8192", joined)
        self.assertIn("-display none", joined)
        self.assertIn("-serial mon:stdio", joined)
        self.assertIn("-boot strict=on,menu=off", joined)
        self.assertIn(
            "serial=TELOS-BOOTSTRAP-DC1,bootindex=1", joined)
        self.assertIn("socket,id=bootstrap,listen=127.0.0.1:12961", joined)
        self.assertNotIn("bridge", joined)
        self.assertNotIn("tap", joined)
        self.assertNotIn("user,id=", joined)

    def test_explicit_tap_config_replaces_isolated_backend(self):
        config = {
            "mode": "precreated-tap",
            "tap": "tap-dc",
            "bridge": "br-lab",
            "uplink": "enp9s0",
            "mac": "52:54:00:11:11:19",
        }
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))):
            command = bootstrap_dc.qemu_command(
                Path("/state"), None, network_config=config)
        joined = " ".join(command)
        self.assertIn(
            "tap,id=bootstrap,ifname=tap-dc,script=no,downscript=no", joined)
        self.assertNotIn("socket,id=bootstrap", joined)

    def test_network_config_must_be_private_and_exact(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "network.json"
            path.write_text(json.dumps({
                "schema": 2,
                "mode": "precreated-tap",
                "tap": "tap-dc",
                "bridge": "br-lab",
                "uplink": "enp9s0",
                "mac": "52:54:00:11:11:19",
            }))
            path.chmod(0o600)
            config = bootstrap_dc.load_network_config(path)
            self.assertEqual(config["tap"], "tap-dc")
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "no broader than 0600"):
                bootstrap_dc.load_network_config(path)

    def test_network_config_rejects_extra_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "network.json"
            path.write_text(json.dumps({
                "schema": 2,
                "mode": "precreated-tap",
                "tap": "tap-dc",
                "bridge": "br-lab",
                "uplink": "enp9s0",
                "mac": "52:54:00:11:11:19",
                "script": "/tmp/run-me",
            }))
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "requires only"):
                bootstrap_dc.load_network_config(path)

    def test_network_config_rejects_symlink_and_malformed_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "actual.json"
            target.write_text("{}")
            target.chmod(0o600)
            link = root / "network.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "regular file"):
                bootstrap_dc.load_network_config(link)

            broken = root / "broken.json"
            broken.write_text("{")
            broken.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "cannot read"):
                bootstrap_dc.load_network_config(broken)

    def test_network_config_rejects_wrong_schema_or_mode(self):
        base = {
            "schema": 2,
            "mode": "precreated-tap",
            "tap": "tap-dc",
            "bridge": "br-lab",
            "uplink": "enp9s0",
            "mac": "52:54:00:11:11:19",
        }
        for field, value in (("schema", 1), ("mode", "user"),
                             ("mode", "bridge-helper")):
            with self.subTest(field=field, value=value), \
                    tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "network.json"
                path.write_text(json.dumps({**base, field: value}))
                path.chmod(0o600)
                with self.assertRaisesRegex(ValueError, "schema 2 precreated-tap"):
                    bootstrap_dc.load_network_config(path)

    def test_network_config_rejects_unsafe_interface_names_and_macs(self):
        base = {
            "schema": 2,
            "mode": "precreated-tap",
            "tap": "tap-dc",
            "bridge": "br-lab",
            "uplink": "enp9s0",
            "mac": "52:54:00:11:11:19",
        }
        cases = (
            ("tap", "tap;run-me", "invalid tap"),
            ("bridge", "bridge-name-is-too-long", "invalid bridge"),
            ("mac", "00:11:22:33:44:55", "synthetic"),
            ("mac", "52:54:00:11:11:zz", "synthetic"),
        )
        for field, value, message in cases:
            with self.subTest(field=field, value=value), \
                    tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "network.json"
                path.write_text(json.dumps({**base, field: value}))
                path.chmod(0o600)
                with self.assertRaisesRegex(ValueError, message):
                    bootstrap_dc.load_network_config(path)

    def test_apply_requires_precreated_tap_on_named_linux_bridge(self):
        config = {
            "mode": "precreated-tap",
            "tap": "tap-dc",
            "bridge": "br-lab",
            "uplink": "enp9s0",
            "mac": "52:54:00:11:11:19",
        }
        with tempfile.TemporaryDirectory() as temp:
            sys_net = Path(temp)
            tap = sys_net / "tap-dc"
            bridge = sys_net / "br-lab"
            uplink = sys_net / "enp9s0"
            tap.mkdir()
            bridge.mkdir()
            uplink.mkdir()
            (bridge / "bridge").mkdir()
            (uplink / "device").mkdir()
            (tap / "tun_flags").write_text("0x1002\n")
            (tap / "owner").write_text(f"{bootstrap_dc.os.getuid()}\n")
            for path in (tap, bridge, uplink):
                (path / "flags").write_text("0x1003\n")
            (tap / "master").symlink_to(bridge)
            (uplink / "master").symlink_to(bridge)
            with mock.patch.object(bootstrap_dc, "SYS_CLASS_NET", sys_net):
                args = bootstrap_dc.tap_network_args(config, verify_host=True)
            self.assertIn(
                "tap,id=bootstrap,ifname=tap-dc,script=no,downscript=no",
                args,
            )

            (tap / "master").unlink()
            with mock.patch.object(bootstrap_dc, "SYS_CLASS_NET", sys_net), \
                    self.assertRaisesRegex(ValueError, "not attached"):
                bootstrap_dc.tap_network_args(config, verify_host=True)
            (tap / "master").symlink_to(bridge)

            (tap / "tun_flags").write_text("0x1001\n")
            with mock.patch.object(bootstrap_dc, "SYS_CLASS_NET", sys_net), \
                    self.assertRaisesRegex(ValueError, "not a TAP"):
                bootstrap_dc.tap_network_args(config, verify_host=True)
            (tap / "tun_flags").write_text("0x1002\n")

            (tap / "owner").write_text(
                f"{bootstrap_dc.os.getuid() + 1}\n")
            with mock.patch.object(bootstrap_dc, "SYS_CLASS_NET", sys_net), \
                    self.assertRaisesRegex(ValueError, "does not match"):
                bootstrap_dc.tap_network_args(config, verify_host=True)
            (tap / "owner").write_text(f"{bootstrap_dc.os.getuid()}\n")

            (tap / "flags").write_text("0x1002\n")
            with mock.patch.object(bootstrap_dc, "SYS_CLASS_NET", sys_net), \
                    self.assertRaisesRegex(ValueError, "not UP"):
                bootstrap_dc.tap_network_args(config, verify_host=True)
            (tap / "flags").write_text("0x1003\n")

            (uplink / "device").rmdir()
            with mock.patch.object(bootstrap_dc, "SYS_CLASS_NET", sys_net), \
                    self.assertRaisesRegex(ValueError, "physical interface"):
                bootstrap_dc.tap_network_args(config, verify_host=True)

    def test_apply_rejects_missing_tap_or_non_bridge(self):
        config = {
            "mode": "precreated-tap",
            "tap": "tap-dc",
            "bridge": "br-lab",
            "uplink": "enp9s0",
            "mac": "52:54:00:11:11:19",
        }
        with tempfile.TemporaryDirectory() as temp:
            sys_net = Path(temp)
            with mock.patch.object(bootstrap_dc, "SYS_CLASS_NET", sys_net), \
                    self.assertRaisesRegex(ValueError, "must already exist"):
                bootstrap_dc.tap_network_args(config, verify_host=True)

            (sys_net / "tap-dc").mkdir()
            (sys_net / "br-lab").mkdir()
            (sys_net / "enp9s0").mkdir()
            with mock.patch.object(bootstrap_dc, "SYS_CLASS_NET", sys_net), \
                    self.assertRaisesRegex(ValueError, "not a Linux bridge"):
                bootstrap_dc.tap_network_args(config, verify_host=True)

    def test_dry_run_with_explicit_config_never_starts_qemu(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / "state"
            state.mkdir(mode=0o700)
            for name in ("bootstrap-dc.qcow2", "OVMF_VARS.fd", "manifest.json"):
                path = state / name
                path.write_text("x")
                path.chmod(0o600)
            config = root / "network.json"
            config.write_text(json.dumps({
                "schema": 2,
                "mode": "precreated-tap",
                "tap": "tap-dc",
                "bridge": "br-lab",
                "uplink": "enp9s0",
                "mac": "52:54:00:11:11:19",
            }))
            config.chmod(0o600)
            output = io.StringIO()
            with mock.patch.object(
                    bootstrap_dc.shutil, "which",
                    return_value="/usr/bin/qemu-system-x86_64"), \
                    mock.patch.object(
                        bootstrap_dc, "ovmf_pair",
                        return_value=(Path("/code"), Path("/vars"))), \
                    mock.patch.object(
                        bootstrap_dc.subprocess, "run") as run_qemu, \
                    contextlib.redirect_stdout(output):
                self.assertEqual(
                    bootstrap_dc.run(
                        state, None, False, network_config_path=config),
                    0,
                )
            run_qemu.assert_not_called()
            self.assertIn("dry run; repeat with --apply", output.getvalue())
            self.assertIn("ifname=tap-dc", output.getvalue())
            self.assertIn("fresh authorized preflight receipt", output.getvalue())

    def test_attachment_apply_requires_network_receipt_before_qemu(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / "state"
            state.mkdir(mode=0o700)
            for name in ("bootstrap-dc.qcow2", "OVMF_VARS.fd", "manifest.json"):
                path = state / name
                path.write_text("x")
                path.chmod(0o600)
            config = root / "network.json"
            config.write_text(json.dumps({
                "schema": 2,
                "mode": "precreated-tap",
                "tap": "tap-dc",
                "bridge": "br-lab",
                "uplink": "enp9s0",
                "mac": "52:54:00:11:11:19",
            }))
            config.chmod(0o600)
            errors = io.StringIO()
            with mock.patch.object(
                    bootstrap_dc.shutil, "which",
                    return_value="/usr/bin/qemu-system-x86_64"), \
                    mock.patch.object(bootstrap_dc.os, "geteuid",
                                      return_value=1000), \
                    mock.patch.object(
                        bootstrap_dc.subprocess, "run") as run_qemu, \
                    contextlib.redirect_stderr(errors):
                self.assertEqual(
                    bootstrap_dc.run(
                        state, None, True, network_config_path=config,
                        confirm="attach-bootstrap-dc"),
                    2,
                )
            run_qemu.assert_not_called()
            self.assertIn("requires a fresh --network-receipt",
                          errors.getvalue())

    def test_cli_passes_network_receipt_to_physical_run(self):
        with mock.patch.object(bootstrap_dc, "run", return_value=0) as run:
            self.assertEqual(bootstrap_dc.main([
                "--state-dir", "/state", "run",
                "--network-config", "/private/network.json",
                "--network-receipt", "/private/receipt.json",
                "--confirm", "attach-bootstrap-dc", "--apply",
            ]), 0)
        run.assert_called_once_with(
            Path("/state"), None, True, None,
            Path("/private/network.json"), Path("/private/receipt.json"),
            "attach-bootstrap-dc",
        )

    def test_invalid_receipt_fails_before_host_network_or_qemu(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / "state"
            state.mkdir(mode=0o700)
            for name in ("bootstrap-dc.qcow2", "OVMF_VARS.fd", "manifest.json"):
                path = state / name
                path.write_text("x")
                path.chmod(0o600)
            config = root / "network.json"
            config.write_text(json.dumps({
                "schema": 2,
                "mode": "precreated-tap",
                "tap": "tap-dc",
                "bridge": "br-lab",
                "uplink": "enp9s0",
                "mac": "52:54:00:11:11:19",
            }))
            config.chmod(0o600)
            receipt = root / "receipt.json"
            receipt.write_text("{}")
            receipt.chmod(0o600)
            git_result = subprocess.CompletedProcess(
                ["git"], 0, stdout="a" * 40 + "\n")
            with mock.patch.object(
                    bootstrap_dc.shutil, "which",
                    return_value="/usr/bin/qemu-system-x86_64"), \
                    mock.patch.object(bootstrap_dc.os, "geteuid",
                                      return_value=1000), \
                    mock.patch.object(
                        bootstrap_dc.subprocess, "run",
                        return_value=git_result) as process, \
                    mock.patch.object(
                        bootstrap_dc, "verify_preflight_receipt",
                        side_effect=ValueError("stale")) as verify, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(bootstrap_dc.run(
                    state, None, True, network_config_path=config,
                    network_receipt_path=receipt,
                    confirm="attach-bootstrap-dc"), 2)
            verify.assert_called_once_with(
                receipt, state / "bootstrap-dc.qcow2",
                bootstrap_dc.DISK_SERIAL, "a" * 40)
            process.assert_called_once()

    def test_apply_fails_closed_before_qemu_if_host_network_is_unverified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / "state"
            state.mkdir(mode=0o700)
            for name in ("bootstrap-dc.qcow2", "OVMF_VARS.fd", "manifest.json"):
                path = state / name
                path.write_text("x")
                path.chmod(0o600)
            config = root / "network.json"
            config.write_text(json.dumps({
                "schema": 2,
                "mode": "precreated-tap",
                "tap": "tap-dc",
                "bridge": "br-lab",
                "uplink": "enp9s0",
                "mac": "52:54:00:11:11:19",
            }))
            config.chmod(0o600)
            with mock.patch.object(
                    bootstrap_dc.shutil, "which",
                    return_value="/usr/bin/qemu-system-x86_64"), \
                    mock.patch.object(bootstrap_dc, "SYS_CLASS_NET", root / "sys"), \
                    mock.patch.object(
                        bootstrap_dc.subprocess, "run") as run_qemu, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    bootstrap_dc.run(
                        state, None, True, network_config_path=config),
                    2,
                )
            run_qemu.assert_not_called()

    def test_attachment_apply_refuses_root_or_missing_confirmation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / "state"
            state.mkdir(mode=0o700)
            for name in ("bootstrap-dc.qcow2", "OVMF_VARS.fd", "manifest.json"):
                path = state / name
                path.write_text("x")
                path.chmod(0o600)
            config = root / "network.json"
            config.write_text(json.dumps({
                "schema": 2,
                "mode": "precreated-tap",
                "tap": "tap-dc",
                "bridge": "br-lab",
                "uplink": "enp9s0",
                "mac": "52:54:00:11:11:19",
            }))
            config.chmod(0o600)
            common = (
                mock.patch.object(
                    bootstrap_dc.shutil, "which",
                    return_value="/usr/bin/qemu-system-x86_64"),
                mock.patch.object(
                    bootstrap_dc.subprocess, "run"),
            )
            with common[0], common[1] as run_qemu, \
                    mock.patch.object(bootstrap_dc.os, "geteuid",
                                      return_value=0), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    bootstrap_dc.run(
                        state, None, True, network_config_path=config,
                        confirm="attach-bootstrap-dc"),
                    2,
                )
            run_qemu.assert_not_called()

            with mock.patch.object(
                    bootstrap_dc.shutil, "which",
                    return_value="/usr/bin/qemu-system-x86_64"), \
                    mock.patch.object(bootstrap_dc.os, "geteuid",
                                      return_value=1000), \
                    mock.patch.object(
                        bootstrap_dc.subprocess, "run") as run_qemu, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    bootstrap_dc.run(
                        state, None, True, network_config_path=config),
                    2,
                )
            run_qemu.assert_not_called()

    def test_attachment_forbids_installer_media(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / "state"
            state.mkdir(mode=0o700)
            for name in ("bootstrap-dc.qcow2", "OVMF_VARS.fd", "manifest.json"):
                path = state / name
                path.write_text("x")
                path.chmod(0o600)
            iso = root / "install.iso"
            iso.write_text("x")
            config = root / "network.json"
            config.write_text(json.dumps({
                "schema": 2,
                "mode": "precreated-tap",
                "tap": "tap-dc",
                "bridge": "br-lab",
                "uplink": "enp9s0",
                "mac": "52:54:00:11:11:19",
            }))
            config.chmod(0o600)
            with mock.patch.object(
                    bootstrap_dc.shutil, "which",
                    return_value="/usr/bin/qemu-system-x86_64"), \
                    mock.patch.object(bootstrap_dc.os, "geteuid",
                                      return_value=1000), \
                    mock.patch.object(
                        bootstrap_dc.subprocess, "run") as run_qemu, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    bootstrap_dc.run(
                        state, iso, False, network_config_path=config),
                    2,
                )
            run_qemu.assert_not_called()

    def test_command_attaches_requested_iso_read_only(self):
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))):
            command = bootstrap_dc.qemu_command(
                Path("/state"), Path("/media/arch.iso"))
        self.assertIn(
            "if=none,id=installmedia,media=cdrom,readonly=on,"
            "file=/media/arch.iso", command)
        joined = " ".join(command)
        self.assertIn("drive=osdisk,serial=TELOS-BOOTSTRAP-DC1,bootindex=2",
                      joined)
        self.assertIn(
            "scsi-cd,bus=mediabus.0,drive=installmedia,bootindex=1",
            joined,
        )

    def test_seed_iso_is_read_only_and_cannot_preempt_installer(self):
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))):
            command = bootstrap_dc.qemu_command(
                Path("/state"),
                Path("/media/arch.iso"),
                Path("/media/telos-seed.iso"),
            )
        joined = " ".join(command)
        self.assertIn(
            "id=seedmedia,media=cdrom,readonly=on,"
            "file=/media/telos-seed.iso",
            joined,
        )
        self.assertIn(
            "scsi-cd,bus=mediabus.0,drive=installmedia,bootindex=1",
            joined,
        )
        self.assertIn("drive=osdisk,serial=TELOS-BOOTSTRAP-DC1,bootindex=2",
                      joined)
        self.assertIn(
            "scsi-cd,bus=mediabus.0,drive=seedmedia,bootindex=3",
            joined,
        )

    def test_create_defaults_to_dry_run(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            with mock.patch.object(bootstrap_dc.shutil, "which",
                                   return_value="/usr/bin/qemu-img"), \
                    mock.patch.object(
                        bootstrap_dc, "ovmf_pair",
                        return_value=(Path("/code"), Path("/vars"))), \
                    mock.patch.object(bootstrap_dc.subprocess, "run") as run:
                self.assertEqual(bootstrap_dc.create(state, False), 0)
            self.assertFalse(state.exists())
            run.assert_not_called()

    def test_destroy_needs_exact_confirmation(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            state.mkdir()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(bootstrap_dc.destroy(state, None), 2)
            self.assertTrue(state.exists())

    def test_destroy_refuses_unknown_files(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            state.mkdir()
            (state / "keep-me").write_text("important\n")
            with contextlib.redirect_stderr(io.StringIO()):
                result = bootstrap_dc.destroy(
                    state, bootstrap_dc.NAME)
            self.assertEqual(result, 2)
            self.assertTrue((state / "keep-me").exists())

    def test_create_is_transactional_and_private(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            firmware = root / "vars"
            firmware.write_bytes(b"firmware")
            state = root / "state"

            def create_disk(command, check):
                Path(command[-2]).write_bytes(b"disk")

            with mock.patch.object(bootstrap_dc.shutil, "which",
                                   return_value="/usr/bin/qemu-img"), \
                    mock.patch.object(
                        bootstrap_dc, "ovmf_pair",
                        return_value=(Path("/code"), firmware)), \
                    mock.patch.object(
                        bootstrap_dc.subprocess, "run",
                        side_effect=create_disk):
                self.assertEqual(bootstrap_dc.create(state, True), 0)

            self.assertEqual(state.stat().st_mode & 0o777, 0o700)
            for name in ("bootstrap-dc.qcow2", "OVMF_VARS.fd", "manifest.json"):
                self.assertEqual((state / name).stat().st_mode & 0o777, 0o600)
            manifest = json.loads((state / "manifest.json").read_text())
            self.assertEqual(manifest["schema"], 1)
            self.assertEqual(
                manifest["disk"]["serial"],
                bootstrap_dc.DISK_SERIAL)
            self.assertEqual(
                manifest["network"]["physical_attachment"],
                "blocked-pending-network-gate")

    def test_create_cleans_up_failed_transaction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            firmware = root / "vars"
            firmware.write_bytes(b"firmware")
            state = root / "state"
            with mock.patch.object(bootstrap_dc.shutil, "which",
                                   return_value="/usr/bin/qemu-img"), \
                    mock.patch.object(
                        bootstrap_dc, "ovmf_pair",
                        return_value=(Path("/code"), firmware)), \
                    mock.patch.object(
                        bootstrap_dc.subprocess, "run",
                        side_effect=subprocess.CalledProcessError(1, "qemu-img")):
                with self.assertRaises(subprocess.CalledProcessError):
                    bootstrap_dc.create(state, True)
            self.assertFalse(state.exists())
            self.assertEqual(list(root.glob(".state.*")), [])

    def test_status_and_destroy_refuse_symlink_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            actual = root / "actual"
            actual.mkdir()
            state = root / "state"
            state.symlink_to(actual, target_is_directory=True)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(bootstrap_dc.destroy(
                    state, bootstrap_dc.NAME), 2)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(bootstrap_dc.status(state), 1)
            self.assertTrue(actual.exists())

    def test_run_refuses_world_readable_state(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            state.mkdir(mode=0o700)
            for name in ("bootstrap-dc.qcow2", "OVMF_VARS.fd", "manifest.json"):
                path = state / name
                path.write_text("x")
                path.chmod(0o600)
            (state / "manifest.json").chmod(0o644)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(bootstrap_dc.run(state, None, False), 2)


if __name__ == "__main__":
    unittest.main()
