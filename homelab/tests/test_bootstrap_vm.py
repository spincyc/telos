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
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fake_image_tools

from vm import bootstrap_dc, simulation_overlay


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

    def test_destroy_clears_a_stale_simulation_lock(self):
        """ControllerOverlay leaves its advisory lock file behind by design, so
        before this was expected, any simulation run against the canonical image
        made destruction refuse forever -- which is exactly what blocked
        reinstalling an image whose console password had been lost."""
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            state.mkdir()
            for key in ("disk", "vars", "manifest"):
                bootstrap_dc.paths(state)[key].touch()
            (state / simulation_overlay.LOCK_NAME).touch()
            self.assertEqual(
                bootstrap_dc.destroy(state, bootstrap_dc.NAME), 0)
            self.assertFalse(state.exists())

    def test_destroy_refuses_while_the_lock_is_actually_held(self):
        """A stale lock file is safe to sweep; a held one is not. Erasing the
        disk under a live run would destroy it from underneath QEMU, so the
        presence of the name must never be mistaken for a free disk."""
        import fcntl
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            state.mkdir()
            for key in ("disk", "vars", "manifest"):
                bootstrap_dc.paths(state)[key].touch()
            lock_path = state / simulation_overlay.LOCK_NAME
            lock_path.touch()
            with lock_path.open("a") as held:
                fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                with contextlib.redirect_stderr(io.StringIO()) as captured:
                    result = bootstrap_dc.destroy(state, bootstrap_dc.NAME)
                fcntl.flock(held.fileno(), fcntl.LOCK_UN)
            self.assertEqual(result, 2)
            self.assertIn("lock is held", captured.getvalue())
            # The disk must still be there: refusing has to be non-destructive.
            self.assertTrue(bootstrap_dc.paths(state)["disk"].exists())

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

    def test_status_separates_a_created_image_from_an_installed_one(self):
        """``status`` used to call a never-installed 197,888-byte image ready.

        Readiness meant only "three files exist with the right modes", which a
        blank canonical satisfies, and every consumer inherited the blind
        spot. It now reports what the image actually holds, and who installed
        it when the receipt says so.
        """
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            state.mkdir(mode=0o700)
            files = bootstrap_dc.paths(state)
            for key in ("vars", "manifest"):
                files[key].write_bytes(b"x")
                files[key].chmod(0o600)
            fake_image_tools.blank_image(files["disk"])
            files["disk"].chmod(0o600)

            def report():
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = bootstrap_dc.status(state)
                return code, out.getvalue()

            with mock.patch.object(
                    bootstrap_dc.subprocess, "run",
                    side_effect=fake_image_tools.image_tool):
                code, text = report()
                self.assertEqual(code, 1)
                self.assertIn("created but not installed", text)
                self.assertIn("entirely unallocated", text)

                fake_image_tools.installed_image(files["disk"])
                files["disk"].chmod(0o600)
                code, text = report()
                self.assertEqual(code, 0)
                self.assertIn(f"{bootstrap_dc.NAME}: ready", text)
                # Installed, but this factory has no record of doing it.
                self.assertIn("not by this factory", text)

                digest = bootstrap_dc._sha256(files["disk"])
                receipt = state / bootstrap_dc.INSTALL_RECEIPT_NAME
                receipt.write_text(json.dumps({
                    "installed_utc": "2026-08-17T00:00:00+00:00",
                    "disk": {"sha256_after": digest},
                }))
                receipt.chmod(0o600)
                code, text = report()
                self.assertEqual(code, 0)
                self.assertIn("installed by this factory", text)
                self.assertIn(digest, text)
                self.assertNotIn("has changed since", text)

                # Drift between the receipt and the disk is reported, not hidden.
                fake_image_tools.installed_image(files["disk"], b" changed")
                files["disk"].chmod(0o600)
                code, text = report()
                self.assertEqual(code, 0)
                self.assertIn("the disk has changed since", text)

    def test_status_reports_an_uninspectable_image_as_unknown_not_ready(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            state.mkdir(mode=0o700)
            files = bootstrap_dc.paths(state)
            for key in ("disk", "vars", "manifest"):
                files[key].write_bytes(b"x")
                files[key].chmod(0o600)

            def broken(argv, **_kwargs):
                return subprocess.CompletedProcess(argv, 0, "not json", "")

            with mock.patch.object(
                    bootstrap_dc.subprocess, "run", side_effect=broken):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = bootstrap_dc.status(state)
            # Fail closed: an image nobody could inspect is never "ready".
            self.assertEqual(code, 1)
            self.assertIn("installation state unknown", out.getvalue())

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


class PersistentControllerCliTests(unittest.TestCase):
    """The operator entry point for a directory that survives relaunch."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.canonical = self.root / "canonical"
        self.canonical.mkdir()
        files = bootstrap_dc.paths(self.canonical)
        for key in ("disk", "vars", "manifest"):
            files[key].write_bytes(b"canonical " + key.encode())
            files[key].chmod(0o600)
        # An INSTALLED canonical. Seeding from a never-installed one is now
        # refused outright, and the refusal has its own tests below; every
        # case here is about what happens once there is something to seed.
        fake_image_tools.installed_image(files["disk"], b" canonical disk")
        files["disk"].chmod(0o600)
        self.persistent_root = self.root / "persistent"

    def call(self, *argv, expect):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = bootstrap_dc.main(list(argv))
        self.assertEqual(result, expect, err.getvalue() or out.getvalue())
        return out.getvalue(), err.getvalue()

    def _fake_qemu_img(self, argv, **kwargs):
        # Models the real tools rather than stubbing them: the installed-image
        # gate really runs here and really reads what these answer.
        return fake_image_tools.image_tool(argv, **kwargs)

    def test_default_acceptance_command_is_unchanged_by_the_new_options(self):
        # The persistent mode added keyword-only options to qemu_command. The
        # disposable acceptance command must be identical without them.
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))):
            command = bootstrap_dc.qemu_command(Path("/state"), None)
        joined = " ".join(command)
        self.assertIn(f"-name {bootstrap_dc.NAME}", joined)
        self.assertIn("listen=127.0.0.1:12961", joined)
        self.assertIn("/state/bootstrap-dc.qcow2", joined)
        self.assertNotIn("persistent", joined)

    def test_persistent_plan_is_a_dry_run_that_creates_and_boots_nothing(self):
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch.object(bootstrap_dc.subprocess, "run") as run:
            out, _ = self.call(
                "--state-dir", str(self.canonical), "persistent-up",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                expect=0)
        run.assert_not_called()
        self.assertFalse(self.persistent_root.exists())
        self.assertIn("dry run; repeat with --apply", out)
        self.assertIn("is not hash-fenced", out)
        self.assertIn("persistent-dc.qcow2", out)
        self.assertIn("-name persistent-dc-lab-dc1", out)
        # Its own loopback segment, never the acceptance run's port.
        self.assertIn(
            f"listen=127.0.0.1:{bootstrap_dc.PERSISTENT_SOCKET_PORT}", out)
        self.assertNotIn("listen=127.0.0.1:12961", out)

    def test_persistent_run_against_the_acceptance_state_is_refused(self):
        # Naming the acceptance canonical itself, by the two spellings an
        # operator could reach it with: as the instance directory, and as the
        # persistent root that contains it.
        with mock.patch.object(bootstrap_dc.subprocess, "run") as run:
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-up",
                "--instance", self.canonical.name,
                "--persistent-root", str(self.canonical.parent),
                "--apply", expect=2)
            self.assertIn("refusing a persistent controller instance", err)
            _, err = self.call(
                "--state-dir", str(bootstrap_dc.DEFAULT_STATE),
                "persistent-up", "--instance", "bootstrap-dc",
                "--persistent-root",
                str(bootstrap_dc.DEFAULT_STATE.parent), "--apply", expect=2)
            self.assertIn("refusing a persistent controller instance", err)
        run.assert_not_called()
        self.assertEqual(
            bootstrap_dc.paths(self.canonical)["disk"].read_bytes(),
            fake_image_tools.INSTALLED + b" canonical disk")

    def test_persistent_up_seeds_then_boots_the_instance_disk_in_place(self):
        state = self.persistent_root / "lab-dc1"
        guests = []

        # bootstrap_dc.subprocess and simulation_overlay.subprocess are the one
        # module object, so a single dispatching patch serves both the seeding
        # qemu-img calls and the guest launch.
        def dispatch(argv, **kwargs):
            # qemu-img *and* sfdisk: both are image-inspection tools the
            # installed-image gate runs before anything is seeded.
            if argv[0] in {"qemu-img", "sfdisk"}:
                return self._fake_qemu_img(argv, **kwargs)
            guests.append(list(argv))
            return subprocess.CompletedProcess(argv, 0)

        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch.object(
                    bootstrap_dc.shutil, "which", return_value="/usr/bin/x"), \
                mock.patch.object(
                    bootstrap_dc.subprocess, "run", side_effect=dispatch):
            out, _ = self.call(
                "--state-dir", str(self.canonical), "persistent-up",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--apply", expect=0)
        self.assertEqual(len(guests), 1)
        argv = guests[0]
        self.assertIn("qemu-system-x86_64", argv[0])
        self.assertIn(
            f"file={state / 'persistent-dc.qcow2'}", " ".join(argv))
        # The durable state survives the run, and the lock is released.
        self.assertTrue((state / "persistent-dc.qcow2").is_file())
        self.assertTrue((state / "persistent-instance.json").is_file())
        self.assertIn("directory state retained at", out)
        self.call(
            "persistent-status", "--instance", "lab-dc1",
            "--persistent-root", str(self.persistent_root), expect=0)

    def test_persistent_up_refuses_a_canonical_that_was_never_installed(self):
        """The bring-up used to "succeed" and produce a worthless instance.

        Its only content gate was ``_regular_file``, so a never-installed
        canonical seeded an 80 GiB blank, booted it to a UEFI dead end, and
        recorded a ``seeded_from`` hash of an empty image -- with exit 0.
        """
        fake_image_tools.blank_image(
            bootstrap_dc.paths(self.canonical)["disk"], b" never installed")
        guests = []

        def dispatch(argv, **kwargs):
            if argv[0] in {"qemu-img", "sfdisk"}:
                return self._fake_qemu_img(argv, **kwargs)
            guests.append(list(argv))
            return subprocess.CompletedProcess(argv, 0)

        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch.object(
                    bootstrap_dc.shutil, "which", return_value="/usr/bin/x"), \
                mock.patch.object(
                    bootstrap_dc.subprocess, "run", side_effect=dispatch):
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-up",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--apply", expect=2)
        self.assertIn("not an installed Controller image", err)
        self.assertIn("entirely unallocated", err)
        # The message names the target that fixes it.
        self.assertIn("homelab-bootstrap-vm-install", err)
        # No guest, no instance, no lock, nothing half-made.
        self.assertEqual(guests, [])
        self.assertFalse(self.persistent_root.exists())

    def test_persistent_seed_medium_is_read_only_and_must_exist(self):
        seed = self.root / "convergence.iso"
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch.object(
                    bootstrap_dc.shutil, "which", return_value="/usr/bin/x"), \
                mock.patch.object(bootstrap_dc.subprocess, "run") as run:
            out, _ = self.call(
                "--state-dir", str(self.canonical), "persistent-up",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--seed-iso", str(seed), expect=0)
            self.assertIn("media=cdrom,readonly=on", out)
            # An applied bring-up refuses a seed medium that is not there,
            # before it creates or locks anything.
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-up",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--seed-iso", str(seed), "--apply", expect=2)
        self.assertIn("is missing", err)
        run.assert_not_called()
        self.assertFalse(self.persistent_root.exists())

    def test_persistent_status_reports_an_absent_instance(self):
        out, _ = self.call(
            "persistent-status", "--instance", "lab-dc1",
            "--persistent-root", str(self.persistent_root), expect=1)
        self.assertIn("absent or incomplete", out)

    def test_persistent_destroy_requires_the_exact_confirmation(self):
        with mock.patch(
                "vm.simulation_overlay.subprocess.run",
                side_effect=self._fake_qemu_img):
            instance = simulation_overlay.PersistentControllerInstance(
                self.persistent_root / "lab-dc1", instance="lab-dc1")
            instance.create(
                bootstrap_dc.paths(self.canonical)["disk"],
                bootstrap_dc.paths(self.canonical)["vars"])
        for wrong in ("destroy lab-dc1", "DESTROY other", "lab-dc1"):
            with self.subTest(wrong=wrong):
                _, err = self.call(
                    "persistent-destroy", "--instance", "lab-dc1",
                    "--persistent-root", str(self.persistent_root),
                    "--confirm", wrong, expect=2)
                self.assertIn("DESTROY lab-dc1", err)
                self.assertTrue(instance.disk.is_file())
        _, err = self.call(
            "persistent-destroy", "--instance", "lab-dc1",
            "--persistent-root", str(self.persistent_root), expect=2)
        self.assertIn("DESTROY lab-dc1", err)
        out, _ = self.call(
            "persistent-destroy", "--instance", "lab-dc1",
            "--persistent-root", str(self.persistent_root),
            "--confirm", "DESTROY lab-dc1", expect=0)
        self.assertIn("destroyed persistent controller instance", out)
        self.assertFalse(instance.state.exists())
        out, _ = self.call(
            "persistent-destroy", "--instance", "lab-dc1",
            "--persistent-root", str(self.persistent_root),
            "--confirm", "DESTROY lab-dc1", expect=0)
        self.assertIn("already absent", out)

    def test_persistent_subcommands_require_an_instance_name(self):
        for command in (
            "persistent-up", "persistent-converge", "persistent-status",
            "persistent-destroy",
        ):
            with self.subTest(command=command):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        bootstrap_dc.main([command])
        _, err = self.call(
            "persistent-up", "--instance", "../escape", expect=2)
        self.assertIn("instance must be", err)

    def test_a_bring_up_never_implies_a_directory_that_is_not_there(self):
        target = self.seeded_instance()
        out, _ = self.call(
            "persistent-status", "--instance", "lab-dc1",
            "--persistent-root", str(self.persistent_root), expect=0)
        self.assertIn("directory: not provisioned", out)
        self.assertIn("persistent-converge", out)
        target.record_convergence({
            "converged_utc": "2026-08-14T20:00:00+00:00",
            "realm": "AD.FACTORY.TEST",
            "domain_sid": "S-1-5-21-7-8-9",
        })
        out, _ = self.call(
            "persistent-status", "--instance", "lab-dc1",
            "--persistent-root", str(self.persistent_root), expect=0)
        self.assertIn("S-1-5-21-7-8-9", out)
        # An unreadable record degrades a read-only report to "unknown" rather
        # than failing it; only paths that act on the marker fail closed.
        target.marker.write_text(
            json.dumps({
                "schema": 1, "mode": "persistent", "instance": "lab-dc1",
                "created_utc": "x", "seeded_from": {"disk": "d",
                                                    "disk_sha256": "s"},
                "converged": {"converged_utc": ""},
            }), encoding="utf-8")
        out, _ = self.call(
            "persistent-status", "--instance", "lab-dc1",
            "--persistent-root", str(self.persistent_root), expect=0)
        self.assertIn("directory: unknown", out)

    def seeded_instance(self, name="lab-dc1"):
        with mock.patch(
                "vm.simulation_overlay.subprocess.run",
                side_effect=self._fake_qemu_img):
            target = simulation_overlay.PersistentControllerInstance(
                self.persistent_root / name, instance=name)
            target.create(
                bootstrap_dc.paths(self.canonical)["disk"],
                bootstrap_dc.paths(self.canonical)["vars"])
        return target


class PersistentConvergenceTests(unittest.TestCase):
    """Provisioning a directory into a persistent instance, in place.

    The properties under test are the ones that make this safe to run against
    durable state: no harness-generated credential, no rewrite of a durable
    ESP, and a host-side convergence claim that can only ever trail the
    in-guest fact.
    """

    PASSWORDS = ("console-secret-typed", "Administrator-secret-typed")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.canonical = self.root / "canonical"
        self.canonical.mkdir()
        files = bootstrap_dc.paths(self.canonical)
        for key in ("disk", "vars", "manifest"):
            files[key].write_bytes(b"canonical " + key.encode())
            files[key].chmod(0o600)
        # An INSTALLED canonical. Seeding from a never-installed one is now
        # refused outright, and the refusal has its own tests below; every
        # case here is about what happens once there is something to seed.
        fake_image_tools.installed_image(files["disk"], b" canonical disk")
        files["disk"].chmod(0o600)
        self.persistent_root = self.root / "persistent"
        self.state = self.persistent_root / "lab-dc1"
        self.typed = []
        self.launched = []

    def call(self, *argv, expect):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = bootstrap_dc.main(list(argv))
        self.assertEqual(result, expect, err.getvalue() or out.getvalue())
        return out.getvalue(), err.getvalue()

    def _fake_qemu_img(self, argv, **kwargs):
        return fake_image_tools.image_tool(argv, **kwargs)

    def _getpass(self, prompt):
        self.typed.append(prompt)
        return self.PASSWORDS[0] if "console" in prompt else self.PASSWORDS[1]

    class _Bundle:
        """A stand-in for the secret-bearing convergence medium."""

        def __init__(self, _repo, output, *, authorization_nonce,
                     password=None, spec=None):
            self.output = Path(output)
            self.password = password
            self.authorization_nonce = authorization_nonce
            self.spec = spec

        def build(self):
            self.output.write_bytes(b"convergence iso")
            return self.output

        @staticmethod
        def guest_command(nonce):
            return f"telos-converge {nonce}"

    class _Child:
        def __init__(self, *_args, **_kwargs):
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO()

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

        def terminate(self):
            raise AssertionError("a finished child must not be signalled")

    def _harness(self, drive):
        """Patch every boundary a convergence crosses except the state itself."""
        return contextlib.ExitStack(), [
            mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))),
            mock.patch.object(
                bootstrap_dc.shutil, "which", return_value="/usr/bin/x"),
            mock.patch.object(
                bootstrap_dc.subprocess, "run",
                side_effect=self._fake_qemu_img),
            mock.patch.object(
                bootstrap_dc.subprocess, "Popen",
                side_effect=lambda argv, **kw: (
                    self.launched.append(list(argv)) or self._Child())),
            mock.patch.object(
                bootstrap_dc, "_controlling_terminal", return_value=True),
            mock.patch.object(
                bootstrap_dc.getpass, "getpass", side_effect=self._getpass),
            mock.patch.object(bootstrap_dc, "FactoryBundle", self._Bundle),
            mock.patch.object(
                bootstrap_dc, "_attach_simulated_gateway",
                return_value=self._Child()),
            mock.patch.object(
                bootstrap_dc, "_drive_persistent_convergence",
                side_effect=drive),
        ]

    @contextlib.contextmanager
    def harness(self, drive):
        stack, patches = self._harness(drive)
        with stack:
            for patch in patches:
                stack.enter_context(patch)
            yield

    @staticmethod
    def _record(*_args, **_kwargs):
        return {
            "converged_utc": "2026-08-14T20:00:00+00:00",
            "realm": "AD.FACTORY.TEST",
            "domain_sid": "S-1-5-21-101-202-303",
        }

    def converge(self, *extra, expect=0, drive=None):
        with self.harness(drive or self._record):
            return self.call(
                "--state-dir", str(self.canonical), "persistent-converge",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                *extra, expect=expect)

    # -- plan ------------------------------------------------------------
    def test_the_plan_creates_boots_and_asks_for_nothing(self):
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch.object(bootstrap_dc.subprocess, "run") as run, \
                mock.patch.object(bootstrap_dc.subprocess, "Popen") as popen, \
                mock.patch.object(
                    bootstrap_dc.getpass, "getpass") as prompt:
            out, _ = self.call(
                "--state-dir", str(self.canonical), "persistent-converge",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root), expect=0)
        run.assert_not_called()
        popen.assert_not_called()
        prompt.assert_not_called()
        self.assertFalse(self.persistent_root.exists())
        self.assertIn("dry run; repeat with --apply", out)
        self.assertIn("ESP is never rewritten", out)
        self.assertIn(bootstrap_dc.CONSOLE_ACCOUNT, out)
        self.assertIn("198.51.100.10", out)
        self.assertIn(
            f"listen=127.0.0.1:{bootstrap_dc.PERSISTENT_SOCKET_PORT}", out)

    def test_convergence_refuses_the_acceptance_state(self):
        with mock.patch.object(bootstrap_dc.subprocess, "run") as run, \
                mock.patch.object(bootstrap_dc.subprocess, "Popen") as popen:
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-converge",
                "--instance", self.canonical.name,
                "--persistent-root", str(self.canonical.parent),
                "--apply", expect=2)
            self.assertIn("refusing a persistent controller instance", err)
            _, err = self.call(
                "--state-dir", str(bootstrap_dc.DEFAULT_STATE),
                "persistent-converge", "--instance", "bootstrap-dc",
                "--persistent-root", str(bootstrap_dc.DEFAULT_STATE.parent),
                "--apply", expect=2)
            self.assertIn("refusing a persistent controller instance", err)
        run.assert_not_called()
        popen.assert_not_called()
        self.assertEqual(
            bootstrap_dc.paths(self.canonical)["disk"].read_bytes(),
            fake_image_tools.INSTALLED + b" canonical disk")

    # -- credentials -----------------------------------------------------
    def test_credentials_come_from_a_terminal_or_the_run_refuses(self):
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch.object(
                    bootstrap_dc.shutil, "which", return_value="/usr/bin/x"), \
                mock.patch.object(
                    bootstrap_dc, "_controlling_terminal",
                    return_value=False), \
                mock.patch.object(
                    bootstrap_dc.subprocess, "run",
                    side_effect=self._fake_qemu_img), \
                mock.patch.object(bootstrap_dc.subprocess, "Popen") as popen:
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-converge",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--apply", expect=2)
        self.assertIn("controlling terminal", err)
        self.assertIn("not a file, argv", err)
        popen.assert_not_called()
        # Nothing was created, so a run that cannot read its credential leaves
        # no half-made instance behind.
        self.assertFalse(self.persistent_root.exists())

    def test_a_typed_credential_is_validated_and_confirmed(self):
        with mock.patch.object(
                bootstrap_dc, "_controlling_terminal", return_value=True):
            with mock.patch.object(
                    bootstrap_dc.getpass, "getpass", return_value=""):
                with self.assertRaisesRegex(ValueError, "non-empty line"):
                    bootstrap_dc._typed_secret("p: ")
            with mock.patch.object(
                    bootstrap_dc.getpass, "getpass", return_value="a\tb"):
                with self.assertRaisesRegex(ValueError, "control characters"):
                    bootstrap_dc._typed_secret("p: ")
            with mock.patch.object(
                    bootstrap_dc.getpass, "getpass",
                    side_effect=["first", "second"]):
                with self.assertRaisesRegex(ValueError, "did not match"):
                    bootstrap_dc._typed_secret("p: ", confirm="again: ")
            with mock.patch.object(
                    bootstrap_dc.getpass, "getpass",
                    side_effect=["same", "same"]):
                self.assertEqual(
                    bootstrap_dc._typed_secret("p: ", confirm="again: "),
                    b"same")

    def test_no_harness_credential_reaches_durable_state(self):
        out, _ = self.converge("--apply")
        self.assertIn("S-1-5-21-101-202-303", out)
        # Both credentials were typed, never generated.
        self.assertEqual(len(self.typed), 3)
        self.assertTrue(any("console" in prompt for prompt in self.typed))
        self.assertTrue(any("Administrator" in prompt for prompt in self.typed))
        # Neither value, nor any prompt, appears anywhere in the durable state
        # or in what the operator was shown.
        durable = b"".join(
            entry.read_bytes() for entry in sorted(self.state.iterdir()))
        for secret in self.PASSWORDS:
            self.assertNotIn(secret.encode(), durable)
            self.assertNotIn(secret, out)
        # ... nor in the argv the guest was launched with.
        for argv in self.launched:
            for secret in self.PASSWORDS:
                self.assertNotIn(secret, " ".join(argv))

    # -- the durable ESP -------------------------------------------------
    def test_the_persistent_path_never_rewrites_a_durable_esp(self):
        self.converge("--apply")
        # The image the harness handed QEMU is byte-for-byte the seeded copy:
        # no loader.conf was rewritten and no boot entry was injected, which is
        # the whole reason this design logs in instead of injecting.
        self.assertEqual(
            (self.state / simulation_overlay.PERSISTENT_DISK_NAME).read_bytes(),
            fake_image_tools.INSTALLED + b" canonical disk")
        self.assertEqual(
            sorted(entry.name for entry in self.state.iterdir()),
            sorted([
                simulation_overlay.PERSISTENT_DISK_NAME,
                simulation_overlay.PERSISTENT_VARS_NAME,
                simulation_overlay.PERSISTENT_MARKER_NAME,
                simulation_overlay.LOCK_NAME,
            ]))
        # The injection machinery is not reachable from this module at all: it
        # is neither imported nor bound, so no persistent verb can grow a path
        # to it by accident.
        source = Path(bootstrap_dc.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "DisposableBootDisk(", "automated_controller", "mcopy",
            "_inject_entry", "_with_init_shell",
        ):
            self.assertNotIn(forbidden, source)
        self.assertFalse(hasattr(bootstrap_dc, "DisposableBootDisk"))

    def test_the_guest_boots_its_own_disk_with_a_read_only_convergence_cd(self):
        self.converge("--apply")
        self.assertEqual(len(self.launched), 1)
        argv = " ".join(self.launched[0])
        self.assertIn(
            f"file={self.state / simulation_overlay.PERSISTENT_DISK_NAME}",
            argv)
        self.assertIn("media=cdrom,readonly=on", argv)
        self.assertIn("controller-convergence.iso", argv)
        self.assertIn("-name persistent-dc-lab-dc1", argv)
        self.assertIn(
            f"listen=127.0.0.1:{bootstrap_dc.PERSISTENT_SOCKET_PORT}", argv)
        # Never installer media, which would reinstall over the directory this
        # mode exists to keep, and never the acceptance canonical or its port.
        self.assertNotIn(str(bootstrap_dc.paths(self.canonical)["disk"]), argv)
        self.assertNotIn("listen=127.0.0.1:12961", argv)

    # -- the record trails the fact --------------------------------------
    def test_a_failed_convergence_records_nothing_and_releases_the_lock(self):
        def explode(*_args, **_kwargs):
            raise bootstrap_dc.SerialAutomationError(
                "timed out waiting for persistent-login-prompt")

        _, err = self.converge("--apply", expect=2, drive=explode)
        self.assertIn("persistent convergence failed", err)
        self.assertIn("persistent-login-prompt", err)
        target = simulation_overlay.PersistentControllerInstance(
            self.state, instance="lab-dc1")
        self.assertTrue(target.exists())
        self.assertIsNone(target.convergence())
        # The lock is free, so the instance can be retried or brought up.
        target.prepare()
        target.close()

    def test_a_convergence_whose_record_fails_is_reported_not_hidden(self):
        with mock.patch.object(
                simulation_overlay.PersistentControllerInstance,
                "record_convergence",
                side_effect=OSError("read-only state")):
            _, err = self.converge("--apply", expect=2)
        self.assertIn("converged but its record could not be written", err)

    def test_a_second_convergence_needs_reconverge_and_says_what_it_skips(self):
        self.converge("--apply")
        _, err = self.converge("--apply", expect=2)
        self.assertIn("already converged", err)
        self.assertIn("--reconverge", err)
        self.assertIn("does NOT change the domain Administrator password", err)
        self.typed.clear()
        out, _ = self.converge("--apply", "--reconverge")
        self.assertIn("already converged", out)
        # A reconvergence asks for the console credential only: the
        # Administrator password is not re-provisioned, so it must not be
        # collected as though it were.
        self.assertEqual(len(self.typed), 1)
        self.assertIn("console", self.typed[0])

    # -- the source image, and what is asked for before it is checked ----
    def test_converge_refuses_a_blank_canonical_before_asking_for_anything(self):
        fake_image_tools.blank_image(
            bootstrap_dc.paths(self.canonical)["disk"], b" never installed")
        _, err = self.converge("--apply", expect=2)
        self.assertIn("not an installed Controller image", err)
        self.assertIn("homelab-bootstrap-vm-install", err)
        # The whole point of the ordering: an operator must never type an
        # unrecoverable secret into a run that cannot possibly succeed. The
        # old code prompted first and hung to the 300 s console timeout.
        self.assertEqual(self.typed, [])
        self.assertEqual(self.launched, [])
        self.assertFalse(self.persistent_root.exists())

    def test_a_retry_after_a_provisioning_attempt_never_asks_for_a_new_password(self):
        """The Administrator prompt follows the guest, not the host marker.

        The convergence record is only written after a fully successful run,
        but the role skips provisioning as soon as ``sam.ldb`` exists. Any
        failure between those two points used to make every retry ask for,
        confirm, and silently discard a new Administrator password while the
        directory kept the one typed on the first attempt.
        """
        def die_after_provisioning(*_args, on_event=None, **_kwargs):
            self.assertIsNotNone(on_event)
            on_event(bootstrap_dc.PROVISIONING_STAGE_EVENT)
            raise RuntimeError("the guest died after provisioning")

        self.converge("--apply", expect=2, drive=die_after_provisioning)
        instance = simulation_overlay.PersistentControllerInstance(
            self.state, instance="lab-dc1")
        # The fact outlived the run that produced it, and it is not mistaken
        # for a convergence.
        self.assertIsNotNone(instance.provisioning_attempted())
        self.assertIsNone(instance.convergence())

        self.typed.clear()
        _, err = self.converge("--apply", expect=2)
        self.assertIn("already reached the directory-provisioning stage", err)
        self.assertIn("--reconverge", err)
        self.assertIn("destroy and recreate", err)
        self.assertEqual(self.typed, [])

        self.typed.clear()
        out, _ = self.converge("--apply", "--reconverge")
        # Only the console credential: the Administrator password cannot be
        # changed from here, so it is not collected as though it could.
        self.assertEqual(len(self.typed), 1)
        self.assertIn("console", self.typed[0])
        self.assertIn("may already hold a password you typed then", out)

    def test_a_first_convergence_still_asks_for_the_administrator_password(self):
        """The fail-closed rule must not refuse the case it exists to serve."""
        self.converge("--apply")
        # Console once, Administrator twice: it is typed and confirmed.
        self.assertEqual(len(self.typed), 3)
        self.assertIn("console", self.typed[0])
        self.assertIn("Administrator", self.typed[1])
        self.assertIn("Administrator", self.typed[2])

    # -- one root command over the console -------------------------------
    def test_a_console_root_command_never_carries_the_credential(self):
        console = mock.Mock()
        console.password = b"console-secret-typed"
        sent = []
        console._send.side_effect = lambda value, event: sent.append(value)
        console._wait.return_value = mock.Mock(
            group=lambda index: b"0" if index == 1 else b"")
        bootstrap_dc._console_root(console, "id -u", "probe")
        commands = b" ".join(sent)
        self.assertIn(b"'id -u'", commands)
        # The credential is answered to sudo's own private prompt, and never
        # appears inside the command the shell records.
        self.assertEqual(
            sum(1 for value in sent if value == console.password), 1)
        self.assertNotIn(console.password, b" ".join(
            value for value in sent if value != console.password))
        # A nonzero result is a named failure, not a silent continuation.
        console._wait.return_value = mock.Mock(
            group=lambda index: b"3" if index == 1 else b"")
        with self.assertRaisesRegex(
                bootstrap_dc.SerialAutomationError, "failed: probe"):
            bootstrap_dc._console_root(console, "id -u", "probe")
        for invalid in ("", "two\nlines"):
            with self.assertRaisesRegex(
                    bootstrap_dc.SerialAutomationError, "invalid"):
                bootstrap_dc._console_root(console, invalid, "probe")
        console.password = None
        with self.assertRaisesRegex(
                bootstrap_dc.SerialAutomationError, "unavailable"):
            bootstrap_dc._console_root(console, "id -u", "probe")

    def test_the_administrator_is_left_enabled_and_proven_so(self):
        # The disposable payload's last act disables Administrator because its
        # synthetic password is thrown away. A persistent directory must keep an
        # administrator the operator can actually use, and the enable is proven
        # rather than assumed.
        self.assertIn("user enable Administrator",
                      bootstrap_dc.ADMINISTRATOR_ENABLE)
        self.assertIn("userAccountControl", bootstrap_dc.ADMINISTRATOR_ENABLE)
        self.assertIn("test $((__telos_uac & 2)) -eq 0",
                      bootstrap_dc.ADMINISTRATOR_ENABLE)
        self.assertNotIn("Administrator", bootstrap_dc.DOMAIN_SID_COMMAND)


class DisposablePathUnchangedTests(unittest.TestCase):
    """The persistent lane must not be able to change an acceptance run."""

    def test_the_disposable_boot_disk_knows_nothing_of_persistence(self):
        from vm import automated_controller

        source = Path(automated_controller.__file__).read_text(encoding="utf-8")
        for forbidden in ("persistent", "bootstrap_dc", "converge"):
            self.assertNotIn(forbidden, source.lower())

    def test_the_acceptance_command_shape_is_untouched(self):
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))):
            command = bootstrap_dc.qemu_command(Path("/state"), None)
        self.assertEqual(command, [
            "qemu-system-x86_64",
            "-name", "bootstrap-dc",
            "-machine", "q35,accel=kvm",
            "-cpu", "host",
            "-smp", "4",
            "-m", "8192",
            "-display", "none",
            "-serial", "mon:stdio",
            "-boot", "strict=on,menu=off",
            "-drive", "if=pflash,format=raw,readonly=on,file=/code",
            "-drive", "if=pflash,format=raw,file=/state/OVMF_VARS.fd",
            "-drive", (
                "if=none,id=osdisk,format=qcow2,cache=none,"
                "file=/state/bootstrap-dc.qcow2"),
            "-device", (
                "virtio-blk-pci,drive=osdisk,serial=TELOS-BOOTSTRAP-DC1,"
                "bootindex=1"),
            "-nodefaults",
            "-netdev", "socket,id=bootstrap,listen=127.0.0.1:12961",
            "-device", "virtio-net-pci,netdev=bootstrap,mac=52:54:00:11:11:11",
        ])


if __name__ == "__main__":
    unittest.main()
