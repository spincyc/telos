import base64
import contextlib
import io
import json
import re
import socket
import subprocess
import tempfile
import threading
import unittest
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fake_image_tools

from vm import bootstrap_dc, directory_identity, simulation_overlay
from homelab.tests.identity_overlay_pin import pinned_acceptance_state


def setUpModule():
    # HANDOFF section 5: no test stats the operator's build/ tree.  Every
    # persistent-instance separation check resolves the reserved acceptance
    # state, which defaults to the real build/homelab/vm/bootstrap-dc, so
    # every test here reserves private spellings of it instead, and names the
    # reserved state by one of them wherever it once named DEFAULT_STATE.
    global RESERVED_ACCEPTANCE_STATE
    RESERVED_ACCEPTANCE_STATE, _ = unittest.enterModuleContext(
        pinned_acceptance_state())

# One well-formed PERMANENT directory identity (ADR 0065), used by every
# durable-path test here. Deliberately synthetic and deliberately NOT the
# owner's real realm: a test fixture that named it would put an effectively
# permanent private value into a tracked file, which is the whole reason the
# document lives under the gitignored overlay in the first place. It is also
# not FactorySpec()'s acceptance identity, so a test that passes could not be
# passing on a silent fallback to it.
DURABLE_IDENTITY = {
    "schema_version": 1,
    "identity": {
        "dns_domain": "ad.example.home.arpa",
        "kerberos_realm": "AD.EXAMPLE.HOME.ARPA",
        "netbios_name": "EXAMPLEAD",
    },
    "services": {
        "bootstrap_dc_fqdn": "bootstrap-dc.ad.example.home.arpa",
        "permanent_dc_fqdn": "dc2.ad.example.home.arpa",
    },
    "network": {"address": "10.1.99.2", "prefix": 28, "gateway": "10.1.99.1"},
}


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
                "--state-dir", str(RESERVED_ACCEPTANCE_STATE),
                "persistent-up", "--instance", "bootstrap-dc",
                "--persistent-root",
                str(RESERVED_ACCEPTANCE_STATE.parent), "--apply", expect=2)
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
        # The durable path has no acceptance fallback, so every case here has
        # to declare the permanent identity. Written into this test's own
        # temporary directory: the suite must never read or write whatever
        # private overlay the developer's machine happens to carry.
        self.identity = self.root / "directory.json"
        self.identity.write_text(json.dumps(DURABLE_IDENTITY))
        self.absent_identity = self.root / "no-such-directory.json"
        self.typed = []
        self.launched = []
        self._Bundle.built = []
        self.converged_with = []

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

        #: Every bundle built in one test. The spec a bundle is handed is what
        #: renders the convergence payload and the role's ansible variables,
        #: so it is the value the durable directory is actually provisioned
        #: under -- worth asserting on directly rather than through printed
        #: text.
        built = []

        def __init__(self, _repo, output, *, authorization_nonce,
                     password=None, spec=None):
            self.output = Path(output)
            self.password = password
            self.authorization_nonce = authorization_nonce
            self.spec = spec
            type(self).built.append(self)

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
                "--directory-identity", str(self.identity),
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
                "--persistent-root", str(self.persistent_root),
                "--directory-identity", str(self.identity), expect=0)
        # The plan may INSPECT, and does: it reports whether the canonical is
        # installed, so an operator is not told a run is ready that --apply
        # would refuse. What it may never do is start a guest or mutate
        # anything, so assert on the shape of what it ran rather than on
        # nothing having run.
        for call in run.call_args_list:
            argv = [str(part) for part in call.args[0]]
            self.assertIn(argv[0], ("qemu-img", "sfdisk"), argv)
            self.assertNotIn("create", argv)
            self.assertFalse(
                any(part.startswith("qemu-system") for part in argv), argv)
        popen.assert_not_called()
        prompt.assert_not_called()
        self.assertFalse(self.persistent_root.exists())
        self.assertIn("dry run; repeat with --apply", out)
        self.assertIn("ESP is never rewritten", out)
        self.assertIn(bootstrap_dc.CONSOLE_ACCOUNT, out)
        self.assertIn("198.51.100.10", out)
        self.assertIn(
            f"listen=127.0.0.1:{bootstrap_dc.PERSISTENT_SOCKET_PORT}", out)

    # -- the permanent directory identity (ADR 0065) ---------------------
    def _capture(self, *args, **_kwargs):
        """Record the spec the guest was actually converged under."""
        self.converged_with.append(args[3])
        return self._record()

    def test_the_plan_names_the_permanent_identity_not_the_acceptance_one(self):
        acceptance = bootstrap_dc.FactorySpec()
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch.object(bootstrap_dc.subprocess, "run"), \
                mock.patch.object(bootstrap_dc.subprocess, "Popen"), \
                mock.patch.object(bootstrap_dc.getpass, "getpass"):
            out, _ = self.call(
                "--state-dir", str(self.canonical), "persistent-converge",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--directory-identity", str(self.identity), expect=0)
        self.assertIn("AD.EXAMPLE.HOME.ARPA at 10.1.99.2/28", out)
        self.assertIn("NetBIOS EXAMPLEAD", out)
        self.assertIn("bootstrap-dc.ad.example.home.arpa", out)
        self.assertIn("dc2.ad.example.home.arpa", out)
        self.assertIn(str(self.identity), out)
        # The plan an operator reads must not carry the synthetic realm they
        # would otherwise be about to make permanent.
        self.assertNotIn(acceptance.realm, out)
        self.assertNotIn(acceptance.domain, out)
        # Narrowed to the identity line: the unrelated TELOS_FACTORY label of
        # the convergence medium legitimately carries the same word.
        self.assertNotIn(f"NetBIOS {acceptance.netbios}", out)
        self.assertNotIn(f"{acceptance.address}/{acceptance.prefix}", out)

    def test_the_guest_is_converged_under_the_overlay_values(self):
        self.converge("--apply", drive=self._capture)
        self.assertEqual(1, len(self.converged_with))
        self.assertEqual(1, len(self._Bundle.built))
        acceptance = bootstrap_dc.FactorySpec()
        # The spec that renders the convergence payload and the role's ansible
        # variables, and the spec the console protocol is driven with, are the
        # same one and both carry the PERMANENT identity.
        for spec in (self.converged_with[0], self._Bundle.built[0].spec):
            self.assertEqual("ad.example.home.arpa", spec.domain)
            self.assertEqual("AD.EXAMPLE.HOME.ARPA", spec.realm)
            self.assertEqual("EXAMPLEAD", spec.netbios)
            self.assertEqual("10.1.99.2", spec.address)
            self.assertEqual(28, spec.prefix)
            self.assertEqual("10.1.99.1", spec.gateway)
            self.assertEqual("10.1.99.0", spec.network)
            self.assertEqual("255.255.255.240", spec.mask)
            self.assertEqual("bootstrap-dc", spec.hostname)
            self.assertNotEqual(acceptance.domain, spec.domain)
            # Fabric, not identity: ADR 0065 does not freeze it and the
            # simulated gateway is the only host that answers it.
            self.assertEqual(acceptance.ntp_upstream, spec.ntp_upstream)

    def test_an_absent_identity_refuses_before_a_credential_is_typed(self):
        with self.harness(self._record):
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-converge",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--directory-identity", str(self.absent_identity),
                "--apply", expect=2)
        self.assertIn(str(self.absent_identity), err)
        for key in ("identity.dns_domain", "identity.kerberos_realm",
                    "identity.netbios_name", "services.bootstrap_dc_fqdn",
                    "services.permanent_dc_fqdn", "network.address",
                    "network.prefix", "network.gateway"):
            self.assertIn(key, err)
        # Unrecoverable credentials are never spent on a run that cannot
        # succeed, and nothing half-made is left behind.
        self.assertEqual([], self.typed)
        self.assertEqual([], self.launched)
        self.assertFalse(self.persistent_root.exists())

    def test_the_dry_run_refuses_an_absent_identity_too(self):
        # An operator must learn their overlay is missing from a plan, not
        # from a refusal after they have typed the console password.
        _, err = self.call(
            "--state-dir", str(self.canonical), "persistent-converge",
            "--instance", "lab-dc1",
            "--persistent-root", str(self.persistent_root),
            "--directory-identity", str(self.absent_identity), expect=2)
        self.assertIn("ADR 0065", err)
        self.assertIn(bootstrap_dc.FactorySpec().realm, err)

    def test_a_malformed_identity_is_a_refusal_never_a_fallback(self):
        broken = self.root / "broken.json"
        document = json.loads(json.dumps(DURABLE_IDENTITY))
        document["identity"]["kerberos_realm"] = "AD.EXAMPLE.HOME.ARPA."
        broken.write_text(json.dumps(document))
        with self.harness(self._record):
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-converge",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--directory-identity", str(broken), "--apply", expect=2)
        self.assertIn("is not the upper-case form of", err)
        self.assertEqual([], self.typed)
        self.assertFalse(self.persistent_root.exists())

    def test_a_bootstrap_controller_by_another_name_is_refused(self):
        # The serial console is the only channel into a simulated persistent
        # instance and every step matches on "<hostname> login:".
        renamed = self.root / "renamed.json"
        document = json.loads(json.dumps(DURABLE_IDENTITY))
        document["services"]["bootstrap_dc_fqdn"] = (
            "dc1.ad.example.home.arpa")
        renamed.write_text(json.dumps(document))
        with self.harness(self._record):
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-converge",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--directory-identity", str(renamed), "--apply", expect=2)
        self.assertIn("serial console protocol matches on that name", err)
        self.assertIn(f"{bootstrap_dc.NAME}.ad.example.home.arpa", err)
        self.assertEqual([], self.typed)
        self.assertFalse(self.persistent_root.exists())

    def test_the_acceptance_state_refusal_still_comes_first(self):
        # Ordering matters: an operator pointed at the acceptance canonical
        # must be told THAT, not told to seed a private overlay first.
        with mock.patch.object(bootstrap_dc.subprocess, "run") as run, \
                mock.patch.object(bootstrap_dc.subprocess, "Popen") as popen:
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-converge",
                "--instance", self.canonical.name,
                "--persistent-root", str(self.canonical.parent),
                "--directory-identity", str(self.absent_identity),
                "--apply", expect=2)
        self.assertIn("refusing a persistent controller instance", err)
        self.assertNotIn("ADR 0065", err)
        run.assert_not_called()
        popen.assert_not_called()

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
                "--state-dir", str(RESERVED_ACCEPTANCE_STATE),
                "persistent-converge", "--instance", "bootstrap-dc",
                "--persistent-root", str(RESERVED_ACCEPTANCE_STATE.parent),
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
                "--directory-identity", str(self.identity),
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


# The owner's real roster, as the private overlay declares it: `person-a` a standard
# user and `person-b` a daily administrator who is deliberately NOT a Domain Admins
# member.  Written to a temporary file and passed by name, so this suite never
# reads or writes whatever overlay this machine actually carries.
PRIVATE_OVERLAY = {
    "schema_version": 1,
    "principals": {
        "standard_user": {"name": "person-a"},
        "daily_administrator": {"name": "person-b"},
        "domain_administrator": {"name": "roster-c"},
    },
}


class PersistentAccountsCliTests(unittest.TestCase):
    """Staging the owner's DURABLE account roster into a running instance.

    The simulated persistent instance has one QEMU socket netdev to a userspace
    gateway that never forwards general traffic, so the host-side Ansible path
    cannot reach it and the serial console is the only channel there is. What
    these prove is that the console verb cannot mint the synthetic acceptance
    roster into a permanent directory, cannot reach acceptance state, cannot
    take a credential it can never apply, and cannot claim a success it did not
    observe.
    """

    CONSOLE = "console-secret-typed"
    OVERLAY = PRIVATE_OVERLAY

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
        fake_image_tools.installed_image(files["disk"], b" canonical disk")
        files["disk"].chmod(0o600)
        self.persistent_root = self.root / "persistent"
        self.state = self.persistent_root / "lab-dc1"
        self.overlay = self.root / "principals.json"
        self.overlay.write_text(json.dumps(self.OVERLAY), encoding="utf-8")
        self.absent_overlay = self.root / "no-such-overlay.json"
        self.typed = []
        self.launched = []
        self.staged_calls = []
        principals = bootstrap_dc._controller_principals()
        self.roster = principals.durable_directory_roster(self.overlay)
        self.plan = principals.directory_account_plan(
            list(principals.DIRECTORY_ROLES), roster=self.roster)
        # Every real name this run could put anywhere it must not.
        self.names = tuple(entry["name"] for entry in self.plan)
        # Shaped to pass the directory's default policy (seven characters,
        # three classes): the host now refuses anything weaker before booting.
        self.secrets = tuple(
            f"{entry['contract_role']}-Secret-Typed-{index}"
            for index, entry in enumerate(self.plan))

    # -- harness ---------------------------------------------------------
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
        if "console password" in prompt:
            return self.CONSOLE
        # The label is matched exactly: ``standard_user`` is a substring of an
        # additional standard user's ``additional_standard_user_<uid>`` label.
        asked = re.search(r" for (\S+?)(?: \(|:)", prompt)
        for entry, secret in zip(self.plan, self.secrets):
            if asked and entry["contract_role"] == asked.group(1):
                return secret
        raise AssertionError(f"unexpected prompt: {prompt}")

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

    def seed(self, *, converged=True, installed=True):
        """Create the instance this verb needs, without booting anything."""
        canonical = bootstrap_dc.paths(self.canonical)
        with mock.patch.object(
                simulation_overlay.subprocess, "run",
                side_effect=self._fake_qemu_img):
            target = simulation_overlay.PersistentControllerInstance(
                self.state, instance="lab-dc1")
            target.create(canonical["disk"], canonical["vars"])
        if converged:
            target.record_convergence({
                "converged_utc": "2026-08-16T09:00:00+00:00",
                "realm": "AD.FACTORY.TEST",
                "domain_sid": "S-1-5-21-101-202-303",
            })
        if not installed:
            disk = self.state / simulation_overlay.PERSISTENT_DISK_NAME
            fake_image_tools.blank_image(disk, b" never installed")
            disk.chmod(0o600)
        return target

    def _stage_result(self, *_args, **kwargs):
        recorder = kwargs.get("on_stage")
        if recorder is not None:
            recorder()
        self.staged_calls.append(sorted(kwargs.get("values", ()) or _args[2]))
        return mock.Mock(operation="stage")

    @contextlib.contextmanager
    def harness(self, drive=None):
        drive = self._stage_result if drive is None else drive
        with contextlib.ExitStack() as stack:
            for patch in (
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
                mock.patch.object(
                    bootstrap_dc, "_attach_simulated_gateway",
                    return_value=self._Child()),
                mock.patch.object(
                    bootstrap_dc, "_drive_persistent_accounts",
                    side_effect=drive),
            ):
                stack.enter_context(patch)
            yield

    def accounts(self, *extra, expect=0, overlay=None, drive=None):
        with self.harness(drive):
            return self.call(
                "--state-dir", str(self.canonical), "persistent-accounts",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--identity-overlay",
                str(self.overlay if overlay is None else overlay),
                *extra, expect=expect)

    def marker(self):
        return json.loads(
            (self.state
             / simulation_overlay.PERSISTENT_MARKER_NAME).read_text())

    def nameless(self, text):
        """The report with every line that legitimately carries a PATH gone.

        ``roster source``, ``state``, the acceptance canonical and the QEMU
        argv all print filesystem paths on purpose, and a path can contain any
        string -- this checkout lives under ``/home/ksh``, which is exactly one
        of the account names the owner's overlay declares. A "no real name is
        printed" check therefore has to look at what the verb SAYS, not at
        where its files happen to live.
        """
        roots = (str(bootstrap_dc.REPOSITORY), str(self.root))
        return "\n".join(
            line for line in text.splitlines()
            if not any(root in line for root in roots))

    # -- plan ------------------------------------------------------------
    def test_the_plan_asks_for_nothing_boots_nothing_and_names_nobody(self):
        self.seed()
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch.object(bootstrap_dc.subprocess, "run") as run, \
                mock.patch.object(bootstrap_dc.subprocess, "Popen") as popen, \
                mock.patch.object(bootstrap_dc.getpass, "getpass") as prompt:
            out, _ = self.call(
                "--state-dir", str(self.canonical), "persistent-accounts",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--identity-overlay", str(self.overlay), expect=0)
        run.assert_not_called()
        popen.assert_not_called()
        prompt.assert_not_called()
        self.assertIn("dry run; repeat with --apply", out)
        self.assertIn("serial console", out)
        for entry in self.plan:
            self.assertIn(entry["contract_role"], out)
            self.assertIn(str(entry["uidNumber"]), out)
        # Real account names are instance data and never reach stdout.
        said = self.nameless(out)
        for name in self.names:
            self.assertNotIn(name, said)
        # ...and neither do the synthetic acceptance names.
        for synthetic in ("student", "operator"):
            self.assertNotIn(synthetic, said)
        self.assertIn("never a Domain Admins member", out)
        self.assertIn(
            f"listen=127.0.0.1:{bootstrap_dc.PERSISTENT_SOCKET_PORT}", out)

    # -- the synthetic roster --------------------------------------------
    def test_a_missing_overlay_is_refused_never_replaced_by_synthetics(self):
        self.seed()
        with mock.patch.object(bootstrap_dc.subprocess, "Popen") as popen, \
                mock.patch.object(
                    bootstrap_dc.getpass, "getpass") as prompt:
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-accounts",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--identity-overlay", str(self.absent_overlay),
                "--apply", expect=2)
        self.assertIn(str(self.absent_overlay), err)
        self.assertIn("synthetic acceptance roster", err)
        self.assertNotIn("student", err)
        popen.assert_not_called()
        prompt.assert_not_called()

    def test_an_unreadable_overlay_is_refused_not_silently_ignored(self):
        self.seed()
        broken = self.root / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        with mock.patch.object(bootstrap_dc.getpass, "getpass") as prompt:
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-accounts",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--identity-overlay", str(broken), "--apply", expect=2)
        self.assertIn("unreadable JSON", err)
        prompt.assert_not_called()

    # -- the target ------------------------------------------------------
    def test_an_absent_instance_is_refused_before_any_prompt(self):
        with mock.patch.object(bootstrap_dc.getpass, "getpass") as prompt, \
                mock.patch.object(bootstrap_dc.subprocess, "Popen") as popen:
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-accounts",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--identity-overlay", str(self.overlay), "--apply", expect=2)
        self.assertIn("no persistent controller instance", err)
        prompt.assert_not_called()
        popen.assert_not_called()

    def test_an_unconverged_instance_is_refused_before_any_prompt(self):
        self.seed(converged=False)
        with mock.patch.object(bootstrap_dc.getpass, "getpass") as prompt, \
                mock.patch.object(bootstrap_dc.subprocess, "Popen") as popen:
            _, err = self.accounts("--apply", expect=2)
        self.assertIn("no recorded directory", err)
        self.assertIn("persistent-converge", err)
        prompt.assert_not_called()
        popen.assert_not_called()

    def test_an_uninstalled_instance_disk_is_refused_before_any_prompt(self):
        self.seed(installed=False)
        _, err = self.accounts("--apply", expect=2)
        self.assertIn("not an installed Controller image", err)
        self.assertEqual([], self.typed)
        self.assertEqual([], self.launched)

    def test_acceptance_state_can_never_be_the_target(self):
        with mock.patch.object(bootstrap_dc.subprocess, "run") as run, \
                mock.patch.object(bootstrap_dc.subprocess, "Popen") as popen, \
                mock.patch.object(bootstrap_dc.getpass, "getpass") as prompt:
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-accounts",
                "--instance", self.canonical.name,
                "--persistent-root", str(self.canonical.parent),
                "--apply", expect=2)
            self.assertIn("refusing a persistent controller instance", err)
            _, err = self.call(
                "--state-dir", str(RESERVED_ACCEPTANCE_STATE),
                "persistent-accounts", "--instance", "bootstrap-dc",
                "--persistent-root", str(RESERVED_ACCEPTANCE_STATE.parent),
                "--apply", expect=2)
            self.assertIn("refusing a persistent controller instance", err)
        run.assert_not_called()
        popen.assert_not_called()
        prompt.assert_not_called()
        self.assertEqual(
            bootstrap_dc.paths(self.canonical)["disk"].read_bytes(),
            fake_image_tools.INSTALLED + b" canonical disk")

    # -- credentials -----------------------------------------------------
    def test_credentials_come_from_a_terminal_or_the_run_refuses(self):
        self.seed()
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch.object(
                    bootstrap_dc.shutil, "which", return_value="/usr/bin/x"), \
                mock.patch.object(
                    bootstrap_dc.subprocess, "run",
                    side_effect=self._fake_qemu_img), \
                mock.patch.object(
                    bootstrap_dc, "_controlling_terminal",
                    return_value=False), \
                mock.patch.object(bootstrap_dc.subprocess, "Popen") as popen:
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-accounts",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--identity-overlay", str(self.overlay), "--apply", expect=2)
        self.assertIn("controlling terminal", err)
        self.assertIn("not a file, argv", err)
        popen.assert_not_called()

    def test_one_credential_is_asked_for_per_contract_role(self):
        self.seed()
        self.accounts("--apply")
        asked = [prompt for prompt in self.typed
                 if "console password" not in prompt]
        # One prompt plus one confirmation for each directory role.
        self.assertEqual(2 * len(self.plan), len(asked))
        for entry in self.plan:
            self.assertTrue(any(entry["contract_role"] in prompt
                                for prompt in asked))

    def test_two_identical_credentials_are_refused_without_booting(self):
        self.seed()
        with self.harness():
            with mock.patch.object(
                    bootstrap_dc.getpass, "getpass",
                    side_effect=lambda prompt: (
                        self.CONSOLE if "console password" in prompt
                        else "One-Secret-For-Everyone-1")):
                _, err = self.call(
                    "--state-dir", str(self.canonical), "persistent-accounts",
                    "--instance", "lab-dc1",
                    "--persistent-root", str(self.persistent_root),
                    "--identity-overlay", str(self.overlay),
                    "--apply", expect=2)
        self.assertIn("its own password", err)
        self.assertEqual([], self.launched)

    def test_temporary_passwords_are_staged_to_change_at_first_logon(self):
        # The owner's choice on 2026-09-25: easy temporary passwords now, and
        # each person sets a policy-compliant one at their first logon.
        self.seed()
        typed, captured = [], {}

        def easy(prompt):
            typed.append(prompt)
            if "console password" in prompt:
                return self.CONSOLE
            role = re.search(r" for (\S+?)(?: \(|:)", prompt).group(1)
            return "easy-" + role

        def drive(*args, **kwargs):
            captured.update(kwargs)
            return self._stage_result(*args, **kwargs)

        with self.harness(drive):
            with mock.patch.object(
                    bootstrap_dc.getpass, "getpass", side_effect=easy):
                out, _ = self.call(
                    "--state-dir", str(self.canonical), "persistent-accounts",
                    "--instance", "lab-dc1",
                    "--persistent-root", str(self.persistent_root),
                    "--identity-overlay", str(self.overlay),
                    "--change-at-first-logon", "--apply", expect=0)
        self.assertIs(True, captured.get("first_logon"))
        self.assertIn("TEMPORARY", out)
        self.assertTrue(any(prompt.startswith("temporary password for ")
                            for prompt in typed))
        record = json.dumps(self.marker())
        self.assertIn('"password_change_at_first_logon": true', record)
        for prompt in typed:
            self.assertNotIn("easy-", record)

    def test_without_the_flag_nothing_is_staged_to_change_at_first_logon(self):
        self.seed()
        captured = {}

        def drive(*args, **kwargs):
            captured.update(kwargs)
            return self._stage_result(*args, **kwargs)

        self.accounts("--apply", drive=drive)
        self.assertIs(False, captured.get("first_logon"))
        self.assertIn('"password_change_at_first_logon": false',
                      json.dumps(self.marker()))

    def test_a_password_the_directory_would_refuse_fails_before_booting(self):
        # 2026-09-25: a refused password surfaced only as "Controller stage
        # returned 1" after a full boot, because the stage program's stderr is
        # closed. The host now applies the directory's default policy first.
        self.seed()
        for weak, reason in (
            ("abc12", "shorter than 7"),
            ("lowercase-only", "fewer than 3"),
        ):
            with self.subTest(reason=reason), self.harness():
                with mock.patch.object(
                        bootstrap_dc.getpass, "getpass",
                        side_effect=lambda prompt, weak=weak: (
                            self.CONSOLE if "console password" in prompt
                            else weak)):
                    _, err = self.call(
                        "--state-dir", str(self.canonical),
                        "persistent-accounts",
                        "--instance", "lab-dc1",
                        "--persistent-root", str(self.persistent_root),
                        "--identity-overlay", str(self.overlay),
                        "--apply", expect=2)
                self.assertIn(reason, err)
                self.assertIn("Nothing was booted", err)
                self.assertNotIn(weak, err)
                self.assertEqual([], self.launched)

    def test_no_credential_reaches_argv_the_marker_or_the_report(self):
        self.seed()
        out, _ = self.accounts("--apply")
        durable = b"".join(
            entry.read_bytes() for entry in sorted(self.state.iterdir()))
        for secret in (self.CONSOLE, *self.secrets):
            self.assertNotIn(secret.encode(), durable)
            self.assertNotIn(secret, out)
            for argv in self.launched:
                self.assertNotIn(secret, " ".join(argv))
        # Nor do the real account names reach the durable marker: it
        # identifies an account by contract role and proves the roster with a
        # fingerprint. ``roster_source`` is a pair of PATHS by design, so it is
        # excluded for the reason ``nameless`` documents.
        record = self.marker()[simulation_overlay.PERSISTENT_ACCOUNTS_KEY]
        recorded = json.dumps({
            key: value for key, value in record.items()
            if key != "roster_source"})
        for name in self.names:
            self.assertNotIn(name, recorded)

    # -- reporting -------------------------------------------------------
    def test_a_successful_staging_reports_each_role_by_contract_role(self):
        self.seed()
        out, _ = self.accounts("--apply")
        self.assertIn(f"staged {len(self.plan)} durable directory accounts",
                      out)
        for entry in self.plan:
            self.assertIn(
                f"  {entry['contract_role']}: directory role "
                f"{entry['role']}, uidNumber {entry['uidNumber']}", out)
        said = self.nameless(out)
        for name in self.names:
            self.assertNotIn(name, said)
        record = self.marker()[simulation_overlay.PERSISTENT_ACCOUNTS_KEY]
        self.assertEqual(
            [entry["contract_role"] for entry in self.plan],
            [account["contract_role"] for account in record["accounts"]])
        self.assertEqual(
            ["domain_administrator"], record["domain_admin_roles"])
        for account in record["accounts"]:
            self.assertNotIn("name", account)
        # And the staged values really were keyed by the overlay's names.
        self.assertEqual([sorted(self.names)], self.staged_calls)

    def test_staging_again_is_refused_unless_restage_is_asked_for(self):
        self.seed()
        self.accounts("--apply")
        _, err = self.accounts("--apply", expect=2)
        self.assertIn("already holds a staged durable roster", err)
        self.assertIn("--restage", err)
        self.accounts("--apply", "--restage")

    # -- failure ---------------------------------------------------------
    def test_a_mid_way_failure_leaves_a_diagnosable_state(self):
        self.seed()

        def fails(*_args, **kwargs):
            kwargs["on_stage"]()
            raise bootstrap_dc.SerialAutomationError(
                "timed out waiting for stage-return-code-observed")

        _, err = self.accounts("--apply", expect=2, drive=fails)
        self.assertIn("staging the durable account roster failed", err)
        self.assertIn("may now hold some of these accounts", err)
        marker = self.marker()
        # No success is claimed...
        self.assertNotIn(simulation_overlay.PERSISTENT_ACCOUNTS_KEY, marker)
        # ...and the attempt that reached the directory is recorded, so the
        # next run refuses rather than asking for credentials the directory
        # would reject as duplicate accounts.
        self.assertIn(
            simulation_overlay.PERSISTENT_ACCOUNTS_ATTEMPT_KEY, marker)
        self.typed.clear()
        _, err = self.accounts("--apply", expect=2)
        self.assertIn("unfinished staging run", err)
        self.assertEqual([], self.typed)
        out, _ = self.call(
            "persistent-status", "--instance", "lab-dc1",
            "--persistent-root", str(self.persistent_root), expect=0)
        self.assertIn("UNFINISHED", out)

    def test_a_staging_whose_record_fails_is_reported_not_hidden(self):
        self.seed()
        with mock.patch.object(
                simulation_overlay.PersistentControllerInstance,
                "record_directory_accounts",
                side_effect=RuntimeError("marker is read-only")):
            _, err = self.accounts("--apply", expect=2)
        self.assertIn("staged but its record could not be written", err)

    # -- privilege separation --------------------------------------------
    def test_the_daily_administrator_never_joins_domain_admins(self):
        principals = bootstrap_dc._controller_principals()
        self.assertEqual(
            ("domain_administrator",), principals.DIRECTORY_ADMIN_ROLES)
        by_role = {entry["contract_role"]: entry for entry in self.plan}
        self.assertEqual("person-b", by_role["daily_administrator"]["name"])
        self.assertEqual("standard", by_role["daily_administrator"]["role"])
        self.assertEqual("person-a", by_role["standard_user"]["name"])
        self.assertEqual("standard", by_role["standard_user"]["role"])
        self.assertEqual(
            "administrator", by_role["domain_administrator"]["role"])
        stage, _destroy, _roles = principals._programs(self.roster)
        # The guest program adds exactly the domain administrator, by name,
        # and the daily administrator's name appears nowhere near the group.
        self.assertIn(
            '"domain_administrator":"'
            + by_role["domain_administrator"]["name"] + '"', stage)
        group = stage.split('add_remove_group_members(', 1)[1].split(')', 1)[0]
        self.assertIn('"Domain Admins"', group)
        self.assertIn('roster["domain_administrator"]', group)
        self.assertNotIn("person-b", group)
        self.assertNotIn("person-a", group)
        # ...and nothing here grants NOPASSWD or a local wheel membership.
        for forbidden in ("NOPASSWD", "wheel"):
            self.assertNotIn(forbidden, stage)


class PersistentAccountsConsoleTests(unittest.TestCase):
    """The serial exchange itself, driven against a scripted guest.

    A live guest cannot be booted here (the canonical Controller image is an
    empty, never-installed disk), so the guest is scripted exactly as the
    existing serial suites script one. What that still proves is the whole
    credential discipline: the login answers the getty's own prompt, the
    payload is written only after the guest proved terminal echo is off, the
    sudo credential answers sudo's own private prompt, and nothing but base64
    ever crosses the wire.
    """

    CONSOLE = b"console-secret-typed"
    OVERLAY = PRIVATE_OVERLAY

    def setUp(self):
        self.observed = {}
        self.failures = []
        self.staged = []
        principals = bootstrap_dc._controller_principals()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        overlay = Path(self.temporary.name) / "principals.json"
        overlay.write_text(json.dumps(self.OVERLAY), encoding="utf-8")
        self.roster = principals.durable_directory_roster(overlay)
        self.plan = principals.directory_account_plan(
            list(principals.DIRECTORY_ROLES), roster=self.roster)
        self.values = {
            entry["name"]: f"Durable-{index}-secret!"
            for index, entry in enumerate(self.plan)
        }

    def _responder(self, right, *, services_rc=b"0", stage_rc=b"0"):
        def run():
            stream = right.makefile("rb", buffering=0)
            try:
                right.sendall(b"bootstrap-dc login: ")
                self.observed["username"] = stream.readline()
                right.sendall(b"\r\nPassword: ")
                self.observed["login-password"] = stream.readline()
                right.sendall(b"\r\n[local-rescue@bootstrap-dc ~]$ ")
                services = stream.readline()
                self.observed["services"] = services
                token = services.split(
                    b"__TELOS_CONTROLLER_SERVICES_", 1)[1].split(b"=", 1)[0]
                right.sendall(
                    b"\r\n__TELOS_CONTROLLER_SERVICES_" + token + b"="
                    + services_rc + b"\r\n")
                if services_rc != b"0":
                    return
                self.observed["stage-blank"] = stream.readline()
                right.sendall(b"\r\n[local-rescue@bootstrap-dc ~]$ ")
                command = stream.readline()
                self.observed["stage-command"] = command
                ready = command.split(
                    b"__TELOS_PRINCIPAL_READY_", 1)[1].split(b"__", 1)[0]
                result = command.split(
                    b"__TELOS_PRINCIPAL_RC_", 1)[1].split(b"=", 1)[0]
                sudo = command.split(
                    b"__TELOS_PRINCIPAL_SUDO_", 1)[1].split(b"__", 1)[0]
                right.sendall(
                    b"\r\n__TELOS_PRINCIPAL_READY_" + ready + b"__\r\n")
                self.observed["stage-payload"] = stream.readline()
                right.sendall(
                    b"\r\n__TELOS_PRINCIPAL_SUDO_" + sudo + b"__\r\n")
                self.observed["stage-sudo-password"] = stream.readline()
                right.sendall(
                    b"\r\n__TELOS_PRINCIPAL_RC_" + result + b"=" + stage_rc
                    + b"\r\n")
                if stage_rc != b"0":
                    return
                self.observed["poweroff-blank"] = stream.readline()
                right.sendall(b"\r\n[local-rescue@bootstrap-dc ~]$ ")
                poweroff = stream.readline()
                self.observed["poweroff-command"] = poweroff
                prompt = poweroff.split(
                    b"__TELOS_PERSISTENT_POWEROFF_", 1)[1].split(b"__", 1)[0]
                right.sendall(
                    b"\r\n__TELOS_PERSISTENT_POWEROFF_" + prompt + b"__\r\n")
                self.observed["poweroff-password"] = stream.readline()
                right.sendall(b"\r\nReached target System Power Off\r\n")
            except BaseException as error:  # surfaced, never swallowed
                self.failures.append(repr(error))
        return run

    def drive(self, **kwargs):
        left, right = socket.socketpair()
        thread = threading.Thread(
            target=self._responder(right, **kwargs), daemon=True)
        thread.start()
        process = mock.Mock()
        process.stdout = left.makefile("rb", buffering=0)
        process.stdin = left.makefile("wb", buffering=0)
        announced = io.StringIO()
        try:
            with contextlib.redirect_stdout(announced):
                with mock.patch.object(
                        bootstrap_dc, "PERSISTENT_CONSOLE_TIMEOUT", 5.0):
                    return bootstrap_dc._drive_persistent_accounts(
                        process, self.CONSOLE, dict(self.values),
                        roster=self.roster, roster_source="a private overlay",
                        timeout=5.0,
                        on_stage=lambda: self.staged.append("reached")
                    ), announced.getvalue()
        finally:
            left.close()
            right.close()
            thread.join(timeout=2)

    def test_the_exchange_logs_in_proves_the_directory_and_stages(self):
        result, announced = self.drive()
        self.assertEqual([], self.failures)
        self.assertEqual("stage", result.operation)
        self.assertEqual(["reached"], self.staged)
        self.assertEqual(b"local-rescue\n", self.observed["username"])
        # The directory is proven live BEFORE the staging attempt is recorded
        # and before a credential is written into it.
        self.assertIn(b"samba.service", self.observed["services"])
        self.assertIn(b"sam.ldb", self.observed["services"])
        self.assertIn("persistent-accounts-shell-ready", announced)
        self.assertIn("controller-service-readiness-observed", announced)
        self.assertIn("persistent-accounts-poweroff-observed", announced)

    def test_the_payload_is_written_only_behind_a_proven_echo_off(self):
        _result, _announced = self.drive()
        command = self.observed["stage-command"]
        # Echo is disabled and PROVEN -- the ready marker prints only behind a
        # successful stty -- before the credentials are written, and the value
        # the shell reads is base64, never a shell word.
        self.assertIn(b"stty -echo || exit 91", command)
        self.assertLess(
            command.index(b"stty -echo"),
            command.index(b"__TELOS_PRINCIPAL_READY_"))
        self.assertIn(b"IFS= read -r __telos_payload", command)
        self.assertEqual(
            self.values,
            json.loads(base64.b64decode(
                self.observed["stage-payload"]).decode("utf-8")))

    def test_the_console_credential_only_ever_answers_sudos_own_prompt(self):
        _result, announced = self.drive()
        command = self.observed["stage-command"]
        # A durable instance's console account has a password the operator
        # typed, so the protocol must NOT take the disposable `sudo -n` path.
        self.assertIn(b"sudo -k -p", command)
        self.assertNotIn(b"sudo -n", command)
        for label in ("login-password", "stage-sudo-password",
                      "poweroff-password"):
            self.assertEqual(self.CONSOLE + b"\n", self.observed[label])
        # The credential is in no command line, and in nothing the operator or
        # a retained log was shown.
        for label in ("services", "stage-command", "stage-payload",
                      "poweroff-command"):
            self.assertNotIn(self.CONSOLE, self.observed[label])
        self.assertNotIn(self.CONSOLE.decode(), announced)
        for secret in self.values.values():
            self.assertNotIn(secret.encode(), command)
            self.assertNotIn(secret, announced)

    def test_a_directory_that_is_not_serving_stops_before_staging(self):
        with self.assertRaises(bootstrap_dc.SerialAutomationError):
            self.drive(services_rc=b"13")
        # Nothing was recorded as having reached the directory, because
        # nothing did.
        self.assertEqual([], self.staged)
        self.assertNotIn("stage-payload", self.observed)

    def test_a_nonzero_guest_result_is_a_named_failure(self):
        principals = bootstrap_dc._controller_principals()
        with self.assertRaisesRegex(
                principals.ControllerPrincipalError, "stage returned 5"):
            self.drive(stage_rc=b"5")
        # The attempt IS recorded: the guest was handed the credentials, so a
        # later run must not assume the directory is untouched.
        self.assertEqual(["reached"], self.staged)


# The owner's requested layout, 2026-09-25, with PLACEHOLDER names (ADR 0046):
# domain administrator 10000, daily administrator 10001, one additional standard
# user 10002, standard user 10003; local_rescue keeps its contract name.
OWNER_LAYOUT = {
    "schema_version": 1,
    "principals": {
        "standard_user": {"name": "roster-a", "uid_number": 10003},
        "daily_administrator": {"name": "roster-b", "uid_number": 10001},
        "domain_administrator": {"name": "roster-c", "uid_number": 10000},
    },
    "additional_standard_users": [
        {"name": "roster-e", "uid_number": 10002},
    ],
}
EXTRA_LABEL = "additional_standard_user_10002"


class PersistentAccountsOwnerLayoutCliTests(PersistentAccountsCliTests):
    """Every persistent-accounts guarantee again, under uid pins and an extra user.

    Inherits the whole CLI suite -- no real name printed or recorded, one
    distinct credential per account, refusals before any prompt -- and runs it
    against the owner's layout, so the additional standard user is held to all
    of it too.
    """

    OVERLAY = OWNER_LAYOUT

    def test_the_daily_administrator_never_joins_domain_admins(self):
        principals = bootstrap_dc._controller_principals()
        by_role = {entry["contract_role"]: entry for entry in self.plan}
        self.assertEqual("administrator",
                         by_role["domain_administrator"]["role"])
        for label in ("standard_user", "daily_administrator", EXTRA_LABEL):
            self.assertEqual("standard", by_role[label]["role"], label)
        stage, _destroy, _roles = principals._programs(self.roster)
        group = stage.split('add_remove_group_members(', 1)[1].split(')', 1)[0]
        self.assertIn('roster["domain_administrator"]', group)
        for name in ("roster-a", "roster-b", "roster-e"):
            self.assertNotIn(name, group)

    def test_the_plan_numbers_every_account_from_the_overlay(self):
        self.seed()
        out, _ = self.accounts()
        for label, uid in (("standard_user", 10003),
                           ("daily_administrator", 10001),
                           ("domain_administrator", 10000),
                           (EXTRA_LABEL, 10002)):
            self.assertIn(f"  {label}: directory role ", out)
            self.assertRegex(
                out, rf"(?m)^  {label}: directory role \w+, uidNumber {uid}, ")
        self.assertIn("additional standard users: 1", out)
        self.assertNotIn("roster-e", self.nameless(out))

    def test_the_additional_user_is_prompted_staged_and_recorded(self):
        self.seed()
        handed = []

        def drive(*args, **kwargs):
            handed.append(kwargs["roster"])
            return self._stage_result(*args, **kwargs)

        out, _ = self.accounts("--apply", drive=drive)
        # Its own prompt and confirmation, by label; the name shows only in
        # the prompt at the operator's own terminal.
        asked = [prompt for prompt in self.typed if EXTRA_LABEL in prompt]
        self.assertEqual(2, len(asked))
        self.assertIn("(roster-e)", asked[0])
        # The console was handed the whole declaration -- pins and extra user.
        self.assertEqual(1, len(handed))
        self.assertEqual(
            ["roster-e"],
            [user.name for user in handed[0].additional_standard_users])
        self.assertEqual(10000, handed[0].uid_numbers["domain_administrator"])
        self.assertEqual([sorted(["roster-a", "roster-b", "roster-c",
                                  "roster-e"])], self.staged_calls)
        self.assertIn(f"  {EXTRA_LABEL}: directory role standard, "
                      "uidNumber 10002", out)
        record = self.marker()[simulation_overlay.PERSISTENT_ACCOUNTS_KEY]
        self.assertEqual(
            [("standard_user", 10003), ("daily_administrator", 10001),
             ("domain_administrator", 10000), (EXTRA_LABEL, 10002)],
            [(account["contract_role"], account["uidNumber"])
             for account in record["accounts"]])
        self.assertEqual(["domain_administrator"],
                         record["domain_admin_roles"])

    def test_an_overlay_the_loader_refuses_is_refused_before_any_prompt(self):
        self.seed()
        clash = json.loads(json.dumps(OWNER_LAYOUT))
        clash["principals"]["standard_user"].pop("uid_number")
        broken = self.root / "clash.json"
        broken.write_text(json.dumps(clash), encoding="utf-8")
        with mock.patch.object(bootstrap_dc.getpass, "getpass") as prompt, \
                mock.patch.object(bootstrap_dc.subprocess, "Popen") as popen:
            _, err = self.call(
                "--state-dir", str(self.canonical), "persistent-accounts",
                "--instance", "lab-dc1",
                "--persistent-root", str(self.persistent_root),
                "--identity-overlay", str(broken), "--apply", expect=2)
        self.assertIn("claimed by both", err)
        prompt.assert_not_called()
        popen.assert_not_called()


class PersistentAccountsOwnerLayoutConsoleTests(PersistentAccountsConsoleTests):
    """The serial exchange under the owner's layout, down to the guest program."""

    OVERLAY = OWNER_LAYOUT

    def test_the_guest_program_creates_the_pinned_and_additional_accounts(self):
        self.drive()
        self.assertEqual([], self.failures)
        command = self.observed["stage-command"]
        encoded = re.search(rb"b64decode\('([A-Za-z0-9+/=]+)'\)", command)
        self.assertIsNotNone(encoded)
        program = base64.b64decode(encoded.group(1)).decode("utf-8")
        self.assertIn(
            '"order":["roster-a","roster-b","roster-c","roster-e"]', program)
        for name, uid in (("roster-a", 10003), ("roster-b", 10001),
                          ("roster-c", 10000), ("roster-e", 10002)):
            self.assertIn(
                f'"{name}":{{"gidNumber":10513,"loginShell":"/bin/bash",'
                f'"uidNumber":{uid}', program)
        self.assertIn('"domain_administrator":"roster-c"', program)
        payload = json.loads(base64.b64decode(
            self.observed["stage-payload"]).decode("utf-8"))
        self.assertEqual(
            ["roster-a", "roster-b", "roster-c", "roster-e"], sorted(payload))


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



class ConsoleValueAnchorTests(unittest.TestCase):
    """A console value is read from a complete line, never a split chunk."""

    def test_a_partial_read_cannot_truncate_the_domain_sid(self):
        # The first live persistent convergence (2026-09-25) recorded a SID
        # whose last sub-authority was two digits of a ten-digit value: the
        # pattern accepted end-of-buffer as a terminator. Synthetic SID here.
        import re as _re

        emitted = b"__TELOS_PERSISTENT_VALUE_tok="
        pattern = _re.compile(
            bootstrap_dc._console_value_pattern(
                emitted, bootstrap_dc.DOMAIN_SID_VALUE),
            _re.MULTILINE)
        line = emitted + b"S-1-5-21-1111111111-2222222222-1000000007\r\n"
        for cut in range(len(line) - 2):
            self.assertIsNone(
                pattern.search(b"\n" + line[:cut]),
                f"a read cut at {cut} bytes matched a partial SID")
        found = pattern.search(b"\n" + line)
        self.assertEqual(
            b"S-1-5-21-1111111111-2222222222-1000000007", found.group(1))

    def test_a_partial_read_cannot_truncate_a_return_code(self):
        import re as _re

        result = b"__TELOS_PERSISTENT_RC_tok="
        pattern = _re.compile(
            bootstrap_dc._console_result_pattern(result), _re.MULTILINE)
        line = result + b"127\r\n"
        for cut in range(len(line) - 2):
            self.assertIsNone(pattern.search(b"\n" + line[:cut]))
        self.assertEqual(b"127", pattern.search(b"\n" + line).group(1))


if __name__ == "__main__":
    unittest.main()
