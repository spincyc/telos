"""Tests for the host-side guest progress channel wiring."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from homelab.vm import simulated_topology
from homelab.vm.guest_progress_host import (
    CLASSIFICATIONS,
    GuestProgressHostError,
    LIVENESS_STATES,
    PROGRESS_PORT_NAME,
    attach_progress_port,
    classify,
    classify_liveness,
    progress_record,
)
from homelab.vm.guest_progress_protocol import (
    AuthenticationError,
    DeadlineError,
    FrameError,
    GuestProgressError,
    ReplayError,
    SchemaError,
    TransitionError,
)
from homelab.vm.guest_progress_transport import TransportError
from homelab.vm.qemu_boundary import audit_disposable_controller


class AttachProgressPortTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.socket_path = self.root / "progress.sock"
        self.argv = [
            "qemu-system-x86_64", "-nodefaults",
            "-netdev", "socket,id=x,connect=127.0.0.1:12971",
            "-device", "virtio-net-pci,netdev=x",
        ]

    def test_port_name_fits_shortest_device_name_limit(self):
        self.assertLess(len(PROGRESS_PORT_NAME), 30)
        self.assertRegex(PROGRESS_PORT_NAME, r"\A[A-Za-z0-9.][A-Za-z0-9.]*\Z")

    def test_appends_exactly_the_three_declared_arguments(self):
        extended, chardev = attach_progress_port(self.argv, self.socket_path)
        self.assertEqual(extended[:len(self.argv)], self.argv)
        self.assertEqual(
            chardev,
            f"socket,id=telosprogress,path={self.socket_path},"
            "server=on,wait=off")
        self.assertEqual(extended[len(self.argv):], [
            "-chardev", chardev,
            "-device", "virtio-serial-pci,id=telosprogressbus",
            "-device",
            "virtserialport,bus=telosprogressbus.0,chardev=telosprogress,"
            f"name={PROGRESS_PORT_NAME}",
        ])
        # The original command object is left untouched for audit comparison.
        self.assertEqual(len(self.argv), 6)

    def test_preserves_tuple_argv_container(self):
        extended, _ = attach_progress_port(tuple(self.argv), self.socket_path)
        self.assertIsInstance(extended, tuple)

    def test_topology_audit_accepts_only_the_allowlisted_chardev(self):
        extended, chardev = attach_progress_port(self.argv, self.socket_path)
        simulated_topology.audit_qemu_argv(
            "controller", extended, allowed_chardevs=(chardev,))
        with self.assertRaisesRegex(ValueError, "forbidden QEMU option"):
            simulated_topology.audit_qemu_argv("controller", extended)
        with self.assertRaisesRegex(ValueError, "forbidden QEMU option"):
            simulated_topology.audit_qemu_argv(
                "controller", extended,
                allowed_chardevs=(chardev.replace(
                    "progress.sock", "other.sock"),))

    def test_refuses_existing_socket_path(self):
        self.socket_path.write_text("")
        with self.assertRaisesRegex(GuestProgressHostError, "absent"):
            attach_progress_port(self.argv, self.socket_path)

    def test_refuses_symlinked_socket_path(self):
        self.socket_path.symlink_to(self.root / "elsewhere")
        with self.assertRaisesRegex(GuestProgressHostError, "absent"):
            attach_progress_port(self.argv, self.socket_path)

    def test_refuses_symlinked_parent(self):
        real = self.root / "real"
        real.mkdir(mode=0o700)
        link = self.root / "link"
        link.symlink_to(real)
        with self.assertRaisesRegex(GuestProgressHostError, "private real"):
            attach_progress_port(self.argv, link / "progress.sock")

    def test_refuses_group_accessible_parent(self):
        os.chmod(self.root, 0o750)
        with self.assertRaisesRegex(GuestProgressHostError, "private real"):
            attach_progress_port(self.argv, self.socket_path)

    def test_refuses_comma_in_path(self):
        with self.assertRaisesRegex(GuestProgressHostError, "QEMU-safe"):
            attach_progress_port(self.argv, self.root / "a,b.sock")

    def test_refuses_over_long_path(self):
        long_name = "p" * (108 - len(str(self.root)))
        with self.assertRaisesRegex(GuestProgressHostError, "too long"):
            attach_progress_port(self.argv, self.root / long_name)

    def test_refuses_argv_with_existing_chardev(self):
        argv = self.argv + [
            "-chardev", "socket,id=other,path=/tmp/other.sock"]
        with self.assertRaisesRegex(
                GuestProgressHostError, "character device"):
            attach_progress_port(argv, self.socket_path)

    def test_refuses_argv_already_using_the_progress_identifier(self):
        for item in (
            "virtserialport,chardev=telosprogress",
            "virtio-serial-pci,id=telosprogressbus",
        ):
            with self.subTest(item=item):
                with self.assertRaisesRegex(
                        GuestProgressHostError, "identifier"):
                    attach_progress_port(
                        self.argv + ["-device", item], self.socket_path)

    def test_refuses_non_string_argv(self):
        for command in ([], ["qemu", 7], "qemu -nodefaults"):
            with self.subTest(command=command):
                with self.assertRaises(GuestProgressHostError):
                    attach_progress_port(command, self.socket_path)


class QemuBoundaryAllowlistTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        os.chmod(root, 0o700)
        self.disk = root / "controller.raw"
        self.vars = root / "OVMF_VARS.fd"
        self.socket_path = root / "progress.sock"
        argv = [
            "qemu-system-x86_64", "-nodefaults",
            "-drive",
            "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF_CODE.fd",
            "-drive", f"if=pflash,format=raw,file={self.vars.resolve()}",
            "-drive",
            f"if=virtio,format=raw,cache=none,file={self.disk.resolve()}",
            "-netdev", "socket,id=simnet,connect=127.0.0.1:12971",
            "-device", "virtio-net-pci,netdev=simnet,mac=52:54:00:31:11:12",
        ]
        self.argv, self.chardev = attach_progress_port(argv, self.socket_path)

    def audit(self, argv, **overrides):
        audit_disposable_controller(
            argv, disk=self.disk, vars_file=self.vars, **overrides)

    def test_accepts_exactly_the_allowlisted_progress_chardev(self):
        self.audit(self.argv, allowed_chardevs=(self.chardev,))

    def test_default_allowlist_stays_closed(self):
        with self.assertRaisesRegex(ValueError, "forbidden QEMU option"):
            self.audit(self.argv)

    def test_rejects_any_other_chardev(self):
        index = self.argv.index("-chardev") + 1
        tampered = list(self.argv)
        tampered[index] = self.chardev.replace(
            "progress.sock", "different.sock")
        with self.assertRaisesRegex(ValueError, "forbidden QEMU option"):
            self.audit(tampered, allowed_chardevs=(self.chardev,))

    def test_rejects_a_duplicate_allowlisted_chardev(self):
        with self.assertRaisesRegex(ValueError, "forbidden QEMU option"):
            self.audit(
                self.argv + ["-chardev", self.chardev],
                allowed_chardevs=(self.chardev,))


class ClassifyTests(unittest.TestCase):
    def test_maps_the_complete_error_taxonomy(self):
        for error, expected in (
            (FrameError("truncated"), "malformed"),
            (SchemaError("unknown field"), "malformed"),
            (AuthenticationError("bad mac"), "unauthenticated"),
            (ReplayError("rollback"), "replayed"),
            (TransitionError("phase mismatch"), "contradictory"),
            (TransportError("read failed"), "unavailable"),
            (DeadlineError("silence"), "stalled"),
        ):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(classify(error), expected)

    def test_anything_else_is_unavailable_never_success(self):
        for error in (GuestProgressError("base"), RuntimeError("boom"),
                      OSError(32, "pipe"), None):
            with self.subTest(error=error):
                self.assertEqual(classify(error), "unavailable")

    def test_liveness_passthrough_is_closed(self):
        for state in LIVENESS_STATES:
            self.assertEqual(classify_liveness(state), state)
        for bad in ("dead", "", "LIVE", b"live", 1, None):
            with self.subTest(bad=bad):
                with self.assertRaises(GuestProgressHostError):
                    classify_liveness(bad)


class ProgressRecordTests(unittest.TestCase):
    def test_record_is_fixed_json_able_and_never_authoritative(self):
        record = progress_record(
            liveness="live", classification="stalled",
            last_phase="install-os", last_sequence=4, events_accepted=5)
        self.assertEqual(frozenset(record), {
            "channel", "port", "authoritative", "liveness", "classification",
            "last_phase", "last_sequence", "events_accepted",
        })
        self.assertEqual(record["channel"], "virtserialport")
        self.assertIs(record["authoritative"], False)
        self.assertEqual(record["port"], PROGRESS_PORT_NAME)
        self.assertEqual(json.loads(json.dumps(record)), record)

    def test_record_never_embeds_key_or_nonce_material(self):
        secret = os.urandom(32)
        for field in ("classification", "last_phase"):
            for value in (secret, "n" * 200):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(GuestProgressHostError):
                        progress_record(liveness="live", **{field: value})
        # Raw digest text cannot pose as a classification either.
        with self.assertRaises(GuestProgressHostError):
            progress_record(liveness="live", classification=secret.hex())
        # No keyword exists through which secret bytes could enter.
        with self.assertRaises(TypeError):
            progress_record(liveness="live", key=secret)
        with self.assertRaises(TypeError):
            progress_record(liveness="live", nonce="attempt-nonce")
        with self.assertRaises(TypeError):
            progress_record(liveness="live", checkpoint=b"{}")

    def test_rejects_incoherent_or_unbounded_inputs(self):
        for kwargs in (
            {"liveness": "absent", "events_accepted": 1},
            {"liveness": "absent", "last_sequence": 0, "events_accepted": 1},
            {"liveness": "absent", "last_phase": "install-os"},
            {"liveness": "live", "last_sequence": 3, "events_accepted": 0},
            {"liveness": "live", "last_sequence": -1, "events_accepted": 1},
            {"liveness": "live", "last_sequence": 2 ** 53, "events_accepted": 1},
            {"liveness": "live", "events_accepted": -1},
            {"liveness": "live", "events_accepted": True},
            {"liveness": "live", "classification": "success"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(GuestProgressHostError):
                    progress_record(**kwargs)

    def test_classification_registry_matches_the_design_document(self):
        self.assertEqual(CLASSIFICATIONS, (
            "absent", "unavailable", "malformed", "unauthenticated",
            "replayed", "stalled", "contradictory", "cleanup-unproved",
        ))
        for classification in CLASSIFICATIONS:
            record = progress_record(
                liveness="stalled", classification=classification)
            self.assertEqual(record["classification"], classification)


if __name__ == "__main__":
    unittest.main()
