"""Wire-compat and unit-text contracts for the Arch guest progress reporter.

The reporter ships inside the live image as a self-contained script, so
these tests load it by path and prove its frames against the real host
parser and receiver.  Live-image proof is deferred to the next privileged
image build; nothing here upgrades a guest report to acceptance evidence.
"""

import importlib.machinery
import importlib.util
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path

from homelab.vm import factory_runner
from homelab.vm.guest_progress_host import PROGRESS_PORT_NAME
from homelab.vm import guest_progress_protocol as protocol
from homelab.vm.guest_progress_protocol import (
    AuthenticationError,
    ProtocolConfig,
    ReceiverState,
    canonical_json,
    encode_frame,
    parse_payload,
)

AIROOTFS = Path(__file__).resolve().parents[1] / "archiso/airootfs"
SCRIPT = AIROOTFS / "usr/local/bin/homelab-progress"
UNIT = AIROOTFS / "etc/systemd/system/homelab-progress.service"
DEVICE_UNIT = "dev-virtio\\x2dports-org.telos.progress.0.device"
WANTS = AIROOTFS / "etc/systemd/system" / (DEVICE_UNIT + ".wants")


def load_script():
    loader = importlib.machinery.SourceFileLoader(
        "homelab_progress", str(SCRIPT))
    spec = importlib.util.spec_from_loader("homelab_progress", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class ReporterWireCompatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_script()

    def setUp(self):
        self.key = os.urandom(32)
        self.config = ProtocolConfig(
            attempt="attempt-1",
            producer=self.module.PRODUCER,
            nonce="nonce-1",
            phases=factory_runner.PROGRESS_PHASES,
            statuses=factory_runner.PROGRESS_STATUSES,
        )
        self.boot_id = "boot-" + str(uuid.uuid4())

    def _event(self, event_type, sequence, **extra):
        return self.module.build_event(
            event_type, attempt="attempt-1", boot_id=self.boot_id,
            sequence=sequence, key=self.key, moment=float(sequence), **extra)

    def test_reporter_lifecycle_is_accepted_by_the_real_receiver(self):
        receiver = ReceiverState(self.config, self.key, deadline=1000.0)
        events = (
            self._event("sync", 0, nonce="nonce-1"),
            self._event("phase-started", 1, phase=self.module.PHASE),
            self._event("heartbeat", 2, phase=self.module.PHASE, progress=50),
            self._event("phase-finished", 3, phase=self.module.PHASE),
        )
        for index, payload in enumerate(events):
            parse_payload(payload, self.config, self.key)
            accepted = receiver.accept(payload, received_at=float(index + 1))
            self.assertFalse(accepted.duplicate)
            self.assertFalse(accepted.authoritative)
        self.assertEqual(receiver.last_sequence, 3)
        self.assertIsNone(receiver.active_phase)
        self.assertEqual(receiver.liveness(now=4.5), "live")

    def test_reporter_framing_matches_the_protocol_encoder(self):
        payload = self._event("sync", 0, nonce="nonce-1")
        self.assertEqual(
            self.module.frame_for(payload),
            encode_frame(json.loads(payload)))
        self.assertEqual(canonical_json(json.loads(payload)), payload)

    def test_forged_key_or_nonce_fails_closed_at_the_host(self):
        receiver = ReceiverState(self.config, self.key, deadline=1000.0)
        forged = self.module.build_event(
            "sync", attempt="attempt-1", boot_id=self.boot_id, sequence=0,
            key=os.urandom(32), nonce="nonce-1", moment=0.0)
        with self.assertRaises(AuthenticationError):
            parse_payload(forged, self.config, self.key)
        wrong_nonce = self._event("sync", 0, nonce="other-nonce")
        with self.assertRaises(AuthenticationError):
            receiver.accept(wrong_nonce, received_at=1.0)

    def test_reporter_accepts_only_the_exact_host_acknowledgment(self):
        receiver = ReceiverState(self.config, self.key, deadline=1000.0)
        payload = self._event("sync", 0, nonce="nonce-1")
        event_id = json.loads(payload)["id"]
        accepted = receiver.accept(payload, received_at=1.0)
        ack = receiver.acknowledgment(accepted)
        ack_payload = canonical_json(ack)
        self.assertTrue(self.module.verify_ack(
            ack_payload, key=self.key, attempt="attempt-1",
            boot_id=self.boot_id, sequence=0, event_id=event_id))
        self.assertFalse(self.module.verify_ack(
            ack_payload, key=os.urandom(32), attempt="attempt-1",
            boot_id=self.boot_id, sequence=0, event_id=event_id))
        self.assertFalse(self.module.verify_ack(
            ack_payload, key=self.key, attempt="attempt-1",
            boot_id=self.boot_id, sequence=1, event_id=event_id))
        tampered = dict(ack)
        tampered["sequence"] = 1
        self.assertFalse(self.module.verify_ack(
            canonical_json(tampered), key=self.key, attempt="attempt-1",
            boot_id=self.boot_id, sequence=1, event_id=event_id))
        forged = dict(ack)
        forged["mac"] = "A" * 43 + "="
        self.assertFalse(self.module.verify_ack(
            canonical_json(forged), key=self.key, attempt="attempt-1",
            boot_id=self.boot_id, sequence=0, event_id=event_id))
        self.assertFalse(self.module.verify_ack(
            b"not json", key=self.key, attempt="attempt-1",
            boot_id=self.boot_id, sequence=0, event_id=event_id))

    def test_embedded_constants_match_the_host_protocol(self):
        self.assertEqual(self.module.SPEC_VERSION, protocol.SPEC_VERSION)
        self.assertEqual(self.module.MAC_DOMAIN, protocol.MAC_DOMAIN)
        self.assertEqual(self.module.ACK_MAC_DOMAIN, protocol.ACK_MAC_DOMAIN)
        self.assertEqual(
            self.module.MAX_FRAME_BYTES, protocol.MAX_FRAME_BYTES)
        self.assertEqual(
            self.module.EVENT_STATUSES, dict(protocol.EVENT_STATUSES))
        self.assertEqual(
            self.module.PRODUCER, factory_runner.PROGRESS_PRODUCER)
        self.assertIn(self.module.PHASE, factory_runner.PROGRESS_PHASES)
        self.assertEqual(self.module.PORT_NAME, PROGRESS_PORT_NAME)
        self.assertEqual(
            self.module.DEVICE_PATH,
            "/dev/virtio-ports/" + PROGRESS_PORT_NAME)


class ReporterCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_script()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)

    def _write(self, value, mode=0o600):
        path = self.root / "credentials.json"
        path.write_text(json.dumps(value))
        os.chmod(path, mode)
        return path

    def test_missing_credentials_exit_zero_silently(self):
        absent = self.root / "credentials.json"
        self.assertEqual(self.module.main(credentials=str(absent)), 0)

    def test_world_readable_credentials_fail_closed(self):
        path = self._write(
            {"attempt": "attempt-1", "nonce": "nonce-1",
             "key_hex": "00" * 32},
            mode=0o644)
        self.assertEqual(self.module.main(credentials=str(path)), 1)

    def test_malformed_credentials_fail_closed(self):
        for value in (
            [],
            {"attempt": "attempt-1", "nonce": "nonce-1"},
            {"attempt": "attempt-1", "nonce": "nonce-1",
             "key_hex": "00" * 32, "extra": 1},
            {"attempt": "attempt 1", "nonce": "nonce-1",
             "key_hex": "00" * 32},
            {"attempt": "attempt-1", "nonce": "nonce-1", "key_hex": "zz"},
            {"attempt": "attempt-1", "nonce": "nonce-1", "key_hex": "00"},
        ):
            with self.subTest(value=value):
                path = self._write(value)
                with self.assertRaises(self.module.ReporterError):
                    self.module.load_credentials(str(path))
                path.unlink()

    def test_valid_credentials_load_and_unavailable_device_is_bounded(self):
        path = self._write(
            {"attempt": "attempt-1", "nonce": "nonce-1",
             "key_hex": "0a" * 32})
        attempt, nonce, key = self.module.load_credentials(str(path))
        self.assertEqual((attempt, nonce), ("attempt-1", "nonce-1"))
        self.assertEqual(key, bytes.fromhex("0a" * 32))
        self.assertIsNone(self.module.wait_for_device(
            str(self.root / "missing-port"), wait=0.0))
        self.assertEqual(self.module.main(
            credentials=str(path), device=str(self.root / "missing-port"),
            device_wait=0.0), 1)


class ReporterUnitTests(unittest.TestCase):
    def test_script_is_an_executable_stdlib_program(self):
        self.assertTrue(os.access(SCRIPT, os.X_OK))
        text = SCRIPT.read_text()
        self.assertEqual(
            text.splitlines()[0], "#!/usr/bin/env python3")
        # Self-contained: the live image has no repository modules to import.
        self.assertNotIn("homelab", "\n".join(
            line for line in text.splitlines()
            if line.startswith(("import ", "from "))))

    def test_service_unit_is_device_bound_bounded_and_hardened(self):
        text = UNIT.read_text()
        for required in (
            f"BindsTo={DEVICE_UNIT}",
            f"After={DEVICE_UNIT}",
            "ConditionPathExists=/usr/local/bin/homelab-progress",
            "ExecStart=/usr/local/bin/homelab-progress",
            "RuntimeMaxSec=",
            "Restart=on-failure",
            "RestartSec=",
            "StartLimitIntervalSec=",
            "StartLimitBurst=",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "PrivateTmp=yes",
            "PrivateNetwork=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "RestrictAddressFamilies=AF_UNIX",
            "SystemCallArchitectures=native",
        ):
            self.assertIn(required, text)
        # PrivateDevices would hide the very virtio port the unit binds to.
        self.assertNotIn("PrivateDevices", text)
        self.assertIn(PROGRESS_PORT_NAME, DEVICE_UNIT.replace("\\x2d", "-"))

    def test_service_is_enabled_by_the_airootfs_symlink_convention(self):
        link = WANTS / "homelab-progress.service"
        self.assertTrue(link.is_symlink())
        self.assertEqual(
            os.readlink(link), "../homelab-progress.service")
        self.assertIn(f"WantedBy={DEVICE_UNIT}", UNIT.read_text())


if __name__ == "__main__":
    unittest.main()
