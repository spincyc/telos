"""Contract tests for the per-run guest-progress credential document.

The document is the one artifact the host and the shipped guest reporter
must agree on byte for byte, so the acceptance test here loads the reporter
by path and feeds it a host-minted document: host and guest are proved
wire-compatible rather than assumed so.
"""

import importlib.machinery
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from homelab.vm import factory_runner
from homelab.vm.guest_progress_credentials import (
    DOCUMENT_NAME,
    GUEST_DOCUMENT_PATH,
    KEY_BYTES,
    GuestProgressCredentialError,
    ProgressCredential,
    destroy_credential_document,
    mint_credential,
    stage_credential_document,
    staging_root,
)
from homelab.vm.guest_progress_protocol import ProtocolConfig, ReceiverState

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "archiso/airootfs/usr/local/bin/homelab-progress")


def load_script():
    """Load the shipped guest reporter by path, as the live image runs it."""
    loader = importlib.machinery.SourceFileLoader(
        "homelab_progress", str(SCRIPT))
    spec = importlib.util.spec_from_loader("homelab_progress", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class CredentialMintingTests(unittest.TestCase):
    def test_minted_credential_is_run_unique_and_strong(self):
        first = mint_credential()
        second = mint_credential()
        self.assertNotEqual(first.attempt, second.attempt)
        self.assertNotEqual(first.nonce, second.nonce)
        self.assertNotEqual(first.key, second.key)
        for credential in (first, second):
            self.assertGreaterEqual(len(credential.key), KEY_BYTES)
            self.assertEqual(len(credential.key), KEY_BYTES)

    def test_document_holds_exactly_the_three_required_fields(self):
        credential = mint_credential(prefix="factory-workstation")
        document = json.loads(credential.document_bytes())
        self.assertEqual(
            set(document), {"attempt", "nonce", "key_hex"})
        self.assertEqual(document["attempt"], credential.attempt)
        self.assertEqual(document["nonce"], credential.nonce)
        self.assertEqual(
            bytes.fromhex(document["key_hex"]), credential.key)
        self.assertGreaterEqual(len(bytes.fromhex(document["key_hex"])), 32)

    def test_the_key_never_appears_in_a_rendered_credential(self):
        credential = mint_credential()
        for text in (repr(credential), str(credential), f"{credential}"):
            self.assertNotIn(credential.key.hex(), text)
            self.assertIn("redacted", text)

    def test_malformed_identities_and_weak_keys_fail_closed(self):
        for kwargs in (
            {"attempt": "attempt 1", "nonce": "n1", "key": os.urandom(32)},
            {"attempt": "a1", "nonce": "nonce 1", "key": os.urandom(32)},
            {"attempt": "a1", "nonce": "n1", "key": os.urandom(31)},
            {"attempt": "a1", "nonce": "n1", "key": bytearray(32)},
            {"attempt": "", "nonce": "n1", "key": os.urandom(32)},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(GuestProgressCredentialError):
                    ProgressCredential(**kwargs)
        with self.assertRaises(GuestProgressCredentialError):
            mint_credential(prefix="not a token")

    def test_the_guest_path_is_the_one_the_reporter_reads(self):
        module = load_script()
        self.assertEqual(GUEST_DOCUMENT_PATH, module.CREDENTIALS_PATH)
        self.assertEqual(DOCUMENT_NAME, Path(module.CREDENTIALS_PATH).name)

    def test_protocol_config_binds_the_credential_identity(self):
        credential = mint_credential()
        config = credential.protocol_config(
            producer=factory_runner.PROGRESS_PRODUCER,
            phases=factory_runner.PROGRESS_PHASES,
            statuses=factory_runner.PROGRESS_STATUSES)
        self.assertIsInstance(config, ProtocolConfig)
        self.assertEqual(config.attempt, credential.attempt)
        self.assertEqual(config.nonce, credential.nonce)


class CredentialStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)

    def test_staged_document_is_private_regular_and_exclusive(self):
        credential = mint_credential()
        directory = staging_root(self.root)
        self.assertEqual(
            stat.S_IMODE(directory.stat().st_mode), 0o700)
        path = stage_credential_document(credential, directory)
        self.assertEqual(path.name, DOCUMENT_NAME)
        info = path.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertFalse(path.is_symlink())
        self.assertEqual(
            json.loads(path.read_bytes()), credential.document())
        # Exclusive: a second staging into the same name fails closed rather
        # than overwriting a document a delivery channel may already hold.
        with self.assertRaises(FileExistsError):
            stage_credential_document(credential, directory)

    def test_staging_refuses_a_world_readable_or_unreal_directory(self):
        credential = mint_credential()
        loose = self.root / "loose"
        loose.mkdir(mode=0o755)
        with self.assertRaises(GuestProgressCredentialError):
            stage_credential_document(credential, loose)
        target = self.root / "target"
        target.mkdir(mode=0o700)
        link = self.root / "link"
        link.symlink_to(target)
        with self.assertRaises(GuestProgressCredentialError):
            stage_credential_document(credential, link)
        with self.assertRaises(GuestProgressCredentialError):
            stage_credential_document(credential, self.root / "missing")
        for name in ("", ".", "..", "a/b"):
            with self.subTest(name=name):
                with self.assertRaises(GuestProgressCredentialError):
                    stage_credential_document(credential, target, name=name)

    def test_destruction_removes_the_document_and_proves_absence(self):
        credential = mint_credential()
        directory = staging_root(self.root)
        path = stage_credential_document(credential, directory)
        self.assertEqual(destroy_credential_document(path), [])
        self.assertFalse(path.exists())
        # Idempotent: destroying an absent document is not a failure.
        self.assertEqual(destroy_credential_document(path), [])
        self.assertEqual(
            destroy_credential_document(self.root / "never-existed"), [])


class ReporterWireCompatibilityTests(unittest.TestCase):
    """The host document must load in the shipped guest reporter itself."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_script()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)

    def test_shipped_reporter_loads_a_host_staged_document(self):
        credential = mint_credential(prefix="factory-workstation")
        directory = staging_root(self.root)
        path = stage_credential_document(credential, directory)
        attempt, nonce, key = self.module.load_credentials(str(path))
        self.assertEqual(attempt, credential.attempt)
        self.assertEqual(nonce, credential.nonce)
        self.assertEqual(key, credential.key)
        self.assertGreaterEqual(len(key), 32)

    def test_a_host_credential_authenticates_against_the_host_receiver(self):
        """One credential, one guest frame, one host receiver: end to end."""
        credential = mint_credential()
        directory = staging_root(self.root)
        path = stage_credential_document(credential, directory)
        attempt, nonce, key = self.module.load_credentials(str(path))
        payload = self.module.build_event(
            "sync", attempt=attempt, boot_id="boot-1", sequence=0, key=key,
            nonce=nonce)
        receiver = ReceiverState(
            credential.protocol_config(
                producer=self.module.PRODUCER,
                phases=factory_runner.PROGRESS_PHASES,
                statuses=factory_runner.PROGRESS_STATUSES),
            credential.key, deadline=1000.0)
        accepted = receiver.accept(payload, received_at=0.0)
        self.assertFalse(accepted.duplicate)
        self.assertEqual(accepted.envelope["attempt"], credential.attempt)
        receiver.close()

    def test_a_world_readable_staged_document_would_be_refused(self):
        """The reporter's own privacy rule, proved against a real file."""
        credential = mint_credential()
        directory = staging_root(self.root)
        path = stage_credential_document(credential, directory)
        os.chmod(path, 0o644)
        with self.assertRaises(self.module.ReporterError):
            self.module.load_credentials(str(path))


if __name__ == "__main__":
    unittest.main()
