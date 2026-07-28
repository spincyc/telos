import json
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from homelab.vm.windows_identity_receipt import (
    KIND,
    PHASES,
    deserialize,
    read,
    serialize,
    write,
)
from homelab.vm.windows_identity_run import IdentityReceipt


def complete_receipt():
    return IdentityReceipt(
        phases=list(PHASES),
        local_credential_rotated=True,
        private_publication_destroyed=True,
        controller_principals_staged=True,
        controller_principals_destroyed=True,
        acceptance_complete=True,
        teardown_complete=True,
    )


class WindowsIdentityReceiptTests(unittest.TestCase):
    def test_round_trip_contains_only_closed_secret_free_facts(self):
        encoded = serialize(complete_receipt())
        document = json.loads(encoded)
        self.assertEqual(KIND, document["kind"])
        self.assertEqual(list(PHASES), document["phases"])
        self.assertEqual({
            "schema", "kind", "phases",
            "local_credential_rotated",
            "private_publication_destroyed",
            "controller_principals_staged",
            "controller_principals_destroyed",
            "acceptance_complete",
            "teardown_complete",
        }, set(document))
        self.assertEqual(document, deserialize(encoded))

    def test_rejects_incomplete_or_reordered_lifecycle(self):
        for phases in (list(PHASES[:-1]), list(reversed(PHASES))):
            with self.subTest(phases=phases):
                with self.assertRaisesRegex(ValueError, "ordered lifecycle"):
                    serialize(replace(complete_receipt(), phases=phases))
        with self.assertRaisesRegex(ValueError, "lacks proof"):
            serialize(replace(
                complete_receipt(), private_publication_destroyed=False))

    def test_rejects_extra_fields_and_non_boolean_proofs(self):
        document = json.loads(serialize(complete_receipt()))
        document["credential"] = "must-not-be-retained"
        with self.assertRaisesRegex(ValueError, "unexpected"):
            deserialize(json.dumps(document))
        document.pop("credential")
        document["teardown_complete"] = 1
        with self.assertRaisesRegex(ValueError, "lacks proof"):
            deserialize(json.dumps(document))

    def test_atomic_write_is_private_and_replaces_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence" / "identity.json"
            write(path, complete_receipt())
            first_inode = path.stat().st_ino
            write(path, complete_receipt())
            self.assertNotEqual(first_inode, path.stat().st_ino)
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE(path.parent.stat().st_mode))
            self.assertEqual(list(PHASES), read(path)["phases"])

    def test_read_rejects_public_file_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "identity.json"
            write(path, complete_receipt())
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode 0600"):
                read(path)
            path.chmod(0o600)
            link = root / "link.json"
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "regular file"):
                read(link)


if __name__ == "__main__":
    unittest.main()
