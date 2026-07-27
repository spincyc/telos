import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import media_seal  # noqa: E402


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class MediaSealTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.arch = self.file("arch.iso", b"arch")
        self.windows = self.file("windows.iso", b"windows")
        self.wimboot = self.file("wimboot", b"boot")
        self.arch_receipt = self.document("arch.json", {
            "filename": self.arch.name,
            "sha256": digest(self.arch),
            "source": "https://example.invalid/arch.iso",
            "signing_fingerprint": "A" * 40,
        })
        self.windows_provenance = self.document("windows-provenance.json", {
            "schema": 2,
            "source": "Microsoft Software Download",
            "download_page": "https://www.microsoft.com/software-download/windows11",
            "filename": self.windows.name,
            "bytes": self.windows.stat().st_size,
            "sha256": digest(self.windows),
            "expected_sha256": digest(self.windows),
            "digest_authority": "operator-supplied Microsoft-published SHA-256",
        })
        self.windows_verification = self.document("windows-verification.json", {
            "schema": 1,
            "iso": self.windows.name,
            "sha256": digest(self.windows),
            "edition": "Windows 11 Pro",
            "install_image": "/sources/install.wim",
            "boot_chain": ["/bootmgr"],
        })
        self.wimboot_metadata = self.document("wimboot.json", {
            "schema": 1,
            "name": "wimboot",
            "version": "test",
            "source": "https://github.com/ipxe/wimboot",
            "release": "https://github.com/ipxe/wimboot/releases/tag/vtest",
            "url": "https://github.com/ipxe/wimboot/releases/download/vtest/wimboot",
            "size": self.wimboot.stat().st_size,
            "sha256": digest(self.wimboot),
        })
        self.install_source = self.root / "install-source"
        self.install_source.mkdir()
        self.install_receipt = {
            "edition": "Windows 11 Pro",
            "install_image": "sources/install.wim",
            "bytes": 9,
            "file_count": 2,
            "source_iso_sha256": digest(self.windows),
        }
        self.document("install-source/receipt.json", self.install_receipt)

    def file(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        return path

    def document(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        return path

    def inventory(self):
        with mock.patch.object(
            media_seal.windows_install_source, "verify_cache",
            return_value=self.install_receipt,
        ) as verifier:
            result = media_seal.inventory(
                arch_iso=self.arch,
                arch_receipt=self.arch_receipt,
                windows_iso=self.windows,
                windows_provenance=self.windows_provenance,
                windows_verification=self.windows_verification,
                windows_install_source_path=self.install_source,
                wimboot=self.wimboot,
                wimboot_metadata=self.wimboot_metadata,
            )
        verifier.assert_called_once_with(self.install_source, digest(self.windows))
        return result

    def test_seal_is_deterministic_atomic_and_offline_verifiable(self):
        first = self.inventory()
        second = self.inventory()
        self.assertEqual(first, second)
        self.assertIn("environment_equivalence", first)
        self.assertEqual(1, first["tool_versions"]["media_seal_contract"])
        self.assertIn("python", first["tool_versions"])
        seal = self.root / "seal.json"
        media_seal.write(seal, first)
        self.assertEqual(first, media_seal.verify(seal, second))

    def test_missing_altered_and_symlinked_inputs_are_rejected(self):
        self.arch.write_bytes(b"altered")
        with self.assertRaisesRegex(media_seal.SealError, "Arch ISO differs"):
            self.inventory()
        self.arch.write_bytes(b"arch")
        self.arch.unlink()
        self.arch.symlink_to(self.wimboot)
        with self.assertRaisesRegex(media_seal.SealError, "not bound"):
            self.inventory()
        self.arch.unlink()
        with self.assertRaisesRegex(media_seal.SealError, "regular file"):
            self.inventory()

    def test_receipt_bound_arch_selector_is_accepted(self):
        versioned = self.root / "arch-version.iso"
        self.arch.rename(versioned)
        self.arch.symlink_to(versioned.name)
        receipt = json.loads(self.arch_receipt.read_text())
        receipt["filename"] = versioned.name
        self.arch_receipt.write_text(json.dumps(receipt))
        self.assertEqual("arch-iso", self.inventory()["content"][0]["name"])

    def test_unsafe_arch_selectors_are_rejected(self):
        target = self.root / "arch-version.iso"
        self.arch.rename(target)
        for selected in (target, Path("other.iso"), Path("subdir") / target.name):
            with self.subTest(selected=str(selected)):
                self.arch.unlink(missing_ok=True)
                self.arch.symlink_to(selected)
                with self.assertRaisesRegex(media_seal.SealError, "not bound"):
                    self.inventory()
        self.arch.unlink()
        chained = self.root / "arch-version-link.iso"
        chained.symlink_to(target.name)
        self.arch.symlink_to(chained.name)
        receipt = json.loads(self.arch_receipt.read_text())
        receipt["filename"] = chained.name
        self.arch_receipt.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(media_seal.SealError, "non-symlink"):
            self.inventory()

    def test_wrong_edition_and_unlisted_receipt_fields_are_rejected(self):
        receipt = json.loads(self.windows_verification.read_text())
        receipt["edition"] = "Windows 11 Home"
        self.windows_verification.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(media_seal.SealError, "not Windows 11 Pro"):
            self.inventory()
        receipt["edition"] = "Windows 11 Pro"
        receipt["surprise"] = "unlisted"
        self.windows_verification.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(media_seal.SealError, "unlisted"):
            self.inventory()

    def test_tampered_or_extended_seal_is_rejected(self):
        expected = self.inventory()
        seal = self.root / "seal.json"
        media_seal.write(seal, expected)
        actual = json.loads(seal.read_text())
        actual["unlisted"] = True
        seal.write_text(json.dumps(actual))
        with self.assertRaisesRegex(media_seal.SealError, "differs"):
            media_seal.verify(seal, expected)

    def test_changed_hash_snapshot_is_rejected(self):
        stable = (1, 2, self.arch.stat().st_size, 3, 4)
        changed = (1, 2, self.arch.stat().st_size, 5, 6)
        with mock.patch.object(
            media_seal, "_snapshot", side_effect=(stable, stable, changed)
        ):
            with self.assertRaisesRegex(media_seal.SealError, "changed"):
                media_seal._record("arch-iso", self.arch)

    def test_hard_linked_sealed_file_is_rejected(self):
        (self.root / "arch-copy.iso").hardlink_to(self.arch)
        with self.assertRaisesRegex(media_seal.SealError, "single-link"):
            media_seal._record("arch-iso", self.arch)


if __name__ == "__main__":
    unittest.main()
