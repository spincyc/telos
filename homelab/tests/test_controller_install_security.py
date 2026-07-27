"""Security boundaries for the destructive offline Controller installer."""

import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import tempfile
import unittest


INSTALLER = Path(__file__).parents[1] / "seed" / "install-controller"
VERIFIER = INSTALLER.with_name("verify-seed")
SPEC = importlib.util.spec_from_loader(
    "controller_seed_verifier",
    SourceFileLoader("controller_seed_verifier", str(VERIFIER)),
)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class ControllerInstallSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INSTALLER.read_text(encoding="utf-8")

    def test_integrity_check_precedes_first_disk_write(self) -> None:
        first_write = self.source.index("wipefs ")
        before_write = self.source[:first_write]
        self.assertIn("receipt.json", before_write)
        self.assertRegex(
            before_write,
            r"(sha256sum|hashlib|verify[-_]seed|verify[-_]receipt)",
        )

    def test_live_keyring_is_populated_before_first_disk_write(self) -> None:
        populate = self.source.index("pacman-key --populate archlinux")
        first_write = self.source.index("wipefs ")
        self.assertLess(populate, first_write)

    def test_source_archive_is_copied_inert_not_extracted_as_root(self) -> None:
        self.assertNotIn('tar -xzf "$seed_root/source/telos.tar.gz"', self.source)
        self.assertNotRegex(self.source, r"\btar\s+.*(?:-[^\n]*x|--extract)")
        self.assertIn(
            '"$target/opt/telos-source/telos.tar.gz"',
            self.source,
        )

    def test_target_identity_is_rechecked_at_erase_boundary(self) -> None:
        first_write = self.source.index("wipefs ")
        confirmation = self.source.index("confirmation did not match")
        before_write = self.source[confirmation:first_write]
        # Discovery alone is insufficient: removable-device names can be
        # reassigned while the operator is reading the confirmation screen.
        self.assertRegex(
            before_write,
            r"lsblk[^\n]*(?:SERIAL|serial)[^\n]*\"\$disk\"",
        )

    def test_password_never_appears_in_arguments_or_answer_files(self) -> None:
        self.assertIn("passwd local-rescue", self.source)
        self.assertNotRegex(self.source, r"(chpasswd|passwd\s+--stdin)")
        self.assertNotRegex(
            self.source,
            r"(?:printf|echo)[^\n]*\|[^\n]*passwd|"
            r"(?:PASS|PASSWORD|password)=['\"]",
        )

    def test_recovery_kernel_is_default_and_has_fallback_entry(self) -> None:
        self.assertIn("default arch-linux-lts.conf", self.source)
        self.assertIn("arch-linux-lts-fallback.conf", self.source)
        self.assertIn("initramfs-linux-lts-fallback.img", self.source)

    def test_no_network_or_encryption_is_added_during_phase_one(self) -> None:
        self.assertNotRegex(
            self.source,
            r"\b(curl|wget|git\s+(?:clone|pull)|cryptsetup|luksFormat)\b",
        )

    def test_receipt_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory)
            payload = seed / "packages/base.pkg.tar.zst"
            payload.parent.mkdir()
            payload.write_bytes(b"signed package")
            receipt = {
                "payload_files": [{
                    "path": "packages/base.pkg.tar.zst",
                    "bytes": payload.stat().st_size,
                    "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
                }],
            }
            (seed / "receipt.json").write_text(json.dumps(receipt))
            verifier.verify(seed)
            payload.write_bytes(b"substitution")
            with self.assertRaisesRegex(ValueError, "receipt mismatch"):
                verifier.verify(seed)

if __name__ == "__main__":
    unittest.main()
