import contextlib
import hashlib
import io
import json
import runpy
import subprocess
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
        self.samba_dns_cache = self.root / "samba-dns"
        self.samba_library = self.file("samba-dns/libndr-nbt.so.0", b"fixture library")
        resources = media_seal.samba_dns.RESOURCES
        pins = json.loads((resources / "pins.json").read_text())
        abi = json.loads((resources / "base-abi.json").read_text())
        self.samba_receipt = {
            "schema": 1,
            "library_sha256": digest(self.samba_library),
            "base_library_sha256": pins["base_library_sha256"],
            "base_package": "smbclient",
            "base_package_version": pins["base_package_version"],
            "soname": "libndr-nbt.so.0",
            "source": pins["source"],
            "resources": {name: digest(resources / name)
                          for name in media_seal.samba_dns.RESOURCE_FILES},
            "abi": abi,
            "build": {
                "library_sha256s": [digest(self.samba_library)] * 2,
                "source_date_epoch": pins["source_date_epoch"],
                "compiler": "fixture compiler",
                "host_packages": "fixture packages",
            },
            "validation": dict(media_seal.samba_dns.VALIDATION),
        }
        self.samba_receipt_path = self.document(
            "samba-dns/receipt.json", self.samba_receipt)
        # The media seal exercises the real cache/receipt validator. Only ELF
        # inspection is substituted, so fixtures never require a built library.
        self.elf = self.enterContext(mock.patch.object(
            media_seal.samba_dns, "_elf", return_value=abi))

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
                samba_dns_cache=self.samba_dns_cache,
            )
        verifier.assert_called_once_with(self.install_source, digest(self.windows))
        self.elf.assert_called_with(self.samba_library)
        return result

    def test_seal_is_deterministic_atomic_and_offline_verifiable(self):
        first = self.inventory()
        second = self.inventory()
        self.assertEqual(first, second)
        self.assertIn("environment_equivalence", first)
        self.assertEqual(2, first["tool_versions"]["media_seal_contract"])
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

    def sealed_with(self, expected, change):
        seal = self.root / "seal.json"
        media_seal.write(seal, expected)
        actual = json.loads(seal.read_text())
        change(actual)
        seal.write_text(json.dumps(actual))
        return seal, actual

    def test_tool_version_difference_alone_is_reported_not_failed(self):
        expected = self.inventory()

        def older_python(receipt):
            receipt["tool_versions"]["python"] = "0.0.1"

        seal, sealed = self.sealed_with(expected, older_python)
        notices = []
        self.assertEqual(
            sealed, media_seal.verify(seal, expected, notice=notices.append))
        self.assertEqual(1, len(notices))
        self.assertIn("tool versions differ", notices[0])
        self.assertIn(
            f"python: sealed 0.0.1, now {expected['tool_versions']['python']}",
            notices[0],
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            media_seal.verify(seal, expected)
        self.assertIn("python: sealed 0.0.1", stderr.getvalue())

    def test_matching_tool_versions_emit_no_notice(self):
        expected = self.inventory()
        seal, _ = self.sealed_with(expected, lambda receipt: None)
        notices = []
        media_seal.verify(seal, expected, notice=notices.append)
        self.assertEqual([], notices)

    def test_content_or_provenance_difference_fails_despite_tool_versions(self):
        def content(receipt):
            receipt["content"][0]["sha256"] = "0" * 64

        def provenance(receipt):
            receipt["provenance"]["records"][0]["sha256"] = "0" * 64

        def assertion(receipt):
            receipt["provenance"]["assertions"]["wimboot_version"] = "other"

        def equivalence(receipt):
            receipt["environment_equivalence"]["validators"].pop()

        def missing_tool_versions(receipt):
            del receipt["tool_versions"]

        expected = self.inventory()
        for change in (
            content, provenance, assertion, equivalence, missing_tool_versions,
        ):
            for tools_also_differ in (False, True):
                with self.subTest(change=change.__name__, tools=tools_also_differ):
                    def mutate(receipt):
                        change(receipt)
                        if tools_also_differ and "tool_versions" in receipt:
                            receipt["tool_versions"]["python"] = "0.0.1"

                    seal, _ = self.sealed_with(expected, mutate)
                    notices = []
                    with self.assertRaisesRegex(media_seal.SealError, "differs"):
                        media_seal.verify(seal, expected, notice=notices.append)
                    self.assertEqual([], notices)

        def malformed_tool_versions(receipt):
            receipt["tool_versions"] = "python 0.0.1"

        seal, _ = self.sealed_with(expected, malformed_tool_versions)
        with self.assertRaisesRegex(media_seal.SealError, "JSON object"):
            media_seal.verify(seal, expected, notice=self.fail)

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

    def test_samba_repair_bytes_and_pinned_provenance_are_sealed(self):
        receipt = self.inventory()
        content = {item["name"]: item for item in receipt["content"]}
        provenance = {item["name"]: item
                      for item in receipt["provenance"]["records"]}
        self.assertEqual(content["samba-dns-library"], {
            "name": "samba-dns-library",
            "bytes": self.samba_library.stat().st_size,
            "sha256": digest(self.samba_library),
        })
        self.assertEqual(provenance["samba-dns-receipt"]["sha256"],
                         digest(self.samba_receipt_path))
        self.assertEqual(receipt["provenance"]["assertions"]["samba_dns"],
                         self.samba_receipt)
        self.assertIn("samba_dns.verify",
                      receipt["environment_equivalence"]["validators"])

    def test_missing_corrupt_and_symlinked_repair_files_are_rejected(self):
        for path in (self.samba_library, self.samba_receipt_path):
            original = path.read_bytes()
            for mutation in ("missing", "corrupt", "symlink"):
                with self.subTest(file=path.name, mutation=mutation):
                    path.unlink()
                    if mutation == "corrupt":
                        path.write_bytes(b"corrupt")
                    elif mutation == "symlink":
                        path.symlink_to(self.wimboot)
                    try:
                        with self.assertRaises(media_seal.SealError):
                            self.inventory()
                    finally:
                        path.unlink(missing_ok=True)
                        path.write_bytes(original)

    def test_changed_valid_repair_receipt_cannot_match_the_previous_seal(self):
        sealed = self.inventory()
        seal = self.root / "seal.json"
        media_seal.write(seal, sealed)
        # Semantically identical JSON still changes the sealed artifact bytes.
        self.samba_receipt_path.write_text(
            json.dumps(self.samba_receipt, indent=2) + "\n")
        changed = self.inventory()
        with self.assertRaisesRegex(media_seal.SealError, "differs"):
            media_seal.verify(seal, changed)

    def test_changed_verified_library_cannot_match_the_previous_seal(self):
        seal = self.root / "seal.json"
        media_seal.write(seal, self.inventory())
        self.samba_library.write_bytes(b"different fixture library")
        new_digest = digest(self.samba_library)
        self.samba_receipt["library_sha256"] = new_digest
        self.samba_receipt["build"]["library_sha256s"] = [new_digest] * 2
        self.samba_receipt_path.write_text(json.dumps(self.samba_receipt))
        changed = self.inventory()
        with self.assertRaisesRegex(media_seal.SealError, "differs"):
            media_seal.verify(seal, changed)

    def test_changed_pinned_repair_provenance_is_rejected(self):
        self.samba_receipt["base_package_version"] = "unsupported"
        self.samba_receipt_path.write_text(json.dumps(self.samba_receipt))
        with self.assertRaisesRegex(media_seal.SealError, "Samba DNS repair does not verify"):
            self.inventory()

    def test_underlying_elf_refusal_is_not_bypassed(self):
        self.elf.side_effect = media_seal.samba_dns.SambaDnsError("fixture ABI mismatch")
        with self.assertRaisesRegex(media_seal.SealError, "fixture ABI mismatch"):
            self.inventory()

    def test_repair_changed_during_verification_cannot_be_sealed(self):
        for path in (self.samba_library, self.samba_receipt_path):
            original = path.read_bytes()

            def change_after_hash(_library):
                if path == self.samba_library:
                    path.write_bytes(original + b"changed")
                else:
                    changed = json.loads(original)
                    changed["build"]["compiler"] = "changed fixture compiler"
                    path.write_text(json.dumps(changed))
                return self.elf.return_value

            with self.subTest(file=path.name):
                self.elf.side_effect = change_after_hash
                try:
                    with self.assertRaises(media_seal.SealError):
                        self.inventory()
                finally:
                    path.write_bytes(original)
                    self.elf.side_effect = None

    def test_old_seal_without_the_required_repair_cannot_pass(self):
        expected = self.inventory()

        def remove_repair(receipt):
            receipt["tool_versions"]["media_seal_contract"] = 1
            receipt["content"] = [item for item in receipt["content"]
                                  if item["name"] != "samba-dns-library"]
            receipt["provenance"]["records"] = [
                item for item in receipt["provenance"]["records"]
                if item["name"] != "samba-dns-receipt"]
            del receipt["provenance"]["assertions"]["samba_dns"]
            receipt["environment_equivalence"]["validators"].remove(
                "samba_dns.verify")

        seal, _ = self.sealed_with(expected, remove_repair)
        with self.assertRaisesRegex(media_seal.SealError, "differs"):
            media_seal.verify(seal, expected, notice=self.fail)

    def cli_args(self, action="create", *, repair=True):
        args = ["homelab-media-seal", action, "--seal", str(self.root / "seal.json")]
        for option, path in (
            ("arch-iso", self.arch), ("arch-receipt", self.arch_receipt),
            ("windows-iso", self.windows),
            ("windows-provenance", self.windows_provenance),
            ("windows-verification", self.windows_verification),
            ("windows-install-source", self.install_source),
            ("wimboot", self.wimboot), ("wimboot-metadata", self.wimboot_metadata),
        ):
            args.extend(("--" + option, str(path)))
        if repair:
            args.extend(("--samba-dns-cache", str(self.samba_dns_cache)))
        return args

    def test_cli_requires_repair_before_touching_inputs(self):
        cli = runpy.run_path(str(ROOT / "bin/homelab-media-seal"))["main"]
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", self.cli_args(repair=False)), \
                mock.patch.object(subprocess, "run") as run, \
                contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as error:
                cli()
        self.assertEqual(error.exception.code, 2)
        self.assertIn("--samba-dns-cache", stderr.getvalue())
        run.assert_not_called()

    def test_cli_forwards_required_cache_for_both_actions(self):
        cli = runpy.run_path(str(ROOT / "bin/homelab-media-seal"))["main"]
        expected = self.inventory()
        for action in ("create", "verify"):
            stdout = io.StringIO()
            with self.subTest(action=action), \
                    mock.patch.object(sys, "argv", self.cli_args(action)), \
                    mock.patch.object(subprocess, "run",
                                      return_value=subprocess.CompletedProcess([], 0)), \
                    mock.patch.object(media_seal.windows_install_source, "verify_cache",
                                      return_value=self.install_receipt), \
                    contextlib.redirect_stdout(stdout):
                self.assertEqual(cli(), 0)
                self.assertEqual(json.loads(stdout.getvalue()), expected)
                self.assertEqual(json.loads((self.root / "seal.json").read_text()),
                                 expected)


if __name__ == "__main__":
    unittest.main()
