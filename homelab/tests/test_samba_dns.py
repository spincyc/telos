"""Offline admission tests for the one-library Samba DNS override."""
import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import samba_dns as dns


def fixture_receipt(library: Path) -> dict:
    """A valid receipt for temporary fake ELF bytes; mock only dns._elf."""
    pins = dns._json(dns.RESOURCES / "pins.json")
    digest = dns._sha(library)
    return {"schema": 1, "library_sha256": digest, "base_package": "smbclient",
            "base_package_version": pins["base_package_version"],
            "base_library_sha256": pins["base_library_sha256"], "soname": dns.LIBRARY,
            "source": pins["source"], "resources": dns._resources(),
            "abi": dns._json(dns.RESOURCES / "base-abi.json"),
            "validation": copy.deepcopy(dns.VALIDATION),
            "build": {"library_sha256s": [digest, digest], "source_date_epoch": pins["source_date_epoch"],
                      "host_packages": "gcc 16.2\n", "compiler": "gcc fixture"}}


class SambaDnsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        (self.cache / dns.LIBRARY).write_bytes(b"temporary library bytes")
        self.receipt = fixture_receipt(self.cache / dns.LIBRARY)
        self.save()
        self.elf = mock.patch.object(dns, "_elf", return_value=copy.deepcopy(self.receipt["abi"]))
        self.elf.start()
        self.addCleanup(self.elf.stop)

    def save(self):
        (self.cache / "receipt.json").write_text(json.dumps(self.receipt))

    def test_verify_and_stage_are_offline_and_copy_only_verified_pair(self):
        (self.cache / "unrelated-source.tar").write_bytes(b"not deployment media")
        with mock.patch.object(dns, "_acquire", side_effect=AssertionError("network acquire")), \
                mock.patch.object(dns, "_run", side_effect=AssertionError("build or runtime execution")):
            self.assertEqual(dns.verify(self.cache), self.receipt)
            destination = self.root / "staged"
            self.assertEqual(dns.stage(self.cache, destination), self.receipt)
            self.assertEqual(dns.stage(self.cache, destination), self.receipt)
        self.assertEqual({dns.LIBRARY, "receipt.json"}, {p.name for p in destination.iterdir()})

    def test_tampered_library_never_stages(self):
        (self.cache / dns.LIBRARY).write_bytes(b"changed")
        destination = self.root / "staged"
        with self.assertRaisesRegex(dns.SambaDnsError, "SHA-256"):
            dns.stage(self.cache, destination)
        self.assertFalse(destination.exists())

    def test_unproved_source_patch_base_or_results_never_pass(self):
        original = copy.deepcopy(self.receipt)
        changes = (("source", {}), ("resources", {}), ("validation", {}),
                   ("base_package_version", "2:4.25.0-1"), ("base_library_sha256", "0" * 64),
                   ("soname", "libndr.so.6"), ("schema", 2))
        for key, value in changes:
            with self.subTest(key=key):
                self.receipt = {**original, key: value}
                self.save()
                with self.assertRaisesRegex(dns.SambaDnsError, "provenance"):
                    dns.verify(self.cache)

    def test_nonreproducible_or_missing_build_evidence_never_passes(self):
        for build in ({}, None, {**self.receipt["build"], "library_sha256s": ["0" * 64] * 2}):
            with self.subTest(build=build):
                self.receipt["build"] = build
                self.save()
                with self.assertRaisesRegex(dns.SambaDnsError, "reproducible"):
                    dns.verify(self.cache)

    def test_new_symbols_dependencies_or_scratch_runpath_are_rejected(self):
        for key, value in (("defined", []), ("undefined", ["new@GLIBC_9.0 U"]),
                           ("needed", ["unexpected.so"]), ("runpath", ["/tmp/build"]),
                           ("bind_now", False), ("nonexec_stack", False)):
            with self.subTest(key=key), mock.patch.object(dns, "_elf", return_value={**self.receipt["abi"], key: value}):
                with self.assertRaisesRegex(dns.SambaDnsError, "ABI/hardening"):
                    dns.verify(self.cache)

    def test_receipt_cannot_lie_about_actual_elf(self):
        self.receipt["abi"]["needed"] = []
        self.save()
        with self.assertRaisesRegex(dns.SambaDnsError, "ELF metadata"):
            dns.verify(self.cache)

    def test_coherent_receipt_cannot_admit_unchanged_base_library(self):
        resources = self.root / "resources"
        shutil.copytree(dns.RESOURCES, resources)
        pins = json.loads((resources / "pins.json").read_text())
        pins["base_library_sha256"] = dns._sha(self.cache / dns.LIBRARY)
        (resources / "pins.json").write_text(json.dumps(pins))
        with mock.patch.object(dns, "RESOURCES", resources):
            self.receipt = fixture_receipt(self.cache / dns.LIBRARY)
            self.save()
            with self.assertRaisesRegex(dns.SambaDnsError, "unmodified base library"):
                dns.verify(self.cache)

    def test_symlink_library_or_receipt_is_rejected(self):
        for name in (dns.LIBRARY, "receipt.json"):
            with self.subTest(name=name):
                path = self.cache / name
                saved = path.read_bytes()
                path.rename(self.root / name)
                path.symlink_to(self.root / name)
                with self.assertRaisesRegex(dns.SambaDnsError, "regular"):
                    dns.verify(self.cache)
                path.unlink()
                path.write_bytes(saved)

    def test_staging_detects_cache_change_before_publication(self):
        original = shutil.copyfile
        def copy(source, target):
            result = original(source, target)
            if Path(source).name == dns.LIBRARY:
                Path(target).write_bytes(b"changed while copying")
            return result
        destination = self.root / "staged"
        with mock.patch.object(dns.shutil, "copyfile", side_effect=copy):
            with self.assertRaisesRegex(dns.SambaDnsError, "SHA-256"):
                dns.stage(self.cache, destination)
        self.assertFalse(destination.exists())

    def test_invalid_existing_destination_is_preserved(self):
        destination = self.root / "staged"
        destination.mkdir()
        marker = destination / "keep"
        marker.write_bytes(b"pre-existing")
        with self.assertRaises(dns.SambaDnsError):
            dns.stage(self.cache, destination)
        self.assertEqual(marker.read_bytes(), b"pre-existing")

    def test_wrong_signature_fingerprint_is_rejected(self):
        with mock.patch.object(dns, "_run", return_value="[GNUPG:] VALIDSIG " + "A" * 40 + " 0\n"):
            with self.assertRaisesRegex(dns.SambaDnsError, "fingerprint"):
                dns._signature(["gpgv"], "B" * 40, self.root / "log")

    def test_cached_input_hash_mismatch_does_not_download(self):
        inputs = self.root / "inputs"
        inputs.mkdir()
        (inputs / "source.tar").write_bytes(b"corrupt")
        with mock.patch.object(dns, "_run", side_effect=AssertionError("network")):
            with self.assertRaisesRegex(dns.SambaDnsError, "hash mismatch"):
                dns._acquire({"filename": "source.tar", "sha256": "0" * 64, "url": "https://example.invalid"}, inputs, self.root)

    def test_sandbox_disables_network_and_keeps_host_readonly(self):
        command = dns._sandbox(self.root, ["true"], cwd=self.root)
        self.assertEqual(command[:4], ["bwrap", "--ro-bind", "/", "/"])
        self.assertIn("--unshare-net", command)
        self.assertIn("--clearenv", command)
        writable = command.index("--bind")
        self.assertEqual(command[writable + 1:writable + 3], [self.root, self.root])


@unittest.skipUnless(shutil.which("gcc") and shutil.which("readelf") and shutil.which("nm"), "ELF tools unavailable")
class ElfInspectionTests(unittest.TestCase):
    def test_reads_real_elf_and_rejects_unrelated_library(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, library = root / "sample.c", root / "sample.so"
            source.write_text("int sample(void) { return 1; }\n")
            subprocess.run(["gcc", "-shared", "-fPIC", "-Wl,-soname,sample.so", "-Wl,-z,relro,-z,now",
                            "-o", str(library), str(source)], check=True, capture_output=True)
            info = dns._elf(library)
            self.assertEqual(info["soname"], ["sample.so"])
            self.assertIn("sample T", info["defined"])
            self.assertTrue(info["elf64_x86_64"] and info["relro"] and info["bind_now"] and info["nonexec_stack"])
            with self.assertRaisesRegex(dns.SambaDnsError, "ABI/hardening"):
                dns._check_abi(info)


if __name__ == "__main__":
    unittest.main()
