"""The service-start guard uses only temporary files and fake package queries."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SOURCE = (Path(__file__).resolve().parents[1] / "ansible/roles/domain_controller"
          / "files/verify-samba-dns-library.py")
SPEC = importlib.util.spec_from_file_location("samba_dns_library_guard", SOURCE)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class LibraryGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "override"
        self.base = self.root / "official"
        self.directory.mkdir(mode=0o755)
        self.base.mkdir(mode=0o755)
        self.original = b"synthetic official serializer"
        self.patched = b"synthetic uncompressed SRV serializer"
        self.base_digest = hashlib.sha256(self.original).hexdigest()
        (self.directory / guard.SONAME).write_bytes(self.patched)
        (self.base / guard.BASE_FILENAME).write_bytes(self.original)
        (self.base / guard.SONAME).symlink_to(guard.BASE_FILENAME)
        self.receipt = {
            "schema": 1, "library_sha256": hashlib.sha256(self.patched).hexdigest(),
            "base_library_sha256": self.base_digest, "base_package": "smbclient",
            "base_package_version": guard.BASE_VERSION, "soname": guard.SONAME,
            "provenance": {"synthetic": True},
        }
        self.save_receipt()
        self.query = mock.Mock(return_value={name: guard.BASE_VERSION for name in guard.PACKAGES})

    def save_receipt(self):
        (self.directory / "receipt.json").write_text(json.dumps(self.receipt))

    def verify(self, **changes):
        options = dict(base_directory=self.base, owner=os.getuid(), trust_root=self.root,
                       base_sha256=self.base_digest, package_query=self.query)
        options.update(changes)
        return guard.verify(self.directory, **options)

    def test_matching_pair_passes_with_additional_provenance(self):
        self.verify()
        self.query.assert_called_once_with()

    def test_each_package_update_refuses_the_stale_override(self):
        for package in guard.PACKAGES:
            with self.subTest(package=package):
                self.query.return_value = {name: guard.BASE_VERSION for name in guard.PACKAGES}
                self.query.return_value[package] = "2:4.24.6-1"
                with self.assertRaisesRegex(guard.GuardError, "^package-version$"):
                    self.verify()

    def test_changed_patched_or_official_bytes_fail(self):
        for path, category in ((self.directory / guard.SONAME, "patched-digest"),
                               (self.base / guard.BASE_FILENAME, "base-digest")):
            with self.subTest(category=category):
                original = path.read_bytes()
                path.write_bytes(b"unexpected replacement")
                with self.assertRaisesRegex(guard.GuardError, f"^{category}$"):
                    self.verify()
                path.write_bytes(original)
        self.query.assert_not_called()

    def test_receipt_cannot_rebind_package_version_soname_or_base(self):
        for key, wrong in (("schema", True), ("schema", 2),
                           ("base_package", "samba"), ("base_package_version", "future"),
                           ("soname", "other.so"), ("base_library_sha256", "f" * 64),
                           ("library_sha256", self.base_digest)):
            with self.subTest(field=key, value=wrong):
                original = self.receipt[key]
                self.receipt[key] = wrong
                self.save_receipt()
                with self.assertRaisesRegex(guard.GuardError, "^receipt-binding$"):
                    self.verify()
                self.receipt[key] = original
        self.query.assert_not_called()

    def test_malformed_missing_duplicate_and_oversized_receipts_fail(self):
        path = self.directory / "receipt.json"
        for raw in (b"not json", b"[]", b"{}", b'\xff', b'{"schema":1,"schema":1}',
                    b" " * (guard.MAX_RECEIPT_BYTES + 1)):
            with self.subTest(raw_length=len(raw)):
                path.write_bytes(raw)
                with self.assertRaisesRegex(guard.GuardError, "^receipt-format$"):
                    self.verify()

    def test_group_other_writable_file_and_directory_are_rejected(self):
        for path in (self.directory, self.base, self.directory / guard.SONAME,
                     self.directory / "receipt.json", self.base / guard.BASE_FILENAME):
            for permission in (0o020, 0o002):
                with self.subTest(path=path.name, permission=permission):
                    previous = path.stat().st_mode & 0o777
                    path.chmod(previous | permission)
                    with self.assertRaises(guard.GuardError):
                        self.verify()
                    path.chmod(previous)

    def test_owner_mismatch_is_rejected(self):
        with self.assertRaisesRegex(guard.GuardError, "^unsafe-directory$"):
            self.verify(owner=os.getuid() + 1)
        with self.assertRaisesRegex(guard.GuardError, "^unsafe-file$"):
            guard.open_regular(self.directory / guard.SONAME, owner=os.getuid() + 1)

    def test_override_links_and_fifos_are_rejected_without_blocking(self):
        for name in (guard.SONAME, "receipt.json"):
            with self.subTest(name=name):
                path = self.directory / name
                original = path.read_bytes()
                path.unlink()
                path.symlink_to(self.base / guard.BASE_FILENAME)
                with self.assertRaisesRegex(guard.GuardError, "^unsafe-file$"):
                    self.verify()
                path.unlink()
                os.mkfifo(path)
                with self.assertRaisesRegex(guard.GuardError, "^unsafe-file$"):
                    self.verify()
                path.unlink()
                path.write_bytes(original)

    def test_base_soname_retargeting_or_regular_replacement_fails(self):
        link = self.base / guard.SONAME
        other = self.base / "libndr-nbt.so.0.0.2"
        other.write_bytes(self.original)
        link.unlink()
        link.symlink_to(other.name)
        with self.assertRaisesRegex(guard.GuardError, "^base-soname$"):
            self.verify()
        link.unlink()
        link.write_bytes(self.original)
        with self.assertRaisesRegex(guard.GuardError, "^base-soname$"):
            self.verify()

    def test_base_soname_cannot_traverse_a_replaceable_intermediate_link(self):
        intermediate = self.root / "intermediate"
        intermediate.symlink_to(self.base / guard.BASE_FILENAME)
        link = self.base / guard.SONAME
        link.unlink()
        link.symlink_to(intermediate)
        self.assertEqual(link.resolve(), self.base / guard.BASE_FILENAME)
        with self.assertRaisesRegex(guard.GuardError, "^base-soname$"):
            self.verify()

    def test_symlink_directory_and_writable_ancestor_are_rejected(self):
        linked = self.root / "linked"
        linked.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaisesRegex(guard.GuardError, "^unsafe-directory$"):
            guard.trusted_directory(linked, owner=os.getuid(), trust_root=self.root)
        self.root.chmod(0o777)
        with self.assertRaisesRegex(guard.GuardError, "^unsafe-directory$"):
            self.verify()
        self.root.chmod(0o700)


class PackageAndCliTests(unittest.TestCase):
    def test_package_query_uses_absolute_binary_clean_env_and_bound(self):
        result = subprocess.CompletedProcess([], 0, "samba 2:4.24.5-1\nsmbclient 2:4.24.5-1\n", "")
        run = mock.Mock(return_value=result)
        with mock.patch.dict(os.environ, {"LD_LIBRARY_PATH": "private", "LD_PRELOAD": "private"}):
            self.assertEqual({name: guard.BASE_VERSION for name in guard.PACKAGES},
                             guard.installed_packages(run=run))
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/usr/bin/pacman", "-Q", "samba", "smbclient"])
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        self.assertEqual(kwargs["timeout"], 10)
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)

    def test_package_failures_and_ambiguous_output_are_fixed_categories(self):
        for status, output in ((1, "private-value"), (0, "samba 2:4.24.5-1\n"),
                               (0, "samba version\nsamba version\n"),
                               (0, "unexpected private-value\n")):
            run = mock.Mock(return_value=subprocess.CompletedProcess([], status, output, "private-value"))
            with self.subTest(status=status, output_length=len(output)):
                with self.assertRaisesRegex(guard.GuardError, "^package-query$"):
                    guard.installed_packages(run=run)
        run = mock.Mock(side_effect=subprocess.TimeoutExpired("private-value", 10))
        with self.assertRaisesRegex(guard.GuardError, "^package-query$"):
            guard.installed_packages(run=run)

    def test_cli_never_prints_private_exception_text_or_input_path(self):
        for error in (OSError("private-value"), guard.GuardError("private-value"),
                      guard.GuardError("base-digest")):
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(output):
                status = guard.main(["--directory", "/private-value"],
                                    verifier=mock.Mock(side_effect=error))
            self.assertEqual(status, 1)
            self.assertNotIn("private-value", output.getvalue())
            self.assertRegex(output.getvalue(), r"^samba-dns-library-guard: (internal-error|base-digest)\n$")

    def test_cli_accepts_only_directory_and_reports_pass(self):
        output = io.StringIO()
        verify = mock.Mock()
        with redirect_stdout(output):
            self.assertEqual(0, guard.main(["--directory", "/fixture"], verifier=verify))
        verify.assert_called_once_with(Path("/fixture"))
        self.assertEqual(output.getvalue(), "samba-dns-library-guard: pass\n")
        with redirect_stderr(output), self.assertRaises(SystemExit) as caught:
            guard.main(["--directory", "/fixture", "--owner", "private-value"], verifier=verify)
        self.assertEqual(caught.exception.code, 2)
        self.assertNotIn("private-value", output.getvalue())


if __name__ == "__main__":
    unittest.main()
