import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.lib.package_contract import BinaryOwnership, MergedPackageContract
import homelab.lib.package_root_gate as subject
from homelab.lib.package_root_gate import PackageRootGateError, audit_package_root


CONTRACT = MergedPackageContract(
    overlays=("workstation",),
    packages=("alpha", "zulu"),
    binaries=(
        BinaryOwnership("/usr/bin/alpha", "alpha"),
        BinaryOwnership("/usr/bin/zulu", "zulu"),
    ),
)


class PackageRootGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "root"
        (self.root / "var/lib/pacman/local").mkdir(parents=True)
        (self.root / "usr/bin").mkdir(parents=True)
        self.package("alpha", "1.2-3", ("usr/bin/alpha",))
        self.package("zulu", "9.0-1", ("usr/bin/zulu",))
        self.executable("usr/bin/alpha")
        self.executable("usr/bin/zulu")

    def tearDown(self):
        self.temporary.cleanup()

    def package(self, name, version, files):
        directory = self.root / "var/lib/pacman/local" / f"{name}-{version}"
        directory.mkdir()
        (directory / "desc").write_text(
            f"%NAME%\n{name}\n\n%VERSION%\n{version}\n\n",
            encoding="utf-8",
        )
        (directory / "files").write_text(
            "%FILES%\n" + "\n".join(files) + "\n\n",
            encoding="utf-8",
        )

    def executable(self, relative):
        path = self.root / relative
        path.write_bytes(b"binary")
        path.chmod(0o755)

    def test_collects_complete_installed_closure_and_exact_owners(self):
        evidence = audit_package_root(self.root, CONTRACT)
        self.assertEqual(
            [(item.name, item.version) for item in evidence.installed_packages],
            [("alpha", "1.2-3"), ("zulu", "9.0-1")],
        )
        self.assertEqual(evidence.required_packages, ("alpha", "zulu"))
        self.assertEqual(
            [(item.path, item.owner, item.resolved_path)
             for item in evidence.binaries],
            [
                ("/usr/bin/alpha", "alpha", "/usr/bin/alpha"),
                ("/usr/bin/zulu", "zulu", "/usr/bin/zulu"),
            ],
        )

    def test_accepts_guest_confined_binary_symlink(self):
        (self.root / "usr/bin/zulu").unlink()
        (self.root / "opt").mkdir()
        self.executable("opt/zulu")
        (self.root / "usr/bin/zulu").symlink_to("../../opt/zulu")
        files = self.root / "var/lib/pacman/local/zulu-9.0-1/files"
        files.write_text(
            "%FILES%\nusr/bin/zulu\nopt/zulu\n\n", encoding="utf-8")
        evidence = audit_package_root(self.root, CONTRACT)
        self.assertEqual(evidence.binaries[1].resolved_path, "/opt/zulu")

    def test_rejects_unowned_or_wrongly_owned_symlink_target(self):
        (self.root / "usr/bin/zulu").unlink()
        (self.root / "opt").mkdir()
        self.executable("opt/zulu")
        (self.root / "usr/bin/zulu").symlink_to("../../opt/zulu")
        with self.assertRaisesRegex(PackageRootGateError, "resolved owner"):
            audit_package_root(self.root, CONTRACT)

        alpha_files = self.root / "var/lib/pacman/local/alpha-1.2-3/files"
        alpha_files.write_text(
            "%FILES%\nusr/bin/alpha\nopt/zulu\n\n", encoding="utf-8")
        with self.assertRaisesRegex(PackageRootGateError, "resolved owner"):
            audit_package_root(self.root, CONTRACT)

    def test_rejects_symlinked_root_or_database_ancestor(self):
        alias = Path(self.temporary.name) / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(PackageRootGateError, "symlinked ancestor"):
            audit_package_root(alias, CONTRACT)

        pacman = self.root / "var/lib/pacman"
        moved = self.root / "pacman-real"
        pacman.rename(moved)
        pacman.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(PackageRootGateError, "database directory"):
            audit_package_root(self.root, CONTRACT)

    def test_rejects_missing_package_and_wrong_or_duplicate_owner(self):
        (self.root / "var/lib/pacman/local/zulu-9.0-1").rename(
            self.root / "zulu-removed")
        with self.assertRaisesRegex(PackageRootGateError, "not installed"):
            audit_package_root(self.root, CONTRACT)

        (self.root / "zulu-removed").rename(
            self.root / "var/lib/pacman/local/zulu-9.0-1")
        files = self.root / "var/lib/pacman/local/zulu-9.0-1/files"
        files.write_text("%FILES%\nusr/bin/alpha\n\n", encoding="utf-8")
        with self.assertRaisesRegex(PackageRootGateError, "duplicate.*ownership"):
            audit_package_root(self.root, CONTRACT)

    def test_rejects_database_directory_identity_mismatch(self):
        package = self.root / "var/lib/pacman/local/alpha-1.2-3"
        package.rename(self.root / "var/lib/pacman/local/unrelated")
        with self.assertRaisesRegex(PackageRootGateError, "identity differs"):
            audit_package_root(self.root, CONTRACT)

    def test_rejects_unsafe_database_files_and_paths(self):
        desc = self.root / "var/lib/pacman/local/alpha-1.2-3/desc"
        target = self.root / "desc-real"
        desc.rename(target)
        desc.symlink_to(target)
        with self.assertRaisesRegex(PackageRootGateError, "cannot read"):
            audit_package_root(self.root, CONTRACT)

        desc.unlink()
        target.rename(desc)
        files = self.root / "var/lib/pacman/local/alpha-1.2-3/files"
        files.write_text("%FILES%\n../../etc/passwd\n\n", encoding="utf-8")
        with self.assertRaisesRegex(PackageRootGateError, "unsafe package"):
            audit_package_root(self.root, CONTRACT)

        files.write_text("%FILES%\n../../escape/\n\n", encoding="utf-8")
        with self.assertRaisesRegex(PackageRootGateError, "unsafe package"):
            audit_package_root(self.root, CONTRACT)

    def test_rejects_invalid_package_name_and_version_metadata(self):
        desc = self.root / "var/lib/pacman/local/alpha-1.2-3/desc"
        desc.write_text(
            "%NAME%\nAlpha\n\n%VERSION%\n1.2-3\n\n", encoding="utf-8")
        with self.assertRaisesRegex(PackageRootGateError, "invalid package name"):
            audit_package_root(self.root, CONTRACT)

        desc.write_text(
            "%NAME%\nalpha\n\n%VERSION%\n1.2 3\n\n", encoding="utf-8")
        with self.assertRaisesRegex(PackageRootGateError, "invalid version"):
            audit_package_root(self.root, CONTRACT)

    def test_accepts_version_marker_and_detects_database_mutation(self):
        marker = self.root / "var/lib/pacman/local/ALPM_DB_VERSION"
        marker.write_text("9\n", encoding="utf-8")
        self.assertEqual(len(audit_package_root(
            self.root, CONTRACT).installed_packages), 2)

        original = subject._confined_executable
        mutated = False

        def mutating_check(root_fd, guest_path):
            nonlocal mutated
            result = original(root_fd, guest_path)
            if not mutated:
                mutated = True
                desc = self.root / "var/lib/pacman/local/alpha-1.2-3/desc"
                desc.write_text(
                    "%NAME%\nalpha\n\n%VERSION%\n1.2-4\n\n",
                    encoding="utf-8",
                )
            return result

        with (
            mock.patch.object(subject, "_confined_executable", mutating_check),
            self.assertRaisesRegex(PackageRootGateError, "changed during audit"),
        ):
            audit_package_root(self.root, CONTRACT)

    def test_rejects_non_executable_and_escaping_or_looping_symlinks(self):
        alpha = self.root / "usr/bin/alpha"
        alpha.chmod(0o644)
        with self.assertRaisesRegex(PackageRootGateError, "regular executable"):
            audit_package_root(self.root, CONTRACT)

        alpha.unlink()
        alpha.symlink_to("../../../../etc/passwd")
        with self.assertRaisesRegex(PackageRootGateError, "escapes root"):
            audit_package_root(self.root, CONTRACT)

        alpha.unlink()
        alpha.symlink_to("alpha")
        with self.assertRaisesRegex(PackageRootGateError, "too deep"):
            audit_package_root(self.root, CONTRACT)

    def test_rejects_binary_symlink_resolving_to_guest_root(self):
        alpha = self.root / "usr/bin/alpha"
        alpha.unlink()
        alpha.symlink_to("/")
        with self.assertRaisesRegex(PackageRootGateError, "resolves to root"):
            audit_package_root(self.root, CONTRACT)

    def test_requires_files_section_but_permits_it_to_be_empty(self):
        files = self.root / "var/lib/pacman/local/alpha-1.2-3/files"
        files.write_text("%BACKUP%\n\n", encoding="utf-8")
        with self.assertRaisesRegex(PackageRootGateError, "lacks FILES"):
            audit_package_root(self.root, CONTRACT)

        empty_contract = MergedPackageContract(
            overlays=(), packages=("alpha",), binaries=())
        files.write_text("%FILES%\n\n", encoding="utf-8")
        evidence = audit_package_root(self.root, empty_contract)
        self.assertIn("alpha", {
            package.name for package in evidence.installed_packages})

    def test_rejects_absent_or_relative_root(self):
        for root in (Path("relative"), Path(self.temporary.name) / "absent"):
            with self.subTest(root=root), self.assertRaises(PackageRootGateError):
                audit_package_root(root, CONTRACT)


if __name__ == "__main__":
    unittest.main()
