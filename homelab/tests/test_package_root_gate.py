from dataclasses import replace
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.lib.package_contract import (
    BinaryOwnership,
    MergedPackageContract,
    ModuleRequirement,
)
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

        original = subject._confined_file
        mutated = False

        def mutating_check(root_fd, guest_path, **keywords):
            nonlocal mutated
            result = original(root_fd, guest_path, **keywords)
            if not mutated:
                mutated = True
                desc = self.root / "var/lib/pacman/local/alpha-1.2-3/desc"
                desc.write_text(
                    "%NAME%\nalpha\n\n%VERSION%\n1.2-4\n\n",
                    encoding="utf-8",
                )
            return result

        with (
            mock.patch.object(subject, "_confined_file", mutating_check),
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


SITE = "usr/lib/python3.14/site-packages"
MODULE_CONTRACT = MergedPackageContract(
    overlays=("controller-domain",),
    packages=("alpha", "zulu"),
    binaries=(),
    modules=(
        ModuleRequirement("ldb", "zulu", "repository"),
        ModuleRequirement("samba.auth", "alpha", "repository"),
        ModuleRequirement("samba.provision", "alpha", "repository"),
        ModuleRequirement("samba.samdb", "alpha", "repository"),
    ),
)


class PackageRootModuleTests(unittest.TestCase):
    """A declared import is proven the way a declared binary is: the file the
    import resolves to exists in the root and ALPM attributes it to exactly the
    package the contract names."""

    ALPHA_FILES = (
        f"{SITE}/samba/__init__.py",
        f"{SITE}/samba/auth.cpython-314-x86_64-linux-gnu.so",
        f"{SITE}/samba/provision/__init__.py",
        f"{SITE}/samba/samdb.py",
    )
    ZULU_FILES = (f"{SITE}/ldb.cpython-314-x86_64-linux-gnu.so",)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "root"
        (self.root / "var/lib/pacman/local").mkdir(parents=True)
        self.build("alpha", "1.2-3", self.ALPHA_FILES)
        self.build("zulu", "9.0-1", self.ZULU_FILES)

    def tearDown(self):
        self.temporary.cleanup()

    def build(self, name, version, files):
        directory = self.root / "var/lib/pacman/local" / f"{name}-{version}"
        directory.mkdir()
        (directory / "desc").write_text(
            f"%NAME%\n{name}\n\n%VERSION%\n{version}\n\n", encoding="utf-8")
        (directory / "files").write_text(
            "%FILES%\n" + "\n".join(files) + "\n\n", encoding="utf-8")
        for relative in files:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"module")

    def test_proves_every_declared_module_and_records_where_it_resolved(self):
        evidence = audit_package_root(self.root, MODULE_CONTRACT)
        self.assertEqual(
            [(item.name, item.owner, item.path) for item in evidence.modules],
            [
                ("ldb", "zulu",
                 f"/{SITE}/ldb.cpython-314-x86_64-linux-gnu.so"),
                ("samba.auth", "alpha",
                 f"/{SITE}/samba/auth.cpython-314-x86_64-linux-gnu.so"),
                ("samba.provision", "alpha",
                 f"/{SITE}/samba/provision/__init__.py"),
                ("samba.samdb", "alpha", f"/{SITE}/samba/samdb.py"),
            ],
        )

    def test_a_module_need_not_be_executable(self):
        """A binary must carry the exec bit; a python file must not have to."""
        (self.root / SITE / "samba/samdb.py").chmod(0o644)
        self.assertEqual(len(audit_package_root(
            self.root, MODULE_CONTRACT).modules), 4)

    def test_rejects_a_module_no_package_ships(self):
        contract = replace(MODULE_CONTRACT, modules=(
            ModuleRequirement("samba.netcmd", "alpha", "repository"),))
        with self.assertRaisesRegex(
                PackageRootGateError,
                "required python module is absent: samba.netcmd"):
            audit_package_root(self.root, contract)

    def test_rejects_a_module_owned_by_another_package(self):
        contract = replace(MODULE_CONTRACT, modules=(
            ModuleRequirement("ldb", "alpha", "repository"),))
        with self.assertRaisesRegex(
                PackageRootGateError, "wrong module owner: ldb"):
            audit_package_root(self.root, contract)

    def test_rejects_a_module_the_database_claims_but_the_root_lacks(self):
        """An ALPM record is a claim about the root, not the root itself."""
        (self.root / SITE / "samba/samdb.py").unlink()
        with self.assertRaisesRegex(
                PackageRootGateError, "cannot inspect required module"):
            audit_package_root(self.root, MODULE_CONTRACT)

    def test_rejects_a_module_symlinked_out_of_the_root(self):
        target = self.root / SITE / "samba/samdb.py"
        target.unlink()
        target.symlink_to("../../../../../../etc/passwd")
        with self.assertRaisesRegex(PackageRootGateError, "escapes root"):
            audit_package_root(self.root, MODULE_CONTRACT)

    def test_refuses_a_root_without_exactly_one_site_packages(self):
        """A module found only under the interpreter that is not the default
        would prove nothing about what actually runs, so an ambiguous root is
        refused rather than guessed at."""
        self.build("yankee", "1-1",
                   ("usr/lib/python3.13/site-packages/ldb.py",))
        with self.assertRaisesRegex(
                PackageRootGateError, "exactly one python site-packages"):
            audit_package_root(self.root, MODULE_CONTRACT)

        bare = MergedPackageContract(
            overlays=(), packages=("alpha",), binaries=(), modules=())
        self.assertEqual(audit_package_root(self.root, bare).modules, ())

    def test_a_root_with_no_python_at_all_refuses_a_module_contract(self):
        empty = Path(self.temporary.name) / "bare"
        (empty / "var/lib/pacman/local/alpha-1.2-3").mkdir(parents=True)
        database = empty / "var/lib/pacman/local/alpha-1.2-3"
        database.joinpath("desc").write_text(
            "%NAME%\nalpha\n\n%VERSION%\n1.2-3\n\n", encoding="utf-8")
        database.joinpath("files").write_text("%FILES%\n\n", encoding="utf-8")
        contract = MergedPackageContract(
            overlays=(), packages=("alpha",), binaries=(),
            modules=(ModuleRequirement("ldb", "alpha", "repository"),))
        with self.assertRaisesRegex(
                PackageRootGateError, "exactly one python site-packages"):
            audit_package_root(empty, contract)


if __name__ == "__main__":
    unittest.main()
