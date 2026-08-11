"""Contracts for the offline workstation pacman repository cache."""

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from homelab.lib import workstation_repo
from homelab.lib.package_contract import (
    PROFILE_OVERLAYS, load_registry, merge_contract)


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "homelab/package-contract.json"


def fake_archive(name: str) -> str:
    return f"{name}-1.0-1-x86_64.pkg.tar.zst"


def make_repo(root: Path, requested, *, extra_packages=()):
    """Stage a fake flat repository and seal it with a real receipt."""
    root.mkdir(parents=True)
    for name in (*requested, *extra_packages):
        archive = root / fake_archive(name)
        archive.write_bytes(f"signed archive {name}".encode())
        (root / (archive.name + ".sig")).write_bytes(b"detached signature")
    (root / workstation_repo.DATABASE).write_bytes(b"pacman database")
    (root / f"{workstation_repo.REPO_NAME}.db").write_bytes(b"pacman database")
    receipt = workstation_repo.build_receipt(
        root, list(requested),
        contract_sha256=workstation_repo.sha256(CONTRACT))
    (root / workstation_repo.RECEIPT_NAME).write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return receipt


class ClosureResolutionTests(unittest.TestCase):
    def test_resolves_exactly_the_workstation_install_contract(self):
        expected = merge_contract(
            load_registry(CONTRACT), PROFILE_OVERLAYS["workstation-install"]
        ).packages
        self.assertEqual(
            workstation_repo.resolve_contract_packages(CONTRACT), expected)
        self.assertIn("linux-lts", expected)

    def test_command_plan_uses_the_seed_download_machinery(self):
        packages = workstation_repo.resolve_contract_packages(CONTRACT)
        plan = workstation_repo.command_plan(
            packages, Path("<stage>"),
            workstation_repo.DEFAULT_PACMAN_CONFIG)
        download, repo_add = plan
        self.assertEqual(download[:2], ["fakeroot", "pacman"])
        self.assertIn("-Syw", download)
        self.assertIn(str(workstation_repo.DEFAULT_PACMAN_CONFIG), download)
        for package in packages:
            self.assertIn(package, download)
        self.assertEqual(repo_add[0], "repo-add")
        self.assertIn(workstation_repo.DATABASE, repo_add[1])


class RepoVerifyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "workstation-repo"
        self.requested = workstation_repo.resolve_contract_packages(CONTRACT)
        self.receipt = make_repo(
            self.root, self.requested, extra_packages=("glibc", "zstd"))

    def test_sealed_repository_verifies_and_reports_identity(self):
        summary = workstation_repo.verify_repo(
            self.root, contract_packages=self.requested)
        self.assertEqual(
            summary["packages"], len(self.requested) + 2)
        self.assertEqual(summary["database"], workstation_repo.DATABASE)
        self.assertEqual(
            summary["receipt_sha256"],
            workstation_repo.sha256(
                self.root / workstation_repo.RECEIPT_NAME))
        self.assertGreater(summary["bytes"], 0)

    def test_receipt_is_deterministic_given_the_resolved_set(self):
        frozen = "2026-08-11T00:00:00+00:00"
        first = workstation_repo.build_receipt(
            self.root, list(self.requested),
            contract_sha256=workstation_repo.sha256(CONTRACT),
            created_utc=frozen)
        second = workstation_repo.build_receipt(
            self.root, list(self.requested),
            contract_sha256=workstation_repo.sha256(CONTRACT),
            created_utc=frozen)
        self.assertEqual(first, second)
        self.assertEqual(
            first["package_verification"],
            "pacman repository signatures required by build-host policy")

    def test_missing_repository_is_refused(self):
        with self.assertRaisesRegex(
                workstation_repo.WorkstationRepoError, "missing"):
            workstation_repo.verify_repo(
                self.root / "absent", contract_packages=self.requested)

    def test_missing_receipt_is_unsealed(self):
        (self.root / workstation_repo.RECEIPT_NAME).unlink()
        with self.assertRaisesRegex(
                workstation_repo.WorkstationRepoError, "unsealed"):
            workstation_repo.verify_repo(
                self.root, contract_packages=self.requested)

    def test_tampered_package_bytes_are_refused(self):
        archive = self.root / fake_archive(self.requested[0])
        archive.write_bytes(b"altered bytes")
        with self.assertRaisesRegex(
                workstation_repo.WorkstationRepoError, "differs"):
            workstation_repo.verify_repo(
                self.root, contract_packages=self.requested)

    def test_unlisted_file_is_refused(self):
        (self.root / "stray.bin").write_bytes(b"stray")
        with self.assertRaisesRegex(
                workstation_repo.WorkstationRepoError, "unlisted"):
            workstation_repo.verify_repo(
                self.root, contract_packages=self.requested)

    def test_deleted_database_is_refused(self):
        (self.root / workstation_repo.DATABASE).unlink()
        with self.assertRaisesRegex(
                workstation_repo.WorkstationRepoError, "missing"):
            workstation_repo.verify_repo(
                self.root, contract_packages=self.requested)

    def test_contract_drift_is_refused(self):
        with self.assertRaisesRegex(
                workstation_repo.WorkstationRepoError, "different package "
                "contract"):
            workstation_repo.verify_repo(
                self.root,
                contract_packages=(*self.requested, "newly-required"))

    def test_symlinked_payload_is_refused(self):
        archive = self.root / fake_archive(self.requested[0])
        replacement = archive.with_name("real-target")
        os.rename(archive, replacement)
        archive.symlink_to(replacement.name)
        with self.assertRaisesRegex(
                workstation_repo.WorkstationRepoError, "symlink"):
            workstation_repo.verify_repo(
                self.root, contract_packages=self.requested)


class ReceiptParseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "workstation-repo"
        self.requested = ("bash", "linux-lts")
        self.receipt = make_repo(self.root, self.requested)

    def parse(self, mutate):
        value = copy.deepcopy(self.receipt)
        mutate(value)
        return workstation_repo.parse_receipt(value)

    def test_receipt_without_signature_entry_is_refused(self):
        def drop_signature(value):
            value["payload_files"] = [
                entry for entry in value["payload_files"]
                if not entry["path"].endswith(".sig")
            ]
        with self.assertRaisesRegex(
                workstation_repo.WorkstationRepoError,
                "no detached signature"):
            self.parse(drop_signature)

    def test_requested_package_absent_from_closure_is_refused(self):
        def add_requested(value):
            value["requested_packages"].append("absent-package")
        with self.assertRaisesRegex(
                workstation_repo.WorkstationRepoError,
                "absent from the closure"):
            self.parse(add_requested)

    def test_unknown_field_and_wrong_policy_are_refused(self):
        with self.assertRaisesRegex(
                workstation_repo.WorkstationRepoError, "unknown field"):
            self.parse(lambda value: value.update(surprise=1))
        with self.assertRaisesRegex(
                workstation_repo.WorkstationRepoError, "signed policy"):
            self.parse(lambda value: value.update(
                package_verification="none"))

    def test_invalid_archive_identity_is_refused(self):
        def rename(value):
            value["package_files"][0]["name"] = "not-an-archive.tar"
        with self.assertRaisesRegex(
                workstation_repo.WorkstationRepoError, "suffix"):
            self.parse(rename)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / "workstation-repo"
        self.requested = workstation_repo.resolve_contract_packages(CONTRACT)

    def runner(self, *, sign=True):
        commands = []

        def run(command, check=True, **_kwargs):
            commands.append(command)
            if command[1] == "pacman":
                cache = Path(command[command.index("--cachedir") + 1])
                for name in (*self.requested, "glibc"):
                    archive = cache / fake_archive(name)
                    archive.write_bytes(f"pkg {name}".encode())
                    if sign:
                        (cache / (archive.name + ".sig")).write_bytes(b"sig")
            elif command[0] == "repo-add":
                database = Path(command[1])
                database.write_bytes(b"database")
                # repo-add leaves a convenience symlink beside the archive.
                link = database.with_name(f"{workstation_repo.REPO_NAME}.db")
                link.symlink_to(database.name)
            else:
                raise AssertionError(f"unexpected command: {command}")
            return None

        return run, commands

    def test_build_downloads_signs_seals_and_verifies(self):
        run, commands = self.runner()
        summary = workstation_repo.build(
            self.output, contract=CONTRACT, runner=run)
        self.assertEqual(commands[0][:2], ["fakeroot", "pacman"])
        self.assertIn("-Syw", commands[0])
        self.assertEqual(commands[1][0], "repo-add")
        self.assertEqual(summary["packages"], len(self.requested) + 1)
        # The published cache holds only regular files; the repo-add
        # convenience symlink was materialized into exact bytes.
        link = self.output / f"{workstation_repo.REPO_NAME}.db"
        self.assertFalse(link.is_symlink())
        self.assertEqual(link.read_bytes(), b"database")
        reverified = workstation_repo.verify_repo(
            self.output, contract_packages=self.requested)
        self.assertEqual(reverified["receipt_sha256"],
                         summary["receipt_sha256"])

    def test_unsigned_archive_refuses_the_whole_build(self):
        run, _commands = self.runner(sign=False)
        with self.assertRaisesRegex(
                workstation_repo.WorkstationRepoError,
                "no detached signature"):
            workstation_repo.build(
                self.output, contract=CONTRACT, runner=run)
        self.assertFalse(self.output.exists())

    def test_rebuild_replaces_the_previous_cache_atomically(self):
        run, _commands = self.runner()
        workstation_repo.build(self.output, contract=CONTRACT, runner=run)
        marker = self.output / workstation_repo.RECEIPT_NAME
        first = marker.read_bytes()
        run, _commands = self.runner()
        workstation_repo.build(self.output, contract=CONTRACT, runner=run)
        self.assertTrue(marker.is_file())
        workstation_repo.verify_repo(
            self.output, contract_packages=self.requested)
        # No staging or displaced-cache residue survives the swap.
        self.assertEqual(
            [path.name for path in sorted(self.output.parent.iterdir())],
            [self.output.name])
        self.assertNotEqual(first, b"")


if __name__ == "__main__":
    unittest.main()
