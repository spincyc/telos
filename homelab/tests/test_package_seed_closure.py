import unittest

from homelab.lib.package_contract import BinaryOwnership, MergedPackageContract
from homelab.lib.package_root_gate import InstalledPackage, PackageRootEvidence
from homelab.lib.package_seed_closure import (
    SeedClosureError,
    SeedPackage,
    parse_seed_receipt,
    reconcile_seed_closure,
)


COMMIT = "a" * 40
DIGEST_SOURCE = "0" * 64
DIGEST_ALPHA = "1" * 64
DIGEST_ALPHA_SIG = "2" * 64
DIGEST_ZULU = "3" * 64
DIGEST_ZULU_SIG = "4" * 64
DIGEST_DATABASE = "5" * 64

CONTRACT = MergedPackageContract(
    overlays=("workstation",),
    packages=("alpha", "zulu"),
    binaries=(
        BinaryOwnership("/usr/bin/alpha", "alpha"),
        BinaryOwnership("/usr/bin/zulu", "zulu"),
    ),
)


def receipt():
    return {
        "schema": 1,
        "created_utc": "2026-07-30T00:00:00+00:00",
        "source": {
            "commit": COMMIT,
            "archive": "source/telos.tar.gz",
            "sha256": DIGEST_SOURCE,
            "tracked_files_only": True,
        },
        "requested_packages": ["alpha"],
        "package_files": [
            {
                "name": "alpha-1.2-3-x86_64.pkg.tar.zst",
                "bytes": 10,
                "sha256": DIGEST_ALPHA,
            },
            {
                "name": "zulu-9.0-1-any.pkg.tar.zst",
                "bytes": 20,
                "sha256": DIGEST_ZULU,
            },
        ],
        "payload_files": [
            {
                "path": "packages/alpha-1.2-3-x86_64.pkg.tar.zst",
                "bytes": 10,
                "sha256": DIGEST_ALPHA,
            },
            {
                "path": "packages/alpha-1.2-3-x86_64.pkg.tar.zst.sig",
                "bytes": 1,
                "sha256": DIGEST_ALPHA_SIG,
            },
            {
                "path": "packages/zulu-9.0-1-any.pkg.tar.zst",
                "bytes": 20,
                "sha256": DIGEST_ZULU,
            },
            {
                "path": "packages/zulu-9.0-1-any.pkg.tar.zst.sig",
                "bytes": 1,
                "sha256": DIGEST_ZULU_SIG,
            },
            {
                "path": "packages/telos.db.tar.gz",
                "bytes": 5,
                "sha256": DIGEST_DATABASE,
            },
        ],
        "package_verification": (
            "pacman repository signatures required by build-host policy"),
        "private_configuration_included": False,
    }


def evidence(installed=(("alpha", "1.2-3"), ("zulu", "9.0-1"))):
    return PackageRootEvidence(
        root="/candidate",
        installed_packages=tuple(
            InstalledPackage(name, version) for name, version in installed
        ),
        required_packages=CONTRACT.packages,
        binaries=(),
    )


class ParseSeedReceiptTests(unittest.TestCase):
    def parse_error(self, value, message):
        with self.assertRaises(SeedClosureError) as raised:
            parse_seed_receipt(value)
        self.assertIn(message, str(raised.exception))

    def test_accepts_exact_receipt(self):
        parsed = parse_seed_receipt(receipt())
        self.assertEqual(parsed.source_commit, COMMIT)
        self.assertEqual(parsed.source_sha256, DIGEST_SOURCE)
        self.assertEqual(parsed.requested_packages, ("alpha",))
        self.assertEqual(parsed.packages, (
            SeedPackage(
                "alpha", "1.2-3", "x86_64",
                "alpha-1.2-3-x86_64.pkg.tar.zst", DIGEST_ALPHA),
            SeedPackage(
                "zulu", "9.0-1", "any",
                "zulu-9.0-1-any.pkg.tar.zst", DIGEST_ZULU),
        ))

    def test_accepts_epoch_version(self):
        value = receipt()
        value["package_files"][0]["name"] = "alpha-1:1.2-3-x86_64.pkg.tar.zst"
        value["payload_files"][0]["path"] = (
            "packages/alpha-1:1.2-3-x86_64.pkg.tar.zst")
        value["payload_files"][1]["path"] = (
            "packages/alpha-1:1.2-3-x86_64.pkg.tar.zst.sig")
        parsed = parse_seed_receipt(value)
        self.assertEqual(parsed.packages[0].version, "1:1.2-3")

    def test_rejects_unknown_and_missing_fields(self):
        value = receipt()
        value["extra"] = 1
        self.parse_error(value, "unknown field: extra")
        value = receipt()
        del value["package_files"]
        self.parse_error(value, "missing field: package_files")

    def test_rejects_wrong_schema(self):
        value = receipt()
        value["schema"] = 2
        self.parse_error(value, "receipt.schema must equal 1")

    def test_rejects_naive_or_offset_timestamp(self):
        value = receipt()
        value["created_utc"] = "2026-07-30T00:00:00"
        self.parse_error(value, "exact UTC timestamp")
        value["created_utc"] = "2026-07-30T00:00:00+02:00"
        self.parse_error(value, "exact UTC timestamp")

    def test_rejects_changed_verification_policy(self):
        value = receipt()
        value["package_verification"] = "signatures optional"
        self.parse_error(value, "not the signed policy")

    def test_rejects_private_configuration(self):
        value = receipt()
        value["private_configuration_included"] = True
        self.parse_error(value, "must be false")

    def test_rejects_inexact_source(self):
        value = receipt()
        value["source"]["commit"] = "abc"
        self.parse_error(value, "not an exact commit")
        value = receipt()
        value["source"]["tracked_files_only"] = False
        self.parse_error(value, "tracked_files_only must be true")
        value = receipt()
        value["source"]["archive"] = "source/other.tar.gz"
        self.parse_error(value, "not the tracked source archive")

    def test_rejects_duplicate_requested_packages(self):
        value = receipt()
        value["requested_packages"] = ["alpha", "alpha"]
        self.parse_error(value, "duplicates")

    def test_rejects_requested_package_outside_closure(self):
        value = receipt()
        value["requested_packages"] = ["alpha", "omega"]
        self.parse_error(value, "absent from the closure: omega")

    def test_rejects_malformed_archive_identity(self):
        for name, message in (
            ("alpha-1.2-3-x86_64.pkg.tar.xz", "unexpected suffix"),
            ("alpha.pkg.tar.zst", "lacks exact identity"),
            ("Alpha-1.2-3-x86_64.pkg.tar.zst", "invalid package name"),
            ("alpha-1 2-3-x86_64.pkg.tar.zst", "invalid version"),
            ("alpha-1.2-r3-x86_64.pkg.tar.zst", "invalid release"),
            ("alpha-1.2-3-armv7h.pkg.tar.zst", "invalid architecture"),
        ):
            value = receipt()
            value["package_files"][0]["name"] = name
            self.parse_error(value, message)

    def test_rejects_duplicate_package_identity(self):
        value = receipt()
        value["package_files"][1]["name"] = "alpha-9.9-1-x86_64.pkg.tar.zst"
        value["payload_files"][2]["path"] = (
            "packages/alpha-9.9-1-x86_64.pkg.tar.zst")
        value["payload_files"][3]["path"] = (
            "packages/alpha-9.9-1-x86_64.pkg.tar.zst.sig")
        self.parse_error(value, "duplicate seed package identity: alpha")

    def test_rejects_empty_package_archive(self):
        value = receipt()
        value["package_files"][0]["bytes"] = 0
        self.parse_error(value, "package archive is empty")

    def test_rejects_archive_absent_or_differing_from_payload(self):
        value = receipt()
        value["payload_files"][0]["path"] = "packages/other.file"
        self.parse_error(value, "absent from payload")
        value = receipt()
        value["payload_files"][0]["bytes"] = 11
        self.parse_error(value, "differs from payload")
        value = receipt()
        value["payload_files"][0]["sha256"] = "f" * 64
        self.parse_error(value, "differs from payload")

    def test_rejects_missing_or_empty_signature(self):
        value = receipt()
        value["payload_files"][1]["path"] = "packages/alpha.unsigned"
        self.parse_error(value, "no detached signature")
        value = receipt()
        value["payload_files"][1]["bytes"] = 0
        self.parse_error(value, "package signature is empty")

    def test_rejects_missing_repository_database(self):
        value = receipt()
        del value["payload_files"][4]
        self.parse_error(value, "lacks the package repository database")

    def test_rejects_unsafe_payload_paths(self):
        for path in ("../escape", "a//b", "packages/./x", "/absolute"):
            value = receipt()
            value["payload_files"][4]["path"] = path
            self.parse_error(value, "not a normalized relative path")

    def test_rejects_duplicate_payload_paths(self):
        value = receipt()
        value["payload_files"][4]["path"] = value["payload_files"][0]["path"]
        self.parse_error(value, "duplicate payload file path")

    def test_rejects_recorded_receipt_payload(self):
        value = receipt()
        value["payload_files"][4]["path"] = "receipt.json"
        self.parse_error(value, "must not include receipt.json")
        value = receipt()
        value["payload_files"][4]["path"] = "nested/receipt.json"
        self.parse_error(value, "must not include receipt.json")


class ReconcileSeedClosureTests(unittest.TestCase):
    def reconcile_error(self, parsed, contract, root, message):
        with self.assertRaises(SeedClosureError) as raised:
            reconcile_seed_closure(parsed, contract, root)
        self.assertIn(message, str(raised.exception))

    def test_accounts_contract_and_installed_packages(self):
        parsed = parse_seed_receipt(receipt())
        proof = reconcile_seed_closure(parsed, CONTRACT, evidence())
        self.assertEqual(proof.source_commit, COMMIT)
        self.assertEqual(proof.contract_packages, ("alpha", "zulu"))
        self.assertEqual(
            proof.accounted_installed,
            (("alpha", "1.2-3"), ("zulu", "9.0-1")),
        )

    def test_rejects_unparsed_receipt(self):
        self.reconcile_error(
            receipt(), CONTRACT, evidence(), "must be a parsed seed receipt")

    def test_rejects_foreign_contract_or_evidence_types(self):
        parsed = parse_seed_receipt(receipt())
        self.reconcile_error(
            parsed, ("alpha",), evidence(), "merged package contract")
        self.reconcile_error(
            parsed, CONTRACT, {"root": "/candidate"}, "package root evidence")

    def test_rejects_evidence_from_different_contract(self):
        parsed = parse_seed_receipt(receipt())
        other = PackageRootEvidence(
            root="/candidate",
            installed_packages=(InstalledPackage("alpha", "1.2-3"),),
            required_packages=("alpha",),
            binaries=(),
        )
        self.reconcile_error(
            parsed, CONTRACT, other, "audited against a different contract")

    def test_rejects_required_package_outside_seed(self):
        contract = MergedPackageContract(
            overlays=("workstation",),
            packages=("alpha", "omega"),
            binaries=(),
        )
        parsed = parse_seed_receipt(receipt())
        root = PackageRootEvidence(
            root="/candidate",
            installed_packages=(InstalledPackage("alpha", "1.2-3"),),
            required_packages=contract.packages,
            binaries=(),
        )
        self.reconcile_error(
            parsed, contract, root,
            "required package is absent from the seed closure: omega")

    def test_rejects_installed_package_outside_seed(self):
        parsed = parse_seed_receipt(receipt())
        root = evidence(
            (("alpha", "1.2-3"), ("rogue", "1-1"), ("zulu", "9.0-1")))
        self.reconcile_error(
            parsed, CONTRACT, root,
            "installed package is absent from the seed closure: rogue")

    def test_rejects_installed_version_drift(self):
        parsed = parse_seed_receipt(receipt())
        root = evidence((("alpha", "1.2-4"), ("zulu", "9.0-1")))
        self.reconcile_error(
            parsed, CONTRACT, root,
            "installed package differs from the seed closure: "
            "alpha 1.2-4 != 1.2-3")


if __name__ == "__main__":
    unittest.main()
