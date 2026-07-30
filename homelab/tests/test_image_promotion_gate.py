import json
import tempfile
import unittest
from pathlib import Path

from homelab.lib.package_contract import EXPECTED_OVERLAYS
from homelab.lib.image_promotion_gate import (
    ImagePromotionGateError,
    gate_candidate_image,
)


COMMIT = "a" * 40
DIGEST_SOURCE = "0" * 64
DIGEST_ALPHA = "1" * 64
DIGEST_ALPHA_SIG = "2" * 64
DIGEST_DATABASE = "5" * 64


def empty_layer():
    return {"packages": [], "binaries": [], "services": []}


def registry():
    overlays = {name: empty_layer() for name in EXPECTED_OVERLAYS}
    overlays["workstation"] = {
        "packages": ["alpha"],
        "binaries": [{"path": "/usr/bin/alpha", "owner": "alpha"}],
        "services": [],
    }
    return {
        "schema_version": 1,
        "common": empty_layer(),
        "overlays": overlays,
    }


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
                "path": "packages/telos.db.tar.gz",
                "bytes": 5,
                "sha256": DIGEST_DATABASE,
            },
        ],
        "package_verification": (
            "pacman repository signatures required by build-host policy"),
        "private_configuration_included": False,
    }


class ImagePromotionGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.root = base / "root"
        (self.root / "var/lib/pacman/local").mkdir(parents=True)
        (self.root / "usr/bin").mkdir(parents=True)
        self.package("alpha", "1.2-3", ("usr/bin/alpha",))
        executable = self.root / "usr/bin/alpha"
        executable.write_bytes(b"binary")
        executable.chmod(0o755)
        self.registry_path = base / "package-contract.json"
        self.write_registry(registry())
        self.receipt_path = base / "receipt.json"
        self.write_receipt(receipt())

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

    def write_registry(self, value):
        self.registry_path.write_text(json.dumps(value), encoding="utf-8")

    def write_receipt(self, value):
        self.receipt_path.write_text(json.dumps(value), encoding="utf-8")

    def gate(self, profile="workstation-install"):
        return gate_candidate_image(
            profile, self.registry_path, self.root, self.receipt_path)

    def gate_error(self, message, profile="workstation-install"):
        with self.assertRaises(ImagePromotionGateError) as raised:
            self.gate(profile)
        self.assertIn(message, str(raised.exception))

    def test_produces_one_attributable_evidence_document(self):
        document = self.gate().to_document()
        self.assertEqual(document["schema"], 1)
        self.assertEqual(document["kind"], "image-promotion-static-evidence")
        self.assertEqual(document["profile"], "workstation-install")
        self.assertEqual(
            document["overlays"],
            ["identity-client", "automatic-updates", "workstation"],
        )
        self.assertEqual(document["seed_source_commit"], COMMIT)
        self.assertEqual(document["contract_packages"], ["alpha"])
        self.assertEqual(
            document["accounted_installed"],
            [{"name": "alpha", "version": "1.2-3"}],
        )
        self.assertEqual(document["binaries"], [{
            "path": "/usr/bin/alpha",
            "owner": "alpha",
            "resolved_path": "/usr/bin/alpha",
        }])

    def test_reports_declared_services_as_unverified(self):
        value = registry()
        value["overlays"]["workstation"]["services"] = ["alpha.service"]
        self.write_registry(value)
        document = self.gate().to_document()
        self.assertEqual(document["declared_services"], ["alpha.service"])
        self.assertIs(document["services_verified"], False)

    def test_rejects_unknown_profile(self):
        self.gate_error("unknown image profile: rogue", profile="rogue")

    def test_attributes_contract_stage(self):
        value = registry()
        del value["overlays"]["workstation"]
        self.write_registry(value)
        self.gate_error("contract: ")

    def test_attributes_root_audit_stage(self):
        value = registry()
        value["overlays"]["workstation"]["packages"] = ["alpha", "omega"]
        value["overlays"]["workstation"]["binaries"] = [
            {"path": "/usr/bin/alpha", "owner": "alpha"},
            {"path": "/usr/bin/omega", "owner": "omega"},
        ]
        self.write_registry(value)
        self.gate_error("root-audit: required package is not installed: omega")

    def test_attributes_seed_closure_stage(self):
        value = receipt()
        value["package_files"][0]["name"] = "beta-1.2-3-x86_64.pkg.tar.zst"
        value["payload_files"][0]["path"] = (
            "packages/beta-1.2-3-x86_64.pkg.tar.zst")
        value["payload_files"][1]["path"] = (
            "packages/beta-1.2-3-x86_64.pkg.tar.zst.sig")
        value["requested_packages"] = ["beta"]
        self.write_receipt(value)
        self.gate_error(
            "seed-closure: required package is absent from the seed closure: "
            "alpha")

    def test_rejects_installed_version_drift_through_the_gate(self):
        value = receipt()
        value["package_files"][0]["name"] = "alpha-1.2-4-x86_64.pkg.tar.zst"
        value["payload_files"][0]["path"] = (
            "packages/alpha-1.2-4-x86_64.pkg.tar.zst")
        value["payload_files"][1]["path"] = (
            "packages/alpha-1.2-4-x86_64.pkg.tar.zst.sig")
        self.write_receipt(value)
        self.gate_error(
            "seed-closure: installed package differs from the seed closure: "
            "alpha 1.2-3 != 1.2-4")

    def test_rejects_duplicate_receipt_keys(self):
        self.receipt_path.write_text(
            '{"schema": 1, "schema": 1}', encoding="utf-8")
        self.gate_error("duplicate object key: schema")

    def test_rejects_unreadable_receipt(self):
        self.receipt_path.unlink()
        self.gate_error("cannot read seed receipt")

    def test_bounds_the_receipt_before_reading_it(self):
        """An endless receipt must be refused, not held in memory first."""
        self.receipt_path.unlink()
        self.receipt_path.symlink_to("/dev/zero")
        self.gate_error("seed receipt is too large")

    def test_rejects_deeply_nested_receipt_with_stage_attribution(self):
        self.receipt_path.write_bytes(b"[" * 200000)
        self.gate_error("seed-closure: seed receipt nests too deeply")


if __name__ == "__main__":
    unittest.main()
