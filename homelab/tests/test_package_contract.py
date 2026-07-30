import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import package_contract


class PackageContractTests(unittest.TestCase):
    def setUp(self):
        self.raw = json.loads(
            (ROOT / "package-contract.json").read_text(encoding="utf-8"))

    def test_repository_registry_and_merge_are_deterministic(self):
        registry = package_contract.parse_registry(self.raw)
        first = package_contract.merge_contract(
            registry, ["services", "controller-network"])
        second = package_contract.merge_contract(
            registry, ["controller-network", "services"])
        self.assertEqual(first, second)
        self.assertEqual(
            first.overlays, ("controller-network", "services"))
        self.assertIn("base", first.packages)
        self.assertIn("dnsmasq", first.packages)
        self.assertIn("podman", first.packages)
        self.assertEqual(first.packages, tuple(sorted(first.packages)))
        self.assertEqual(first.binaries, tuple(sorted(first.binaries)))

    def test_audited_role_requirements_are_explicit(self):
        registry = package_contract.parse_registry(self.raw)
        controller = package_contract.merge_contract(
            registry, [
                "controller-network",
                "controller-domain",
                "controller-factory",
            ])
        workstation = package_contract.merge_contract(
            registry,
            package_contract.PROFILE_OVERLAYS["workstation-install"])
        installer = package_contract.merge_contract(
            registry, package_contract.PROFILE_OVERLAYS["installer-live"])
        image_host = package_contract.merge_contract(
            registry, ["image-build-host"])
        self.assertTrue(
            {
                "dhcpcd", "dnsmasq", "iproute2", "nginx", "glibc",
                "samba", "7zip", "wimlib",
            }
            <= set(controller.packages))
        self.assertTrue(
            {
                ("/usr/bin/getent", "glibc"),
                ("/usr/bin/ip", "iproute2"),
                ("/usr/bin/smbcontrol", "samba"),
                ("/usr/bin/timedatectl", "systemd"),
            }
            <= {(item.path, item.owner) for item in controller.binaries})
        self.assertTrue(
            {
                "python", "openssh", "sssd", "pam", "curl", "diffutils",
                "util-linux",
            } <= set(workstation.packages))
        self.assertTrue(
            {
                ("/usr/bin/cmp", "diffutils"),
                ("/usr/bin/curl", "curl"),
                ("/usr/bin/logger", "util-linux"),
                ("/usr/lib/security/pam_mkhomedir.so", "pam"),
            }
            <= {(item.path, item.owner) for item in workstation.binaries})
        self.assertIn("e2fsprogs", installer.packages)
        self.assertIn(
            package_contract.BinaryOwnership(
                path="/usr/bin/mkfs.ext4", owner="e2fsprogs"),
            installer.binaries,
        )
        self.assertTrue(
            {"gnupg", "iproute2", "mtools", "nftables", "util-linux"}
            <= set(image_host.packages))
        self.assertTrue(
            {
                ("/usr/bin/gpg", "gnupg"),
                ("/usr/bin/ip", "iproute2"),
                ("/usr/bin/lsblk", "util-linux"),
                ("/usr/bin/mcopy", "mtools"),
                ("/usr/bin/mount", "util-linux"),
                ("/usr/bin/nft", "nftables"),
                ("/usr/bin/umount", "util-linux"),
            }
            <= {(item.path, item.owner) for item in image_host.binaries})

    def test_unknown_overlay_is_rejected(self):
        registry = package_contract.parse_registry(self.raw)
        with self.assertRaisesRegex(
                package_contract.PackageContractError, "unknown overlay"):
            package_contract.merge_contract(registry, ["not-a-role"])

    def test_duplicate_package_is_rejected(self):
        self.raw["common"]["packages"].append("base")
        with self.assertRaisesRegex(
                package_contract.PackageContractError, "duplicate packages"):
            package_contract.parse_registry(self.raw)

    def test_duplicate_binary_is_rejected(self):
        self.raw["common"]["binaries"].append(
            copy.deepcopy(self.raw["common"]["binaries"][0]))
        with self.assertRaisesRegex(
                package_contract.PackageContractError,
                "duplicate binary paths"):
            package_contract.parse_registry(self.raw)

    def test_relative_binary_path_is_rejected(self):
        for path in (
            "usr/bin/bash",
            "/usr/bin/../bin/bash",
            "/usr/bin/../../etc/passwd",
            "/usr/bin/\x00bash",
            "/usr/bin/\nbash",
        ):
            with self.subTest(path=path):
                raw = copy.deepcopy(self.raw)
                raw["common"]["binaries"][0]["path"] = path
                with self.assertRaisesRegex(
                        package_contract.PackageContractError,
                        "non-normalized absolute"):
                    package_contract.parse_registry(raw)

    def test_absent_owner_package_is_rejected(self):
        self.raw["common"]["binaries"][0]["owner"] = "not-installed"
        with self.assertRaisesRegex(
                package_contract.PackageContractError,
                "owner is absent.*merged"):
            package_contract.parse_registry(self.raw)

    def test_common_overlay_collision_is_rejected(self):
        self.raw["overlays"]["services"]["packages"].append("base")
        with self.assertRaisesRegex(
                package_contract.PackageContractError,
                "collides between common and services"):
            package_contract.parse_registry(self.raw)

    def test_unknown_fields_are_rejected_at_every_level(self):
        self.raw["common"]["binaries"][0]["note"] = "not in schema"
        with self.assertRaisesRegex(
                package_contract.PackageContractError, "unknown field"):
            package_contract.parse_registry(self.raw)

    def test_duplicate_json_object_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_text(
                '{"schema_version":1,"schema_version":1,'
                '"common":{},"overlays":{}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                    package_contract.PackageContractError,
                    "duplicate object key"):
                package_contract.load_registry(path)

    def test_overlay_selection_must_be_explicit_and_unique(self):
        registry = package_contract.parse_registry(self.raw)
        with self.assertRaisesRegex(
                package_contract.PackageContractError,
                "overlay selection must be an array"):
            package_contract.merge_contract(registry, None)
        with self.assertRaisesRegex(
                package_contract.PackageContractError,
                "overlay selection has duplicates"):
            package_contract.merge_contract(registry, ["services", "services"])

    def test_role_overlays_may_share_identical_owned_requirements(self):
        registry = package_contract.parse_registry(self.raw)
        merged = package_contract.merge_contract(
            registry, ["controller-domain", "identity-client"])
        self.assertEqual(merged.packages.count("samba"), 1)
        self.assertEqual(
            [item.path for item in merged.binaries].count("/usr/bin/net"), 1)

    def test_exact_scalar_and_collection_types_are_required(self):
        self.raw["schema_version"] = True
        with self.assertRaisesRegex(
                package_contract.PackageContractError, "must equal 1"):
            package_contract.parse_registry(self.raw)
        self.raw["schema_version"] = 1
        self.raw["common"]["packages"] = "base"
        with self.assertRaisesRegex(
                package_contract.PackageContractError, "must be an array"):
            package_contract.parse_registry(self.raw)


if __name__ == "__main__":
    unittest.main()
