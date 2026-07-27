"""Tests for the offline Controller seed builder."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


PATH = Path(__file__).parents[1] / "seed/build.py"
SPEC = importlib.util.spec_from_file_location("seed_build", PATH)
seed = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(seed)


class SeedBuildTests(unittest.TestCase):
    def test_public_package_list_is_unique_and_has_controller_services(self):
        names = seed.package_names(seed.DEFAULT_PACKAGES)
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue({"samba", "krb5", "bind", "dnsmasq", "nginx"} <= set(names))

    def test_package_parser_ignores_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packages"
            path.write_text("# note\nbase # required\n\nlinux-lts\n", encoding="utf-8")
            self.assertEqual(seed.package_names(path), ["base", "linux-lts"])

    def test_plan_freshens_databases_and_downloads_every_package(self):
        commands = seed.command_plan(
            ["base", "samba"], Path("/tmp/stage"), Path("/tmp/seed.iso")
        )
        self.assertEqual(commands[0][0:2], ["sudo", "pacman"])
        self.assertIn("--config", commands[0])
        self.assertIn("-Syw", commands[0])
        self.assertIn("--dbpath", commands[0])
        self.assertIn("--cachedir", commands[0])
        self.assertEqual(commands[0][-3:], ["--", "base", "samba"])
        self.assertEqual(commands[-1][0:4], ["xorriso", "-as", "mkisofs", "-volid"])

    def test_output_is_ignored(self):
        ignore = (seed.ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/homelab/var/", ignore)
        self.assertTrue(seed.DEFAULT_OUTPUT.is_relative_to(seed.ROOT / "homelab/var"))

    def test_installer_never_mentions_private_overlay(self):
        installer = PATH.with_name("install-controller-deps").read_text(encoding="utf-8")
        self.assertNotIn("telos-private", installer)
        self.assertIn("-U --needed", installer)

    def test_receipt_covers_every_payload_file(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            (stage / "packages").mkdir()
            (stage / "packages/a.pkg.tar.zst").write_bytes(b"package")
            (stage / "install-controller-deps").write_text("installer", encoding="utf-8")
            source = {"commit": "a" * 40, "sha256": "b" * 64}
            seed.write_receipt(stage, ["a"], source)
            import json
            receipt = json.loads((stage / "receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(
                {item["path"] for item in receipt["payload_files"]},
                {"install-controller-deps", "packages/a.pkg.tar.zst"},
            )

    def test_source_guard_names_private_and_key_material(self):
        source = PATH.read_text(encoding="utf-8")
        self.assertIn('startswith("telos-private/")', source)
        self.assertIn('startswith("homelab/instance/")', source)
        self.assertIn(
            b"-----BEGIN OPENSSH PRIVATE KEY-----", seed.FORBIDDEN_TEXT_MARKERS
        )


if __name__ == "__main__":
    unittest.main()
