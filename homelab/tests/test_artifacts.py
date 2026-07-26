"""Tests for the artifact service configuration and checksum manifest."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import artifacts  # noqa: E402


class TestNginx(unittest.TestCase):
    def test_binds_the_managed_address_only(self):
        # ADR 0011: a Controller with a second NIC must not serve on a network
        # it does not own.
        config = artifacts.render_nginx(listen_address="10.0.7.2")
        self.assertIn("listen 10.0.7.2:80;", config)
        self.assertNotIn("listen 80;", config)

    def test_is_read_only(self):
        config = artifacts.render_nginx(listen_address="10.0.7.2")
        self.assertIn("limit_except GET HEAD", config)
        self.assertIn("autoindex off", config)

    def test_names_the_governing_adrs(self):
        config = artifacts.render_nginx(listen_address="10.0.7.2")
        for adr in ("ADR 0048", "ADR 0044", "ADR 0011"):
            self.assertIn(adr, config)


class TestManifest(unittest.TestCase):
    def test_checksums_every_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "vmlinuz").write_bytes(b"kernel")
            (root / "sub").mkdir()
            (root / "sub" / "initrd.img").write_bytes(b"initrd")
            manifest = artifacts.build_manifest(root)
            self.assertEqual(set(manifest["artifacts"]), {"vmlinuz", "sub/initrd.img"})

    def test_verification_passes_for_untouched_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.img").write_bytes(b"payload")
            self.assertEqual(artifacts.verify_against(artifacts.build_manifest(root), root), [])

    def test_an_altered_artifact_is_caught(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.img").write_bytes(b"payload")
            manifest = artifacts.build_manifest(root)
            (root / "a.img").write_bytes(b"payload tampered")
            problems = artifacts.verify_against(manifest, root)
            self.assertEqual(len(problems), 1)
            self.assertIn("checksum mismatch", problems[0])

    def test_a_missing_artifact_is_caught(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.img").write_bytes(b"payload")
            manifest = artifacts.build_manifest(root)
            (root / "a.img").unlink()
            self.assertIn("not present", artifacts.verify_against(manifest, root)[0])


class TestIpxe(unittest.TestCase):
    def test_has_exactly_one_boot_target(self):
        # A menu with one entry is a timeout waiting to pick the wrong thing.
        script = artifacts.render_ipxe(base_url="http://10.0.7.2/boot")
        self.assertNotIn("menu", script.lower())
        self.assertEqual(script.count("boot ||"), 1)

    def test_serial_console_is_enabled(self):
        # The acceptance matrix drives the installer over the serial console.
        script = artifacts.render_ipxe(base_url="http://10.0.7.2/boot")
        self.assertIn("console=ttyS0,115200", script)

    def test_failure_drops_to_a_shell_with_an_explanation(self):
        script = artifacts.render_ipxe(base_url="http://10.0.7.2/boot")
        self.assertIn(":failed", script)
        self.assertIn("checksum", script)


if __name__ == "__main__":
    unittest.main()
