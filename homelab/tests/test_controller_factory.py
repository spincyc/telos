import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vm"))

import controller_factory  # noqa: E402


class ControllerFactoryBundleTests(unittest.TestCase):
    def test_synthetic_identity_is_fixed_and_non_private(self):
        spec = controller_factory.FactorySpec()
        self.assertEqual("ad.factory.test", spec.domain)
        self.assertEqual("FACTORY", spec.netbios)
        self.assertEqual("10.1.31.2", spec.address)
        self.assertNotIn("home.arpa", spec.domain)

    def test_dedicated_tftp_service_has_no_dhcp_implementation(self):
        text = controller_factory.tftp_unit(ControllerFactoryBundleTests.spec())
        self.assertIn("/usr/bin/in.tftpd", text)
        self.assertNotIn("dnsmasq", text)
        self.assertNotIn("dhcp", text.lower())

    @staticmethod
    def spec():
        return controller_factory.FactorySpec()

    def test_bundle_contains_local_ansible_and_no_secret_in_arguments(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            secret = "Synthetic-Only-Password-47!"
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, root / "factory.iso", password=secret)
            stage = bundle.stage(root / "stage")
            self.assertTrue((stage / "ansible/playbooks/bootstrap-controller.yml").is_file())
            self.assertTrue((stage / "converge-controller").is_file())
            self.assertEqual(0o600, (stage / "secret/ad-admin").stat().st_mode & 0o777)
            for path in stage.rglob("*"):
                if path.is_file() and path != stage / "secret/ad-admin":
                    self.assertNotIn(secret, path.read_text(errors="ignore"))
            command = bundle.guest_command()
            self.assertNotIn(secret, command)
            self.assertIn("TELOS_FACTORY", command)

    def test_verifier_covers_ad_dns_pxe_http_and_authority_split(self):
        checks = "\n".join(controller_factory.verification_commands(
            self.spec()))
        for needle in (
            "samba-tool domain info", "samba-tool dbcheck", "_ldap._tcp",
            "telos-factory-tftp", "nginx -t", "boot.ipxe", "69", "53",
        ):
            self.assertIn(needle, checks)

    def test_bundle_refuses_symlink_output(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            target = root / "target"
            target.write_text("")
            (root / "factory.iso").symlink_to(target)
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, root / "factory.iso", password="x")
            with self.assertRaises(ValueError):
                bundle.build()

    def test_iso_builder_forces_root_ownership_inside_guest(self):
        source = Path(controller_factory.__file__).read_text()
        self.assertIn('"-uid", "0"', source)
        self.assertIn('"-gid", "0"', source)

    def test_context_cleanup_removes_secret_bearing_output(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "factory.iso"
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, output, password="synthetic")
            bundle.build = lambda: output.write_bytes(b"iso") or output
            with bundle:
                self.assertTrue(output.exists())
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
