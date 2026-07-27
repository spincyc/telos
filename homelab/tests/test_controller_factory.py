import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vm"))

import controller_factory  # noqa: E402

NONCE = "a" * 64

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
                ROOT.parent, root / "factory.iso", password=secret,
                authorization_nonce=NONCE)
            stage = bundle.stage(root / "stage")
            self.assertTrue((stage / "ansible/playbooks/bootstrap-controller.yml").is_file())
            self.assertTrue((stage / "converge-controller").is_file())
            variables = (stage / "factory-vars.json").read_text()
            factory_ansible = (stage / "factory-ansible.cfg").read_text()
            self.assertIn(
                "stdout_callback = ansible.builtin.default", factory_ansible)
            self.assertIn(
                "callback_result_format = yaml", factory_ansible)
            self.assertIn('"homelab_ad_ntp_upstreams": ["198.51.100.10"]',
                          variables)
            self.assertIn(
                '"homelab_ad_development_clock_receipt_file": '
                '"/run/telos-factory-state/clock.receipt"', variables)
            self.assertIn('"homelab_ad_manage_packages": false', variables)
            self.assertEqual(0o600, (stage / "secret/ad-admin").stat().st_mode & 0o777)
            for path in stage.rglob("*"):
                if path.is_file() and path != stage / "secret/ad-admin":
                    self.assertNotIn(secret, path.read_text(errors="ignore"))
            command = bundle.guest_command(NONCE)
            self.assertNotIn(secret, command)
            self.assertIn("TELOS_FACTORY", command)
            self.assertNotIn("touch /run/telos-factory-authorized", command)
            script = (stage / "converge-controller").read_text()
            self.assertIn('/etc/homelab/manifest.json', script)
            self.assertIn("authorization nonce mismatch", script)
            self.assertIn(
                "server 198.51.100.10 iburst", script)
            self.assertNotIn("restrict default ignore", script)
            self.assertIn(
                "timeout 30 ntpd -n -gq -c "
                "/run/telos-factory-state/ntp-measure.conf", script)
            self.assertNotIn("ntpd -n -gq -p ", script)
            self.assertIn(
                "pacman -Q samba krb5 ntp python-cryptography", script)
            self.assertIn(
                "/usr/share/ipxe/x86_64/ipxe.efi", script)
            self.assertLess(
                script.index("timeout 30 ntpd"),
                script.index("clock.receipt"))

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
                ROOT.parent, root / "factory.iso", password="x",
                authorization_nonce=NONCE)
            with self.assertRaises(ValueError):
                bundle.build()

    def test_stage_refuses_symlink_and_tightens_existing_directory(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            real = root / "real"
            real.mkdir()
            link = root / "stage-link"
            link.symlink_to(real, target_is_directory=True)
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, root / "factory.iso", password="synthetic",
                authorization_nonce=NONCE)
            with self.assertRaisesRegex(ValueError, "real directory"):
                bundle.stage(link)
            stage = root / "stage"
            stage.mkdir(mode=0o755)
            bundle.stage(stage)
            self.assertEqual(0o700, stage.stat().st_mode & 0o777)

    def test_iso_builder_forces_root_ownership_inside_guest(self):
        source = Path(controller_factory.__file__).read_text()
        self.assertIn('"-uid", "0"', source)
        self.assertIn('"-gid", "0"', source)

    def test_context_cleanup_removes_secret_bearing_output(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "factory.iso"
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, output, password="synthetic",
                authorization_nonce=NONCE)
            bundle.build = lambda: output.write_bytes(b"iso") or output
            with bundle:
                self.assertTrue(output.exists())
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
