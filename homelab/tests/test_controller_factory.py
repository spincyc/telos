import json
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

    def test_convergence_publishes_reachable_unas_storage_by_default(self):
        # Gate 9: the disposable Controller is itself the optional UNAS
        # storage authority.  The convergence vars must set
        # homelab_storage_address to the Controller's own address so the
        # domain_controller role publishes `unas -> 10.1.31.2`, making the
        # per-user [homes] share reachable by default.  Left empty the role
        # skips publication and arch-storage-attached could never mount.  The
        # gate-8 drive later repoints the record to make storage absent.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, root / "factory.iso",
                authorization_nonce=NONCE)
            stage = bundle.stage(root / "stage")
            variables = json.loads((stage / "factory-vars.json").read_text())
        self.assertEqual(
            variables["homelab_storage_address"],
            controller_factory.FactorySpec().address)
        self.assertEqual("10.1.31.2", variables["homelab_storage_address"])

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
            self.assertTrue(
                (stage / "controller-auth-diagnostic.py").is_file())
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
                'probe.sendto(request, ("198.51.100.10", 123))', script)
            self.assertIn(
                "candidate[24:32] == request[40:48]", script)
            self.assertIn("candidate[0] >> 6 != 3", script)
            self.assertIn("(candidate[0] >> 3) & 0x7 == 4", script)
            self.assertIn("1 <= candidate[1] <= 15", script)
            self.assertIn(
                "time.clock_settime(time.CLOCK_REALTIME, measured)", script)
            self.assertLess(
                script.index("time-sync-response"),
                script.index("time-sync-clock"))
            self.assertLess(
                script.index("time-sync-clock"),
                script.index("payload-stage"))
            self.assertLess(
                script.index("payload-stage"),
                script.index("package-preflight"))
            self.assertLess(
                script.index("package-preflight"),
                script.index("TELOS FACTORY STEP ansible"))
            self.assertIn(
                'check verify-01 "samba-tool domain info 127.0.0.1"',
                script)
            self.assertIn("check verify-10 ", script)
            self.assertIn(
                "TELOS FACTORY STEP administrator-disable", script)
            self.assertIn(
                "--attributes=userAccountControl", script)
            self.assertIn(
                '[[ "$administrator_uac" =~ ^[0-9]+$ ]]', script)
            self.assertIn("(( administrator_uac & 2 ))", script)
            self.assertNotIn("accountFlags:.*D", script)
            self.assertIn(
                "for package in samba krb5 ntp python-cryptography", script)
            self.assertIn(
                'TELOS FACTORY STEP package-missing-$package', script)
            self.assertIn(
                "log level = 0 auth_json_audit:3@"
                "/run/telos-factory-auth-audit/auth.jsonl",
                script,
            )
            self.assertNotIn(
                "log file = /run/telos-factory-auth-audit", script)
            self.assertIn(
                "grep -Fxc $'\\tlog level = 0 auth_json_audit:3@", script)
            self.assertIn(
                "! grep -Eq '^[[:space:]]*[^#;].*auth_json_audit'",
                script,
            )
            self.assertIn(
                "testparm -s /etc/samba/smb.conf >/dev/null 2>&1", script)
            self.assertNotIn("--parameter-name='log level'", script)
            self.assertIn(
                "auth_audit_live=$(smbcontrol all debuglevel)", script)
            self.assertIn(
                "mapfile -t auth_audit_levels", script)
            self.assertIn(
                'if (token == "auth_json_audit:")', script)
            self.assertIn(
                '[[ ${#auth_audit_levels[@]} -gt 0 ]]', script)
            self.assertIn(
                'for auth_audit_level in "${auth_audit_levels[@]}"', script)
            self.assertIn("smbd -b | awk", script)
            self.assertIn(
                '$1 == "HAVE_JSON_OBJECT" && NF == 1', script)
            self.assertNotIn("auth_audit_tokens", script)
            self.assertIn(
                "test -d /run/telos-factory-auth-audit", script)
            self.assertIn(
                "test -f /run/telos-factory-auth-audit/auth.jsonl", script)
            self.assertIn(
                "stat -c '%u:%g:%a:%h'", script)
            self.assertNotIn("stat -Lc '%U:%G:%a:%F:%h'", script)
            auth_markers = (
                "auth-audit-preflight",
                "auth-audit-sink-create",
                "auth-audit-config-write",
                "auth-audit-config-verify",
                "auth-audit-restart",
                "auth-audit-sink-verify",
            )
            for marker in auth_markers:
                self.assertIn(f"TELOS FACTORY STEP {marker}", script)
            for before, after in zip(auth_markers, auth_markers[1:]):
                self.assertLess(
                    script.index(f"TELOS FACTORY STEP {before}"),
                    script.index(f"TELOS FACTORY STEP {after}"),
                )
            self.assertIn(
                "/usr/share/ipxe/x86_64/ipxe.efi", script)
            self.assertLess(
                script.index("systemctl stop ntpd.service"),
                script.index("probe.sendto"))
            self.assertLess(
                script.index("probe.sendto"),
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
