"""Static contract tests for the host-level Samba AD domain-controller role.

These tests deliberately do not provision a domain.  They protect the boundary
around that destructive, credential-bearing operation and require the role to
ship observable acceptance and recovery paths that can later be exercised in
the isolated VM.
"""

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/domain_controller"

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the host
    yaml = None


@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
class TestDomainControllerRole(unittest.TestCase):
    def load(self, relative):
        return yaml.safe_load((ROLE / relative).read_text())

    def tasks(self):
        return self.load("tasks/main.yml")

    def all_tasks(self):
        pending = list(self.tasks())
        flattened = []
        while pending:
            task = pending.pop(0)
            flattened.append(task)
            for section in ("block", "rescue", "always"):
                pending[0:0] = task.get(section, [])
        return flattened

    def role_text(self):
        return "\n".join(
            path.read_text()
            for path in sorted(ROLE.rglob("*"))
            if path.is_file() and path.suffix != ".pyc"
        )

    def test_every_yaml_file_parses(self):
        self.assertTrue(ROLE.is_dir(), "domain_controller role is missing")
        for path in sorted(ROLE.rglob("*.yml")):
            with self.subTest(path=path.relative_to(ROLE)):
                yaml.safe_load(path.read_text())

    def test_instance_identity_has_no_public_default(self):
        defaults = self.load("defaults/main.yml")
        private_values = (
            "homelab_ad_dns_domain",
            "homelab_ad_realm",
            "homelab_ad_netbios_domain",
        )
        for name in private_values:
            with self.subTest(variable=name):
                self.assertEqual(defaults.get(name), "")

        public_text = self.role_text()
        for private_literal in (
            "private.example",
            "PRIVATE.EXAMPLE",
            "EXAMPLELAB",
        ):
            with self.subTest(private_literal=private_literal):
                self.assertNotIn(private_literal, public_text)

    def test_first_domain_creation_is_off_by_default(self):
        defaults = self.load("defaults/main.yml")
        switches = {
            name: value for name, value in defaults.items()
            if "provision" in name.lower() and isinstance(value, bool)
        }
        self.assertTrue(switches, "there is no explicit first-DC switch")
        self.assertTrue(all(value is False for value in switches.values()))

    def test_provisioning_requires_both_opt_in_and_a_secret(self):
        text = (ROLE / "tasks/main.yml").read_text()
        self.assertRegex(text, r"(?i)assert")
        self.assertRegex(text, r"(?i)(first.*(?:dc|domain)|(?:dc|domain).*first)")
        self.assertRegex(text, r"(?i)(password|secret)")

        provisioners = [
            task for task in self.all_tasks()
            if str(task.get("name", "")).lower().startswith("provision ")
            and ("ansible.builtin.command" in task
                 or "ansible.builtin.shell" in task)
        ]
        self.assertTrue(provisioners, "no guarded domain provision task found")
        for task in provisioners:
            with self.subTest(task=task.get("name")):
                self.assertIs(task.get("no_log"), True)
                self.assertTrue(
                    "when" in task or any(
                        parent.get("name")
                        == "Provision with an ephemeral credential feeder"
                        for parent in self.tasks()
                    ),
                    "provisioning must be conditional",
                )

    def test_preflight_precedes_every_mutating_task(self):
        tasks = self.tasks()
        names = [str(task.get("name", "")) for task in tasks]
        package_index = names.index("Install Samba AD dependencies")
        preflight = "\n".join(str(task) for task in tasks[:package_index])
        self.assertIn("ansible_fqdn", preflight)
        self.assertIn("getent", preflight)
        self.assertIn("NTPSynchronized", preflight)
        self.assertIn("ansible_check_mode", preflight)
        self.assertIn("end_host", preflight)
        self.assertIn("Require explicit authorization", preflight)
        self.assertIn("Require a protected one-time password file", preflight)

    def test_credential_feeder_is_removed_even_after_failure(self):
        provisions = [
            task for task in self.tasks()
            if task.get("name") == "Provision with an ephemeral credential feeder"
        ]
        self.assertEqual(1, len(provisions))
        self.assertIn("block", provisions[0])
        self.assertIn("always", provisions[0])
        self.assertIn(
            "state': 'absent",
            str(provisions[0]["always"]),
        )

    def test_password_feeder_rejects_a_blank_first_line(self):
        driver = ROLE / "files/provision-domain.py"
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as secret:
            secret.write("\nnot-the-first-line\n")
            secret.flush()
            result = subprocess.run(
                [
                    sys.executable, str(driver),
                    "--password-file", secret.name,
                    "--realm", "EXAMPLE.INVALID",
                    "--domain", "EXAMPLE",
                    "--server-role", "dc",
                    "--dns-backend", "SAMBA_INTERNAL",
                    "--use-rfc2307",
                ],
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("nonempty first line", result.stderr)

    def test_rfc2307_switches_are_mutually_exclusive_and_required(self):
        driver = (ROLE / "files/provision-domain.py").read_text()
        self.assertIn("add_mutually_exclusive_group(required=True)", driver)

    def test_no_secret_value_is_written_to_a_template(self):
        for path in sorted((ROLE / "templates").glob("*")):
            with self.subTest(path=path.name):
                text = path.read_text()
                self.assertNotRegex(
                    text,
                    r"(?i)(admin|administrator|provision).*(password|secret)"
                    r"|(password|secret).*(admin|administrator|provision)",
                )

    def test_it_installs_samba_and_kerberos_support(self):
        defaults = self.load("defaults/main.yml")
        package_values = [
            value for name, value in defaults.items()
            if "package" in name.lower() and isinstance(value, list)
        ]
        packages = {str(item) for values in package_values for item in values}
        if not packages:
            packages = set(re.findall(
                r"\b(?:samba|krb5|bind|bind-tools|openresolv)\b",
                (ROLE / "tasks/main.yml").read_text(),
            ))
        self.assertIn("samba", packages)
        self.assertIn("krb5", packages)

    def test_conflicting_samba_units_are_disabled(self):
        text = (ROLE / "tasks/main.yml").read_text()
        for unit in ("smb.service", "nmb.service", "winbind.service"):
            with self.subTest(unit=unit):
                self.assertIn(unit, text)
        self.assertRegex(text, r"(?i)(disabled|enabled:\s*false)")

    def test_the_ad_dc_service_is_enabled(self):
        text = (ROLE / "tasks/main.yml").read_text()
        self.assertIn("samba.service", text)
        self.assertRegex(text, r"(?i)enabled:\s*true")

    def test_acceptance_probes_cover_domain_dns_and_kerberos(self):
        text = self.role_text()
        commands = []
        for path in sorted(ROLE.rglob("*.yml")):
            document = yaml.safe_load(path.read_text())
            if not isinstance(document, list):
                continue
            for task in document:
                for module in ("ansible.builtin.command", "ansible.builtin.shell"):
                    value = task.get(module)
                    if isinstance(value, dict) and isinstance(value.get("argv"), list):
                        commands.append(" ".join(str(item) for item in value["argv"]))
                    elif isinstance(value, dict) and value.get("cmd"):
                        commands.append(str(value["cmd"]))
                    elif isinstance(value, str):
                        commands.append(value)
        command_text = "\n".join(commands)
        required = {
            "domain information": r"samba-tool\s+domain\s+info",
            "AD service discovery": r"(?i)(_ldap\._tcp|_kerberos\._tcp|SRV)",
            "Kerberos ticket": r"\bkinit\b",
        }
        for claim, pattern in required.items():
            with self.subTest(claim=claim):
                self.assertRegex(command_text + "\n" + text, pattern)

    def test_acceptance_probes_do_not_embed_credentials(self):
        text = self.role_text()
        self.assertNotRegex(text, r"(?i)kinit\s+.*(?:--password|-w\s+)")
        self.assertNotRegex(
            text,
            r"(?im)^\s*(?:admin_?)?(?:password|secret)\s*[:=]\s*[\"'][^{}]",
        )

    def test_recovery_uses_supported_online_domain_backup(self):
        text = re.sub(r"[\n\r\[\],'\"{}]+", " ", self.role_text())
        self.assertRegex(text, r"samba-tool\s+(?:\\n\s*)?domain\s+backup\s+online")
        self.assertRegex(text, r"(?i)(backup|recovery).*(director|destination|path)")


if __name__ == "__main__":
    unittest.main()
