import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "homelab" / "workstations" / "acceptance.py"
CONTRACT = SCRIPT.with_name("acceptance.json")


def load_module():
    spec = importlib.util.spec_from_file_location("workstation_acceptance", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class WorkstationAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()
        inputs = cls.module.load_instance(cls.module.EXAMPLE_INSTANCE)
        cls.contract = cls.module.instantiate(
            cls.module.load_contract(CONTRACT), inputs
        )

    def test_contract_is_valid(self):
        self.assertEqual([], self.module.contract_errors(self.contract))

    def test_both_operating_systems_cover_storage_failure_states(self):
        checks = self.contract["checks"]
        for os_name in ("windows", "arch"):
            ids = {check["id"] for check in checks if check["os"] == os_name}
            for state in ("available", "unreachable", "denied"):
                self.assertIn(f"{os_name}-smb-{state}", ids)

    def test_storage_failures_require_successful_login(self):
        checks = self.contract["checks"]
        failure_checks = [
            check
            for check in checks
            if check["id"].endswith(("-smb-unreachable", "-smb-denied"))
        ]
        self.assertEqual(4, len(failure_checks))
        for check in failure_checks:
            self.assertIn("Logon succeeds", check["pass"])

    def test_daily_and_domain_admin_roles_remain_separate(self):
        principals = self.contract["principals"]
        self.assertEqual("user", principals["daily_administrator"]["domain_role"])
        self.assertEqual(
            "administrator",
            principals["daily_administrator"]["workstation_role"],
        )
        self.assertEqual(
            "administrator",
            principals["domain_administrator"]["domain_role"],
        )

    def test_public_contract_uses_instance_variables(self):
        source = CONTRACT.read_text(encoding="utf-8")
        for variable in (
            "dns_domain",
            "kerberos_realm",
            "netbios_domain",
            "storage_host",
            "daily_administrator",
            "domain_administrator",
            "standard_user",
            "local_rescue",
        ):
            with self.subTest(variable=variable):
                self.assertIn("{{" + variable + "}}", source)

    def test_missing_instance_value_is_rejected(self):
        inputs = self.module.load_instance(self.module.EXAMPLE_INSTANCE)
        del inputs["storage_host"]
        with self.assertRaisesRegex(ValueError, "unresolved instance variable"):
            self.module.instantiate(self.module.load_contract(CONTRACT), inputs)

    def test_cli_validates_and_emits_parseable_json(self):
        validation = subprocess.run(
            [sys.executable, str(SCRIPT), "validate"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, validation.returncode, validation.stderr)
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "checklist",
                "--os",
                "arch",
                "--include-storage",
                "--format",
                "json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        checks = json.loads(result.stdout)
        self.assertTrue(checks)
        self.assertTrue(all(check["os"] == "arch" for check in checks))


if __name__ == "__main__":
    unittest.main()
