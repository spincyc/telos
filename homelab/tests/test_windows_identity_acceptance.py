import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "workstations"))

import windows_identity_acceptance as acceptance  # noqa: E402

RUN_ID = "12345678-1234-4123-8123-123456789abc"


def details():
    return {
        "controller-ready": {
            "samba_ad": True, "dns": True, "kerberos": True, "time": True,
            "synthetic_directory": True},
        "windows-joined": {
            "domain_joined": True, "secure_channel": True,
            "machine_account": True, "join_material": "one-use"},
        "windows-standard-online": {
            "principal_role": "standard", "elevated": False,
            "identity_resolved": True, "cache_primed": True},
        "windows-daily-admin": {
            "principal_role": "daily-administrator", "local_admin": True,
            "domain_admin": False, "cache_primed": True},
        "domain-admin-separate": {"same_principal": False},
        "windows-rebooted-joined": {
            "native_boot": True, "domain_joined": True, "secure_channel": True},
        "windows-cached-policy": {
            "cached_logons_configured": True, "cached_logon_count": 4,
            "managed_user_roster": 2, "administrative_margin": 2,
            "capacity_sufficient": True},
        "controller-offline": {
            "authority_reachable": False, "dns_reachable": False,
            "kerberos_reachable": False, "ldap_reachable": False,
            "smb_reachable": False},
        "windows-cached-login": {
            "controller_online": False, "cached": True,
            "principal_role": "standard", "login": "allowed"},
        "windows-cached-admin-login": {
            "controller_online": False, "cached": True,
            "principal_role": "daily-administrator", "login": "allowed",
            "local_admin": True},
        "windows-uncached-denied": {
            "controller_online": False,
            "principal_role": "uncached-domain-user", "login": "denied"},
        "windows-local-rescue": {
            "controller_online": False, "scope": "local",
            "local_admin": True, "login": "allowed"},
        "controller-restored": {
            "authority_reachable": True, "dns_reachable": True,
            "kerberos_reachable": True, "ldap_reachable": True,
            "smb_reachable": True},
        "windows-secure-channel-restored": {
            "secure_channel": True, "rejoin_required": False},
        "windows-update-policy": {
            "automatic_updates_configured": True,
            "policy_source": "local-policy-or-domain",
            "live_microsoft_update_tested": False},
        "gateway-offline": {
            "gateway_reachable": False, "controller_reachable": True,
            "domain_login": True},
        "update-source-offline": {
            "update_source_reachable": False, "login_unaffected": True,
            "diagnostics_secret_free": True},
        "optional-storage-offline": {
            "storage_reachable": False, "login_succeeded": True,
            "login_seconds": 3.5, "login_bound_seconds": 30,
            "local_profile": True},
        "optional-storage-access-denied": {
            "storage_reachable": True, "storage_access": "denied",
            "login_succeeded": True, "login_seconds": 4,
            "login_bound_seconds": 30, "local_profile": True},
        "ad-dns-offline": {
            "dns_reachable": False, "kerberos_reachable": False,
            "ldap_reachable": False, "smb_reachable": False,
            "cached_login": True},
        "combined-dependencies-offline": {
            "controller_reachable": False, "gateway_reachable": False,
            "update_source_reachable": False,
            "optional_storage_reachable": False,
            "cached_login": True, "local_rescue": True},
        "windows-services-restored": {
            "dns_reachable": True, "secure_channel": True,
            "optional_storage_reachable": True, "rejoin_required": False,
            "rebuild_required": False},
        "windows-diagnostics-sanitized": {
            "secrets_found": 0, "reusable_credentials_retained": False,
            "qemu_arguments_secret_free": True,
            "tracked_artifacts_secret_free": True, "logs_secret_free": True},
        "windows-identity-acceptance": {
            "checks": 24, "firmware_activation_tested": False,
            "live_microsoft_update_tested": False,
            "deferred": ["disable-reenable"]},
    }


def valid_events(contract):
    values = details()
    return [
        {
            "schema_version": 1, "sequence": sequence, "check": check,
            "result": "pass", "external_access": False,
            "observed_at": f"2026-07-28T13:{sequence:02d}:00Z",
            "run_id": RUN_ID, **values[check],
        }
        for sequence, check in enumerate(contract["required_checks"], 1)
    ]


class WindowsIdentityAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = acceptance.load_json(acceptance.CONTRACT)

    def test_contract_and_complete_evidence_pass(self):
        self.assertEqual([], acceptance.validate_contract(self.contract))
        result = acceptance.judge(
            self.contract, valid_events(self.contract))
        self.assertEqual("pass", result["result"])
        self.assertEqual(24, result["checks"])
        self.assertEqual(["disable-reenable"], result["deferred"])

    def test_missing_duplicate_reordered_and_extra_evidence_fail(self):
        cases = {}
        missing = valid_events(self.contract)
        missing.pop()
        cases["missing"] = missing
        duplicate = valid_events(self.contract)
        duplicate[-1] = copy.deepcopy(duplicate[-2])
        cases["duplicate"] = duplicate
        reordered = valid_events(self.contract)
        reordered[2], reordered[3] = reordered[3], reordered[2]
        cases["reordered"] = reordered
        extra = valid_events(self.contract)
        extra[0]["password"] = "must-not-be-retained"
        cases["extra field"] = extra
        for label, events in cases.items():
            with self.subTest(label=label), self.assertRaises(
                    acceptance.EvidenceError):
                acceptance.judge(self.contract, events)

    def test_envelope_failures_are_rejected(self):
        mutations = (
            ("external_access", True),
            ("result", "fail"),
            ("run_id", "different-run"),
            ("observed_at", "not-a-time"),
            ("sequence", 99),
        )
        for field, value in mutations:
            events = valid_events(self.contract)
            events[0][field] = value
            with self.subTest(field=field), self.assertRaises(
                    acceptance.EvidenceError):
                acceptance.judge(self.contract, events)

    def test_privilege_outage_recovery_and_sanitization_fail_closed(self):
        mutations = (
            ("windows-standard-online", "elevated", True),
            ("windows-daily-admin", "domain_admin", True),
            ("controller-offline", "dns_reachable", True),
            ("windows-uncached-denied", "login", "allowed"),
            ("windows-secure-channel-restored", "rejoin_required", True),
            ("windows-diagnostics-sanitized", "secrets_found", 1),
        )
        for check, field, value in mutations:
            events = valid_events(self.contract)
            event = next(item for item in events if item["check"] == check)
            event[field] = value
            with self.subTest(check=check, field=field), self.assertRaises(
                    acceptance.EvidenceError):
                acceptance.judge(self.contract, events)

    def test_cached_capacity_and_storage_login_bounds_are_enforced(self):
        events = valid_events(self.contract)
        policy = next(
            item for item in events
            if item["check"] == "windows-cached-policy")
        policy["cached_logon_count"] = 3
        with self.assertRaisesRegex(
                acceptance.EvidenceError, "capacity is insufficient"):
            acceptance.judge(self.contract, events)
        for check in (
                "optional-storage-offline",
                "optional-storage-access-denied"):
            events = valid_events(self.contract)
            event = next(item for item in events if item["check"] == check)
            event["login_seconds"] = 30.1
            with self.subTest(check=check), self.assertRaisesRegex(
                    acceptance.EvidenceError, "30-second"):
                acceptance.judge(self.contract, events)

    def test_cli_accepts_valid_jsonl_and_rejects_invalid_json(self):
        with tempfile.TemporaryDirectory() as name:
            evidence = Path(name) / "events.jsonl"
            evidence.write_text("".join(
                json.dumps(event) + "\n"
                for event in valid_events(self.contract)), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(acceptance.__file__), str(evidence)],
                check=False, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("pass", json.loads(result.stdout)["result"])
            evidence.write_text("not json\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(acceptance.__file__), str(evidence)],
                check=False, capture_output=True, text=True)
            self.assertEqual(1, result.returncode)
            self.assertIn("windows identity acceptance:", result.stderr)


if __name__ == "__main__":
    unittest.main()
