import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "workstations"))

import identity_lifecycle as lifecycle  # noqa: E402


def event(check, **fields):
    return {"check": check, "result": "pass", "external_access": False, **fields}


def valid_events(contract):
    details = {
        "controller-ready": {
            "samba_ad": True, "dns": True, "kerberos": True, "time": True,
            "synthetic_directory": True},
        "windows-joined": {
            "domain_joined": True, "secure_channel": True, "machine_account": True},
        "arch-joined": {
            "domain_joined": True, "secure_channel": True, "machine_account": True},
        "windows-standard-online": {
            "principal_role": "standard", "elevated": False},
        "arch-standard-online": {
            "principal_role": "standard", "elevated": False},
        "windows-daily-admin": {
            "principal_role": "daily-administrator", "local_admin": True,
            "domain_admin": False},
        "arch-daily-admin": {
            "principal_role": "daily-administrator", "local_admin": True,
            "domain_admin": False},
        "domain-admin-separate": {"same_principal": False},
        "controller-offline": {"authority_reachable": False},
        "windows-cached-login": {"controller_online": False, "cached": True},
        "arch-cached-login": {"controller_online": False, "cached": True},
        "windows-uncached-denied": {"controller_online": False, "login": "denied"},
        "arch-uncached-denied": {"controller_online": False, "login": "denied"},
        "windows-local-rescue": {"scope": "local", "local_admin": True},
        "arch-local-rescue": {"scope": "local", "local_admin": True},
        "controller-restored": {"authority_reachable": True},
        "windows-secure-channel-restored": {"secure_channel": True},
        "arch-identity-restored": {"identity_lookup": True},
    }
    return [event(check, **details.get(check, {}))
            for check in contract["required_checks"]]


class IdentityLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = lifecycle.load_json(lifecycle.CONTRACT)

    def test_contract_is_valid_and_synthetic(self):
        self.assertEqual(lifecycle.validate_contract(self.contract), [])
        names = {item["name"] for item in self.contract["principals"].values()}
        self.assertNotIn("ksh", names)
        self.assertNotIn("ksh-root", names)

    def test_complete_local_lifecycle_passes(self):
        result = lifecycle.judge(self.contract, valid_events(self.contract))
        self.assertEqual(result["result"], "pass")
        self.assertFalse(result["external_access"])
        self.assertEqual(result["deferred"], ["disable-reenable"])

    def test_missing_step_fails(self):
        evidence = valid_events(self.contract)
        evidence.pop(2)
        with self.assertRaisesRegex(lifecycle.EvidenceError, "missing evidence"):
            lifecycle.judge(self.contract, evidence)

    def test_reordered_step_fails(self):
        evidence = valid_events(self.contract)
        evidence[1], evidence[2] = evidence[2], evidence[1]
        with self.assertRaisesRegex(lifecycle.EvidenceError, "out of order"):
            lifecycle.judge(self.contract, evidence)

    def test_duplicate_step_fails(self):
        evidence = valid_events(self.contract)
        evidence.append(copy.deepcopy(evidence[-1]))
        with self.assertRaisesRegex(lifecycle.EvidenceError, "duplicate evidence"):
            lifecycle.judge(self.contract, evidence)

    def test_any_external_access_fails(self):
        evidence = valid_events(self.contract)
        evidence[0]["external_access"] = True
        with self.assertRaisesRegex(lifecycle.EvidenceError, "external_access=false"):
            lifecycle.judge(self.contract, evidence)

    def test_standard_user_elevation_fails(self):
        evidence = valid_events(self.contract)
        evidence[3]["elevated"] = True
        with self.assertRaisesRegex(lifecycle.EvidenceError, "standard user"):
            lifecycle.judge(self.contract, evidence)

    def test_daily_admin_must_not_be_domain_admin(self):
        evidence = valid_events(self.contract)
        check = next(item for item in evidence
                     if item["check"] == "windows-daily-admin")
        check["domain_admin"] = True
        with self.assertRaisesRegex(lifecycle.EvidenceError, "least-privileged"):
            lifecycle.judge(self.contract, evidence)

    def test_uncached_user_must_be_denied_during_outage(self):
        evidence = valid_events(self.contract)
        check = next(item for item in evidence
                     if item["check"] == "arch-uncached-denied")
        check["login"] = "allowed"
        with self.assertRaisesRegex(lifecycle.EvidenceError, "uncached outage"):
            lifecycle.judge(self.contract, evidence)

    def test_jsonl_parser_reports_line(self):
        with self.assertRaisesRegex(lifecycle.EvidenceError, "line 2"):
            lifecycle.load_events(['{"ok": true}\n', "nope\n"])


if __name__ == "__main__":
    unittest.main()
