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
        "arch-storage-attached": {
            "storage_reachable": True, "mount_state": "mounted",
            "storage_access": "authorized"},
        "arch-storage-denied": {
            "storage_reachable": True, "mount_state": "refused",
            "storage_access": "denied", "foreign_share": True},
        "arch-storage-absent-login": {
            "storage_reachable": False, "mount_state": "absent",
            "login": "allowed", "login_path_independent": True,
            "login_seconds": 4, "login_bound_seconds": 30},
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

    def test_revocation_contract_preserves_the_offline_limit(self):
        revocation = next(
            item for item in self.contract["deferred_checks"]
            if item["id"] == "disable-reenable"
        )
        self.assertEqual(revocation["applies_to"], ["windows", "arch"])
        self.assertEqual(revocation["release_gate"], "deferred")
        sequence = revocation["required_sequence"]
        self.assertLess(
            sequence.index("connected-login-denied"),
            sequence.index("cached-offline-login-still-allowed"),
        )
        self.assertIn("connected-network-access-denied", sequence)
        self.assertIn("old-credential-denied-online", sequence)
        self.assertEqual(sequence[-1], "new-credential-accepted-offline")

    def test_phase_one_requires_indefinite_cached_login_on_both_systems(self):
        required = self.contract["required_checks"]
        for os_name in ("windows", "arch"):
            self.assertIn(f"{os_name}-cached-login", required)
            self.assertIn(f"{os_name}-uncached-denied", required)
            self.assertIn(f"{os_name}-local-rescue", required)

    def test_human_acceptance_guide_names_the_non_revocation_boundary(self):
        guide = (ROOT / "IDENTITY-LIFECYCLE-ACCEPTANCE.md").read_text()
        self.assertIn("offline_credentials_expiration = 0", guide)
        self.assertIn("does not erase credentials already cached", guide)
        self.assertIn("Windows secure channel", guide)
        self.assertIn("Arch identity", guide)
        self.assertIn("Phase-two revocation remains deferred", guide)

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

    # ---- Gate 9: optional per-user SMB storage ----

    def _storage_event(self, evidence, check):
        return next(item for item in evidence if item["check"] == check)

    def test_contract_orders_storage_checks_after_identity_restored(self):
        required = self.contract["required_checks"]
        anchor = required.index("arch-identity-restored")
        positions = [required.index(check)
                     for check in lifecycle.STORAGE_CHECKS]
        self.assertEqual(positions, sorted(positions))
        self.assertGreater(positions[0], anchor)
        result = lifecycle.judge(self.contract, valid_events(self.contract))
        self.assertEqual(result["checks"], len(required))
        self.assertEqual(len(required), 21)

    def test_contract_without_storage_checks_is_invalid(self):
        for check in lifecycle.STORAGE_CHECKS:
            contract = copy.deepcopy(self.contract)
            contract["required_checks"].remove(check)
            self.assertTrue(any(
                "optional-storage" in error
                for error in lifecycle.validate_contract(contract)))

    def test_contract_with_reordered_storage_checks_is_invalid(self):
        contract = copy.deepcopy(self.contract)
        checks = contract["required_checks"]
        first = checks.index("arch-storage-attached")
        last = checks.index("arch-storage-absent-login")
        checks[first], checks[last] = checks[last], checks[first]
        self.assertTrue(any(
            "attached, denied, absent-login" in error
            for error in lifecycle.validate_contract(contract)))
        contract = copy.deepcopy(self.contract)
        checks = contract["required_checks"]
        checks.remove("arch-storage-attached")
        checks.insert(0, "arch-storage-attached")
        self.assertTrue(any(
            "arch-identity-restored" in error
            for error in lifecycle.validate_contract(contract)))

    def test_contract_pins_login_bound_and_storage_policy(self):
        contract = copy.deepcopy(self.contract)
        contract["login_bound_seconds"] = 300
        self.assertTrue(any(
            "login_bound_seconds" in error
            for error in lifecycle.validate_contract(contract)))
        contract = copy.deepcopy(self.contract)
        del contract["login_bound_seconds"]
        self.assertTrue(any(
            "login_bound_seconds" in error
            for error in lifecycle.validate_contract(contract)))
        for mutation in (
            {"nfs": "enabled"},
            {"login_dependency": "allowed"},
            {"protocol": "nfs"},
            {"authorization": "shared"},
        ):
            contract = copy.deepcopy(self.contract)
            contract["optional_storage"].update(mutation)
            self.assertTrue(any(
                "optional_storage" in error
                for error in lifecycle.validate_contract(contract)))
        contract = copy.deepcopy(self.contract)
        del contract["optional_storage"]
        self.assertTrue(any(
            "optional_storage" in error
            for error in lifecycle.validate_contract(contract)))

    def test_storage_attach_judged_fields_fail_closed(self):
        for field, value in (
            ("storage_reachable", False),
            ("storage_reachable", None),
            ("mount_state", "absent"),
            ("storage_access", "denied"),
        ):
            evidence = valid_events(self.contract)
            check = self._storage_event(evidence, "arch-storage-attached")
            check[field] = value
            with self.assertRaisesRegex(
                    lifecycle.EvidenceError, "mounted and authorized"):
                lifecycle.judge(self.contract, evidence)
        evidence = valid_events(self.contract)
        del self._storage_event(
            evidence, "arch-storage-attached")["mount_state"]
        with self.assertRaisesRegex(
                lifecycle.EvidenceError, "mounted and authorized"):
            lifecycle.judge(self.contract, evidence)

    def test_storage_denial_judged_fields_fail_closed(self):
        for field, value in (
            ("storage_reachable", False),
            ("mount_state", "mounted"),
            ("storage_access", "authorized"),
            ("foreign_share", False),
            ("foreign_share", None),
        ):
            evidence = valid_events(self.contract)
            check = self._storage_event(evidence, "arch-storage-denied")
            check[field] = value
            with self.assertRaisesRegex(
                    lifecycle.EvidenceError, "foreign user's share"):
                lifecycle.judge(self.contract, evidence)

    def test_storage_absent_login_judged_fields_fail_closed(self):
        for field, value in (
            ("storage_reachable", True),
            ("mount_state", "mounted"),
            ("login", "denied"),
            ("login_path_independent", False),
            ("login_path_independent", None),
        ):
            evidence = valid_events(self.contract)
            check = self._storage_event(
                evidence, "arch-storage-absent-login")
            check[field] = value
            with self.assertRaisesRegex(
                    lifecycle.EvidenceError, "proven independent"):
                lifecycle.judge(self.contract, evidence)

    def test_storage_absent_login_duration_is_bounded_and_typed(self):
        for value in (31, 30.5, -1, True, "4", float("nan"), float("inf"),
                      None):
            evidence = valid_events(self.contract)
            check = self._storage_event(
                evidence, "arch-storage-absent-login")
            check["login_seconds"] = value
            with self.assertRaisesRegex(
                    lifecycle.EvidenceError, "login bound"):
                lifecycle.judge(self.contract, evidence)
        evidence = valid_events(self.contract)
        check = self._storage_event(evidence, "arch-storage-absent-login")
        del check["login_seconds"]
        with self.assertRaisesRegex(lifecycle.EvidenceError, "login bound"):
            lifecycle.judge(self.contract, evidence)
        evidence = valid_events(self.contract)
        check = self._storage_event(evidence, "arch-storage-absent-login")
        check["login_bound_seconds"] = 60
        with self.assertRaisesRegex(
                lifecycle.EvidenceError, "contract login bound"):
            lifecycle.judge(self.contract, evidence)
        evidence = valid_events(self.contract)
        check = self._storage_event(evidence, "arch-storage-absent-login")
        check["login_seconds"] = 30
        result = lifecycle.judge(self.contract, evidence)
        self.assertEqual(result["result"], "pass")


if __name__ == "__main__":
    unittest.main()
