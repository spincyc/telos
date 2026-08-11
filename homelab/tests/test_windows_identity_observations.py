"""Exact-source Windows identity observation mapping."""

import unittest

from homelab.vm.windows_identity_observations import (
    ObservationRecords,
    WindowsIdentityObservationError,
    derive_observation,
    map_exact_observation,
)


def credential(action, **changes):
    result = {
        "schema_version": 1,
        "event": "credential-action-result",
        "nonce": "ab" * 16,
        "action": action,
        "result": "pass",
        "principal_sid": "S-1-5-21-1-2-3-1201",
        "principal_matches_expected": True,
        "authenticated": True,
        "local_administrators_member": False,
        "authentication_type": "Kerberos",
        "authentication_semantics": "cached-domain",
        "cache_evidence": "offline-cache-proven",
        "login_elapsed_seconds": 2.5,
        "domain_reachable": False,
        "controller_reachable": False,
        "gateway_reachable": True,
        "failure_classification": "none",
    }
    result.update(changes)
    return result


def probe(action, observation):
    return {
        "schema_version": 1,
        "action": action,
        "result": "pass",
        "observed_at": "2026-07-28T15:00:00Z",
        "observation": observation,
    }


def fault(check, *offline):
    return {
        "schema_version": 1,
        "check": check,
        "offline_dependencies": list(offline),
    }


class WindowsIdentityObservationTests(unittest.TestCase):
    diagnostics = {
        "secrets_found": 0,
        "reusable_credentials_retained": False,
        "qemu_arguments_secret_free": True,
        "tracked_artifacts_secret_free": True,
        "logs_secret_free": True,
    }

    def test_structured_probes_close_readiness_and_identity_fields(self):
        readiness = map_exact_observation(
            "controller-ready",
            ObservationRecords(static_probes={
                "controller-readiness": probe("controller-readiness", {
                    "samba_ad": True,
                    "dns": True,
                    "kerberos": True,
                    "time": True,
                    "synthetic_directory": True,
                }),
            }),
        )
        self.assertEqual({
            "samba_ad": True,
            "dns": True,
            "kerberos": True,
            "time": True,
            "synthetic_directory": True,
        }, readiness)

        managed = probe("managed-identity-state", {
            "standard_identity_resolved": True,
            "standard_profile_present": True,
            "operator_identity_resolved": True,
            "operator_profile_present": True,
            "operator_local_administrator": True,
            "operator_domain_administrator": False,
            "directory_admin_identity_resolved": True,
            "directory_admin_domain_administrator": True,
            "operator_is_directory_admin": False,
        })
        daily = map_exact_observation(
            "windows-daily-admin",
            ObservationRecords(
                static_probes={"managed-identity-state": managed},
                credential_actions={"operator-local-administrators-check":
                    credential(
                    "operator-local-administrators-check",
                    local_administrators_member=True,
                    domain_reachable=True,
                    controller_reachable=True,
                    authentication_semantics="connected-domain",
                    cache_evidence="online-interactive-logon")},
            ),
        )
        self.assertEqual({
            "principal_role": "daily-administrator",
            "local_admin": True,
            "domain_admin": False,
            "cache_primed": True,
        }, daily)
        self.assertEqual(
            {"same_principal": False},
            map_exact_observation(
                "domain-admin-separate",
                ObservationRecords(static_probes={
                    "managed-identity-state": managed,
                }),
            ),
        )

    def test_cached_login_is_derived_without_caller_source_labels(self):
        fields = map_exact_observation(
            "windows-cached-login",
            ObservationRecords(
                credential_actions={"cached-domain-login":
                    credential("cached-domain-login")},
                fault_record=fault(
                    "windows-cached-login", "controller"),
            ),
        )
        self.assertEqual({
            "controller_online": False,
            "cached": True,
            "principal_role": "standard",
            "login": "allowed",
        }, fields)

    def test_gateway_fault_uses_measured_gateway_and_controller_state(self):
        fields = map_exact_observation(
            "gateway-offline",
            ObservationRecords(
                credential_actions={"connected-domain-login": credential(
                    "connected-domain-login",
                    domain_reachable=True,
                    controller_reachable=True,
                    gateway_reachable=False,
                    authentication_semantics="connected-domain",
                    cache_evidence="online-interactive-logon",
                )},
                fault_record=fault("gateway-offline", "gateway"),
            ),
        )
        self.assertEqual({
            "gateway_reachable": False,
            "controller_reachable": True,
            "domain_login": True,
        }, fields)

    def test_update_source_login_and_diagnostics_have_exact_sources(self):
        fields = map_exact_observation(
            "update-source-offline",
            ObservationRecords(
                static_probes={"dependency-reachability": probe(
                    "dependency-reachability", {
                        "update_source_reachable": False,
                        "optional_storage_reachable": True,
                        "optional_storage_authorization_denied": False,
                    })},
                credential_actions={"connected-domain-login": credential(
                    "connected-domain-login",
                    domain_reachable=True,
                    controller_reachable=True,
                    authentication_semantics="connected-domain",
                    cache_evidence="online-interactive-logon",
                )},
                fault_record=fault(
                    "update-source-offline", "update-source"),
                diagnostics_scan=self.diagnostics,
            ),
        )
        self.assertEqual({
            "update_source_reachable": False,
            "login_unaffected": True,
            "diagnostics_secret_free": True,
        }, fields)

    def test_diagnostics_scan_maps_without_fixture_acceptance_fields(self):
        self.assertEqual(
            self.diagnostics,
            map_exact_observation(
                "windows-diagnostics-sanitized",
                ObservationRecords(diagnostics_scan=self.diagnostics),
            ),
        )

    def test_uncached_denial_comes_from_failure_record(self):
        fields = map_exact_observation(
            "windows-uncached-denied",
            ObservationRecords(
                credential_actions={"uncached-domain-user-denied":
                    credential(
                    "uncached-domain-user-denied",
                    authenticated=False,
                    principal_sid="",
                    principal_matches_expected=False,
                    authentication_type="None",
                    authentication_semantics="domain-logon-denied",
                    cache_evidence="offline-cache-miss-proven",
                    failure_classification="windows-logon-failure",
                )},
                fault_record=fault(
                    "windows-uncached-denied", "controller"),
            ),
        )
        self.assertEqual("denied", fields["login"])
        self.assertEqual("uncached-domain-user", fields["principal_role"])

    def test_storage_denial_includes_bounded_login_and_profile(self):
        records = ObservationRecords(
            static_probes={"dependency-reachability": probe(
                "dependency-reachability", {
                "update_source_reachable": True,
                "optional_storage_reachable": True,
                "optional_storage_authorization_denied": True,
            })},
            credential_actions={"connected-domain-login": credential(
                "connected-domain-login",
                domain_reachable=True,
                controller_reachable=True,
                authentication_semantics="connected-domain",
                cache_evidence="online-interactive-logon",
            )},
            fault_record=fault("optional-storage-access-denied"),
        )
        self.assertEqual({
            "storage_reachable": True,
            "storage_access": "denied",
            "login_succeeded": True,
            "login_seconds": 2.5,
            "login_bound_seconds": 30,
        }, map_exact_observation(
            "optional-storage-access-denied", records))

    def test_fixture_fields_and_asserted_labels_are_not_accepted(self):
        records = ObservationRecords(
            credential_actions={"cached-domain-login": {
                **credential("cached-domain-login"),
                "source": "credential:windows-cached-login",
            }},
            fault_record=fault("windows-cached-login", "controller"),
        )
        with self.assertRaisesRegex(
                WindowsIdentityObservationError, "credential action"):
            map_exact_observation("windows-cached-login", records)

    def test_machine_account_and_cache_priming_remain_unproved(self):
        joined = ObservationRecords(
            static_probes={"domain-state": probe("domain-state", {
                "part_of_domain": True,
                "domain": "FACTORY.TEST",
                "secure_channel": True,
                "operator": "operator@FACTORY.TEST",
                "operator_local_administrator": True,
            })},
            join_proof={
                "schema_version": 1,
                "join_media_destroyed": True,
                "joined_after_reboot": True,
                "domain": "FACTORY.TEST",
                "operator": "operator@FACTORY.TEST",
                "operator_local_administrator": True,
            },
        )
        self.assertEqual({
            "domain_joined": True,
            "secure_channel": True,
            "machine_account": True,
            "join_material": "one-use",
        }, map_exact_observation("windows-joined", joined))


if __name__ == "__main__":
    unittest.main()
