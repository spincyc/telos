"""The durable workstation binding: realm, fabric and SID refusals (TASK-28).

Every fixture is synthetic and built in a temporary directory.  Nothing here
reads ``build/``, ``homelab/var/`` or ``homelab/instance/``: the roster
fingerprint is passed in rather than resolved from the private roster.
"""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from homelab.vm import durable_workstation, simulated_gateway
from homelab.vm.simulation_overlay import PersistentControllerInstance
from homelab.tests.identity_overlay_pin import pinned_acceptance_state


def setUpModule():
    # HANDOFF section 5: no test stats the operator's build/ tree.  Every
    # persistent-instance separation check resolves the reserved acceptance
    # state, which defaults to the real build/homelab/vm/bootstrap-dc, so
    # every test here reserves private spellings of it instead.
    unittest.enterModuleContext(pinned_acceptance_state())

DOMAIN = "ad.example.home.arpa"
REALM = DOMAIN.upper()
NETBIOS = "EXAMPLEAD"
BOOTSTRAP = f"bootstrap-dc.{DOMAIN}"
PERMANENT = f"dc2.{DOMAIN}"
SID = "S-1-5-21-1111111111-2222222222-3333333333"
FINGERPRINT = "0123456789abcdef"
INSTANCE = "lab-dc1"


def identity_document(**network):
    """A permanent identity on the per-run fabric's own Controller addressing."""
    values = {
        "address": str(simulated_gateway.CONTROLLER_IP),
        "prefix": durable_workstation.FABRIC_PREFIX,
        "gateway": str(simulated_gateway.GATEWAY_IP),
    }
    values.update(network)
    return {
        "schema_version": 1,
        "identity": {
            "dns_domain": DOMAIN, "kerberos_realm": REALM,
            "netbios_name": NETBIOS,
        },
        "services": {
            "bootstrap_dc_fqdn": BOOTSTRAP, "permanent_dc_fqdn": PERMANENT,
        },
        "network": values,
    }


def marker(**converged):
    record = {
        "converged_utc": "2026-01-01T00:00:00+00:00",
        "realm": REALM, "netbios": NETBIOS, "dns_domain": DOMAIN,
        "domain_sid": SID,
    }
    record.update(converged)
    return {
        "schema": 1, "mode": "persistent", "instance": INSTANCE,
        "created_utc": "2026-01-01T00:00:00+00:00",
        "converged": record,
        "directory_accounts": {
            "staged_utc": "2026-01-01T00:00:00+00:00",
            "roster_fingerprint": FINGERPRINT,
            "accounts": [{"contract_role": "standard_user"}],
        },
    }


class BindingFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.persistent = self.root / "persistent"
        self.state = self.persistent / INSTANCE
        self.state.mkdir(parents=True)
        for name in ("persistent-dc.qcow2", "OVMF_VARS.fd"):
            (self.state / name).write_bytes(b"synthetic")
        self.write_marker(marker())
        self.identity = self.root / "directory.json"
        self.write_identity(identity_document())
        self.canonical = self.root / "canonical"

    def write_marker(self, document):
        (self.state / "persistent-instance.json").write_text(
            json.dumps(document))

    def write_identity(self, document):
        self.identity.write_text(json.dumps(document))

    def bind(self, **overrides):
        options = {
            "canonical_state": self.canonical,
            "identity_path": self.identity,
            "roster_fingerprint": FINGERPRINT,
        }
        options.update(overrides)
        return durable_workstation.durable_binding(
            self.persistent, INSTANCE, **options)

    def refused(self, pattern, **overrides):
        with self.assertRaisesRegex(
                durable_workstation.DurableBindingError, pattern) as caught:
            self.bind(**overrides)
        return str(caught.exception)


class DurableBindingTests(BindingFixture):
    def test_a_consistent_instance_binds_to_the_bootstrap_controller(self):
        binding = self.bind()
        self.assertEqual(binding.instance, INSTANCE)
        self.assertEqual(binding.state, self.state.absolute())
        self.assertEqual(binding.kerberos_realm, REALM)
        self.assertEqual(binding.dns_domain, DOMAIN)
        self.assertEqual(binding.netbios_name, NETBIOS)
        self.assertEqual(binding.controller_fqdn, BOOTSTRAP)
        self.assertEqual(binding.permanent_dc_fqdn, PERMANENT)
        self.assertEqual(binding.domain_sid, SID)
        self.assertEqual(binding.roster_fingerprint, FINGERPRINT)
        # A binding that reaches a log names its instance and nothing else.
        self.assertEqual(repr(binding), f"DurableBinding(instance='{INSTANCE}')")

    def test_the_fabric_is_the_gateway_s_own_addressing(self):
        self.assertEqual(durable_workstation.FABRIC_PREFIX, 28)
        self.assertEqual(
            durable_workstation.FABRIC_CONTROLLER_ADDRESS,
            simulated_gateway.CONTROLLER_IP)
        self.assertEqual(
            durable_workstation.FABRIC_GATEWAY_ADDRESS,
            simulated_gateway.GATEWAY_IP)

    def test_off_fabric_addressing_is_refused_without_printing_it(self):
        for key, value in (
                ("address", "10.1.31.3"), ("prefix", 24),
                ("gateway", "10.1.31.14")):
            with self.subTest(key=key):
                self.write_identity(identity_document(**{key: value}))
                message = self.refused(f"network.{key}")
                self.assertIn("fabric", message)
                self.assertNotIn(str(value), message.replace(
                    str(self.identity), ""))

    def test_a_marker_holding_another_realm_is_refused(self):
        for key, value in (
                ("realm", "OTHER.HOME.ARPA"), ("dns_domain", "other.home.arpa"),
                ("netbios", "OTHER")):
            with self.subTest(key=key):
                self.write_marker(marker(**{key: value}))
                message = self.refused(key)
                self.assertNotIn(value, message)

    def test_a_bootstrap_controller_not_named_bootstrap_dc_is_refused(self):
        document = identity_document()
        document["services"]["bootstrap_dc_fqdn"] = f"dc1.{DOMAIN}"
        self.write_identity(document)
        self.refused("host name is not 'bootstrap-dc'")

    def test_an_instance_without_a_directory_or_roster_is_refused(self):
        unconverged = marker()
        del unconverged["converged"]
        self.write_marker(unconverged)
        self.refused("no converged directory")
        self.write_marker(marker(domain_sid=None))
        self.refused("domain SID")
        unstaged = marker()
        del unstaged["directory_accounts"]
        self.write_marker(unstaged)
        self.refused("no staged durable account roster")

    def test_the_password_policy_may_bind_before_accounts_are_staged(self):
        # UAT 2026-10-07: the short policy must exist before permanent short
        # passwords can be staged, so only the policy step skips this.
        unstaged = marker()
        del unstaged["directory_accounts"]
        self.write_marker(unstaged)
        binding = self.bind(require_accounts=False)
        self.assertEqual(binding.roster_fingerprint, FINGERPRINT)
        # A roster that is staged must still be the current one.
        self.write_marker(marker())
        self.refused("fingerprint", require_accounts=False,
                     roster_fingerprint="fedcba9876543210")

    def test_a_stale_roster_fingerprint_is_refused(self):
        self.refused("fingerprint", roster_fingerprint="fedcba9876543210")

    def test_the_roster_fingerprint_is_resolved_when_not_given(self):
        with mock.patch.object(
                durable_workstation, "_current_roster_fingerprint",
                return_value=FINGERPRINT) as resolve:
            self.bind(roster_fingerprint=None, overlay_path=Path("/x.json"))
        resolve.assert_called_once_with(Path("/x.json"))

    def test_absent_misnamed_and_acceptance_instances_are_refused(self):
        with self.assertRaisesRegex(
                durable_workstation.DurableBindingError, "lowercase"):
            durable_workstation.durable_binding(
                self.persistent, "../escape", canonical_state=self.canonical)
        with self.assertRaisesRegex(
                durable_workstation.DurableBindingError, "no persistent"):
            durable_workstation.durable_binding(
                self.persistent, "absent", canonical_state=self.canonical,
                identity_path=self.identity, roster_fingerprint=FINGERPRINT)
        # A directory holding the acceptance artefact is never an instance.
        (self.state / "bootstrap-dc.qcow2").write_bytes(b"canonical")
        self.refused("acceptance")

    def test_an_absent_identity_overlay_is_refused(self):
        self.refused("not declared", identity_path=self.root / "absent.json")


class RealmAgreementTests(BindingFixture):
    def realm(self, **fields):
        values = {
            "dns_domain": DOMAIN, "kerberos_realm": REALM,
            "workgroup": NETBIOS, "controller_fqdn": BOOTSTRAP,
            "durable": True,
        }
        values.update(fields)
        return SimpleNamespace(**values)

    def test_a_durable_bundle_pinning_the_bootstrap_controller_agrees(self):
        durable_workstation.require_durable_realm_agreement(
            self.realm(), self.bind())

    def test_disagreements_are_refused(self):
        binding = self.bind()
        for fields, pattern in (
                ({"durable": False}, "permanent realm"),
                ({"kerberos_realm": "OTHER.HOME.ARPA"}, "Kerberos realm"),
                ({"dns_domain": "other.home.arpa"}, "DNS domain"),
                ({"workgroup": "OTHER"}, "NetBIOS"),
                ({"controller_fqdn": PERMANENT}, "predates SRV-first")):
            with self.subTest(fields=fields):
                with self.assertRaisesRegex(
                        durable_workstation.DurableBindingError, pattern):
                    durable_workstation.require_durable_realm_agreement(
                        self.realm(**fields), binding)


class RecordedDcNameTests(BindingFixture):
    """Owner decision 2026-09-30, aiq TASK-42: the DC name is recorded."""

    RESTORED = "dr-2609302105"
    realm = RealmAgreementTests.realm

    def restored(self):
        self.write_marker(marker(dc_hostname=self.RESTORED))
        return self.bind()

    def workstation(self, *stages, discovery=None):
        document = {
            "workstation": "lab-ws1",
            "ledger": [{"stage": stage} for stage in ("adopt", *stages)],
        }
        if discovery is not None:
            document["arch_dc_discovery"] = discovery
        return document

    def test_an_instance_without_the_field_runs_the_canonical_name(self):
        binding = self.bind()
        self.assertEqual(binding.dc_hostname, "bootstrap-dc")
        self.assertEqual(binding.controller_fqdn, BOOTSTRAP)
        target = PersistentControllerInstance(self.state, instance=INSTANCE)
        self.assertEqual(target.dc_hostname(), "bootstrap-dc")
        from homelab.vm import bootstrap_dc, simulation_overlay
        self.assertEqual(simulation_overlay.DEFAULT_DC_HOSTNAME,
                         bootstrap_dc.NAME)

    def test_a_restored_instance_binds_under_its_recorded_name(self):
        binding = self.restored()
        self.assertEqual(binding.dc_hostname, self.RESTORED)
        self.assertEqual(binding.controller_fqdn, f"{self.RESTORED}.{DOMAIN}")
        # The overlay's frozen names are unchanged; only the DC moved.
        self.assertEqual(binding.permanent_dc_fqdn, PERMANENT)
        self.write_marker(marker(dc_hostname="Not A Name"))
        self.refused("dc_hostname")

    def test_srv_first_accepts_another_dc_name_and_says_so(self):
        binding = self.restored()
        note = durable_workstation.require_durable_realm_agreement(
            self.realm(), binding, srv_first=True)
        self.assertIn("DNS SRV first", note)
        self.assertIn(self.RESTORED, note)
        self.assertNotIn(DOMAIN, note)
        self.assertIsNone(durable_workstation.require_durable_realm_agreement(
            self.realm(controller_fqdn=f"{self.RESTORED}.{DOMAIN}"), binding))
        with self.assertRaisesRegex(durable_workstation.DurableBindingError,
                                    "outside"):
            durable_workstation.require_durable_realm_agreement(
                self.realm(controller_fqdn="dc.other.home.arpa"), binding,
                srv_first=True)

    def test_a_pinned_only_workstation_is_refused_after_a_rename(self):
        binding = self.restored()
        # rehearsal-auto-ws1's shape: installed before TASK-42, no record.
        legacy = self.workstation("arch-install", "arch-join", "windows-join")
        with self.assertRaisesRegex(
                durable_workstation.DurableBindingError,
                "predates SRV-first discovery") as caught:
            durable_workstation.require_workstation_dc_agreement(
                legacy, binding)
        self.assertIn("lab-ws1", str(caught.exception))
        self.assertIn("Install its Arch side again", str(caught.exception))
        self.assertNotIn(DOMAIN, str(caught.exception))
        pinned = self.workstation(
            "arch-install", discovery={"mode": "pinned",
                                       "fallback_fqdn": BOOTSTRAP, "utc": "u"})
        with self.assertRaises(durable_workstation.DurableBindingError):
            durable_workstation.require_workstation_dc_agreement(
                pinned, binding)
        # Against the DC it was installed for, the same disk is fine.
        self.assertIsNone(durable_workstation.require_workstation_dc_agreement(
            legacy, self.bind_unrestored()))

    def bind_unrestored(self):
        self.write_marker(marker())
        return self.bind()

    def test_an_srv_first_workstation_is_accepted_after_a_rename(self):
        binding = self.restored()
        srv_first = self.workstation(
            "arch-install", discovery={"mode": "srv-first",
                                       "fallback_fqdn": BOOTSTRAP, "utc": "u"})
        note = durable_workstation.require_workstation_dc_agreement(
            srv_first, binding)
        self.assertIn("kept workstation lab-ws1's Arch side finds the domain "
                      "controller by DNS SRV first", note)

    def test_windows_joins_by_domain_name_and_pins_no_dc(self):
        """TASK-42 item 4: Windows' DC locator finds the DC by SRV itself."""
        control = Path(durable_workstation.__file__).with_name(
            "windows_join_control")
        join = (control / "TelosJoin.ps1").read_text(encoding="utf-8")
        self.assertIn("-MethodName JoinDomainOrWorkgroup", join)
        self.assertIn("Name = $domain", join)
        for script in sorted(control.glob("*.ps1")):
            text = script.read_text(encoding="utf-8")
            for pin in ("ControllerFqdn", "bootstrap-dc", " -Server "):
                with self.subTest(script=script.name, pin=pin):
                    self.assertNotIn(pin, text)

    def test_the_workstation_record_is_a_closed_shape(self):
        from homelab.vm import workstation_instance as wi
        good = {"mode": "srv-first", "fallback_fqdn": BOOTSTRAP, "utc": "u"}
        self.assertEqual(wi._validated_dc_discovery(dict(good)), good)
        for bad in (dict(good, mode="dns"),
                    dict(good, fallback_fqdn="Not A Name"),
                    dict(good, extra="x"), {"mode": "pinned"}, "srv-first"):
            with self.subTest(record=bad):
                with self.assertRaises(wi.WorkstationInvalid):
                    wi._validated_dc_discovery(bad)

    def test_a_workstation_without_an_arch_side_has_nothing_to_judge(self):
        self.assertIsNone(durable_workstation.require_workstation_dc_agreement(
            self.workstation(), self.restored()))


class LiveDirectoryTests(BindingFixture):
    TRUNCATED = "S-1-5-21-1111111111-2222222222-33"

    def test_an_exact_sid_matches(self):
        self.assertEqual(
            durable_workstation.check_live_directory(SID, SID),
            durable_workstation.SID_MATCH)

    def test_a_truncated_record_is_repairable_and_nothing_else_is(self):
        self.assertEqual(
            durable_workstation.check_live_directory(self.TRUNCATED, SID),
            durable_workstation.SID_REPAIR)
        for recorded, live in (
                (SID, "S-1-5-21-1111111111-2222222222-4444444444"),
                (SID, self.TRUNCATED),
                ("S-1-5-21-1111111111-2222222222-34", SID),
                (self.TRUNCATED, "S-1-5-21-1111111111-2222222222-3"),
                (SID, ""),
                ("not a sid", SID)):
            with self.subTest(recorded=recorded, live=live):
                with self.assertRaises(
                        durable_workstation.DurableBindingError) as caught:
                    durable_workstation.check_live_directory(recorded, live)
                self.assertNotIn("S-1-5-21", str(caught.exception))

    def test_a_repair_completes_the_record_and_the_marker_accepts_it(self):
        self.write_marker(marker(domain_sid=self.TRUNCATED))
        instance = PersistentControllerInstance(self.state, instance=INSTANCE)
        record = instance.convergence()
        repaired = durable_workstation.repaired_convergence(
            record, SID, now="2026-01-02T00:00:00+00:00")
        self.assertEqual(repaired["domain_sid"], SID)
        self.assertEqual(record["domain_sid"], self.TRUNCATED)
        self.assertEqual(
            repaired["domain_sid_repaired"]["repaired_utc"],
            "2026-01-02T00:00:00+00:00")
        for key in ("realm", "netbios", "dns_domain", "converged_utc"):
            self.assertEqual(repaired[key], record[key])
        instance.record_convergence(repaired)
        self.assertEqual(instance.convergence()["domain_sid"], SID)
        with self.assertRaisesRegex(
                durable_workstation.DurableBindingError, "needs no repair"):
            durable_workstation.repaired_convergence(repaired, SID)


if __name__ == "__main__":
    unittest.main()
