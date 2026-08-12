"""Contract tests for the read-only gate-4 PXE authority audit."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from homelab.vm import factory_runner, pxe_authority_audit as audit


GW = "52:54:00:31:11:01"
CT = "52:54:00:31:11:12"
WS = "52:54:00:31:12:12"


def ready():
    return {"event": "switch-ready", "ports": [
        {"port": "gateway", "mac": GW},
        {"port": "controller", "mac": CT},
        {"port": "workstation", "mac": WS},
    ]}


def connected(port, mac, generation=1):
    return {"event": "port-connected", "port": port, "mac": mac,
            "generation": generation}


def dhcp(kind, peer, source, client, **extra):
    return {"event": "dhcp", "kind": kind, "peer": peer,
            "source_mac": source, "client_mac": client,
            "transaction": "deadbeef", **extra}


def flow(peer, delivered_to, ethertype=0x0800, protocol=None,
         src_port=None, dst_port=None):
    event = {"event": "flow", "peer": peer, "delivered_to": delivered_to,
             "ethertype": ethertype}
    if protocol is not None:
        event["ip_protocol"] = protocol
    if src_port is not None:
        event["src_port"] = src_port
    if dst_port is not None:
        event["dst_port"] = dst_port
    return event


def clean_run_events():
    return [
        ready(),
        connected("gateway", GW),
        connected("controller", CT),
        connected("workstation", WS),
        dhcp("DISCOVER", "workstation", WS, WS, architecture=7),
        dhcp("OFFER", "gateway", GW, WS, delivered_to="workstation",
             offered_ip="10.1.31.11", boot_file="ipxe.efi"),
        dhcp("REQUEST", "workstation", WS, WS, requested_ip="10.1.31.11"),
        dhcp("ACK", "gateway", GW, WS, delivered_to="workstation",
             offered_ip="10.1.31.11"),
        {"event": "port-disconnected", "port": "workstation", "mac": WS,
         "generation": 1},
        {"event": "switch-summary", "frames": 9, "deliveries": 9,
         "blocked": 0, "accepted_ports": 3},
    ]


class AuditHelper(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write_log(self, events, name="switch.jsonl", raw=None):
        path = self.root / name
        if raw is None:
            raw = "".join(json.dumps(event) + "\n" for event in events)
        path.write_text(raw, encoding="utf-8")
        return path

    def audit(self, events, **kwargs):
        path = self.write_log(events, **kwargs)
        return audit.audit_paths([path], audit.factory_topology())

    def verdicts(self, result):
        return {check["check"]: check["verdict"]
                for check in result["checks"]}


class SoleAuthorityTests(AuditHelper):
    def test_clean_run_passes_every_provable_check(self):
        result = self.audit(clean_run_events())
        verdicts = self.verdicts(result)
        self.assertEqual(verdicts[audit.CHECK_SOLE_AUTHORITY], "PASS")
        self.assertEqual(verdicts[audit.CHECK_CONTROLLER_SILENCE], "PASS")
        self.assertEqual(verdicts[audit.CHECK_FABRIC_CLOSURE], "PASS")
        self.assertEqual(
            verdicts[audit.CHECK_APPROVED_FLOWS], "NOT-PROVABLE")
        self.assertEqual(result["verdict"], "NOT-PROVABLE")

    def test_no_dhcp_activity_is_not_a_pass(self):
        events = [ready(), connected("gateway", GW),
                  connected("controller", CT), connected("workstation", WS)]
        result = self.audit(events)
        check = self.verdicts(result)
        self.assertEqual(check[audit.CHECK_SOLE_AUTHORITY], "NOT-PROVABLE")

    def test_rogue_controller_offer_fails(self):
        events = clean_run_events()
        events.insert(5, dhcp("OFFER", "controller", CT, WS, blocked=True))
        result = self.audit(events)
        verdicts = self.verdicts(result)
        self.assertEqual(verdicts[audit.CHECK_SOLE_AUTHORITY], "FAIL")
        self.assertEqual(verdicts[audit.CHECK_CONTROLLER_SILENCE], "FAIL")
        self.assertEqual(result["verdict"], "FAIL")
        sole = next(check for check in result["checks"]
                    if check["check"] == audit.CHECK_SOLE_AUTHORITY)
        self.assertIn("rogue DHCP OFFER", sole["details"][0])
        self.assertIn("blocked by switch", sole["details"][0])

    def test_server_frame_with_spoofed_gateway_label_fails(self):
        events = clean_run_events()
        events.insert(5, dhcp("ACK", "gateway", CT, WS))
        result = self.audit(events)
        self.assertEqual(
            self.verdicts(result)[audit.CHECK_SOLE_AUTHORITY], "FAIL")


class ControllerSilenceTests(AuditHelper):
    def test_any_controller_dhcp_frame_fails(self):
        events = clean_run_events()
        events.insert(5, dhcp("DISCOVER", "controller", CT, CT))
        result = self.audit(events)
        self.assertEqual(
            self.verdicts(result)[audit.CHECK_CONTROLLER_SILENCE], "FAIL")

    def test_absent_controller_is_not_provable(self):
        events = [event for event in clean_run_events()
                  if event.get("port") != "controller"]
        result = self.audit(events)
        check = next(check for check in result["checks"]
                     if check["check"] == audit.CHECK_CONTROLLER_SILENCE)
        self.assertEqual(check["verdict"], "NOT-PROVABLE")
        self.assertIn("never joined", check["missing"][0])


class FabricClosureTests(AuditHelper):
    def test_unknown_endpoint_egress_fails(self):
        events = clean_run_events()
        events[5] = dhcp("OFFER", "gateway", GW, WS,
                         delivered_to="intruder")
        result = self.audit(events)
        check = next(check for check in result["checks"]
                     if check["check"] == audit.CHECK_FABRIC_CLOSURE)
        self.assertEqual(check["verdict"], "FAIL")
        self.assertIn("'intruder'", check["details"][0])
        self.assertEqual(result["verdict"], "FAIL")

    def test_unknown_connected_endpoint_fails(self):
        events = clean_run_events()
        events.insert(4, connected("intruder", "52:54:00:99:99:99"))
        result = self.audit(events)
        self.assertEqual(
            self.verdicts(result)[audit.CHECK_FABRIC_CLOSURE], "FAIL")

    def test_spoofed_source_mac_fails_even_when_blocked(self):
        events = clean_run_events()
        events.insert(4, {"event": "source-mac-blocked",
                          "port": "workstation", "expected": WS,
                          "observed": "52:54:00:aa:bb:cc"})
        result = self.audit(events)
        self.assertEqual(
            self.verdicts(result)[audit.CHECK_FABRIC_CLOSURE], "FAIL")

    def test_missing_switch_ready_is_not_provable(self):
        events = clean_run_events()[1:]
        result = self.audit(events)
        check = next(check for check in result["checks"]
                     if check["check"] == audit.CHECK_FABRIC_CLOSURE)
        self.assertEqual(check["verdict"], "NOT-PROVABLE")
        self.assertIn("switch-ready", check["missing"][0])

    def test_wrong_fabric_enumeration_fails(self):
        events = clean_run_events()
        events[0] = {"event": "switch-ready", "ports": [
            {"port": "gateway", "mac": GW},
            {"port": "controller", "mac": CT},
        ]}
        result = self.audit(events)
        self.assertEqual(
            self.verdicts(result)[audit.CHECK_FABRIC_CLOSURE], "FAIL")


class ApprovedFlowTests(AuditHelper):
    def test_todays_logs_are_not_provable_with_exact_missing_field(self):
        result = self.audit(clean_run_events())
        check = next(check for check in result["checks"]
                     if check["check"] == audit.CHECK_APPROVED_FLOWS)
        self.assertEqual(check["verdict"], "NOT-PROVABLE")
        self.assertEqual(check["missing"],
                         [audit.MISSING_FLOW_FIELDS])

    def test_approved_flows_pass_once_recorded(self):
        events = clean_run_events()
        events.extend([
            flow("workstation", "controller", protocol=17,
                 src_port=2070, dst_port=69),
            flow("workstation", "controller", protocol=6,
                 src_port=49000, dst_port=80),
            flow("controller", "workstation", protocol=6,
                 src_port=80, dst_port=49000),
            flow("controller", "gateway", protocol=17,
                 src_port=40000, dst_port=53),
            flow("workstation", "controller", ethertype=0x0806),
            flow("workstation", "gateway", protocol=17,
                 src_port=68, dst_port=67),
        ])
        result = self.audit(events)
        verdicts = self.verdicts(result)
        self.assertEqual(verdicts[audit.CHECK_APPROVED_FLOWS], "PASS")
        self.assertEqual(result["verdict"], "PASS")

    def test_unapproved_flow_to_controller_fails(self):
        events = clean_run_events()
        events.append(flow("workstation", "controller", protocol=6,
                           src_port=49000, dst_port=9999))
        result = self.audit(events)
        self.assertEqual(
            self.verdicts(result)[audit.CHECK_APPROVED_FLOWS], "FAIL")

    def test_controller_dhcp_flow_fails(self):
        events = clean_run_events()
        events.append(flow("controller", "workstation", protocol=17,
                           src_port=67, dst_port=68))
        result = self.audit(events)
        check = next(check for check in result["checks"]
                     if check["check"] == audit.CHECK_APPROVED_FLOWS)
        self.assertEqual(check["verdict"], "FAIL")
        self.assertIn("DHCP/ProxyDHCP", check["details"][0])

    def test_identity_announcement_to_controller_is_approved(self):
        events = clean_run_events()
        events.append(flow("gateway", "controller", ethertype=0x88B5))
        result = self.audit(events)
        self.assertEqual(
            self.verdicts(result)[audit.CHECK_APPROVED_FLOWS], "PASS")

    def test_identity_announcement_from_controller_fails(self):
        events = clean_run_events()
        events.append(flow("controller", "workstation", ethertype=0x88B5))
        result = self.audit(events)
        self.assertEqual(
            self.verdicts(result)[audit.CHECK_APPROVED_FLOWS], "FAIL")

    def test_proxydhcp_port_4011_fails(self):
        events = clean_run_events()
        events.append(flow("workstation", "controller", protocol=17,
                           src_port=68, dst_port=4011))
        result = self.audit(events)
        self.assertEqual(
            self.verdicts(result)[audit.CHECK_APPROVED_FLOWS], "FAIL")


class RealisticFlowTests(AuditHelper):
    """The approved-flows check on the real AD DC + PXE service surface.

    These mirror the actual per-delivery flows recorded by real gate-7 arch
    and windows domain-join runs: AD services answered over both TCP and UDP,
    reply legs to ephemeral client ports, TFTP data transfers, the controller
    as a DNS/NTP/DHCP client of the gateway, RPC, NetBIOS, and ambient
    link-local traffic.  A clean run must PASS; a rogue must still FAIL.
    """

    def approved(self, *flows):
        events = clean_run_events()
        events.extend(flows)
        return self.verdicts(self.audit(events))[audit.CHECK_APPROVED_FLOWS]

    def test_ad_services_over_udp_are_approved(self):
        # CLDAP (389/udp) and Kerberos (88/udp) with their ephemeral replies.
        self.assertEqual("PASS", self.approved(
            flow("workstation", "controller", protocol=17,
                 src_port=41576, dst_port=389),
            flow("controller", "workstation", protocol=17,
                 src_port=389, dst_port=41576),
            flow("workstation", "controller", protocol=17,
                 src_port=37961, dst_port=88),
            flow("controller", "workstation", protocol=17,
                 src_port=88, dst_port=37961),
        ))

    def test_netbios_and_rpc_are_approved(self):
        self.assertEqual("PASS", self.approved(
            flow("controller", "workstation", protocol=17,
                 src_port=137, dst_port=137),           # NetBIOS name (nmbd)
            flow("workstation", "controller", protocol=6,
                 src_port=53032, dst_port=139),          # NetBIOS session
            flow("controller", "workstation", protocol=6,
                 src_port=139, dst_port=53032),
            flow("workstation", "controller", protocol=6,
                 src_port=61573, dst_port=135),          # RPC endpoint mapper
            flow("workstation", "controller", protocol=6,
                 src_port=61582, dst_port=49153),        # dynamic RPC endpoint
            flow("controller", "workstation", protocol=6,
                 src_port=49153, dst_port=61582),
        ))

    def test_controller_as_gateway_client_reply_is_approved(self):
        # The controller queries the gateway's resolver/clock; the reply lands
        # on the controller's ephemeral port and must not be a violation.
        self.assertEqual("PASS", self.approved(
            flow("controller", "gateway", protocol=17,
                 src_port=51192, dst_port=123),
            flow("gateway", "controller", protocol=17,
                 src_port=123, dst_port=51192),
            flow("controller", "gateway", protocol=17,
                 src_port=53132, dst_port=53),
            flow("gateway", "controller", protocol=17,
                 src_port=53, dst_port=53132),
        ))

    def test_controller_dhcp_client_lease_is_approved(self):
        # The controller acquiring its own lease from the gateway is a client,
        # not a competing authority.
        self.assertEqual("PASS", self.approved(
            flow("controller", "gateway", protocol=17,
                 src_port=68, dst_port=67),
            flow("gateway", "controller", protocol=17,
                 src_port=67, dst_port=68),
        ))

    def test_controller_serving_dhcp_still_fails(self):
        # But the controller sourcing the server port is a rogue authority.
        result = self.approved(
            flow("controller", "workstation", protocol=17,
                 src_port=67, dst_port=68))
        self.assertEqual("FAIL", result)

    def test_tftp_data_phase_is_approved_when_correlated(self):
        self.assertEqual("PASS", self.approved(
            flow("workstation", "controller", protocol=17,
                 src_port=1308, dst_port=69),            # read request
            flow("controller", "workstation", protocol=17,
                 src_port=51132, dst_port=1308),         # data (server TID)
            flow("workstation", "controller", protocol=17,
                 src_port=1308, dst_port=51132),         # ack
        ))

    def test_uncorrelated_ephemeral_pair_to_controller_fails(self):
        # The same ephemeral-to-ephemeral shape without a preceding TFTP read
        # request is not an approved transfer.
        self.assertEqual("FAIL", self.approved(
            flow("controller", "workstation", protocol=17,
                 src_port=51132, dst_port=1308)))

    def test_ambient_link_local_traffic_is_approved(self):
        self.assertEqual("PASS", self.approved(
            flow("controller", "workstation", ethertype=0x86DD),   # IPv6 ND
            flow("workstation", "controller", ethertype=0x888E),   # EAPOL
            flow("workstation", "controller", protocol=1),          # ICMP
            flow("workstation", "controller", protocol=2),          # IGMP
            flow("workstation", "controller", protocol=17,
                 src_port=49418, dst_port=5355),                     # LLMNR
            flow("workstation", "controller", protocol=17,
                 src_port=5353, dst_port=5353),                      # mDNS
            flow("workstation", "controller", protocol=17,
                 src_port=59646, dst_port=1900),                     # SSDP
        ))

    def test_controller_egress_to_unapproved_service_fails(self):
        # A controller reaching out to the workstation on a non-service port
        # (a backdoor client) is a violation even though it stays in-fabric.
        result = self.approved(
            flow("controller", "workstation", protocol=6,
                 src_port=40000, dst_port=4444))
        self.assertEqual("FAIL", result)

    def test_inbound_unapproved_high_port_still_fails(self):
        self.assertEqual("FAIL", self.approved(
            flow("workstation", "controller", protocol=6,
                 src_port=49000, dst_port=31337)))


class EvidenceQualityTests(AuditHelper):
    def test_malformed_json_line_is_refused(self):
        path = self.write_log(
            None, raw='{"event": "switch-ready", "ports": []}\nnot json\n')
        with self.assertRaises(audit.EvidenceFormatError):
            audit.audit_paths([path], audit.factory_topology())

    def test_event_without_name_is_refused(self):
        path = self.write_log(None, raw='{"kind": "OFFER"}\n')
        with self.assertRaises(audit.EvidenceFormatError):
            audit.audit_paths([path], audit.factory_topology())

    def test_dhcp_event_missing_required_field_is_refused(self):
        path = self.write_log([{"event": "dhcp", "kind": "OFFER"}])
        with self.assertRaises(audit.EvidenceFormatError):
            audit.audit_paths([path], audit.factory_topology())

    def test_empty_log_is_refused(self):
        path = self.write_log(None, raw="")
        with self.assertRaises(audit.EvidenceFormatError):
            audit.audit_paths([path], audit.factory_topology())

    def test_evidence_limit_poisons_absence_claims(self):
        events = clean_run_events()
        events.append({"event": "evidence-limit", "omitted": 5})
        result = self.audit(events)
        verdicts = self.verdicts(result)
        self.assertTrue(result["evidence_limited"])
        for check in (audit.CHECK_SOLE_AUTHORITY,
                      audit.CHECK_CONTROLLER_SILENCE,
                      audit.CHECK_FABRIC_CLOSURE):
            self.assertEqual(verdicts[check], "NOT-PROVABLE")

    def test_rogue_offer_still_fails_under_evidence_limit(self):
        events = clean_run_events()
        events.append(dhcp("OFFER", "controller", CT, WS, blocked=True))
        events.append({"event": "evidence-limit", "omitted": 5})
        result = self.audit(events)
        self.assertEqual(
            self.verdicts(result)[audit.CHECK_SOLE_AUTHORITY], "FAIL")


class TopologyTests(unittest.TestCase):
    def test_factory_topology_matches_factory_runner_switch_command(self):
        command = factory_runner.switch_command(0, Path("unused"))
        bound = {}
        for index, item in enumerate(command):
            if item == "--port":
                name, mac = command[index + 1].split("=", 1)
                bound[name] = mac.lower()
        self.assertEqual(bound, audit.factory_topology().by_name)

    def test_gateway_endpoint_must_be_named_gateway(self):
        with self.assertRaises(audit.TopologyError):
            audit.make_topology(
                {"gw": GW, "controller": CT}, "gw", "controller")

    def test_duplicate_macs_are_refused(self):
        with self.assertRaises(audit.TopologyError):
            audit.make_topology(
                {"gateway": GW, "controller": GW}, "gateway", "controller")

    def test_invalid_mac_is_refused(self):
        with self.assertRaises(audit.TopologyError):
            audit.make_topology(
                {"gateway": "zz:54:00:31:11:01", "controller": CT},
                "gateway", "controller")


class CommandLineTests(AuditHelper):
    def run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = audit.main(argv)
        return code, stdout.getvalue()

    def test_cli_renders_verdicts_and_result_json(self):
        path = self.write_log(clean_run_events())
        json_path = self.root / "result.json"
        code, output = self.run_cli(
            ["audit", str(path), "--json", str(json_path)])
        self.assertEqual(code, 3)
        self.assertIn("PASS         gate4.dhcp-sole-authority", output)
        self.assertIn(
            "NOT-PROVABLE gate4.controller-approved-flows-only", output)
        self.assertIn("VERDICT NOT-PROVABLE workstation-factory-gate-4",
                      output)
        result = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(result["gate"], "workstation-factory-gate-4")
        self.assertEqual(result["verdict"], "NOT-PROVABLE")

    def test_cli_fail_exit_code(self):
        events = clean_run_events()
        events.append(dhcp("OFFER", "controller", CT, WS))
        path = self.write_log(events)
        code, output = self.run_cli(["audit", str(path)])
        self.assertEqual(code, 1)
        self.assertIn("FAIL", output)

    def test_cli_pass_exit_code_requires_flow_evidence(self):
        events = clean_run_events()
        events.append(flow("workstation", "controller", protocol=17,
                           src_port=2070, dst_port=69))
        path = self.write_log(events)
        code, output = self.run_cli(["audit", str(path)])
        self.assertEqual(code, 0)
        self.assertIn("VERDICT PASS", output)

    def test_cli_refuses_malformed_evidence(self):
        path = self.write_log(None, raw="garbage\n")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code, _output = self.run_cli(["audit", str(path)])
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", stderr.getvalue())

    def test_cli_accepts_explicit_topology(self):
        topology_path = self.root / "topology.json"
        topology_path.write_text(json.dumps({
            "endpoints": {"gateway": GW, "controller": CT,
                          "workstation": WS},
            "gateway": "gateway", "controller": "controller",
        }), encoding="utf-8")
        path = self.write_log(clean_run_events())
        code, _output = self.run_cli(
            ["audit", str(path), "--topology", str(topology_path)])
        self.assertEqual(code, 3)

    def test_cli_merges_multiple_logs(self):
        first = self.write_log(clean_run_events(), name="one.jsonl")
        second = self.write_log(
            [dhcp("OFFER", "controller", CT, WS)], name="two.jsonl")
        code, output = self.run_cli(["audit", str(first), str(second)])
        self.assertEqual(code, 1)
        self.assertIn("two.jsonl:1", output)


if __name__ == "__main__":
    unittest.main()
