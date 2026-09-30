"""Tests for simulation host-network evidence and invariants."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# factory_verify is imported the way its own tests import it, so check 9 is
# exercised through the real verifier rather than a re-implementation.
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "vm"))

from vm import host_network_evidence as evidence  # noqa: E402
import factory_verify  # noqa: E402


def fixture(socket_lines: str = "") -> dict[str, object]:
    observations = []
    for command in evidence.COMMANDS:
        observations.append({
            "command": list(command),
            "returncode": 0,
            "stdout": socket_lines if command[0] == "ss" else "stable",
            "stderr": "",
        })
    return {"schema": 1, "captured_at": "ignored", "observations": observations}


class HostNetworkEvidenceTests(unittest.TestCase):
    def test_identical_snapshots_pass(self):
        self.assertEqual(evidence.compare(fixture(), fixture()), [])

    def test_in_memory_capture_tuple_commands_are_valid(self):
        captured = fixture()
        for item in captured["observations"]:
            item["command"] = tuple(item["command"])
        self.assertEqual(evidence.compare(captured, copy.deepcopy(captured)), [])

    def test_matching_failed_commands_do_not_pass(self):
        before = fixture()
        after = fixture()
        for snapshot in (before, after):
            snapshot["observations"][0]["returncode"] = 127
            snapshot["observations"][0]["stderr"] = "ip: command not found"
        violations = evidence.compare(before, after)
        self.assertTrue(any("command failed" in item for item in violations))

    def test_matching_unsupported_nft_is_recorded_but_not_overclaimed(self):
        before = fixture()
        after = fixture()
        for snapshot in (before, after):
            nft = next(
                item for item in snapshot["observations"]
                if tuple(item["command"])
                == ("nft", "-j", "--stateless", "list", "ruleset"))
            nft["returncode"] = 3
            nft["stdout"] = ""
            nft["stderr"] = evidence.NFT_UNAVAILABLE
        self.assertEqual(evidence.compare(before, after), [])

    def test_only_the_exact_unsupported_nft_failure_is_tolerated(self):
        mutations = (
            ("returncode", 1),
            ("stdout", "{}"),
            ("stderr", evidence.NFT_UNAVAILABLE + "\n"),
            ("stderr", "Operation not permitted"),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                before = fixture()
                after = fixture()
                for snapshot in (before, after):
                    nft = next(
                        item for item in snapshot["observations"]
                        if tuple(item["command"])
                        == ("nft", "-j", "--stateless", "list", "ruleset"))
                    nft.update({
                        "returncode": 3,
                        "stdout": "",
                        "stderr": evidence.NFT_UNAVAILABLE,
                    })
                    nft[field] = value
                violations = evidence.compare(before, after)
                self.assertTrue(
                    any("command failed" in item for item in violations),
                    violations,
                )

    def test_address_lease_countdown_does_not_claim_host_change(self):
        before = fixture()
        after = fixture()
        command = ("ip", "-j", "address", "show")
        for snapshot, lifetime in ((before, 100), (after, 97)):
            address = next(
                item for item in snapshot["observations"]
                if tuple(item["command"]) == command)
            address["stdout"] = json.dumps([{
                "ifname": "eno1",
                "addr_info": [{
                    "family": "inet",
                    "local": "10.1.31.123",
                    "valid_life_time": lifetime,
                    "preferred_life_time": lifetime,
                }],
            }])
        self.assertEqual(evidence.compare(before, after), [])

    def test_address_identity_change_is_detected_despite_lease_countdown(self):
        before = fixture()
        after = fixture()
        command = ("ip", "-j", "address", "show")
        for snapshot, address_value, lifetime in (
                (before, "10.1.31.123", 100),
                (after, "10.1.31.124", 97)):
            address = next(
                item for item in snapshot["observations"]
                if tuple(item["command"]) == command)
            address["stdout"] = json.dumps([{
                "ifname": "eno1",
                "addr_info": [{
                    "family": "inet",
                    "local": address_value,
                    "valid_life_time": lifetime,
                    "preferred_life_time": lifetime,
                }],
            }])
        self.assertTrue(evidence.compare(before, after))

    def test_missing_required_command_does_not_pass(self):
        before = fixture()
        del before["observations"][0]
        violations = evidence.compare(before, fixture())
        self.assertTrue(any("missing command" in item for item in violations))

    def test_duplicate_command_does_not_pass(self):
        before = fixture()
        before["observations"].append(copy.deepcopy(before["observations"][0]))
        self.assertTrue(any(
            "duplicate commands" in item
            for item in evidence.compare(before, fixture())))

    def test_every_non_socket_surface_is_immutable(self):
        before = fixture()
        for index, command in enumerate(evidence.COMMANDS[:-1]):
            with self.subTest(command=command):
                after = copy.deepcopy(before)
                after["observations"][index]["stdout"] = "changed"
                self.assertTrue(evidence.compare(before, after))

    def test_permits_only_named_private_qemu_listeners_during_run(self):
        before = fixture()
        after = fixture(
            "tcp LISTEN 0 1 127.0.0.1:12971 0.0.0.0:* users:qemu\n"
            "tcp LISTEN 0 1 127.0.0.1:12972 0.0.0.0:* users:qemu")
        self.assertEqual(
            evidence.compare(
                before, after, allow_qemu_listeners=True,
                allowed_ports=frozenset({12971, 12972})), [])

    def test_requires_exact_dynamic_listener_set(self):
        before = fixture()
        during = fixture(
            "tcp LISTEN 0 1 127.0.0.1:43127 0.0.0.0:* users:python")
        self.assertEqual(evidence.compare(
            before, during, allow_qemu_listeners=True,
            allowed_ports=frozenset({43127})), [])
        violations = evidence.compare(
            before, during, allow_qemu_listeners=True,
            allowed_ports=frozenset({43127, 43128}))
        self.assertTrue(any("listener set did not match" in item
                            for item in violations))
        duplicate_port = fixture(
            "tcp LISTEN 0 1 127.0.0.1:43127 0.0.0.0:* users:python\n"
            "tcp LISTEN 0 1 [::ffff:127.0.0.1]:43127 [::]:* users:python")
        self.assertTrue(evidence.compare(
            before, duplicate_port, allow_qemu_listeners=True,
            allowed_ports=frozenset({43127})))

    def test_rejects_wildcard_wrong_port_and_udp(self):
        before = fixture()
        lines = (
            "tcp LISTEN 0 1 0.0.0.0:12971 0.0.0.0:*\n"
            "tcp LISTEN 0 1 127.0.0.1:12973 0.0.0.0:*\n"
            "udp UNCONN 0 0 127.0.0.1:12971 0.0.0.0:*")
        self.assertTrue(evidence.compare(
            before, fixture(lines), allow_qemu_listeners=True))

    def test_rejects_removed_preexisting_socket(self):
        before = fixture("tcp LISTEN 0 1 127.0.0.1:22 0.0.0.0:*")
        self.assertTrue(evidence.compare(
            before, fixture(), allow_qemu_listeners=True))

    def test_socket_column_alignment_is_not_a_state_change(self):
        before = fixture("tcp LISTEN 0      128    0.0.0.0:22 0.0.0.0:*")
        after = fixture("tcp LISTEN 0 128 0.0.0.0:22    0.0.0.0:*")
        self.assertEqual(evidence.compare(before, after), [])

    def test_cycle_requires_complete_cleanup(self):
        before = fixture()
        during = fixture(
            "tcp LISTEN 0 1 127.0.0.1:12971 0.0.0.0:* users:qemu")
        ports = frozenset({12971})
        self.assertEqual(evidence.compare_cycle(
            before, during, fixture(), allowed_ports=ports), [])
        violations = evidence.compare_cycle(
            before, during, during, allowed_ports=ports)
        self.assertTrue(any(item.startswith("after simulation:") for item in violations))

    def test_written_evidence_is_private(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "evidence.json"
            evidence.write(fixture(), target)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)
            self.assertIn('"schema": 1', target.read_text())

    def test_evidence_writer_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            victim = root / "victim"
            victim.write_text("keep")
            target = root / "evidence.json"
            target.symlink_to(victim)
            with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                evidence.write(fixture(), target)
            self.assertEqual(victim.read_text(), "keep")


# ---------------------------------------------------------------------------
# Gate-12 change counters
# ---------------------------------------------------------------------------
#
# Every fixture below is synthetic.  Nothing here reads host state, and the
# names and addresses are deliberately fictional (TEST-NET-1, 192.0.2.0/24)
# so that no real network identifier exists to leak in the first place.

LOOPBACK = {"ifindex": 1, "ifname": "fixture-lo", "link_type": "loopback"}
UPLINK = {"ifindex": 2, "ifname": "fixture-uplink", "link_type": "ether",
          "linkinfo": {"info_kind": "veth"}}
TAP = {"ifindex": 9, "ifname": "fixture-tap", "link_type": "ether",
       "linkinfo": {"info_kind": "tun", "info_data": {"type": "tap"}}}
BRIDGE = {"ifindex": 10, "ifname": "fixture-br", "link_type": "ether",
          "linkinfo": {"info_kind": "bridge"}}
VLAN = {"ifindex": 11, "ifname": "fixture-vl", "link_type": "ether",
        "linkinfo": {"info_kind": "vlan", "info_data": {"id": 42}}}

BASE_LINKS = [LOOPBACK, UPLINK]
BASE_ADDRESSES = [{
    "ifname": "fixture-uplink",
    "addr_info": [{"family": "inet", "local": "192.0.2.10", "prefixlen": 24,
                   "valid_life_time": 100, "preferred_life_time": 100}],
}]
BASE_ROUTES = [{"dst": "default", "gateway": "192.0.2.1",
                "dev": "fixture-uplink"}]
BASE_RULESET = {"nftables": [{"metainfo": {"version": "fixture"}}]}
BASE_SOCKETS = "tcp LISTEN 0 128 192.0.2.10:22 0.0.0.0:*"

SURFACES = {
    "link": (evidence.LINK_COMMAND, lambda: json.dumps(BASE_LINKS)),
    "address": (evidence.ADDRESS_COMMAND, lambda: json.dumps(BASE_ADDRESSES)),
    "route4": (evidence.ROUTE4_COMMAND, lambda: json.dumps(BASE_ROUTES)),
    "route6": (evidence.ROUTE6_COMMAND, lambda: json.dumps([])),
    "bridge_link": (evidence.BRIDGE_LINK_COMMAND, lambda: json.dumps([])),
    "bridge_vlan": (evidence.BRIDGE_VLAN_COMMAND, lambda: json.dumps([])),
    "netns": (evidence.NETNS_COMMAND, lambda: ""),
    "nft": (evidence.NFT_COMMAND, lambda: json.dumps(BASE_RULESET)),
    "sockets": (evidence.SOCKET_COMMAND, lambda: BASE_SOCKETS),
}

UNIFI = evidence.unifi_no_contact(
    audited_processes=3, auditor="fixture-argv-audit",
    egress_contacts=0, egress_observation="fixture-egress-ledger")


def snapshot(**overrides) -> dict[str, object]:
    """A well-formed, fully successful capture with per-surface overrides.

    Each keyword is a surface name from ``SURFACES``; a string replaces that
    command's stdout, a mapping replaces whole observation fields.
    """
    unknown = set(overrides) - set(SURFACES)
    assert not unknown, unknown
    observations = []
    for name, (command, default) in SURFACES.items():
        item = {"command": list(command), "returncode": 0,
                "stdout": default(), "stderr": ""}
        override = overrides.get(name)
        if isinstance(override, str):
            item["stdout"] = override
        elif isinstance(override, dict):
            item.update(override)
        observations.append(item)
    return {"schema": 1, "captured_at": "fixture", "observations": observations}


def links(*extra) -> str:
    return json.dumps(BASE_LINKS + list(extra))


#: What ``change_counters`` returns for an unchanged host proven by snapshots.
ZERO = dict({name: 0 for name in evidence.CATEGORIES},
            basis={"forwarding": evidence.BASIS_SNAPSHOT})


class ChangeCounterTests(unittest.TestCase):
    def counters(self, before, after, **kwargs):
        kwargs.setdefault("unifi", UNIFI)
        return evidence.change_counters(before, after, **kwargs)

    def test_identical_snapshots_yield_all_zero_counters(self):
        counters = self.counters(snapshot(), snapshot())
        self.assertEqual(counters, ZERO)
        self.assertEqual(
            sorted(counters),
            sorted(["tap", "bridge", "route", "vlan", "forwarding",
                    "listener", "unifi", "basis"]))

    def test_a_created_tap_is_counted(self):
        counters = self.counters(snapshot(), snapshot(link=links(TAP)))
        self.assertEqual(counters["tap"], 1)
        self.assertEqual(counters["bridge"], 0)

    def test_a_created_bridge_is_counted(self):
        counters = self.counters(snapshot(), snapshot(link=links(BRIDGE)))
        self.assertEqual(counters["bridge"], 1)

    def test_an_enslaved_bridge_port_is_counted(self):
        after = snapshot(bridge_link=json.dumps(
            [{"ifname": "fixture-tap", "master": "fixture-br",
              "state": "forwarding"}]))
        self.assertEqual(self.counters(snapshot(), after)["bridge"], 1)

    def test_a_created_vlan_link_is_counted(self):
        self.assertEqual(
            self.counters(snapshot(), snapshot(link=links(VLAN)))["vlan"], 1)

    def test_a_created_bridge_vlan_entry_is_counted(self):
        after = snapshot(bridge_vlan=json.dumps(
            [{"ifname": "fixture-br", "vlans": [{"vlan": 42}]}]))
        self.assertEqual(self.counters(snapshot(), after)["vlan"], 1)

    def test_an_added_route_is_counted_on_both_families(self):
        cases = {
            "route4": json.dumps(
                BASE_ROUTES + [{"dst": "198.51.100.0/24",
                                "dev": "fixture-tap"}]),
            "route6": json.dumps([{"dst": "2001:db8::/64",
                                   "dev": "fixture-tap"}]),
        }
        for surface, value in cases.items():
            with self.subTest(surface=surface):
                counters = self.counters(
                    snapshot(), snapshot(**{surface: value}))
                self.assertEqual(counters["route"], 1)
                self.assertEqual(counters["tap"], 0)

    def test_a_forwarding_ruleset_change_is_counted(self):
        after = snapshot(nft=json.dumps({"nftables": BASE_RULESET["nftables"] + [
            {"rule": {"chain": "forward", "expr": [{"accept": None}]}}]}))
        self.assertEqual(self.counters(snapshot(), after)["forwarding"], 1)

    def test_a_listener_left_behind_is_counted(self):
        after = snapshot(
            sockets=BASE_SOCKETS + "\ntcp LISTEN 0 1 192.0.2.10:8443 0.0.0.0:*")
        self.assertEqual(self.counters(snapshot(), after)["listener"], 1)

    def test_a_disappearing_preexisting_listener_is_counted(self):
        self.assertEqual(
            self.counters(snapshot(), snapshot(sockets=""))["listener"], 1)

    def test_a_recorded_unifi_contact_is_counted(self):
        observation = evidence.unifi_no_contact(
            audited_processes=1, auditor="fixture-argv-audit",
            egress_contacts=2, egress_observation="fixture-egress-ledger")
        counters = self.counters(snapshot(), snapshot(), unifi=observation)
        self.assertEqual(counters["unifi"], 2)


class AttributionRuleTests(unittest.TestCase):
    """Pre-existing state is not a change; anything the run did is."""

    def test_preexisting_host_topology_is_never_a_change(self):
        # A host that already runs its own tap, bridge, VLAN, extra route and
        # listener before the run, unchanged throughout, costs nothing.
        busy = dict(
            link=links(TAP, BRIDGE, VLAN),
            route4=json.dumps(BASE_ROUTES + [{"dst": "198.51.100.0/24",
                                              "dev": "fixture-br"}]),
            bridge_link=json.dumps([{"ifname": "fixture-tap",
                                     "master": "fixture-br"}]),
            sockets=BASE_SOCKETS + "\ntcp LISTEN 0 1 192.0.2.10:8443 0.0.0.0:*",
        )
        counters = evidence.change_counters(
            snapshot(**busy), snapshot(**busy),
            during=snapshot(**busy), unifi=UNIFI)
        self.assertEqual(counters, ZERO)

    def test_an_object_created_and_torn_down_inside_the_run_is_counted(self):
        counters = evidence.change_counters(
            snapshot(), snapshot(), during=snapshot(link=links(TAP)),
            unifi=UNIFI)
        self.assertEqual(counters["tap"], 1)

    def test_a_transient_object_is_invisible_without_the_live_snapshot(self):
        # The same cycle judged from its endpoints alone: documented, and the
        # reason the live snapshot should always be supplied.
        counters = evidence.change_counters(
            snapshot(), snapshot(), unifi=UNIFI)
        self.assertEqual(counters["tap"], 0)

    def test_the_runs_own_loopback_control_listeners_are_exempt(self):
        during = snapshot(
            sockets=BASE_SOCKETS
            + "\ntcp LISTEN 0 1 127.0.0.1:12971 0.0.0.0:* users:qemu")
        counters = evidence.change_counters(
            snapshot(), snapshot(), during=during,
            allowed_ports=frozenset({12971}), unifi=UNIFI)
        self.assertEqual(counters["listener"], 0)

    def test_an_unexempted_transient_listener_is_counted(self):
        during = snapshot(
            sockets=BASE_SOCKETS
            + "\ntcp LISTEN 0 1 192.0.2.10:12971 0.0.0.0:* users:qemu")
        counters = evidence.change_counters(
            snapshot(), snapshot(), during=during,
            allowed_ports=frozenset({12971}), unifi=UNIFI)
        self.assertEqual(counters["listener"], 1)

    def test_an_address_change_is_attributed_to_its_interface_kind(self):
        base = dict(link=links(TAP))
        after = dict(
            base,
            address=json.dumps(BASE_ADDRESSES + [{
                "ifname": "fixture-tap",
                "addr_info": [{"family": "inet", "local": "198.51.100.1",
                               "prefixlen": 24}]}]))
        counters = evidence.change_counters(
            snapshot(**base), snapshot(**after), unifi=UNIFI)
        self.assertEqual(counters["tap"], 1)
        self.assertEqual(counters["route"], 0)

    def test_a_lease_countdown_is_not_a_change(self):
        renewed = json.dumps([{
            "ifname": "fixture-uplink",
            "addr_info": [{"family": "inet", "local": "192.0.2.10",
                           "prefixlen": 24, "valid_life_time": 41,
                           "preferred_life_time": 41}]}])
        counters = evidence.change_counters(
            snapshot(), snapshot(address=renewed), unifi=UNIFI)
        self.assertEqual(counters, ZERO)


class FailClosedTests(unittest.TestCase):
    """Nothing unobserved, unreadable, or unattributable becomes a zero."""

    def assertUnproven(self, *expected, **kwargs):
        report = evidence.classify(**kwargs)
        self.assertFalse(report["proven"], report)
        for name in expected:
            self.assertEqual(report["counters"][name], evidence.UNPROVEN,
                             report)
            self.assertIn(name, report["unproven"], report)
            self.assertTrue(report["reasons"][name])
        with self.assertRaises(evidence.UnprovenCategory) as raised:
            evidence.change_counters(**kwargs)
        for name in expected:
            self.assertIn(name, raised.exception.reasons)
        return report

    def test_a_failed_observation_does_not_yield_zero(self):
        broken = snapshot(link={"returncode": 1, "stdout": "",
                                "stderr": "fixture failure"})
        self.assertUnproven(
            "tap", "bridge", "vlan", before=snapshot(), after=broken,
            unifi=UNIFI)

    def test_a_missing_snapshot_does_not_yield_zero(self):
        # Every category the snapshots prove; ``unifi`` is proven separately
        # by its own observation and is unaffected.
        snapshot_derived = [
            name for name in evidence.CATEGORIES if name != "unifi"]
        report = self.assertUnproven(
            *snapshot_derived, before={}, after=snapshot(), unifi=UNIFI)
        self.assertEqual(report["unproven"], sorted(snapshot_derived))

    def test_a_missing_command_does_not_yield_zero(self):
        incomplete = snapshot()
        incomplete["observations"] = [
            item for item in incomplete["observations"]
            if tuple(item["command"]) != evidence.ROUTE4_COMMAND]
        self.assertUnproven(
            "route", before=incomplete, after=snapshot(), unifi=UNIFI)

    def test_a_duplicated_command_does_not_yield_zero(self):
        duplicated = snapshot()
        duplicated["observations"].append(
            copy.deepcopy(duplicated["observations"][0]))
        self.assertUnproven(
            "tap", "bridge", "vlan", before=duplicated, after=snapshot(),
            unifi=UNIFI)

    def test_unparseable_output_does_not_yield_zero(self):
        self.assertUnproven(
            "route", before=snapshot(), after=snapshot(route4="not json"),
            unifi=UNIFI)

    def test_an_unattributable_link_change_does_not_yield_zero(self):
        # A veth is a real host network change and is none of the seven
        # categories, so the categories the link surface proves go unproven
        # instead of quietly counting nothing.
        added = {"ifindex": 12, "ifname": "fixture-veth",
                 "link_type": "ether", "linkinfo": {"info_kind": "veth"}}
        self.assertUnproven(
            "tap", "bridge", "vlan", before=snapshot(),
            after=snapshot(link=links(added)), unifi=UNIFI)

    def test_an_unavailable_ruleset_leaves_forwarding_unproven(self):
        unavailable = {"returncode": 3, "stdout": "",
                       "stderr": evidence.NFT_UNAVAILABLE}
        before = snapshot(nft=unavailable)
        after = snapshot(nft=unavailable)
        # compare() tolerates this exact failure as "no observable change";
        # counting is stricter, because an unreadable ruleset is not a proof
        # that the ruleset did not change.
        self.assertEqual(evidence.compare(before, after), [])
        self.assertUnproven("forwarding", before=before, after=after,
                            unifi=UNIFI)

    def test_a_namespace_change_leaves_the_topology_categories_unproven(self):
        after = snapshot(netns="fixture-namespace (id: 0)")
        self.assertUnproven(
            "tap", "bridge", "route", "vlan", "forwarding",
            before=snapshot(), after=after, unifi=UNIFI)

    def test_an_address_change_on_an_unmapped_interface_is_unproven(self):
        moved = json.dumps([{
            "ifname": "fixture-uplink",
            "addr_info": [{"family": "inet", "local": "192.0.2.11",
                           "prefixlen": 24}]}])
        self.assertUnproven(
            "tap", "bridge", "vlan", "route", before=snapshot(),
            after=snapshot(address=moved), unifi=UNIFI)

    def test_a_failed_socket_observation_does_not_yield_zero(self):
        broken = snapshot(sockets={"returncode": 127, "stdout": "",
                                   "stderr": "fixture failure"})
        self.assertUnproven(
            "listener", before=snapshot(), after=broken, unifi=UNIFI)


class UnifiObservationTests(unittest.TestCase):
    """COMMANDS observes no UniFi surface, so the zero must be supplied."""

    def test_unifi_is_unproven_without_an_explicit_observation(self):
        report = evidence.classify(snapshot(), snapshot())
        self.assertEqual(report["unproven"], ["unifi"])
        self.assertEqual(report["counters"]["unifi"], evidence.UNPROVEN)
        # Every other category is still an honest integer zero.
        for name in evidence.CATEGORIES:
            if name != "unifi":
                self.assertEqual(report["counters"][name], 0, report)
        with self.assertRaises(evidence.UnprovenCategory):
            evidence.change_counters(snapshot(), snapshot())

    def test_a_supplied_observation_proves_the_zero(self):
        counters = evidence.change_counters(
            snapshot(), snapshot(), unifi=UNIFI)
        self.assertEqual(counters["unifi"], 0)

    def test_a_partial_observation_is_unproven(self):
        cases = {
            "wrong schema": dict(UNIFI, schema=2),
            "no guest audit": {k: v for k, v in UNIFI.items()
                               if k != "guest_isolation_audit"},
            "no host egress": {k: v for k, v in UNIFI.items()
                               if k != "host_egress"},
            "empty guest audit": dict(
                UNIFI, guest_isolation_audit={"audited_processes": 0,
                                              "auditor": "fixture"}),
            "unnamed auditor": dict(
                UNIFI, guest_isolation_audit={"audited_processes": 1,
                                              "auditor": "  "}),
            "unnamed egress observation": dict(
                UNIFI, host_egress={"contacts": 0, "observation": ""}),
            "non-integer contacts": dict(
                UNIFI, host_egress={"contacts": "0",
                                    "observation": "fixture"}),
            "boolean contacts": dict(
                UNIFI, host_egress={"contacts": False,
                                    "observation": "fixture"}),
            "not a mapping": "no UniFi contact, honest",
        }
        for label, observation in cases.items():
            with self.subTest(case=label):
                report = evidence.classify(
                    snapshot(), snapshot(), unifi=observation)
                self.assertEqual(report["counters"]["unifi"],
                                 evidence.UNPROVEN)

    def test_the_builder_refuses_an_observation_that_observed_nothing(self):
        cases = (
            dict(audited_processes=0, auditor="a", egress_contacts=0,
                 egress_observation="b"),
            dict(audited_processes=1, auditor="", egress_contacts=0,
                 egress_observation="b"),
            dict(audited_processes=1, auditor="a", egress_contacts=-1,
                 egress_observation="b"),
            dict(audited_processes=1, auditor="a", egress_contacts=0,
                 egress_observation="   "),
            dict(audited_processes=True, auditor="a", egress_contacts=0,
                 egress_observation="b"),
        )
        for arguments in cases:
            with self.subTest(**arguments):
                with self.assertRaises(ValueError):
                    evidence.unifi_no_contact(**arguments)


# ---------------------------------------------------------------------------
# The forwarding counter's privilege basis
# ---------------------------------------------------------------------------
#
# Every fact below comes from an injected reader.  Nothing reads this host's
# /proc: a test that did would pass or fail with the shell it ran in.

#: ``/proc/self/status`` of an unprivileged, NoNewPrivs process, as the
#: kernel prints it.  CapBnd is full and CapInh is set on purpose: neither is
#: part of the proof, and a test pins that they are ignored.
STATUS_FIELDS = {
    "Name": "fixture-driver",
    "Uid": "1000\t1000\t1000\t1000",
    "Gid": "1000\t1000\t1000\t1000",
    "CapInh": "0000000000000000",
    "CapPrm": "0000000000000000",
    "CapEff": "0000000000000000",
    "CapBnd": "000001ffffffffff",
    "CapAmb": "0000000000000000",
    "NoNewPrivs": "1",
    "Seccomp": "0",
}
SYSCTLS = {path: "0" for path in evidence.FORWARDING_SYSCTLS}
IP_FORWARD = evidence.FORWARDING_SYSCTLS[0]

#: What an unprivileged ``nft -j --stateless list ruleset`` prints.
UNREADABLE_RULESET = {
    "returncode": 1, "stdout": "",
    "stderr": "netlink: Error: cache initialization failed: Operation not "
              "permitted\nError: Operation not permitted (perhaps you must "
              "be root?)"}

NET_ADMIN = f"{1 << 12:016x}"
SYS_ADMIN = f"{1 << 21:016x}"
FULL = "000001ffffffffff"


def host_files(status=None, sysctls=None, *, unreadable=()):
    """A fake reader over a fabricated /proc; ``None`` drops a status line."""
    fields = dict(STATUS_FIELDS, **(status or {}))
    files = {evidence.PROC_STATUS: "".join(
        f"{name}:\t{value}\n" for name, value in fields.items()
        if value is not None)}
    for path, value in dict(SYSCTLS, **(sysctls or {})).items():
        files[path] = value + "\n"
    for path in unreadable:
        files.pop(path, None)
    return files.get


def unprivileged(status=None, sysctls=None, *, unreadable=(),
                 nft=UNREADABLE_RULESET, **overrides):
    """A capture by the unprivileged, NoNewPrivs factory: nft unreadable."""
    captured = snapshot(nft=nft, **overrides)
    captured["privilege"] = evidence.privilege_facts(
        host_files(status, sysctls, unreadable=unreadable))
    return captured


class PrivilegeFactsTests(unittest.TestCase):
    """What ``capture`` records: raw kernel text, judged only later."""

    def test_the_facts_are_read_through_the_injected_reader(self):
        facts = evidence.privilege_facts(host_files())
        self.assertEqual(evidence.PRIVILEGE_SCHEMA, facts["schema"])
        self.assertEqual(
            {"NoNewPrivs": "1", "Uid": "1000\t1000\t1000\t1000",
             "CapEff": "0" * 16, "CapPrm": "0" * 16, "CapAmb": "0" * 16},
            facts["status"])
        self.assertEqual(SYSCTLS, facts["sysctls"])
        # The sets the proof deliberately ignores are not even recorded.
        self.assertNotIn("CapBnd", facts["status"])
        self.assertNotIn("CapInh", facts["status"])

    def test_the_default_reader_is_this_processs_own_status(self):
        self.assertEqual("/proc/self/status", evidence.PROC_STATUS)
        self.assertEqual(
            ("/proc/sys/net/ipv4/ip_forward",
             "/proc/sys/net/ipv6/conf/all/forwarding",
             "/proc/sys/net/ipv6/conf/default/forwarding"),
            evidence.FORWARDING_SYSCTLS)
        self.assertEqual({"CAP_NET_ADMIN": 12, "CAP_SYS_ADMIN": 21},
                         evidence.FORBIDDEN_CAPABILITIES)

    def test_an_unreadable_status_records_no_fact(self):
        facts = evidence.privilege_facts(
            host_files(unreadable=(evidence.PROC_STATUS,)))
        self.assertEqual(
            {name: None for name in evidence.PRIVILEGE_FIELDS},
            facts["status"])
        self.assertEqual(SYSCTLS, facts["sysctls"])

    def test_an_unreadable_sysctl_is_recorded_as_none(self):
        facts = evidence.privilege_facts(host_files(unreadable=(IP_FORWARD,)))
        self.assertIsNone(facts["sysctls"][IP_FORWARD])

    def test_a_repeated_status_field_is_not_trusted(self):
        text = host_files()(evidence.PROC_STATUS) + "NoNewPrivs:\t1\n"
        facts = evidence.privilege_facts(
            lambda path: text if path == evidence.PROC_STATUS else "0\n")
        self.assertIsNone(facts["status"]["NoNewPrivs"])

    def test_the_default_reader_returns_none_rather_than_raising(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.assertIsNone(
                evidence._read_text(str(Path(temporary) / "absent")))

    def test_capture_records_the_facts_beside_the_observations(self):
        def run(command):
            return evidence.Observation(tuple(command), 0, "", "")

        with mock.patch.object(evidence, "_run", side_effect=run):
            captured = evidence.capture(read=host_files())
            again = evidence.capture(read=host_files())
        self.assertEqual(evidence.privilege_facts(host_files()),
                         captured["privilege"])
        self.assertEqual(len(evidence.COMMANDS),
                         len(captured["observations"]))
        # The extra key is invisible to the simulation's own comparison.
        self.assertEqual([], evidence.compare(captured, again))


class ForwardingPrivilegeBasisTests(unittest.TestCase):
    """An unreadable ruleset proves forwarding only by privilege, or not."""

    def classify(self, before, after, **kwargs):
        return evidence.classify(before, after, **kwargs)

    def assertForwardingUnproven(self, before, after, *fragments,
                                 only=True, **kwargs):
        report = self.classify(before, after, **kwargs)
        self.assertEqual(evidence.UNPROVEN, report["counters"]["forwarding"],
                         report)
        self.assertIn("forwarding", report["unproven"])
        if only:
            self.assertEqual(["forwarding", "unifi"], report["unproven"])
        for fragment in fragments:
            self.assertIn(fragment, report["reasons"]["forwarding"])
        with self.assertRaises(evidence.UnprovenCategory) as raised:
            evidence.change_counters(before, after, unifi=UNIFI, **kwargs)
        self.assertIn("forwarding", raised.exception.reasons)
        return report

    def test_privilege_proves_forwarding_zero_with_an_unreadable_ruleset(self):
        report = self.classify(unprivileged(), unprivileged())
        self.assertEqual(0, report["counters"]["forwarding"])
        self.assertEqual({"forwarding": evidence.BASIS_PRIVILEGE},
                         report["basis"])
        # Six proven zeros; only the counter ADR 0080 waives is unproven.
        self.assertEqual(["unifi"], report["unproven"])
        for name in ("tap", "bridge", "route", "vlan", "listener"):
            self.assertEqual(0, report["counters"][name])

    def test_change_counters_states_the_privilege_basis(self):
        counters = evidence.change_counters(
            unprivileged(), unprivileged(), unifi=UNIFI)
        self.assertEqual(
            dict(ZERO, basis={"forwarding": evidence.BASIS_PRIVILEGE}),
            counters)

    def test_net_admin_or_sys_admin_in_any_judged_set_is_unproven(self):
        for name in evidence.CAPABILITY_SETS:
            for mask, capability in ((NET_ADMIN, "CAP_NET_ADMIN"),
                                     (SYS_ADMIN, "CAP_SYS_ADMIN"),
                                     (FULL, "CAP_NET_ADMIN, CAP_SYS_ADMIN")):
                with self.subTest(set=name, capability=capability):
                    self.assertForwardingUnproven(
                        unprivileged(), unprivileged(status={name: mask}),
                        "after snapshot", f"{name} holds {capability}")

    def test_an_unrelated_capability_does_not_unprove(self):
        # CAP_NET_RAW (13) is neither of the two bits the proof refuses.
        report = self.classify(
            unprivileged(status={"CapEff": f"{1 << 13:016x}",
                                 "CapPrm": f"{1 << 13:016x}"}),
            unprivileged())
        self.assertEqual(0, report["counters"]["forwarding"])

    def test_no_new_privs_zero_is_unproven(self):
        self.assertForwardingUnproven(
            unprivileged(status={"NoNewPrivs": "0"}), unprivileged(),
            "before snapshot", "NoNewPrivs")

    def test_the_live_snapshot_is_judged_too(self):
        self.assertForwardingUnproven(
            unprivileged(), unprivileged(),
            "during snapshot", "CapEff holds CAP_NET_ADMIN",
            during=unprivileged(status={"CapEff": NET_ADMIN}))

    def test_a_uid_of_zero_is_unproven(self):
        # euid 0 writes a root-owned sysctl through its owner bits with no
        # capability, and a real or saved 0 can become the euid.
        for uids in ("0\t0\t0\t0", "1000\t0\t1000\t1000",
                     "0\t1000\t1000\t1000", "1000\t1000\t0\t1000"):
            with self.subTest(uids=uids):
                self.assertForwardingUnproven(
                    unprivileged(), unprivileged(status={"Uid": uids}),
                    "Uid holds 0")

    def test_a_missing_or_malformed_fact_is_unproven(self):
        cases = {
            "NoNewPrivs absent": dict(status={"NoNewPrivs": None}),
            "NoNewPrivs malformed": dict(status={"NoNewPrivs": "yes"}),
            "CapEff absent": dict(status={"CapEff": None}),
            "CapPrm malformed": dict(status={"CapPrm": "not-a-mask"}),
            "CapAmb absent": dict(status={"CapAmb": None}),
            "Uid absent": dict(status={"Uid": None}),
            "Uid short": dict(status={"Uid": "1000\t1000"}),
            "status unreadable": dict(unreadable=(evidence.PROC_STATUS,)),
        }
        for label, kwargs in cases.items():
            with self.subTest(label):
                self.assertForwardingUnproven(
                    unprivileged(), unprivileged(**kwargs))

    def test_a_snapshot_without_privilege_facts_is_unproven(self):
        for facts in (None, {"schema": 2}, "facts", {"schema": 1}):
            with self.subTest(facts=facts):
                after = unprivileged()
                if facts is None:
                    del after["privilege"]
                else:
                    after["privilege"] = facts
                self.assertForwardingUnproven(unprivileged(), after)

    def test_the_bounding_and_inheritable_sets_are_not_judged(self):
        report = self.classify(
            unprivileged(status={"CapBnd": FULL, "CapInh": FULL}),
            unprivileged(status={"CapBnd": FULL, "CapInh": NET_ADMIN}))
        self.assertEqual(0, report["counters"]["forwarding"])

    def test_a_changed_sysctl_is_a_forwarding_change(self):
        report = self.classify(
            unprivileged(), unprivileged(sysctls={IP_FORWARD: "1"}))
        self.assertEqual(1, report["counters"]["forwarding"])
        self.assertEqual(["unifi"], report["unproven"])
        self.assertEqual(evidence.BASIS_PRIVILEGE,
                         report["basis"]["forwarding"])

    def test_a_changed_sysctl_counts_even_without_the_privilege_facts(self):
        report = self.classify(
            unprivileged(status={"NoNewPrivs": "0"}),
            unprivileged(sysctls={path: "1" for path in SYSCTLS}))
        self.assertEqual(3, report["counters"]["forwarding"])

    def test_a_sysctl_flipped_and_restored_inside_the_run_is_counted(self):
        report = self.classify(
            unprivileged(), unprivileged(),
            during=unprivileged(sysctls={IP_FORWARD: "1"}))
        self.assertEqual(1, report["counters"]["forwarding"])

    def test_an_unrecorded_sysctl_is_unproven(self):
        self.assertForwardingUnproven(
            unprivileged(unreadable=(IP_FORWARD,)), unprivileged(),
            "forwarding sysctls were not recorded")
        self.assertForwardingUnproven(
            unprivileged(), unprivileged(sysctls={IP_FORWARD: "on"}))

    def test_a_readable_ruleset_keeps_the_snapshot_basis(self):
        # Root: the ruleset is compared exactly as before, and the privilege
        # facts -- here a full capability set -- are not consulted.
        root = {"CapEff": FULL, "CapPrm": FULL, "NoNewPrivs": "0",
                "Uid": "0\t0\t0\t0"}
        readable = {"nft": {"returncode": 0,
                            "stdout": json.dumps(BASE_RULESET)}}
        report = self.classify(unprivileged(root, **readable),
                               unprivileged(root, **readable))
        self.assertEqual(0, report["counters"]["forwarding"])
        self.assertEqual({"forwarding": evidence.BASIS_SNAPSHOT},
                         report["basis"])
        changed = {"nft": {"returncode": 0, "stdout": json.dumps(
            {"nftables": BASE_RULESET["nftables"] + [{"table": {}}]})}}
        report = self.classify(unprivileged(root, **readable),
                               unprivileged(root, **changed))
        self.assertEqual(1, report["counters"]["forwarding"])
        self.assertEqual(evidence.BASIS_SNAPSHOT,
                         report["basis"]["forwarding"])

    def test_a_readable_ruleset_counts_a_recorded_sysctl_change_too(self):
        readable = {"nft": {"returncode": 0,
                            "stdout": json.dumps(BASE_RULESET)}}
        report = self.classify(
            unprivileged(**readable),
            unprivileged(sysctls={IP_FORWARD: "1"}, **readable))
        self.assertEqual(1, report["counters"]["forwarding"])
        # Snapshots that never recorded the sysctls still prove as before.
        self.assertEqual(0, self.classify(
            snapshot(), snapshot())["counters"]["forwarding"])

    def test_one_unreadable_side_is_enough_to_need_privilege(self):
        readable = {"nft": {"returncode": 0,
                            "stdout": json.dumps(BASE_RULESET)}}
        report = self.classify(unprivileged(**readable), unprivileged())
        self.assertEqual(evidence.BASIS_PRIVILEGE,
                         report["basis"]["forwarding"])
        self.assertEqual(0, report["counters"]["forwarding"])

    def test_malformed_nft_evidence_is_not_an_unreadable_ruleset(self):
        # Only a present, well-formed, failed nft run opens the privilege
        # basis; a missing or corrupt observation stays unproven.
        missing = unprivileged()
        missing["observations"] = [
            item for item in missing["observations"]
            if tuple(item["command"]) != evidence.NFT_COMMAND]
        duplicated = unprivileged()
        duplicated["observations"].append(copy.deepcopy(next(
            item for item in duplicated["observations"]
            if tuple(item["command"]) == evidence.NFT_COMMAND)))
        cases = {
            "missing": missing,
            "duplicated": duplicated,
            "boolean exit": unprivileged(nft=dict(UNREADABLE_RULESET,
                                                  returncode=True)),
            "no stderr": unprivileged(nft=dict(UNREADABLE_RULESET,
                                               stderr=None)),
        }
        for label, after in cases.items():
            with self.subTest(label):
                report = self.assertForwardingUnproven(unprivileged(), after)
                self.assertEqual(evidence.BASIS_SNAPSHOT,
                                 report["basis"]["forwarding"])

    def test_a_namespace_change_still_unproves_forwarding(self):
        self.assertForwardingUnproven(
            unprivileged(), unprivileged(netns="fixture-namespace (id: 0)"),
            only=False)

    def test_privilege_reasons_carry_no_identifier(self):
        report = self.classify(
            unprivileged(), unprivileged(status={"CapEff": NET_ADMIN}))
        text = json.dumps(report)
        for identifier in ("fixture-driver", "1000", IP_FORWARD):
            self.assertNotIn(identifier, text)


class NoIdentifierLeakTests(unittest.TestCase):
    """Counters and category names only: no host identity may escape."""

    IDENTIFIERS = ("fixture-lo", "fixture-uplink", "fixture-tap", "fixture-br",
                   "fixture-vl", "fixture-veth", "fixture-namespace",
                   "192.0.2.10", "192.0.2.1", "198.51.100.1", "2001:db8::/64",
                   "fixture-argv-audit", "fixture-egress-ledger")

    def assertNoIdentifier(self, text: str):
        for identifier in self.IDENTIFIERS:
            self.assertNotIn(identifier, text)

    def test_no_report_carries_a_fixture_identifier(self):
        cases = {
            "clean": (snapshot(), snapshot()),
            "tap": (snapshot(), snapshot(link=links(TAP))),
            "veth": (snapshot(), snapshot(link=links(
                {"ifname": "fixture-veth", "linkinfo": {"info_kind": "veth"}}))),
            "namespace": (snapshot(),
                          snapshot(netns="fixture-namespace (id: 0)")),
            "listener": (snapshot(), snapshot(
                sockets=BASE_SOCKETS
                + "\ntcp LISTEN 0 1 192.0.2.10:8443 0.0.0.0:*")),
            "route": (snapshot(), snapshot(route4=json.dumps(
                BASE_ROUTES + [{"dst": "198.51.100.0/24",
                                "dev": "fixture-tap"}]))),
            "unreadable": ({}, snapshot()),
        }
        for label, (before, after) in cases.items():
            with self.subTest(case=label):
                report = evidence.classify(before, after, unifi=UNIFI)
                self.assertNoIdentifier(json.dumps(report, sort_keys=True))

    def test_the_unproven_exception_message_carries_no_identifier(self):
        with self.assertRaises(evidence.UnprovenCategory) as raised:
            evidence.change_counters(
                snapshot(), snapshot(netns="fixture-namespace (id: 0)"),
                unifi=UNIFI)
        self.assertNoIdentifier(str(raised.exception))
        self.assertNoIdentifier(json.dumps(raised.exception.reasons))


class GateTwelveCheckNineTests(unittest.TestCase):
    """The counters judged by the real verifier, not by a restatement of it."""

    CHECK = "no_host_network_change"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.serial = 0

    def check(self, measurements):
        self.serial += 1
        directory = self.root / f"run-{self.serial}"
        directory.mkdir()
        (directory / "result.json").write_text(json.dumps({
            "schema": 1, "status": "pass", "retained": [],
            "measurements": measurements}))
        receipt = factory_verify.verify_run(directory)
        return receipt["checks"][self.CHECK]

    def status(self, measurements):
        return self.check(measurements)["status"]

    def test_proven_zero_counters_render_check_nine_pass(self):
        counters = evidence.change_counters(
            snapshot(), snapshot(), during=snapshot(), unifi=UNIFI)
        self.assertEqual(
            self.status({"host_network_changes": counters}), "PASS")

    def test_a_counted_change_does_not_render_pass(self):
        counters = evidence.change_counters(
            snapshot(), snapshot(link=links(TAP)), unifi=UNIFI)
        self.assertEqual(
            self.status({"host_network_changes": counters}), "FAIL")

    def test_an_unproven_unifi_counter_alone_renders_waived_not_pass(self):
        # The classify() rendering with no UniFi observation: six proven zeros
        # and the sentinel in the unifi slot.  ADR 0080 waives exactly that
        # counter, so the check is WAIVED -- never PASS.
        report = evidence.classify(snapshot(), snapshot())
        self.assertEqual(["unifi"], report["unproven"])
        self.assertEqual(factory_verify.UNPROVEN_COUNTER, evidence.UNPROVEN)
        self.assertEqual(
            self.status({"host_network_changes": report["counters"]}), "WAIVED")

    def test_another_unproven_counter_is_never_waived(self):
        # The waiver covers the unifi counter only: an unreadable ruleset
        # leaves forwarding unproven too, and the check fails closed.
        unreadable = {"returncode": 1, "stdout": "", "stderr": "denied"}
        report = evidence.classify(snapshot(), snapshot(nft=unreadable))
        self.assertEqual(["forwarding", "unifi"], report["unproven"])
        self.assertEqual(
            self.status({"host_network_changes": report["counters"]}), "FAIL")

    def test_omitting_the_measurement_leaves_check_nine_not_run(self):
        # The other honest rendering: a producer that catches
        # UnprovenCategory and emits nothing keeps the check at NOT-RUN.
        with self.assertRaises(evidence.UnprovenCategory):
            evidence.change_counters(snapshot(), snapshot())
        self.assertEqual(self.status({}), "NOT-RUN")

    @staticmethod
    def measurement(report):
        """The classify() rendering a producer emits: counters plus basis."""
        return dict(report["counters"], basis=report["basis"])

    def test_the_basis_vocabulary_mirrors_the_verifier(self):
        self.assertEqual(
            (evidence.BASIS_SNAPSHOT, evidence.BASIS_PRIVILEGE),
            factory_verify.HOST_NETWORK_BASES["forwarding"])
        self.assertEqual(evidence.BASIS_PRIVILEGE,
                         factory_verify.PRIVILEGE_BASIS)

    def test_a_privilege_proof_beside_unproven_unifi_is_waived_and_says_so(self):
        # The unprivileged factory: ruleset unreadable, privilege proven,
        # sysctls equal, no UniFi observation.  Six proven zeros and the one
        # waived slot -- and the receipt names the weaker forwarding proof.
        report = evidence.classify(unprivileged(), unprivileged())
        check = self.check({"host_network_changes": self.measurement(report)})
        self.assertEqual("WAIVED", check["status"])
        self.assertEqual("ADR 0080", check["waiver"]["adr"])
        self.assertIn("forwarding proven by privilege (the run could not "
                      "change it), not by a ruleset snapshot", check["detail"])
        self.assertNotIn("VLAN/forwarding", check["detail"])

    def test_a_privilege_proof_alone_passes_and_says_so(self):
        counters = evidence.change_counters(
            unprivileged(), unprivileged(), unifi=UNIFI)
        check = self.check({"host_network_changes": counters})
        self.assertEqual("PASS", check["status"])
        self.assertIn("forwarding proven by privilege", check["detail"])

    def test_a_snapshot_proof_keeps_the_plain_detail(self):
        check = self.check({"host_network_changes": self.measurement(
            evidence.classify(snapshot(), snapshot()))})
        self.assertEqual("WAIVED", check["status"])
        self.assertIn("no TAP/bridge/route/VLAN/forwarding/listener change",
                      check["detail"])
        self.assertNotIn("privilege", check["detail"])

    def test_a_changed_forwarding_sysctl_fails_check_nine(self):
        report = evidence.classify(
            unprivileged(), unprivileged(sysctls={IP_FORWARD: "1"}))
        self.assertEqual(
            self.status({"host_network_changes": self.measurement(report)}),
            "FAIL")

    def test_an_unprivileged_proof_that_fails_is_never_waived(self):
        report = evidence.classify(
            unprivileged(), unprivileged(status={"CapEff": NET_ADMIN}))
        self.assertEqual(
            self.status({"host_network_changes": self.measurement(report)}),
            "FAIL")

    def test_an_unrecognised_basis_fails_rather_than_being_ignored(self):
        zeros = {name: 0 for name in evidence.CATEGORIES}
        for basis in ({"forwarding": "assumed"}, {"tap": "privilege"},
                      {"unifi": "snapshot"}, "privilege", ["privilege"]):
            with self.subTest(basis=basis):
                check = self.check(
                    {"host_network_changes": dict(zeros, basis=basis)})
                self.assertEqual("FAIL", check["status"])
                self.assertIn("proof basis", check["detail"])


if __name__ == "__main__":
    unittest.main()
