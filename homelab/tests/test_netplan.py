"""Tests for the ADR 0045 managed-network plan.

Each validation rule the ADR states gets at least one test that proves the rule
rejects what it is supposed to reject. A validator that is never tested against
its own failure cases is indistinguishable from no validator at all, which is
roughly the state the previous design was in.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from netplan import (  # noqa: E402
    DNS_SUFFIX,
    NetworkPlanError,
    advisories,
    build_plan,
)

GOOD = {
    "managed_ipv4_cidr": "10.0.7.0/24",
    "controller_ipv4_address": "10.0.7.2",
    "dhcp_pool_start": "10.0.7.100",
    "dhcp_pool_end": "10.0.7.200",
}


def plan_with(**overrides):
    inputs = dict(GOOD)
    inputs.update(overrides)
    return build_plan(inputs)


class TestDerivation(unittest.TestCase):
    def test_accepts_a_reasonable_plan(self):
        plan = build_plan(GOOD)
        self.assertEqual(plan.managed_ipv4_cidr, "10.0.7.0/24")
        self.assertEqual(plan.controller_ipv4_address, "10.0.7.2")

    def test_derives_every_value_the_adr_lists(self):
        plan = build_plan(GOOD)
        self.assertEqual(plan.netmask, "255.255.255.0")
        self.assertEqual(plan.network_address, "10.0.7.0")
        self.assertEqual(plan.broadcast_address, "10.0.7.255")
        self.assertEqual(plan.usable_addresses, 254)
        self.assertEqual(plan.pool_size, 101)

    def test_dns_server_is_the_controller(self):
        plan = plan_with(controller_ipv4_address="10.0.7.9")
        self.assertEqual(plan.dns_server, "10.0.7.9")

    def test_dns_suffix_is_fixed_not_prompted(self):
        self.assertEqual(build_plan(GOOD).dns_suffix, DNS_SUFFIX)
        self.assertEqual(DNS_SUFFIX, "home.arpa")

    def test_no_default_router_is_advertised(self):
        # ADR 0011: the isolated acceptance network has no router, and dnsmasq
        # must not advertise one that does not exist.
        self.assertIsNone(build_plan(GOOD).default_router)

    def test_summary_rows_mention_the_derived_values(self):
        rows = dict(build_plan(GOOD).summary_rows())
        self.assertIn("Default router", rows)
        self.assertIn("none advertised", rows["Default router"])
        self.assertIn("home.arpa", rows["DNS suffix"])


class TestParsing(unittest.TestCase):
    def test_rejects_missing_inputs(self):
        for field in GOOD:
            with self.subTest(field=field):
                with self.assertRaises(NetworkPlanError):
                    plan_with(**{field: ""})

    def test_rejects_unknown_input(self):
        inputs = dict(GOOD, gateway="10.0.7.1")
        with self.assertRaisesRegex(NetworkPlanError, "unknown network input"):
            build_plan(inputs)

    def test_rejects_leading_zero_octets(self):
        # 010 is octal to some parsers and decimal to others. A provisioning
        # tool must not be ambiguous about which host it is configuring.
        with self.assertRaisesRegex(NetworkPlanError, "unambiguous"):
            plan_with(controller_ipv4_address="10.0.007.2")

    def test_rejects_non_addresses(self):
        for bad in ("10.0.7", "10.0.7.2.9", "10.0.7.256", "ten.oh.seven.two", "10.0.7.-2"):
            with self.subTest(bad=bad):
                with self.assertRaises(NetworkPlanError):
                    plan_with(controller_ipv4_address=bad)

    def test_rejects_cidr_without_prefix(self):
        with self.assertRaisesRegex(NetworkPlanError, "address/prefix"):
            plan_with(managed_ipv4_cidr="10.0.7.0")

    def test_rejects_out_of_range_prefix(self):
        with self.assertRaises(NetworkPlanError):
            plan_with(managed_ipv4_cidr="10.0.7.0/33")


class TestValidationRules(unittest.TestCase):
    def test_rejects_cidr_with_host_bits_set(self):
        with self.assertRaisesRegex(NetworkPlanError, "host bits set") as caught:
            plan_with(managed_ipv4_cidr="10.0.7.5/24")
        # The message must tell the operator the answer, not just the problem.
        self.assertIn("10.0.7.0/24", str(caught.exception))

    def test_rejects_controller_outside_the_subnet(self):
        with self.assertRaisesRegex(NetworkPlanError, "not inside"):
            plan_with(controller_ipv4_address="10.0.8.2")

    def test_rejects_pool_endpoints_outside_the_subnet(self):
        with self.assertRaises(NetworkPlanError):
            plan_with(dhcp_pool_end="10.0.8.200")

    def test_rejects_the_network_address(self):
        with self.assertRaisesRegex(NetworkPlanError, "network address"):
            plan_with(controller_ipv4_address="10.0.7.0")

    def test_rejects_the_broadcast_address(self):
        with self.assertRaisesRegex(NetworkPlanError, "broadcast address"):
            plan_with(dhcp_pool_end="10.0.7.255")

    def test_rejects_reversed_pool(self):
        with self.assertRaisesRegex(NetworkPlanError, "greater than"):
            plan_with(dhcp_pool_start="10.0.7.200", dhcp_pool_end="10.0.7.100")

    def test_rejects_controller_inside_the_pool(self):
        # The rule that matters most in practice: dnsmasq must never be able to
        # hand a client the address its own DNS server answers on.
        with self.assertRaisesRegex(NetworkPlanError, "inside the DHCP pool"):
            plan_with(controller_ipv4_address="10.0.7.150")

    def test_rejects_controller_on_a_pool_boundary(self):
        for boundary in ("10.0.7.100", "10.0.7.200"):
            with self.subTest(boundary=boundary):
                with self.assertRaisesRegex(NetworkPlanError, "inside the DHCP pool"):
                    plan_with(controller_ipv4_address=boundary)

    def test_rejects_subnet_too_small_to_hold_the_plan(self):
        for tiny in ("10.0.7.0/31", "10.0.7.4/32"):
            with self.subTest(tiny=tiny):
                with self.assertRaisesRegex(NetworkPlanError, "usable address"):
                    build_plan({
                        "managed_ipv4_cidr": tiny,
                        "controller_ipv4_address": "10.0.7.1",
                        "dhcp_pool_start": "10.0.7.1",
                        "dhcp_pool_end": "10.0.7.1",
                    })

    def test_accepts_a_single_address_pool(self):
        plan = plan_with(dhcp_pool_start="10.0.7.100", dhcp_pool_end="10.0.7.100")
        self.assertEqual(plan.pool_size, 1)

    def test_accepts_a_tight_but_legal_slash_30(self):
        plan = build_plan({
            "managed_ipv4_cidr": "192.168.50.0/30",
            "controller_ipv4_address": "192.168.50.1",
            "dhcp_pool_start": "192.168.50.2",
            "dhcp_pool_end": "192.168.50.2",
        })
        self.assertEqual(plan.usable_addresses, 2)
        self.assertEqual(plan.pool_size, 1)


class TestAdvisories(unittest.TestCase):
    def test_quiet_for_an_ordinary_plan(self):
        self.assertEqual(advisories(build_plan(GOOD)), [])

    def test_notes_a_public_range(self):
        notes = advisories(build_plan({
            "managed_ipv4_cidr": "203.0.113.0/24",
            "controller_ipv4_address": "203.0.113.2",
            "dhcp_pool_start": "203.0.113.100",
            "dhcp_pool_end": "203.0.113.200",
        }))
        self.assertTrue(any("RFC 1918" in note for note in notes))

    def test_notes_a_tiny_pool(self):
        notes = advisories(plan_with(dhcp_pool_start="10.0.7.100", dhcp_pool_end="10.0.7.102"))
        self.assertTrue(any("only 3" in note for note in notes))

    def test_advisories_never_raise(self):
        # An advisory is not a validation rule and must not be able to stop an
        # install that ADR 0045 permits.
        self.assertIsInstance(advisories(build_plan(GOOD)), list)


if __name__ == "__main__":
    unittest.main()
