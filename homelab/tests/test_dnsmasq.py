"""Tests for the generated dnsmasq configuration.

`dnsmasq --test` checks syntax. It cannot tell you that a syntactically perfect
file advertises a default gateway on a network with no router, or binds to an
interface the Controller does not own. Those are the failures that matter, and
they are decisions rather than syntax, so they are tested here.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import dnsmasq  # noqa: E402
from netplan import build_plan  # noqa: E402

PLAN = build_plan({
    "managed_ipv4_cidr": "10.0.7.0/24",
    "controller_ipv4_address": "10.0.7.2",
    "dhcp_pool_start": "10.0.7.100",
    "dhcp_pool_end": "10.0.7.200",
})


def render(**kwargs):
    options = dict(interface="lan0", controller_hostname="polycarp")
    options.update(kwargs)
    return dnsmasq.render(PLAN, **options)


def directives(text):
    """Configuration lines only. The file explains itself in comments, and a
    comment naming a directive is not the same as setting it."""
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


class TestGeneratedConfiguration(unittest.TestCase):
    def test_binds_only_the_selected_interface(self):
        text = render()
        self.assertIn("interface=lan0", text)
        self.assertIn("bind-interfaces", text)
        self.assertIn("except-interface=lo", text)
        self.assertNotIn("bind-dynamic", directives(text))

    def test_listens_on_the_controller_address(self):
        self.assertIn("listen-address=10.0.7.2", render())

    def test_pool_matches_the_validated_plan(self):
        self.assertIn("dhcp-range=10.0.7.100,10.0.7.200,255.255.255.0,12h", render())

    def test_advertises_the_controller_as_dns(self):
        self.assertIn("dhcp-option=option:dns-server,10.0.7.2", render())

    def test_never_advertises_a_default_router(self):
        # ADR 0011. A router option with a value here would black-hole every
        # client on the isolated acceptance network.
        lines = directives(render())
        self.assertIn("dhcp-option=option:router", lines)
        self.assertFalse([l for l in lines if l.startswith("dhcp-option=option:router,")])

    def test_publishes_the_controller_fqdn(self):
        self.assertIn("host-record=polycarp.home.arpa,10.0.7.2", render())

    def test_refuses_to_lease_the_controller_address(self):
        self.assertIn("dhcp-host=10.0.7.2,ignore", render())

    def test_no_managed_ipv6(self):
        # ADR 0013.
        lines = directives(render())
        self.assertFalse([l for l in lines if l.startswith("enable-ra")])
        self.assertFalse([l for l in lines if l.startswith("dhcp-range=::")])

    def test_names_the_governing_adrs_in_the_file(self):
        # A generated file that a human will read during an outage should say
        # why it looks the way it does.
        text = render()
        for adr in ("ADR 0011", "ADR 0012", "ADR 0013", "ADR 0044"):
            self.assertIn(adr, text)


class TestPxe(unittest.TestCase):
    def test_tftp_is_limited_to_the_first_stage(self):
        text = render()
        self.assertIn("enable-tftp", text)
        self.assertIn("tftp-root=/srv/tftp", text)
        self.assertIn("tftp-secure", text)

    def test_offers_uefi_and_bios_first_stages(self):
        text = render()
        self.assertIn("dhcp-boot=tag:efi64,ipxe.efi", text)
        self.assertIn("dhcp-boot=tag:bios,undionly.kpxe", text)

    def test_breaks_the_ipxe_chainload_loop(self):
        text = render(http_base_url="http://10.0.7.2/boot")
        self.assertIn("dhcp-match=set:ipxe,175", text)
        self.assertIn("dhcp-boot=tag:ipxe,http://10.0.7.2/boot/boot.ipxe", text)

    def test_says_so_when_no_artifact_service_is_configured(self):
        text = render()
        self.assertIn("No HTTP artifact base URL", text)

    def test_pxe_can_be_disabled(self):
        lines = directives(render(enable_pxe=False))
        self.assertNotIn("enable-tftp", lines)
        self.assertTrue([l for l in lines if l.startswith("dhcp-range=")])


class TestRejections(unittest.TestCase):
    def test_requires_an_interface(self):
        with self.assertRaises(ValueError):
            dnsmasq.render(PLAN, interface="", controller_hostname="polycarp")

    def test_requires_a_short_hostname(self):
        with self.assertRaisesRegex(ValueError, "short hostname"):
            dnsmasq.render(PLAN, interface="lan0", controller_hostname="polycarp.home.arpa")

    def test_refusals_pass_for_generated_output(self):
        self.assertEqual(dnsmasq.refusals(PLAN, render()), [])

    def test_refusals_catch_a_smuggled_default_route(self):
        broken = render().replace(
            "dhcp-option=option:router\n", "dhcp-option=option:router,10.0.7.1\n")
        self.assertIn("ADR 0011: a default router is advertised", dnsmasq.refusals(PLAN, broken))

    def test_refusals_catch_bind_dynamic(self):
        broken = render().replace("bind-interfaces", "bind-dynamic")
        self.assertTrue(any("bind-dynamic" in p for p in dnsmasq.refusals(PLAN, broken)))

    def test_refusals_catch_a_pool_that_does_not_match_the_plan(self):
        broken = render().replace("10.0.7.200", "10.0.7.240")
        self.assertTrue(any("does not match" in p for p in dnsmasq.refusals(PLAN, broken)))


if __name__ == "__main__":
    unittest.main()
