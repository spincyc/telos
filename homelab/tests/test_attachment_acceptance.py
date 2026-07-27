import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vm.attachment_acceptance import (  # noqa: E402
    Listener,
    check_units,
    default_gateways,
    interface_addresses,
    parse_listeners,
    parse_resolvers,
    prohibited_listeners,
)


class TestAttachmentAcceptance(unittest.TestCase):
    def test_exact_interface_address_is_extracted(self):
        data = [
            {
                "ifname": "enp1s0",
                "addr_info": [
                    {"family": "inet", "local": "10.1.11.10", "prefixlen": 24},
                    {"family": "inet6", "local": "::1", "prefixlen": 128},
                ],
            }
        ]
        self.assertEqual(interface_addresses(data, "enp1s0"), {"10.1.11.10/24"})

    def test_only_interface_default_route_is_accepted(self):
        data = [
            {"dst": "default", "gateway": "10.1.11.1", "dev": "enp1s0"},
            {"dst": "default", "gateway": "192.0.2.1", "dev": "other"},
        ]
        self.assertEqual(default_gateways(data, "enp1s0"), {"10.1.11.1"})

    def test_link_resolvers_are_exact(self):
        text = "Global:\nLink 2 (enp1s0): 10.1.11.1 10.1.11.2\n"
        self.assertEqual(
            parse_resolvers(text, "enp1s0"), {"10.1.11.1", "10.1.11.2"}
        )

    def test_prohibited_listener_is_reported_on_any_address(self):
        text = (
            "udp UNCONN 0 0 0.0.0.0:67 0.0.0.0:*\n"
            "tcp LISTEN 0 128 [::]:22 [::]:*\n"
        )
        listeners = parse_listeners(text)
        self.assertEqual(
            prohibited_listeners(listeners), [Listener("udp", "0.0.0.0", 67)]
        )

    def test_prohibited_units_must_be_disabled_and_inactive(self):
        self.assertEqual(check_units({"dnsmasq.service": ("disabled", "inactive")}), [])
        failures = check_units({"dnsmasq.service": ("enabled", "active")})
        self.assertEqual(len(failures), 2)


if __name__ == "__main__":
    unittest.main()
