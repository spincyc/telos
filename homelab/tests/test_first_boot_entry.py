"""Tests for the first-boot entry point's manifest reading."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "bin"))

import importlib.machinery  # noqa: E402
entry = importlib.machinery.SourceFileLoader(
    "homelab_first_boot", str(ROOT / "bin/homelab-first-boot")).load_module()


def write_manifest(document):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(document, handle)
    handle.close()
    return Path(handle.name)


class TestExpectations(unittest.TestCase):
    def test_reads_mac_and_address_from_the_manifest(self):
        path = write_manifest({
            "managed_interface": {"permanent_mac": "60:cf:84:77:c6:6f"},
            "network": {"entered": {"controller_ipv4_address": "10.0.7.2"}},
        })
        self.assertEqual(entry.load_expectations(path),
                         ("60:cf:84:77:c6:6f", "10.0.7.2"))

    def test_a_controller_without_managed_network_has_nothing_to_activate(self):
        # ADR 0008: where external infrastructure owns DHCP, these services
        # stay stopped and that is a success, not a failure.
        path = write_manifest({"profile": "controller", "hostname": "polycarp"})
        self.assertIsNone(entry.load_expectations(path))
        self.assertEqual(entry.main(["--manifest", str(path)]), 0)

    def test_a_missing_manifest_is_not_a_crash(self):
        self.assertIsNone(entry.load_expectations(Path("/nonexistent/manifest.json")))

    def test_the_bundle_is_dhcp_and_the_artifact_service(self):
        # ADR 0012: they start together or not at all.
        self.assertIn("dnsmasq-homelab.service", entry.BUNDLE)
        self.assertIn("nginx-homelab.service", entry.BUNDLE)


class TestUnitsAreNotEnabledAtBoot(unittest.TestCase):
    """The fail-closed design depends on these not starting on their own."""

    def test_dnsmasq_unit_has_no_wantedby(self):
        text = (ROOT / "profiles/controller/systemd/dnsmasq-homelab.service").read_text()
        install = text.split("[Install]", 1)[1]
        self.assertNotIn("WantedBy=", install)

    def test_nginx_unit_has_no_wantedby(self):
        text = (ROOT / "profiles/controller/systemd/nginx-homelab.service").read_text()
        install = text.split("[Install]", 1)[1]
        self.assertNotIn("WantedBy=", install)

    def test_the_activation_unit_is_the_one_that_is_enabled(self):
        text = (ROOT / "profiles/controller/systemd/homelab-first-boot.service").read_text()
        self.assertIn("WantedBy=multi-user.target", text)


if __name__ == "__main__":
    unittest.main()
