"""Contracts for the controlled bootstrap-controller network gate."""

import re
import unittest
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[2]
GUIDE = ROOT / "site/pages/homelab/controller-network-gate.md"
ADR = ROOT / "homelab/decisions/0076-controlled-controller-network-attachment.md"
ROLLBACK = ROOT / "homelab/network/ROLLBACK.md"
MAKEFILE = ROOT / "Makefile"
HOST_HELPER = ROOT / "homelab/bin/homelab-host-network"


class ControllerNetworkDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.guide = GUIDE.read_text()
        cls.adr = ADR.read_text()
        cls.rollback = ROLLBACK.read_text()
        cls.makefile = MAKEFILE.read_text()
        cls.host_helper = HOST_HELPER.read_text()

    @staticmethod
    def prose(text: str) -> str:
        return " ".join(line.removeprefix("> ").strip() for line in text.splitlines())

    def test_public_guide_is_linked_from_homelab_landing_page(self) -> None:
        landing = (ROOT / "site/pages/homelab/index.md").read_text()
        self.assertIn("(controller-network-gate/index.md)", landing)

    def test_guide_keeps_network_authority_on_unifi(self) -> None:
        self.assertIn(
            "UniFi remains the only DHCP and client-DNS authority", self.guide
        )
        for forbidden_service in ("AD", "DNS", "DHCP", "PXE", "TFTP", "HTTP"):
            self.assertIn(forbidden_service, self.guide)
        self.assertIn("options 66/67", self.guide)
        self.assertIn("ordinary client", self.guide)

    def test_guide_is_an_operator_checklist_not_a_sketch(self) -> None:
        for section in (
            "## Gate record",
            "## 1. Record the baseline",
            "## 2. Create the validation network",
            "## 3. Put the network in its own zone",
            "## 4. Add the policies",
            "## 5. Configure one access port",
            "## 6. Reserve the VM address",
            "## 7. Prove the boundary",
            "## Roll back",
        ):
            self.assertIn(section, self.guide)
        self.assertGreaterEqual(self.guide.count("**Verify:"), 5)
        self.assertGreaterEqual(self.guide.count("**Stop if:"), 4)
        self.assertIn("What this does", self.guide)
        self.assertIn("Expected result", self.guide)

    def test_plan_is_small_and_uses_human_friendly_boundaries(self) -> None:
        self.assertIn("normally `/28`", self.guide)
        self.assertIn("14 usable addresses", self.prose(self.guide))
        self.assertIn("`10.A.B.0/28`", self.guide)
        self.assertIn("`10.A.B.1`", self.guide)
        self.assertNotIn("10.0.0.0/8", self.guide)

    def test_public_documents_keep_instance_values_private(self) -> None:
        public = "\n".join((self.guide, self.adr, self.rollback))
        self.assertIn("private overlay", self.guide)
        self.assertIn("private network JSON", self.rollback)
        self.assertIn("mode `0600`", self.rollback)
        self.assertNotRegex(
            public,
            r"\b(?:cece|ava|jack|packy|anna|finn|therese|charlie|aidan|lucy|eli)"
            r"\b",
        )
        literal_ipv4 = set(
            re.findall(r"(?<![A-Za-z0-9.])(?:10\.)\d+\.\d+\.\d+(?:/\d+)?", public)
        )
        self.assertEqual(literal_ipv4, set())

    def test_unifi_references_are_https_official_help_pages(self) -> None:
        links = re.findall(r"\]\((https?://[^)]+)\)", self.guide)
        self.assertGreaterEqual(len(links), 5)
        for link in links:
            parsed = urlparse(link)
            self.assertEqual(parsed.scheme, "https")
            self.assertEqual(parsed.hostname, "help.ui.com")
            self.assertTrue(parsed.path.startswith("/hc/en-us/articles/"))
        for article in (
            "9761080275607",
            "115003173168",
            "26136855808919",
            "360012097513",
            "15179064940439",
        ):
            self.assertTrue(any(article in link for link in links), article)

    def test_adr_records_gate_and_guest_independent_rollback(self) -> None:
        for phrase in (
            "Status: Accepted",
            "ordinary UniFi DHCP client",
            "UniFi remains the sole network authority",
            "no UniFi DHCP option 66 or 67",
            "Rollback must not require logging in",
            "Samba AD DNS, PXE options and workstation enrollment",
        ):
            self.assertIn(phrase, self.adr)

    def test_rollback_starts_with_isolation_and_preserves_vm(self) -> None:
        prose = self.prose(self.rollback)
        for phrase in (
            "Use the host console",
            "sudo ip link set dev tap-dc down",
            "Do not log in to the guest",
            "DETACH eno2 br-dc tap-dc",
            "Prove recovery",
            "ordinary client",
            "Preserve the installed VM",
            "bootstrap-dc.qcow2",
        ):
            self.assertIn(phrase, prose)

    def test_make_exposes_separate_plan_run_check_and_teardown_gates(self) -> None:
        targets = (
            "homelab-bootstrap-network-preflight",
            "homelab-bootstrap-network-plan",
            "homelab-bootstrap-network-receipt",
            "homelab-bootstrap-network-authorize",
            "homelab-bootstrap-network-run",
            "homelab-bootstrap-network-check",
            "homelab-bootstrap-network-teardown",
        )
        phony = self.makefile.split(".DELETE_ON_ERROR:", 1)[0]
        for target in targets:
            self.assertRegex(self.makefile, rf"(?m)^{re.escape(target)}:")
            self.assertIn(target, phony)
        self.assertIn("NETWORK_CONFIG=<private 0600 attachment JSON>", self.makefile)
        self.assertIn("NETWORK_RECEIPT=<fresh private 0600 receipt>", self.makefile)
        self.assertIn(
            "NETWORK_RECEIPT=/absolute/private/path/bootstrap-network-receipt.json",
            self.guide,
        )
        self.assertIn("APPLY=1 CONFIRM=attach-bootstrap-dc", self.guide)
        self.assertIn("homelab-bootstrap-network-authorize", self.guide)
        teardown = self.makefile.split(
            "homelab-bootstrap-network-teardown:", 1
        )[1].split("homelab-bootstrap-controller:", 1)[0]
        self.assertIn("APPLY=1 homelab/bin/homelab-host-network teardown", teardown)
        self.assertIn("then type the helper confirmation", teardown)
        self.assertIn(
            'confirm_teardown="DETACH $physical $bridge $tap"', self.host_helper
        )
        self.assertIn(
            'read -r -p "Type $confirm_teardown to continue: " answer',
            self.host_helper,
        )

    def test_default_make_network_actions_are_non_mutating(self) -> None:
        run = self.makefile.split(
            "homelab-bootstrap-network-run:", 1
        )[1].split("homelab-bootstrap-network-check:", 1)[0]
        self.assertIn("dry run:", run)
        self.assertIn("--apply", run)
        self.assertIn("--confirm '$(CONFIRM)'", run)
        self.assertIn("--network-receipt '$(abspath $(NETWORK_RECEIPT))'", run)
        self.assertIn("fresh authorized receipt", run)
        self.assertRegex(run, r"if \[ '\$\(APPLY\)' != 1 \]")


if __name__ == "__main__":
    unittest.main()
