"""Shape tests for the fail-closed Controller attachment check."""

from pathlib import Path
import unittest


SCRIPT = (
    Path(__file__).parents[1] / "bin" / "homelab-network-attach-preflight"
)


class NetworkAttachPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_checks_root_lock_and_forwarding(self) -> None:
        self.assertIn("passwd -S root", self.source)
        self.assertIn("net.ipv4.ip_forward", self.source)
        self.assertIn("net.ipv6.conf.all.forwarding", self.source)

    def test_checks_effective_ssh_policy(self) -> None:
        self.assertIn("sshd -T", self.source)
        self.assertIn("permitrootlogin no", self.source)
        self.assertIn("passwordauthentication no", self.source)
        self.assertIn("kbdinteractiveauthentication no", self.source)

    def test_authority_services_must_be_masked(self) -> None:
        for unit in ("dnsmasq.service", "dhcpd.service", "tftpd.service",
                     "named.service", "samba.service", "ntpd.service",
                     "nginx.service"):
            self.assertIn(unit, self.source)
        self.assertIn("expected masked", self.source)
        self.assertIn("systemctl show --property=LoadState --value", self.source)
        self.assertIn('systemctl is-active "$unit"', self.source)
        self.assertIn("expected inactive", self.source)

    def test_checks_authority_ports_and_fails_closed(self) -> None:
        for port in ("53", "67", "69", "88", "389", "445", "636", "4011"):
            self.assertIn(port, self.source)
        self.assertIn("RESULT FAIL", self.source)
        self.assertRegex(self.source, r'exit 1')

    def test_probe_failures_are_not_changed_to_success(self) -> None:
        self.assertNotIn("systemctl is-enabled \"$unit\" 2>/dev/null || true",
                         self.source)
        self.assertIn("listening sockets could not be read", self.source)
        self.assertIn("load state could not be read", self.source)


if __name__ == "__main__":
    unittest.main()
