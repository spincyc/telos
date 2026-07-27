"""Static security contract for the privileged host network helper."""

from pathlib import Path
import unittest


HELPER = (
    Path(__file__).parents[1] / "bin" / "homelab-host-network"
)


class HostNetworkHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = HELPER.read_text()

    def test_is_shell_syntax_valid(self):
        import subprocess
        subprocess.run(["bash", "-n", str(HELPER)], check=True)

    def test_topology_names_are_fixed(self):
        self.assertIn("physical=eno2", self.text)
        self.assertIn("bridge=br-dc", self.text)
        self.assertIn("tap=tap-dc", self.text)
        self.assertNotIn("eval ", self.text)
        self.assertNotIn("source ", self.text)

    def test_apply_requires_exact_interactive_confirmation(self):
        self.assertIn('[ "${APPLY:-0}" = 1 ]', self.text)
        self.assertIn(
            '[ "$answer" = "$confirm_prepare" ]', self.text)
        self.assertIn(
            '[ "$answer" = "$confirm_teardown" ]', self.text)

    def test_does_not_create_network_authority(self):
        for forbidden in (
            "iptables ", "nft ", "ip route add", "ip address add",
            "dnsmasq", "dhcpd", "sysctl -w",
        ):
            self.assertNotIn(forbidden, self.text)

    def test_state_is_private_and_not_sourced(self):
        self.assertIn("install -d -m 0700 -o root -g root", self.text)
        self.assertIn("chmod 0600", self.text)
        self.assertIn("[ ! -L \"$state_file\" ]", self.text)
        self.assertIn("unexpected state key", self.text)

    def test_teardown_is_resumable_and_removes_state_last(self):
        teardown = self.text.split("teardown() {", 1)[1].split(
            "\n}\n\nrequire_root", 1)[0]
        self.assertIn('exists "$tap" && run ip link delete "$tap"', teardown)
        self.assertIn('exists "$bridge" && run ip link delete "$bridge"', teardown)
        self.assertIn('! exists "$tap" || die', teardown)
        self.assertIn('! exists "$bridge" || die', teardown)
        self.assertLess(
            teardown.index("restore_network_manager"),
            teardown.index('rm -f -- "$state_file"'),
        )
        self.assertLess(
            teardown.index('! exists "$bridge" || die'),
            teardown.index('rm -f -- "$state_file"'),
        )
        self.assertIn('"$physical link state was not restored;', teardown)
        self.assertIn('"NetworkManager state was not restored;', teardown)
        self.assertNotIn(
            '[ "$physical_was_up" = 1 ] &&', teardown,
        )

    def test_teardown_rejects_unexpected_surviving_topology(self):
        teardown = self.text.split("teardown() {", 1)[1].split(
            "\n}\n\nrequire_root", 1)[0]
        self.assertIn('"$tap exists outside the expected bridge"', teardown)
        self.assertIn('"$physical has an unexpected master"', teardown)
        self.assertIn("trusted state retained", teardown)


if __name__ == "__main__":
    unittest.main()
