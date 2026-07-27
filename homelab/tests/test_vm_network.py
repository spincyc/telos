"""Safety tests for the deferred bootstrap-dc network decision."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vm.network import (  # noqa: E402
    UnsafeNetworkPlan,
    assert_isolated,
    describe,
    socket_network_args,
)


class TestIsolatedBootstrapNetwork(unittest.TestCase):
    def test_listener_is_bound_only_to_loopback(self):
        args = socket_network_args(role="listen", mac="52:54:00:11:11:11")
        text = " ".join(args)
        self.assertIn("listen=127.0.0.1:12961", text)
        self.assertIn("-nodefaults", args)

    def test_client_uses_the_same_loopback_segment(self):
        args = socket_network_args(role="connect", mac="52:54:00:11:11:12")
        self.assertIn("connect=127.0.0.1:12961", " ".join(args))

    def test_every_physical_attachment_mode_is_deferred(self):
        for mode in ("bridge", "tap", "trunk", "existing-lan", "unifi"):
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(UnsafeNetworkPlan, "deferred"):
                    socket_network_args(
                        role="listen", mac="52:54:00:11:11:11", mode=mode
                    )

    def test_rejects_host_or_unifi_mutation_terms(self):
        unsafe_fragments = (
            ["-nodefaults", "-netdev", "tap,ifname=tap0"],
            ["-nodefaults", "-netdev", "bridge,br=br0"],
            ["-nodefaults", "-netdev", "user,id=n0"],
            ["-nodefaults", "--unifi-network", "provisioning"],
            ["-nodefaults", "--vlan-trunk", "eno1"],
        )
        for argv in unsafe_fragments:
            with self.subTest(argv=argv):
                with self.assertRaises(UnsafeNetworkPlan):
                    assert_isolated(argv)

    def test_rejects_non_loopback_socket_listener(self):
        with self.assertRaisesRegex(UnsafeNetworkPlan, "loopback"):
            assert_isolated(
                [
                    "-nodefaults",
                    "-netdev",
                    "socket,id=bootstrap,listen=0.0.0.0:12961",
                ]
            )

    def test_rejects_default_qemu_devices(self):
        with self.assertRaisesRegex(UnsafeNetworkPlan, "defaults"):
            assert_isolated(
                [
                    "-netdev",
                    "socket,id=bootstrap,listen=127.0.0.1:12961",
                ]
            )

    def test_rejects_an_extra_network_backend(self):
        with self.assertRaisesRegex(UnsafeNetworkPlan, "exactly one"):
            assert_isolated(
                [
                    "-nodefaults",
                    "-netdev",
                    "socket,id=bootstrap,listen=127.0.0.1:12961",
                    "-netdev",
                    "vde,id=other",
                ]
            )

    def test_rejects_shorthand_nic(self):
        with self.assertRaisesRegex(UnsafeNetworkPlan, "shorthand"):
            assert_isolated(
                [
                    "-nodefaults",
                    "-netdev",
                    "socket,id=bootstrap,listen=127.0.0.1:12961",
                    "-nic",
                    "none",
                ]
            )

    def test_uses_only_synthetic_macs(self):
        with self.assertRaisesRegex(UnsafeNetworkPlan, "synthetic"):
            socket_network_args(role="listen", mac="00:11:22:33:44:55")

    def test_plan_explicitly_names_unchanged_external_systems(self):
        text = "\n".join(describe())
        self.assertIn("Host interfaces changed: none", text)
        self.assertIn("UniFi settings changed: none", text)
        self.assertIn("Physical attachment remains a later deployment gate", text)


if __name__ == "__main__":
    unittest.main()
