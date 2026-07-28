import ipaddress
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm.simulated_gateway import HubPolicy, ethernet, ipv4, udp
from homelab.vm.windows_identity_dependency import (
    DEPENDENCIES,
    DependencyPeer,
    OPTIONAL_STORAGE_ACCESS_DENIED,
)
from homelab.vm.windows_identity_run import (
    NativeProcessBoundary,
    WindowsIdentityRunError,
)


CLIENT_MAC = bytes.fromhex("525400311111")
CLIENT_IP = ipaddress.IPv4Address("10.1.31.11")


class _Process:
    def __init__(self, pid=123, returncode=None):
        self.pid = pid
        self.returncode = returncode

    def poll(self):
        return self.returncode


def arp_request(target: ipaddress.IPv4Address) -> bytes:
    payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    payload += (
        CLIENT_MAC + CLIENT_IP.packed + b"\0" * 6 + target.packed)
    return ethernet(b"\xff" * 6, CLIENT_MAC, 0x0806, payload)


def health_request(role: str) -> bytes:
    spec = DEPENDENCIES[role]
    return ethernet(
        spec["mac"], CLIENT_MAC, 0x0800,
        ipv4(
            CLIENT_IP, spec["ip"], 17,
            udp(41000, spec["port"], b"health"),
        ),
    )

def dependency_request(role: str, payload: bytes) -> bytes:
    spec = DEPENDENCIES[role]
    return ethernet(
        spec["mac"], CLIENT_MAC, 0x0800,
        ipv4(
            CLIENT_IP, spec["ip"], 17,
            udp(41000, spec["port"], payload),
        ),
    )


class WindowsIdentityDependencyTests(unittest.TestCase):
    def test_each_peer_is_guest_visible_at_its_distinct_l2_identity(self):
        identities = set()
        for role, spec in DEPENDENCIES.items():
            peer = DependencyPeer(role)
            arp = peer.handle(arp_request(spec["ip"]))
            self.assertEqual(1, len(arp))
            self.assertEqual(CLIENT_MAC, arp[0][:6])
            self.assertEqual(spec["mac"], arp[0][6:12])
            response = peer.handle(health_request(role))
            self.assertEqual(1, len(response))
            self.assertEqual(CLIENT_MAC, response[0][:6])
            self.assertEqual(spec["mac"], response[0][6:12])
            self.assertIn(
                f"{role}:available".encode("ascii"), response[0])
            identities.add((spec["ip"], spec["mac"], spec["port"]))
        self.assertEqual(len(DEPENDENCIES), len(identities))

    def test_peer_rejects_requests_for_the_other_dependency(self):
        self.assertEqual(
            [],
            DependencyPeer("update-source").handle(
                health_request("optional-storage")),
        )

    def test_optional_storage_has_reachable_but_access_denied_mode(self):
        peer = DependencyPeer("optional-storage")
        response = peer.handle(
            dependency_request("optional-storage", b"authorize"))
        self.assertEqual(1, len(response))
        self.assertIn(OPTIONAL_STORAGE_ACCESS_DENIED, response[0])
        self.assertEqual(
            [],
            DependencyPeer("update-source").handle(
                dependency_request("update-source", b"authorize")),
        )
        self.assertEqual(
            [],
            peer.handle(dependency_request(
                "optional-storage", b"credential=not-allowed")),
        )

    def test_switch_routes_guest_arp_and_health_to_dependency_peer(self):
        policy = HubPolicy(gateway_peer=1)
        peers = {1, 2, 3}
        role = "update-source"
        peer = DependencyPeer(role)

        arp_deliveries, _ = policy.route(
            2, arp_request(DEPENDENCIES[role]["ip"]), peers)
        self.assertIn(3, arp_deliveries)
        reply = peer.handle(arp_deliveries[3][0])[0]
        reply_deliveries, _ = policy.route(3, reply, peers)
        self.assertEqual([reply], reply_deliveries[2])

        health_deliveries, _ = policy.route(
            2, health_request(role), peers)
        self.assertEqual(
            [health_request(role)], health_deliveries[3])
        response = peer.handle(health_deliveries[3][0])[0]
        response_deliveries, _ = policy.route(3, response, peers)
        self.assertEqual([response], response_deliveries[2])

    def test_start_creates_distinct_switch_peers_and_guest_endpoints(self):
        boundary = NativeProcessBoundary(Path("/attempt"), Path("/controller"))
        boundary.port = 34001
        created = []

        def popen(command, **kwargs):
            process = _Process(pid=100 + len(created))
            created.append((command, kwargs, process))
            return process

        with (
            mock.patch(
                "homelab.vm.windows_identity_run.subprocess.Popen",
                side_effect=popen),
            mock.patch(
                "homelab.vm.windows_identity_run.wait_for_switch_port"),
        ):
            boundary._start_dependency("update-source")
            boundary._start_dependency("optional-storage")
        self.assertNotEqual(
            boundary.processes["update-source"],
            boundary.processes["optional-storage"],
        )
        self.assertEqual(
            ("10.1.31.3", 31338),
            boundary.dependency_endpoints["update-source"],
        )
        self.assertEqual(
            ("10.1.31.4", 31339),
            boundary.dependency_endpoints["optional-storage"],
        )
        self.assertIn("update-source", created[0][0])
        self.assertIn("optional-storage", created[1][0])
        self.assertEqual([], list(created[0][1].get("pass_fds", ())))
        boundary.processes.clear()

    def test_failed_switch_port_readiness_reaps_new_dependency(self):
        boundary = NativeProcessBoundary(Path("/attempt"), Path("/controller"))
        boundary.port = 34001
        process = _Process()

        def terminate(children):
            process.returncode = -15
            return []

        with (
            mock.patch(
                "homelab.vm.windows_identity_run.subprocess.Popen",
                return_value=process),
            mock.patch(
                "homelab.vm.windows_identity_run.wait_for_switch_port",
                side_effect=WindowsIdentityRunError("not ready")),
            mock.patch(
                "homelab.vm.windows_identity_run.terminate_children",
                side_effect=terminate),
        ):
            with self.assertRaisesRegex(WindowsIdentityRunError, "not ready"):
                boundary._start_dependency("update-source")
        self.assertNotIn("update-source", boundary.processes)
        self.assertNotIn("update-source", boundary.dependency_endpoints)

    def test_switch_declares_pinned_dependency_ports(self):
        with tempfile.TemporaryDirectory() as name:
            attempt = Path(name) / "attempt"
            attempt.mkdir()
            boundary = NativeProcessBoundary(
                attempt, Path(name) / "controller")
            listener = mock.Mock()
            listener.getsockname.return_value = ("127.0.0.1", 34001)
            listener.fileno.return_value = 9
            commands = []

            def popen(command, **_kwargs):
                commands.append(command)
                return _Process(len(commands))

            with (
                mock.patch.object(boundary, "_validate"),
                mock.patch(
                    "homelab.vm.windows_identity_run.socket.socket",
                    return_value=listener),
                mock.patch(
                    "homelab.vm.windows_identity_run.subprocess.Popen",
                    side_effect=popen),
                mock.patch(
                    "homelab.vm.windows_identity_run.wait_for_switch_port"),
                mock.patch(
                    "homelab.vm.windows_identity_run.switch_command",
                    return_value=["switch"]),
                mock.patch(
                    "homelab.vm.windows_identity_run.gateway_command",
                    return_value=["gateway"]),
            ):
                boundary.start_switch()
            switch = commands[0]
            for role, spec in DEPENDENCIES.items():
                self.assertIn(
                    f"{role}={bytes(spec['mac']).hex(':')}", switch)
            boundary.processes.clear()

    @mock.patch("homelab.vm.windows_identity_run.terminate_children")
    def test_windows_teardown_reaps_dependencies_before_guest(self, terminate):
        boundary = NativeProcessBoundary(Path("/attempt"), Path("/controller"))
        roles = ("optional-storage", "update-source", "windows")
        processes = []
        for offset, role in enumerate(roles):
            process = _Process(100 + offset)
            processes.append(process)
            boundary.processes[role] = process
        terminate.side_effect = lambda selected: (
            [setattr(process, "returncode", -15) for process in selected]
            and []
        )
        boundary.dependency_endpoints = {
            role: (str(spec["ip"]), int(spec["port"]))
            for role, spec in DEPENDENCIES.items()
        }

        boundary.stop_windows()

        self.assertEqual([
            mock.call(processes[:2]),
            mock.call(processes[2:]),
        ], terminate.call_args_list)
        self.assertEqual({}, boundary.processes)
        self.assertEqual({}, boundary.dependency_endpoints)


if __name__ == "__main__":
    unittest.main()
