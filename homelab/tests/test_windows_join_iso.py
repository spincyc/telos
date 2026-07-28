"""One-use private Windows domain-join media contracts."""

import json
from pathlib import Path
import socket
import tempfile
import unittest

from homelab.vm.windows_join_iso import (
    DuplexJoinSerial,
    JOIN_DEVICE,
    JoinMediaChannel,
    JoinMediaState,
    WindowsJoinIsoError,
    build_join_iso,
    execute_join_and_prove,
    execute_join_channel,
    launch_join_command,
)


NONCE = "ab" * 16
MATERIAL = {
    "nonce": NONCE,
    "domain": "ad.example.test",
    "realm": "AD.EXAMPLE.TEST",
    "username": "join-operator",
    "password": "private value",
    "operator": "operator@AD.EXAMPLE.TEST",
}


class FakeQmp:
    def __init__(self, fail_at=None):
        self.calls = []
        self.fail_at = fail_at
        self.backend_open = False

    def execute(self, command, arguments=None):
        self.calls.append((command, arguments))
        if command == self.fail_at:
            raise RuntimeError("sensitive qmp detail")
        if command == "blockdev-add":
            self.backend_open = True
        elif command == "blockdev-del":
            self.backend_open = False
        return {}

    def holds_inode(self, _device, _inode):
        return self.backend_open


class WindowsJoinIsoTests(unittest.TestCase):
    def private_root(self, temporary):
        root = Path(temporary) / "private"
        root.mkdir(mode=0o700)
        return root

    def test_builder_keeps_secrets_out_of_argv_and_makes_private_iso(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            output = root / "join.iso"
            observed = {}

            def runner(command, *, check):
                self.assertTrue(check)
                observed["argv"] = command
                stage = Path(command[-1])
                observed["join"] = json.loads(
                    (stage / "join.json").read_text(encoding="utf-8"))
                Path(command[command.index("-o") + 1]).write_bytes(b"iso")

            build_join_iso(output, MATERIAL, runner=runner)
            argv = "\0".join(observed["argv"])
            for value in MATERIAL.values():
                self.assertNotIn(value, argv)
            self.assertEqual(MATERIAL["password"], observed["join"]["password"])
            self.assertEqual(0o600, output.stat().st_mode & 0o777)
            self.assertFalse(any(
                item.name.startswith(".windows-join-")
                for item in root.iterdir()))

    def test_builder_rejects_public_parent_links_and_bad_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            with self.assertRaisesRegex(WindowsJoinIsoError, "private"):
                build_join_iso(root / "join.iso", MATERIAL)
            private = self.private_root(temporary)
            linked = root / "linked"
            linked.symlink_to(private, target_is_directory=True)
            with self.assertRaisesRegex(WindowsJoinIsoError, "private"):
                build_join_iso(linked / "join.iso", MATERIAL)
            with self.assertRaisesRegex(WindowsJoinIsoError, "fields"):
                build_join_iso(
                    private / "join.iso", {**MATERIAL, "extra": "no"})
            with self.assertRaisesRegex(WindowsJoinIsoError, "realm"):
                build_join_iso(
                    private / "join.iso",
                    {**MATERIAL, "realm": "OTHER.EXAMPLE.TEST"})
            with self.assertRaisesRegex(WindowsJoinIsoError, "operator"):
                build_join_iso(
                    private / "join.iso",
                    {**MATERIAL, "operator": "operator@OTHER.EXAMPLE.TEST"})

    def test_script_has_load_marker_release_gate_join_and_reboot_order(self):
        script = Path(
            "homelab/vm/windows_join_control/"
            "Invoke-TelosDomainJoin.ps1"
        ).read_text(encoding="utf-8")
        positions = [
            script.index("ConvertTo-SecureString"),
            script.index('"join-material-loaded"'),
            script.index("TELOS_JOIN_MEDIA_DESTROYED"),
            script.index("Add-Computer"),
            script.index("Add-LocalGroupMember"),
            script.rindex("Get-LocalGroupMember"),
            script.index("Restart-Computer"),
        ]
        self.assertEqual(sorted(positions), positions)
        self.assertNotIn("Domain Admins", script)
        self.assertNotIn("Add-ADGroupMember", script)
        self.assertIn("'S-1-5-32-544'", script)
        command = launch_join_command()
        self.assertIn("TELOS_JOIN", command)
        for value in MATERIAL.values():
            self.assertNotIn(value, command)

    def test_host_destroys_exact_media_before_releasing_guest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            qmp = FakeQmp()
            channel = JoinMediaChannel(qmp, iso, NONCE)
            channel.attach()
            events = []
            marker = json.dumps({
                "schema_version": 1,
                "event": "join-material-loaded",
                "nonce": NONCE,
            })
            channel.release_after_marker(
                marker,
                await_device_deleted=lambda device: events.append(
                    ("deleted", device, iso.exists())),
                send_release=lambda line: events.append(
                    ("released", line, iso.exists())),
            )
            self.assertFalse(iso.exists())
            self.assertEqual(
                [
                    "blockdev-add", "device_add", "device_add", "qom-set",
                    "qom-set", "device_del", "device_del", "blockdev-del",
                ],
                [call[0] for call in qmp.calls])
            self.assertEqual({
                "driver": "usb-bot",
                "id": "telos-join-bot",
                "bus": "identityusb.0",
                "port": "1",
                "attached": False,
            }, qmp.calls[1][1])
            self.assertEqual({
                "driver": "scsi-cd",
                "id": JOIN_DEVICE,
                "bus": "telos-join-bot.0",
                "drive": "telos-join-media",
            }, qmp.calls[2][1])
            self.assertEqual([
                ("deleted", JOIN_DEVICE, True),
                ("deleted", "telos-join-bot", True),
                ("released", f"TELOS_JOIN_MEDIA_DESTROYED {NONCE}", False),
            ], events)
            self.assertIs(JoinMediaState.RELEASED, channel.state)

    def test_partial_attach_failure_retains_node_and_exact_iso_for_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            qmp = FakeQmp(fail_at="device_add")
            channel = JoinMediaChannel(qmp, iso, NONCE)
            with self.assertRaisesRegex(WindowsJoinIsoError, "attach failed"):
                channel.attach()
            self.assertTrue(channel.node_added)
            self.assertTrue(iso.exists())
            qmp.fail_at = None
            channel.cleanup(await_device_deleted=lambda _: None)
            self.assertFalse(channel.node_added)
            self.assertFalse(iso.exists())

    def test_renamed_original_is_destroyed_by_held_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"secret")
            iso.chmod(0o600)
            qmp = FakeQmp()
            channel = JoinMediaChannel(qmp, iso, NONCE)
            channel.attach()
            renamed = root / "renamed-secret.iso"
            iso.rename(renamed)
            iso.write_bytes(b"replacement")
            iso.chmod(0o600)
            marker = json.dumps({
                "schema_version": 1,
                "event": "join-material-loaded",
                "nonce": NONCE,
            })
            channel.release_after_marker(
                marker, await_device_deleted=lambda _: None,
                send_release=lambda _: None)
            self.assertFalse(renamed.exists())
            self.assertTrue(iso.exists())

    def test_failed_release_enters_retryable_destroyed_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"secret")
            iso.chmod(0o600)
            channel = JoinMediaChannel(FakeQmp(), iso, NONCE)
            channel.attach()
            marker = json.dumps({
                "schema_version": 1,
                "event": "join-material-loaded",
                "nonce": NONCE,
            })
            with self.assertRaisesRegex(WindowsJoinIsoError, "release failed"):
                channel.release_after_marker(
                    marker, await_device_deleted=lambda _: None,
                    send_release=lambda _: (_ for _ in ()).throw(
                        BrokenPipeError()))
            self.assertFalse(iso.exists())
            self.assertIs(
                JoinMediaState.DESTROYED_AWAITING_RELEASE, channel.state)
            sent = []
            channel.retry_release(sent.append)
            channel.retry_release(sent.append)
            self.assertEqual(
                [f"TELOS_JOIN_MEDIA_DESTROYED {NONCE}"], sent)
            self.assertIs(JoinMediaState.RELEASED, channel.state)

    def test_bad_marker_never_unplugs_or_releases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            qmp = FakeQmp()
            channel = JoinMediaChannel(qmp, iso, NONCE)
            channel.attach()
            before = list(qmp.calls)
            with self.assertRaisesRegex(WindowsJoinIsoError, "marker"):
                channel.release_after_marker(
                    "{}", await_device_deleted=lambda _: None,
                    send_release=lambda _: self.fail("must not release"))
            self.assertEqual(before, qmp.calls)
            self.assertTrue(iso.exists())

    def test_production_helper_uses_one_duplex_connection_for_both_directions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            channel = JoinMediaChannel(FakeQmp(), iso, NONCE)
            host, guest = socket.socketpair()
            serial = DuplexJoinSerial(host)
            marker = json.dumps({
                "schema_version": 1,
                "event": "join-material-loaded",
                "nonce": NONCE,
            })
            launched = []

            def launch(command):
                launched.append(command)
                guest.sendall((marker + "\n").encode("ascii"))

            execute_join_channel(
                channel=channel,
                serial=serial,
                launch_guest=launch,
                await_device_deleted=lambda _: None,
            )
            self.assertEqual(
                f"TELOS_JOIN_MEDIA_DESTROYED {NONCE}\n",
                guest.recv(256).decode("ascii"))
            self.assertEqual(1, len(launched))
            self.assertIs(JoinMediaState.RELEASED, channel.state)
            self.assertTrue(serial.closed)
            guest.close()

    def test_composition_closes_private_com1_before_public_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            channel = JoinMediaChannel(FakeQmp(), iso, NONCE)
            host, guest = socket.socketpair()
            serial = DuplexJoinSerial(host)
            marker = json.dumps({
                "schema_version": 1,
                "event": "join-material-loaded",
                "nonce": NONCE,
            })

            def launch(_command):
                guest.sendall((marker + "\n").encode("ascii"))

            proof = execute_join_and_prove(
                channel=channel,
                serial=serial,
                launch_guest=launch,
                await_device_deleted=lambda _: None,
                probe_after_reboot=lambda: {
                    "schema_version": 2,
                    "boot_completed": True,
                    "domain_joined": True,
                    "domain": "ad.example.test",
                    "operator": "operator@AD.EXAMPLE.TEST",
                    "operator_local_administrator": True,
                    **({"serial_was_closed": serial.closed}
                       if not serial.closed else {}),
                },
                expected_domain="ad.example.test",
            )
            self.assertTrue(proof["joined_after_reboot"])
            guest.close()

    def test_duplex_serial_bounds_marker_and_rejects_use_after_close(self):
        host, guest = socket.socketpair()
        serial = DuplexJoinSerial(host, maximum_line=64)
        guest.sendall(b"x" * 65 + b"\n")
        with self.assertRaisesRegex(WindowsJoinIsoError, "exceeds"):
            serial.read_marker()
        serial.close()
        with self.assertRaisesRegex(WindowsJoinIsoError, "closed"):
            serial.send_release("public")
        guest.close()

    def test_post_reboot_static_probe_is_required_for_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            channel = JoinMediaChannel(FakeQmp(), iso, NONCE)
            channel.destroyed = True
            channel.state = JoinMediaState.RELEASED
            proof = channel.prove_join_and_reboot(
                lambda: {
                    "schema_version": 2,
                    "boot_completed": True,
                    "domain_joined": True,
                    "domain": "ad.example.test",
                    "operator": "operator@AD.EXAMPLE.TEST",
                    "operator_local_administrator": True,
                },
                expected_domain="ad.example.test",
            )
            self.assertTrue(proof["join_media_destroyed"])
            self.assertTrue(proof["joined_after_reboot"])
            with self.assertRaisesRegex(WindowsJoinIsoError, "proof"):
                channel.prove_join_and_reboot(
                    lambda: {
                        "schema_version": 2,
                        "boot_completed": False,
                        "domain_joined": True,
                        "domain": "ad.example.test",
                        "operator": "operator@AD.EXAMPLE.TEST",
                        "operator_local_administrator": True,
                    },
                    expected_domain="ad.example.test",
                )


if __name__ == "__main__":
    unittest.main()
