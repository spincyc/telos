"""One-use private Windows domain-join media contracts."""

import json
from pathlib import Path
import tempfile
import unittest

from homelab.vm.windows_join_iso import (
    JOIN_DEVICE,
    JoinMediaChannel,
    WindowsJoinIsoError,
    build_join_iso,
    launch_join_command,
)


NONCE = "ab" * 16
MATERIAL = {
    "nonce": NONCE,
    "domain": "ad.example.test",
    "username": "join-operator",
    "password": "private value",
}


class FakeQmp:
    def __init__(self, fail_at=None):
        self.calls = []
        self.fail_at = fail_at

    def execute(self, command, arguments=None):
        self.calls.append((command, arguments))
        if command == self.fail_at:
            raise RuntimeError("sensitive qmp detail")
        return {}


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
            script.index("Restart-Computer"),
        ]
        self.assertEqual(sorted(positions), positions)
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
                ["blockdev-add", "device_add", "device_del", "blockdev-del"],
                [call[0] for call in qmp.calls])
            self.assertEqual([
                ("deleted", JOIN_DEVICE, True),
                ("released", f"TELOS_JOIN_MEDIA_DESTROYED {NONCE}", False),
            ], events)

    def test_changed_inode_or_qmp_failure_retains_cleanup_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            channel = JoinMediaChannel(FakeQmp(), iso, NONCE)
            channel.attach()
            original = root / "original"
            iso.rename(original)
            iso.write_bytes(b"replacement")
            iso.chmod(0o600)
            marker = json.dumps({
                "schema_version": 1,
                "event": "join-material-loaded",
                "nonce": NONCE,
            })
            released = []
            with self.assertRaisesRegex(
                    WindowsJoinIsoError, "identity changed"):
                channel.release_after_marker(
                    marker, await_device_deleted=lambda _: None,
                    send_release=released.append)
            self.assertFalse(channel.destroyed)
            self.assertFalse(channel.attached)
            self.assertFalse(channel.node_added)
            self.assertEqual([], released)
            self.assertTrue(iso.exists())
            self.assertTrue(original.exists())

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

    def test_post_reboot_static_probe_is_required_for_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            channel = JoinMediaChannel(FakeQmp(), iso, NONCE)
            channel.destroyed = True
            proof = channel.prove_join_and_reboot(
                lambda: {
                    "schema_version": 1,
                    "boot_completed": True,
                    "domain_joined": True,
                    "domain": "ad.example.test",
                },
                expected_domain="ad.example.test",
            )
            self.assertTrue(proof["join_media_destroyed"])
            self.assertTrue(proof["joined_after_reboot"])
            with self.assertRaisesRegex(WindowsJoinIsoError, "proof"):
                channel.prove_join_and_reboot(
                    lambda: {
                        "schema_version": 1,
                        "boot_completed": False,
                        "domain_joined": True,
                        "domain": "ad.example.test",
                    },
                    expected_domain="ad.example.test",
                )


if __name__ == "__main__":
    unittest.main()
