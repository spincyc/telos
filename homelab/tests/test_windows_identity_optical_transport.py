"""System contract for inbox-driver Windows identity media transport."""

import json
from pathlib import Path
import tempfile
import unittest

from homelab.vm.windows_credential_action_iso import (
    ACTION_DEVICE,
    CredentialActionMediaChannel,
    WindowsCredentialActionError,
)
from homelab.vm.windows_join_iso import JOIN_DEVICE, JoinMediaChannel


NONCE = "ab" * 16


class ReservingQmp:
    """Minimal QMP model that enforces one reserved USB port."""

    def __init__(self):
        self.parent = None
        self.child = None
        self.calls = []
        self.backend_open = False

    def execute(self, command, arguments=None):
        self.calls.append((command, arguments))
        if command == "device_add":
            if arguments["driver"] == "usb-bot":
                if (
                    arguments["bus"] != "identityusb.0"
                    or arguments["port"] != "1"
                    or self.parent is not None
                ):
                    raise RuntimeError("reserved port is occupied")
                self.parent = arguments["id"]
            elif arguments["driver"] == "scsi-cd":
                if (
                    self.parent is None
                    or arguments["bus"] != f"{self.parent}.0"
                    or self.child is not None
                ):
                    raise RuntimeError("wrong optical child")
                self.child = arguments["id"]
            else:
                raise RuntimeError("wrong private media device")
        elif command == "device_del":
            if arguments["id"] == self.child:
                self.child = None
            elif arguments["id"] == self.parent and self.child is None:
                self.parent = None
            else:
                raise RuntimeError("wrong device deletion")
        elif command == "blockdev-add":
            self.backend_open = True
        elif command == "blockdev-del":
            self.backend_open = False
        return {}

    def holds_inode(self, _device, _inode):
        return self.backend_open


class WindowsIdentityOpticalTransportTests(unittest.TestCase):
    def test_join_and_credential_media_use_reserved_port_sequentially(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private"
            root.mkdir(mode=0o700)
            join_iso = root / "join.iso"
            action_iso = root / "action.iso"
            for path in (join_iso, action_iso):
                path.write_bytes(b"private")
                path.chmod(0o600)
            qmp = ReservingQmp()
            join = JoinMediaChannel(qmp, join_iso, NONCE)
            action = CredentialActionMediaChannel(qmp, action_iso, NONCE)

            join.attach()
            with self.assertRaisesRegex(
                    WindowsCredentialActionError, "attach failed"):
                action.attach()
            self.assertEqual(JOIN_DEVICE, qmp.child)
            # The failed attach owns only its backend; cleanup must not touch
            # the join device occupying the reserved port.
            action.cleanup(await_device_deleted=lambda _: None)

            join.release_after_marker(
                json.dumps({
                    "schema_version": 1,
                    "event": "join-material-loaded",
                    "nonce": NONCE,
                }),
                await_device_deleted=lambda device:
                self.assertIn(device, {JOIN_DEVICE, "telos-join-bot"}),
                send_release=lambda _: None,
            )
            self.assertIsNone(qmp.parent)
            self.assertIsNone(qmp.child)

            action_iso.write_bytes(b"private")
            action_iso.chmod(0o600)
            action = CredentialActionMediaChannel(
                qmp, action_iso, NONCE)
            action.attach()
            action.release_after_marker(
                json.dumps({
                    "schema_version": 1,
                    "event": "credential-material-loaded",
                    "nonce": NONCE,
                }),
                await_device_deleted=lambda device:
                self.assertIn(
                    device,
                    {ACTION_DEVICE, "telos-credential-action-bot"}),
                send_release=lambda _: None,
            )
            self.assertIsNone(qmp.parent)
            self.assertIsNone(qmp.child)
            self.assertFalse(join_iso.exists())
            self.assertFalse(action_iso.exists())


if __name__ == "__main__":
    unittest.main()
