"""One-use private Windows domain-join media contracts."""

import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock

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
from homelab.vm.windows_public_command import MAX_PUBLIC_COMMAND_CHARS


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
            "TelosJoin.ps1"
        ).read_text(encoding="utf-8")
        positions = [
            script.index("ConvertTo-SecureString"),
            script.index('"join-material-loaded"'),
            script.index("TELOS_JOIN_MEDIA_DESTROYED"),
            script.index("Add-Computer"),
            script.index("Add-LocalGroupMember"),
            script.rindex("Get-LocalGroupMember"),
            script.index("New-ItemProperty"),
            script.index("Get-ItemPropertyValue"),
            script.index("generic logon policy verification failed"),
            script.index('"join-reboot-ready"'),
            script.index("TELOS_JOIN_REBOOT_ACK"),
            script.index('"join-reboot-accepted"'),
            script.index("$serial.Close()"),
            script.index("Restart-Computer"),
        ]
        self.assertEqual(sorted(positions), positions)
        self.assertNotIn("Domain Admins", script)
        self.assertNotIn("Add-ADGroupMember", script)
        self.assertIn("'S-1-5-32-544'", script)
        self.assertIn(
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'",
            script,
        )
        self.assertIn("'DontDisplayLastUserName'", script)
        self.assertIn("-PropertyType DWord -Value 1 -Force", script)
        self.assertNotIn("Set-ItemProperty", script)
        self.assertIn("generic logon policy mutation failed", script)
        self.assertIn("generic logon policy readback failed", script)
        self.assertLess(
            script.index("New-ItemProperty"),
            script.index("Get-ItemPropertyValue"),
        )
        command = launch_join_command()
        self.assertIn("TELOS_JOIN", command)
        self.assertLessEqual(len(command), MAX_PUBLIC_COMMAND_CHARS)
        self.assertIn("1..40", command)
        self.assertIn("|? DriveLetter", command)
        self.assertIn(
            "switch($v.Count){0{sleep 1}1{$d=$v[0]}default{throw 2}}",
            command,
        )
        self.assertEqual(1, command.count("&("))
        self.assertGreater(command.index("&("), command.index("};if(!$d)"))
        self.assertNotIn("Select-Object -First 1", command)
        self.assertIn(
            "$volumes.Count -ne 1",
            script,
        )
        self.assertLess(
            script.index("Where-Object DriveLetter"),
            script.index("$volumes.Count -ne 1"),
        )
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
            guest_errors = []
            guest_thread = None

            def launch(command):
                nonlocal guest_thread
                launched.append(command)
                guest.sendall((marker + "\n").encode("ascii"))
                def complete_join():
                    try:
                        release = guest.recv(256).decode("ascii")
                        self.assertEqual(
                            f"TELOS_JOIN_MEDIA_DESTROYED {NONCE}\n", release)
                        guest.sendall((json.dumps({
                            "schema_version": 1,
                            "event": "join-reboot-ready",
                            "nonce": NONCE,
                        }) + "\n").encode("ascii"))
                        self.assertEqual(
                            f"TELOS_JOIN_REBOOT_ACK {NONCE}\n",
                            guest.recv(256).decode("ascii"),
                        )
                        guest.sendall((json.dumps({
                            "schema_version": 1,
                            "event": "join-reboot-accepted",
                            "nonce": NONCE,
                        }) + "\n").encode("ascii"))
                    except BaseException as error:
                        guest_errors.append(error)
                guest_thread = threading.Thread(
                    target=complete_join, daemon=True)
                guest_thread.start()

            execute_join_channel(
                channel=channel,
                serial=serial,
                launch_guest=launch,
                await_device_deleted=lambda _: None,
            )
            guest_thread.join(timeout=1)
            self.assertFalse(guest_thread.is_alive())
            self.assertFalse(guest_errors)
            self.assertEqual(1, len(launched))
            self.assertIs(JoinMediaState.REBOOT_ACCEPTED, channel.state)
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
                def complete_join():
                    guest.recv(256)
                    guest.sendall((json.dumps({
                        "schema_version": 1,
                        "event": "join-reboot-ready",
                        "nonce": NONCE,
                    }) + "\n").encode("ascii"))
                    guest.recv(256)
                    guest.sendall((json.dumps({
                        "schema_version": 1,
                        "event": "join-reboot-accepted",
                        "nonce": NONCE,
                    }) + "\n").encode("ascii"))
                threading.Thread(target=complete_join, daemon=True).start()

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

    def test_invalid_post_reboot_proof_has_result_coordinate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            channel = JoinMediaChannel(FakeQmp(), iso, NONCE)
            channel.state = JoinMediaState.REBOOT_ACCEPTED
            with self.assertRaises(WindowsJoinIsoError) as caught:
                channel.prove_join_and_reboot(
                    lambda: {"private": "invalid"},
                    expected_domain="ad.example.test",
                )
        self.assertEqual("result", caught.exception.coordinate.phase)
        self.assertEqual(
            "WindowsJoinIsoError",
            caught.exception.coordinate.error_type,
        )
        self.assertNotIn("private", str(caught.exception))

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

    def test_reboot_ready_result_is_exact_nonce_bound_and_post_release(self):
        channel = JoinMediaChannel(FakeQmp(), Path("unused"), NONCE)
        ready = json.dumps({
            "schema_version": 1,
            "event": "join-reboot-ready",
            "nonce": NONCE,
        })
        with self.assertRaisesRegex(
                WindowsJoinIsoError, "cannot precede"):
            channel.accept_reboot_ready(ready)
        channel.state = JoinMediaState.RELEASED
        for invalid in (
            "{}",
            json.dumps({
                "schema_version": 1,
                "event": "join-reboot-ready",
                "nonce": "cd" * 16,
            }),
            json.dumps({
                "schema_version": 1,
                "event": "join-reboot-ready",
                "nonce": NONCE,
                "password": "must-not-be-accepted",
            }),
        ):
            with self.assertRaisesRegex(WindowsJoinIsoError, "invalid"):
                channel.accept_reboot_ready(invalid)
        channel.accept_reboot_ready(ready)
        self.assertIs(JoinMediaState.REBOOT_READY, channel.state)
        accepted = json.dumps({
            "schema_version": 1,
            "event": "join-reboot-accepted",
            "nonce": NONCE,
        })
        for invalid in (
            "{}",
            json.dumps({
                "schema_version": 1,
                "event": "join-reboot-accepted",
                "nonce": "cd" * 16,
            }),
            json.dumps({
                "schema_version": 1,
                "event": "join-reboot-accepted",
                "nonce": NONCE,
                "extra": True,
            }),
        ):
            with self.assertRaisesRegex(WindowsJoinIsoError, "invalid"):
                channel.accept_reboot_confirmation(invalid)
        channel.accept_reboot_confirmation(accepted)
        self.assertIs(JoinMediaState.REBOOT_ACCEPTED, channel.state)

    def test_guest_failure_result_has_allowlisted_secret_free_coordinate(self):
        channel = JoinMediaChannel(FakeQmp(), Path("unused"), NONCE)
        channel.state = JoinMediaState.RELEASED
        failure = json.dumps({
            "schema_version": 1,
            "event": "join-reboot-failed",
            "nonce": NONCE,
            "phase": "policy-readback",
        })
        with self.assertRaises(WindowsJoinIsoError) as caught:
            channel.accept_reboot_ready(failure)
        self.assertEqual(
            "result-guest-policy-readback",
            caught.exception.coordinate.phase,
        )
        self.assertNotIn(NONCE, str(caught.exception))
        channel.state = JoinMediaState.RELEASED
        reboot_ack_failure = json.dumps({
            "schema_version": 1,
            "event": "join-reboot-failed",
            "nonce": NONCE,
            "phase": "reboot-ack",
        })
        with self.assertRaises(WindowsJoinIsoError) as caught:
            channel.accept_reboot_ready(reboot_ack_failure)
        self.assertEqual(
            "result-guest-reboot-ack",
            caught.exception.coordinate.phase,
        )

    def test_malformed_result_has_parse_coordinate_and_retains_serial(self):
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
                def reject():
                    guest.recv(256)
                    guest.sendall(b'{"event":"unexpected"}\n')
                threading.Thread(target=reject, daemon=True).start()

            with self.assertRaises(WindowsJoinIsoError) as caught:
                execute_join_channel(
                    channel=channel,
                    serial=serial,
                    launch_guest=launch,
                    await_device_deleted=lambda _: None,
                )
            self.assertEqual("result-parse", caught.exception.coordinate.phase)
            self.assertEqual(
                "WindowsJoinIsoError",
                caught.exception.coordinate.error_type,
            )
            self.assertFalse(serial.closed)
            self.assertIs(JoinMediaState.RELEASED, channel.state)
            serial.close()
            guest.close()

    def test_result_timeout_has_receive_coordinate_and_no_reboot_ready(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            channel = JoinMediaChannel(FakeQmp(), iso, NONCE)
            host, guest = socket.socketpair()
            serial = DuplexJoinSerial(host, timeout=0.05)
            marker = json.dumps({
                "schema_version": 1,
                "event": "join-material-loaded",
                "nonce": NONCE,
            })

            def launch(_command):
                guest.sendall((marker + "\n").encode("ascii"))
                threading.Thread(
                    target=lambda: guest.recv(256), daemon=True).start()

            with self.assertRaises(WindowsJoinIsoError) as caught:
                execute_join_channel(
                    channel=channel,
                    serial=serial,
                    launch_guest=launch,
                    await_device_deleted=lambda _: None,
                )
            self.assertEqual(
                "result-receive", caught.exception.coordinate.phase)
            self.assertEqual("TimeoutError", caught.exception.coordinate.error_type)
            self.assertIs(JoinMediaState.RELEASED, channel.state)
            self.assertFalse(serial.closed)
            serial.close()
            guest.close()

    def test_reboot_ack_failure_is_typed_and_retains_serial_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            channel = JoinMediaChannel(FakeQmp(), iso, NONCE)

            class AckFailureSerial:
                closed = False

                def read_marker(self):
                    return json.dumps({
                        "schema_version": 1,
                        "event": "join-material-loaded",
                        "nonce": NONCE,
                    })

                def send_release(self, _line):
                    return None

                def read_result(self):
                    return json.dumps({
                        "schema_version": 1,
                        "event": "join-reboot-ready",
                        "nonce": NONCE,
                    })

                def send_reboot_ack(self, _nonce):
                    raise BrokenPipeError("private detail")

                def close(self):
                    self.closed = True

            serial = AckFailureSerial()
            with self.assertRaises(WindowsJoinIsoError) as caught:
                execute_join_channel(
                    channel=channel,
                    serial=serial,
                    launch_guest=lambda _: None,
                    await_device_deleted=lambda _: None,
                )
            self.assertEqual("result-ack", caught.exception.coordinate.phase)
            self.assertEqual("OSError", caught.exception.coordinate.error_type)
            self.assertNotIn("private detail", str(caught.exception))
            self.assertFalse(serial.closed)
            self.assertIs(JoinMediaState.REBOOT_READY, channel.state)

    def test_accepted_confirmation_receive_and_parse_failures_are_typed(self):
        ready = json.dumps({
            "schema_version": 1,
            "event": "join-reboot-ready",
            "nonce": NONCE,
        })
        cases = (
            (
                TimeoutError(),
                "accepted-receive",
                "TimeoutError",
            ),
            (
                json.dumps({
                    "schema_version": 1,
                    "event": "join-reboot-accepted",
                    "nonce": "cd" * 16,
                }),
                "accepted-parse",
                "WindowsJoinIsoError",
            ),
        )
        for final_result, phase, error_type in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                root = self.private_root(temporary)
                iso = root / "join.iso"
                iso.write_bytes(b"private")
                iso.chmod(0o600)
                channel = JoinMediaChannel(FakeQmp(), iso, NONCE)

                class ConfirmationSerial:
                    closed = False

                    def __init__(self):
                        self.results = iter((ready, final_result))

                    def read_marker(self):
                        return json.dumps({
                            "schema_version": 1,
                            "event": "join-material-loaded",
                            "nonce": NONCE,
                        })

                    def send_release(self, _line):
                        return None

                    def read_result(self):
                        result = next(self.results)
                        if isinstance(result, BaseException):
                            raise result
                        return result

                    def send_reboot_ack(self, _nonce):
                        return None

                    def close(self):
                        self.closed = True

                serial = ConfirmationSerial()
                with self.assertRaises(WindowsJoinIsoError) as caught:
                    execute_join_channel(
                        channel=channel,
                        serial=serial,
                        launch_guest=lambda _: None,
                        await_device_deleted=lambda _: None,
                    )
                self.assertEqual(phase, caught.exception.coordinate.phase)
                self.assertEqual(
                    error_type, caught.exception.coordinate.error_type)
                self.assertFalse(serial.closed)
                self.assertIs(JoinMediaState.REBOOT_READY, channel.state)

    def test_duplex_serial_uses_one_absolute_marker_release_deadline(self):
        connection = mock.Mock()
        connection.recv.side_effect = [
            b"m", b"a", b"r", b"k", b"e", b"r", b"\n"]
        clock = mock.Mock(side_effect=[
            0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 1.01])
        serial = DuplexJoinSerial(
            connection, maximum_line=64, timeout=1.0, clock=clock)

        self.assertEqual("marker", serial.read_marker())
        with self.assertRaisesRegex(WindowsJoinIsoError, "deadline expired"):
            serial.send_release("public")

        connection.sendall.assert_not_called()
        self.assertAlmostEqual(
            0.9, connection.settimeout.call_args_list[0].args[0])

    def test_post_reboot_static_probe_is_required_for_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            channel = JoinMediaChannel(FakeQmp(), iso, NONCE)
            channel.destroyed = True
            channel.state = JoinMediaState.REBOOT_ACCEPTED
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
            with self.assertRaises(WindowsJoinIsoError) as caught:
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
            self.assertEqual("result", caught.exception.coordinate.phase)


if __name__ == "__main__":
    unittest.main()
