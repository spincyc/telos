"""One-use Windows credential-action media contracts."""

import json
from pathlib import Path
import socket
import tempfile
import unittest

from homelab.vm.windows_credential_action_iso import (
    ACTION_DEVICE,
    ACTIONS,
    CredentialActionMediaChannel,
    CredentialActionMediaState,
    DuplexCredentialActionSerial,
    WindowsCredentialActionError,
    build_credential_action_iso,
    execute_credential_action,
    launch_credential_action_command,
    parse_action_result,
)


NONCE = "cd" * 16
MATERIAL = {
    "nonce": NONCE,
    "action": "cached-domain-login",
    "username": "acceptance-operator",
    "domain": "ad.example.test",
    "password": "private credential value",
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


class WindowsCredentialActionIsoTests(unittest.TestCase):
    def private_root(self, temporary):
        root = Path(temporary) / "private"
        root.mkdir(mode=0o700)
        return root

    def test_builder_keeps_all_material_out_of_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            output = root / "action.iso"
            observed = {}

            def runner(command, *, check):
                self.assertTrue(check)
                observed["argv"] = command
                stage = Path(command[-1])
                observed["material"] = json.loads(
                    (stage / "action.json").read_text(encoding="utf-8"))
                Path(command[command.index("-o") + 1]).write_bytes(b"iso")

            build_credential_action_iso(output, MATERIAL, runner=runner)
            argv = "\0".join(observed["argv"])
            for value in MATERIAL.values():
                self.assertNotIn(value, argv)
            self.assertEqual(MATERIAL["password"],
                             observed["material"]["password"])
            self.assertEqual(0o600, output.stat().st_mode & 0o777)
            self.assertFalse(any(
                item.name.startswith(".windows-credential-action-")
                for item in root.iterdir()))

    def test_builder_rejects_non_allowlisted_and_mismatched_domain_action(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            with self.assertRaisesRegex(
                    WindowsCredentialActionError, "allowlisted"):
                build_credential_action_iso(
                    root / "action.iso", {**MATERIAL, "action": "command"})
            with self.assertRaisesRegex(
                    WindowsCredentialActionError, "requires a domain"):
                build_credential_action_iso(
                    root / "action.iso", {**MATERIAL, "domain": "."})
            self.assertEqual(5, len(ACTIONS))

    def test_script_loads_then_waits_for_destruction_before_native_action(self):
        script = Path(
            "homelab/vm/windows_credential_action_control/"
            "Invoke-TelosCredentialAction.ps1"
        ).read_text(encoding="utf-8")
        positions = [
            script.index("$password = [string]$document.password"),
            script.index('"credential-material-loaded"'),
            script.index("TELOS_CREDENTIAL_ACTION_MEDIA_DESTROYED"),
            script.index("CreateProcessWithLogonW(\n        $username"),
        ]
        self.assertEqual(sorted(positions), positions)
        self.assertIn("logonFlags", script)
        self.assertIn("$username, $domain, $password, 1,", script)
        self.assertIn(
            "$action -eq 'uncached-domain-user-denied' -and\n"
            "                -not $controllerReachable -and "
            "$logonError -eq 1326",
            script)
        self.assertIn(
            "failure_classification = 'windows-logon-failure'", script)
        self.assertIn("Get-LocalGroupMember -SID $administratorSid", script)
        self.assertNotIn("WindowsBuiltInRole]::Administrator", script)
        self.assertIn(
            "$loginClock = [Diagnostics.Stopwatch]::StartNew()", script)
        self.assertIn(
            "$loginClock.Elapsed.TotalSeconds, 3", script)
        self.assertGreater(
            script.rindex("$loginClock.Stop()"),
            script.index("$childResult = Get-Content"))
        self.assertIn(
            "Test-Path -LiteralPath $env:USERPROFILE -PathType Container",
            script)
        self.assertIn(
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0'", script)
        self.assertIn("controller_reachable = [bool]$controllerReachable",
                      script)
        self.assertIn("gateway_reachable = [bool]$gatewayReachable", script)
        self.assertIn("cacheEvidence = 'offline-cache-proven'", script)
        self.assertIn("TerminateProcess(", script)
        self.assertLess(script.index("TerminateProcess("),
                        script.index("throw 'credential action timed out'"))
        command = launch_credential_action_command()
        for value in MATERIAL.values():
            self.assertNotIn(value, command)

    def test_exact_media_is_destroyed_before_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "action.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            qmp = FakeQmp()
            channel = CredentialActionMediaChannel(qmp, iso, NONCE)
            channel.attach()
            events = []
            channel.release_after_marker(
                json.dumps({
                    "schema_version": 1,
                    "event": "credential-material-loaded",
                    "nonce": NONCE,
                }),
                await_device_deleted=lambda device: events.append(
                    ("deleted", device, iso.exists())),
                send_release=lambda line: events.append(
                    ("released", line, iso.exists())),
            )
            self.assertEqual([
                ("deleted", ACTION_DEVICE, True),
                ("deleted", "telos-credential-action-bot", True),
                ("released",
                 f"TELOS_CREDENTIAL_ACTION_MEDIA_DESTROYED {NONCE}", False),
            ], events)
            self.assertEqual(
                [
                    "blockdev-add", "device_add", "device_add", "qom-set",
                    "qom-set", "device_del", "device_del", "blockdev-del",
                ],
                [call[0] for call in qmp.calls])
            self.assertEqual({
                "driver": "usb-bot",
                "id": "telos-credential-action-bot",
                "bus": "identityusb.0",
                "port": "1",
                "attached": False,
            }, qmp.calls[1][1])
            self.assertEqual({
                "driver": "scsi-cd",
                "id": ACTION_DEVICE,
                "bus": "telos-credential-action-bot.0",
                "drive": "telos-credential-action-media",
            }, qmp.calls[2][1])

    def test_partial_attach_and_cleanup_failure_retain_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "action.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            qmp = FakeQmp("device_add")
            channel = CredentialActionMediaChannel(qmp, iso, NONCE)
            with self.assertRaisesRegex(
                    WindowsCredentialActionError, "attach failed"):
                channel.attach()
            self.assertTrue(channel.node_added)
            qmp.fail_at = "blockdev-del"
            with self.assertRaisesRegex(
                    WindowsCredentialActionError, "cleanup failed"):
                channel.cleanup(await_device_deleted=lambda _: None)
            self.assertTrue(channel.node_added)
            self.assertTrue(iso.exists())

    def test_renamed_secret_inode_is_destroyed_without_unlinking_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "action.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            channel = CredentialActionMediaChannel(FakeQmp(), iso, NONCE)
            channel.attach()
            original = root / "original"
            iso.rename(original)
            iso.write_bytes(b"replacement")
            iso.chmod(0o600)
            channel.release_after_marker(
                json.dumps({
                    "schema_version": 1,
                    "event": "credential-material-loaded",
                    "nonce": NONCE,
                }),
                await_device_deleted=lambda _: None,
                send_release=lambda _: None,
            )
            self.assertTrue(channel.destroyed)
            self.assertTrue(iso.exists())
            self.assertFalse(original.exists())

    def test_failed_release_is_idempotently_retryable_after_destruction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "action.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            channel = CredentialActionMediaChannel(FakeQmp(), iso, NONCE)
            channel.attach()
            with self.assertRaisesRegex(
                    WindowsCredentialActionError, "release failed"):
                channel.release_after_marker(
                    json.dumps({
                        "schema_version": 1,
                        "event": "credential-material-loaded",
                        "nonce": NONCE,
                    }),
                    await_device_deleted=lambda _: None,
                    send_release=lambda _: (_ for _ in ()).throw(
                        BrokenPipeError()),
                )
            self.assertFalse(iso.exists())
            self.assertIs(
                CredentialActionMediaState.DESTROYED_AWAITING_RELEASE,
                channel.state)
            sent = []
            channel.retry_release(sent.append)
            channel.retry_release(sent.append)
            self.assertEqual([
                f"TELOS_CREDENTIAL_ACTION_MEDIA_DESTROYED {NONCE}",
            ], sent)

    def test_result_parser_accepts_only_strict_public_jsonl(self):
        result = {
            "schema_version": 1,
            "event": "credential-action-result",
            "nonce": NONCE,
            "action": MATERIAL["action"],
            "result": "pass",
            "principal": "AD\\acceptance-operator",
            "authenticated": True,
            "local_administrators_member": False,
            "authentication_type": "Kerberos",
            "authentication_semantics": "cached-domain",
            "cache_evidence": "offline-cache-proven",
            "login_elapsed_seconds": 1.25,
            "local_profile_available": True,
            "domain_reachable": False,
            "controller_reachable": False,
            "gateway_reachable": True,
            "failure_classification": "none",
        }
        parsed = parse_action_result(
            json.dumps(result) + "\n",
            nonce=NONCE, action=MATERIAL["action"],
            expected_principal="AD\\acceptance-operator",
            allowed_authentication_types=frozenset({"Kerberos"}))
        self.assertEqual(result, parsed)
        with self.assertRaisesRegex(
                WindowsCredentialActionError, "invalid"):
            parse_action_result(
                json.dumps(result), nonce=NONCE, action=MATERIAL["action"],
                expected_principal="AD\\acceptance-operator",
                allowed_authentication_types=frozenset({"Kerberos"}))
        for mutation in (
                {**result, "password": "leak"},
                {**result, "authenticated": 1},
                {**result, "login_elapsed_seconds": float("nan")},
                {**result, "controller_reachable": True},
                {**result, "nonce": "00" * 16}):
            with self.assertRaises(WindowsCredentialActionError):
                parse_action_result(
                    json.dumps(mutation) + "\n",
                    nonce=NONCE, action=MATERIAL["action"],
                    expected_principal="AD\\acceptance-operator",
                    allowed_authentication_types=frozenset({"Kerberos"}))

    def test_action_semantics_reject_network_or_membership_mismatch(self):
        base = {
            "schema_version": 1,
            "event": "credential-action-result",
            "nonce": NONCE,
            "action": "connected-domain-login",
            "result": "pass",
            "principal": "AD\\operator",
            "authenticated": True,
            "local_administrators_member": False,
            "authentication_type": "Kerberos",
            "authentication_semantics": "connected-domain",
            "cache_evidence": "online-interactive-logon",
            "login_elapsed_seconds": 0.75,
            "local_profile_available": True,
            "domain_reachable": False,
            "controller_reachable": False,
            "gateway_reachable": True,
            "failure_classification": "none",
        }
        with self.assertRaisesRegex(
                WindowsCredentialActionError, "measurement"):
            parse_action_result(
                json.dumps(base) + "\n", nonce=NONCE,
                action="connected-domain-login",
                expected_principal="AD\\operator",
                allowed_authentication_types=frozenset({"Kerberos"}))
        membership = {
            **base,
            "action": "operator-local-administrators-check",
            "domain_reachable": True,
            "controller_reachable": True,
        }
        with self.assertRaisesRegex(
                WindowsCredentialActionError, "Administrators membership"):
            parse_action_result(
                json.dumps(membership) + "\n", nonce=NONCE,
                action="operator-local-administrators-check",
                expected_principal="AD\\operator",
                allowed_authentication_types=frozenset({"Kerberos"}))

        unavailable_profile = {
            **base,
            "domain_reachable": True,
            "controller_reachable": True,
            "local_profile_available": False,
        }
        with self.assertRaisesRegex(
                WindowsCredentialActionError, "principal proof"):
            parse_action_result(
                json.dumps(unavailable_profile) + "\n", nonce=NONCE,
                action="connected-domain-login",
                expected_principal="AD\\operator",
                allowed_authentication_types=frozenset({"Kerberos"}))

    def test_uncached_denial_requires_offline_classified_failure(self):
        result = {
            "schema_version": 1,
            "event": "credential-action-result",
            "nonce": NONCE,
            "action": "uncached-domain-user-denied",
            "result": "pass",
            "principal": "AD\\never-cached",
            "authenticated": False,
            "local_administrators_member": False,
            "authentication_type": "None",
            "authentication_semantics": "domain-logon-denied",
            "cache_evidence": "offline-cache-miss-proven",
            "login_elapsed_seconds": 0.5,
            "local_profile_available": False,
            "domain_reachable": False,
            "controller_reachable": False,
            "gateway_reachable": True,
            "failure_classification": "windows-logon-failure",
        }
        self.assertEqual(result, parse_action_result(
            json.dumps(result) + "\n",
            nonce=NONCE,
            action="uncached-domain-user-denied",
            expected_principal="AD\\never-cached",
            allowed_authentication_types=frozenset()))
        for mutation in (
                {**result, "domain_reachable": True},
                {**result, "authenticated": True},
                {**result, "local_profile_available": True},
                {**result, "cache_evidence": "offline-cache-proven"},
                {**result, "failure_classification": "script-failure"},
                {**result, "result": "error"}):
            with self.assertRaises(WindowsCredentialActionError):
                parse_action_result(
                    json.dumps(mutation) + "\n",
                    nonce=NONCE,
                    action="uncached-domain-user-denied",
                    expected_principal="AD\\never-cached",
                    allowed_authentication_types=frozenset())

    def test_composition_uses_one_duplex_session_and_closes_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "action.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            channel = CredentialActionMediaChannel(FakeQmp(), iso, NONCE)
            host, guest = socket.socketpair()
            serial = DuplexCredentialActionSerial(host)
            result = {
                "schema_version": 1,
                "event": "credential-action-result",
                "nonce": NONCE,
                "action": MATERIAL["action"],
                "result": "pass",
                "principal": "AD\\acceptance-operator",
                "authenticated": True,
                "local_administrators_member": False,
                "authentication_type": "Kerberos",
                "authentication_semantics": "cached-domain",
                "cache_evidence": "offline-cache-proven",
                "login_elapsed_seconds": 1.25,
                "local_profile_available": True,
                "domain_reachable": False,
                "controller_reachable": False,
                "gateway_reachable": True,
                "failure_classification": "none",
            }

            def launch(_command):
                guest.sendall((json.dumps({
                    "schema_version": 1,
                    "event": "credential-material-loaded",
                    "nonce": NONCE,
                }) + "\n").encode())

            def guest_result():
                self.assertEqual(
                    f"TELOS_CREDENTIAL_ACTION_MEDIA_DESTROYED {NONCE}\n",
                    guest.recv(256).decode())
                guest.sendall((json.dumps(result) + "\n").encode())

            import threading
            worker = threading.Thread(target=guest_result)
            worker.start()
            observed = execute_credential_action(
                channel=channel,
                serial=serial,
                action=MATERIAL["action"],
                expected_principal="AD\\acceptance-operator",
                allowed_authentication_types=frozenset({"Kerberos"}),
                launch_guest=launch,
                await_device_deleted=lambda _: None,
            )
            worker.join()
            guest.close()
            self.assertEqual(result, observed)
            self.assertTrue(serial.closed)
            self.assertIs(CredentialActionMediaState.RELEASED, channel.state)

    def test_composition_closes_serial_and_cleans_media_on_result_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            iso = root / "action.iso"
            iso.write_bytes(b"private")
            iso.chmod(0o600)
            channel = CredentialActionMediaChannel(FakeQmp(), iso, NONCE)
            host, guest = socket.socketpair()
            serial = DuplexCredentialActionSerial(host)

            def launch(_command):
                guest.sendall((json.dumps({
                    "schema_version": 1,
                    "event": "credential-material-loaded",
                    "nonce": NONCE,
                }) + "\n").encode())

            def guest_result():
                guest.recv(256)
                guest.sendall(b"{}\n")

            import threading
            worker = threading.Thread(target=guest_result)
            worker.start()
            with self.assertRaisesRegex(
                    WindowsCredentialActionError, "schema"):
                execute_credential_action(
                    channel=channel, serial=serial,
                    action=MATERIAL["action"],
                    expected_principal="AD\\acceptance-operator",
                    allowed_authentication_types=frozenset({"Kerberos"}),
                    launch_guest=launch,
                    await_device_deleted=lambda _: None,
                )
            worker.join()
            guest.close()
            self.assertTrue(serial.closed)
            self.assertTrue(channel.destroyed)


if __name__ == "__main__":
    unittest.main()
