import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from homelab.vm.windows_control_serial import (
    MAX_RECORD_BYTES,
    WindowsControlSerialError,
    attach_qemu_serial,
    control_probe,
    fault_reachability_fields,
    parse_probe_record,
    receive_probe_record,
)


def record(action="domain-state"):
    observations = {
        "domain-state": {
            "part_of_domain": True,
            "domain": "FACTORY.TEST",
            "secure_channel": True,
        },
        "cached-logon-policy": {
            "configured": True,
            "cached_logon_count": 2,
        },
        "dependency-reachability": {
            "update_source_reachable": False,
            "optional_storage_reachable": True,
            "optional_storage_authorization_denied": True,
        },
    }
    return {
        "schema_version": 1,
        "action": action,
        "result": "pass",
        "observed_at": "2026-07-28T15:00:00Z",
        "observation": observations[action],
    }


class WindowsControlSerialTests(unittest.TestCase):
    def test_qemu_serial_uses_private_socket_without_mutating_source_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            source = ["qemu-system-x86_64", "-serial", "stdio", "-m", "8G"]
            result = attach_qemu_serial(source, root / "control.sock")
            self.assertEqual("stdio", source[source.index("-serial") + 1])
            self.assertEqual(
                "chardev:telosidentity",
                result[result.index("-serial") + 1])
            joined = " ".join(result)
            self.assertIn("server=on,wait=off", joined)
            self.assertIn(str(root / "control.sock"), joined)
            self.assertNotIn("password", joined.casefold())
            self.assertNotIn("credential", joined.casefold())

    def test_qemu_serial_rejects_unsafe_runtime_and_ambiguous_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            with self.assertRaisesRegex(
                    WindowsControlSerialError, "private"):
                attach_qemu_serial(
                    ["qemu", "-serial", "stdio"], root / "serial.sock")
            root.chmod(0o700)
            (root / "serial.sock").write_bytes(b"occupied")
            with self.assertRaisesRegex(
                    WindowsControlSerialError, "absent"):
                attach_qemu_serial(
                    ["qemu", "-serial", "stdio"], root / "serial.sock")
            with self.assertRaisesRegex(
                    WindowsControlSerialError, "exactly one"):
                attach_qemu_serial(["qemu"], root / "other.sock")
            with self.assertRaisesRegex(
                    WindowsControlSerialError, "QEMU-safe"):
                attach_qemu_serial(
                    ["qemu", "-serial", "stdio"], root / "bad,path.sock")

    def test_launch_is_manifest_allowlisted_and_contains_no_input_value(self):
        probe = control_probe("domain-state")
        self.assertEqual("domain-state", probe.action)
        self.assertIn("-Action 'domain-state'", probe.command)
        with self.assertRaisesRegex(
                WindowsControlSerialError, "not allowlisted"):
            control_probe("domain-state'; Write-Host private")

    def test_parser_accepts_only_exact_action_specific_public_schema(self):
        encoded = json.dumps(record(), separators=(",", ":")).encode() + b"\n"
        self.assertEqual(
            "FACTORY.TEST",
            parse_probe_record(encoded, "domain-state")["observation"]["domain"])
        for mutation in (
            lambda value: value.update(action="update-policy"),
            lambda value: value.update(secret="must-not-pass"),
            lambda value: value["observation"].update(extra=True),
        ):
            candidate = record()
            mutation(candidate)
            with self.assertRaises(WindowsControlSerialError):
                parse_probe_record(
                    json.dumps(candidate).encode() + b"\n", "domain-state")
        with self.assertRaisesRegex(
                WindowsControlSerialError, "size limit"):
            parse_probe_record(b" " * MAX_RECORD_BYTES + b"\n", "domain-state")

    def test_parser_rejects_multiline_trailing_and_bool_as_integer(self):
        candidate = record("cached-logon-policy")
        candidate["observation"]["cached_logon_count"] = True
        with self.assertRaises(WindowsControlSerialError):
            parse_probe_record(
                json.dumps(candidate).encode() + b"\n",
                "cached-logon-policy")
        encoded = json.dumps(record()).encode()
        for invalid in (encoded, encoded + b"\n{}\n", encoded + b"\r\n"):
            with self.assertRaises(WindowsControlSerialError):
                parse_probe_record(invalid, "domain-state")

    def test_dependency_probe_maps_only_reachability_fault_fields(self):
        encoded = json.dumps(
            record("dependency-reachability")).encode() + b"\n"
        observed = parse_probe_record(
            encoded, "dependency-reachability")
        self.assertEqual(
            {"update_source_reachable": False},
            fault_reachability_fields(observed, "update-source-offline"))
        self.assertEqual(
            {"storage_reachable": True},
            fault_reachability_fields(observed, "optional-storage-offline"))
        self.assertEqual({
            "storage_reachable": True,
            "storage_access": "denied",
        }, fault_reachability_fields(
            observed, "optional-storage-access-denied"))
        self.assertEqual({
            "update_source_reachable": False,
            "optional_storage_reachable": True,
        }, fault_reachability_fields(
            observed, "combined-dependencies-offline"))
        self.assertEqual(
            {"optional_storage_reachable": True},
            fault_reachability_fields(observed, "windows-services-restored"))
        with self.assertRaisesRegex(
                WindowsControlSerialError, "no dependency"):
            fault_reachability_fields(observed, "controller-offline")

    def test_dependency_probe_mapping_rejects_unvalidated_shapes(self):
        candidate = record("dependency-reachability")
        candidate["observation"]["update_source_reachable"] = 0
        with self.assertRaisesRegex(
                WindowsControlSerialError, "schema"):
            fault_reachability_fields(candidate, "update-source-offline")

    def test_storage_denial_proof_is_distinct_from_an_outage(self):
        for reachable, denied in ((False, True), (True, False)):
            candidate = record("dependency-reachability")
            candidate["observation"]["optional_storage_reachable"] = reachable
            candidate["observation"][
                "optional_storage_authorization_denied"] = denied
            with self.assertRaisesRegex(
                    WindowsControlSerialError, "storage denial proof"):
                fault_reachability_fields(
                    candidate, "optional-storage-access-denied")

    def test_receiver_reads_one_record_from_unix_socket(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "serial.sock"
            ready = threading.Event()

            def serve():
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                    server.bind(str(path))
                    ready.set()
                    server.listen(1)
                    connection, _ = server.accept()
                    with connection:
                        connection.sendall(
                            json.dumps(record()).encode() + b"\n")

            thread = threading.Thread(target=serve)
            thread.start()
            self.assertTrue(ready.wait(2))
            observed = receive_probe_record(
                path, "domain-state", timeout=2)
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertTrue(observed["observation"]["secure_channel"])


if __name__ == "__main__":
    unittest.main()
