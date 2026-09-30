"""Contracts for the bounded private Windows installation lifecycle."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from homelab.vm import windows_install_run


class WindowsInstallRunTests(unittest.TestCase):
    def bundle(self, root: Path) -> Path:
        root.mkdir(mode=0o700)
        disk = root / "windows.qcow2"
        for name in ("windows.qcow2", "OVMF_VARS.fd", "publication.iso"):
            (root / name).write_bytes(name.encode())
        command = [
            "qemu", "-drive",
            f"if=none,id=osdisk,file={disk.resolve()}",
            "-device", "nvme,drive=osdisk,serial=TELOS-WIN-0001",
        ]
        import hashlib
        digest = hashlib.sha256(
            json.dumps(command, separators=(",", ":")).encode()).hexdigest()
        (root / "authorization.json").write_text(json.dumps({
            "authorization": {
                "disk": {"disk": "record"},
                "disk_serial": "TELOS-WIN-0001",
                "qemu_argv_sha256": digest,
                "release_version": "20260727.005",
            },
        }))
        (root / "qemu-command.json").write_text(json.dumps({"argv": command}))
        return root

    def test_default_is_dry_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            with mock.patch.object(
                    windows_install_run, "inspect_qcow2",
                    return_value={"disk": "record"}), mock.patch.object(
                        windows_install_run, "audit_qemu_disk_boundary"):
                self.assertEqual(windows_install_run.run(
                    bundle, controller_state=Path("/state"),
                    duration=60, apply=False), 0)
            self.assertFalse((bundle / "evidence").exists())

    def test_qmp_socket_path_is_recovered_from_the_authorized_argv(self):
        """The bundle-adjacent socket exceeded AF_UNIX from a deep checkout."""
        path = windows_install_run._qmp_socket_path([
            "qemu", "-qmp", "unix:/tmp/telos-win-abc/windows.qmp,"
            "server=on,wait=off",
        ])
        self.assertEqual(Path("/tmp/telos-win-abc/windows.qmp"), path)
        for argv in (
            ["qemu"],
            ["qemu", "-qmp"],
            ["qemu", "-qmp", "tcp:127.0.0.1:4444,server=on"],
            ["qemu", "-qmp", "unix:/tmp/x.qmp"],
            ["qemu", "-qmp", "unix:relative.qmp,server=on"],
            ["qemu", "-qmp", "unix:/" + "a" * 120 + ",server=on"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(RuntimeError):
                    windows_install_run._qmp_socket_path(argv)

    def test_long_bounded_run_uses_reduced_screenshot_cadence(self):
        self.assertEqual(windows_install_run.MAX_DURATION, 10800)
        self.assertEqual(windows_install_run._screenshot_interval(3600), 10)
        self.assertEqual(windows_install_run._screenshot_interval(7200), 30)

    def test_bundle_rejects_group_or_world_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            bundle.chmod(0o755)
            with mock.patch.object(
                    windows_install_run, "inspect_qcow2",
                    return_value={"disk": "record"}):
                with self.assertRaisesRegex(RuntimeError, "private"):
                    windows_install_run._bundle(bundle)

    def test_bundle_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            target = self.bundle(temporary / "target")
            link = temporary / "bundle"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "non-symlink"):
                windows_install_run._bundle(link)

    def test_bundle_rejects_changed_command_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            with mock.patch.object(
                    windows_install_run, "inspect_qcow2",
                    return_value={"disk": "record"}), mock.patch.object(
                        windows_install_run, "audit_qemu_disk_boundary"):
                authorization = json.loads(
                    (bundle / "authorization.json").read_text())
                authorization["authorization"]["disk"] = {"disk": "record"}
                authorization["authorization"]["qemu_argv_sha256"] = "0" * 64
                (bundle / "authorization.json").write_text(
                    json.dumps(authorization))
                with self.assertRaisesRegex(RuntimeError, "command differs"):
                    windows_install_run._bundle(bundle)

    def test_retained_logs_are_redacted_then_bounded_and_sized(self):
        # Check 15 fails any retained top-level file over the evidence limit.
        # Whatever stage the run reaches, both retained logs are redacted
        # whole and THEN bounded to it with both ends kept; a log already
        # within it is exactly the redacted log; result.json records sizes.
        from contextlib import nullcontext
        from homelab.vm import artifact_scan
        from homelab.vm.factory_verify import EVIDENCE_LIMIT
        from homelab.vm.simulation_evidence import redact
        secret = "windows-install-straddle-secret-9b41"
        filler = b"".join(
            b"setup serial line %07d\n" % index
            for index in range(3 * EVIDENCE_LIMIT // 25))
        # Overwritten where a byte cut the tail's length from the end splits
        # the label: the old order (cut, then redact) would keep the value.
        cut = len(filler) - EVIDENCE_LIMIT * 3 // 4
        line = b"\nPassword: " + secret.encode() + b"\n"
        big = filler[:cut - 4] + line + filler[cut - 4 + len(line):]
        self.assertIn(secret.encode(), redact(big[cut:]))
        small = b"publication ready\nsecret=" + secret.encode() + b"\n"
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            evidence = bundle / "evidence"

            def refuse_overlay(*_args, **_kwargs):
                (evidence / "controller-publication.log").write_bytes(small)
                (evidence / "workstation-serial.log").write_bytes(big)
                raise RuntimeError("controller overlay refused")

            with mock.patch.object(
                    windows_install_run, "inspect_qcow2",
                    return_value={"disk": "record"}), mock.patch.object(
                        windows_install_run, "audit_qemu_disk_boundary"), \
                    mock.patch.object(
                        windows_install_run, "_qmp_socket_path",
                        return_value=bundle / "windows.qmp"), \
                    mock.patch.object(
                        windows_install_run, "paths",
                        return_value={"disk": Path("/state/disk"),
                                      "vars": Path("/state/vars")}), \
                    mock.patch.object(windows_install_run, "socket"), \
                    mock.patch.object(
                        windows_install_run, "SignalGuard", nullcontext), \
                    mock.patch.object(
                        windows_install_run, "DisposableBootDisk",
                        side_effect=refuse_overlay):
                with self.assertRaisesRegex(RuntimeError, "overlay refused"):
                    windows_install_run.run(
                        bundle, controller_state=Path("/state"),
                        duration=600, apply=True)
            publication = (evidence / "controller-publication.log").read_bytes()
            serial = (evidence / "workstation-serial.log").read_bytes()
            self.assertLessEqual(len(serial), EVIDENCE_LIMIT)
            self.assertTrue(serial.startswith(b"setup serial line 0000000\n"))
            self.assertTrue(big.endswith(serial[-4096:]))
            self.assertEqual(serial.count(b"[telos evidence: "), 1)
            serial.decode("utf-8")
            self.assertNotIn(secret.encode(), serial)
            self.assertEqual(publication, redact(small))
            for name in ("controller-publication.log",
                         "workstation-serial.log"):
                self.assertEqual(
                    (evidence / name).stat().st_mode & 0o777, 0o600)
            result = json.loads((evidence / "result.json").read_text())
            self.assertEqual("fail", result["status"])
            recorded = result["retained_logs"]
            self.assertEqual(recorded["controller-publication.log"], {
                "original_bytes": len(small),
                "retained_bytes": len(publication), "elided_bytes": 0})
            self.assertEqual(
                recorded["workstation-serial.log"]["original_bytes"],
                len(big))
            self.assertEqual(
                recorded["workstation-serial.log"]["retained_bytes"],
                len(serial))
            self.assertGreater(
                recorded["workstation-serial.log"]["elided_bytes"],
                EVIDENCE_LIMIT)
            scan = artifact_scan.scan_paths(
                evidence,
                ["controller-publication.log", "workstation-serial.log"],
                known_secrets=[secret])
            self.assertEqual(
                scan.counters, dict.fromkeys(artifact_scan.CATEGORIES, 0),
                scan.findings)

    def test_private_publication_is_retained_0600_for_identity_handoff(self):
        # Owner decision 2026-08-12: the install hands the credential-bearing
        # recovery publication off to the identity recovery gate (which
        # destroys it) instead of destroying it here. It is retained mode-0600;
        # a symlink or a missing publication fails closed.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            publication = root / "publication.iso"
            publication.write_bytes(b"embedded private inputs")
            publication.chmod(0o644)
            self.assertIsNone(
                windows_install_run._retain_private_publication(publication))
            self.assertTrue(publication.is_file())
            self.assertEqual(publication.stat().st_mode & 0o777, 0o600)
            missing = root / "absent.iso"
            self.assertIn(
                "unavailable",
                windows_install_run._retain_private_publication(missing))
            target = root / "target"
            target.write_bytes(b"preserve")
            link = root / "link.iso"
            link.symlink_to(target)
            self.assertIn(
                "symlink",
                windows_install_run._retain_private_publication(link))
            self.assertTrue(target.exists())

    def test_acceptance_measurements_emit_only_what_this_gate_observed(self):
        block = windows_install_run.acceptance_measurements(
            canonical_unchanged=True, loopback_only_audited=True,
            windows_installed=True)
        self.assertEqual({
            "controller_disk_unchanged": True,
            "firmware_vars_unchanged": True,
            "external_connections_after_offline_gate": 0,
            # One run cannot order Windows against Arch; the field exists so an
            # aggregate driver concatenates the phases instead of inventing the
            # sequence, and it renders NOT-RUN rather than PASS on its own.
            "install_order": ["windows"],
        }, block)
        # guest_disks: windows.qcow2 is the PERSISTENT disk gate 7 overlays, so
        # "all guest disks disposable and run-scoped" is not true of this run
        # and a partial inventory would pass the check by omission.
        # login: native readiness is proved by a serial marker, never by
        # driving a login.
        for absent in (
            "guest_disks", "default_boot", "login", "host_network_changes",
            "optional_storage_absence_nonblocking", "artifact_scan",
        ):
            self.assertNotIn(absent, block)
        self.assertEqual({}, windows_install_run.acceptance_measurements(
            canonical_unchanged=False, loopback_only_audited=False,
            windows_installed=False))

    def test_qmp_connection_waits_for_socket_readiness(self):
        client = object()
        with mock.patch.object(
                windows_install_run.QmpClient, "connect",
                side_effect=[FileNotFoundError(), client]) as connect, \
                mock.patch.object(windows_install_run.time, "sleep"):
            self.assertIs(
                windows_install_run._connect_qmp(
                    Path("/private/windows.qmp"),
                    expected_peer_pid=731, timeout=1),
                client)
        self.assertEqual(connect.call_count, 2)
        self.assertEqual([
            mock.call(
                Path("/private/windows.qmp"), timeout=1,
                expected_peer_pid=731),
            mock.call(
                Path("/private/windows.qmp"), timeout=1,
                expected_peer_pid=731),
        ], connect.call_args_list)

    def test_lifecycle_requires_overlay_native_marker_and_one_pxe_boot(self):
        serial = "\n".join((
            'BdsDxe: loading Boot0003 "UEFI PXEv4"',
            'BdsDxe: starting Boot0003 "UEFI PXEv4"',
            "http://10.1.31.2/private/run-abc/boot.ipxe",
            "Using install.bat",
            "Using winpeshl.ini",
            "Windows Imaging Format bootloader",
            windows_install_run.NATIVE_READY_MARKER,
        ))
        windows_install_run._validate_lifecycle(serial)

        with self.assertRaisesRegex(RuntimeError, "exactly one PXE"):
            windows_install_run._validate_lifecycle(
                serial + '\nBdsDxe: starting Boot0003 "UEFI PXEv4"')
        with self.assertRaisesRegex(RuntimeError, "native Windows"):
            windows_install_run._validate_lifecycle(
                serial.replace(windows_install_run.NATIVE_READY_MARKER, ""))


if __name__ == "__main__":
    unittest.main()
