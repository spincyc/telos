"""Contracts for the bounded private Windows installation lifecycle."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from homelab.vm import windows_install_run


def make_bundle(root: Path) -> Path:
    """A private bundle whose authorization matches its tiny QEMU argv."""
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


class WindowsInstallRunTests(unittest.TestCase):
    def bundle(self, root: Path) -> Path:
        return make_bundle(root)

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

    def test_post_run_check_shares_the_live_wimboot_signature(self):
        # One definition: the post-run validation and the live wait refuse a
        # second banner through the same check, as the same PxeLoop.
        looped = "\n".join((FIRST_BOOT, SECOND_BOOT, NATIVE_READY))
        with self.assertRaises(windows_install_run.PxeLoop) as caught:
            windows_install_run._validate_lifecycle(looped)
        self.assertEqual(2, caught.exception.banners)

    def test_a_split_banner_is_never_counted(self):
        # A serial read can stop mid-line; a fixed literal only delays a match.
        tail = "wimboot v2.9.0 -- Windows Imaging Format bootloader -- x\n"
        for cut in range(len(tail)):
            with self.subTest(cut=cut):
                partial = FIRST_BOOT + "\n" + tail[:cut]
                expected = 2 if windows_install_run.WIMBOOT_BANNER in (
                    tail[:cut]) else 1
                self.assertEqual(
                    expected, windows_install_run.wimboot_banners(partial))


#: A healthy first boot, as the live serial records it (measured from the
#: 2026-10-01 bundles): one PXE firmware boot, the private overlay, one banner.
FIRST_BOOT = "\n".join((
    'BdsDxe: loading Boot0003 "UEFI PXEv4 (MAC:525400311212)"',
    'BdsDxe: starting Boot0003 "UEFI PXEv4 (MAC:525400311212)"',
    "http://10.1.31.2/private/run-abc/boot.ipxe... ok",
    "http://10.1.31.2/windows/20260727.005/wimboot... ok",
    "wimboot v2.9.0 -- Windows Imaging Format bootloader -- "
    "https://ipxe.org/wimboot",
    'Command line: "wimboot"',
    "Using install.bat",
    "Using winpeshl.ini",
))
#: The loop: WinPE rebooted into PXE instead of the NVMe and wimboot ran again.
SECOND_BOOT = "\n".join((
    'BdsDxe: starting Boot0003 "UEFI PXEv4 (MAC:525400311212)"',
    "http://10.1.31.2/windows/20260727.005/wimboot... ok",
    "wimboot v2.9.0 -- Windows Imaging Format bootloader -- "
    "https://ipxe.org/wimboot",
))
NATIVE_READY = windows_install_run.NATIVE_READY_MARKER
SETUP_PROGRESS = "Windows Setup is copying files"


class FakeProcess:
    def __init__(self, pid):
        self.pid = pid
        self.stdout = None

    def poll(self):
        return None


class FakeWorkstation(FakeProcess):
    """Emits one serial chunk per poll, as a live guest does, then exits."""

    def __init__(self, pid, chunks, *, exits):
        super().__init__(pid)
        self.chunks = list(chunks)
        self.exits = exits
        self.polls = 0
        self.serial: Path | None = None

    def poll(self):
        self.polls += 1
        if self.chunks:
            with self.serial.open("a", encoding="utf-8") as stream:
                stream.write(self.chunks.pop(0) + "\n")
            return None
        if self.exits or self.polls > 50:  # never spin to the deadline
            return 0
        return None


class FakeQmp:
    def __init__(self):
        self.closed = False
        self.screens = 0

    def screenshot(self, path):
        self.screens += 1
        Path(path).write_bytes(b"P6\n1 1\n255\n\0\0\0")

    def close(self):
        self.closed = True


class FakeBootDisk:
    def __init__(self, *_args, **_kwargs):
        self.disk = Path("/overlay/controller.raw")
        self.vars = Path("/overlay/OVMF_VARS.fd")
        self.overlay = mock.Mock()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class LiveWaitTests(unittest.TestCase):
    """The wait for native readiness, driven against fakes: no QEMU, no host."""

    def live_run(self, chunks, *, exits=True):
        from contextlib import ExitStack, nullcontext, redirect_stdout
        import io
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        bundle = make_bundle(Path(temporary.name) / "bundle")
        evidence = bundle / "evidence"
        workstation = FakeWorkstation(704, chunks, exits=exits)
        processes = {
            "switch": FakeProcess(701), "gateway": FakeProcess(702),
            "controller": FakeProcess(703), "workstation": workstation,
        }
        qmp = FakeQmp()

        def popen(argv, **_kwargs):
            return processes[argv[0]]

        def capture(process, path):
            self.assertIs(workstation, process)
            path.touch(mode=0o600)
            workstation.serial = path
            return mock.Mock()

        terminate = mock.Mock(return_value=[])
        sleeps = mock.Mock()
        authorization = {"authorization": {"release_version": "20260727.005"}}
        patches = {
            "_bundle": mock.Mock(return_value=(authorization, ["workstation"])),
            "_qmp_socket_path": mock.Mock(
                return_value=bundle / "windows.qmp"),
            "paths": mock.Mock(return_value={
                "disk": Path("/state/disk"), "vars": Path("/state/vars")}),
            "socket": mock.Mock(),
            "SignalGuard": nullcontext,
            "DisposableBootDisk": FakeBootDisk,
            "qemu_commands": mock.Mock(
                return_value={"controller": ["controller"]}),
            "switch_command": mock.Mock(return_value=["switch"]),
            "gateway_command": mock.Mock(return_value=["gateway"]),
            "subprocess": mock.Mock(Popen=mock.Mock(side_effect=popen)),
            "wait_for_switch_port": mock.Mock(),
            "audit_live_process": mock.Mock(),
            "activate_publication": mock.Mock(),
            "capture_serial": capture,
            "_connect_qmp": mock.Mock(return_value=qmp),
            "terminate_children": terminate,
        }
        error = None
        with ExitStack() as stack:
            for name, value in patches.items():
                stack.enter_context(
                    mock.patch.object(windows_install_run, name, value))
            stack.enter_context(
                mock.patch.object(windows_install_run.time, "sleep", sleeps))
            stack.enter_context(redirect_stdout(io.StringIO()))
            try:
                status = windows_install_run.run(
                    bundle, controller_state=Path("/state"), duration=7200,
                    apply=True)
            except Exception as raised:  # noqa: BLE001 - asserted by callers
                status, error = None, raised
        result = json.loads((evidence / "result.json").read_text())
        return {"status": status, "error": error, "result": result,
                "workstation": workstation, "qmp": qmp,
                "terminate": terminate, "processes": processes,
                "sleeps": sleeps, "evidence": evidence}

    def test_a_second_wimboot_banner_fails_fast_with_the_pxe_loop_category(self):
        # The 2026-10-01 loop: a second banner, then (had it been allowed to
        # keep waiting) nothing but silence until the duration ran out.
        run = self.live_run(
            [FIRST_BOOT, SETUP_PROGRESS, SECOND_BOOT]
            + [SETUP_PROGRESS] * 40, exits=False)
        self.assertIsInstance(run["error"], windows_install_run.PxeLoop)
        # Stopped on the poll that saw the second banner, not at the deadline.
        self.assertEqual(3, run["workstation"].polls)
        self.assertEqual(40, len(run["workstation"].chunks))
        self.assertEqual(2, run["sleeps"].call_count)
        result = run["result"]
        self.assertEqual("fail", result["status"])
        self.assertEqual("windows-setup", result["phase"])
        self.assertEqual(windows_install_run.PXE_LOOP, "pxe-loop")
        self.assertEqual("pxe-loop", result["failure_category"])
        self.assertEqual(2, result["wimboot_banners"])
        self.assertEqual("PxeLoop", result["error_type"])
        self.assertIn("2 wimboot banners", result["error"])
        # Torn down exactly as any failure is: every child terminated, QMP
        # closed, logs retained redacted, the publication handed off.
        run["terminate"].assert_called_once()
        self.assertEqual(
            sorted(run["processes"].values(), key=lambda p: p.pid),
            sorted(run["terminate"].call_args.args[0], key=lambda p: p.pid))
        self.assertTrue(run["qmp"].closed)
        self.assertIn("workstation-serial.log", result["retained_logs"])
        self.assertTrue(result["private_publication_retained_for_identity"])
        serial = (run["evidence"] / "workstation-serial.log").read_text()
        self.assertEqual(2, windows_install_run.wimboot_banners(serial))

    def test_the_category_distinguishes_the_loop_from_every_other_failure(self):
        loop = self.live_run([FIRST_BOOT, SECOND_BOOT], exits=False)["result"]
        exited = self.live_run([FIRST_BOOT], exits=True)
        self.assertIn("exited before native", str(exited["error"]))
        other = exited["result"]
        self.assertNotIn("failure_category", other)
        self.assertNotIn("wimboot_banners", other)
        # Same teardown record otherwise: only the category fields differ.
        self.assertEqual(
            set(other) | {"failure_category", "wimboot_banners"}, set(loop))
        exited["terminate"].assert_called_once()

    def test_one_banner_then_native_ready_is_unchanged_success(self):
        run = self.live_run(
            [FIRST_BOOT, SETUP_PROGRESS, NATIVE_READY], exits=True)
        self.assertIsNone(run["error"])
        self.assertEqual(0, run["status"])
        result = run["result"]
        self.assertEqual({
            "schema", "status", "phase", "pxe_firmware_boots",
            "release_version", "measurements", "retained_logs",
            "private_publication_retained_for_identity",
        }, set(result))
        self.assertEqual("observed", result["status"])
        self.assertEqual("native-windows-clean-shutdown", result["phase"])
        self.assertEqual(1, result["pxe_firmware_boots"])
        self.assertEqual(4, run["workstation"].polls)
        run["terminate"].assert_called_once()
        self.assertTrue(run["qmp"].closed)


if __name__ == "__main__":
    unittest.main()
