import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm import windows_identity_run
from homelab.vm.windows_identity_run import (
    IdentityOperations,
    NativeProcessBoundary,
    WindowsIdentityRunError,
    run_lifecycle,
)
from homelab.tests.windows_identity_fixture import (
    write_prepared_authorization,
)


class _Process:
    def __init__(self, pid, *, returncode=None):
        self.pid = pid
        self.returncode = returncode
        self.stdout = mock.Mock()
        self.stdin = mock.Mock()

    def poll(self):
        return self.returncode


class _Socket:
    def __init__(self, events):
        self.events = events

    def setsockopt(self, *arguments):
        self.events.append(("setsockopt", arguments))

    def bind(self, endpoint):
        self.events.append(("bind", endpoint))

    def listen(self, backlog):
        self.events.append(("listen", backlog))

    def getsockname(self):
        return ("127.0.0.1", 43119)

    def fileno(self):
        return 17

    def close(self):
        self.events.append(("socket-close",))


class NativeProcessBoundaryTests(unittest.TestCase):
    def make_boundary(self, root):
        attempt = root / "attempt"
        controller = root / "controller"
        attempt.mkdir(mode=0o700)
        controller.mkdir(mode=0o700)
        for item in (
            attempt / "windows.qcow2",
            attempt / "OVMF_VARS.fd",
            controller / "bootstrap-dc.qcow2",
            controller / "OVMF_VARS.fd",
        ):
            item.write_bytes(b"private")
            item.chmod(0o600)
        write_prepared_authorization(attempt, controller)
        return NativeProcessBoundary(attempt, controller)

    def test_native_processes_start_in_isolated_dependency_order(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            events = []
            processes = iter((_Process(101), _Process(102), _Process(103),
                              _Process(104)))
            overlay = mock.Mock()
            overlay.disk = boundary.runtime / "controller" / "disk.raw"
            overlay.vars = boundary.runtime / "controller" / "vars.fd"

            def popen(command, **_kwargs):
                events.append(("popen", command[0]))
                return next(processes)

            disposable = mock.Mock()
            disposable.prepare.side_effect = lambda: (
                events.append(("overlay", "prepared")) or overlay)
            factory = mock.Mock()
            factory.output = boundary.runtime / "controller-convergence.iso"
            factory.password = "private"
            factory.build.side_effect = lambda: factory.output.write_bytes(
                b"private factory media")
            factory.close.side_effect = lambda: factory.output.unlink(
                missing_ok=True)
            with (
                mock.patch.object(
                    windows_identity_run.socket, "socket",
                    side_effect=lambda: _Socket(events)),
                mock.patch.object(
                    windows_identity_run, "switch_command",
                    return_value=["switch"]) as switch_command,
                mock.patch.object(
                    windows_identity_run, "gateway_command",
                    return_value=["gateway"]) as gateway_command,
                mock.patch.object(
                    windows_identity_run, "controller_command",
                    return_value=["controller"]) as controller_command,
                mock.patch.object(
                    windows_identity_run, "qemu_identity_command",
                    return_value=["windows"]) as windows_command,
                mock.patch.object(
                    windows_identity_run, "DisposableBootDisk",
                    return_value=disposable),
                mock.patch.object(
                    windows_identity_run, "FactoryBundle",
                    return_value=factory) as factory_type,
                mock.patch.object(
                    windows_identity_run.QmpClient, "connect") as qmp_connect,
                mock.patch.object(
                    boundary, "_process_holds_inode",
                    side_effect=(
                        True, False, True, False, True, True, True,
                        True, True)),
                mock.patch.object(
                    windows_identity_run, "SerialAutomation") as automation,
                mock.patch.object(
                    windows_identity_run.subprocess, "Popen",
                    side_effect=popen),
                mock.patch.object(
                    windows_identity_run, "wait_for_switch_port",
                    side_effect=lambda _log, role, _mac, **_kwargs:
                    (events.append(("ready", role)) or 1)),
                mock.patch.object(
                    windows_identity_run, "wait_for_plain_dhcp_transaction",
                    side_effect=lambda _log, role, _mac, **_kwargs:
                    events.append(("dhcp-ready", role))),
                mock.patch.object(
                    windows_identity_run, "audit_live_process",
                    side_effect=lambda _pid, role, **_kwargs:
                    events.append(("audit", role))),
                mock.patch.object(
                    boundary, "_start_dependency",
                    side_effect=lambda role:
                    events.append(("dependency", role))),
            ):
                boundary.start_switch()
                boundary.start_controller()
                boundary.authorized_command = ["windows"]
                boundary.start_windows()

            automation.return_value.establish_disposable_controller_session\
                .assert_called_once_with()
            self.assertTrue(switch_command.call_args.kwargs["identity_mode"])
            self.assertTrue(gateway_command.call_args.kwargs["identity_mode"])
            automation.return_value.install_offline_controller_dependencies\
                .assert_called_once_with()
            automation.return_value.converge_disposable_controller\
                .assert_called_once()
            qmp_connect.return_value.await_device_deleted.assert_has_calls([
                mock.call("identityseedcd", timeout=30.0),
                mock.call("identityfactorycd", timeout=30.0),
            ])
            factory_type.assert_called_once()

            try:
                milestones = [
                    event for event in events
                    if event[0] in {
                        "popen", "overlay", "ready", "audit", "dhcp-ready",
                        "dependency",
                    }
                ]
                self.assertEqual([
                    ("popen", "switch"),
                    ("popen", "gateway"),
                    ("ready", "gateway"),
                    ("overlay", "prepared"),
                    ("popen", "controller"),
                    ("audit", "controller"),
                    ("ready", "controller"),
                    ("popen", "windows"),
                    ("audit", "client"),
                    ("ready", "workstation"),
                    ("dhcp-ready", "workstation"),
                    ("dependency", "update-source"),
                    ("dependency", "optional-storage"),
                ], milestones)
                controller_command.assert_called_once_with(
                    boundary.controller_state,
                    overlay.disk,
                    overlay.vars,
                    43119,
                    disk_format="raw",
                )
                windows_command.assert_called_once_with(
                    disk=boundary.attempt / "windows.qcow2",
                    variables=boundary.attempt / "OVMF_VARS.fd",
                    qmp_socket=boundary.qmp_root / "windows.qmp",
                    serial_socket=boundary.qmp_root / "windows.serial",
                    switch_port=43119,
                    control_iso=boundary.attempt / "control.iso",
                )
            finally:
                boundary.processes.clear()
                boundary._cleanup_qmp_root()

    def test_controller_rejects_unsafe_opened_seed_descriptor(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary._validate()
            boundary.port = 43119
            boundary.runtime.mkdir(mode=0o700)
            boundary.processes.update({
                "switch": _Process(101),
                "gateway": _Process(102),
            })
            overlay = mock.Mock()
            overlay.disk = boundary.runtime / "controller" / "disk.raw"
            overlay.vars = boundary.runtime / "controller" / "vars.fd"
            disposable = mock.Mock()
            disposable.prepare.return_value = overlay
            factory = mock.Mock()
            factory.output = boundary.runtime / "controller-convergence.iso"

            with (
                mock.patch.object(
                    windows_identity_run, "DisposableBootDisk",
                    return_value=disposable),
                mock.patch.object(
                    windows_identity_run, "FactoryBundle",
                    return_value=factory),
                mock.patch.object(
                    windows_identity_run, "controller_command",
                    return_value=["controller"]),
                mock.patch.object(
                    windows_identity_run.subprocess, "Popen",
                    return_value=_Process(103)),
                mock.patch.object(
                    windows_identity_run, "audit_live_process"),
                mock.patch.object(
                    windows_identity_run, "wait_for_switch_port"),
                mock.patch.object(
                    windows_identity_run, "wait_for_plain_dhcp_transaction"),
                mock.patch.object(
                    windows_identity_run.QmpClient, "connect") as qmp_connect,
                mock.patch.object(
                    windows_identity_run, "SerialAutomation") as automation,
                mock.patch.object(boundary, "stop_controller"),
                mock.patch.object(
                    windows_identity_run.os, "fstat",
                    return_value=mock.Mock(
                        st_mode=0o100622, st_dev=7, st_ino=11)),
            ):
                with self.assertRaisesRegex(
                    WindowsIdentityRunError,
                    "opened Controller seed media is unsafe",
                ):
                    boundary.start_controller()

            qmp_connect.return_value.execute.assert_not_called()
            automation.return_value.install_offline_controller_dependencies\
                .assert_not_called()
            boundary.processes.clear()
            boundary.controller_qmp = None
            boundary.controller_overlay = None
            boundary.controller_factory_bundle = None
            assert boundary.controller_qmp_root is not None
            boundary.controller_qmp_root.rmdir()
            boundary.controller_qmp_root = None

    def test_controller_rejects_seed_inode_mismatch_before_device_add(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary._validate()
            boundary.port = 43119
            boundary.runtime.mkdir(mode=0o700)
            boundary.processes.update({
                "switch": _Process(101),
                "gateway": _Process(102),
            })
            overlay = mock.Mock()
            overlay.disk = boundary.runtime / "controller" / "disk.raw"
            overlay.vars = boundary.runtime / "controller" / "vars.fd"
            disposable = mock.Mock()
            disposable.prepare.return_value = overlay
            factory = mock.Mock()
            factory.output = boundary.runtime / "controller-convergence.iso"

            with (
                mock.patch.object(
                    windows_identity_run, "DisposableBootDisk",
                    return_value=disposable),
                mock.patch.object(
                    windows_identity_run, "FactoryBundle",
                    return_value=factory),
                mock.patch.object(
                    windows_identity_run, "controller_command",
                    return_value=["controller"]),
                mock.patch.object(
                    windows_identity_run.subprocess, "Popen",
                    return_value=_Process(103)),
                mock.patch.object(
                    windows_identity_run, "audit_live_process"),
                mock.patch.object(
                    windows_identity_run, "wait_for_switch_port"),
                mock.patch.object(
                    windows_identity_run.QmpClient, "connect") as qmp_connect,
                mock.patch.object(
                    windows_identity_run, "SerialAutomation") as automation,
                mock.patch.object(boundary, "stop_controller"),
                mock.patch.object(
                    boundary, "_process_holds_inode", return_value=False),
            ):
                with self.assertRaisesRegex(
                    WindowsIdentityRunError,
                    "Controller seed media identity differs from audit",
                ):
                    boundary.start_controller()

            commands = [
                call.args[0]
                for call in qmp_connect.return_value.execute.call_args_list
            ]
            self.assertEqual(["blockdev-add", "blockdev-add"], commands)
            self.assertNotIn("device_add", commands)
            automation.return_value.install_offline_controller_dependencies\
                .assert_not_called()
            boundary.processes.clear()
            boundary.controller_qmp = None
            boundary.controller_overlay = None
            boundary.controller_factory_bundle = None
            assert boundary.controller_qmp_root is not None
            boundary.controller_qmp_root.rmdir()
            boundary.controller_qmp_root = None

    def test_switch_binds_only_an_ephemeral_loopback_listener(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            events = []
            with (
                mock.patch.object(
                    windows_identity_run.socket, "socket",
                    side_effect=lambda: _Socket(events)),
                mock.patch.object(
                    windows_identity_run, "switch_command",
                    return_value=["switch"]),
                mock.patch.object(
                    windows_identity_run, "gateway_command",
                    return_value=["gateway"]),
                mock.patch.object(
                    windows_identity_run.subprocess, "Popen",
                    side_effect=(_Process(101), _Process(102))),
                mock.patch.object(
                    windows_identity_run, "wait_for_switch_port"),
                mock.patch.object(
                    windows_identity_run, "wait_for_plain_dhcp_transaction"),
                mock.patch.object(boundary, "_start_dependency"),
                mock.patch.object(
                    boundary, "_process_holds_inode",
                    return_value=True),
            ):
                boundary.start_switch()

            self.assertEqual([("bind", ("127.0.0.1", 0))], [
                event for event in events if event[0] == "bind"])
            self.assertEqual(43119, boundary.port)

    def test_controller_and_windows_require_switch_first(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            with self.assertRaisesRegex(
                    WindowsIdentityRunError, "switch must start"):
                boundary.start_controller()
            with self.assertRaisesRegex(
                    WindowsIdentityRunError, "switch must start"):
                boundary.start_windows()

    def test_control_iso_is_bound_by_exact_path_hash_and_read_only_mode(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary._validate()

            control_iso = boundary.attempt / "control.iso"
            control_iso.chmod(0o644)
            with self.assertRaisesRegex(
                    WindowsIdentityRunError, "mode 0444"):
                boundary._validate()

            control_iso.chmod(0o444)
            original = control_iso.read_bytes()
            control_iso.chmod(0o600)
            control_iso.write_bytes(original + b"tampered")
            control_iso.chmod(0o444)
            with self.assertRaisesRegex(
                    WindowsIdentityRunError, "authorized static artifact"):
                boundary._validate()

    def test_control_iso_authorization_contains_no_payload_or_secret(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            authorization = (
                boundary.attempt / "authorization.json").read_text(
                    encoding="utf-8")
            self.assertNotIn("static read-only control payload", authorization)
            self.assertNotIn("password", authorization.casefold())
            self.assertEqual(
                b"static read-only control payload",
                (boundary.attempt / "control.iso").read_bytes())

    def test_runtime_command_allows_only_private_qmp_and_loopback_port_variance(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary._validate()
            boundary.port = 43119
            boundary.runtime.mkdir(mode=0o700)
            authorized = [
                "qemu-system-x86_64",
                "-qmp", "unix:/private/attempt/windows.qmp,server=on,wait=off",
                "-serial", "chardev:telosidentity",
                "-chardev",
                (
                    "socket,id=telosidentity,"
                    "path=/private/attempt/windows.serial,"
                    "server=on,wait=off"
                ),
                "-drive", "file=/private/windows.qcow2",
                "-device",
                (
                    "nvme,drive=osdisk,serial=TELOS-WIN-0001,"
                    "bootindex=1"
                ),
                "-netdev",
                "socket,id=factory,connect=127.0.0.1:31415",
            ]
            runtime = [
                "qemu-system-x86_64",
                "-qmp", "unix:/private/runtime/windows.qmp,server=on,wait=off",
                "-serial", "chardev:telosidentity",
                "-chardev",
                (
                    "socket,id=telosidentity,"
                    "path=/private/runtime/windows.serial,"
                    "server=on,wait=off"
                ),
                "-drive", "file=/private/windows.qcow2",
                "-device",
                (
                    "nvme,drive=osdisk,serial=TELOS-WIN-0001,"
                    "bootindex=1"
                ),
                "-netdev",
                "socket,id=factory,connect=127.0.0.1:43119",
            ]
            boundary.authorized_command = authorized
            with (
                mock.patch.object(
                    windows_identity_run, "qemu_identity_command",
                    return_value=runtime),
                mock.patch.object(
                    windows_identity_run.subprocess, "Popen",
                    return_value=_Process(104)) as popen,
                mock.patch.object(
                    windows_identity_run, "audit_live_process"),
                mock.patch.object(
                    windows_identity_run, "wait_for_switch_port"),
                mock.patch.object(
                    windows_identity_run,
                    "wait_for_plain_dhcp_transaction"),
                mock.patch.object(boundary, "_start_dependency"),
                mock.patch.object(
                    boundary, "_process_holds_inode",
                    return_value=True),
            ):
                boundary.start_windows()
            popen.assert_called_once()

            boundary.processes.clear()
            boundary._cleanup_qmp_root()
            boundary.authorized_command = authorized
            tampered = list(runtime)
            tampered[tampered.index("-drive") + 1] = (
                "file=/different/windows.qcow2")
            with (
                mock.patch.object(
                    windows_identity_run, "qemu_identity_command",
                    return_value=tampered),
                mock.patch.object(
                    windows_identity_run.subprocess, "Popen") as popen,
            ):
                with self.assertRaisesRegex(
                        WindowsIdentityRunError, "authorized template"):
                    boundary.start_windows()
            popen.assert_not_called()

            for label, mutate in (
                (
                    "missing",
                    lambda value: value.replace(",bootindex=1", ""),
                ),
                (
                    "changed",
                    lambda value: value.replace(
                        ",bootindex=1", ",bootindex=2"),
                ),
                (
                    "duplicate",
                    lambda value: value + ",bootindex=1",
                ),
            ):
                with self.subTest(bootindex=label):
                    boundary.authorized_command = authorized
                    tampered = list(runtime)
                    device_index = next(
                        index for index, value in enumerate(tampered)
                        if value.startswith("nvme,drive=osdisk,")
                    )
                    tampered[device_index] = mutate(tampered[device_index])
                    with (
                        mock.patch.object(
                            windows_identity_run, "qemu_identity_command",
                            return_value=tampered),
                        mock.patch.object(
                            windows_identity_run.subprocess, "Popen") as popen,
                    ):
                        with self.assertRaisesRegex(
                                WindowsIdentityRunError,
                                "authorized template"):
                            boundary.start_windows()
                    popen.assert_not_called()

            boundary.authorized_command = authorized
            tampered = list(runtime)
            serial_index = tampered.index("-chardev") + 1
            tampered[serial_index] = tampered[serial_index].replace(
                "server=on", "server=off")
            with (
                mock.patch.object(
                    windows_identity_run, "qemu_identity_command",
                    return_value=tampered),
                mock.patch.object(
                    windows_identity_run.subprocess, "Popen") as popen,
            ):
                with self.assertRaisesRegex(
                        WindowsIdentityRunError, "authorized template"):
                    boundary.start_windows()
            popen.assert_not_called()

    def test_pristine_boot_timeout_reaps_once_and_retries_before_dependencies(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary._validate()
            boundary.port = 43119
            boundary.runtime.mkdir(mode=0o700)
            boundary.authorized_command = ["windows"]
            processes = [_Process(201), _Process(202)]
            events = []
            readiness_calls = 0

            def popen(*_args, **_kwargs):
                process = processes[len([
                    event for event in events if event[0] == "spawn"
                ])]
                events.append(("spawn", process.pid))
                return process

            def readiness(_cursor):
                nonlocal readiness_calls
                readiness_calls += 1
                if readiness_calls == 1:
                    boundary.windows_switch_generation = 7
                    raise RuntimeError("not ready")

            def stop_windows(*roles):
                self.assertEqual(("windows",), roles)
                process = boundary.processes.pop("windows")
                process.returncode = 0
                events.append(("reaped", process.pid))

            with (
                mock.patch.object(
                    windows_identity_run, "qemu_identity_command",
                    return_value=["windows"]),
                mock.patch.object(
                    windows_identity_run.subprocess, "Popen",
                    side_effect=popen) as popen_mock,
                mock.patch.object(
                    windows_identity_run, "audit_live_process"),
                mock.patch.object(
                    boundary, "_wait_for_process_inode"),
                mock.patch.object(
                    boundary, "_wait_for_windows_os_readiness",
                    side_effect=readiness) as readiness_mock,
                mock.patch.object(
                    windows_identity_run, "wait_for_switch_disconnect",
                    side_effect=lambda *_args, **_kwargs:
                    events.append(("disconnected", 7))),
                mock.patch.object(
                    boundary, "_collect_boot_failure_diagnostic",
                    return_value={
                        "reason": "firmware-did-not-read-osdisk",
                        "qmp_rd_bytes": 0,
                        "qmp_rd_operations": 0,
                        "qmp_wr_bytes": 0,
                        "qmp_wr_operations": 0,
                        "overlay_blocks": 8,
                    },
                ) as pristine,
                mock.patch.object(boundary, "_stop", side_effect=stop_windows),
                mock.patch.object(
                    boundary, "_start_dependency",
                    side_effect=lambda role:
                    events.append(("dependency", role))),
            ):
                boundary.start_windows()

            self.assertEqual(2, popen_mock.call_count)
            self.assertEqual(2, readiness_mock.call_count)
            pristine.assert_called_once()
            self.assertEqual([
                ("spawn", 201),
                ("reaped", 201),
                ("disconnected", 7),
                ("spawn", 202),
                ("dependency", "update-source"),
                ("dependency", "optional-storage"),
            ], events)
            self.assertIs(boundary.processes["windows"], processes[1])
            self.assertFalse(boundary.control_iso_fd)
            boundary.processes.clear()
            boundary._cleanup_qmp_root()

    def test_windows_readiness_binds_both_switch_generations(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary.runtime.mkdir(mode=0o700)
            boundary.gateway_switch_generation = 3
            cursor = windows_identity_run.SwitchEvidenceCursor(
                device=1, inode=2, offset=3)
            with (
                mock.patch.object(
                    windows_identity_run, "wait_for_switch_port",
                    return_value=7),
                mock.patch.object(
                    windows_identity_run,
                    "wait_for_plain_dhcp_transaction") as dhcp,
            ):
                boundary._wait_for_windows_os_readiness(cursor)
            dhcp.assert_called_once_with(
                boundary.runtime / "switch.jsonl",
                "workstation",
                windows_identity_run.MACS["client"],
                timeout=90,
                after=cursor,
                generation=7,
                gateway_generation=3,
            )

    def test_boot_retry_requires_zero_qmp_writes_and_unchanged_overlay(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary._validate()
            boundary.runtime.mkdir(mode=0o700)
            overlay = boundary.attempt / "windows.qcow2"
            info = overlay.stat()
            expected = (
                info.st_dev, info.st_ino, info.st_size, info.st_blocks,
                boundary._sha256(overlay),
            )
            process = _Process(201)
            qmp = mock.Mock()
            qmp.execute.return_value = [{
                "device": "osdisk",
                "stats": {
                    "rd_bytes": 0,
                    "rd_operations": 0,
                    "wr_bytes": 0,
                    "wr_operations": 0,
                },
            }]
            with mock.patch.object(
                    boundary, "_connect_boot_diagnostic_qmp",
                    return_value=qmp):
                diagnostic = boundary._collect_boot_failure_diagnostic(
                    process, expected)
            qmp.execute.assert_called_once_with("query-blockstats")
            qmp.close.assert_called_once_with()
            firmware_before = boundary._sha256(
                boundary.attempt / "OVMF_VARS.fd")
            diagnostic["overlay_pristine_after_reap"] = True
            boundary._record_windows_boot_retry(
                1, diagnostic, firmware_before, retry_eligible=True)
            self.assertEqual({
                "boot_attempt": 1,
                "event": "windows-boot-readiness-timeout",
                "firmware_mutation_retained": True,
                "firmware_sha256_after": firmware_before,
                "firmware_sha256_before": firmware_before,
                "overlay_blocks": expected[3],
                "overlay_pristine_after_reap": True,
                "qmp_rd_bytes": 0,
                "qmp_rd_operations": 0,
                "qmp_wr_bytes": 0,
                "qmp_wr_operations": 0,
                "reason": "firmware-did-not-read-osdisk",
                "retry_eligible": True,
                "schema_version": 1,
            }, json.loads(
                (boundary.runtime /
                 "windows-boot-attempt-1.json").read_text()))

            qmp.reset_mock()
            qmp.execute.return_value = [{
                "device": "osdisk",
                "stats": {
                    "rd_bytes": 8192,
                    "rd_operations": 2,
                    "wr_bytes": 0,
                    "wr_operations": 0,
                },
            }]
            with mock.patch.object(
                    boundary, "_connect_boot_diagnostic_qmp",
                    return_value=qmp):
                read_diagnostic = boundary._collect_boot_failure_diagnostic(
                    process, expected)
            self.assertEqual(
                "osdisk-read-without-os-readiness",
                read_diagnostic["reason"],
            )

            qmp.reset_mock()
            qmp.execute.return_value = [{
                "device": "osdisk",
                "stats": {
                    "rd_bytes": 4096,
                    "rd_operations": 1,
                    "wr_bytes": 4096,
                    "wr_operations": 1,
                },
            }]
            with mock.patch.object(
                    boundary, "_connect_boot_diagnostic_qmp",
                    return_value=qmp):
                write_diagnostic = (
                    boundary._collect_boot_failure_diagnostic(
                        process, expected))
            self.assertEqual(
                "osdisk-written-without-os-readiness",
                write_diagnostic["reason"],
            )
            write_diagnostic["overlay_pristine_after_reap"] = True
            self.assertFalse(boundary._boot_retry_is_eligible(
                write_diagnostic))

            overlay.write_bytes(b"guest write")
            descriptor = os.open(
                overlay, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                with self.assertRaisesRegex(
                        WindowsIdentityRunError, "overlay changed"):
                    boundary._prove_pristine_overlay(
                        descriptor, overlay, expected)
            finally:
                os.close(descriptor)

    def test_boot_artifact_snapshot_binds_fd_hash_and_path_inode(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            overlay = boundary.attempt / "windows.qcow2"
            descriptor, identity = boundary._open_boot_artifact(overlay)
            replacement = boundary.attempt / "replacement.qcow2"
            replacement.write_bytes(overlay.read_bytes())
            replacement.chmod(0o600)
            overlay.unlink()
            replacement.rename(overlay)
            try:
                self.assertEqual(identity[4], boundary._sha256_fd(descriptor))
                with self.assertRaisesRegex(
                        WindowsIdentityRunError,
                        "boot artifact identity changed"):
                    boundary._prove_boot_artifact_path(overlay, identity)
                with self.assertRaisesRegex(
                        WindowsIdentityRunError,
                        "boot artifact identity changed"):
                    boundary._prove_pristine_overlay(
                        descriptor, overlay, identity)
            finally:
                os.close(descriptor)

    def test_boot_artifact_snapshot_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            target = boundary.attempt / "windows.qcow2"
            link = boundary.attempt / "linked.qcow2"
            link.symlink_to(target)
            with self.assertRaisesRegex(
                    WindowsIdentityRunError, "boot artifact open failed"):
                boundary._open_boot_artifact(link)

    def test_second_boot_timeout_fails_closed_without_a_third_spawn(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary._validate()
            boundary.port = 43119
            boundary.runtime.mkdir(mode=0o700)
            boundary.authorized_command = ["windows"]
            processes = [_Process(201), _Process(202)]

            def stop_first(*_roles):
                process = boundary.processes.pop("windows")
                process.returncode = 0

            with (
                mock.patch.object(
                    windows_identity_run, "qemu_identity_command",
                    return_value=["windows"]),
                mock.patch.object(
                    windows_identity_run.subprocess, "Popen",
                    side_effect=processes) as popen,
                mock.patch.object(
                    windows_identity_run, "audit_live_process"),
                mock.patch.object(
                    boundary, "_wait_for_process_inode"),
                mock.patch.object(
                    boundary, "_wait_for_windows_os_readiness",
                    side_effect=RuntimeError("not ready")),
                mock.patch.object(
                    boundary, "_collect_boot_failure_diagnostic",
                    return_value={
                        "reason": "firmware-did-not-read-osdisk",
                        "qmp_rd_bytes": 0,
                        "qmp_rd_operations": 0,
                        "qmp_wr_bytes": 0,
                        "qmp_wr_operations": 0,
                        "overlay_blocks": 8,
                    }),
                mock.patch.object(boundary, "_stop", side_effect=stop_first),
                mock.patch.object(boundary, "stop_windows"),
            ):
                with self.assertRaisesRegex(
                        WindowsIdentityRunError, "bounded retry"):
                    boundary.start_windows()
            self.assertEqual(2, popen.call_count)
            terminal = json.loads((
                boundary.runtime / "windows-boot-attempt-2.json"
            ).read_text())
            self.assertEqual(2, terminal["boot_attempt"])
            self.assertEqual(
                "firmware-did-not-read-osdisk", terminal["reason"])
            self.assertEqual(0, terminal["qmp_rd_bytes"])
            self.assertEqual(0, terminal["qmp_rd_operations"])
            self.assertEqual(0, terminal["qmp_wr_bytes"])
            self.assertEqual(0, terminal["qmp_wr_operations"])
            self.assertEqual(8, terminal["overlay_blocks"])
            self.assertIs(terminal["overlay_pristine_after_reap"], True)
            expected_firmware = boundary._sha256(
                boundary.attempt / "OVMF_VARS.fd")
            self.assertEqual(
                expected_firmware, terminal["firmware_sha256_before"])
            self.assertEqual(
                expected_firmware, terminal["firmware_sha256_after"])
            self.assertIs(terminal["firmware_mutation_retained"], True)
            self.assertFalse(terminal["retry_eligible"])
            self.assertEqual(0o600, stat.S_IMODE((
                boundary.runtime / "windows-boot-attempt-2.json"
            ).stat().st_mode))

    def test_boot_timeout_records_terminal_diagnostic_before_disconnect_failure(
            self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary._validate()
            boundary.port = 43119
            boundary.runtime.mkdir(mode=0o700)
            boundary.authorized_command = ["windows"]
            process = _Process(201)

            def readiness(_cursor):
                boundary.windows_switch_generation = 7
                raise RuntimeError("not ready")

            def stop_windows(*roles):
                self.assertEqual(("windows",), roles)
                boundary.processes.pop("windows").returncode = 0

            with (
                mock.patch.object(
                    windows_identity_run, "qemu_identity_command",
                    return_value=["windows"]),
                mock.patch.object(
                    windows_identity_run.subprocess, "Popen",
                    return_value=process) as popen,
                mock.patch.object(
                    windows_identity_run, "audit_live_process"),
                mock.patch.object(
                    boundary, "_wait_for_process_inode"),
                mock.patch.object(
                    boundary, "_wait_for_windows_os_readiness",
                    side_effect=readiness),
                mock.patch.object(
                    windows_identity_run, "wait_for_switch_disconnect",
                    side_effect=RuntimeError("disconnect unproven")),
                mock.patch.object(
                    boundary, "_collect_boot_failure_diagnostic",
                    return_value={
                        "reason": "firmware-did-not-read-osdisk",
                        "qmp_rd_bytes": 0,
                        "qmp_rd_operations": 0,
                        "qmp_wr_bytes": 0,
                        "qmp_wr_operations": 0,
                        "overlay_blocks": 8,
                    }),
                mock.patch.object(boundary, "_stop", side_effect=stop_windows),
                mock.patch.object(boundary, "stop_windows"),
            ):
                with self.assertRaisesRegex(
                        WindowsIdentityRunError,
                        "switch disconnect proof failed"):
                    boundary.start_windows()

            self.assertEqual(1, popen.call_count)
            diagnostic = json.loads((
                boundary.runtime / "windows-boot-attempt-1.json"
            ).read_text())
            self.assertEqual(1, diagnostic["boot_attempt"])
            self.assertEqual(
                "firmware-did-not-read-osdisk", diagnostic["reason"])
            self.assertEqual(0, diagnostic["qmp_rd_bytes"])
            self.assertEqual(0, diagnostic["qmp_wr_bytes"])
            self.assertIs(diagnostic["overlay_pristine_after_reap"], True)
            self.assertIs(diagnostic["switch_disconnect_proven"], False)
            self.assertIs(diagnostic["retry_eligible"], False)

    def test_boot_diagnostic_is_exclusive_nonfollowing_and_fully_written(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary.runtime.mkdir(mode=0o700)
            firmware = boundary._sha256(
                boundary.attempt / "OVMF_VARS.fd")
            diagnostic = {
                "reason": "firmware-did-not-read-osdisk",
                "qmp_rd_bytes": 0,
                "qmp_rd_operations": 0,
                "qmp_wr_bytes": 0,
                "qmp_wr_operations": 0,
                "overlay_blocks": 8,
                "overlay_pristine_after_reap": True,
                "switch_disconnect_proven": True,
            }
            real_write = os.write

            def short_write(descriptor, content):
                return real_write(descriptor, content[:7])

            with (
                mock.patch.object(
                    windows_identity_run.os, "write",
                    side_effect=short_write) as write,
                mock.patch.object(
                    windows_identity_run.os, "fsync",
                    wraps=os.fsync) as fsync,
            ):
                boundary._record_windows_boot_retry(
                    1, diagnostic, firmware, retry_eligible=True)
            self.assertGreater(write.call_count, 1)
            self.assertEqual(2, fsync.call_count)
            output = boundary.runtime / "windows-boot-attempt-1.json"
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            self.assertEqual(
                "firmware-did-not-read-osdisk",
                json.loads(output.read_text())["reason"])

            original = output.read_bytes()
            with self.assertRaisesRegex(
                    WindowsIdentityRunError, "creation failed"):
                boundary._record_windows_boot_retry(
                    1, diagnostic, firmware, retry_eligible=True)
            self.assertEqual(original, output.read_bytes())

            target = boundary.runtime / "elsewhere"
            target.write_text("untouched", encoding="utf-8")
            symlink = boundary.runtime / "windows-boot-attempt-2.json"
            symlink.symlink_to(target)
            with self.assertRaisesRegex(
                    WindowsIdentityRunError, "creation failed"):
                boundary._record_windows_boot_retry(
                    2, diagnostic, firmware, retry_eligible=False)
            self.assertEqual("untouched", target.read_text(encoding="utf-8"))

    def test_windows_start_preserves_primary_failure_when_teardown_fails(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary._validate()
            boundary.port = 43119
            boundary.runtime.mkdir(mode=0o700)
            boundary.authorized_command = ["windows"]
            primary = RuntimeError("readiness failed")
            cleanup = RuntimeError("teardown failed")
            with (
                mock.patch.object(
                    windows_identity_run, "qemu_identity_command",
                    side_effect=primary),
                mock.patch.object(
                    boundary, "stop_windows", side_effect=cleanup),
            ):
                with self.assertRaisesRegex(
                        WindowsIdentityRunError,
                        "startup failed and teardown also failed") as raised:
                    boundary.start_windows()
            self.assertIs(raised.exception.__cause__, primary)
            self.assertIs(raised.exception.__context__, cleanup)

    def test_qmp_authentication_retries_transient_socket_failures(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary.runtime.mkdir()
            boundary.qmp_root = Path(name) / "qmp"
            boundary.qmp_root.mkdir(mode=0o700)
            process = _Process(104)
            boundary.processes["windows"] = process
            client = mock.Mock()
            clock = iter((0.0, 0.1, 0.2, 0.3))
            with (
                mock.patch.object(
                    windows_identity_run.time, "monotonic",
                    side_effect=lambda: next(clock)),
                mock.patch.object(
                    windows_identity_run.time, "sleep") as sleep,
                mock.patch.object(
                    windows_identity_run.QmpClient, "connect",
                    side_effect=(FileNotFoundError(), ConnectionRefusedError(),
                                 client)) as connect,
            ):
                boundary.authenticate_qmp()

            self.assertIs(client, boundary.qmp)
            self.assertEqual(3, connect.call_count)
            self.assertEqual([mock.call(0.1), mock.call(0.1)],
                             sleep.call_args_list)

    def test_control_inode_wait_accepts_a_delayed_qemu_open(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            process = _Process(104)
            with (
                mock.patch.object(
                    boundary, "_process_holds_inode",
                    side_effect=(False, True)) as holds,
                mock.patch.object(
                    windows_identity_run.time, "monotonic",
                    side_effect=(0.0, 0.1)),
                mock.patch.object(
                    windows_identity_run.time, "sleep") as sleep,
            ):
                boundary._wait_for_process_inode(
                    process, device=7, inode=11, timeout=1.0)
            self.assertEqual(2, holds.call_count)
            sleep.assert_called_once_with(0.05)

    def test_control_inode_wait_rejects_process_exit(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            process = _Process(104, returncode=1)
            with mock.patch.object(
                    boundary, "_process_holds_inode") as holds:
                with self.assertRaisesRegex(
                        WindowsIdentityRunError,
                        "exited before opening"):
                    boundary._wait_for_process_inode(
                        process, device=7, inode=11)
            holds.assert_not_called()

    def test_control_inode_wait_has_a_bounded_never_open_failure(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            process = _Process(104)
            with (
                mock.patch.object(
                    boundary, "_process_holds_inode",
                    return_value=False),
                mock.patch.object(
                    windows_identity_run.time, "monotonic",
                    side_effect=(0.0, 0.1, 0.2)),
                mock.patch.object(
                    windows_identity_run.time, "sleep") as sleep,
            ):
                with self.assertRaisesRegex(
                        WindowsIdentityRunError, "in time"):
                    boundary._wait_for_process_inode(
                        process, device=7, inode=11, timeout=0.15)
            sleep.assert_called_once_with(0.05)

    def test_qmp_retry_aborts_when_windows_exits(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary.processes["windows"] = _Process(104, returncode=1)
            with (
                mock.patch.object(
                    windows_identity_run.time, "monotonic",
                    side_effect=(0.0, 0.1)),
                mock.patch.object(
                    windows_identity_run.QmpClient, "connect") as connect,
            ):
                with self.assertRaisesRegex(
                        WindowsIdentityRunError,
                        "exited before QMP authentication"):
                    boundary.authenticate_qmp()
            connect.assert_not_called()

    def test_qmp_retry_has_a_bounded_timeout(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            boundary.qmp_root = Path(name) / "qmp"
            boundary.qmp_root.mkdir(mode=0o700)
            boundary.processes["windows"] = _Process(104)
            with (
                mock.patch.object(
                    windows_identity_run.time, "monotonic",
                    side_effect=(0.0, 29.9, 30.0)),
                mock.patch.object(windows_identity_run.time, "sleep"),
                mock.patch.object(
                    windows_identity_run.QmpClient, "connect",
                    side_effect=ConnectionRefusedError("not ready")) as connect,
            ):
                with self.assertRaisesRegex(
                        WindowsIdentityRunError,
                        "timed out authenticating Windows QMP"):
                    boundary.authenticate_qmp()
            connect.assert_called_once_with(
                boundary.qmp_root / "windows.qmp", timeout=2,
                expected_peer_pid=104)

    def test_cleanup_closes_qmp_and_overlay_and_reaps_every_process(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            processes = {
                "switch": _Process(101),
                "gateway": _Process(102),
                "controller": _Process(103),
                "windows": _Process(104),
            }
            boundary.processes.update(processes)
            qmp = mock.Mock()
            overlay = mock.Mock()
            boundary.qmp = qmp
            boundary.controller_overlay = overlay
            terminated = []

            def terminate(selected):
                selected = list(selected)
                terminated.append(selected)
                for process in selected:
                    process.returncode = -15
                return []

            with mock.patch.object(
                    windows_identity_run, "terminate_children",
                    side_effect=terminate):
                boundary.stop_windows()
                boundary.stop_controller()
                boundary.stop_switch()

            qmp.close.assert_called_once_with()
            overlay.close.assert_called_once_with()
            self.assertIsNone(boundary.qmp)
            self.assertIsNone(boundary.controller_overlay)
            self.assertEqual([
                [processes["windows"]],
                [processes["controller"]],
                [processes["gateway"], processes["switch"]],
            ], terminated)
            self.assertEqual({}, boundary.processes)

    def test_windows_teardown_removes_qmp_and_probe_serial_sockets(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            runtime = Path(name) / "private-runtime"
            runtime.mkdir(mode=0o700)
            boundary.qmp_root = runtime
            boundary.serial_socket = runtime / "windows.serial"
            qmp_socket = runtime / "windows.qmp"
            with (
                windows_identity_run.socket.socket(
                    windows_identity_run.socket.AF_UNIX,
                    windows_identity_run.socket.SOCK_STREAM) as qmp,
                windows_identity_run.socket.socket(
                    windows_identity_run.socket.AF_UNIX,
                    windows_identity_run.socket.SOCK_STREAM) as serial,
            ):
                qmp.bind(str(qmp_socket))
                serial.bind(str(boundary.serial_socket))
                boundary.stop_windows()

            self.assertFalse(runtime.exists())
            self.assertFalse(qmp_socket.exists())
            self.assertIsNone(boundary.serial_socket)
            self.assertIsNone(boundary.qmp_root)

    def test_cleanup_preserves_failed_process_for_a_later_retry(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            windows = _Process(104)
            qmp = mock.Mock()
            qmp.close.side_effect = OSError("QMP disappeared")
            boundary.processes["windows"] = windows
            boundary.qmp = qmp
            with mock.patch.object(
                    windows_identity_run, "terminate_children",
                    return_value=["pid 104 survived"]) as terminate:
                with self.assertRaisesRegex(
                        WindowsIdentityRunError,
                        "QMP close: OSError; Windows process"):
                    boundary.stop_windows()

            terminate.assert_called_once_with([windows])
            self.assertIs(qmp, boundary.qmp)
            self.assertIs(windows, boundary.processes["windows"])

    def test_failed_start_is_cleaned_when_process_was_already_created(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self.make_boundary(Path(name))
            events = []

            def start_switch():
                boundary.processes["switch"] = _Process(101)
                events.append("start-switch")

            def start_controller():
                boundary.processes["controller"] = _Process(102)
                events.append("start-controller")
                raise RuntimeError("audit rejected Controller")

            def stop(role):
                return lambda: (
                    events.append(f"stop-{role}"),
                    boundary.processes.pop(role, None),
                )

            noop = lambda: None
            operations = IdentityOperations(
                start_switch=start_switch,
                start_controller=start_controller,
                start_windows=noop,
                authenticate_qmp=noop,
                rotate_local_credential=noop,
                destroy_private_publication=noop,
                stage_controller_principals=noop,
                run_acceptance_phases=noop,
                destroy_controller_principals=noop,
                stop_windows=stop("windows"),
                stop_controller=stop("controller"),
                stop_switch=stop("switch"),
            )
            with self.assertRaises(WindowsIdentityRunError):
                run_lifecycle(operations)

            self.assertEqual([
                "start-switch", "start-controller",
                "stop-controller", "stop-switch",
            ], events)
            self.assertEqual({}, boundary.processes)


if __name__ == "__main__":
    unittest.main()
