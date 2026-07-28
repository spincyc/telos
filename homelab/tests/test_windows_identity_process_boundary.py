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
                    windows_identity_run, "controller_command",
                    return_value=["controller"]) as controller_command,
                mock.patch.object(
                    windows_identity_run, "qemu_identity_command",
                    return_value=["windows"]) as windows_command,
                mock.patch.object(
                    windows_identity_run, "DisposableBootDisk",
                    return_value=disposable),
                mock.patch.object(
                    windows_identity_run.subprocess, "Popen",
                    side_effect=popen),
                mock.patch.object(
                    windows_identity_run, "wait_for_switch_port",
                    side_effect=lambda _log, role:
                    events.append(("ready", role))),
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

            try:
                milestones = [
                    event for event in events
                    if event[0] in {"popen", "overlay", "ready", "audit"}
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
                mock.patch.object(boundary, "_start_dependency"),
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
                mock.patch.object(boundary, "_start_dependency"),
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
                boundary.qmp_root / "windows.qmp", timeout=2)

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
