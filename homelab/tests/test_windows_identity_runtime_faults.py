import signal
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm.windows_identity_faults import native_fault_operations
from homelab.vm.windows_identity_run import (
    NativeProcessBoundary,
    WindowsIdentityRunError,
)


class Process:
    def __init__(self, pid=4321, returncode=None):
        self.pid = pid
        self.returncode = returncode

    def poll(self):
        return self.returncode


class WindowsIdentityRuntimeFaultTests(unittest.TestCase):
    def boundary(self):
        return NativeProcessBoundary(Path("/attempt"), Path("/controller"))

    def test_native_operations_bind_every_runtime_setter(self):
        boundary = self.boundary()
        observe = mock.Mock()
        operations = native_fault_operations(boundary, observe)
        self.assertEqual(
            boundary.set_controller_available,
            operations.set_controller_available,
        )
        self.assertEqual(
            boundary.set_gateway_available,
            operations.set_gateway_available,
        )
        self.assertEqual(
            boundary.set_update_source_available,
            operations.set_update_source_available,
        )
        self.assertEqual(
            boundary.set_optional_storage_available,
            operations.set_optional_storage_available,
        )
        self.assertIs(observe, operations.observe)

    @mock.patch("homelab.vm.windows_identity_run.os.kill")
    def test_each_separately_owned_dependency_is_reversibly_suspended(
        self, kill,
    ):
        boundary = self.boundary()
        setters = {
            "controller": boundary.set_controller_available,
            "gateway": boundary.set_gateway_available,
            "update-source": boundary.set_update_source_available,
            "optional-storage": boundary.set_optional_storage_available,
        }
        for offset, (role, setter) in enumerate(setters.items()):
            process = Process(4300 + offset)
            boundary.processes[role] = process
            setter(False)
            self.assertIn(role, boundary.suspended_processes)
            setter(True)
            self.assertNotIn(role, boundary.suspended_processes)
            self.assertEqual([
                mock.call(process.pid, signal.SIGSTOP),
                mock.call(process.pid, signal.SIGCONT),
            ], kill.call_args_list[-2:])

    @mock.patch("homelab.vm.windows_identity_run.os.kill")
    def test_missing_or_dead_dependency_refuses_to_claim_an_outage(self, kill):
        boundary = self.boundary()
        with self.assertRaisesRegex(
            WindowsIdentityRunError, "no separately owned process"
        ):
            boundary.set_update_source_available(False)
        boundary.processes["optional-storage"] = Process(returncode=9)
        with self.assertRaisesRegex(
            WindowsIdentityRunError, "process is not live"
        ):
            boundary.set_optional_storage_available(False)
        kill.assert_not_called()

    @mock.patch("homelab.vm.windows_identity_run.os.kill")
    def test_duplicate_transition_is_rejected_without_a_second_signal(
        self, kill,
    ):
        boundary = self.boundary()
        boundary.processes["controller"] = Process()
        boundary.set_controller_available(False)
        with self.assertRaisesRegex(
            WindowsIdentityRunError, "already offline"
        ):
            boundary.set_controller_available(False)
        self.assertEqual(1, kill.call_count)

    @mock.patch("homelab.vm.windows_identity_run.os.kill")
    def test_non_boolean_availability_is_rejected(self, kill):
        boundary = self.boundary()
        boundary.processes["gateway"] = Process()
        with self.assertRaisesRegex(
            WindowsIdentityRunError, "availability must be boolean"
        ):
            boundary.set_gateway_available(0)
        kill.assert_not_called()

    @mock.patch("homelab.vm.windows_identity_run.terminate_children")
    @mock.patch("homelab.vm.windows_identity_run.os.kill")
    def test_teardown_resumes_a_suspended_process_before_termination(
        self, kill, terminate,
    ):
        process = Process()
        boundary = self.boundary()
        boundary.processes["gateway"] = process
        boundary.suspended_processes.add("gateway")
        terminate.side_effect = lambda _children: (
            setattr(process, "returncode", 0) or []
        )

        boundary._stop("gateway")

        kill.assert_called_once_with(process.pid, signal.SIGCONT)
        terminate.assert_called_once_with([process])
        self.assertNotIn("gateway", boundary.processes)
        self.assertNotIn("gateway", boundary.suspended_processes)

    @mock.patch("homelab.vm.windows_identity_run.terminate_children")
    @mock.patch(
        "homelab.vm.windows_identity_run.os.kill",
        side_effect=ProcessLookupError,
    )
    def test_failed_resume_still_terminates_and_reaps_process(self, kill, terminate):
        boundary = self.boundary()
        process = Process()
        boundary.processes["controller"] = process
        boundary.suspended_processes.add("controller")
        terminate.side_effect = lambda _children: (
            setattr(process, "returncode", 0) or []
        )

        with self.assertRaisesRegex(
            WindowsIdentityRunError, "resume before teardown"
        ):
            boundary._stop("controller")

        terminate.assert_called_once_with([process])
        self.assertNotIn("controller", boundary.processes)
        self.assertNotIn("controller", boundary.suspended_processes)

    @mock.patch("homelab.vm.windows_identity_run.terminate_children")
    @mock.patch("homelab.vm.windows_identity_run.os.kill")
    def test_dead_suspended_process_is_reconciled_and_reaped(
        self, kill, terminate,
    ):
        process = Process(returncode=9)
        boundary = self.boundary()
        boundary.processes["controller"] = process
        boundary.suspended_processes.add("controller")
        terminate.return_value = []

        boundary._stop("controller")

        kill.assert_not_called()
        terminate.assert_called_once_with([process])
        self.assertNotIn("controller", boundary.processes)
        self.assertNotIn("controller", boundary.suspended_processes)

    @mock.patch("homelab.vm.windows_identity_run.terminate_children")
    def test_console_release_failure_does_not_skip_controller_cleanup(
        self, terminate,
    ):
        process = Process()
        terminate.side_effect = lambda _children: (
            setattr(process, "returncode", 0) or []
        )
        boundary = self.boundary()
        boundary.processes["controller"] = process
        boundary.controller_console = mock.Mock()
        boundary.controller_console.release_password.side_effect = (
            KeyboardInterrupt())
        controller_qmp = mock.Mock()
        controller_overlay = mock.Mock()
        boundary.controller_qmp = controller_qmp
        boundary.controller_overlay = controller_overlay

        with self.assertRaisesRegex(
            WindowsIdentityRunError, "credential release: KeyboardInterrupt"
        ):
            boundary.stop_controller()

        controller_qmp.close.assert_called_once()
        controller_overlay.close.assert_called_once()
        terminate.assert_called_once_with([process])
        self.assertNotIn("controller", boundary.processes)

    @mock.patch(
        "homelab.vm.windows_identity_run.os.close",
        side_effect=OSError("private"),
    )
    def test_failed_control_fd_close_drops_stale_descriptor(self, close):
        boundary = self.boundary()
        boundary.control_iso_fd = 91
        with self.assertRaisesRegex(
            WindowsIdentityRunError, "control ISO ownership"
        ):
            boundary.stop_windows()
        self.assertIsNone(boundary.control_iso_fd)
        close.assert_called_once_with(91)

    @mock.patch(
        "homelab.vm.windows_identity_run.os.close",
        side_effect=OSError("private"),
    )
    def test_failed_controller_media_fd_close_drops_stale_descriptor(
        self, close,
    ):
        boundary = self.boundary()
        boundary.controller_factory_fd = 92
        boundary.controller_factory_bundle = mock.Mock()
        with mock.patch.object(
            boundary, "_destroy_owned_inode",
        ) as destroy:
            with self.assertRaisesRegex(
                WindowsIdentityRunError, "Controller convergence media"
            ):
                boundary.stop_controller()
        destroy.assert_called_once()
        self.assertIsNone(boundary.controller_factory_fd)
        close.assert_called_once_with(92)


if __name__ == "__main__":
    unittest.main()
