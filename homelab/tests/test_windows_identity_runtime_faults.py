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
    def test_failed_resume_retains_process_ownership(self, kill, terminate):
        boundary = self.boundary()
        boundary.processes["controller"] = Process()
        boundary.suspended_processes.add("controller")

        with self.assertRaisesRegex(
            WindowsIdentityRunError, "resume before teardown"
        ):
            boundary._stop("controller")

        terminate.assert_not_called()
        self.assertIn("controller", boundary.processes)
        self.assertIn("controller", boundary.suspended_processes)

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


if __name__ == "__main__":
    unittest.main()
