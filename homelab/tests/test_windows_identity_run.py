import unittest

from homelab.vm.windows_identity_run import (
    IdentityOperations,
    WindowsIdentityRunError,
    run_lifecycle,
)


class Recorder:
    def __init__(self, failure=None):
        self.events = []
        self.failure = failure

    def operation(self, name):
        def invoke():
            self.events.append(name)
            if self.failure == name:
                raise RuntimeError("private failure")
        return invoke

    def operations(self):
        names = (
            "start_switch", "start_controller", "start_windows",
            "authenticate_qmp", "rotate_local_credential",
            "destroy_private_publication", "stage_controller_principals",
            "run_acceptance_phases", "destroy_controller_principals",
            "stop_windows", "stop_controller", "stop_switch",
        )
        return IdentityOperations(**{
            name: self.operation(name) for name in names})


class WindowsIdentityRunTests(unittest.TestCase):
    def test_secret_and_destruction_boundaries_have_one_order(self):
        recorder = Recorder()
        receipt = run_lifecycle(recorder.operations())
        self.assertEqual([
            "start_switch",
            "start_controller",
            "start_windows",
            "authenticate_qmp",
            "rotate_local_credential",
            "destroy_private_publication",
            "stage_controller_principals",
            "run_acceptance_phases",
            "destroy_controller_principals",
            "stop_windows",
            "stop_controller",
            "stop_switch",
        ], recorder.events)
        self.assertTrue(receipt.private_publication_destroyed)
        self.assertTrue(receipt.controller_principals_destroyed)
        self.assertTrue(receipt.teardown_complete)

    def test_rotation_failure_never_destroys_publication_or_stages_principals(self):
        recorder = Recorder("rotate_local_credential")
        with self.assertRaisesRegex(
                WindowsIdentityRunError, "lifecycle: RuntimeError"):
            run_lifecycle(recorder.operations())
        self.assertNotIn("destroy_private_publication", recorder.events)
        self.assertNotIn("stage_controller_principals", recorder.events)
        self.assertEqual(
            ["stop_windows", "stop_controller", "stop_switch"],
            recorder.events[-3:])

    def test_staged_principals_are_destroyed_after_acceptance_failure(self):
        recorder = Recorder("run_acceptance_phases")
        with self.assertRaises(WindowsIdentityRunError):
            run_lifecycle(recorder.operations())
        self.assertIn("destroy_controller_principals", recorder.events)
        self.assertEqual(
            ["stop_windows", "stop_controller", "stop_switch"],
            recorder.events[-3:])

    def test_cleanup_failure_is_not_hidden(self):
        recorder = Recorder("stop_controller")
        with self.assertRaisesRegex(
                WindowsIdentityRunError, "controller teardown"):
            run_lifecycle(recorder.operations())


if __name__ == "__main__":
    unittest.main()
