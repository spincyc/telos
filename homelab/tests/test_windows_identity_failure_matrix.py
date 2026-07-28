import unittest

from homelab.vm.windows_identity_run import (
    IdentityOperations,
    WindowsIdentityRunError,
    run_lifecycle,
)


class StatefulOperations:
    """Model effects only after an operation successfully returns."""

    operation_names = (
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
    )

    def __init__(self, failure):
        self.failure = failure
        self.events = []
        self.running = set()
        self.local_credential_rotated = False
        self.private_publication_exists = True
        self.controller_principals_exist = False

    def operation(self, name):
        def invoke():
            self.events.append(name)
            if name == self.failure:
                if name.startswith("start_"):
                    # A failed start may already own a partially created
                    # resource, so the lifecycle must still stop that role.
                    self.running.add(name.removeprefix("start_"))
                raise RuntimeError(f"injected {name} failure")
            if name.startswith("start_"):
                self.running.add(name.removeprefix("start_"))
            elif name.startswith("stop_"):
                self.running.remove(name.removeprefix("stop_"))
            elif name == "rotate_local_credential":
                self.local_credential_rotated = True
            elif name == "destroy_private_publication":
                self.private_publication_exists = False
            elif name == "stage_controller_principals":
                self.controller_principals_exist = True
            elif name == "destroy_controller_principals":
                self.controller_principals_exist = False

        return invoke

    def operations(self):
        return IdentityOperations(**{
            name: self.operation(name) for name in self.operation_names
        })


class WindowsIdentityFailureMatrixTests(unittest.TestCase):
    CASES = {
        "start_switch": (
            ["start_switch", "stop_switch"],
            True, False, False, set(),
        ),
        "start_controller": (
            [
                "start_switch", "start_controller",
                "stop_controller", "stop_switch",
            ],
            True, False, False, set(),
        ),
        "start_windows": (
            [
                "start_switch", "start_controller", "start_windows",
                "stop_windows", "stop_controller", "stop_switch",
            ],
            True, False, False, set(),
        ),
        "authenticate_qmp": (
            [
                "start_switch", "start_controller", "start_windows",
                "authenticate_qmp",
                "stop_windows", "stop_controller", "stop_switch",
            ],
            True, False, False, set(),
        ),
        "rotate_local_credential": (
            [
                "start_switch", "start_controller", "start_windows",
                "authenticate_qmp", "rotate_local_credential",
                "stop_windows", "stop_controller", "stop_switch",
            ],
            True, False, False, set(),
        ),
        "destroy_private_publication": (
            [
                "start_switch", "start_controller", "start_windows",
                "authenticate_qmp", "rotate_local_credential",
                "destroy_private_publication",
                "stop_windows", "stop_controller", "stop_switch",
            ],
            True, True, False, set(),
        ),
        "stage_controller_principals": (
            [
                "start_switch", "start_controller", "start_windows",
                "authenticate_qmp", "rotate_local_credential",
                "destroy_private_publication", "stage_controller_principals",
                "stop_windows", "stop_controller", "stop_switch",
            ],
            False, True, False, set(),
        ),
        "run_acceptance_phases": (
            [
                "start_switch", "start_controller", "start_windows",
                "authenticate_qmp", "rotate_local_credential",
                "destroy_private_publication", "stage_controller_principals",
                "run_acceptance_phases", "destroy_controller_principals",
                "stop_windows", "stop_controller", "stop_switch",
            ],
            False, True, False, set(),
        ),
        "destroy_controller_principals": (
            [
                "start_switch", "start_controller", "start_windows",
                "authenticate_qmp", "rotate_local_credential",
                "destroy_private_publication", "stage_controller_principals",
                "run_acceptance_phases", "destroy_controller_principals",
                "stop_windows", "stop_controller", "stop_switch",
            ],
            False, True, True, set(),
        ),
        "stop_windows": (
            [
                "start_switch", "start_controller", "start_windows",
                "authenticate_qmp", "rotate_local_credential",
                "destroy_private_publication", "stage_controller_principals",
                "run_acceptance_phases", "destroy_controller_principals",
                "stop_windows", "stop_controller", "stop_switch",
            ],
            False, True, False, {"windows"},
        ),
        "stop_controller": (
            [
                "start_switch", "start_controller", "start_windows",
                "authenticate_qmp", "rotate_local_credential",
                "destroy_private_publication", "stage_controller_principals",
                "run_acceptance_phases", "destroy_controller_principals",
                "stop_windows", "stop_controller", "stop_switch",
            ],
            False, True, False, {"controller"},
        ),
        "stop_switch": (
            [
                "start_switch", "start_controller", "start_windows",
                "authenticate_qmp", "rotate_local_credential",
                "destroy_private_publication", "stage_controller_principals",
                "run_acceptance_phases", "destroy_controller_principals",
                "stop_windows", "stop_controller", "stop_switch",
            ],
            False, True, False, {"switch"},
        ),
    }

    def test_every_operation_failure_preserves_security_and_reverse_cleanup(self):
        self.assertEqual(
            set(StatefulOperations.operation_names), set(self.CASES),
            "the matrix must name every injectable IdentityOperations phase",
        )
        for failure, expected in self.CASES.items():
            with self.subTest(failure=failure):
                (
                    expected_events,
                    publication_exists,
                    credential_rotated,
                    principals_exist,
                    running,
                ) = expected
                recorder = StatefulOperations(failure)
                if failure == "destroy_controller_principals":
                    diagnostic = "controller principal destruction: RuntimeError"
                elif failure.startswith("stop_"):
                    role = failure.removeprefix("stop_")
                    diagnostic = f"{role} teardown: RuntimeError"
                else:
                    diagnostic = "lifecycle: RuntimeError"

                with self.assertRaisesRegex(
                    WindowsIdentityRunError, diagnostic
                ):
                    run_lifecycle(recorder.operations())

                self.assertEqual(expected_events, recorder.events)
                self.assertEqual(
                    publication_exists, recorder.private_publication_exists)
                self.assertEqual(
                    credential_rotated, recorder.local_credential_rotated)
                self.assertEqual(
                    principals_exist, recorder.controller_principals_exist)
                self.assertEqual(running, recorder.running)


if __name__ == "__main__":
    unittest.main()
