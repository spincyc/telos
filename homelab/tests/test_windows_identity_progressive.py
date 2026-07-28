import unittest
import tempfile
from pathlib import Path
from unittest import mock

from homelab.vm.windows_identity_progressive import (
    NativeBoundaryRotationSession,
    ProgressiveRotationPlan,
    WindowsIdentityProgressiveError,
    execute_progressive_rotation,
)
from homelab.vm.windows_identity_reference import (
    GuestProvenance,
    ValidatedIdentityReference,
)
from homelab.vm.windows_gui import Image


GUEST = GuestProvenance("release", "en-US", "x64", "a" * 64, "b" * 64)


def reference(kind):
    return ValidatedIdentityReference(
        kind, kind, kind != "sign-in", False, GUEST, Path(f"{kind}.ppm"),
        Image(16, 16, bytes(range(256)) * 3), (1280, 800),
        (0, 0, 16, 16), ("c" * 64,) * 3)


class Context:
    def __init__(self, value, events, label):
        self.value, self.events, self.label = value, events, label

    def __enter__(self):
        self.events.append(f"{self.label}:enter")
        return self.value

    def __exit__(self, *_):
        self.events.append(f"{self.label}:exit")


class Recovery(Context):
    def destroy_publication(self):
        self.events.append("destroy")


class Interaction:
    def __init__(self, events, fail=None):
        self.events, self.fail = events, fail

    def observe(self, value, timeout):
        self.events.append(f"observe:{value.state_kind}")
        if self.fail == value.state_kind:
            raise RuntimeError("Old-private-47!")

    def observe_departure(self, value, timeout):
        self.events.append(f"departed:{value.state_kind}")

    def type_secret(self, value):
        self.events.append("type")

    def key(self, value):
        self.events.append(f"key:{value}")

    def chord(self, *values):
        self.events.append("chord:" + "+".join(values))


class ProgressiveRotationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def plan(self):
        return ProgressiveRotationPlan(
            *(Path(f"{kind}.json") for kind in (
                "sign-in", "desktop", "security-options", "change-password")),
            expected_guest=GUEST,
            evidence_root=Path(self.temporary.name) / "evidence",
            change_password_keys=("down", "ret"), timeout=100,
            checkpoint_timeout=20, initial_sign_in_delay=0,
            lock_settle_delay=0)

    def execute(self, *, fail=None, clock=lambda: 0):
        events = []
        self.events = events
        recovery = Recovery("Old-private-47!", events, "recovery")
        session = Context(object(), events, "session")
        references = [
            reference(kind) for kind in (
                "sign-in", "desktop", "security-options", "change-password")]
        with mock.patch(
            "homelab.vm.windows_identity_progressive.load_identity_reference",
            side_effect=references,
        ):
            receipt = execute_progressive_rotation(
                plan=self.plan(), session=session, recovery=recovery,
                generate_credential=lambda: "New-private-83!", clock=clock,
                pause=lambda _: None,
                interaction_factory=lambda _qmp, _root: Interaction(events, fail))
        return events, receipt

    def test_rotation_proves_reauthentication_then_immediately_destroys(self):
        events, receipt = self.execute()
        destroyed = events.index("destroy")
        self.assertEqual("observe:desktop", events[destroyed - 1])
        self.assertLess(events.index("chord:meta_l+l"), destroyed)
        replacement_sign_in = events.index(
            "observe:sign-in", events.index("chord:meta_l+l"))
        self.assertLess(replacement_sign_in, destroyed)
        self.assertIn("departed:change-password", events)
        departure = events.index("departed:change-password")
        self.assertEqual("key:ret", events[departure + 1])
        self.assertIn("key:spc", events[:events.index("observe:sign-in")])
        self.assertEqual("session:exit", events[-2])
        self.assertEqual("recovery:exit", events[-1])
        self.assertTrue(receipt.publication_destroyed)
        self.assertTrue(receipt.replacement_sign_in_proved)

    def test_failure_before_outcome_preserves_publication_and_tears_down(self):
        with self.assertRaisesRegex(
            WindowsIdentityProgressiveError, "RuntimeError"
        ) as caught:
            self.execute(fail="change-password")
        events = self.events
        self.assertNotIn("Old-private-47!", str(caught.exception))
        self.assertNotIn("destroy", events)
        self.assertEqual(["session:exit", "recovery:exit"], events[-2:])

    def test_failed_reauthentication_preserves_publication_and_hides_secret(self):
        events = []
        recovery = Recovery("Old-private-47!", events, "recovery")
        session = Context(object(), events, "session")
        calls = {"sign-in": 0}

        class FailingInteraction(Interaction):
            def observe(self, value, timeout):
                calls[value.state_kind] = calls.get(value.state_kind, 0) + 1
                if value.state_kind == "sign-in" and calls["sign-in"] == 2:
                    raise RuntimeError("New-private-83!")
                super().observe(value, timeout)

        with mock.patch(
            "homelab.vm.windows_identity_progressive.load_identity_reference",
            side_effect=[reference(kind) for kind in (
                "sign-in", "desktop", "security-options", "change-password")],
        ):
            with self.assertRaises(WindowsIdentityProgressiveError) as caught:
                execute_progressive_rotation(
                    plan=self.plan(), session=session, recovery=recovery,
                    generate_credential=lambda: "New-private-83!",
                    interaction_factory=lambda _qmp, _root: FailingInteraction(events))
        self.assertNotIn("destroy", events)
        self.assertEqual(["session:exit", "recovery:exit"], events[-2:])
        self.assertNotIn("New-private-83!", str(caught.exception))

    def test_global_deadline_is_enforced_before_next_operation(self):
        times = iter((0, 1, 2, 101))
        with self.assertRaisesRegex(
            WindowsIdentityProgressiveError, "deadline expired"
        ):
            self.execute(clock=lambda: next(times))

    def test_manifest_validation_happens_before_opening_private_contexts(self):
        events = []
        with mock.patch(
            "homelab.vm.windows_identity_progressive.load_identity_reference",
            side_effect=OSError("invalid"),
        ):
            with self.assertRaisesRegex(
                WindowsIdentityProgressiveError, "validation failed"
            ):
                execute_progressive_rotation(
                    plan=self.plan(),
                    session=Context(object(), events, "session"),
                    recovery=Recovery("secret", events, "recovery"),
                    generate_credential=lambda: "different-secret")
        self.assertEqual([], events)

    def test_invalid_public_navigation_is_rejected_before_private_contexts(self):
        events = []
        invalid = self.plan()
        invalid = type(invalid)(
            **{**invalid.__dict__, "change_password_keys": ("unsafe",)})
        with self.assertRaisesRegex(
            WindowsIdentityProgressiveError, "invalid progressive plan"
        ):
            execute_progressive_rotation(
                plan=invalid,
                session=Context(object(), events, "session"),
                recovery=Recovery("secret", events, "recovery"),
                generate_credential=lambda: "different-secret")
        self.assertEqual([], events)

    def test_native_session_starts_and_tears_down_in_reverse_order(self):
        events = []
        boundary = mock.Mock()
        boundary.qmp = object()
        for name in (
            "start_switch", "start_controller", "start_windows",
            "authenticate_qmp", "stop_windows", "stop_controller",
            "stop_switch",
        ):
            setattr(
                boundary, name,
                mock.Mock(side_effect=lambda selected=name: events.append(selected)))
        with NativeBoundaryRotationSession(boundary) as qmp:
            self.assertIs(qmp, boundary.qmp)
        self.assertEqual([
            "start_switch", "start_controller", "start_windows",
            "authenticate_qmp", "stop_windows", "stop_controller",
            "stop_switch",
        ], events)

    def test_native_partial_start_failure_cleans_every_intended_role(self):
        events = []
        boundary = mock.Mock()
        boundary.start_switch.side_effect = lambda: events.append("start-switch")
        boundary.start_controller.side_effect = RuntimeError("private")
        boundary.stop_controller.side_effect = lambda: events.append("stop-controller")
        boundary.stop_switch.side_effect = lambda: events.append("stop-switch")
        with self.assertRaises(RuntimeError):
            with NativeBoundaryRotationSession(boundary):
                self.fail("unreachable")
        self.assertEqual(
            ["start-switch", "stop-controller", "stop-switch"], events)

    def test_native_teardown_retains_failed_role_for_retry(self):
        boundary = mock.Mock()
        boundary.qmp = object()
        boundary.stop_windows.side_effect = [
            RuntimeError("private backend detail"), None]
        session = NativeBoundaryRotationSession(boundary)
        session.__enter__()
        with self.assertRaisesRegex(
                WindowsIdentityProgressiveError, "windows: RuntimeError"):
            session.__exit__(None, None, None)
        self.assertEqual(["windows"], session._intended)
        session.__exit__(None, None, None)
        self.assertEqual([], session._intended)


if __name__ == "__main__":
    unittest.main()
