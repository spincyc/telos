import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from homelab.vm import (
    windows_identity_orchestrator,
    windows_identity_progressive as progressive_subject,
)
from homelab.vm.windows_identity_adapter import WindowsIdentityAdapterError
from homelab.vm.windows_identity_progressive import (
    NativeBoundaryRotationSession,
    ProgressiveGuiFailureDiagnostic,
    ProgressiveRotationPlan,
    WindowsIdentityProgressiveError,
    execute_progressive_rotation,
)
from homelab.vm.windows_identity_run import (
    IdentityFailureDiagnostic,
    PrivateIdentityMaterial,
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

    def test_post_secret_observation_never_retains_pixels(self):
        evidence = Path(self.temporary.name) / "evidence"
        evidence.mkdir(mode=0o700)
        qmp = mock.Mock()
        qmp.screenshot.side_effect = (
            lambda path: path.write_bytes(b"ephemeral-pixels"))
        driver = mock.Mock(
            sequence=0,
            observer=SimpleNamespace(root=evidence),
            clock=mock.Mock(side_effect=(0.0, 0.0, 0.0)),
            pause=mock.Mock(),
            interval=1.0,
        )
        with (
            mock.patch.object(
                progressive_subject,
                "WindowsCredentialRotationDriver",
                return_value=driver,
            ),
            mock.patch.object(
                progressive_subject, "read_ppm",
                return_value=SimpleNamespace(width=1280, height=800),
            ),
            mock.patch.object(
                progressive_subject, "crop_image",
                return_value=mock.sentinel.cropped,
            ),
            mock.patch.object(
                progressive_subject, "image_distance", return_value=0.0,
            ),
            mock.patch.object(
                progressive_subject, "useful_frame", return_value=True,
            ),
        ):
            interaction = progressive_subject._GuiInteraction(qmp, evidence)
            interaction.disable_durable_capture()
            with self.assertRaisesRegex(
                    progressive_subject.WindowsIdentityGuiError,
                    "disabled"):
                interaction.observe(reference("desktop"), 1.0)
            interaction.observe_ephemeral(reference("desktop"), 1.0)

        self.assertEqual(2, qmp.screenshot.call_count)
        self.assertEqual([], list(evidence.iterdir()))

    def test_ephemeral_observation_rejects_wrong_full_frame_geometry(self):
        evidence = Path(self.temporary.name) / "wrong-geometry"
        evidence.mkdir(mode=0o700)
        qmp = mock.Mock()
        qmp.screenshot.side_effect = (
            lambda path: path.write_bytes(b"ephemeral-pixels"))
        driver = mock.Mock(
            sequence=0,
            observer=SimpleNamespace(root=evidence),
            clock=mock.Mock(side_effect=(0.0, 0.0)),
            pause=mock.Mock(),
            interval=1.0,
        )
        with (
            mock.patch.object(
                progressive_subject,
                "WindowsCredentialRotationDriver",
                return_value=driver,
            ),
            mock.patch.object(
                progressive_subject, "read_ppm",
                return_value=SimpleNamespace(width=640, height=400),
            ),
        ):
            interaction = progressive_subject._GuiInteraction(qmp, evidence)
            with self.assertRaisesRegex(
                    progressive_subject.WindowsIdentityGuiError,
                    "geometry differs"):
                interaction.observe_ephemeral(reference("desktop"), 1.0)
        self.assertEqual([], list(evidence.iterdir()))

    def test_concrete_interaction_classifies_ephemeral_sign_in_twice(self):
        evidence = Path(self.temporary.name) / "alternate-evidence"
        evidence.mkdir(mode=0o700)
        qmp = mock.Mock()
        qmp.screenshot.side_effect = (
            lambda path: path.write_bytes(b"ephemeral-pixels"))
        driver = mock.Mock(
            sequence=0,
            observer=SimpleNamespace(root=evidence),
            clock=mock.Mock(side_effect=(0.0, 0.0, 0.0, 2.0)),
            pause=mock.Mock(),
            interval=1.0,
        )
        with (
            mock.patch.object(
                progressive_subject,
                "WindowsCredentialRotationDriver",
                return_value=driver,
            ),
            mock.patch.object(
                progressive_subject, "read_ppm",
                return_value=SimpleNamespace(width=1280, height=800),
            ),
            mock.patch.object(
                progressive_subject, "crop_image",
                return_value=mock.sentinel.cropped,
            ),
            mock.patch.object(
                progressive_subject, "image_distance",
                side_effect=(10.0, 0.0, 10.0, 0.0),
            ),
            mock.patch.object(
                progressive_subject, "useful_frame", return_value=True,
            ),
        ):
            interaction = progressive_subject._GuiInteraction(qmp, evidence)
            for method in (
                "observe_departure", "type_secret", "key", "chord",
            ):
                self.assertTrue(hasattr(interaction, method))
            with self.assertRaises(
                    progressive_subject.WindowsIdentityGuiAlternateState
            ) as caught:
                interaction.observe_ephemeral(
                    reference("desktop"),
                    1.0,
                    alternatives=(("sign-in", reference("sign-in")),),
                )

        self.assertEqual("sign-in", caught.exception.state)
        self.assertEqual(2, qmp.screenshot.call_count)
        self.assertEqual([], list(evidence.iterdir()))

    def test_concrete_interaction_classifies_only_terminal_near_reference(self):
        for state, distances in (
            ("desktop", (9.0, 30.0, 9.0, 30.0)),
            ("sign-in", (30.0, 9.0, 30.0, 9.0)),
        ):
            with self.subTest(state=state):
                evidence = Path(self.temporary.name) / f"near-{state}"
                evidence.mkdir(mode=0o700)
                qmp = mock.Mock()
                qmp.screenshot.side_effect = (
                    lambda path: path.write_bytes(b"ephemeral-pixels"))
                driver = mock.Mock(
                    sequence=0,
                    observer=SimpleNamespace(root=evidence),
                    clock=mock.Mock(side_effect=(0.0, 0.0, 0.0, 2.0)),
                    pause=mock.Mock(),
                    interval=1.0,
                )
                with (
                    mock.patch.object(
                        progressive_subject,
                        "WindowsCredentialRotationDriver",
                        return_value=driver,
                    ),
                    mock.patch.object(
                        progressive_subject, "read_ppm",
                        return_value=SimpleNamespace(width=1280, height=800),
                    ),
                    mock.patch.object(
                        progressive_subject, "crop_image",
                        return_value=mock.sentinel.cropped,
                    ),
                    mock.patch.object(
                        progressive_subject, "image_distance",
                        side_effect=distances,
                    ),
                    mock.patch.object(
                        progressive_subject, "useful_frame",
                        return_value=True,
                    ),
                ):
                    interaction = progressive_subject._GuiInteraction(
                        qmp, evidence)
                    with self.assertRaises(
                        progressive_subject.WindowsIdentityGuiNearReference,
                    ) as caught:
                        interaction.observe_ephemeral(
                            reference("desktop"),
                            1.0,
                            alternatives=(
                                ("sign-in", reference("sign-in")),
                            ),
                        )

                self.assertEqual(state, caught.exception.state)
                self.assertEqual(2, qmp.screenshot.call_count)
                self.assertEqual([], list(evidence.iterdir()))

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
                generate_credential=lambda: (
                    events.append("generate") or "New-private-83!"),
                after_rotation=lambda _replacement: None,
                clock=clock,
                pause=lambda _: None,
                interaction_factory=lambda _qmp, _root: Interaction(events, fail))
        return events, receipt

    def test_rotation_proves_reauthentication_then_immediately_destroys(self):
        events, receipt = self.execute()
        destroyed = events.index("destroy")
        self.assertEqual("observe:desktop", events[destroyed - 1])
        self.assertLess(events.index("chord:meta_l+l"), destroyed)
        generated = events.index("generate")
        self.assertGreater(generated, events.index("observe:change-password"))
        self.assertGreater(generated, events.index("observe:desktop"))
        self.assertLess(generated, events.index("type", generated))
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

    def test_failed_post_rotation_acceptance_preserves_publication(self):
        events = []
        recovery = Recovery("Old-private-47!", events, "recovery")
        session = Context(object(), events, "session")
        references = [
            reference(kind) for kind in (
                "sign-in", "desktop", "security-options", "change-password")]

        def fail_acceptance(_replacement):
            events.append("acceptance")
            raise RuntimeError("New-private-83!")

        with mock.patch(
            "homelab.vm.windows_identity_progressive.load_identity_reference",
            side_effect=references,
        ):
            with self.assertRaises(WindowsIdentityProgressiveError) as caught:
                execute_progressive_rotation(
                    plan=self.plan(),
                    session=session,
                    recovery=recovery,
                    generate_credential=lambda: "New-private-83!",
                    after_rotation=fail_acceptance,
                    pause=lambda _: None,
                    interaction_factory=lambda _qmp, _root: Interaction(events),
                )
        self.assertIn("acceptance", events)
        self.assertNotIn("destroy", events)
        self.assertNotIn("New-private-83!", str(caught.exception))
        self.assertEqual(["session:exit", "recovery:exit"], events[-2:])

    def test_static_probe_failure_retains_only_allowlisted_coordinates(self):
        events = []
        secret = "Controller-private-message-47!"

        diagnostic = IdentityFailureDiagnostic.static_probe(
            "controller-ready",
            "controller-readiness",
            WindowsIdentityAdapterError(secret),
            phase="outcome-receive",
        )
        callbacks = SimpleNamespace(
            static_probe=lambda _action: (_ for _ in ()).throw(
                WindowsIdentityAdapterError(
                    secret, diagnostic=diagnostic)))
        material = PrivateIdentityMaterial(
            Path(self.temporary.name) / "unused-publication",
            Path(self.temporary.name),
            rotate_guest=mock.Mock(),
            stage_principals=mock.Mock(),
            destroy_principals=mock.Mock(),
        )

        def acceptance(_local, _principals):
            windows_identity_orchestrator._validated_static_probes(
                callbacks, "controller-ready")

        references = [
            reference(kind) for kind in (
                "sign-in", "desktop", "security-options", "change-password")]
        with mock.patch(
            "homelab.vm.windows_identity_progressive.load_identity_reference",
            side_effect=references,
        ):
            with self.assertRaises(WindowsIdentityProgressiveError) as caught:
                execute_progressive_rotation(
                    plan=self.plan(),
                    session=Context(object(), events, "session"),
                    recovery=Recovery("Old-private-47!", events, "recovery"),
                    generate_credential=material.generate_replacement_credential,
                    after_rotation=lambda replacement:
                        material.run_scoped_acceptance(
                            replacement, acceptance),
                    pause=lambda _: None,
                    interaction_factory=lambda _qmp, _root:
                        Interaction(events),
                )
        message = str(caught.exception)
        self.assertIn("check=controller-ready", message)
        self.assertIn(
            "operation=static-probe.controller-readiness.outcome-receive",
            message,
        )
        self.assertIn("error=WindowsIdentityAdapterError", message)
        self.assertNotIn(secret, message)
        self.assertNotIn("Old-private-47!", message)
        self.assertEqual(diagnostic, caught.exception.diagnostic)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("destroy", events)
        self.assertEqual(["session:exit", "recovery:exit"], events[-2:])

    def test_unknown_static_probe_error_is_normalized_without_context(self):
        secret = "Unknown-private-message-47!"

        class SecretFailure(RuntimeError):
            pass

        callbacks = SimpleNamespace(
            static_probe=lambda _action: (_ for _ in ()).throw(
                SecretFailure(secret)))
        with self.assertRaises(
            windows_identity_orchestrator.WindowsIdentityOrchestratorError,
        ) as caught:
            windows_identity_orchestrator._validated_static_probes(
                callbacks, "controller-ready")
        message = str(caught.exception)
        self.assertIn("error=UnexpectedError", message)
        self.assertNotIn("SecretFailure", message)
        self.assertNotIn(secret, message)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_failure_before_outcome_preserves_publication_and_tears_down(self):
        with self.assertRaisesRegex(
            WindowsIdentityProgressiveError,
            "stage=change-password; operation=observe; "
            "error=UnexpectedError",
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
                    after_rotation=lambda _replacement: None,
                    interaction_factory=lambda _qmp, _root: FailingInteraction(events))
        self.assertNotIn("destroy", events)
        self.assertEqual(["session:exit", "recovery:exit"], events[-2:])
        self.assertNotIn("New-private-83!", str(caught.exception))

    def test_gui_phase_failures_have_only_allowlisted_coordinates(self):
        cases = (
            ("key", 1, "initial-sign-in", "wake"),
            ("observe", 1, "initial-sign-in", "observe"),
            ("type-secret", 1, "old-sign-in", "submit"),
            ("observe", 2, "initial-desktop", "observe"),
            ("chord", 1, "security-options", "request"),
            ("observe", 3, "security-options", "observe"),
            ("key", 3, "change-password", "navigate"),
            ("observe", 4, "change-password", "observe"),
            ("type-secret", 2, "credential-rotation", "submit"),
            ("observe-departure", 1, "change-password-confirmation",
             "observe-departure"),
            ("key", 8, "change-password-confirmation", "acknowledge"),
            ("observe", 5, "post-rotation-desktop", "observe"),
            ("chord", 2, "replacement-sign-in", "lock"),
            ("key", 9, "replacement-sign-in", "wake"),
            ("observe", 6, "replacement-sign-in", "observe"),
            ("type-secret", 5, "replacement-sign-in", "submit"),
            ("observe", 7, "final-desktop", "observe"),
        )
        self.assertEqual(
            {(stage, operation)
             for _, _, stage, operation in cases},
            ProgressiveGuiFailureDiagnostic._COORDINATES,
        )
        for method, occurrence, expected_stage, expected_operation in cases:
            with self.subTest(
                stage=expected_stage, operation=expected_operation,
            ):
                events = []
                counts = {}
                secret = (
                    f"private-backend-{expected_stage}-"
                    f"{expected_operation}-47!")

                class FailingPhaseInteraction(Interaction):
                    def _fail(self, selected):
                        counts[selected] = counts.get(selected, 0) + 1
                        if (
                            selected == method
                            and counts[selected] == occurrence
                        ):
                            try:
                                raise RuntimeError(secret)
                            except RuntimeError:
                                raise WindowsIdentityProgressiveError(secret)

                    def observe(self, value, timeout):
                        self._fail("observe")
                        super().observe(value, timeout)

                    def observe_departure(self, value, timeout):
                        self._fail("observe-departure")
                        super().observe_departure(value, timeout)

                    def type_secret(self, value):
                        self._fail("type-secret")
                        super().type_secret(value)

                    def key(self, value):
                        self._fail("key")
                        super().key(value)

                    def chord(self, *values):
                        self._fail("chord")
                        super().chord(*values)

                references = [
                    reference(kind) for kind in (
                        "sign-in", "desktop", "security-options",
                        "change-password")]
                with mock.patch(
                    "homelab.vm.windows_identity_progressive."
                    "load_identity_reference",
                    side_effect=references,
                ):
                    with self.assertRaises(
                        WindowsIdentityProgressiveError,
                    ) as caught:
                        execute_progressive_rotation(
                            plan=self.plan(),
                            session=Context(
                                object(), events, "session"),
                            recovery=Recovery(
                                "Old-private-47!", events, "recovery"),
                            generate_credential=lambda: "New-private-83!",
                            after_rotation=lambda _replacement: None,
                            pause=lambda _: None,
                            interaction_factory=lambda _qmp, _root:
                                FailingPhaseInteraction(events),
                        )
                diagnostic = caught.exception.diagnostic
                self.assertIsInstance(
                    diagnostic, ProgressiveGuiFailureDiagnostic)
                self.assertEqual(expected_stage, diagnostic.stage)
                self.assertEqual(expected_operation, diagnostic.operation)
                self.assertEqual("UnexpectedError", diagnostic.error_type)
                self.assertIn(
                    f"stage={expected_stage}", str(caught.exception))
                self.assertNotIn(
                    "WindowsIdentityProgressiveError",
                    str(caught.exception),
                )
                self.assertNotIn(secret, str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn("destroy", events)
                self.assertEqual(
                    ["session:exit", "recovery:exit"], events[-2:])

    def test_gui_diagnostic_constructor_rejects_unlisted_values(self):
        with self.assertRaisesRegex(ValueError, "coordinates"):
            ProgressiveGuiFailureDiagnostic(
                "initial-sign-in", "type-secret", "UnexpectedError")
        with self.assertRaisesRegex(ValueError, "type"):
            ProgressiveGuiFailureDiagnostic(
                "initial-sign-in", "observe", "PrivateBackendError")

    def test_global_deadline_is_enforced_before_next_operation(self):
        times = iter((0, 1, 2, 101))
        with self.assertRaisesRegex(
            WindowsIdentityProgressiveError, "deadline expired"
        ):
            self.execute(clock=lambda: next(times))

    def test_rotation_deadline_starts_after_session_acquisition(self):
        now = [0.0]
        events = []

        class DelayedSession(Context):
            def __enter__(self):
                now[0] = 500.0
                return super().__enter__()

        references = [
            reference(kind) for kind in (
                "sign-in", "desktop", "security-options", "change-password")]
        with mock.patch(
            "homelab.vm.windows_identity_progressive.load_identity_reference",
            side_effect=references,
        ):
            receipt = execute_progressive_rotation(
                plan=self.plan(),
                session=DelayedSession(object(), events, "session"),
                recovery=Recovery("Old-private-47!", events, "recovery"),
                generate_credential=lambda: "New-private-83!",
                after_rotation=lambda _replacement: None,
                clock=lambda: now[0],
                pause=lambda _: None,
                interaction_factory=lambda _qmp, _root: Interaction(events),
            )
        self.assertTrue(receipt.replacement_sign_in_proved)
        self.assertIn("observe:sign-in", events)

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
                    generate_credential=lambda: "different-secret",
                    after_rotation=lambda _replacement: None)
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
                generate_credential=lambda: "different-secret",
                after_rotation=lambda _replacement: None)
        invalid = self.plan()
        invalid = type(invalid)(**{
            **invalid.__dict__,
            "post_join_operator_account_keys": ("unsafe",),
        })
        with self.assertRaisesRegex(
            WindowsIdentityProgressiveError, "invalid progressive plan"
        ):
            execute_progressive_rotation(
                plan=invalid,
                session=Context(object(), events, "session"),
                recovery=Recovery("secret", events, "recovery"),
                generate_credential=lambda: "different-secret",
                after_rotation=lambda _replacement: None)
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
