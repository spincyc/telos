#!/usr/bin/env python3
"""Direct parity tests for child-process supervision."""

from __future__ import annotations

import importlib
import inspect
import signal
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src"


class ProcessStub:
    def __init__(
        self,
        events: list[tuple[str, object]],
        *,
        wait_actions: list[object],
        poll_results: list[int | None] | None = None,
        send_failures: list[BaseException | None] | None = None,
        terminate_failure: BaseException | None = None,
    ) -> None:
        self.events = events
        self.wait_actions = wait_actions.copy()
        self.poll_results = (poll_results or []).copy()
        self.send_failures = (send_failures or []).copy()
        self.terminate_failure = terminate_failure

    def wait(self, timeout: int | None = None) -> int:
        self.events.append(("wait", timeout))
        if not self.wait_actions:
            raise AssertionError("unexpected wait")
        action = self.wait_actions.pop(0)
        if isinstance(action, BaseException):
            raise action
        if callable(action):
            return action(timeout)
        return action

    def poll(self) -> int | None:
        self.events.append(("poll", None))
        if not self.poll_results:
            raise AssertionError("unexpected poll")
        return self.poll_results.pop(0)

    def send_signal(self, signum: int) -> None:
        self.events.append(("send", signum))
        failure = self.send_failures.pop(0) if self.send_failures else None
        if failure is not None:
            raise failure

    def terminate(self) -> None:
        self.events.append(("terminate", None))
        if self.terminate_failure is not None:
            raise self.terminate_failure


class SignalFailure(RuntimeError):
    """An injected signal-handler operation failure."""


class SignalHarness:
    def __init__(
        self,
        events: list[tuple[str, object]],
        *,
        forwarded_signals: tuple[int, int] = (
            signal.SIGHUP,
            signal.SIGTERM,
        ),
        fail_get: int | None = None,
        fail_install: int | None = None,
        fail_restore: int | None = None,
    ) -> None:
        self.events = events
        self.forwarded_signals = forwarded_signals
        self.fail_get = fail_get
        self.fail_install = fail_install
        self.fail_restore = fail_restore
        self.old = {
            signum: object()
            for signum in forwarded_signals
        }
        self.installed: dict[int, object] = {}

    def getsignal(self, signum: int) -> object:
        self.events.append(("getsignal", signum))
        if signum == self.fail_get:
            raise SignalFailure(f"getsignal failed for {signum}")
        return self.old[signum]

    def set_signal(self, signum: int, handler: object) -> object:
        restoring = handler is self.old[signum]
        operation = "restore" if restoring else "install"
        self.events.append((operation, signum))
        if not restoring and signum == self.fail_install:
            raise SignalFailure(f"install failed for {signum}")
        if restoring and signum == self.fail_restore:
            raise SignalFailure(f"restore failed for {signum}")
        if not restoring:
            self.installed[signum] = handler
        return self.old[signum]


class ChildProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(SOURCE_ROOT))
        cls.process_policy = importlib.import_module("worktree_marshal.process")
        cls.engine = importlib.import_module("worktree_marshal.engine")

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            sys.path.remove(str(SOURCE_ROOT))
        except ValueError:
            pass

    def invoke(
        self,
        process: ProcessStub,
        harness: SignalHarness,
        *,
        interrupt_signal: int = signal.SIGINT,
        keyboard_interrupt: type[BaseException] = KeyboardInterrupt,
        process_lookup_error: type[BaseException] = ProcessLookupError,
        timeout_expired: type[BaseException] = subprocess.TimeoutExpired,
    ) -> int:
        return self.process_policy.wait_for_child(
            process,
            forwarded_signals=lambda: harness.forwarded_signals,
            get_signal_handler=harness.getsignal,
            set_signal_handler=harness.set_signal,
            interrupt_signal=lambda: interrupt_signal,
            keyboard_interrupt=lambda: keyboard_interrupt,
            process_lookup_error=lambda: process_lookup_error,
            timeout_expired=lambda: timeout_expired,
        )

    def test_process_import_is_engine_free_and_side_effect_free(self) -> None:
        script = (
            "import os, signal, sys; "
            "before_environment = dict(os.environ); "
            "before_handlers = ("
            "signal.getsignal(signal.SIGHUP), "
            "signal.getsignal(signal.SIGTERM)"
            "); "
            f"sys.path.insert(0, {str(SOURCE_ROOT)!r}); "
            "import worktree_marshal.process; "
            "after_handlers = ("
            "signal.getsignal(signal.SIGHUP), "
            "signal.getsignal(signal.SIGTERM)"
            "); "
            "raise SystemExit("
            "'worktree_marshal.engine' in sys.modules "
            "or dict(os.environ) != before_environment "
            "or after_handlers != before_handlers"
            ")"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=PACKAGE_ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_engine_preserves_the_existing_process_helper_surface(self) -> None:
        self.assertIsNot(
            self.engine.wait_for_child,
            self.process_policy.wait_for_child,
        )
        self.assertIsNot(
            self.engine.normalized_exit_status,
            self.process_policy.normalized_exit_status,
        )
        expected_parameters = (
            ("wait_for_child", "process"),
            ("normalized_exit_status", "returncode"),
        )
        for helper_name, parameter_name in expected_parameters:
            with self.subTest(helper=helper_name):
                helper = getattr(self.engine, helper_name)
                parameters = inspect.signature(helper).parameters
                self.assertEqual(tuple(parameters), (parameter_name,))
                self.assertIs(
                    parameters[parameter_name].kind,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
                self.assertIs(
                    parameters[parameter_name].default,
                    inspect.Parameter.empty,
                )

    def test_engine_wrapper_uses_rebound_signal_and_timeout_dependencies(
        self,
    ) -> None:
        forwarded = (71, 72)
        interrupt = 73
        events: list[tuple[str, object]] = []
        harness = SignalHarness(events, forwarded_signals=forwarded)

        class ReboundTimeout(Exception):
            pass

        class InitialTimeout(Exception):
            pass

        def interrupt_after_rebinding(timeout: int | None) -> int:
            self.assertIsNone(timeout)
            self.engine.signal = after_setup_signal_api
            raise KeyboardInterrupt

        def rebind_timeout(timeout: int | None) -> int:
            self.assertEqual(timeout, 10)
            self.engine.subprocess = SimpleNamespace(
                TimeoutExpired=ReboundTimeout,
            )
            raise ReboundTimeout

        after_setup_signal_api = SimpleNamespace(
            SIGHUP=forwarded[0],
            SIGTERM=forwarded[1],
            SIGINT=interrupt,
            getsignal=harness.getsignal,
            signal=harness.set_signal,
        )
        signal_api = SimpleNamespace(
            SIGHUP=forwarded[0],
            SIGTERM=forwarded[1],
            SIGINT=interrupt + 1,
            getsignal=harness.getsignal,
            signal=harness.set_signal,
        )
        subprocess_api = SimpleNamespace(TimeoutExpired=InitialTimeout)
        process = ProcessStub(
            events,
            wait_actions=[interrupt_after_rebinding, rebind_timeout, -9],
            poll_results=[None],
        )

        with (
            mock.patch.object(self.engine, "signal", signal_api),
            mock.patch.object(self.engine, "subprocess", subprocess_api),
        ):
            observed = self.engine.wait_for_child(process)

        self.assertEqual(observed, -9)
        self.assertEqual(
            events,
            [
                ("getsignal", forwarded[0]),
                ("install", forwarded[0]),
                ("getsignal", forwarded[1]),
                ("install", forwarded[1]),
                ("wait", None),
                ("poll", None),
                ("send", interrupt),
                ("wait", 10),
                ("terminate", None),
                ("wait", None),
                ("restore", forwarded[0]),
                ("restore", forwarded[1]),
            ],
        )

    def test_engine_wrapper_honors_rebound_exception_names(self) -> None:
        forwarded = (75, 76)

        class ReboundInterrupt(BaseException):
            pass

        interrupt_events: list[tuple[str, object]] = []
        interrupt_harness = SignalHarness(
            interrupt_events,
            forwarded_signals=forwarded,
        )
        signal_api = SimpleNamespace(
            SIGHUP=forwarded[0],
            SIGTERM=forwarded[1],
            SIGINT=77,
            getsignal=interrupt_harness.getsignal,
            signal=interrupt_harness.set_signal,
        )
        interrupt_process = ProcessStub(
            interrupt_events,
            wait_actions=[KeyboardInterrupt()],
        )

        with (
            mock.patch.object(self.engine, "signal", signal_api),
            mock.patch.object(
                self.engine,
                "KeyboardInterrupt",
                ReboundInterrupt,
                create=True,
            ),
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.engine.wait_for_child(interrupt_process)

        self.assertEqual(
            interrupt_events[-3:],
            [
                ("wait", None),
                ("restore", forwarded[0]),
                ("restore", forwarded[1]),
            ],
        )

        class ReboundLookupError(OSError):
            pass

        lookup_events: list[tuple[str, object]] = []
        lookup_harness = SignalHarness(
            lookup_events,
            forwarded_signals=forwarded,
        )

        def forward_signal(timeout: int | None) -> int:
            self.assertIsNone(timeout)
            lookup_harness.installed[forwarded[0]](forwarded[0], None)
            return 0

        lookup_process = ProcessStub(
            lookup_events,
            wait_actions=[forward_signal],
            poll_results=[None],
            send_failures=[ProcessLookupError("child exited")],
        )
        lookup_signal_api = SimpleNamespace(
            SIGHUP=forwarded[0],
            SIGTERM=forwarded[1],
            SIGINT=77,
            getsignal=lookup_harness.getsignal,
            signal=lookup_harness.set_signal,
        )

        with (
            mock.patch.object(self.engine, "signal", lookup_signal_api),
            mock.patch.object(
                self.engine,
                "ProcessLookupError",
                ReboundLookupError,
                create=True,
            ),
        ):
            with self.assertRaisesRegex(
                ProcessLookupError,
                "^child exited$",
            ):
                self.engine.wait_for_child(lookup_process)

        self.assertEqual(
            lookup_events[-4:],
            [
                ("poll", None),
                ("send", forwarded[0]),
                ("restore", forwarded[0]),
                ("restore", forwarded[1]),
            ],
        )

    def test_engine_wrapper_resolves_exception_names_at_match_time(
        self,
    ) -> None:
        forwarded = (78, 79)
        interrupt = 80
        events: list[tuple[str, object]] = []
        harness = SignalHarness(events, forwarded_signals=forwarded)

        class InitialInterrupt(BaseException):
            pass

        class ReboundInterrupt(BaseException):
            pass

        class InitialLookupError(OSError):
            pass

        class ReboundLookupError(OSError):
            pass

        def raise_rebound_interrupt(timeout: int | None) -> int:
            self.assertIsNone(timeout)
            self.engine.KeyboardInterrupt = ReboundInterrupt
            raise ReboundInterrupt

        process = ProcessStub(
            events,
            wait_actions=[raise_rebound_interrupt, 31],
            poll_results=[None],
        )

        def raise_rebound_lookup(signum: int) -> None:
            events.append(("send", signum))
            self.engine.ProcessLookupError = ReboundLookupError
            raise ReboundLookupError

        process.send_signal = raise_rebound_lookup
        signal_api = SimpleNamespace(
            SIGHUP=forwarded[0],
            SIGTERM=forwarded[1],
            SIGINT=interrupt,
            getsignal=harness.getsignal,
            signal=harness.set_signal,
        )

        with (
            mock.patch.object(self.engine, "signal", signal_api),
            mock.patch.object(
                self.engine,
                "KeyboardInterrupt",
                InitialInterrupt,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "ProcessLookupError",
                InitialLookupError,
                create=True,
            ),
        ):
            observed = self.engine.wait_for_child(process)

        self.assertEqual(observed, 31)
        self.assertEqual(
            events,
            [
                ("getsignal", forwarded[0]),
                ("install", forwarded[0]),
                ("getsignal", forwarded[1]),
                ("install", forwarded[1]),
                ("wait", None),
                ("poll", None),
                ("send", interrupt),
                ("wait", 10),
                ("restore", forwarded[0]),
                ("restore", forwarded[1]),
            ],
        )

    def test_engine_wrapper_resolves_signal_operations_lazily(self) -> None:
        forwarded = (81, 82)
        events: list[tuple[str, object]] = []
        harness = SignalHarness(events, forwarded_signals=forwarded)
        second_api = SimpleNamespace(
            SIGHUP=forwarded[0],
            SIGTERM=forwarded[1],
            SIGINT=83,
            getsignal=harness.getsignal,
            signal=harness.set_signal,
        )
        first_set_signal = mock.Mock(
            side_effect=AssertionError("captured the old signal module"),
        )

        def rebind_after_first_lookup(signum: int) -> object:
            handler = harness.getsignal(signum)
            self.engine.signal = second_api
            return handler

        first_api = SimpleNamespace(
            SIGHUP=forwarded[0],
            SIGTERM=forwarded[1],
            SIGINT=83,
            getsignal=rebind_after_first_lookup,
            signal=first_set_signal,
        )
        process = ProcessStub(events, wait_actions=[0])

        with mock.patch.object(self.engine, "signal", first_api):
            observed = self.engine.wait_for_child(process)

        self.assertEqual(observed, 0)
        first_set_signal.assert_not_called()
        self.assertEqual(
            events,
            [
                ("getsignal", forwarded[0]),
                ("install", forwarded[0]),
                ("getsignal", forwarded[1]),
                ("install", forwarded[1]),
                ("wait", None),
                ("restore", forwarded[0]),
                ("restore", forwarded[1]),
            ],
        )

    def test_normal_wait_forwards_only_to_a_live_child_and_restores(self) -> None:
        events: list[tuple[str, object]] = []
        harness = SignalHarness(events)

        def wait_action(timeout: int | None) -> int:
            self.assertIsNone(timeout)
            hup_handler = harness.installed[signal.SIGHUP]
            term_handler = harness.installed[signal.SIGTERM]
            self.assertIs(hup_handler, term_handler)
            hup_handler(signal.SIGHUP, None)
            term_handler(signal.SIGTERM, None)
            return 17

        process = ProcessStub(
            events,
            wait_actions=[wait_action],
            poll_results=[None, 0],
        )

        self.assertEqual(self.invoke(process, harness), 17)
        self.assertEqual(
            events,
            [
                ("getsignal", signal.SIGHUP),
                ("install", signal.SIGHUP),
                ("getsignal", signal.SIGTERM),
                ("install", signal.SIGTERM),
                ("wait", None),
                ("poll", None),
                ("send", signal.SIGHUP),
                ("poll", None),
                ("restore", signal.SIGHUP),
                ("restore", signal.SIGTERM),
            ],
        )

    def test_forwarded_signal_ignores_a_process_lookup_race(self) -> None:
        events: list[tuple[str, object]] = []
        harness = SignalHarness(events)

        def wait_action(timeout: int | None) -> int:
            harness.installed[signal.SIGHUP](signal.SIGHUP, None)
            return 4

        process = ProcessStub(
            events,
            wait_actions=[wait_action],
            poll_results=[None],
            send_failures=[ProcessLookupError("child exited")],
        )

        self.assertEqual(self.invoke(process, harness), 4)
        self.assertIn(("send", signal.SIGHUP), events)
        self.assertEqual(
            events[-2:],
            [
                ("restore", signal.SIGHUP),
                ("restore", signal.SIGTERM),
            ],
        )

    def test_forwarded_signal_propagates_other_failures_and_restores(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        harness = SignalHarness(events)

        def wait_action(timeout: int | None) -> int:
            harness.installed[signal.SIGHUP](signal.SIGHUP, None)
            return 4

        process = ProcessStub(
            events,
            wait_actions=[wait_action],
            poll_results=[None],
            send_failures=[RuntimeError("signal failed")],
        )

        with self.assertRaisesRegex(RuntimeError, "^signal failed$"):
            self.invoke(process, harness)

        self.assertEqual(
            events[-4:],
            [
                ("poll", None),
                ("send", signal.SIGHUP),
                ("restore", signal.SIGHUP),
                ("restore", signal.SIGTERM),
            ],
        )

    def test_keyboard_interrupt_forwards_sigint_and_waits_again(self) -> None:
        events: list[tuple[str, object]] = []
        harness = SignalHarness(events)
        process = ProcessStub(
            events,
            wait_actions=[KeyboardInterrupt(), 23],
            poll_results=[None],
        )

        self.assertEqual(self.invoke(process, harness), 23)
        self.assertEqual(
            events,
            [
                ("getsignal", signal.SIGHUP),
                ("install", signal.SIGHUP),
                ("getsignal", signal.SIGTERM),
                ("install", signal.SIGTERM),
                ("wait", None),
                ("poll", None),
                ("send", signal.SIGINT),
                ("wait", 10),
                ("restore", signal.SIGHUP),
                ("restore", signal.SIGTERM),
            ],
        )

    def test_keyboard_interrupt_tolerates_exit_races_and_dead_children(
        self,
    ) -> None:
        cases = (
            (
                "lookup-race",
                [None],
                [ProcessLookupError("child exited")],
                True,
            ),
            ("already-dead", [9], [], False),
        )
        for name, poll_results, send_failures, sent in cases:
            with self.subTest(case=name):
                events: list[tuple[str, object]] = []
                harness = SignalHarness(events)
                process = ProcessStub(
                    events,
                    wait_actions=[KeyboardInterrupt(), 9],
                    poll_results=poll_results,
                    send_failures=send_failures,
                )

                self.assertEqual(self.invoke(process, harness), 9)
                self.assertEqual(
                    ("send", signal.SIGINT) in events,
                    sent,
                )
                self.assertEqual(
                    events[-3:],
                    [
                        ("wait", 10),
                        ("restore", signal.SIGHUP),
                        ("restore", signal.SIGTERM),
                    ],
                )

    def test_keyboard_interrupt_timeout_terminates_then_waits_unbounded(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        harness = SignalHarness(events)
        timeout = subprocess.TimeoutExpired(["child"], 10)
        process = ProcessStub(
            events,
            wait_actions=[KeyboardInterrupt(), timeout, -15],
            poll_results=[None],
        )

        self.assertEqual(self.invoke(process, harness), -15)
        self.assertEqual(
            events,
            [
                ("getsignal", signal.SIGHUP),
                ("install", signal.SIGHUP),
                ("getsignal", signal.SIGTERM),
                ("install", signal.SIGTERM),
                ("wait", None),
                ("poll", None),
                ("send", signal.SIGINT),
                ("wait", 10),
                ("terminate", None),
                ("wait", None),
                ("restore", signal.SIGHUP),
                ("restore", signal.SIGTERM),
            ],
        )

    def test_keyboard_interrupt_second_wait_propagates_other_failures(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        harness = SignalHarness(events)
        process = ProcessStub(
            events,
            wait_actions=[
                KeyboardInterrupt(),
                RuntimeError("second wait failed"),
            ],
            poll_results=[None],
        )

        with self.assertRaisesRegex(RuntimeError, "^second wait failed$"):
            self.invoke(process, harness)

        self.assertNotIn(("terminate", None), events)
        self.assertEqual(
            events[-3:],
            [
                ("wait", 10),
                ("restore", signal.SIGHUP),
                ("restore", signal.SIGTERM),
            ],
        )

    def test_timeout_termination_and_final_wait_failures_propagate(
        self,
    ) -> None:
        cases = (
            (
                "terminate",
                [KeyboardInterrupt(), subprocess.TimeoutExpired(["child"], 10)],
                RuntimeError("terminate failed"),
                "terminate failed",
                False,
            ),
            (
                "final-wait",
                [
                    KeyboardInterrupt(),
                    subprocess.TimeoutExpired(["child"], 10),
                    RuntimeError("final wait failed"),
                ],
                None,
                "final wait failed",
                True,
            ),
        )
        for name, wait_actions, terminate_failure, message, final_wait in cases:
            with self.subTest(case=name):
                events: list[tuple[str, object]] = []
                harness = SignalHarness(events)
                process = ProcessStub(
                    events,
                    wait_actions=wait_actions,
                    poll_results=[None],
                    terminate_failure=terminate_failure,
                )

                with self.assertRaisesRegex(RuntimeError, f"^{message}$"):
                    self.invoke(process, harness)

                self.assertIn(("terminate", None), events)
                self.assertEqual(
                    events.count(("wait", None)),
                    2 if final_wait else 1,
                )
                self.assertEqual(
                    events[-2:],
                    [
                        ("restore", signal.SIGHUP),
                        ("restore", signal.SIGTERM),
                    ],
                )

    def test_arbitrary_wait_failure_restores_both_handlers(self) -> None:
        events: list[tuple[str, object]] = []
        harness = SignalHarness(events)
        process = ProcessStub(
            events,
            wait_actions=[RuntimeError("wait failed")],
        )

        with self.assertRaisesRegex(RuntimeError, "^wait failed$"):
            self.invoke(process, harness)

        self.assertEqual(
            events[-3:],
            [
                ("wait", None),
                ("restore", signal.SIGHUP),
                ("restore", signal.SIGTERM),
            ],
        )

    def test_partial_handler_installation_failure_is_not_rolled_back(
        self,
    ) -> None:
        cases = (
            (
                "first-install",
                {"fail_install": signal.SIGHUP},
                f"install failed for {signal.SIGHUP}",
                [
                    ("getsignal", signal.SIGHUP),
                    ("install", signal.SIGHUP),
                ],
            ),
            (
                "second-get",
                {"fail_get": signal.SIGTERM},
                f"getsignal failed for {signal.SIGTERM}",
                [
                    ("getsignal", signal.SIGHUP),
                    ("install", signal.SIGHUP),
                    ("getsignal", signal.SIGTERM),
                ],
            ),
            (
                "second-install",
                {"fail_install": signal.SIGTERM},
                f"install failed for {signal.SIGTERM}",
                [
                    ("getsignal", signal.SIGHUP),
                    ("install", signal.SIGHUP),
                    ("getsignal", signal.SIGTERM),
                    ("install", signal.SIGTERM),
                ],
            ),
        )
        for name, harness_arguments, message, expected_events in cases:
            with self.subTest(case=name):
                events: list[tuple[str, object]] = []
                harness = SignalHarness(events, **harness_arguments)
                process = ProcessStub(events, wait_actions=[0])

                with self.assertRaisesRegex(
                    SignalFailure,
                    f"^{message}$",
                ):
                    self.invoke(process, harness)

                self.assertEqual(events, expected_events)
                self.assertNotIn(("wait", None), events)
                self.assertNotIn(("restore", signal.SIGHUP), events)

    def test_restoration_failure_masks_wait_failure_and_stops_restoring(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        harness = SignalHarness(events, fail_restore=signal.SIGHUP)
        primary = RuntimeError("wait failed")
        process = ProcessStub(events, wait_actions=[primary])

        with self.assertRaisesRegex(
            SignalFailure,
            f"^restore failed for {signal.SIGHUP}$",
        ) as raised:
            self.invoke(process, harness)

        self.assertIs(raised.exception.__context__, primary)
        self.assertEqual(
            events[-2:],
            [
                ("wait", None),
                ("restore", signal.SIGHUP),
            ],
        )
        self.assertNotIn(("restore", signal.SIGTERM), events)

    def test_exit_status_normalization_is_exact(self) -> None:
        expected = {
            -255: 383,
            -15: 143,
            -1: 129,
            0: 0,
            1: 1,
            127: 127,
            255: 255,
        }
        for returncode, status in expected.items():
            with self.subTest(returncode=returncode):
                self.assertEqual(
                    self.process_policy.normalized_exit_status(returncode),
                    status,
                )

        self.assertIs(
            self.process_policy.normalized_exit_status(False),
            False,
        )
        self.assertIs(
            self.process_policy.normalized_exit_status(True),
            True,
        )

    def test_engine_exit_status_resolves_abs_after_negative_comparison(
        self,
    ) -> None:
        initial_absolute = mock.Mock(
            side_effect=AssertionError("resolved abs before comparison"),
        )
        rebound_absolute = mock.Mock(return_value=12)

        class RebindingReturnCode:
            def __lt__(code_self, other: object) -> bool:
                self.assertEqual(other, 0)
                self.engine.abs = rebound_absolute
                return True

        returncode = RebindingReturnCode()
        with mock.patch.object(
            self.engine,
            "abs",
            initial_absolute,
            create=True,
        ):
            observed = self.engine.normalized_exit_status(returncode)

        self.assertEqual(observed, 140)
        initial_absolute.assert_not_called()
        rebound_absolute.assert_called_once_with(returncode)

    def test_engine_exit_status_skips_abs_for_nonnegative_values(self) -> None:
        absolute = mock.Mock(
            side_effect=AssertionError("abs called for nonnegative status"),
        )
        with mock.patch.object(self.engine, "abs", absolute, create=True):
            for returncode in (False, True, 0, 1, 255):
                with self.subTest(returncode=returncode):
                    self.assertIs(
                        self.engine.normalized_exit_status(returncode),
                        returncode,
                    )

        absolute.assert_not_called()

    def test_command_kernel_and_wrapper_surfaces_are_exact(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(self.process_policy.command).parameters),
            (
                "argv",
                "cwd",
                "check",
                "text",
                "environment",
                "input_data",
                "base_environment",
                "sanitize_environment",
                "process_run",
                "inherited_descriptors",
                "filesystem_path",
                "error_type",
            ),
        )
        self.assertEqual(
            str(inspect.signature(self.engine.command)),
            "(argv: 'Sequence[str]', *, cwd: 'Path', check: 'bool' = "
            "True, text: 'bool' = True, environment: "
            "'dict[str, str] | None' = None, input_data: "
            "'str | bytes | None' = None) -> "
            "'subprocess.CompletedProcess'",
        )


if __name__ == "__main__":
    unittest.main()
