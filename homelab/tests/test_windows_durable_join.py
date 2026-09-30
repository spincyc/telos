"""The durable Windows join (TASK-28 step 8), with every guest faked.

No QEMU guest is launched and nothing reads ``build/``, ``homelab/var/`` or
``homelab/instance/``: the persistent Controller session, gate 6's rotation
driver and gate 6's join are fakes; the kept workstation, the canonical state
and the attempt live in a temporary directory; the roster overlay is pinned
to a synthetic one naming every directory role.  Every realm, SID, name and
password is synthetic.
"""

import ast
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from homelab.tests.identity_overlay_pin import (
    overlay_document, pinned_identity_overlay)
from homelab.tests.test_windows_durable_prepare import (
    DOMAIN, INSTANCE, PRIVATE_VALUES, REALM, binding, canonical_state,
    fake_control_iso, snapshot, write_kept_workstation)
from homelab.vm import controller_principals
from homelab.vm.directory_password_policy import DirectoryPasswordPolicy
from homelab.vm import windows_durable_join as join
from homelab.vm import windows_durable_prepare as prepare
from homelab.vm import windows_identity_adapter
from homelab.vm import workstation_instance as wi
from homelab.vm.bootstrap_dc import SOCKET_MAC
from homelab.vm.controller_join_material import ControllerJoinResult
from homelab.vm.secret_scan import count_secret_occurrences, secret_needles
from homelab.vm.simulated_topology import MACS
from homelab.vm.windows_identity_run import WindowsIdentityRunError


ROOT = Path(__file__).resolve().parents[2]
NAMES = {"standard_user": "person-b", "daily_administrator": "person-a",
         "domain_administrator": "person-a-root"}
CONSOLE = b"Console-Rescue-Typed-1!"
LOCAL = "Break-Glass-Local-2!"
DAILY = "Daily-Current-Pass-3!"
OLD_LOCAL = "Synthetic-Old-Local-4"
JOIN_CREDENTIAL = "Synthetic-Join-credential-47!"
SECRETS = (CONSOLE.decode(), LOCAL, DAILY, OLD_LOCAL, JOIN_CREDENTIAL)


def setUpModule():
    # Every directory role named, so the durable roster resolves; gate 6's
    # acceptance roster reads the same pinned overlay.
    unittest.enterModuleContext(
        pinned_identity_overlay(overlay_document(NAMES)))


def owner_secrets() -> join.OwnerSecrets:
    return join.OwnerSecrets(CONSOLE, LOCAL, DAILY)


class Prompter:
    """A terminal that answers each prompt from a script and records it."""

    def __init__(self, events=None, *, locals_=(LOCAL,), daily=DAILY,
                 console=CONSOLE):
        self.events = [] if events is None else events
        self.locals = list(locals_)
        self.daily = daily
        self.console = console
        self.prompts: list[tuple[str, str | None]] = []

    def __call__(self, text, *, confirm=None):
        self.prompts.append((text, confirm))
        if text.startswith("local-rescue console password"):
            self.events.append("prompt-console")
            return self.console
        if text.startswith("new Windows local-administrator"):
            self.events.append("prompt-local")
            value = self.locals.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value.encode()
        if text.startswith("current domain password"):
            self.events.append("prompt-daily")
            return self.daily.encode()
        raise AssertionError(f"unexpected prompt {text!r}")


# -- the owner's credentials ------------------------------------------------------
class CredentialPolicyTests(unittest.TestCase):
    def test_typeable_values_are_printable_us_ascii(self):
        self.assertIsNone(join.typeable_problem("Correct-Horse_9!{x}"))
        for value, reason in (
                ("Pässword-1!", "cannot type"), ("tab\there-1A", "cannot type"),
                (" Leading-1A", "space"), ("x" * 128, "long"), ("", "long")):
            with self.subTest(reason=reason):
                problem = join.typeable_problem(value)
                self.assertIn(reason, problem)
                self.assertNotIn(value or "\0", problem)

    def test_the_break_glass_policy_is_the_directorys_plus_typeability(self):
        self.assertIsNone(join.local_administrator_password_problem(LOCAL))
        for value, reason in (
                ("Ab1!", "shorter"), ("alllowercaseletters", "fewer"),
                ("Telosadmin-Pass-9", "account name"),
                ("Pässword-Strong-1", "cannot type")):
            with self.subTest(reason=reason):
                self.assertIn(
                    reason, join.local_administrator_password_problem(value))

    def test_a_recorded_relaxed_policy_takes_a_short_break_glass_value(self):
        """Owner decision 2026-09-30: short passwords on ``rehearsal``."""
        relaxed = DirectoryPasswordPolicy(
            min_length=4, complexity=False, min_age_days=0,
            source=f"{INSTANCE}'s recorded directory policy")
        problem = join.local_administrator_password_problem
        self.assertIsNone(problem("k9wv", relaxed))
        self.assertIsNone(problem("telosadmin", relaxed))
        self.assertEqual(
            problem("k9w", relaxed),
            f"is shorter than 4 characters under {INSTANCE}'s recorded "
            "directory policy")
        # Typeability is unchanged by any policy.
        self.assertIn("cannot type", problem("k9wä", relaxed))
        # Without a record, today's reason, word for word.
        self.assertEqual(problem("k9wv"), "is shorter than 7 characters")
        prompter = Prompter(locals_=("k9w", "k9wv"))
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            secrets = join.collect_owner_secrets(
                INSTANCE, "person-a", prompt=prompter, policy=relaxed)
        self.assertEqual(secrets.local_administrator, "k9wv")
        self.assertIn(f"under {INSTANCE}'s recorded directory policy",
                      error.getvalue())
        self.assertNotIn("k9w", error.getvalue())

    def test_prompts_are_asked_in_order_and_the_new_one_twice(self):
        prompter = Prompter()
        with contextlib.redirect_stderr(io.StringIO()):
            secrets = join.collect_owner_secrets(
                INSTANCE, "person-a", prompt=prompter)
        self.assertEqual(prompter.events,
                         ["prompt-console", "prompt-local", "prompt-daily"])
        (console, no_confirm), (local, confirm), (daily, _) = prompter.prompts
        self.assertIn(INSTANCE, console)
        self.assertIsNone(no_confirm)
        self.assertIn("telosadmin", local)
        self.assertIn("retype", confirm)
        self.assertIn("person-a", daily)
        self.assertEqual((secrets.console, secrets.local_administrator,
                          secrets.daily_administrator), (CONSOLE, LOCAL, DAILY))
        self.assertNotIn(LOCAL, repr(secrets))
        secrets.clear()
        self.assertEqual(secrets.values(), ())

    def test_a_refused_or_mistyped_new_password_is_asked_again(self):
        prompter = Prompter(locals_=(
            ValueError("the two credential entries did not match"),
            "too-weak", LOCAL))
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            secrets = join.collect_owner_secrets(
                INSTANCE, "person-a", prompt=prompter)
        self.assertEqual(secrets.local_administrator, LOCAL)
        self.assertEqual(prompter.events.count("prompt-local"), 3)
        self.assertNotIn("too-weak", error.getvalue())

    def test_three_refusals_stop_before_anything_else_is_asked(self):
        prompter = Prompter(locals_=("weak", "weak", "weak"))
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(
                    join.DurableWindowsJoinError, "nothing was started"):
                join.collect_owner_secrets(
                    INSTANCE, "person-a", prompt=prompter)
        self.assertNotIn("prompt-daily", prompter.events)

    def test_break_glass_custody_requires_distinct_values(self):
        for prompter in (Prompter(daily=LOCAL),
                         Prompter(console=LOCAL.encode())):
            with self.subTest(), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(
                        join.DurableWindowsJoinError, "must differ") as caught:
                    join.collect_owner_secrets(
                        INSTANCE, "person-a", prompt=prompter)
                self.assertNotIn(LOCAL, str(caught.exception))

    def test_an_untypeable_daily_password_is_refused(self):
        prompter = Prompter(daily="Dåily-Pass-1!")
        with self.assertRaisesRegex(
                join.DurableWindowsJoinError, "cannot type"):
            join.collect_owner_secrets(INSTANCE, "person-a", prompt=prompter)


# -- gate 6's credential owner ---------------------------------------------------
class FakeRecovery:
    def __init__(self):
        self.entered = 0
        self.destroyed = 0

    def __enter__(self):
        self.entered += 1
        return OLD_LOCAL

    def __exit__(self, *exc):
        return None

    def destroy_publication(self):
        self.destroyed += 1


class MaterialTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.tmp.chmod(0o700)
        self.publication = self.tmp / "publication.iso"
        self.publication.write_bytes(b"synthetic publication")
        self.publication.chmod(0o600)

    def material(self):
        material = join.DurablePrivateIdentityMaterial(
            self.publication, self.tmp, replacement=LOCAL)
        self.inner = FakeRecovery()
        material.recovery = join.CustodyRecovery(self.inner)
        return material

    def test_the_replacement_is_the_owners_and_is_handed_over_once(self):
        material = self.material()
        self.assertIs(material.generate_replacement_credential(), LOCAL)
        with self.assertRaises(WindowsIdentityRunError):
            material.generate_replacement_credential()

    def test_scoped_acceptance_stages_and_destroys_nothing(self):
        material = self.material()
        seen = []
        replacement = material.generate_replacement_credential()
        material.run_scoped_acceptance(
            replacement, lambda local, principals: seen.append(
                (local, dict(principals))))
        self.assertEqual(seen, [(LOCAL, {})])
        self.assertEqual(material._principals, {})
        # The staging callbacks gate 6 would call refuse, and were not called.
        with self.assertRaisesRegex(join.DurableWindowsJoinError, "stages no"):
            material.stage_guest_principals({"x": "y"})
        with self.assertRaisesRegex(join.DurableWindowsJoinError, "stages no"):
            material.destroy_guest_principals(("x",))

    def test_the_publication_is_kept_for_the_kept_workstation(self):
        material = self.material()
        with material.recovery as old:
            self.assertEqual(old, OLD_LOCAL)
            material.recovery.destroy_publication()
        self.assertTrue(material.recovery.release_requested)
        self.assertEqual(self.inner.destroyed, 0)
        self.assertEqual(self.publication.read_bytes(),
                         b"synthetic publication")
        with self.assertRaisesRegex(join.DurableWindowsJoinError, "outside"):
            material.recovery.destroy_publication()

    def test_gate_sixs_legacy_paths_are_refused(self):
        material = self.material()
        with self.assertRaises(join.DurableWindowsJoinError):
            material.rotate_local_credential()
        with self.assertRaises(join.DurableWindowsJoinError):
            material.destroy_private_publication()


# -- the boundary: persistent Controller, no fault operation ---------------------
class FakeConsole:
    def __init__(self):
        self.reader = io.BytesIO()
        self.writer = io.BytesIO()
        self.timeout = 42.0


class FakeSession:
    """A persistent Controller session that never boots anything."""

    instances: list = []

    def __init__(self, target, *, port, password, canonical_state,
                 events=None, transcript=b"login ok\n[REDACTED]\n",
                 stop_error=None):
        self.target = target
        self.port = port
        self.password = password
        self.canonical_state = canonical_state
        self.events = [] if events is None else events
        self.transcript = transcript
        self.stop_error = stop_error
        self.facts = {"launches": 0, "logins": 0, "live_argv_audited": False,
                      "clean_poweroffs": 0, "terminated_fallback": False,
                      "lock_released": True}
        self.events.append("controller-session")
        FakeSession.instances.append(self)

    def start(self, *, attached=None):
        self.events.append("controller-start")
        if attached is not None:
            attached()
        self.facts.update(launches=1, logins=1, live_argv_audited=True,
                          lock_released=False)
        return FakeConsole()

    def stop(self):
        self.events.append("controller-stop")
        self.facts.update(clean_poweroffs=1, lock_released=True)
        if self.stop_error is not None:
            raise self.stop_error

    def redacted_transcript(self, extra_secrets=()):
        self.events.append("controller-transcript")
        self.extra_secrets = list(extra_secrets)
        return self.transcript

    def close(self):
        self.events.append("controller-close")


class FakeJoinSerial:
    def __init__(self, reader, writer, *, timeout, events=None):
        self.events = events if events is not None else []
        self.timeout = timeout
        self.console = None

    def stage(self, credential):
        self.events.append("join-stage")
        return ControllerJoinResult("stage", "tj-0123456789abcdef", False, ())

    def destroy(self):
        self.events.append("join-destroy")
        return ControllerJoinResult("destroy", "tj-0123456789abcdef", True, ())


def fake_join_module(events):
    return SimpleNamespace(ControllerJoinSerial=lambda *a, **k: FakeJoinSerial(
        *a, events=events, **k))


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.attempt = self.tmp / "attempt"
        self.attempt.mkdir(mode=0o700)
        self.events: list[str] = []
        self.sessions: list[FakeSession] = []

    def factory(self, **session_options):
        def make(target, **options):
            session = FakeSession(target, events=self.events,
                                  **options, **session_options)
            self.sessions.append(session)
            return session
        return make

    def boundary(self, **session_options):
        return join.DurableWindowsBoundary(
            self.attempt, self.tmp / "canonical",
            target=mock.sentinel.target, console_password=CONSOLE,
            session_factory=self.factory(**session_options))

    def test_every_fault_operation_is_refused(self):
        boundary = self.boundary()
        boundary.processes["gateway"] = mock.Mock(pid=1)
        for call in (
                lambda: boundary.set_controller_available(False),
                lambda: boundary.set_gateway_available(False),
                lambda: boundary.set_update_source_available(False),
                lambda: boundary.set_optional_storage_available(False),
                lambda: boundary._set_process_available("gateway", False)):
            with self.subTest(), mock.patch.object(join.os, "kill") as kill:
                with self.assertRaises(join.DurableFaultRefused):
                    call()
                kill.assert_not_called()
        self.assertEqual(boundary.suspended_processes, set())

    def test_the_fabric_is_the_persistent_one(self):
        launched = []

        def popen(argv, **_options):
            launched.append(list(argv))
            return mock.Mock(pid=5000 + len(launched))

        boundary = self.boundary()
        with mock.patch.object(join, "_popen", popen), mock.patch.object(
                join, "wait_for_switch_port", return_value=3), \
                mock.patch.object(boundary, "_validate"):
            boundary.start_switch()
        switch, gateway = launched
        ports = [switch[index + 1] for index, part in enumerate(switch)
                 if part == "--port"]
        self.assertIn(f"controller={SOCKET_MAC.lower()}", ports)
        self.assertIn(f"workstation={MACS['client']}", ports)
        self.assertEqual(len(ports), 3)  # gateway, controller, workstation
        self.assertIn("--identity-mode", switch)
        self.assertEqual(
            gateway[gateway.index("--controller-mac") + 1], SOCKET_MAC)
        self.assertIn("--identity-mode", gateway)
        self.assertEqual(boundary.gateway_switch_generation, 3)
        self.assertNotIn("controller", boundary.processes)
        # No credential rides a child's argv.
        needles = secret_needles(SECRETS)
        for argv in launched:
            self.assertEqual(count_secret_occurrences(
                ["\0".join(argv).encode()], needles), 0)
        # Gate 6's fault-test dependency services are never started.
        boundary._start_dependency("update-source")
        self.assertEqual(set(boundary.processes), {"switch", "gateway"})

    def test_the_controller_is_a_session_never_a_child_process(self):
        boundary = self.boundary()
        boundary.port = 40123
        with mock.patch.object(join, "wait_for_switch_port") as attached:
            boundary.start_controller()
        session, = self.sessions
        self.assertIs(session.target, mock.sentinel.target)
        self.assertEqual((session.port, session.password), (40123, CONSOLE))
        attached.assert_called_once()
        self.assertEqual(attached.call_args.args[1:3],
                         ("controller", SOCKET_MAC))
        self.assertNotIn("controller", boundary.processes)
        with mock.patch.object(join, "_join_material",
                               return_value=fake_join_module(self.events)):
            boundary.stage_join_principal(JOIN_CREDENTIAL)
            boundary.destroy_join_principal()
        boundary.stop_controller()
        self.assertEqual(self.events, [
            "controller-session", "controller-start", "join-stage",
            "join-destroy", "controller-stop", "controller-transcript",
            "controller-close"])
        # The transcript is redacted of the join credential, while the
        # session still holds the console credential.
        self.assertEqual(session.extra_secrets, [JOIN_CREDENTIAL])
        self.assertIs(boundary.persistent_facts["clean_poweroff"], True)
        self.assertEqual(boundary._console_password, b"")
        with self.assertRaises(WindowsIdentityRunError):
            boundary.start_controller()

    def test_a_teardown_problem_is_recorded_not_raised_but_interrupts_pass(self):
        boundary = self.boundary(stop_error=RuntimeError("lock stuck"))
        boundary.port = 40123
        with mock.patch.object(join, "wait_for_switch_port"):
            boundary.start_controller()
        boundary.stop_controller()
        self.assertEqual(boundary.persistent_facts["stop_error"],
                         "RuntimeError")
        self.assertIn("controller-close", self.events)
        interrupted = self.boundary(stop_error=KeyboardInterrupt())
        interrupted.port = 40123
        with mock.patch.object(join, "wait_for_switch_port"):
            interrupted.start_controller()
        with self.assertRaises(KeyboardInterrupt):
            interrupted.stop_controller()
        self.assertEqual(self.events.count("controller-close"), 2)

    def test_the_join_principal_needs_the_live_console(self):
        with self.assertRaises(WindowsIdentityRunError):
            self.boundary().stage_join_principal(JOIN_CREDENTIAL)
        with self.assertRaises(WindowsIdentityRunError):
            self.boundary().destroy_join_principal()


# -- the adapter: the Controller-side diagnostic is disabled ----------------------
class AdapterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.windows = mock.Mock()
        self.windows.poll.return_value = None
        self.boundary = mock.Mock(
            processes={"windows": self.windows}, qmp=mock.Mock(),
            serial_socket=self.root / "com1.sock")

    def adapter(self, **options):
        return join.DurableWindowsAdapter(
            self.boundary, self.root, realm=DOMAIN,
            local_principal=join.LOCAL_ADMINISTRATOR,
            scan_secrets=join._no_secret_scan, timeout=7, **options)

    def test_the_controller_console_is_never_shared(self):
        adapter = self.adapter()
        with self.assertRaises(join.DurableControllerAuthDisabled) as caught:
            adapter._shared_controller_console()
        self.assertNotIsInstance(caught.exception, ValueError)
        self.assertFalse(self.boundary.controller_console.called)

    def test_staging_is_refused_and_the_join_principal_is_the_boundarys(self):
        adapter = self.adapter()
        with self.assertRaises(join.DurableWindowsJoinError):
            adapter.stage_principals({"person-b": "x"})
        with self.assertRaises(join.DurableWindowsJoinError):
            adapter.destroy_principals(("person-b",))
        self.boundary.stage_join_principal.return_value = "staged"
        self.boundary.destroy_join_principal.return_value = "destroyed"
        self.assertEqual(adapter.stage_join_principal("x"), "staged")
        self.assertEqual(adapter.destroy_join_principal(), "destroyed")
        with self.assertRaises(join.DurableWindowsJoinError):
            adapter.scan_secrets(("x",))

    def test_the_domain_sign_in_arms_the_guest_diagnostic_but_no_controller_one(
            self):
        daily = controller_principals.daily_administrator()
        principal = f"{daily}@{REALM}"
        sign_in = mock.Mock(
            state_kind="sign-in",
            state=f"focused password field for domain account {principal}")
        plan = mock.Mock(
            initial_sign_in_delay=0, lock_settle_delay=0,
            wake_after_lock_keys=(), post_join_operator_account_keys=(),
            post_join_operator_account_calibrated=True,
            post_join_operator_sign_in_manifest=None, checkpoint_timeout=11)
        session = mock.Mock()
        manager = mock.MagicMock()
        manager.__enter__.return_value = session
        factory = mock.Mock(return_value=manager)
        with (
            mock.patch.object(
                windows_identity_adapter, "_load_references",
                return_value=(sign_in, mock.sentinel.desktop,
                              mock.sentinel.security, mock.sentinel.change)),
            mock.patch.object(
                windows_identity_adapter, "_private_evidence_root",
                return_value=self.root / "reauth-evidence"),
            mock.patch.object(
                windows_identity_adapter, "_GuiInteraction") as interaction,
            mock.patch.object(
                windows_identity_adapter, "_prove_secret_entry_departure"),
            mock.patch.object(
                windows_identity_adapter, "_capture_secret_entry_baseline",
                return_value=None),
            mock.patch.object(
                windows_identity_adapter,
                "ControllerAuthDiagnosticSession") as controller_auth,
        ):
            adapter = self.adapter(
                rotation_plan=plan, post_submit_diagnostic=factory)
            adapter.reauthenticate_domain_operator(principal, DAILY, "a" * 32)
        controller_auth.assert_not_called()
        factory.assert_called_once()
        session.arm.assert_called_once()
        session.submitted.assert_called_once()
        interaction.return_value.type_secret.assert_called_once()
        self.assertEqual(adapter.controller_auth_result.host_error,
                         "DurableControllerAuthDisabled")


# -- the clean shutdown -----------------------------------------------------------
class FakeWindows:
    def __init__(self, exits_after=None, returncode=0):
        self.polls = 0
        self.exits_after = exits_after
        self.returncode = None
        self._code = returncode

    def poll(self):
        self.polls += 1
        if self.exits_after is not None and self.polls > self.exits_after:
            self.returncode = self._code
        return self.returncode


class ShutdownTests(unittest.TestCase):
    def shutdown(self, process, adapter, qmp=None):
        boundary = SimpleNamespace(processes={"windows": process}, qmp=qmp)
        ticks = iter(range(10_000))
        return join.shutdown_windows(
            adapter, boundary, timeout=5, acpi_timeout=5,
            clock=lambda: next(ticks), sleep=lambda _seconds: None)

    def test_stop_computer_through_the_run_dialog(self):
        adapter = mock.Mock()
        method = self.shutdown(FakeWindows(exits_after=3), adapter)
        self.assertEqual(method, "stop-computer")
        adapter.launch_guest.assert_called_once_with(join.SHUTDOWN_COMMAND)
        self.assertIn("Stop-Computer -Force", join.SHUTDOWN_COMMAND)

    def test_the_acpi_power_button_is_the_fallback(self):
        adapter = mock.Mock()
        adapter.launch_guest.side_effect = RuntimeError("no desktop")
        qmp = mock.Mock()
        method = self.shutdown(FakeWindows(exits_after=3), adapter, qmp)
        self.assertEqual(method, "acpi-power-button")
        qmp.execute.assert_called_once_with("system_powerdown", timeout=10)

    def test_a_guest_that_does_not_stop_or_crashes_is_refused(self):
        for process, qmp in ((FakeWindows(), mock.Mock()),
                             (FakeWindows(exits_after=1, returncode=1), None)):
            with self.subTest(), self.assertRaises(
                    join.DurableWindowsJoinError):
                self.shutdown(process, mock.Mock(), qmp)
        with self.assertRaisesRegex(join.DurableWindowsJoinError, "not running"):
            self.shutdown(FakeWindows(exits_after=0), mock.Mock())


# -- one join into one real prepared attempt, the guests faked -------------------
def write_publication(path: Path, password: str) -> None:
    """A real ISO carrying one unattend credential, as gate 5 publishes it."""
    with tempfile.TemporaryDirectory() as name:
        payload = Path(name) / "payload" / "windows"
        payload.mkdir(parents=True)
        (payload / "Autounattend.xml").write_text(
            '<unattend xmlns="urn:schemas-microsoft-com:unattend"><settings>'
            "<component><UserAccounts><LocalAccounts><LocalAccount>"
            f"<Password><Value>{password}</Value></Password>"
            "</LocalAccount></LocalAccounts></UserAccounts></component>"
            "</settings></unattend>")
        subprocess.run(
            ["xorriso", "-as", "mkisofs", "-quiet", "-o", str(path),
             str(Path(name) / "payload")], check=True, capture_output=True)
    path.chmod(0o600)


class FakeRotationSession:
    """Gate 6's rotation session with only the persistent Controller started."""

    def __init__(self, boundary, events):
        self.boundary = boundary
        self.events = events

    def __enter__(self):
        self.boundary.port = 40123
        self.boundary.start_controller()
        return mock.sentinel.qmp

    def __exit__(self, *_exc):
        self.events.append("session-exit")
        self.boundary.stop_controller()


@unittest.skipUnless(shutil.which("qemu-img") and shutil.which("xorriso"),
                     "qemu-img and xorriso are required")
class ExecuteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.state = write_kept_workstation(self.tmp / "workstations")
        write_publication(self.state / wi.PUBLICATION_NAME, OLD_LOCAL)
        self.workstation = wi.WorkstationInstance(self.state, name="w1")
        self.canonical = canonical_state(self.tmp)
        self.marker = self.workstation.read_marker()
        self.attempt = prepare.prepare(
            self.workstation, self.marker, binding(),
            controller_state=self.canonical, run_root=self.tmp / "runs",
            control_iso_builder=fake_control_iso)
        self.events: list[str] = []
        self.join_calls: list[dict] = []
        self.join_error: BaseException | None = None
        self.transcript = b"login ok\n[REDACTED]\n"

    def rotation(self, *, plan, session, recovery, generate_credential,
                 after_rotation):
        with recovery as old, session:
            self.events.append("rotate")
            self.assertEqual(old, OLD_LOCAL)
            replacement = generate_credential()
            self.assertEqual(replacement, LOCAL)
            after_rotation(replacement)
            recovery.destroy_publication()
        return SimpleNamespace(
            phases=("old-credential-sign-in-proved",
                    "replacement-credential-sign-in-proved",
                    "post-rotation-acceptance-complete",
                    "private-publication-destroyed"),
            publication_destroyed=True, replacement_sign_in_proved=True)

    def execute_join(self, **kwargs):
        self.join_calls.append(kwargs)
        self.events.append("join")
        kwargs["stage_join_principal"](JOIN_CREDENTIAL)
        if self.join_error is not None:
            kwargs["destroy_join_principal"]()
            raise self.join_error
        kwargs["destroy_join_principal"]()
        return ({"schema_version": 1, "join_media_destroyed": True,
                 "joined_after_reboot": True, "domain": DOMAIN,
                 "operator": f"person-a@{REALM}",
                 "operator_local_administrator": True}, True)

    def shutdown(self, adapter, boundary):
        self.events.append("windows-shutdown")
        return "stop-computer"

    def execute(self):
        def factory(target, **options):
            return FakeSession(target, events=self.events,
                               transcript=self.transcript, **options)

        before = os.environ.copy()
        with mock.patch.multiple(
                join, execute_progressive_rotation=self.rotation,
                _execute_join=self.execute_join,
                shutdown_windows=self.shutdown,
                NativeBoundaryRotationSession=lambda boundary:
                    FakeRotationSession(boundary, self.events),
                wait_for_switch_port=mock.Mock(),
                _join_material=lambda: fake_join_module(self.events)):
            try:
                return join.DurableWindowsJoin(
                    self.workstation, binding(),
                    target=mock.sentinel.target,
                    controller_state=self.canonical,
                    secrets=owner_secrets(),
                    session_factory=factory).execute(
                        self.attempt, self.marker)
            finally:
                self.assertEqual(os.environ.copy(), before)

    def result(self) -> tuple[dict, str]:
        text = (self.attempt / "evidence" / "result.json").read_text()
        return json.loads(text), text

    def assert_no_secret_retained(self):
        needles = secret_needles(SECRETS)
        for path in sorted(self.attempt.rglob("*")):
            if path.is_file() and path.name not in ("windows.qcow2",):
                with self.subTest(path=path.name):
                    self.assertEqual(count_secret_occurrences(
                        [path.read_bytes()], needles), 0)

    def test_rotate_join_shut_down_in_order_publication_kept(self):
        publication = (self.state / wi.PUBLICATION_NAME).read_bytes()
        outcome = self.execute()
        self.assertEqual(self.events, [
            "controller-session", "controller-start", "rotate", "join",
            "join-stage", "join-destroy", "windows-shutdown", "session-exit",
            "controller-stop", "controller-transcript", "controller-close"])
        call, = self.join_calls
        self.assertEqual(call["realm"], DOMAIN)
        self.assertEqual(call["operator_credential"], DAILY)
        self.assertEqual(call["callbacks"].local_principal, "telosadmin")
        # Gate 6 would have destroyed it here; the kept workstation keeps it.
        self.assertEqual(
            (self.state / wi.PUBLICATION_NAME).read_bytes(), publication)
        recorded, text = self.result()
        self.assertEqual(outcome["status"], "observed")
        self.assertEqual(recorded["status"], "observed")
        for key in ("local_administrator_rotated", "joined_after_reboot",
                    "secure_channel_proved", "operator_local_administrator",
                    "join_principal_destroyed", "windows_clean_shutdown",
                    "evidence_secret_free"):
            self.assertIs(recorded[key], True, key)
        self.assertEqual(recorded["controller_auth_diagnostic"], "disabled")
        self.assertEqual(recorded["fault_operations"], "none")
        self.assertIs(recorded["controller"]["clean_poweroff"], True)
        self.assertTrue(all(recorded["teardown"].values()))
        self.assertEqual(recorded["bound_instance"], INSTANCE)
        for value in PRIVATE_VALUES + tuple(NAMES.values()):
            self.assertNotIn(value, text)
        self.assertTrue((self.attempt / "attempt-consumed.json").is_file())
        self.assertTrue((self.attempt / "terminal-teardown.json").is_file())
        self.assert_no_secret_retained()

    def test_a_failed_join_leaves_the_publication_and_records_the_failure(self):
        publication = (self.state / wi.PUBLICATION_NAME).read_bytes()
        self.join_error = WindowsIdentityRunError(
            f"synthetic join fault {DAILY}")
        with self.assertRaises(Exception):
            self.execute()
        recorded, text = self.result()
        self.assertEqual(recorded["status"], "fail")
        self.assertIs(recorded["local_administrator_rotated"], True)
        self.assertIs(recorded["joined_after_reboot"], False)
        self.assertIn("controller-stop", self.events)
        self.assertNotIn("windows-shutdown", self.events)
        self.assertEqual(
            (self.state / wi.PUBLICATION_NAME).read_bytes(), publication)
        self.assertNotIn(DAILY, text)
        self.assert_no_secret_retained()

    def test_an_undestroyed_join_principal_is_named_for_cleanup(self):
        def stage_only(**kwargs):
            self.events.append("join")
            kwargs["stage_join_principal"](JOIN_CREDENTIAL)
            raise WindowsIdentityRunError("synthetic lost destruction")

        self.execute_join = stage_only
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(Exception):
            self.execute()
        recorded, _ = self.result()
        self.assertEqual(recorded["controller"]["join_principal_may_remain"],
                         "tj-0123456789abcdef")
        self.assertIs(recorded["controller"]["join_principal_destroyed"], False)
        self.assertIn("tj-0123456789abcdef", error.getvalue())
        self.assert_no_secret_retained()

    def test_a_credential_in_the_evidence_refuses_the_fold(self):
        self.transcript = f"leaked {JOIN_CREDENTIAL}\n".encode()
        with self.assertRaisesRegex(
                join.DurableWindowsJoinError, "retained evidence"):
            self.execute()
        recorded, _ = self.result()
        self.assertIs(recorded["evidence_secret_free"], False)
        self.assertEqual(recorded["status"], "fail")

    def test_an_attempt_for_another_head_is_refused_before_anything_starts(self):
        marker = json.loads(json.dumps(self.marker))
        marker["ledger"][-1]["disk_sha256"] = "00" * 32
        self.marker = marker
        with self.assertRaisesRegex(join.DurableWindowsJoinError, "ledger"):
            self.execute()
        self.assertEqual(self.events, [])

    def test_the_rotation_plan_is_gate_sixs_production_plan(self):
        # Gate 6's own factory, over this very attempt, builds the plan the
        # durable runner must match field for field -- but for the
        # realm-relabelled operator sign-in reference.
        import dataclasses
        from homelab.vm import windows_identity_factory as factory
        from homelab.vm.windows_identity_run import NativeProcessBoundary

        bundle = self.tmp / "bundle"
        bundle.mkdir(mode=0o700)
        (bundle / "publication.iso").write_bytes(b"x")
        (bundle / "publication.iso").chmod(0o600)
        boundary = NativeProcessBoundary(self.attempt, self.canonical)
        boundary._validate()
        try:
            with mock.patch.object(factory, "_source_bundle",
                                   return_value=bundle), \
                    mock.patch.object(factory, "_retained_inventory"):
                gate6 = factory.default_acceptance_factory(boundary)
        finally:
            boundary.release_prestart_ownership()
        authorization = json.loads(
            (self.attempt / "authorization.json").read_text())
        durable, command = join.rotation_plan(self.attempt, authorization)
        self.assertEqual(
            dataclasses.replace(
                durable, post_join_operator_sign_in_manifest=(
                    gate6.rotation_plan.post_join_operator_sign_in_manifest)),
            gate6.rotation_plan)
        self.assertEqual(durable.post_join_operator_sign_in_manifest.parent,
                         self.attempt / prepare.DURABLE_REFERENCES)
        self.assertEqual(command.desktop.state_kind, "desktop")


# -- the runner: the kept workstation, its lock, the fold, the publication --------
class FakeJoin:
    """``DurableWindowsJoin`` that records when it would have started guests."""

    def __init__(self, test):
        self.test = test

    def __call__(self, workstation, bound, *, target, controller_state,
                 secrets):
        test = self.test
        test.constructed.append({"secrets": secrets, "target": target})

        class Execute:
            def execute(self, attempt, marker):
                observer = wi.WorkstationInstance(
                    workstation.state, name=workstation.state.name)
                test.events.append("execute")
                test.locked.append(observer.locked())
                test.accounts.append(
                    list(workstation.read_marker()["machine_accounts"]))
                evidence = attempt / "evidence"
                evidence.mkdir(mode=0o700)
                (evidence / "result.json").write_text(json.dumps(
                    {"status": "fail" if test.execute_error else "observed"}))
                if test.execute_error is not None:
                    raise test.execute_error
                return {"status": "observed"}

        return Execute()


class RunFixture:
    STAGES = ("adopt", "arch-install", "arch-join")
    REAL_DISK = False

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.root = self.tmp / "workstations"
        self.run_root = self.tmp / "runs"
        self.state = write_kept_workstation(
            self.root, stages=self.STAGES, real_disk=self.REAL_DISK)
        self.events: list[str] = []
        self.locked: list = []
        self.accounts: list = []
        self.constructed: list = []
        self.execute_error: BaseException | None = None
        self.prompter = Prompter(self.events)
        for name, value in (
                ("durable_binding", lambda *a, **k: binding()),
                ("preview_command", lambda *a: [
                    "qemu-system-x86_64", "-name",
                    f"persistent-dc-{INSTANCE}"]),
                ("preflight_problems", lambda *a: []),
                ("prepare_attempt", self.prepare),
                ("DurableWindowsJoin", FakeJoin(self)),
                ("WINDOWS_GROWTH_BYTES", 0)):
            patcher = mock.patch.object(join, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        if not self.REAL_DISK:
            patcher = mock.patch.object(
                join, "inspect_workstation",
                lambda *a, **k: self.events.append("inspect"))
            patcher.start()
            self.addCleanup(patcher.stop)

    def prepare(self, workstation, marker, bound, **options):
        self.events.append("prepare")
        attempt = self.run_root / "w1" / "attempt-synthetic"
        attempt.mkdir(parents=True, mode=0o700)
        overlay = attempt / "windows.qcow2"
        if self.REAL_DISK:
            subprocess.run(
                ["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2",
                 "-b", str(workstation.disk.resolve()), str(overlay)],
                check=True, capture_output=True)
        else:
            overlay.write_bytes(b"synthetic overlay")
        overlay.chmod(0o600)
        (attempt / "OVMF_VARS.fd").write_bytes(b"post-join vars\n")
        return attempt

    def args(self, *extra):
        return join.parser().parse_args([
            "--workstation", "w1", "--root", str(self.root),
            "--persistent-dc", INSTANCE,
            "--persistent-root", str(self.tmp / "persistent"),
            "--controller-state", str(self.tmp / "canonical"),
            "--run-root", str(self.run_root), *extra])

    def run_quietly(self, *extra) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(io.StringIO()):
            status = join.run(self.args(*extra), prompt=self.prompter)
        self.status = status
        return output.getvalue()

    def marker(self) -> dict:
        return json.loads((self.state / wi.MARKER_NAME).read_text())


class RunTests(RunFixture, unittest.TestCase):
    def test_the_dry_run_prints_the_plan_and_names_only_the_instance(self):
        before = snapshot(self.state)
        plan = self.run_quietly()
        self.assertEqual(snapshot(self.state), before)
        self.assertEqual(self.prompter.prompts, [])
        self.assertEqual(self.events, [])
        self.assertFalse(self.run_root.exists())
        for needle in ("dry run", INSTANCE, "w1", "windows-join",
                       "adopt, arch-install, arch-join", "Prompts",
                       "twice", "TELOS-WIN-01", "tj-",
                       "only then is the custody publication shredded"):
            self.assertIn(needle, plan)
        for value in PRIVATE_VALUES + tuple(NAMES.values()):
            self.assertNotIn(value, plan)

    def test_the_bound_instances_recorded_policy_judges_the_new_password(self):
        relaxed = DirectoryPasswordPolicy(
            min_length=4, complexity=False, min_age_days=0,
            source=f"{INSTANCE}'s recorded directory policy")
        self.prompter.locals = ["k9wv"]
        with mock.patch.object(join, "durable_binding",
                               lambda *a, **k: binding(
                                   password_policy=relaxed)), \
                mock.patch.object(wi.WorkstationInstance, "fold",
                                  autospec=True, return_value={
                                      "stage": "windows-join",
                                      "disk_sha256": "cd" * 32}), \
                mock.patch.object(wi.WorkstationInstance,
                                  "retire_publication", autospec=True):
            plan = self.run_quietly()
            self.assertIn(f"meet {INSTANCE}'s recorded directory policy "
                          "(at least 4 characters; complexity off)", plan)
            self.run_quietly("--apply")
        self.assertEqual(self.status, 0)
        self.assertEqual(self.events.count("prompt-local"), 1)

    def test_apply_prompts_first_then_records_executes_folds_and_retires(self):
        entry = {"stage": "windows-join", "utc": "2026-09-30T02:00:00+00:00",
                 "disk_sha256": "cd" * 32, "vars_sha256": "ef" * 32,
                 "source": "synthetic"}

        def fold(workstation, overlay, stage, **options):
            self.events.append("fold")
            self.fold_call = (overlay, stage, options)
            return entry

        def retire(workstation):
            self.events.append("retire")

        with mock.patch.object(wi.WorkstationInstance, "fold", autospec=True,
                               side_effect=fold), \
                mock.patch.object(wi.WorkstationInstance, "retire_publication",
                                  autospec=True, side_effect=retire):
            output = self.run_quietly("--apply")
        self.assertEqual(self.status, 0)
        self.assertEqual(self.events, [
            "inspect", "prompt-console", "prompt-local", "prompt-daily",
            "prepare", "execute", "fold", "retire"])
        attempt = self.run_root / "w1" / "attempt-synthetic"
        overlay, stage, options = self.fold_call
        self.assertEqual((overlay, stage), (attempt / "windows.qcow2",
                                            "windows-join"))
        self.assertEqual(options["firmware_vars"], attempt / "OVMF_VARS.fd")
        # The lock is held throughout; the machine account was recorded
        # before the join could create it.
        self.assertEqual(self.locked, [True])
        self.assertEqual(self.accounts, [["TELOS-WIN-01"]])
        self.assertFalse(wi.WorkstationInstance(
            self.state, name="w1").locked())
        self.assertFalse((attempt / "windows.qcow2").exists())
        recorded = json.loads((attempt / "evidence" / "result.json").read_text())
        self.assertIs(recorded["folded"], True)
        self.assertIs(recorded["publication_retired"], True)
        self.assertIn("custody publication is retired", output)
        # The typed values reached the join and were dropped afterwards.
        secrets = self.constructed[0]["secrets"]
        self.assertEqual(secrets.values(), ())

    def test_a_failure_before_the_fold_keeps_the_publication_and_ledger(self):
        self.execute_error = RuntimeError("synthetic join fault")
        publication = (self.state / wi.PUBLICATION_NAME).read_bytes()
        with mock.patch.object(wi.WorkstationInstance, "fold") as fold, \
                mock.patch.object(
                    wi.WorkstationInstance, "retire_publication") as retire:
            with self.assertRaisesRegex(RuntimeError, "synthetic join fault"):
                self.run_quietly("--apply")
        fold.assert_not_called()
        retire.assert_not_called()
        self.assertEqual(
            (self.state / wi.PUBLICATION_NAME).read_bytes(), publication)
        marker = self.marker()
        self.assertEqual([e["stage"] for e in marker["ledger"]],
                         list(self.STAGES))
        self.assertEqual(marker["machine_accounts"], ["TELOS-WIN-01"])
        attempt = self.run_root / "w1" / "attempt-synthetic"
        self.assertFalse((attempt / "windows.qcow2").exists())
        recorded = json.loads((attempt / "evidence" / "result.json").read_text())
        self.assertIs(recorded["folded"], False)
        self.assertFalse(wi.WorkstationInstance(self.state, name="w1").locked())
        self.assertEqual(self.constructed[0]["secrets"].values(), ())

    def test_a_retirement_failure_after_the_fold_is_reported(self):
        with mock.patch.object(wi.WorkstationInstance, "fold",
                               return_value={"disk_sha256": "cd" * 32}), \
                mock.patch.object(
                    wi.WorkstationInstance, "retire_publication",
                    side_effect=wi.WorkstationInUse("publication open")):
            self.run_quietly("--apply")
        self.assertEqual(self.status, 2)
        attempt = self.run_root / "w1" / "attempt-synthetic"
        recorded = json.loads((attempt / "evidence" / "result.json").read_text())
        self.assertIs(recorded["folded"], True)
        self.assertIs(recorded["publication_retired"], False)

    def test_refusals_come_before_any_prompt(self):
        with mock.patch.object(join, "preflight_problems",
                               lambda *a: ["OVMF firmware was not found"]):
            with self.assertRaisesRegex(join.DurableWindowsJoinError, "OVMF"):
                self.run_quietly("--apply")
        self.assertEqual(self.prompter.prompts, [])
        self.assertFalse(self.run_root.exists())

    def test_a_workstation_bound_elsewhere_is_refused(self):
        with mock.patch.object(join, "durable_binding",
                               lambda *a, **k: binding(instance="other-dc")):
            with self.assertRaisesRegex(RuntimeError, "bound to"):
                self.run_quietly()

    def test_a_realm_gate_six_cannot_derive_is_refused_quietly(self):
        with mock.patch.object(join, "durable_binding", lambda *a, **k: binding(
                kerberos_realm="OTHER.EXAMPLE.TEST")):
            with self.assertRaises(RuntimeError) as caught:
                self.run_quietly()
        for value in PRIVATE_VALUES + ("OTHER.EXAMPLE.TEST",):
            self.assertNotIn(value, str(caught.exception))

    def test_rosters_that_disagree_are_refused(self):
        with mock.patch.object(controller_principals, "daily_administrator",
                               return_value="someone-else"):
            with self.assertRaisesRegex(
                    join.DurableWindowsJoinError, "daily_administrator") as c:
                self.run_quietly()
        self.assertNotIn("someone-else", str(c.exception))
        self.assertNotIn("person-a", str(c.exception))


class NotNextTests(RunFixture, unittest.TestCase):
    STAGES = ("adopt", "arch-install")

    def test_only_the_next_stage_runs(self):
        with self.assertRaisesRegex(join.DurableWindowsJoinError, "arch-join"):
            self.run_quietly()
        self.assertEqual(self.prompter.prompts, [])


class RetireOnlyTests(RunFixture, unittest.TestCase):
    STAGES = ("adopt", "arch-install", "arch-join", "windows-join")

    def test_a_folded_join_whose_publication_remains_only_retires_it(self):
        plan = self.run_quietly()
        self.assertIn("still held", plan)
        self.assertTrue((self.state / wi.PUBLICATION_NAME).exists())
        self.run_quietly("--apply")
        self.assertEqual(self.status, 0)
        self.assertFalse((self.state / wi.PUBLICATION_NAME).exists())
        self.assertIn("retired_utc", self.marker()["publication"])
        self.assertEqual(self.prompter.prompts, [])
        self.assertEqual(self.constructed, [])
        with self.assertRaisesRegex(join.DurableWindowsJoinError, "nothing"):
            self.run_quietly()


@unittest.skipUnless(shutil.which("qemu-img"), "qemu-img is required")
class RealFoldTests(RunFixture, unittest.TestCase):
    """One apply against a real qcow2, the real ``fold`` and ``retire``."""

    REAL_DISK = True

    def test_the_publication_is_shredded_only_after_the_fold(self):
        real_fold = wi.WorkstationInstance.fold
        real_retire = wi.WorkstationInstance.retire_publication
        seen = {}

        def fold(workstation, *args, **options):
            self.events.append("fold")
            return real_fold(workstation, *args, **options)

        def retire(workstation):
            seen["ledger"] = [entry["stage"] for entry in
                              workstation.read_marker()["ledger"]]
            seen["publication"] = workstation.publication.exists()
            self.events.append("retire")
            return real_retire(workstation)

        with mock.patch.object(wi.WorkstationInstance, "fold", autospec=True,
                               side_effect=fold), \
                mock.patch.object(wi.WorkstationInstance, "retire_publication",
                                  autospec=True, side_effect=retire):
            self.run_quietly("--apply")
        self.assertEqual(self.status, 0)
        self.assertEqual(self.events[-3:], ["execute", "fold", "retire"])
        self.assertEqual(seen["ledger"][-1], "windows-join")
        self.assertIs(seen["publication"], True)
        marker = self.marker()
        self.assertEqual([entry["stage"] for entry in marker["ledger"]],
                         ["adopt", "arch-install", "arch-join", "windows-join"])
        self.assertEqual((self.state / wi.VARS_NAME).read_bytes(),
                         b"post-join vars\n")
        self.assertFalse((self.state / wi.PUBLICATION_NAME).exists())
        self.assertIn("retired_utc", marker["publication"])
        self.assertEqual(marker["machine_accounts"], ["TELOS-WIN-01"])


# -- the composition: gate 6 unmodified, nothing unsafe reachable -----------------
class CompositionTests(unittest.TestCase):
    GATE6 = (
        "windows_identity_run", "windows_identity_orchestrator",
        "windows_identity_adapter", "windows_identity_progressive",
        "windows_identity_prepare", "windows_identity_factory",
        "windows_identity_faults", "windows_identity_gui",
        "windows_identity_recovery", "controller_principals",
        "persistent_controller_session")

    def test_importing_the_durable_join_changes_no_gate_six_module(self):
        # A fresh interpreter: snapshot every gate-6 module's globals and its
        # classes' dicts, import the durable modules, compare identities.
        program = (
            "import importlib, json, inspect\n"
            f"names = {list(self.GATE6)!r}\n"
            "def snap():\n"
            "    out = {}\n"
            "    for name in names:\n"
            "        module = importlib.import_module('homelab.vm.' + name)\n"
            "        for key, value in vars(module).items():\n"
            "            out[name + '.' + key] = id(value)\n"
            "            if inspect.isclass(value) and value.__module__ == "
            "module.__name__:\n"
            "                for attr, member in vars(value).items():\n"
            "                    out[name + '.' + key + '.' + attr] = id(member)\n"
            "    return out\n"
            "before = snap()\n"
            "import homelab.vm.windows_durable_join\n"
            "import homelab.vm.windows_durable_prepare\n"
            "after = snap()\n"
            "changed = sorted(k for k in before if after.get(k) != before[k])\n"
            "print(json.dumps(changed))\n")
        completed = subprocess.run(
            [sys.executable, "-c", program], cwd=ROOT, check=True,
            capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(ROOT)})
        self.assertEqual(json.loads(completed.stdout), [])

    def test_no_fault_phase_staging_or_acceptance_entry_is_referenced(self):
        tree = ast.parse(Path(join.__file__).read_text(encoding="utf-8"))
        referenced = {
            node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
        } | {
            node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
        } | {
            alias.name for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) for alias in node.names
        }
        for forbidden in (
                "run_fault_phases", "FaultPhaseOperations",
                "execute_windows_identity_acceptance", "_run_acceptance_checks",
                "execute_production_identity_acceptance",
                "ControllerPrincipalSerial", "ControllerAuthDiagnosticSession",
                "DisposableBootDisk", "pause", "SIGSTOP", "send_signal"):
            self.assertNotIn(forbidden, referenced, forbidden)

    def test_gate_fives_guest_identity_is_what_the_join_assumes(self):
        gate5 = (ROOT / "homelab/vm/windows_install_prepare.py").read_text()
        self.assertIn(f'computer_name="{join.WINDOWS_COMPUTER_NAME}"', gate5)
        self.assertIn(f'local_user="{join.LOCAL_ADMINISTRATOR}"', gate5)
        factory = (ROOT / "homelab/vm/windows_identity_factory.py").read_text()
        self.assertIn(f'local_principal="{join.LOCAL_ADMINISTRATOR}"', factory)
        self.assertTrue(wi.valid_machine_account(join.WINDOWS_COMPUTER_NAME))

    def test_the_names_are_required(self):
        for missing in ("--workstation", "--persistent-dc"):
            argv = ["--workstation", "w1", "--persistent-dc", INSTANCE]
            index = argv.index(missing)
            del argv[index:index + 2]
            with self.subTest(missing=missing), contextlib.redirect_stderr(
                    io.StringIO()), self.assertRaises(SystemExit):
                join.parser().parse_args(argv)


class PendingFoldTests(unittest.TestCase):
    def test_an_interrupted_fold_is_refused_naming_reconcile(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = write_kept_workstation(Path(temporary) / "workstations")
            workstation = wi.WorkstationInstance(state, name="w1")
            marker = workstation.read_marker()
            marker["pending_fold"] = {"stage": "arch-join"}
            with self.assertRaisesRegex(
                    join.DurableWindowsJoinError, "reconcile"):
                join.join_mode(workstation, marker)


if __name__ == "__main__":
    unittest.main()
