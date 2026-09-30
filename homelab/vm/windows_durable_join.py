#!/usr/bin/env python3
"""Join a kept workstation's Windows to its persistent domain, then fold it.

TASK-28, step 8 of ``homelab/DURABLE-WORKSTATION-FLOW.md``: stage
``windows-join`` of a kept workstation ``W`` (``workstation_instance``), after
``arch-join``.  Gate 6 (``windows_identity_*``) is composed, never edited, so
the disposable gate stays byte-identical:

* ``windows_durable_prepare`` builds gate 6's attempt over an overlay of
  ``W/workstation.qcow2`` (Windows boots by systemd-boot's five-second Windows
  default), with the control probe and the post-join operator sign-in
  reference rendered for the bound realm;
* ``DurableWindowsBoundary`` is gate 6's ``NativeProcessBoundary`` with the
  Controller replaced by a ``PersistentControllerSession`` of the bound
  instance on the per-run switch.  The Controller is never one of the
  boundary's child processes, and every fault setter raises, so no pause,
  SIGSTOP or outage can reach the durable directory;
* ``DurablePrivateIdentityMaterial`` is gate 6's credential owner with no
  principal staging (the durable accounts already exist) and with the
  replacement local-administrator credential the one the OWNER typed, not a
  generated one.  Gate 6's Ctrl+Alt+Del rotation
  (``execute_progressive_rotation``) consumes it, and gate 6's publication
  destruction is deferred to ``W``: the publication is shredded only after
  the fold, so a failed attempt needs a retry, never a reinstall;
* ``DurableWindowsAdapter`` is gate 6's adapter with the Controller-side
  authentication diagnostic disabled (it never reaches the durable console)
  and the one-use ``tj-`` join principal staged and destroyed with proof over
  the persistent session's console, exactly as the persistent probe does;
* gate 6's ``_execute_join`` runs unchanged: join, reboot, the daily
  administrator's domain sign-in with the CURRENT password the owner typed
  (it was changed at first logon in stage ``arch-join``), and the post-reboot
  probe that proves membership, the secure channel and the operator's local
  administrator right.  Windows is then shut down cleanly from inside.

The lifecycle, all under ``W``'s lock: prompts (Controller console password,
new local-administrator password twice, daily administrator's current
password) before any guest or fabric process; ``record_machine_account``;
rotate; join; reboot; sign-in and probe; clean shutdown; fold overlay and
firmware variables as ``windows-join``; only then ``retire_publication``.
The dry run (the default) prints the plan and names the bound instance only,
never the realm, the domain SID or a principal.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Callable, Mapping

if not __package__:  # Direct execution by the Make recipe (PEP 366).
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "homelab.vm"

from . import controller_principals  # noqa: E402
from .arch_durable_install_run import (  # noqa: E402
    _existing_ancestor, _gib, require_workstation_binding)
from .bootstrap_dc import (  # noqa: E402
    CONSOLE_ACCOUNT, DEFAULT_PERSISTENT_ROOT, DEFAULT_STATE, SOCKET_MAC,
    _persistent_running, _typed_secret, ovmf_pair, persistent_switch_command)
from .controller_image import (  # noqa: E402
    ControllerImageError, assert_installed)
from .directory_password_policy import (  # noqa: E402
    SAMBA_DEFAULT, DirectoryPasswordPolicy)
from .durable_workstation import DurableBinding, durable_binding  # noqa: E402
from .factory_runner import (  # noqa: E402
    GATEWAY_MAC, gateway_command, wait_for_switch_port)
from .persistent_controller_session import (  # noqa: E402
    PersistentControllerSession, _join_material, session_command)
from .secret_scan import (  # noqa: E402
    count_secret_occurrences, secret_needles)
from .secure_artifacts import atomic_write  # noqa: E402
from .signal_cleanup import RunInterrupted, SignalGuard  # noqa: E402
from .simulated_topology import MACS  # noqa: E402
from .simulation_evidence import redact  # noqa: E402
from .simulation_overlay import PersistentControllerInstance  # noqa: E402
from .windows_durable_prepare import (  # noqa: E402
    DEFAULT_RUNS, STAGE, _sha256, inspect_workstation)
from .windows_durable_prepare import prepare as prepare_attempt  # noqa: E402
from .windows_gui import PLAIN, SHIFTED  # noqa: E402
from .windows_identity_adapter import (  # noqa: E402
    NativeWindowsAcceptanceAdapter)
from .windows_identity_factory import REFERENCE_ROOT, _references  # noqa: E402
from .windows_identity_orchestrator import (  # noqa: E402
    _execute_join, resolve_identity_roster)
from .windows_identity_prepare import DISK_NAME, VARS_NAME  # noqa: E402
from .windows_identity_progressive import (  # noqa: E402
    NativeBoundaryRotationSession, ProgressiveRotationPlan,
    execute_progressive_rotation)
from .windows_identity_run import (  # noqa: E402
    NativeProcessBoundary, PrivateIdentityMaterial, WindowsIdentityRunError)
from .windows_postsubmit_diagnostic import (  # noqa: E402
    PostSubmitDiagnosticSession)
from .windows_public_command import PublicPowerShellLaunchPlan  # noqa: E402
from .workstation_instance import (  # noqa: E402
    DEFAULT_ROOT, WorkstationInstance, workstation_state)


#: Gate 5's synthetic guest identity (``windows_install_prepare``): the local
#: break-glass administrator gate 6 rotates, and the computer name whose
#: account the join creates.  A drift test holds both to gate 5's source.
LOCAL_ADMINISTRATOR = "telosadmin"
WINDOWS_COMPUTER_NAME = "TELOS-WIN-01"
#: The clean shutdown is issued the way gate 6 issues its fault-restore
#: reboot: a PowerShell line through the calibrated Run dialog.
#: ``Stop-Computer`` is a full shutdown, never a Fast Startup hibernation.
SHUTDOWN_COMMAND = (
    'powershell -NoProfile -Command "Start-Sleep -Seconds 8; '
    'Stop-Computer -Force"')
SHUTDOWN_TIMEOUT = 300.0
ACPI_SHUTDOWN_TIMEOUT = 180.0
#: A conservative bound on what a join adds to the overlay (a first-logon
#: profile, logs and paging); the fold's standalone copy holds disk + growth.
WINDOWS_GROWTH_BYTES = 8 * 1024 ** 3
#: Gate 6's switch accepts every declared port within this bound; the
#: persistent Controller's console login alone may take five minutes.
SWITCH_ACCEPT_TIMEOUT = 1200
SWITCH_IDLE_TIMEOUT = 3600
PASSWORD_MAX_LENGTH = 127
RESULT_NAME = "result.json"
TRANSCRIPT_NAME = "controller-console-transcript.log"
#: Files the evidence scan skips: guest media, and pixel captures of masked
#: fields that cannot carry typed text.
UNSCANNED = frozenset({DISK_NAME, VARS_NAME, "control.iso"})


class DurableWindowsJoinError(RuntimeError):
    """A durable Windows join cannot proceed, or did not do what it must."""


class DurableFaultRefused(WindowsIdentityRunError):
    """A fault operation was asked of the durable fabric; none exists."""


class DurableControllerAuthDisabled(RuntimeError):
    """The Controller-side authentication diagnostic is off on this path.

    Deliberately not a ``ValueError``: gate 6's adapter treats a session it
    cannot construct as "no receipt" and continues to the sign-in, which is
    exactly the disabled behaviour; a ``ValueError`` would abort instead.
    """


# -- the owner's credentials ------------------------------------------------------
class OwnerSecrets:
    """The three values the owner types, in memory only, never in ``repr``."""

    def __init__(self, console: bytes, local_administrator: str,
                 daily_administrator: str) -> None:
        self.console = console
        self.local_administrator = local_administrator
        self.daily_administrator = daily_administrator

    def __repr__(self) -> str:
        return "OwnerSecrets(<private>)"

    def values(self) -> tuple[str, ...]:
        return tuple(value for value in (
            self.console.decode("utf-8", errors="replace"),
            self.local_administrator, self.daily_administrator) if value)

    def clear(self) -> None:
        self.console = b""
        self.local_administrator = ""
        self.daily_administrator = ""


def typeable_problem(value: str) -> str | None:
    """Why QMP could not type *value* into the guest, or ``None``.

    Gate 6 types every credential as US-layout key events
    (``windows_gui.QmpClient.type_text``); a value it cannot encode would
    fail only after the guest booted.  The reason never quotes the value.
    """
    if not 1 <= len(value) <= PASSWORD_MAX_LENGTH:
        return f"is not 1 to {PASSWORD_MAX_LENGTH} characters long"
    if value != value.strip():
        return "begins or ends with a space"
    for character in value:
        if not (("a" <= character <= "z") or ("A" <= character <= "Z")
                or ("0" <= character <= "9") or character in PLAIN
                or character in SHIFTED):
            return ("uses a character the guest keyboard cannot type "
                    "(printable US-ASCII only)")
    return None


def local_administrator_password_problem(
    password: str, policy: DirectoryPasswordPolicy = SAMBA_DEFAULT,
) -> str | None:
    """The host-side policy for the replacement break-glass password.

    Typeability, then the bound directory's password policy (*policy*: the
    instance's recorded one, or Samba's default), which a domain member's
    password policy may later apply to local accounts too.  A recorded
    policy's refusal names it; the default's reads as it always has.
    """
    problem = typeable_problem(password)
    if problem is not None:
        return problem
    problem = controller_principals.directory_password_problem(
        password, LOCAL_ADMINISTRATOR, policy)
    if problem is not None and policy.recorded:
        return f"{problem} under {policy.source}"
    return problem


def collect_owner_secrets(
    instance: str, daily_name: str, *,
    prompt: Callable[..., bytes] = _typed_secret, attempts: int = 3,
    policy: DirectoryPasswordPolicy = SAMBA_DEFAULT,
) -> OwnerSecrets:
    """Ask, in order, for every value the run needs; nothing has started yet."""
    console = prompt(
        f"{CONSOLE_ACCOUNT} console password for persistent instance "
        f"{instance}: ")
    local = ""
    for _attempt in range(attempts):
        try:
            local = prompt(
                f"new Windows local-administrator ({LOCAL_ADMINISTRATOR}) "
                "password: ",
                confirm="retype the new Windows local-administrator "
                        "password: ").decode("utf-8")
        except ValueError as error:
            print(f"error: {error}; try again", file=sys.stderr)
            continue
        problem = local_administrator_password_problem(local, policy)
        if problem is None:
            break
        print(f"error: the new local-administrator password {problem}; try "
              "again", file=sys.stderr)
        local = ""
    if not local:
        raise DurableWindowsJoinError(
            "no acceptable local-administrator password was typed; nothing "
            "was started")
    daily = prompt(
        f"current domain password for daily_administrator ({daily_name}): "
    ).decode("utf-8")
    problem = typeable_problem(daily)
    if problem is not None:
        raise DurableWindowsJoinError(
            f"the daily administrator's password {problem}; gate 6 types it "
            "at the Windows sign-in. Nothing was started")
    if local in (daily, console.decode("utf-8", errors="replace")):
        raise DurableWindowsJoinError(
            "the new local-administrator password must differ from the daily "
            "administrator's and the Controller console's (break-glass "
            "custody, owner decision 2026-09-30). Nothing was started")
    return OwnerSecrets(console, local, daily)


# -- gate 6's credential owner, for a durable directory ------------------------------
class CustodyRecovery(AbstractContextManager[str]):
    """Gate 6's recovered local credential; ``W`` keeps the publication.

    Gate 6 destroys the publication right after the acceptance that consumed
    it.  Here that request is recorded and nothing is unlinked: the kept
    workstation shreds its custody publication only after the fold.
    """

    def __init__(self, inner: AbstractContextManager[str]) -> None:
        self._inner = inner
        self._active = False
        self.release_requested = False

    def __enter__(self) -> str:
        value = self._inner.__enter__()
        self._active = True
        return value

    def __exit__(self, *exc: object) -> None:
        self._active = False
        self._inner.__exit__(*exc)

    def destroy_publication(self) -> None:
        if not self._active:
            raise DurableWindowsJoinError(
                "the publication release was requested outside its recovery")
        self.release_requested = True


def _refuse_staging(*_args: object) -> None:
    raise DurableWindowsJoinError(
        "a durable directory stages no principals: its accounts already exist")


def _refuse_legacy_rotation(_old: str, _new: str) -> None:
    raise DurableWindowsJoinError("the legacy rotation callback is unavailable")


class DurablePrivateIdentityMaterial(PrivateIdentityMaterial):
    """Gate 6's credential owner with the owner's replacement and no staging."""

    def __init__(self, publication: Path, private_parent: Path, *,
                 replacement: str) -> None:
        super().__init__(
            publication, private_parent,
            rotate_guest=_refuse_legacy_rotation,
            stage_principals=_refuse_staging,
            destroy_principals=_refuse_staging)
        self.recovery = CustodyRecovery(self.recovery)
        self._owner_replacement: str | None = replacement

    def generate_replacement_credential(self) -> str:
        """The owner-typed password, handed over once; nothing is generated."""
        if self._new_local is not None or not self._owner_replacement:
            raise WindowsIdentityRunError(
                "replacement credential is already owned")
        self._new_local, self._owner_replacement = self._owner_replacement, None
        return self._new_local

    def stage_controller_principals(self) -> None:
        if self._old_local is not None or self._recovery_context is not None:
            raise WindowsIdentityRunError(
                "recovered credential must be destroyed before staging")
        # Nothing to stage: the durable accounts exist in the directory.

    def destroy_controller_principals(self) -> None:
        # Nothing was staged, so nothing is destroyed.
        return None

    def rotate_local_credential(self) -> None:
        raise DurableWindowsJoinError(
            "the durable join rotates through gate 6's progressive rotation "
            "only")

    def destroy_private_publication(self) -> None:
        raise DurableWindowsJoinError(
            "the custody publication is retired by the kept workstation after "
            "the fold, never here")

    def close(self, *, controller_destroyed: bool = False) -> None:
        self._owner_replacement = None
        super().close(controller_destroyed=controller_destroyed)


# -- gate 6's process boundary, with the persistent Controller -------------------
def _popen(argv: list[str], **options) -> subprocess.Popen[bytes]:
    return subprocess.Popen(argv, **options)


class DurableWindowsBoundary(NativeProcessBoundary):
    """Gate 6's switch, gateway and Windows; the bound instance as Controller.

    The persistent Controller is owned by its session and is never entered in
    ``self.processes``, so gate 6's ``_stop`` and ``_set_process_available``
    -- a terminate and a SIGSTOP -- have no handle on it at all; the fault
    setters raise besides.  It stops only by the session's console poweroff.
    """

    def __init__(
        self, attempt: Path, controller_state: Path, *,
        target: PersistentControllerInstance, console_password: bytes,
        session_factory: Callable[..., PersistentControllerSession]
        = PersistentControllerSession,
    ) -> None:
        super().__init__(attempt, controller_state)
        self._target = target
        self._console_password = console_password
        self._session_factory = session_factory
        self.persistent_session: PersistentControllerSession | None = None
        self._persistent_console = None
        self._join_serial = None
        self.join_credentials: list[str] = []
        self.persistent_transcript: bytes | None = None
        self.persistent_facts: dict[str, object] = {
            "started": False, "controller_attached": False,
            "stopped": False, "stop_error": None,
            "dependency_services": "none",
        }

    # -- the fabric: the instance keeps its own MAC --------------------------
    def start_switch(self) -> None:
        self._validate()
        if self.runtime.exists():
            raise WindowsIdentityRunError("identity runtime already exists")
        self.runtime.mkdir(mode=0o700)
        evidence = self.runtime / "switch.jsonl"
        listener = socket.socket()
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(3)
            self.port = int(listener.getsockname()[1])
            self.processes["switch"] = _popen(
                persistent_switch_command(
                    listener.fileno(), evidence, controller_mac=SOCKET_MAC,
                    workstation_mac=MACS["client"],
                    accept_timeout=SWITCH_ACCEPT_TIMEOUT,
                    idle_timeout=SWITCH_IDLE_TIMEOUT, identity_mode=True),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT, pass_fds=(listener.fileno(),))
        except BaseException:
            self._stop("switch")
            raise
        finally:
            listener.close()
        try:
            self.processes["gateway"] = _popen(
                gateway_command(
                    self.port, controller_mac=SOCKET_MAC, identity_mode=True),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT)
            self.gateway_switch_generation = wait_for_switch_port(
                evidence, "gateway", GATEWAY_MAC)
        except BaseException:
            self._stop("gateway", "switch")
            raise

    def _start_dependency(self, role: str) -> None:
        # Gate 6 starts its fault-test update source and optional storage
        # here.  A durable join runs no fault phase, so none exists.
        return None

    # -- the Controller: a persistent session, never a child process ---------
    def start_controller(self) -> None:
        if self.port is None:
            raise WindowsIdentityRunError("switch must start before Controller")
        if self.persistent_session is not None:
            raise WindowsIdentityRunError(
                "the persistent Controller session already exists")
        if not self._console_password:
            raise WindowsIdentityRunError(
                "the Controller console credential was already dropped")
        session = self._session_factory(
            self._target, port=self.port, password=self._console_password,
            canonical_state=self.controller_state)
        self.persistent_session = session
        self._persistent_console = session.start(
            attached=self._controller_attached)
        self.persistent_facts["started"] = True

    def _controller_attached(self) -> None:
        wait_for_switch_port(
            self.runtime / "switch.jsonl", "controller", SOCKET_MAC,
            timeout=60.0)
        self.persistent_facts["controller_attached"] = True

    def stop_controller(self) -> None:
        """Power the directory off over its console; record, never power-cut.

        A teardown problem here (a terminate fallback, a lock that would not
        release) is recorded in ``persistent_facts`` and reported by the
        runner; it does not fail the Windows side, whose overlay it cannot
        touch.  An interrupt still propagates.
        """
        session = self.persistent_session
        if session is None:
            self._console_password = b""
            return
        try:
            session.stop()
        except Exception as error:  # noqa: BLE001 - recorded, not hidden
            self.persistent_facts["stop_error"] = type(error).__name__
        finally:
            facts = dict(getattr(session, "facts", {}))
            self.persistent_facts.update(
                stopped=True,
                launches=facts.get("launches"),
                logins=facts.get("logins"),
                live_argv_audited=facts.get("live_argv_audited"),
                clean_poweroff=(
                    int(facts.get("clean_poweroffs") or 0) >= 1
                    and not facts.get("terminated_fallback")),
                terminated_fallback=bool(facts.get("terminated_fallback")),
                lock_released=bool(facts.get("lock_released")))
            # Taken while the session still holds its credential, so the
            # redaction can prove the transcript free of it.
            self.persistent_transcript = session.redacted_transcript(
                list(self.join_credentials))
            try:
                session.close()
            except Exception as error:  # noqa: BLE001 - recorded
                self.persistent_facts["stop_error"] = (
                    self.persistent_facts["stop_error"]
                    or type(error).__name__)
            self.persistent_session = None
            self._persistent_console = None
            self._join_serial = None
            self._console_password = b""

    # -- the one-use join principal, over the persistent console ------------
    def stage_join_principal(self, credential: str):
        """The persistent probe's own stage, over the logged-in console."""
        console = self._persistent_console
        if console is None:
            raise WindowsIdentityRunError(
                "the persistent Controller console is unavailable")
        if self._join_serial is None:
            module = _join_material()
            serial = module.ControllerJoinSerial(
                console.reader, console.writer, timeout=console.timeout)
            serial.console = console
            self._join_serial = serial
        # Held only so the transcript and the evidence can be proven free of
        # it; dropped by ``forget_credentials``.
        self.join_credentials.append(credential)
        # The principal's random name is recorded before the stage is sent,
        # so a lost acknowledgement still leaves the name to clean up by.
        self.persistent_facts.update(
            join_principal=getattr(self._join_serial, "_principal", None),
            join_principal_destroyed=False)
        staged = self._join_serial.stage(credential)
        self.persistent_facts["join_principal"] = staged.principal
        return staged

    def destroy_join_principal(self):
        if self._join_serial is None:
            raise WindowsIdentityRunError(
                "the Controller join-principal owner is unavailable")
        proof = self._join_serial.destroy()
        self.persistent_facts["join_principal_destroyed"] = bool(
            proof.destruction_proved)
        return proof

    def forget_credentials(self) -> None:
        self.join_credentials.clear()
        self._console_password = b""

    # -- no fault operation exists on a durable fabric ----------------------
    def _set_process_available(self, role: str, available: bool) -> None:
        raise DurableFaultRefused(
            f"{role} availability cannot change: a durable join injects no "
            "fault, and the persistent Controller is a durable directory")

    def set_controller_available(self, available: bool) -> None:
        self._set_process_available("controller", available)

    def set_gateway_available(self, available: bool) -> None:
        self._set_process_available("gateway", available)

    def set_update_source_available(self, available: bool) -> None:
        self._set_process_available("update-source", available)

    def set_optional_storage_available(self, available: bool) -> None:
        self._set_process_available("optional-storage", available)


# -- gate 6's adapter, with the Controller-side diagnostic disabled --------------
class DurableWindowsAdapter(NativeWindowsAcceptanceAdapter):
    """Gate 6's adapter over the durable boundary."""

    def _shared_controller_console(self):
        # The only consumers are gate 6's Controller-side auth watcher (armed
        # before the domain sign-in, run under sudo on the Controller) and its
        # principal and join-material serials, which this class replaces.
        # Refusing here disables the watcher on the durable console.
        raise DurableControllerAuthDisabled(
            "the Controller-side authentication diagnostic is disabled on a "
            "durable directory")

    def stage_principals(self, values):
        _refuse_staging(values)

    def destroy_principals(self, names):
        _refuse_staging(names)

    def stage_join_principal(self, credential: str):
        return self.boundary.stage_join_principal(credential)

    def destroy_join_principal(self):
        return self.boundary.destroy_join_principal()


def _no_secret_scan(_secrets: tuple[str, ...]) -> Mapping[str, object]:
    raise DurableWindowsJoinError(
        "gate 6's acceptance secret scan belongs to its fault phases, which a "
        "durable join does not run")


# -- the clean shutdown ------------------------------------------------------------
def _await_exit(process, timeout: float, *, clock=time.monotonic,
                sleep=time.sleep) -> bool:
    deadline = clock() + timeout
    while clock() < deadline:
        if process.poll() is not None:
            return True
        sleep(0.5)
    return process.poll() is not None


def shutdown_windows(
    adapter: NativeWindowsAcceptanceAdapter, boundary: NativeProcessBoundary,
    *, timeout: float = SHUTDOWN_TIMEOUT,
    acpi_timeout: float = ACPI_SHUTDOWN_TIMEOUT,
    clock=time.monotonic, sleep=time.sleep,
) -> str:
    """Shut Windows down from inside, and prove QEMU exited on its own.

    ``Stop-Computer`` through gate 6's Run-dialog launcher first; if that
    cannot be issued or does not finish, the ACPI power button.  A guest that
    ignores both is refused: its overlay is not a disk to fold.
    """
    process = boundary.processes.get("windows")
    if process is None or process.poll() is not None:
        raise DurableWindowsJoinError(
            "Windows is not running, so its clean shutdown cannot be proved")
    method = None
    try:
        adapter.launch_guest(SHUTDOWN_COMMAND)
        method = "stop-computer"
    except (KeyboardInterrupt, SystemExit, RunInterrupted):
        raise
    except Exception:  # noqa: BLE001 - the fallback below decides
        method = None
    if method is not None and _await_exit(
            process, timeout, clock=clock, sleep=sleep):
        return _clean(process, method)
    qmp = boundary.qmp
    if qmp is not None and process.poll() is None:
        try:
            qmp.execute("system_powerdown", timeout=10)
        except (KeyboardInterrupt, SystemExit, RunInterrupted):
            raise
        except Exception:  # noqa: BLE001 - refused below
            pass
        if _await_exit(process, acpi_timeout, clock=clock, sleep=sleep):
            return _clean(process, "acpi-power-button")
    raise DurableWindowsJoinError(
        "Windows did not shut down cleanly; its overlay will not be folded")


def _clean(process, method: str) -> str:
    if process.returncode != 0:
        raise DurableWindowsJoinError(
            f"Windows QEMU exited with status {process.returncode} after "
            f"{method}; that is not a clean shutdown")
    return method


# -- one join into one prepared attempt -----------------------------------------
def require_durable_authorization(
    attempt: Path, workstation: WorkstationInstance, marker: dict,
    binding: DurableBinding,
) -> dict:
    """The attempt's authorization, held to ``W``'s head and the binding."""
    authorization = json.loads(
        (attempt / "authorization.json").read_text(encoding="utf-8"))
    durable = authorization.get("durable")
    head = marker["ledger"][-1]
    if not isinstance(durable, dict) or durable.get("stage") != STAGE:
        raise DurableWindowsJoinError(
            "the attempt was not prepared for a durable windows-join")
    if durable.get("workstation") != workstation.state.name:
        raise DurableWindowsJoinError(
            "the attempt was prepared for another kept workstation")
    if durable.get("bound_instance") != binding.instance:
        raise DurableWindowsJoinError(
            "the attempt was prepared against another persistent instance")
    if durable.get("ledger_head") != {
            "stage": head["stage"], "disk_sha256": head["disk_sha256"],
            "vars_sha256": head.get("vars_sha256")}:
        raise DurableWindowsJoinError(
            "the attempt was not prepared on the kept workstation's ledger "
            "head")
    backing = authorization.get("overlay", {}).get("backing_path")
    if not backing or not os.path.samefile(backing, workstation.disk):
        raise DurableWindowsJoinError(
            "the attempt's overlay is not backed by the kept workstation's "
            "disk")
    reference = durable.get("operator_sign_in_reference") or {}
    path = attempt / str(reference.get("path"))
    if (path.is_symlink() or not path.is_file()
            or not path.resolve().is_relative_to(attempt.resolve())
            or _sha256(path) != reference.get("sha256")):
        raise DurableWindowsJoinError(
            "the relabelled operator sign-in reference changed after prepare")
    return authorization


def rotation_plan(
    attempt: Path, authorization: dict,
) -> tuple[ProgressiveRotationPlan, PublicPowerShellLaunchPlan]:
    """Gate 6's production plan, but for the realm-relabelled sign-in."""
    _guest, references = _references(authorization)
    durable = authorization["durable"]
    plan = ProgressiveRotationPlan(
        sign_in_manifest=REFERENCE_ROOT / "sign-in.json",
        desktop_manifest=REFERENCE_ROOT / "desktop.json",
        security_options_manifest=REFERENCE_ROOT / "security-options.json",
        change_password_manifest=REFERENCE_ROOT / "change-password.json",
        expected_guest=references["sign-in"].guest,
        evidence_root=attempt / "rotation-evidence",
        change_password_keys=("down", "down", "down", "ret"),
        post_join_local_account_calibrated=True,
        post_join_sign_in_manifest=REFERENCE_ROOT / "post-join-sign-in.json",
        post_join_operator_account_calibrated=True,
        post_join_operator_sign_in_manifest=(
            attempt / durable["operator_sign_in_reference"]["path"]),
        post_join_retain_submit_frames=10,
        post_join_operator_desktop_manifest=(
            REFERENCE_ROOT / "post-join-operator-desktop.json"),
    )
    command = PublicPowerShellLaunchPlan(
        desktop=references["desktop"], run_dialog=references["run-dialog"])
    return plan, command


def _write_json(path: Path, document: Mapping[str, object]) -> None:
    atomic_write(path, (json.dumps(document, indent=2, sort_keys=True)
                        + "\n").encode("utf-8"))


def _amend_result(evidence: Path, **fields: object) -> None:
    output = evidence / RESULT_NAME
    if output.is_symlink() or not output.is_file():
        return
    result = json.loads(output.read_text(encoding="utf-8"))
    result.update(fields)
    _write_json(output, result)


def _scrub(text: str, secrets: tuple[str, ...]) -> str:
    for value in sorted((value for value in secrets if value), key=len,
                        reverse=True):
        text = text.replace(value, "[REDACTED]")
    return redact(text.encode("utf-8", errors="replace")).decode(
        "utf-8", errors="replace")


def evidence_secret_hits(attempt: Path, secrets: tuple[str, ...]) -> list[str]:
    """Every retained text file under *attempt* that carries a secret."""
    values = tuple(value for value in secrets if value)
    if not values:
        return []
    needles = secret_needles(values)
    hits = []
    for path in sorted(Path(attempt).rglob("*")):
        if (path.is_symlink() or not path.is_file()
                or path.name in UNSCANNED or path.suffix == ".ppm"):
            continue
        with path.open("rb") as stream:
            chunks = iter(lambda: stream.read(1024 * 1024), b"")
            if count_secret_occurrences(chunks, needles):
                hits.append(str(path.relative_to(attempt)))
    return hits


class DurableWindowsJoin:
    """One durable Windows join into one prepared attempt.  Folds nothing."""

    def __init__(
        self, workstation: WorkstationInstance, binding: DurableBinding, *,
        target: PersistentControllerInstance, controller_state: Path,
        secrets: OwnerSecrets,
        session_factory: Callable[..., PersistentControllerSession]
        = PersistentControllerSession,
    ) -> None:
        self.workstation = workstation
        self.binding = binding
        self.target = target
        self.controller_state = Path(controller_state)
        self.secrets = secrets
        self.session_factory = session_factory

    def execute(self, attempt: Path, marker: dict) -> dict:
        attempt = Path(attempt).absolute()
        evidence = attempt / "evidence"
        if evidence.exists() or evidence.is_symlink():
            raise DurableWindowsJoinError("attempt already has evidence")
        evidence.mkdir(mode=0o700)
        result: dict = {
            "schema": 1, "kind": "durable-windows-join", "stage": STAGE,
            "status": "fail", "phase": "starting",
            "workstation": self.workstation.state.name,
            "bound_instance": self.binding.instance,
            "attempt": attempt.name,
            "machine_account": WINDOWS_COMPUTER_NAME,
            "local_administrator_credential": "owner-typed; never stored",
            "local_administrator_rotated": False,
            "joined_after_reboot": False,
            "secure_channel_proved": False,
            "operator_local_administrator": False,
            "join_principal_destroyed": False,
            "windows_clean_shutdown": False,
            "principal_staging": "none; the durable accounts already exist",
            "fault_operations": "none",
            "controller_auth_diagnostic": "disabled",
            "publication": "held by the kept workstation until the fold",
        }
        boundary = DurableWindowsBoundary(
            attempt, self.controller_state, target=self.target,
            console_password=self.secrets.console,
            session_factory=self.session_factory)
        try:
            self._run(boundary, attempt, marker, result)
            result.update(status="observed", phase="windows-joined-shut-down")
            return result
        except BaseException as error:
            secrets = self.secrets.values() + tuple(boundary.join_credentials)
            result["error_type"] = type(error).__name__
            result["error"] = _scrub(str(error), secrets)
            diagnostic = getattr(error, "diagnostic", None)
            if diagnostic is not None and hasattr(diagnostic, "render"):
                result["diagnostic"] = _scrub(diagnostic.render(), secrets)
            raise
        finally:
            # Validation-only ownership of the control disc, when Windows
            # never started (idempotent otherwise).
            boundary.release_prestart_ownership()
            result["controller"] = {
                key: boundary.persistent_facts.get(key) for key in (
                    "started", "controller_attached", "launches", "logins",
                    "live_argv_audited", "clean_poweroff",
                    "terminated_fallback", "lock_released", "stop_error",
                    "dependency_services", "join_principal_destroyed")}
            principal = boundary.persistent_facts.get("join_principal")
            if principal and not boundary.persistent_facts.get(
                    "join_principal_destroyed"):
                # A random tj- name, not a credential: the owner needs it to
                # remove the principal by hand (``samba-tool user delete``).
                result["controller"]["join_principal_may_remain"] = principal
                print("error: a one-use join principal may remain in the "
                      f"directory of {self.binding.instance}: {principal}",
                      file=sys.stderr)
            transcript = boundary.persistent_transcript
            if transcript is not None:
                atomic_write(evidence / TRANSCRIPT_NAME, transcript)
            result["controller"]["transcript"] = (
                "retained, redacted" if transcript is not None
                else "withheld or absent")
            _write_json(evidence / RESULT_NAME, result)
            hits = evidence_secret_hits(
                attempt, self.secrets.values()
                + tuple(boundary.join_credentials))
            boundary.forget_credentials()
            result["evidence_secret_free"] = not hits
            _write_json(evidence / RESULT_NAME, result)
            if hits and result["status"] == "observed":
                result["status"] = "fail"
                _write_json(evidence / RESULT_NAME, result)
                raise DurableWindowsJoinError(
                    "a typed credential reached the retained evidence ("
                    + ", ".join(hits) + "); the overlay will not be folded. "
                    "Shred those files")

    def _run(self, boundary: DurableWindowsBoundary, attempt: Path,
             marker: dict, result: dict) -> None:
        boundary._validate()
        authorization = require_durable_authorization(
            attempt, self.workstation, marker, self.binding)
        plan, command = rotation_plan(attempt, authorization)

        def post_submit_diagnostic(**options: object):
            if boundary.serial_socket is None:
                raise DurableWindowsJoinError(
                    "live Windows serial endpoint is unavailable")
            return PostSubmitDiagnosticSession.connect(
                boundary.serial_socket, **options)

        adapter = DurableWindowsAdapter(
            boundary, attempt, realm=self.binding.dns_domain,
            local_principal=LOCAL_ADMINISTRATOR, scan_secrets=_no_secret_scan,
            rotation_plan=plan, command_plan=command,
            post_submit_diagnostic=post_submit_diagnostic)
        material = DurablePrivateIdentityMaterial(
            self.workstation.publication, attempt,
            replacement=self.secrets.local_administrator)
        after_rotation = self._join(adapter, boundary, attempt, material, result)
        outcome = "failed"
        try:
            # One use, exactly as gate 6's CLI claims its attempts.
            boundary.claim_attempt()
            result["phase"] = "local-administrator-rotation"
            receipt = execute_progressive_rotation(
                plan=plan, session=NativeBoundaryRotationSession(boundary),
                recovery=material.recovery,
                generate_credential=material.generate_replacement_credential,
                after_rotation=after_rotation)
            outcome = "succeeded"
        except (KeyboardInterrupt, SystemExit, RunInterrupted):
            outcome = "interrupted"
            raise
        finally:
            try:
                material.close(controller_destroyed=True)
            finally:
                boundary.release_prestart_ownership()
                teardown = boundary.audit_teardown()
                result["teardown"] = teardown
                try:
                    boundary.terminalize_attempt(
                        outcome=outcome, teardown=teardown)
                except (OSError, RuntimeError, ValueError) as error:
                    result["terminal_receipt_error"] = type(error).__name__
        if not (receipt.replacement_sign_in_proved
                and "post-rotation-acceptance-complete" in receipt.phases
                and material.recovery.release_requested):
            raise DurableWindowsJoinError(
                "the rotation returned without its join and shutdown proof")
        if not all(result["teardown"].values()):
            raise DurableWindowsJoinError(
                "gate 6's teardown audit was incomplete: "
                + ", ".join(key for key, value in result["teardown"].items()
                            if not value))

    def _join(self, adapter: DurableWindowsAdapter,
              boundary: DurableWindowsBoundary, attempt: Path,
              material: DurablePrivateIdentityMaterial,
              result: dict) -> Callable[[str], None]:
        binding = self.binding
        secrets = self.secrets

        def acceptance(_local: str, principals: Mapping[str, str]) -> None:
            if principals:
                raise DurableWindowsJoinError(
                    "a durable join must stage no principals")
            result["phase"] = "windows-join"
            proof, destroyed = _execute_join(
                realm=binding.dns_domain, private_root=attempt,
                operator_credential=secrets.daily_administrator,
                callbacks=adapter.callbacks(),
                stage_join_principal=adapter.stage_join_principal,
                destroy_join_principal=adapter.destroy_join_principal)
            # prove_join_and_reboot already required each of these; they are
            # restated so the record says what was proved, never a value.
            joined = proof.get("joined_after_reboot") is True
            result.update(
                joined_after_reboot=joined, secure_channel_proved=joined,
                operator_local_administrator=(
                    proof.get("operator_local_administrator") is True),
                join_principal_destroyed=destroyed is True)
            if not (joined and destroyed is True
                    and result["operator_local_administrator"]):
                raise DurableWindowsJoinError(
                    "the join returned without complete proof")
            result["phase"] = "windows-shutdown"
            result["windows_shutdown_method"] = shutdown_windows(
                adapter, boundary)
            result["windows_clean_shutdown"] = True

        def after_rotation(replacement: str) -> None:
            # Called by gate 6 only after a fresh sign-in with the
            # replacement proved the rotation.
            result["local_administrator_rotated"] = True
            material.run_scoped_acceptance(replacement, acceptance)

        return after_rotation


# -- the kept workstation ------------------------------------------------------
def open_workstation(root: Path, name: str) -> WorkstationInstance:
    return WorkstationInstance(workstation_state(root, name), name=name)


def join_mode(workstation: WorkstationInstance, marker: dict) -> str:
    """``join`` when windows-join is next; ``retire`` when only the
    publication is left after a windows-join fold; otherwise a refusal."""
    name = marker["workstation"]
    refusal = workstation.pending_fold_refusal(marker)
    if refusal is not None:
        raise DurableWindowsJoinError(refusal)
    following = workstation.next_stage(marker)
    if following == STAGE:
        return "join"
    stages = [entry["stage"] for entry in marker["ledger"]]
    if following is None and STAGE in stages:
        if marker["publication"].get("retired_utc"):
            raise DurableWindowsJoinError(
                f"kept workstation {name} already folded {STAGE} and retired "
                "its publication; nothing is left to do")
        return "retire"
    raise DurableWindowsJoinError(
        f"the next stage for kept workstation {name} is {following!r}, not "
        f"{STAGE!r}")


def require_join_realm(binding: DurableBinding) -> None:
    """Gate 6's join derives the Kerberos realm by upper-casing the domain."""
    if binding.dns_domain.upper() != binding.kerberos_realm:
        raise DurableWindowsJoinError(
            f"persistent instance {binding.instance}'s Kerberos realm is not "
            "its DNS domain upper-cased, which gate 6's join assumes; values "
            "are not printed")


def require_roster_agreement(overlay_path: Path | None = None) -> str:
    """The daily administrator's name, once both rosters agree on it.

    Gate 6's join and probes resolve principals from the acceptance roster
    (the default overlay); the durable directory holds the durable roster.
    They must name the same three accounts, or gate 6 would sign in, and add
    to local Administrators, an account the directory does not hold.
    """
    resolve_identity_roster()
    try:
        durable = controller_principals.durable_directory_roster(
            overlay_path).roster
    except (controller_principals.IdentityRosterError, OSError,
            ValueError) as error:
        raise DurableWindowsJoinError(str(error)) from error
    acceptance = {
        "standard_user": controller_principals.standard_user(),
        "daily_administrator": controller_principals.daily_administrator(),
        "domain_administrator": controller_principals.domain_administrator(),
    }
    disagreeing = [role for role, name in acceptance.items()
                   if durable.get(role) != name]
    if disagreeing:
        raise DurableWindowsJoinError(
            "gate 6's roster and the durable roster name different accounts "
            f"for {', '.join(disagreeing)}; names are not printed")
    return acceptance["daily_administrator"]


def persistent_target(binding: DurableBinding) -> PersistentControllerInstance:
    return PersistentControllerInstance(binding.state, instance=binding.instance)


def preview_command(
    target: PersistentControllerInstance, controller_state: Path,
) -> list[str]:
    """The audited persistent argv, built (and so refused) before any run."""
    return session_command(target, 65535, canonical_state=controller_state)


def space_needs(workstation: WorkstationInstance, run_root: Path) -> list[dict]:
    allocated = workstation.disk.stat().st_blocks * 512
    needs: dict[int, dict] = {}
    for directory, amount in (
            (workstation.state, allocated + WINDOWS_GROWTH_BYTES),
            (_existing_ancestor(run_root), WINDOWS_GROWTH_BYTES)):
        device = directory.stat().st_dev
        entry = needs.setdefault(device, {"path": directory, "needed": 0})
        entry["needed"] += amount
    for entry in needs.values():
        entry["free"] = shutil.disk_usage(entry["path"]).free
    return list(needs.values())


def preflight_problems(
    workstation: WorkstationInstance, target: PersistentControllerInstance,
    space: list[dict],
) -> list[str]:
    """Every refusal an --apply run can know before the owner types anything."""
    problems = [f"{tool} is not installed" for tool in (
        "qemu-system-x86_64", "qemu-img", "xorriso") if not shutil.which(tool)]
    if ovmf_pair() is None:
        problems.append("OVMF firmware was not found")
    if _persistent_running(target) is not False:
        problems.append(f"persistent instance {target.instance} is already "
                        "running or its lock cannot be probed")
    publication = workstation.publication
    if publication.is_symlink() or not publication.is_file():
        problems.append(
            "the kept workstation holds no custody publication, so the local "
            "administrator credential cannot be recovered")
    for entry in space:
        if entry["free"] < entry["needed"]:
            problems.append(f"not enough free space: {entry['path']} needs "
                            f"about {_gib(entry['needed'])}")
    if not problems:
        try:
            assert_installed(
                target.disk, subject=f"the persistent instance disk "
                f"{target.disk}", remedy="Recreate and converge the instance.")
        except ControllerImageError as error:
            problems.append(str(error))
    return problems


def _discard_overlay(overlay: Path) -> bool:
    try:
        overlay.unlink(missing_ok=True)
    except OSError:
        return False
    return True


def print_plan(
    args: argparse.Namespace, workstation: WorkstationInstance, marker: dict,
    binding: DurableBinding, space: list[dict], preview: list[str],
) -> None:
    stages = ", ".join(entry["stage"] for entry in marker["ledger"])
    print("Boundary: loopback-only switch; no host or UniFi changes")
    print(f"Kept workstation: {workstation.state.name} at {workstation.state}; "
          f"stages done: {stages}; next stage {STAGE}")
    print(f"Bound instance: {binding.instance}. The kept workstation's marker "
          f"names it; its realm, domain SID and roster are checked against "
          f"it and never printed")
    print(f"Controller: persistent instance {binding.instance} booted IN "
          f"PLACE on the per-run switch under its lock, keeping its own MAC "
          f"{SOCKET_MAC}; logged in as {CONSOLE_ACCOUNT}; no QMP, no media, "
          f"no pause and no fault injection; the Controller-side "
          f"authentication diagnostic is disabled; stopped by a clean console "
          f"poweroff")
    print(f"Windows: a fresh overlay backed by {workstation.disk} with the "
          f"kept workstation's firmware variables; Windows boots by "
          f"systemd-boot's five-second Windows default")
    print(f"Steps: record machine account {WINDOWS_COMPUTER_NAME} in the "
          f"marker; rotate the local administrator ({LOCAL_ADMINISTRATOR}) "
          f"password to the one you type (gate 6's Ctrl+Alt+Del change); "
          f"gate 6's domain join with a one-use tj- principal staged and "
          f"destroyed with proof on the persistent Controller (no other "
          f"principal is staged); reboot; domain sign-in as the daily "
          f"administrator with the password you type; the post-reboot probe "
          f"proves membership, the secure channel and the local "
          f"Administrators right; clean Windows shutdown")
    print(f"On success: the overlay and firmware variables are folded into "
          f"{workstation.state.name} as stage {STAGE}; only then is the "
          f"custody publication shredded")
    print(f"On failure: the overlay is removed; {workstation.state.name} and "
          f"its publication are unchanged, so the stage can be retried "
          f"without a reinstall; evidence stays under {args.run_root}")
    print(f"Prompts (--apply only, in this order, before any guest starts): "
          f"1) the {CONSOLE_ACCOUNT} console password of {binding.instance}; "
          f"2) a new Windows local-administrator password, twice (checked "
          f"here first; never stored); 3) the daily administrator's current "
          f"domain password")
    policy = binding.password_policy
    print(f"Password policy: the new local-administrator password must be "
          f"typeable and meet {policy.source} ({policy.requirement()})")
    for entry in space:
        verdict = "" if entry["free"] >= entry["needed"] else " (INSUFFICIENT)"
        print(f"Free space: {entry['path']} needs about "
              f"{_gib(entry['needed'])}, has {_gib(entry['free'])}{verdict}")
    print(" ".join(preview).replace(
        "127.0.0.1:65535", "127.0.0.1:<per-run port>"))


def _retire(workstation: WorkstationInstance, binding: DurableBinding,
            apply: bool) -> int:
    print(f"Kept workstation: {workstation.state.name}; stage {STAGE} is "
          f"folded but its custody publication is still held")
    print(f"Bound instance: {binding.instance}")
    print("On --apply: the publication is shredded; nothing boots")
    if not apply:
        print("dry run; repeat with --apply")
        return 0
    with SignalGuard(), workstation:
        marker = workstation.read_marker()
        require_workstation_binding(marker, binding)
        if join_mode(workstation, marker) != "retire":
            raise DurableWindowsJoinError("the kept workstation changed")
        workstation.retire_publication()
    print(f"Retired the custody publication of {workstation.state.name}")
    return 0


def run(args: argparse.Namespace, *,
        prompt: Callable[..., bytes] = _typed_secret) -> int:
    workstation = open_workstation(args.root, args.workstation)
    marker = workstation.read_marker()
    mode = join_mode(workstation, marker)
    binding = durable_binding(
        args.persistent_root, args.persistent_dc,
        canonical_state=args.controller_state,
        identity_path=args.directory_identity)
    require_workstation_binding(marker, binding)
    if mode == "retire":
        return _retire(workstation, binding, args.apply)
    require_join_realm(binding)
    daily_name = require_roster_agreement()
    target = persistent_target(binding)
    preview = preview_command(target, args.controller_state)
    space = space_needs(workstation, args.run_root)
    print_plan(args, workstation, marker, binding, space, preview)
    if not args.apply:
        print("dry run; repeat with --apply")
        return 0
    problems = preflight_problems(workstation, target, space)
    if problems:
        raise DurableWindowsJoinError("; ".join(problems))
    secrets: OwnerSecrets | None = None
    with SignalGuard(), workstation:
        try:
            # Re-read under the lock: another run may have folded meanwhile.
            marker = workstation.read_marker()
            if join_mode(workstation, marker) != "join":
                raise DurableWindowsJoinError("the kept workstation changed")
            require_workstation_binding(marker, binding)
            # Read-only refusals first, so a typed credential is never spent
            # on a disk that cannot be joined.
            source = inspect_workstation(workstation, marker)
            secrets = collect_owner_secrets(
                binding.instance, daily_name, prompt=prompt,
                policy=binding.password_policy)
            attempt = prepare_attempt(
                workstation, marker, binding,
                controller_state=args.controller_state,
                run_root=args.run_root, source=source)
            print(f"Attempt: {attempt}")
            workstation.record_machine_account(WINDOWS_COMPUTER_NAME)
            evidence = attempt / "evidence"
            overlay = attempt / DISK_NAME
            entry: dict | None = None
            try:
                DurableWindowsJoin(
                    workstation, binding, target=target,
                    controller_state=args.controller_state,
                    secrets=secrets).execute(attempt, marker)
                entry = workstation.fold(
                    overlay, STAGE, firmware_vars=attempt / VARS_NAME,
                    source=str(attempt))
            finally:
                discarded = _discard_overlay(overlay)
                _amend_result(
                    evidence, folded=entry is not None,
                    fold=None if entry is None else {
                        key: entry.get(key) for key in (
                            "stage", "utc", "disk_sha256", "vars_sha256")},
                    overlay_discarded=discarded)
        finally:
            if secrets is not None:
                secrets.clear()
        # Only now, with the join folded, is the one-use credential shredded.
        try:
            workstation.retire_publication()
        except (RuntimeError, OSError) as error:
            _amend_result(evidence, publication_retired=False)
            print(f"error: stage {STAGE} is folded but the custody "
                  f"publication was not retired ({error}); repeat this target "
                  f"with --apply, which then only retires it", file=sys.stderr)
            return 2
        _amend_result(evidence, publication_retired=True)
    print(f"Folded stage {STAGE} into {workstation.state.name}; ledger head "
          f"{entry['disk_sha256']}; the custody publication is retired")
    print(f"Evidence: {evidence}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Join a kept workstation's Windows to its persistent "
                    "domain (TASK-28 step 8); a dry run unless --apply")
    result.add_argument("--workstation", required=True,
                        help="the kept workstation's stable name")
    result.add_argument(
        "--root", type=Path, default=DEFAULT_ROOT,
        help="root holding kept workstations (DURABLE_WORKSTATION_ROOT)")
    result.add_argument("--persistent-dc", required=True,
                        help="the persistent instance the workstation is "
                             "bound to")
    result.add_argument("--persistent-root", type=Path,
                        default=DEFAULT_PERSISTENT_ROOT)
    result.add_argument(
        "--directory-identity", type=Path, default=None,
        help="the permanent directory identity document (ADR 0065); "
             "defaults to the private overlay's")
    result.add_argument(
        "--controller-state", type=Path, default=DEFAULT_STATE,
        help="the DISPOSABLE acceptance canonical, refused as the persistent "
             "disk and never booted here")
    result.add_argument("--run-root", type=Path, default=DEFAULT_RUNS)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(args)
    except RunInterrupted as error:
        print(f"error: {error}", file=sys.stderr)
        return error.exit_code
    except (RuntimeError, OSError, ValueError, EOFError,
            subprocess.CalledProcessError) as error:
        print(f"error: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
