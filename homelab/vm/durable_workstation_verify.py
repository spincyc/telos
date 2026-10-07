#!/usr/bin/env python3
"""Prove a kept workstation works as kept, across a Controller relaunch.

TASK-28, step 9 of ``homelab/DURABLE-WORKSTATION-FLOW.md``: the keep-verify of
a kept workstation ``W`` (``workstation_instance``) whose ledger holds every
disk-changing stage -- ``adopt``, ``arch-install``, ``arch-join`` and
``windows-join``.  It re-proves both joins the way the owner will use them,
and it is read-only toward ``W``:

* **Overlays only, under ``W``'s lock.**  Arch boots one fresh overlay of
  ``W/workstation.qcow2`` and Windows another (gate 6's attempt layout), each
  with a copy of ``W``'s firmware variables less EDK2's ``HDDP`` boot-path
  cache (``ovmf_vars``); both overlays are removed afterwards.  ``W``'s disk,
  variables and marker are hashed before and after and must be unchanged.
  Nothing is folded, no machine account is recorded, and no ledger entry is
  written: ``workstation_instance`` offers only the stage fold,
  ``record_machine_account`` and ``retire_publication``, and a verify is none
  of them, so the run's evidence directory is its only record.
* **One fabric, one persistent session.**  The bound instance's own disk is
  booted in place on a per-run switch (``PersistentControllerSession``: no
  QMP, no medium, no pause) and proved to be the bound directory (realm and
  SID) before any workstation boots.  Between the two systems it is RELAUNCHED
  -- a clean console poweroff, then a cold boot in the same session, which
  logs in again with the console password it holds in memory -- and AD, the
  realm, the SID and the clock are proved again.  That is the re-authentication
  path the owner meets after every power cycle of the lab.
* **Arch** (step 7 composed, gate 8 underneath): the overlay boots, gate 8's
  menu drive selects Arch, the domain-online gate is awaited, the daily
  administrator logs in on ttyS0 with its CURRENT password, the disk's roster
  is proved, gate 8's ``elevate_operator`` opens a root shell, ``net ads
  testjoin`` runs, and step 7's name-free check proves ``sssctl`` online,
  every directory role at its recorded uidNumber, the sealed join unit and
  the node name; the workstation then powers off from inside.
* **Windows** (step 8 composed, gate 6 underneath): gate 6's attempt is
  prepared over the second overlay with the control probe and the operator
  sign-in reference rendered for the bound realm.  Windows boots by the
  menu's five-second Windows default, gate 6's domain sign-in signs the daily
  administrator in (the Controller-side authentication diagnostic stays
  disabled and the post-submit diagnostic is not armed: it belongs to the
  join), gate 6's read-only ``Invoke-TelosIdentityProbe`` proves the
  interactive operator, membership, the secure channel and the local
  Administrators right, and Windows shuts down from inside.  No principal is
  staged: a verify writes nothing into the directory.
* **Firmware, read-only.**  ``W``'s variable store is parsed on the host: its
  ``BootOrder`` must still start with ``Linux Boot Manager`` (Windows can
  promote itself during ``windows-join``), and the Arch boot records which
  entry systemd-boot highlighted by default, which must be Windows.  A
  ``BootOrder`` regression refuses the run before any prompt: its menu drive
  could not pass.

The Controller console password and the daily administrator's current
password are typed at the controlling terminal after every refusal and before
any process starts, held in memory only, and never reach argv, the
environment, a file, the evidence or a retained transcript.  The dry run (the
default) prints the plan and starts nothing.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Mapping, Sequence

if not __package__:  # Direct execution by the Make recipe (PEP 366).
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "homelab.vm"

from .arch_durable_install_run import require_workstation_binding  # noqa: E402
from .arch_durable_join import (  # noqa: E402
    JOIN_GROWTH_BYTES, ROSTER_BINDING_FAILURE, ArchDurableJoinError,
    DurableArchJoinBoundary, MODE_CURRENT, OwnerCredentials, _copy_vars,
    _create_overlay, account_name, directory_account_record, drive_join,
    first_logon_login, machine_account, planned_accounts,
    power_off_workstation, prove_joined_identity)
from .arch_durable_join import preflight_problems as arch_preflight_problems  # noqa: E402
from .arch_durable_join import require_roster_agreement as require_arch_roster  # noqa: E402
from .arch_identity_run import (  # noqa: E402
    DEFAULT_DURATION, MAX_DURATION, MENU_RENDER_TIMEOUT,
    SUDO_ELEVATION_TIMEOUT, ArchIdentityBoundary, ArchIdentityBundle,
    ArchIdentityDrive, await_domain_online, drive_boot_menu, elevate_operator)
from .bootstrap_dc import (  # noqa: E402
    CONSOLE_ACCOUNT, DEFAULT_PERSISTENT_ROOT, DEFAULT_STATE, SOCKET_MAC,
    _typed_secret, persistent_switch_command)
from .credential_custody import (  # noqa: E402
    AGENT, AgentCredentialSource, CustodyError, credential_source,
    instance_custody)
from .durable_workstation import DurableBinding, durable_binding  # noqa: E402
from .factory_runner import (  # noqa: E402
    GATEWAY_MAC, capture_switch_evidence_cursor, gateway_command,
    wait_for_switch_port)
from .ovmf_vars import (  # noqa: E402
    EFI_GLOBAL_VARIABLE, FirmwareVariablesError, firmware_variables,
    load_option)
from .persistent_controller_session import (  # noqa: E402
    PersistentControllerSession, _probe_directory, session_command)
from .secret_scan import count_secret_occurrences, secret_needles  # noqa: E402
from .serial_automation import SerialAutomationError  # noqa: E402
from .signal_cleanup import (  # noqa: E402
    RunInterrupted, SignalGuard, terminate_children)
from .simulated_topology import MACS  # noqa: E402
from .simulation_evidence import (  # noqa: E402
    private_directory, private_file, redact, redact_and_bound)
from .simulation_overlay import PersistentControllerInstance, sha256  # noqa: E402
from .windows_durable_join import (  # noqa: E402
    LOCAL_ADMINISTRATOR, WINDOWS_COMPUTER_NAME, WINDOWS_GROWTH_BYTES,
    DurableWindowsAdapter, DurableWindowsBoundary, _no_secret_scan,
    evidence_secret_hits, require_join_realm, rotation_plan, shutdown_windows,
    typeable_problem)
from .windows_durable_join import require_roster_agreement as require_windows_roster  # noqa: E402
from .windows_durable_prepare import _image_info  # noqa: E402
from .windows_durable_prepare import prepare as prepare_attempt  # noqa: E402
from .windows_identity_orchestrator import _post_reboot_proof  # noqa: E402
from .windows_identity_prepare import DISK_NAME, VARS_NAME  # noqa: E402
from .windows_identity_progressive import NativeBoundaryRotationSession  # noqa: E402
from .windows_identity_run import WindowsIdentityRunError  # noqa: E402
from .workstation_instance import (  # noqa: E402
    DEFAULT_ROOT, FLOW_STAGES, WorkstationInstance, workstation_state)

from homelab.workstations.arch_second import (  # noqa: E402
    MENU_WINDOWS_TITLE, NVRAM_LINUX_LABEL, NVRAM_WINDOWS_LABEL,
    SAFE_HOSTNAME)


#: Not a ledger stage: a verify folds nothing (``workstation_instance``).
LABEL = "keep-verify"
#: Run directories, beside the other durable stages' under the gitignored
#: ``homelab/var``; never inside ``W``, whose ``destroy`` refuses strays.
DEFAULT_RUNS = Path("homelab/var/factory/durable-workstation-verifies")
RESULT_NAME = "result.json"
CONTROLLER_TRANSCRIPT_NAME = "controller-transcript.log"
ARCH_BUNDLE_DIR = "arch"
WINDOWS_ATTEMPTS_DIR = "windows"
FABRIC_DIR = "fabric"
#: Both phases' overlays live under the run root; nothing grows beside ``W``.
RUN_GROWTH_BYTES = JOIN_GROWTH_BYTES + WINDOWS_GROWTH_BYTES
#: The switch waits this long for every declared port: the Controller boots
#: and is proved before the Arch workstation is spawned.
SWITCH_ACCEPT_TIMEOUT = 1200.0
#: Frames stop while the Controller is relaunched; the bound is generous.
SWITCH_IDLE_TIMEOUT = 3600.0
GATEWAY_PORT_TIMEOUT = 30.0
CONTROLLER_PORT_TIMEOUT = 60.0
TESTJOIN_TIMEOUT = 120.0
#: A recorded failure message is scrubbed, then bounded to this many chars.
FAILURE_MESSAGE_LIMIT = 400
LEDGER_ENTRY_NOTE = (
    "none: workstation_instance offers no non-stage annotation, and a "
    "keep-verify is not a stage; this evidence directory is the record")

NO_DIRECTORY_WRITES = (
    "a keep-verify writes nothing into the directory: no join principal and "
    "no other principal is staged")
TESTJOIN_FAILURE = (
    "net ads testjoin failed from the kept Arch: the machine account's "
    "secret no longer authenticates against the persistent directory")
TESTJOIN_INCOMPLETE_FAILURE = (
    "the root shell never reported the net ads testjoin result")
BOOT_ORDER_FAILURE = (
    "the kept workstation's firmware BootOrder no longer starts with an "
    "active {linux!r} entry (Windows may have promoted itself during "
    "windows-join), so its systemd-boot menu would not appear and the Arch "
    "boot could not pass. Nothing was started and nothing was asked")


class KeepVerifyError(RuntimeError):
    """The keep-verify cannot proceed, or did not prove what it must."""


def _say(message: str) -> None:
    print(f"keep-verify: {message}", flush=True)


# -- the firmware variable store, read-only -----------------------------------
#: The store itself is parsed by ``ovmf_vars``, shared with every runner that
#: carries a store into a boot.
#: systemd-boot's loader interface (``LoaderEntryDefault``, ``...OneShot``).
SYSTEMD_BOOT_VENDOR = uuid.UUID("4a67b082-0a4c-41cf-b6c7-440b29bb8c4f")
#: The id systemd-boot gives the Windows Boot Manager entry it finds.
WINDOWS_LOADER_ENTRY = "auto-windows"


def _utf16_string(value: bytes) -> str:
    return value.decode("utf-16-le", "replace").split("\0", 1)[0]


def boot_order_facts(path: Path) -> dict[str, object]:
    """What *path*'s firmware will boot, read and never written.

    ``linux_first`` is the check: the first ``BootOrder`` entry is an active
    ``Linux Boot Manager``, so systemd-boot's menu appears.  The rest is
    recorded: the ordered entry descriptions (firmware labels, not instance
    data), a pending ``BootNext``, and any systemd-boot default override.
    """
    facts: dict[str, object] = {
        "parsed": False, "order": [], "linux_first": False,
        "windows_present": False, "boot_next": None,
        "loader_entry_default": None, "loader_entry_oneshot": None,
        "menu_default_intact": False,
    }
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        facts["error"] = "the firmware variables are missing"
        return facts
    try:
        variables = firmware_variables(path.read_bytes())
        raw_order = variables.get((EFI_GLOBAL_VARIABLE, "BootOrder"), b"")
        order = []
        for index in range(0, len(raw_order) - 1, 2):
            number = struct.unpack_from("<H", raw_order, index)[0]
            name = f"Boot{number:04X}"
            option = variables.get((EFI_GLOBAL_VARIABLE, name))
            if option is None:
                order.append({"entry": name, "description": None,
                              "active": False})
                continue
            active, description = load_option(option)
            order.append({"entry": name, "description": description,
                          "active": active})
    except (FirmwareVariablesError, OSError, struct.error) as error:
        facts["error"] = type(error).__name__
        return facts
    boot_next = variables.get((EFI_GLOBAL_VARIABLE, "BootNext"))
    overrides = {
        key: (None if value is None else _utf16_string(value))
        for key, value in (
            ("loader_entry_default",
             variables.get((SYSTEMD_BOOT_VENDOR, "LoaderEntryDefault"))),
            ("loader_entry_oneshot",
             variables.get((SYSTEMD_BOOT_VENDOR, "LoaderEntryOneShot"))))}
    facts.update(
        parsed=True, order=order,
        linux_first=bool(order) and order[0]["active"] is True
        and order[0]["description"] == NVRAM_LINUX_LABEL,
        windows_present=any(
            entry["active"] and entry["description"] == NVRAM_WINDOWS_LABEL
            for entry in order),
        boot_next=(None if boot_next is None or len(boot_next) < 2 else
                   f"Boot{struct.unpack_from('<H', boot_next, 0)[0]:04X}"),
        menu_default_intact=all(
            value is None or value.startswith(WINDOWS_LOADER_ENTRY)
            for value in overrides.values()),
        **overrides)
    return facts


def menu_default_entry(raw: bytes | str) -> str | None:
    """The entry systemd-boot highlighted in its first render: its default.

    The menu is drawn with the default highlighted before any key is sent,
    and gate 8's drive moves the highlight only afterwards, so the FIRST
    highlighted known title in the console's raw render is the default.
    Uses the dual-boot lane's own cell and highlight grammar.
    """
    from .dualboot_acceptance import (
        _MENU_HIGHLIGHT_ATTR, _MENU_ROW, KNOWN_MENU_ENTRIES)

    text = (raw.decode("utf-8", "replace") if isinstance(raw, bytes)
            else raw)
    for match in _MENU_ROW.finditer(text):
        title = match.group(3).strip()
        if (title in KNOWN_MENU_ENTRIES
                and _MENU_HIGHLIGHT_ATTR.search(match.group(2))):
            return title
    return None


# -- the owner's credentials -----------------------------------------------------
class VerifySecrets:
    """The two values the owner types, in memory only, never in ``repr``."""

    def __init__(self, console: bytes, daily: bytes, *,
                 extra: tuple[bytes, ...] = (),
                 users: Mapping[str, bytes] | None = None) -> None:
        self.console = console
        self.daily = daily
        #: Agent custody only (TASK-40): the stores' other values, scanned
        #: for in the evidence too; empty for the owner.
        self.extra = tuple(extra)
        #: ``--verify-users`` (owner request 2026-10-07): each standard
        #: account's current password, by contract role.
        self.users = dict(users or {})

    def __repr__(self) -> str:
        return "VerifySecrets(<withheld>)"

    def values(self) -> list[bytes]:
        own = [value for value in (self.console, self.daily) if value]
        own += [value for value in self.users.values()
                if value and value not in own]
        return own + [value for value in self.extra
                      if value and value not in own]

    def texts(self) -> tuple[str, ...]:
        return tuple(value.decode("utf-8", "replace")
                     for value in self.values())

    def daily_text(self) -> str:
        return self.daily.decode("utf-8")

    def clear(self) -> None:
        # Python cannot wipe an immutable bytes object; every reference this
        # object holds is dropped, which is the most it can do.
        self.console = b""
        self.daily = b""
        self.extra = ()
        self.users = {}


def collect_verify_secrets(
    instance: str, daily_name: str, *,
    prompt: Callable[..., bytes] = _typed_secret,
    users: Sequence[Mapping] = (),
) -> VerifySecrets:
    """Ask, in order, for the values the run needs; nothing has started.

    *users* are the standard accounts ``--verify-users`` logs in, each asked
    for by its contract role and name after the daily administrator's.
    """
    console = prompt(f"{CONSOLE_ACCOUNT} console password for persistent "
                     f"instance {instance}: ")
    daily = prompt(f"CURRENT domain password for daily_administrator "
                   f"({daily_name}): ")
    typed_users = {
        str(account["contract_role"]): prompt(
            f"CURRENT domain password for {account['contract_role']} "
            f"({account['name']}): ")
        for account in users}
    try:
        problem = typeable_problem(daily.decode("utf-8"))
    except UnicodeDecodeError:
        problem = "is not UTF-8"
    if problem is not None:
        raise KeepVerifyError(
            f"the daily administrator's password {problem}; gate 6 types it "
            f"at the Windows sign-in. Nothing was started")
    if daily == console:
        raise KeepVerifyError(
            "the daily administrator's password and the Controller console "
            "password must differ; the two you typed are identical. Nothing "
            "was started")
    if console in typed_users.values():
        raise KeepVerifyError(
            "a standard account's password equals the Controller console "
            "password. Nothing was started")
    return VerifySecrets(console, daily, users=typed_users)


def agent_verify_secrets(
    source: AgentCredentialSource, users: Sequence[Mapping] = (),
) -> VerifySecrets:
    """The values from custody (TASK-40): console, proven current daily.

    *users* (``--verify-users``) adds each standard account's proven current
    password; one staged for a change at first logon has none and is refused.
    """
    console = source.console()
    try:
        daily = source.live_current("daily_administrator")
        user_values = {
            str(account["contract_role"]): source.live_current(
                str(account["contract_role"])) for account in users}
    except CustodyError as error:
        raise KeepVerifyError(str(error)) from error
    try:
        problem = typeable_problem(daily.decode("utf-8"))
    except UnicodeDecodeError:
        problem = "is not UTF-8"
    if problem is not None:
        raise KeepVerifyError(
            f"the daily administrator's password {problem}; gate 6 types it "
            f"at the Windows sign-in. Nothing was started")
    return VerifySecrets(console, daily, extra=tuple(
        value.encode("utf-8") for value in source.scan_values()),
        users=user_values)


# -- the Arch phase -----------------------------------------------------------------
#: Every check the Arch boundary proves, by its own name; the verify records
#: each as ``arch_<name>``, except ``menu_defaults_to_windows`` (firmware).
ARCH_CHECKS = (
    "workstation_booted", "menu_rendered", "menu_defaults_to_windows",
    "entry_selected", "domain_online_observed", "login_completed",
    "roster_matches", "elevated", "testjoin_passed", "sssd_online",
    "uids_pinned", "join_once_sealed", "hostname_matches",
    "workstation_clean_poweroff", "echo_never_observed", "transcript_retained",
)


#: ``--verify-users`` (owner request 2026-10-07): every standard account
#: logs in at the getty with its own password and runs as its staged uid.
USER_LOGINS_CHECK = "standard_accounts_login"
USER_LOGIN_FAILURE = (
    "a standard account did not log in at the Arch getty with its current "
    "password, or did not run as its staged uidNumber")


def arch_check_name(key: str) -> str:
    return key if key == "menu_defaults_to_windows" else f"arch_{key}"


def standard_accounts(accounts: Sequence[Mapping]) -> list[Mapping]:
    """The roster's standard accounts: every one but the two administrators."""
    return [account for account in accounts
            if account.get("contract_role") not in (
                "daily_administrator", "domain_administrator")]


def session_uid_command(token: str) -> tuple[bytes, bytes]:
    """One user-shell command reporting ``id -u`` behind a token marker.

    The echoed command line carries ``%s`` after the marker, never a digit,
    so only the printed value can match.
    """
    marker = b"__TELOS_VERIFY_UID_" + token.encode("ascii") + b"="
    return (b"printf '\\n" + marker + b"%s\\n' \"$(id -u)\"", marker)


def prove_session_uid(console, token: str) -> int | None:
    command, marker = session_uid_command(token)
    console._send(command, "arch-verify-user-uid-sent")
    try:
        # Anchored on a real line end: a split serial read must never yield
        # the leading digits of a longer number.
        match = console._wait(
            rb"(?:^|\n)" + re.escape(marker) + rb"([0-9]+)(?=[\r\n])",
            "arch-verify-user-uid")
    except SerialAutomationError:
        return None
    return int(match.group(1))


def testjoin_command(token: str) -> tuple[bytes, bytes]:
    """One root-shell command that reports ``net ads testjoin``, name-free.

    It names nothing but a token-scoped marker; the echo of the command line
    itself carries ``%s`` after the marker, never a digit, so it cannot be
    read as the result.
    """
    marker = b"__TELOS_VERIFY_TESTJOIN_" + token.encode("ascii") + b"="
    command = (
        b"printf '\\n" + marker + b"%s\\n' \"$(net ads testjoin >/dev/null "
        b"2>&1 && echo 1 || echo 0)\"")
    return command, marker


def prove_testjoin(
    console, facts: dict, *, timeout: float = TESTJOIN_TIMEOUT,
) -> bool:
    """Run ``net ads testjoin`` from the root shell and record the verdict."""
    command, marker = testjoin_command(console.token)
    original = console.timeout
    console.timeout = min(console.timeout, timeout)
    try:
        console._send(command, "arch-verify-testjoin-sent")
        try:
            match = console._wait(
                rb"(?:^|\n)" + re.escape(marker) + rb"([01])(?=[\r\n])",
                "arch-verify-testjoin")
        except SerialAutomationError as error:
            raise KeepVerifyError(TESTJOIN_INCOMPLETE_FAILURE) from error
    finally:
        console.timeout = original
    facts["passed"] = match.group(1) == b"1"
    return facts["passed"]


class VerifyArchBoundary(DurableArchJoinBoundary):
    """Step 7's boundary without the join, on a fabric and session it borrows.

    The per-run switch and the persistent session belong to the verify, which
    keeps both across the Controller relaunch; this boundary owns only the
    workstation.  So it starts no fabric and no Controller, stages no
    principal and attaches no media, and its stop is gate 8's teardown of the
    workstation alone -- never step 7's, which would power the borrowed
    Controller off.  The fault hooks gate 8 drives stay refused (step 7).
    """

    def __init__(
        self, bundle: ArchIdentityBundle, *, binding: DurableBinding,
        target: PersistentControllerInstance, credentials: OwnerCredentials,
        accounts: Sequence[Mapping], hostname: str, fabric: "Fabric",
        canonical_state: Path = DEFAULT_STATE,
        duration: float = DEFAULT_DURATION,
        user_logins: Sequence[tuple[Mapping, bytes]] = (),
    ) -> None:
        super().__init__(
            bundle, binding=binding, target=target, credentials=credentials,
            accounts=accounts, hostname=hostname, mode=MODE_CURRENT,
            canonical_state=canonical_state, duration=duration,
            session_factory=_refuse_session)
        self.fabric = fabric
        self.user_logins = tuple(user_logins)
        self.checks = {key: False for key in ARCH_CHECKS}
        if self.user_logins:
            self.checks[USER_LOGINS_CHECK] = False
        self.facts = {"mode": LABEL, "login": {}, "testjoin": {},
                      "identity": {}, "menu_default_entry": None}

    def _start_all(self) -> None:
        # The QMP and guest-progress sockets live in a private tempdir that
        # gate 8's stop removes; the switch log is the verify's.
        self._qmp_root = Path(tempfile.mkdtemp(prefix="telos-arch-verify-"))
        self._qmp_root.chmod(0o700)
        self._port = self.fabric.port
        self._deadline = time.monotonic() + self.duration
        self._watchdog = threading.Timer(self.duration, self._expire)
        self._watchdog.daemon = True
        self._watchdog.start()
        # Proven by the verify before this boundary was built.
        self._controller_online = True
        self._start_workstation()

    def _retain_switch_log(self) -> None:
        # One switch log serves both phases; the verify keeps it in place.
        return None

    def _start_workstation(self) -> None:
        """Boot the overlay and drive systemd-boot's menu to Arch."""
        _process, console = self._boot_workstation()
        self.checks["workstation_booted"] = True
        _say("Arch overlay booted; driving the systemd-boot menu")
        drive_boot_menu(
            console, self._boot_facts,
            reset=lambda: self._workstation_qmp.execute("system_reset"),
            menu_timeout=MENU_RENDER_TIMEOUT,
            on_stall=self._retain_boot_stall_evidence)
        self.checks["menu_rendered"] = bool(self._boot_facts.get("menu_seen"))
        default = menu_default_entry(
            bytes(self._workstation_tee)
            or bytes(getattr(console, "transcript", b"")))
        self.facts["menu_default_entry"] = default
        self.checks["menu_defaults_to_windows"] = (
            default == MENU_WINDOWS_TITLE)
        self.checks["entry_selected"] = bool(
            self._boot_facts.get("handoff_seen"))

    def finish(self) -> None:
        """Login, roster, root shell, testjoin, identity, clean poweroff."""
        console = self._workstation_console
        process = self._processes.get("workstation")
        if console is None or process is None:
            raise KeepVerifyError("the Arch console is not open")
        await_domain_online(console, self._boot_facts)
        self.checks["domain_online_observed"] = True
        if self.user_logins:
            self._prove_user_logins(console)
        login: dict[str, object] = {}
        self.facts["login"] = login
        live = first_logon_login(
            console, login,
            username=account_name(
                self.accounts, "daily_administrator").encode("ascii"),
            password=self._credentials.daily, new_password=None)
        self.checks["login_completed"] = True
        console.password = live
        observed = ArchIdentityDrive(console).confirm_roster()
        self.checks["roster_matches"] = (
            observed == self.binding.roster_fingerprint)
        if not self.checks["roster_matches"]:
            raise KeepVerifyError(ROSTER_BINDING_FAILURE)
        elevate_operator(
            console, self._boot_facts, timeout=SUDO_ELEVATION_TIMEOUT)
        self.checks["elevated"] = True
        testjoin: dict[str, object] = {}
        self.facts["testjoin"] = testjoin
        prove_testjoin(console, testjoin)
        self.checks["testjoin_passed"] = testjoin.get("passed") is True
        identity: dict[str, object] = {}
        self.facts["identity"] = identity
        failure: BaseException | None = None
        try:
            prove_joined_identity(
                console, identity, domain=self.binding.dns_domain,
                accounts=self.accounts, hostname=self.hostname)
        except ArchDurableJoinError as error:
            failure = error
        finally:
            for key in ("sssd_online", "uids_pinned", "join_once_sealed",
                        "hostname_matches"):
                self.checks[key] = identity.get(key) is True
        _say("Arch proofs recorded; powering the workstation off")
        poweroff: dict[str, object] = {}
        power_off_workstation(console, process, poweroff)
        self.facts["workstation_poweroff"] = poweroff
        self.checks["workstation_clean_poweroff"] = (
            poweroff.get("workstation_clean_poweroff") is True)
        if failure is not None:
            raise failure
        if not self.checks["testjoin_passed"]:
            raise KeepVerifyError(TESTJOIN_FAILURE)

    def _prove_user_logins(self, console) -> None:
        """Each standard account logs in at the getty, runs as its uid, exits.

        The daily administrator's own proofs follow at the next getty, so
        everything after this is exactly the verify without the option.
        Facts name contract roles only, never an account.
        """
        results: list[dict[str, object]] = []
        self.facts["user_logins"] = results
        for index, (account, password) in enumerate(self.user_logins):
            record: dict[str, object] = {
                "contract_role": account.get("contract_role"),
                "login_completed": False, "uid_matches": False}
            results.append(record)
            login: dict[str, object] = {}
            first_logon_login(
                console, login,
                username=str(account["name"]).encode("ascii"),
                password=password, new_password=None)
            record["login_completed"] = login.get("login_completed") is True
            record["echo_observed"] = login.get("echo_observed") is True
            uid = prove_session_uid(console, f"{console.token}u{index}")
            record["uid_matches"] = (
                uid is not None and uid == int(account["uidNumber"]))
            console._send(b"exit", "arch-verify-user-logout")
            if not (record["login_completed"] and record["uid_matches"]):
                break
        self.checks[USER_LOGINS_CHECK] = (
            len(results) == len(self.user_logins)
            and all(record["login_completed"] is True
                    and record["uid_matches"] is True for record in results))
        if not self.checks[USER_LOGINS_CHECK]:
            raise KeepVerifyError(USER_LOGIN_FAILURE)

    def stop(self) -> list[str]:
        """Gate 8's teardown of the workstation; the Controller is not ours."""
        self._persistent_console = None
        failures = ArchIdentityBoundary.stop(self)
        self.checks["transcript_retained"] = (
            self.facts.get("workstation_transcript") == "retained")
        return failures


def _refuse_session(*_args, **_kwargs):
    raise KeepVerifyError(
        "the keep-verify boundaries borrow the verify's persistent session; "
        "they never create one")


# -- the Windows phase ------------------------------------------------------------
class VerifyWindowsBoundary(DurableWindowsBoundary):
    """Step 8's boundary on the verify's fabric and running Controller.

    ``start_switch`` validates the attempt exactly as gate 6 does and then
    attaches to the verify's switch instead of spawning one; ``runtime`` is
    that switch's directory, so gate 6's readiness waits read its log.
    ``start_controller`` only requires the verify's session to be logged in:
    the Controller is never a child of this boundary, and step 8's
    ``stop_controller`` has no session of its own to stop.  Every fault
    setter still raises (step 8).
    """

    def __init__(
        self, attempt: Path, controller_state: Path, *,
        target: PersistentControllerInstance, fabric: "Fabric",
        controller_live: Callable[[], bool],
    ) -> None:
        super().__init__(
            attempt, controller_state, target=target, console_password=b"",
            session_factory=_refuse_session)
        self.fabric = fabric
        self.runtime = Path(fabric.runtime)
        self._controller_live = controller_live

    def start_switch(self) -> None:
        self._validate()
        port = getattr(self.fabric, "port", None)
        generation = getattr(self.fabric, "gateway_generation", None)
        if port is None or generation is None:
            raise WindowsIdentityRunError(
                "the verify's per-run switch is not running")
        self.port = int(port)
        self.gateway_switch_generation = int(generation)

    def start_controller(self) -> None:
        if self.port is None:
            raise WindowsIdentityRunError("switch must start before Controller")
        if not self._controller_live():
            raise WindowsIdentityRunError(
                "the persistent Controller is not logged in on the verify's "
                "switch")
        self.persistent_facts.update(
            started=True, controller_attached=True, shared_session=True)


class VerifyWindowsAdapter(DurableWindowsAdapter):
    """Step 8's adapter; a verify stages nothing, not even a join principal."""

    def stage_join_principal(self, credential: str):
        raise KeepVerifyError(NO_DIRECTORY_WRITES)

    def destroy_join_principal(self):
        raise KeepVerifyError(NO_DIRECTORY_WRITES)


def _session_live(session) -> bool:
    try:
        return session.console is not None
    except Exception:  # noqa: BLE001 - a session that is not logged in
        return False


# -- the fabric both phases share ----------------------------------------------------
class Fabric:
    """The per-run switch and gateway, told the instance's own MAC.

    It declares the Controller's port and one workstation port, which Arch
    and then Windows hold in turn (both boot as the simulated client MAC).
    The gateway stays connected throughout, so the switch outlives the
    Controller's relaunch and the gap between the two workstation boots.
    """

    def __init__(
        self, runtime: Path, *, idle_timeout: float = SWITCH_IDLE_TIMEOUT,
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
        wait_port: Callable[..., int] = wait_for_switch_port,
    ) -> None:
        self.runtime = Path(runtime)
        self.switch_log = self.runtime / "switch.jsonl"
        self.idle_timeout = idle_timeout
        self._popen = popen
        self._wait_port = wait_port
        self.port: int | None = None
        self.gateway_generation: int | None = None
        self.processes: list = []

    def start(self) -> None:
        private_directory(self.runtime)
        descriptor = os.open(
            self.runtime / "fabric.log",
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        # Each child keeps its own copy of the log descriptor.
        with os.fdopen(descriptor, "wb") as log, socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(3)
            self.port = int(listener.getsockname()[1])
            self.processes.append(self._popen(
                persistent_switch_command(
                    listener.fileno(), self.switch_log,
                    controller_mac=SOCKET_MAC, workstation_mac=MACS["client"],
                    accept_timeout=SWITCH_ACCEPT_TIMEOUT,
                    idle_timeout=self.idle_timeout, identity_mode=True),
                stdin=subprocess.DEVNULL, stdout=log,
                stderr=subprocess.STDOUT, pass_fds=(listener.fileno(),)))
            listener.close()
            self.processes.append(self._popen(
                gateway_command(
                    self.port, controller_mac=SOCKET_MAC, identity_mode=True),
                stdin=subprocess.DEVNULL, stdout=log,
                stderr=subprocess.STDOUT))
        self.gateway_generation = self._wait_port(
            self.switch_log, "gateway", GATEWAY_MAC,
            timeout=GATEWAY_PORT_TIMEOUT)

    def cursor(self):
        return capture_switch_evidence_cursor(self.switch_log)

    def wait_controller(self, cursor) -> None:
        """The Controller's NEXT connection: after a relaunch, generation 2."""
        self._wait_port(self.switch_log, "controller", SOCKET_MAC,
                        timeout=CONTROLLER_PORT_TIMEOUT, after=cursor)

    def stop(self) -> list[str]:
        return terminate_children(
            self.processes, terminate_timeout=10.0, kill_timeout=2.0)


# -- the kept workstation, read-only ------------------------------------------------
def open_workstation(root: Path, name: str) -> WorkstationInstance:
    return WorkstationInstance(workstation_state(root, name), name=name)


def require_every_stage_folded(workstation: WorkstationInstance) -> dict:
    """``W``'s validated marker, when all four stages are folded."""
    marker = workstation.read_marker()
    name = marker["workstation"]
    # The one refusal every stage runner raises, naming the reconcile target.
    refusal = workstation.pending_fold_refusal(marker)
    if refusal is not None:
        raise KeepVerifyError(refusal)
    stages = [entry["stage"] for entry in marker["ledger"]]
    if stages != list(FLOW_STAGES):
        raise KeepVerifyError(
            f"kept workstation {name} has folded {', '.join(stages)}; a "
            f"keep-verify needs every stage folded ({', '.join(FLOW_STAGES)}),"
            f" and its next stage is {workstation.next_stage(marker)!r}")
    return marker


def require_machine_accounts(marker: dict, hostname: str) -> None:
    """The two computer accounts the joins recorded, one per system."""
    recorded = marker["machine_accounts"]
    for account, stage in ((machine_account(hostname), "arch-join"),
                           (WINDOWS_COMPUTER_NAME, "windows-join")):
        if account not in recorded:
            raise KeepVerifyError(
                f"kept workstation {marker['workstation']} records no machine "
                f"account {account}, which stage {stage} records before it "
                f"joins; give the host name stage arch-join joined")


def inspect_kept_workstation(
    workstation: WorkstationInstance, marker: dict, *,
    image_info: Callable[[Path], dict] | None = None,
) -> dict:
    """``W``'s disk and variables proven at the ledger head, hashed once.

    Shaped like ``windows_durable_prepare.inspect_workstation``'s answer so
    gate 6's attempt can be prepared from it, but it does not require the
    custody publication: ``windows-join`` retires it after its fold.
    """
    image_info = image_info or _image_info
    head = marker["ledger"][-1]
    for path, label in ((workstation.disk, "disk"),
                        (workstation.vars, "firmware variables")):
        if path.is_symlink() or not path.is_file():
            raise KeepVerifyError(
                f"the kept workstation's {label} must be a regular file: "
                f"{path}")
    info = image_info(workstation.disk)
    if (info.get("format") != "qcow2" or info.get("dirty-flag")
            or info.get("backing-filename")
            or info.get("full-backing-filename")):
        raise KeepVerifyError(
            "the kept workstation's disk is not a clean standalone qcow2")
    disk_sha256 = sha256(workstation.disk)
    vars_sha256 = sha256(workstation.vars)
    if disk_sha256 != head["disk_sha256"]:
        raise KeepVerifyError(
            "the kept workstation's disk no longer hashes to its ledger head; "
            "it changed outside a fold")
    if vars_sha256 != head.get("vars_sha256"):
        raise KeepVerifyError(
            "the kept workstation's firmware variables no longer match its "
            "ledger head; they changed outside a fold")
    return {
        "workstation": str(workstation.state),
        "disk": {"path": str(workstation.disk.resolve()),
                 "sha256": disk_sha256,
                 "virtual_size": info.get("virtual-size"), "dirty": False},
        "firmware": {"path": str(workstation.vars.resolve()),
                     "sha256": vars_sha256},
        "ledger_head": {"stage": head["stage"],
                        "disk_sha256": head["disk_sha256"],
                        "vars_sha256": head.get("vars_sha256")},
    }


def _marker_sha256(workstation: WorkstationInstance) -> str:
    return sha256(workstation.marker)


def _existing_ancestor(path: Path) -> Path:
    for candidate in (Path(path).absolute(), *Path(path).absolute().parents):
        if candidate.is_dir():
            return candidate
    return Path("/")


def space_needs(run_root: Path) -> list[dict]:
    """Both overlays grow under *run_root*; nothing is copied beside ``W``."""
    directory = _existing_ancestor(run_root)
    return [{"path": directory, "needed": RUN_GROWTH_BYTES,
             "free": shutil.disk_usage(directory).free}]


def _gib(value: int) -> str:
    return f"{value / 1024 ** 3:.1f} GiB"


def preflight_problems(
    binding: DurableBinding, space: list[dict],
) -> list[str]:
    """Every refusal an --apply run can know before the owner types."""
    problems = arch_preflight_problems(binding)
    if not shutil.which("xorriso"):
        problems.insert(0, "xorriso is not installed")
    for entry in space:
        if entry["free"] < entry["needed"]:
            problems.append(f"not enough free space: {entry['path']} needs "
                            f"about {_gib(entry['needed'])}")
    return problems


# -- one verify ---------------------------------------------------------------------
CONTROLLER_CHECKS = (
    "fabric_started", "controller_logged_in", "live_argv_audited",
    "directory_bound", "controller_relaunched", "ad_live_after_relaunch",
    "directory_bound_after_relaunch",
    "clock_within_kerberos_skew_after_relaunch", "controller_clean_poweroffs",
    "controller_lock_released", "controller_transcript_secret_free",
)
WINDOWS_CHECKS = (
    "windows_attempt_prepared", "windows_booted", "windows_signed_in",
    "windows_interactive_operator", "windows_secure_channel",
    "windows_domain_matches", "windows_operator_local_administrator",
    "windows_clean_shutdown", "windows_teardown_complete",
)
KEPT_CHECKS = (
    "boot_order_linux_first", "workstation_unchanged", "overlays_discarded",
    "evidence_secret_free",
)
#: Every secret-free boolean a passing verify proves.
REQUIRED_CHECKS = (
    CONTROLLER_CHECKS + tuple(arch_check_name(key) for key in ARCH_CHECKS)
    + WINDOWS_CHECKS + KEPT_CHECKS)


def _run_id() -> str:
    return (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            + f"-{os.getpid()}-{secrets.token_hex(4)}")


class KeepVerify:
    """One keep-verify of one kept workstation into one run directory.

    The phases are ordered and isolated: a failure in the Arch phase is
    recorded and the Controller is still relaunched and Windows still
    verified, because every piece of evidence one live run can give is worth
    the owner's typing; a Controller that cannot be proved to be the bound
    directory stops everything before any workstation boots.
    """

    def __init__(
        self, workstation: WorkstationInstance, binding: DurableBinding, *,
        accounts: Sequence[Mapping], daily_name: str, hostname: str,
        secrets: VerifySecrets, run_dir: Path, controller_state: Path,
        duration: float = DEFAULT_DURATION,
        session_factory: Callable[..., object] = PersistentControllerSession,
        fabric_factory: Callable[..., Fabric] = Fabric,
        arch_boundary_factory: Callable[..., VerifyArchBoundary]
        = VerifyArchBoundary,
        windows_boundary_factory: Callable[..., VerifyWindowsBoundary]
        = VerifyWindowsBoundary,
        windows_adapter_factory: Callable[..., VerifyWindowsAdapter]
        = VerifyWindowsAdapter,
    ) -> None:
        self.workstation = workstation
        self.binding = binding
        self.target = PersistentControllerInstance(
            binding.state, instance=binding.instance)
        self.accounts = [dict(account) for account in accounts]
        self.daily_name = daily_name
        self.hostname = hostname
        self.secrets = secrets
        self.run_dir = Path(run_dir)
        self.evidence = self.run_dir / "evidence"
        self.controller_state = Path(controller_state)
        self.duration = duration
        self._session_factory = session_factory
        self._fabric_factory = fabric_factory
        self._arch_boundary_factory = arch_boundary_factory
        self._windows_boundary_factory = windows_boundary_factory
        self._windows_adapter_factory = windows_adapter_factory
        self.arch_boundary: VerifyArchBoundary | None = None
        self.windows_boundary: VerifyWindowsBoundary | None = None
        self.required = REQUIRED_CHECKS + (
            (arch_check_name(USER_LOGINS_CHECK),)
            if getattr(secrets, "users", None) else ())
        self.checks: dict[str, bool] = {key: False for key in self.required}
        self.facts: dict[str, object] = {}
        self.failures: list[dict[str, object]] = []

    # -- recording ---------------------------------------------------------
    def _private_values(self) -> list[str]:
        binding = self.binding
        values = [binding.dns_domain, binding.kerberos_realm,
                  binding.netbios_name, binding.domain_sid,
                  binding.controller_fqdn, binding.permanent_dc_fqdn]
        values += [str(account.get("name", "")) for account in self.accounts]
        return [value for value in values if value]

    def _scrub(self, text: str) -> str:
        for value in sorted(self.secrets.texts(), key=len, reverse=True):
            text = text.replace(value, "[REDACTED]")
        for value in sorted(self._private_values(), key=len, reverse=True):
            text = re.sub(re.escape(value), "[instance]", text,
                          flags=re.IGNORECASE)
        text = redact(text.encode("utf-8", "replace")).decode(
            "utf-8", "replace")
        return text[:FAILURE_MESSAGE_LIMIT]

    def _failed(self, step: str, error: BaseException) -> None:
        self.failures.append({
            "step": step, "type": type(error).__name__,
            "check": getattr(error, "check", None),
            "message": self._scrub(str(error)),
        })
        _say(f"{step} failed: {type(error).__name__}")

    # -- preparation -------------------------------------------------------
    def _prepare_arch(self) -> ArchIdentityBundle:
        directory = self.run_dir / ARCH_BUNDLE_DIR
        directory.mkdir(mode=0o700)
        bundle = ArchIdentityBundle(directory, self.controller_state)
        bundle.realm = self.binding.kerberos_realm
        _create_overlay(self.workstation.disk, bundle.disk)
        _copy_vars(self.workstation.vars, bundle.firmware)
        return bundle

    def _prepare_windows(self, marker: dict, source: dict) -> Path:
        attempt = prepare_attempt(
            self.workstation, marker, self.binding,
            controller_state=self.controller_state,
            run_root=self.run_dir / WINDOWS_ATTEMPTS_DIR, source=source)
        # Gate 6's validation never reads this record; a reader of the
        # attempt must not mistake it for a windows-join attempt.
        authorization_path = attempt / "authorization.json"
        authorization = json.loads(
            authorization_path.read_text(encoding="utf-8"))
        authorization["durable"]["stage"] = LABEL
        private_file(authorization_path, (
            json.dumps(authorization, indent=2, sort_keys=True)
            + "\n").encode("utf-8"))
        return attempt

    # -- the Controller ----------------------------------------------------
    def _prove_directory(self, console, key: str) -> bool:
        """Realm and SID are hard refusals; the rest is measured."""
        record: dict[str, object] = {}
        self.facts[key] = record
        _probe_directory(console, self.binding, record)
        return (record.get("realm_matches") is True
                and record.get("domain_sid") in ("match", "repair-needed"))

    # -- the phases ----------------------------------------------------------
    def _arch_phase(self, bundle: ArchIdentityBundle, fabric: Fabric) -> None:
        boundary = self._arch_boundary_factory(
            bundle, binding=self.binding, target=self.target,
            credentials=OwnerCredentials(
                self.secrets.console, self.secrets.daily, None, b"",
                extra=tuple(getattr(self.secrets, "extra", ()))),
            accounts=self.accounts, hostname=self.hostname, fabric=fabric,
            canonical_state=self.controller_state, duration=self.duration,
            **({"user_logins": self._user_logins()}
               if getattr(self.secrets, "users", None) else {}))
        self.arch_boundary = boundary
        try:
            drive_join(boundary)
        except (KeyboardInterrupt, SystemExit, RunInterrupted):
            raise
        except Exception as error:  # noqa: BLE001 - recorded; Windows next
            self._failed("arch", error)
        finally:
            keys = ARCH_CHECKS + ((USER_LOGINS_CHECK,)
                                  if getattr(self.secrets, "users", None)
                                  else ())
            for key in keys:
                self.checks[arch_check_name(key)] = (
                    boundary.checks.get(key) is True)
            self.facts["arch"] = boundary.facts

    def _user_logins(self) -> list[tuple[Mapping, bytes]]:
        users = self.secrets.users
        return [(account, users[str(account["contract_role"])])
                for account in standard_accounts(self.accounts)
                if str(account["contract_role"]) in users]

    def _windows_phase(self, attempt: Path, fabric: Fabric, session) -> None:
        facts: dict[str, object] = {
            "attempt": attempt.name,
            "controller_auth_diagnostic": "disabled",
            "post_submit_diagnostic": "not armed; it belongs to the join",
            "principal_staging": "none",
        }
        self.facts["windows"] = facts
        try:
            self._windows_attempt(attempt, fabric, session, facts)
        except (KeyboardInterrupt, SystemExit, RunInterrupted):
            raise
        except Exception as error:  # noqa: BLE001 - recorded
            self._failed("windows", error)

    def _windows_attempt(
        self, attempt: Path, fabric: Fabric, session, facts: dict,
    ) -> None:
        checks = self.checks
        authorization = json.loads(
            (attempt / "authorization.json").read_text(encoding="utf-8"))
        plan, command = rotation_plan(attempt, authorization)
        boundary = self._windows_boundary_factory(
            attempt, self.controller_state, target=self.target,
            fabric=fabric, controller_live=lambda: _session_live(session))
        self.windows_boundary = boundary
        adapter = self._windows_adapter_factory(
            boundary, attempt, realm=self.binding.dns_domain,
            local_principal=LOCAL_ADMINISTRATOR, scan_secrets=_no_secret_scan,
            rotation_plan=plan, command_plan=command,
            post_submit_diagnostic=None)
        principal = f"{self.daily_name}@{self.binding.dns_domain.upper()}"
        outcome = "failed"
        try:
            # One use, exactly as gate 6's CLI claims its attempts.
            boundary.claim_attempt()
            with NativeBoundaryRotationSession(boundary):
                checks["windows_booted"] = True
                _say("Windows booted by the menu's default; signing the "
                     "daily administrator in")
                adapter.reauthenticate_domain_operator(
                    principal, self.secrets.daily_text(), uuid.uuid4().hex)
                checks["windows_signed_in"] = True
                probe_error: Exception | None = None
                try:
                    proof = _post_reboot_proof(adapter.callbacks(), principal)
                    checks["windows_interactive_operator"] = True
                    checks["windows_secure_channel"] = (
                        proof.get("domain_joined") is True)
                    checks["windows_domain_matches"] = (
                        str(proof.get("domain", "")).casefold()
                        == self.binding.dns_domain.casefold())
                    checks["windows_operator_local_administrator"] = (
                        proof.get("operator_local_administrator") is True)
                except (KeyboardInterrupt, SystemExit, RunInterrupted):
                    raise
                except Exception as error:  # noqa: BLE001 - after shutdown
                    probe_error = error
                _say("Windows proofs recorded; shutting Windows down")
                facts["shutdown_method"] = shutdown_windows(adapter, boundary)
                checks["windows_clean_shutdown"] = True
                if probe_error is not None:
                    raise probe_error
            outcome = "succeeded"
        except (KeyboardInterrupt, SystemExit, RunInterrupted):
            outcome = "interrupted"
            raise
        finally:
            boundary.release_prestart_ownership()
            teardown = boundary.audit_teardown()
            facts["teardown"] = teardown
            checks["windows_teardown_complete"] = all(teardown.values())
            if boundary.attempt_claim is not None:
                try:
                    boundary.terminalize_attempt(
                        outcome=outcome, teardown=teardown)
                except (OSError, RuntimeError, ValueError) as error:
                    facts["terminal_receipt_error"] = type(error).__name__
            facts["controller"] = dict(boundary.persistent_facts)
        missing = [key for key in (
            "windows_secure_channel", "windows_domain_matches",
            "windows_operator_local_administrator") if not checks[key]]
        if missing:
            raise KeepVerifyError(
                "gate 6's identity probe did not prove: " + ", ".join(missing))

    # -- the run -----------------------------------------------------------
    def run(self, marker: dict, source: dict, firmware: dict) -> dict:
        """Everything, in order; returns the result it also retains."""
        private_directory(self.evidence)
        head = marker["ledger"][-1]
        before = {"disk": source["disk"]["sha256"],
                  "vars": source["firmware"]["sha256"],
                  "marker": _marker_sha256(self.workstation)}
        self.facts["firmware"] = firmware
        self.checks["boot_order_linux_first"] = firmware.get(
            "linux_first") is True
        started = datetime.now(UTC).isoformat()
        fabric: Fabric | None = None
        session = None
        bundle: ArchIdentityBundle | None = None
        attempt: Path | None = None
        interrupted: BaseException | None = None
        step = "prepare"
        try:
            bundle = self._prepare_arch()
            attempt = self._prepare_windows(marker, source)
            self.checks["windows_attempt_prepared"] = True
            step = "fabric"
            fabric = self._fabric_factory(self.run_dir / FABRIC_DIR)
            fabric.start()
            self.checks["fabric_started"] = True
            step = "controller"
            session = self._session_factory(
                self.target, port=fabric.port, password=self.secrets.console,
                canonical_state=self.controller_state)
            _say(f"booting persistent instance {self.binding.instance} in "
                 f"place")
            cursor = fabric.cursor()
            console = session.start(
                attached=lambda: fabric.wait_controller(cursor))
            self.checks["controller_logged_in"] = True
            self.checks["live_argv_audited"] = bool(
                session.facts.get("live_argv_audited"))
            self.checks["directory_bound"] = self._prove_directory(
                console, "directory")
            step = "arch"
            self._arch_phase(bundle, fabric)
            step = "relaunch"
            _say("relaunching the persistent Controller: clean console "
                 "poweroff, then a cold boot in the same session")
            cursor = fabric.cursor()
            console = session.relaunch(
                attached=lambda: fabric.wait_controller(cursor))
            facts = session.facts
            self.checks["controller_relaunched"] = (
                int(facts.get("launches") or 0) == 2
                and int(facts.get("logins") or 0) == 2
                and int(facts.get("clean_poweroffs") or 0) >= 1
                and not facts.get("terminated_fallback"))
            # ``start`` returns only after samba answered on the new boot.
            self.checks["ad_live_after_relaunch"] = True
            self.checks["directory_bound_after_relaunch"] = (
                self._prove_directory(console, "directory_after_relaunch"))
            self.checks["clock_within_kerberos_skew_after_relaunch"] = (
                self.facts["directory_after_relaunch"].get(
                    "clock_within_kerberos_skew") is True)
            step = "windows"
            self._windows_phase(attempt, fabric, session)
            step = "poweroff"
            session.stop()
        except (KeyboardInterrupt, SystemExit, RunInterrupted) as error:
            interrupted = error
            self._failed(step, error)
        except Exception as error:  # noqa: BLE001 - recorded, then judged
            self._failed(step, error)
        finally:
            self._teardown(session, fabric, bundle, attempt)
        result = self._finish(head, before, started)
        if interrupted is not None:
            raise interrupted
        return result

    def _teardown(self, session, fabric, bundle, attempt) -> None:
        problems: list[str] = []
        if session is not None:
            try:
                session.stop()
            except BaseException as error:  # noqa: BLE001 - recorded
                problems.append(
                    f"persistent controller stop: {type(error).__name__}")
            facts = dict(getattr(session, "facts", {}))
            self.facts["controller"] = {key: facts.get(key) for key in (
                "launches", "logins", "live_argv_audited", "clean_poweroffs",
                "terminated_fallback", "lock_released")}
            self.checks["controller_clean_poweroffs"] = (
                int(facts.get("clean_poweroffs") or 0) >= 2
                and not facts.get("terminated_fallback"))
            self.checks["controller_lock_released"] = bool(
                facts.get("lock_released"))
            # Taken while the session still holds its credential, so the
            # redaction can prove the transcript free of it.
            transcript = session.redacted_transcript(self.secrets.values())
            if transcript is not None:
                retained, sizes = redact_and_bound(transcript)
                private_file(self.evidence / CONTROLLER_TRANSCRIPT_NAME,
                             retained)
                self.facts["controller_transcript"] = sizes
                self.checks["controller_transcript_secret_free"] = True
            else:
                self.facts["controller_transcript"] = "withheld"
            with contextlib.suppress(Exception):
                session.close()
        if fabric is not None:
            problems += fabric.stop()
        discarded = True
        for overlay in ((bundle.disk if bundle is not None else None),
                        (attempt / DISK_NAME if attempt is not None else None)):
            if overlay is None:
                continue
            try:
                overlay.unlink(missing_ok=True)
            except OSError:
                discarded = False
        self.checks["overlays_discarded"] = (
            discarded and bundle is not None and attempt is not None)
        if attempt is not None:
            # Informational: whether a Windows boot rewrote the copy it used.
            self.facts["firmware_after_windows_boot"] = boot_order_facts(
                attempt / VARS_NAME)
        if problems:
            self.facts["teardown_problems"] = problems

    def _finish(self, head: dict, before: dict, started: str) -> dict:
        after = {"disk": sha256(self.workstation.disk),
                 "vars": sha256(self.workstation.vars),
                 "marker": _marker_sha256(self.workstation)}
        self.facts["workstation_hashes"] = {"before": before, "after": after}
        self.checks["workstation_unchanged"] = (
            before == after and after["disk"] == head["disk_sha256"]
            and after["vars"] == head.get("vars_sha256"))
        hits = evidence_secret_hits(self.run_dir, self.secrets.texts())
        self.checks["evidence_secret_free"] = not hits
        if hits:
            self.facts["evidence_secret_hits"] = hits
        passed = (not self.failures
                  and all(self.checks[key] is True for key in self.required))
        result = {
            "schema": 1, "kind": "durable-workstation-verify",
            "label": LABEL,
            "workstation": self.workstation.state.name,
            "bound_instance": self.binding.instance,
            "hostname": self.hostname,
            "ledger_head": {"stage": head["stage"],
                            "disk_sha256": head["disk_sha256"],
                            "vars_sha256": head.get("vars_sha256")},
            "folded": False,
            "ledger_entry": LEDGER_ENTRY_NOTE,
            "started_utc": started,
            "finished_utc": datetime.now(UTC).isoformat(),
            "checks": dict(self.checks),
            "facts": self.facts,
            "failures": self.failures,
            "verdict": "pass" if passed else "fail",
        }
        payload = (json.dumps(result, indent=2, sort_keys=True, default=str)
                   + "\n").encode("utf-8")
        values = self.secrets.values()
        if values and count_secret_occurrences(
                [payload], secret_needles(values)):
            # Nothing above should carry one; if a message did, it goes.
            for failure in self.failures:
                failure["message"] = "[withheld]"
            result.update(verdict="fail", facts={"withheld": True})
            result["checks"]["evidence_secret_free"] = False
            payload = (json.dumps(result, indent=2, sort_keys=True,
                                  default=str) + "\n").encode("utf-8")
        private_file(self.evidence / RESULT_NAME, payload)
        return result


# -- the plan ------------------------------------------------------------------------
def print_plan(
    args: argparse.Namespace, workstation: WorkstationInstance, marker: dict,
    binding: DurableBinding, accounts: Sequence[Mapping], firmware: dict,
    space: list[dict], preview: list[str], *, agent: bool = False,
) -> None:
    name = workstation.state.name
    stages = ", ".join(entry["stage"] for entry in marker["ledger"])
    print("Boundary: loopback-only switch; no host or UniFi changes")
    print(f"Kept workstation: {name} at {workstation.state}; stages done: "
          f"{stages}; {LABEL} folds nothing")
    print(f"Bound instance: {binding.instance}. The workstation's marker, the "
          f"instance's realm, domain SID and staged roster fingerprint are "
          f"compared, never printed")
    print(f"Controller: persistent instance {binding.instance}, its own disk "
          f"booted IN PLACE under its lock on the per-run switch (its own MAC "
          f"{SOCKET_MAC}; no QMP, no medium, no pause, no fault); relaunched "
          f"once between the two systems by a clean console poweroff and a "
          f"cold boot in the same session, which logs in again with the "
          f"console password it holds in memory; stopped by a clean console "
          f"poweroff")
    print(f"Disks: two fresh overlays backed by {workstation.disk}, one for "
          f"Arch and one for gate 6's Windows attempt, each booted with a copy "
          f"of the workstation's firmware variables; both are removed "
          f"afterwards")
    print(f"Arch hostname: {args.hostname}; machine accounts "
          f"{machine_account(args.hostname)} and {WINDOWS_COMPUTER_NAME} are "
          f"recorded in the marker")
    print("Steps: prove the directory's realm and SID; boot the Arch overlay "
          "and drive the systemd-boot menu to Arch, recording the entry it "
          "highlighted by default; wait for the domain-online gate; log in "
          "on ttyS0 as the daily administrator with its CURRENT password; "
          "prove the disk's roster; elevate with sudo; run net ads testjoin; "
          "check sssctl online, every directory role at its pinned uid, the "
          "sealed join unit and the node name; power Arch off; power the "
          "Controller off over its console and boot it again; prove AD live, "
          "the realm, the SID and the clock again; boot the Windows overlay "
          "by the menu's five-second Windows default; sign the daily "
          "administrator in through gate 6's domain sign-in (its "
          "Controller-side diagnostic disabled); run gate 6's read-only "
          "identity probe (interactive operator, membership, secure channel, "
          "local Administrators right); shut Windows down from inside; power "
          "the Controller off. No principal is staged")
    print("Directory roles checked (uidNumbers from the durable account "
          "record; names are compared on the guest, never printed): "
          + ", ".join(f"{account['contract_role']} uid "
                      f"{account['uidNumber']}" for account in accounts))
    order = ", ".join(str(entry.get("description")) for entry in
                      firmware.get("order", [])) or "none"
    print(f"Firmware (read-only, {workstation.vars}): BootOrder {order}; "
          f"{NVRAM_LINUX_LABEL} first: "
          + ("yes" if firmware.get("linux_first") else "NO (REGRESSION)")
          + f"; {NVRAM_WINDOWS_LABEL} present: "
          + ("yes" if firmware.get("windows_present") else "no")
          + "; systemd-boot default override: "
          + (str(firmware.get("loader_entry_default") or "none")))
    if agent:
        print(f"Credentials: agent custody (throwaway instance "
              f"{binding.instance}); nothing is asked at a terminal. The "
              f"{CONSOLE_ACCOUNT} console password and the daily "
              "administrator's proven current password are read from the "
              "instance's custody store, and every stored value is scanned "
              "for in the evidence")
    else:
        print("Prompts, in order, all at this terminal before any process "
              "starts; none is ever written to a file, argv, the environment, "
              "the evidence or a transcript:")
        print(f"  1. the {CONSOLE_ACCOUNT} console password of persistent "
              f"instance {binding.instance}")
        print("  2. the daily administrator's CURRENT domain password (the "
              "one stage arch-join's first logon set)")
    print(f"Read-only toward {name}: its disk, firmware variables and marker "
          f"are hashed before and after and must be unchanged, and its lock "
          f"is held throughout. No ledger entry is recorded "
          f"({LEDGER_ENTRY_NOTE.split(': ', 1)[1]}); evidence goes under "
          f"{Path(args.run_root) / name}/run-<id>/")
    for entry in space:
        verdict = "" if entry["free"] >= entry["needed"] else " (INSUFFICIENT)"
        print(f"Free space: {entry['path']} needs about "
              f"{_gib(entry['needed'])}, has {_gib(entry['free'])}{verdict}")
    print(f"Arch phase bound: {args.duration:g} seconds")
    print(" ".join(preview).replace(
        "127.0.0.1:65535", "127.0.0.1:<per-run port>"))


# -- the command line ------------------------------------------------------------------
def run(
    args: argparse.Namespace, *,
    prompt: Callable[..., bytes] = _typed_secret,
    verify_factory: Callable[..., KeepVerify] = KeepVerify,
) -> int:
    if not 60 <= args.duration <= MAX_DURATION:
        raise KeepVerifyError(
            f"duration must be between 60 and {MAX_DURATION:g} seconds")
    if not SAFE_HOSTNAME.fullmatch(args.hostname):
        raise KeepVerifyError(
            "the Arch hostname must be lowercase letters, digits and hyphens, "
            "starting with a letter")
    workstation = open_workstation(args.root, args.workstation)
    marker = require_every_stage_folded(workstation)
    require_machine_accounts(marker, args.hostname)
    binding = durable_binding(
        args.persistent_root, args.persistent_dc,
        canonical_state=args.controller_state,
        identity_path=args.directory_identity)
    discovery = require_workstation_binding(marker, binding)
    if discovery:
        # TASK-42: an SRV-first Arch side reaches a DC under another name.
        print(f"Directory discovery: {discovery}")
    require_join_realm(binding)
    accounts = planned_accounts(directory_account_record(binding))
    require_arch_roster(binding, accounts)
    daily_name = require_windows_roster()
    if daily_name != account_name(accounts, "daily_administrator"):
        raise KeepVerifyError(
            "gate 6's daily administrator is not the durable roster's; names "
            "are not printed")
    target = PersistentControllerInstance(
        binding.state, instance=binding.instance)
    preview = session_command(
        target, 65535, canonical_state=args.controller_state)
    firmware = boot_order_facts(workstation.vars)
    space = space_needs(args.run_root)
    agent = instance_custody(target) == AGENT
    print_plan(args, workstation, marker, binding, accounts, firmware, space,
               preview, agent=agent)
    if not args.apply:
        print("dry run; repeat with --apply")
        return 0
    problems = preflight_problems(binding, space)
    if problems:
        raise KeepVerifyError("; ".join(problems))
    with SignalGuard(), workstation:
        # Re-read under the lock: every refusal precedes the first prompt.
        marker = require_every_stage_folded(workstation)
        require_machine_accounts(marker, args.hostname)
        require_workstation_binding(marker, binding)
        firmware = boot_order_facts(workstation.vars)
        if not firmware.get("linux_first"):
            raise KeepVerifyError(
                BOOT_ORDER_FAILURE.format(linux=NVRAM_LINUX_LABEL))
        source = inspect_kept_workstation(workstation, marker)
        credentials = credential_source(
            target, prompt=prompt,
            workstation=(workstation.state, workstation.state.name))
        users = (standard_accounts(accounts)
                 if getattr(args, "verify_users", False) else [])
        if credentials.agent:
            verify_secrets = agent_verify_secrets(credentials, users)
        else:
            verify_secrets = collect_verify_secrets(
                binding.instance, daily_name, prompt=credentials.ask,
                users=users)
        try:
            root = Path(args.run_root).absolute()
            private_directory(root / workstation.state.name)
            run_dir = root / workstation.state.name / f"run-{_run_id()}"
            run_dir.mkdir(mode=0o700)
            _say(f"evidence: {run_dir / 'evidence'}")
            verify = verify_factory(
                workstation, binding, accounts=accounts,
                daily_name=daily_name, hostname=args.hostname,
                secrets=verify_secrets, run_dir=run_dir,
                controller_state=args.controller_state,
                duration=args.duration)
            result = verify.run(marker, source, firmware)
        finally:
            verify_secrets.clear()
    for failure in result["failures"]:
        print(f"error: {failure['step']}: {failure['type']}: "
              f"{failure['message']}", file=sys.stderr)
    unproven = sorted(key for key, value in result["checks"].items()
                      if value is not True)
    if unproven:
        print("unproven: " + ", ".join(unproven), file=sys.stderr)
    print(f"{workstation.state.name}: {LABEL} "
          f"{'PASS' if result['verdict'] == 'pass' else 'FAIL'}; "
          f"evidence {run_dir / 'evidence'}")
    return 0 if result["verdict"] == "pass" else 2


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Prove a kept workstation works as kept: both joins "
                    "across a persistent Controller relaunch (TASK-28 step "
                    "9); read-only toward it, a dry run unless --apply")
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
        "--hostname", required=True,
        help="the Arch host name stage arch-join joined")
    result.add_argument(
        "--controller-state", type=Path, default=DEFAULT_STATE,
        help="the DISPOSABLE acceptance canonical, refused as the persistent "
             "disk and never booted here")
    result.add_argument("--run-root", type=Path, default=DEFAULT_RUNS)
    result.add_argument(
        "--duration", type=float, default=DEFAULT_DURATION,
        help="the Arch phase's wall-clock bound in seconds")
    result.add_argument(
        "--verify-users", action="store_true",
        help="also log every standard account in at the Arch getty with its "
             "own current password and prove its uidNumber (owner request "
             "2026-10-07); asks for each one's password under owner custody")
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
