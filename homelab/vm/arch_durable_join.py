#!/usr/bin/env python3
"""Join a kept workstation's Arch to its persistent directory, once.

TASK-28, step 7 of ``homelab/DURABLE-WORKSTATION-FLOW.md``: stage
``arch-join`` of a kept workstation ``W`` (``workstation_instance``) whose
ledger already holds ``arch-install`` (step 6).  That install deferred its
join and left a sealed boot-time unit (``telos-arch-join-once``) that joins
the permanent domain from one-use media and then seals itself.  This runner
supplies the media and everything around it:

* **The persistent Controller, in place, on the per-run switch.**  A
  ``PersistentControllerSession`` boots the bound instance's own disk under
  its lock, logs in over its console, proves samba live, and is proved to be
  the bound directory (realm and SID, ``persistent_controller_session``'s own
  directory probe) before anything is written into it.  It has no pause and
  no signal method; this boundary refuses every fault hook gate 8 drives, so
  none can reach a durable directory.  It stops by a clean console poweroff.
* **One ``tj-`` join principal**, staged and destroyed with proof by the same
  one-use lifecycle the probe and gates 5-8 use, over the already
  authenticated Controller console.  It is staged before the workstation
  boots, the join media are built from it, attached after the Linux handoff
  (never during firmware, whose boot manager would record the device in the
  variables this stage folds), destroyed by exact inode when the guest has
  consumed them, and the principal is destroyed only after the guest printed
  ``TELOS ARCH JOIN VERIFIED`` -- which a durable render prints only after
  ``net ads testjoin`` passed and the seal was written and synced.
* **The first logon.**  The daily administrator logs in on ttyS0 and, when
  the durable account record says its password must change at first logon,
  answers pam_sss's expired-password exchange with the temporary password and
  the new one the owner typed.  The exchange is prompt-driven, bounded, and
  proves after every write that the console never echoed a typed value.
  ``--first-logon-done`` (``FIRST_LOGON_DONE=1``) makes a retry ask for the
  CURRENT password instead, for a run whose change landed before it failed.
* **Break-glass custody** (owner decision 2026-09-30): the Arch
  ``local-rescue`` password is one the owner types, distinct from every other
  credential, set once from the elevated shell and never stored.
* **Proof, then the fold.**  From the root shell: SSSD reports its domain
  online, every directory role resolves at the uidNumber the durable account
  record pins (names travel only through an echo-suppressed ``read`` and are
  compared on the guest, never printed), the join unit is sealed, and the
  host name is the one recorded.  The workstation and the Controller both
  power off cleanly, and only then is the overlay folded into ``W`` as
  ``arch-join`` with the firmware variables it booted with.  On any failure
  ``W``'s disk, variables and ledger are unchanged; its marker keeps the
  machine account recorded BEFORE the join, so ``destroy`` lists it.

Gate 8 (``arch_identity_run``) is composed, never edited:
``DurableArchJoinBoundary`` subclasses ``ArchIdentityBoundary`` and overrides
its fabric, Controller, workstation start and stop; the boot command, menu
drive, domain-online gate, roster proof, ``sudo -S`` elevation and the
``passwd`` exchange are gate 8's functions called as they are.

Every owner credential is typed at the controlling terminal before any
process starts, held in memory, written only to a guest console that asked
for it, and never reaches argv, the environment, a file, the evidence or a
retained transcript.  The dry run (the default) prints the plan and starts
nothing.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Mapping, Sequence

if not __package__:  # Direct execution by the Make recipe (PEP 366).
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "homelab.vm"

from .arch_durable_install_run import (  # noqa: E402
    require_workstation_binding)
from .arch_identity_run import (  # noqa: E402
    BUNDLE_DISK, BUNDLE_FIRMWARE, BUNDLE_QEMU_COMMAND, CONSOLE_READY_TIMEOUT,
    DEFAULT_DURATION, GETTY_NEVER_APPEARED_FAILURE, JOIN_FAILURE,
    JOIN_PRINCIPAL_NOT_DESTROYED_FAILURE, JOIN_TIMEOUT, MAX_DURATION,
    MENU_RENDER_TIMEOUT, RESCUE_PASSWORD_TIMEOUT, SUDO_ELEVATION_TIMEOUT,
    WORKSTATION_FIRMWARE_LOG_FILENAME, ArchIdentityBoundary,
    ArchIdentityBundle, ArchIdentityDrive, ArchIdentityError,
    TimestampedEvents, _file_sha256, _utc_now, await_domain_online,
    drive_boot_menu,
    elevate_operator, operator_principal, rescue_principal,
    rescue_prompt_pattern, resolved_roster, roster_fingerprint,
    set_rescue_password, workstation_boot_command)
from .arch_install_prepare import require_netbios_hostname  # noqa: E402
from .arch_install_run import JOIN_ISO_NAME, run_join_install  # noqa: E402
from .bootstrap_dc import (  # noqa: E402
    CONSOLE_ACCOUNT, DEFAULT_PERSISTENT_ROOT, DEFAULT_STATE, SOCKET_MAC,
    _persistent_running, _typed_secret, ovmf_pair, persistent_switch_command)
from .controller_image import (  # noqa: E402
    ControllerImageError, assert_installed)
from .durable_workstation import DurableBinding, durable_binding  # noqa: E402
from .factory_runner import (  # noqa: E402
    GATEWAY_MAC, gateway_command, wait_for_switch_port)
from .persistent_controller_session import (  # noqa: E402
    TRANSCRIPT_LIMIT, PersistentControllerSession, _join_material,
    _probe_directory)
from .secret_scan import count_secret_occurrences, secret_needles  # noqa: E402
from .serial_automation import (  # noqa: E402
    SerialAutomation, SerialAutomationError)
from .signal_cleanup import RunInterrupted, SignalGuard  # noqa: E402
from .simulated_topology import MACS  # noqa: E402
from .simulation_evidence import (  # noqa: E402
    private_directory, private_file, redact, redact_and_bound)
from .simulation_overlay import (  # noqa: E402
    PersistentControllerInstance, sha256)
from .workstation_instance import (  # noqa: E402
    DEFAULT_ROOT, WorkstationInstance, workstation_state)

from homelab.workstations.arch_second import (  # noqa: E402
    JOIN_MEDIA_CONSUMED_MARKER, JOIN_ONCE_SEAL_PATH, JOIN_ONCE_UNIT_PATH,
    JOIN_VERIFIED_MARKER, SAFE_HOSTNAME)


#: The ledger stage this runner folds (``workstation_instance.FLOW_STAGES``).
STAGE = "arch-join"
#: Run directories, beside step 6's under the gitignored ``homelab/var``.
DEFAULT_RUNS = Path("homelab/var/factory/durable-arch-joins")
RESULT_NAME = "result.json"
CONTROLLER_TRANSCRIPT_NAME = "controller-transcript.log"
#: A conservative bound on what one join and first logon add to the disk
#: (a machine keytab, SSSD caches, one home directory, journals).
JOIN_GROWTH_BYTES = 2 * 1024 ** 3
#: The switch waits this long for all three ports: the persistent Controller
#: boots and is probed before the workstation is spawned.
SWITCH_ACCEPT_TIMEOUT = 1200.0
SWITCH_PORT_TIMEOUT = 60.0
#: Per wait inside the first-logon exchange: a Kerberos round trip, then the
#: kpasswd change against the persistent Controller.
FIRST_LOGON_TIMEOUT = 120.0
#: pam_sss asks for the new password twice.  A third ask is a refusal.
NEW_PASSWORD_WRITES = 2
#: Per wait of the root-shell checks; the SSSD online wait inside is 15 x 2s.
CHECK_TIMEOUT = 120.0
CHECK_ONLINE_TRIES = 15
POWEROFF_TIMEOUT = 180.0
POWEROFF_EXIT_TIMEOUT = 60.0

MODE_FIRST_LOGON = "first-logon"
MODE_CURRENT = "current"

#: Every check a passing run proves; ``password_changed`` joins them in
#: first-logon mode.  All are secret-free booleans.
REQUIRED_CHECKS = (
    "fabric_started", "controller_logged_in", "live_argv_audited",
    "directory_bound", "join_principal_staged", "join_media_built",
    "join_media_attached", "join_media_consumed", "join_media_destroyed",
    "join_verified", "join_principal_destroyed", "domain_online_observed",
    "login_completed", "echo_never_observed", "roster_matches", "elevated",
    "rescue_password_set", "sssd_online", "uids_pinned", "join_once_sealed",
    "hostname_matches", "workstation_clean_poweroff",
    "controller_clean_poweroff", "controller_lock_released",
    "transcripts_secret_free",
)

NO_FAULTS_FAILURE = (
    "a durable join never takes the persistent Controller offline: it has no "
    "pause, suspend or signal method, and its disk is a durable directory")
ECHO_OBSERVED_FAILURE = (
    "a typed credential appeared on the workstation console after it was "
    "written, so the reader was echoing; nothing further was written, and "
    "the retained transcript is scrubbed of it")
LOGIN_PROMPT_MISSING_FAILURE = (
    "the ttyS0 login never asked for the daily administrator's password, so "
    "no credential was written")
TEMPORARY_REFUSED_FAILURE = (
    "the ttyS0 login refused the daily administrator's TEMPORARY password "
    "before any change was asked for; nothing changed in the directory")
CURRENT_REFUSED_FAILURE = (
    "pam_sss asked for the current password a second time: it refused the "
    "temporary password during the change; nothing changed in the directory")
CHANGE_REFUSED_FAILURE = (
    "the password stack took the new password and did not log in: the change "
    "was refused (the directory's policy, its password history, or a "
    "mismatch). Whether it landed is unproven; try FIRST_LOGON_DONE=1 with "
    "the NEW password first, then without it")
CHANGE_FAILED_FAILURE = (
    "pam_sss reported that the password change failed")
CHANGE_NOT_REQUESTED_FAILURE = (
    "the daily administrator logged in with the temporary password and the "
    "directory never asked for a change, so the new password you typed was "
    "NOT set. The account is not marked to change at first logon; repeat "
    "with FIRST_LOGON_DONE=1 and type the password that logged in as the "
    "current one")
CHANGE_STILL_PENDING_FAILURE = (
    "the directory asks the daily administrator to change its password at "
    "first logon, but this run asked for its CURRENT password (FIRST_LOGON_DONE"
    "=1, or an account record staged without a first-logon change); nothing "
    "further was written. If FIRST_LOGON_DONE=1 was given, repeat without "
    "FIRST_LOGON_DONE and type the temporary password")
LOGIN_REFUSED_FAILURE = (
    "the ttyS0 login refused the daily administrator's current password")
EXCHANGE_STALLED_FAILURE = (
    "the ttyS0 login went quiet in the middle of the first-logon exchange")
CHECK_ECHO_FAILURE = (
    "the root shell never confirmed echo was off before the directory names "
    "were sent, so none was sent")
CHECK_INCOMPLETE_FAILURE = (
    "the root-shell identity checks did not report every field")
SEALED_FAILURE = (
    "the join unit is not sealed: the seal file or the unit's "
    "ConditionPathExists guard is missing, so the next boot would wait for "
    "join media again")
DOMAIN_OFFLINE_FAILURE = (
    "sssctl never reported the domain online from the joined workstation")
UID_MISMATCH_FAILURE = (
    "a directory role does not resolve at the uidNumber the durable account "
    "record pins")
HOSTNAME_MISMATCH_FAILURE = (
    "the workstation's host name is not the one this run recorded")
ROSTER_BINDING_FAILURE = (
    "the disk reports a roster fingerprint other than the one the persistent "
    "instance staged")


class ArchDurableJoinError(RuntimeError):
    """The durable Arch join cannot proceed, or did not do what it must."""


class _ConsoleTee:
    """The workstation console as ``SerialAutomation`` reads it, also kept.

    Not ``persistent_controller_session._TeeReader``: that one reads with
    ``read``, which on the persistent session's unbuffered pipe returns what
    is there, but on gate 8's default-buffered workstation pipe blocks until
    the whole request arrives -- a short prompt would never be read.  This
    one reads exactly as ``SerialAutomation`` would without it (``read1``
    when the stream has it), and keeps a bounded tail.
    """

    def __init__(self, raw, sink: bytearray, *,
                 limit: int = TRANSCRIPT_LIMIT) -> None:
        self._raw = raw
        self._sink = sink
        self._limit = limit

    def fileno(self) -> int:
        return self._raw.fileno()

    def read1(self, size: int = -1) -> bytes:
        read = getattr(self._raw, "read1", None) or self._raw.read
        chunk = read(size) or b""
        self._sink.extend(chunk)
        if len(self._sink) > self._limit:
            del self._sink[:len(self._sink) - self._limit]
        return chunk

    read = read1


def _say(message: str) -> None:
    print(f"arch-join: {message}", flush=True)


# -- the owner's credentials ------------------------------------------------
@dataclass(repr=False)
class OwnerCredentials:
    """Every value the owner typed, in memory only.

    ``daily`` is the daily administrator's TEMPORARY password in first-logon
    mode and its CURRENT one otherwise; ``new_daily`` is ``None`` in current
    mode.  ``repr`` names no value.
    """

    console: bytes
    daily: bytes
    new_daily: bytes | None
    rescue: bytes

    def __repr__(self) -> str:
        return "OwnerCredentials(<withheld>)"

    def values(self) -> list[bytes]:
        return [value for value in (
            self.console, self.daily, self.new_daily, self.rescue) if value]

    def clear(self) -> None:
        # Python cannot wipe an immutable bytes object; every reference this
        # object holds is dropped, which is the most it can do.
        self.console = self.daily = self.rescue = b""
        self.new_daily = None


def owner_credentials(
    mode: str, *, daily_name: str, rescue_name: str, instance: str,
    prompt: Callable[..., bytes] | None = None,
) -> OwnerCredentials:
    """Ask for every credential, in order, then judge them all.

    All of it happens before any process starts: a value the directory's
    default policy would refuse, or one typed twice, is refused here rather
    than after a boot.  The Controller password and the TEMPORARY/current
    password are not judged: they already exist and are whatever they are.
    """
    ask = prompt or _typed_secret
    console = ask(f"{CONSOLE_ACCOUNT} console password for persistent "
                  f"instance {instance}: ")
    if mode == MODE_FIRST_LOGON:
        daily = ask(f"TEMPORARY password for daily_administrator "
                    f"({daily_name}): ")
        new_daily = ask(
            f"NEW password for daily_administrator ({daily_name}): ",
            confirm="retype the NEW password: ")
    else:
        daily = ask(f"CURRENT password for daily_administrator "
                    f"({daily_name}): ")
        new_daily = None
    rescue = ask(
        f"NEW break-glass password for the Arch {rescue_name} account: ",
        confirm="retype the break-glass password: ")
    credentials = OwnerCredentials(console, daily, new_daily, rescue)
    try:
        _judge_credentials(credentials, daily_name=daily_name,
                           rescue_name=rescue_name)
    except BaseException:
        credentials.clear()
        raise
    return credentials


def _judge_credentials(
    credentials: OwnerCredentials, *, daily_name: str, rescue_name: str,
) -> None:
    principals = _controller_principals()
    judged = [("the new daily_administrator password", credentials.new_daily,
               daily_name),
              ("the break-glass password", credentials.rescue, rescue_name)]
    for label, value, account in judged:
        if value is None:
            continue
        problem = principals.directory_password_problem(
            value.decode("utf-8"), account)
        if problem is not None:
            raise ArchDurableJoinError(
                f"{label} {problem}; the directory's default policy would "
                f"refuse it. Nothing was booted")
    values = credentials.values()
    if len(set(values)) != len(values):
        raise ArchDurableJoinError(
            "every credential must be distinct: the Controller console "
            "password, the daily administrator's passwords and the "
            "break-glass password; two you typed are identical. Nothing was "
            "booted")


def _controller_principals():
    """``controller_principals``, deferred so importing this module reads no roster."""
    from . import controller_principals
    return controller_principals


# -- the directory's accounts -------------------------------------------------
def directory_account_record(binding: DurableBinding) -> dict:
    """The persistent instance's durable account record (names none)."""
    target = PersistentControllerInstance(
        binding.state, instance=binding.instance)
    record = target.directory_accounts()
    if record is None:
        raise ArchDurableJoinError(
            f"{binding.instance} records no staged durable account roster")
    return record


def planned_accounts(record: Mapping) -> list[dict]:
    """``[{contract_role, name, uidNumber}]``, the record's pins with names.

    The names come from the owner's private roster through the single
    derivation both durable lanes use (``directory_account_plan``); each
    record entry must be planned under the same contract role at the same
    uidNumber, or the directory and the roster describe different accounts.
    The expected number is the RECORD's: it is what the directory holds.
    Messages name contract roles only.
    """
    principals = _controller_principals()
    try:
        roster = principals.durable_directory_roster()
        plan = principals.directory_account_plan(
            list(principals.DIRECTORY_ROLES), roster=roster)
    except (principals.IdentityRosterError, principals.DirectoryPlanError,
            OSError, ValueError) as error:
        raise ArchDurableJoinError(str(error)) from error
    planned = {entry["contract_role"]: entry for entry in plan}
    recorded = {
        str(account["contract_role"]): account
        for account in record.get("accounts", [])}
    if set(planned) != set(recorded):
        raise ArchDurableJoinError(
            "the durable account record and the private roster plan "
            "different contract roles: recorded "
            + ", ".join(sorted(recorded)) + "; planned "
            + ", ".join(sorted(planned)))
    accounts = []
    for entry in plan:
        role = entry["contract_role"]
        pinned = recorded[role].get("uidNumber")
        if isinstance(pinned, bool) or not isinstance(pinned, int):
            raise ArchDurableJoinError(
                f"the durable account record pins no uidNumber for {role}")
        if int(entry["uidNumber"]) != pinned:
            raise ArchDurableJoinError(
                f"the private roster now plans {role} at uidNumber "
                f"{entry['uidNumber']}, but the directory recorded {pinned}")
        accounts.append({
            "contract_role": role, "name": str(entry["name"]),
            "uidNumber": pinned})
    return accounts


def account_name(accounts: Sequence[Mapping], role: str) -> str:
    for account in accounts:
        if account["contract_role"] == role:
            return str(account["name"])
    raise ArchDurableJoinError(f"no directory account plays {role}")


def require_roster_agreement(
    binding: DurableBinding, accounts: Sequence[Mapping],
) -> None:
    """Gate 8's roster and the durable one must be the same roster.

    Gate 8's functions (the roster proof, the break-glass ``passwd``) read the
    host's default roster; the directory's accounts come from the durable
    one.  Compared, never printed.
    """
    if roster_fingerprint() != binding.roster_fingerprint:
        raise ArchDurableJoinError(
            f"the roster this host resolves is not the one persistent "
            f"instance {binding.instance} staged; values are not printed")
    if operator_principal() != account_name(accounts, "daily_administrator"):
        raise ArchDurableJoinError(
            "the host roster's daily administrator is not the durable "
            "roster's; names are not printed")


def machine_account(hostname: str) -> str:
    """The computer account ``net ads join`` creates for *hostname*."""
    return hostname.upper() + "$"


# -- the first logon ------------------------------------------------------------
LOGIN_PROMPT = rb"(?:^|\n)[\w.-]+ login:"
PASSWORD_PROMPT = rb"(?:^|\n)Password:"


def first_logon_outcome_pattern() -> bytes:
    """Every step of the ttyS0 login after its password was written.

    pam_sss's expired-password exchange is ``Password expired. Change your
    password now.``, then ``Current Password:``, ``New Password:`` and
    ``Reenter new Password:``; gate 8's ``rescue_prompt_pattern`` already
    matches the last two in either module's wording, line-anchored, and is
    reused.  ``expired`` is informational, ``failed`` is a diagnostic from a
    fixed vocabulary (never a value), and ``incorrect``, ``getty`` and
    ``shell`` are verdicts.  ``shell`` anchors on a real prompt line, as gate
    8's login does, and ``getty`` only on a prompt still waiting at the end
    of its line: util-linux prints ``Last login: <when>`` on the way to the
    shell, which a bare ``<word> login:`` would read as a refusal.
    """
    return (
        rb"(?:^|\n)(?P<current>(?i:current[ \t]+password:)[ \t]*)"
        rb"|" + rescue_prompt_pattern()
        + rb"|(?P<expired>(?i:password[ \t]+expired|password[ \t]+has[ \t]+"
        rb"expired|required[ \t]+to[ \t]+change[ \t]+your[ \t]+password))"
        rb"|(?P<failed>(?i:password[ \t]+change[ \t]+failed"
        rb"|authentication[ \t]+token[ \t]+manipulation[ \t]+error"
        rb"|password[ \t]+change[ \t]+not[ \t]+possible"
        rb"|passwords[ \t]+do[ \t]+not[ \t]+match"
        rb"|have[ \t]+exhausted[ \t]+maximum))"
        rb"|(?:^|\n)(?P<incorrect>Login incorrect)"
        rb"|(?:^|\n)(?P<getty>(?!Last )[\w.-]+ login:[ \t]*$)"
        rb"|(?:^|\n)(?P<shell>[^\n]*\$[ \t]*$)"
    )


def _slug(value: bytes) -> str:
    return re.sub(r"[^a-z]+", "-", value.decode("ascii", "replace").lower()
                  ).strip("-")[:48]


def echoed(console, typed: Sequence[bytes]) -> bool:
    """Whether any typed value is on the console, raw or Base64-wrapped."""
    values = [value for value in typed if value]
    seen = bytes(getattr(console, "transcript", b"") or b"")
    if not values or not seen:
        return False
    return count_secret_occurrences([seen], secret_needles(values)) > 0


def first_logon_login(
    console, facts: dict, *, username: bytes, password: bytes,
    new_password: bytes | None, timeout: float = FIRST_LOGON_TIMEOUT,
) -> bytes:
    """Log the daily administrator in on ttyS0, changing its password if asked.

    Prompt-driven and fail-closed, gate 8's discipline: nothing is written
    that a reader did not just ask for, every wait is bounded, and each
    distinguishable stop names its own layer.  After every step the console
    is scanned for the typed values: PAM's password prompts read with echo
    off, and a value on the console means a reader that was not, so the
    exchange stops before it writes again.

    *new_password* ``None`` is current mode: the password is expected to log
    straight in, and an expired-password ask stops the run without writing.
    Returns the password that is now live for the account.
    """
    typed = [value for value in (password, new_password) if value]
    facts.update({
        "first_logon_mode": (
            MODE_FIRST_LOGON if new_password is not None else MODE_CURRENT),
        "getty_seen": False, "login_password_sent": False,
        "expired_notice_seen": False, "current_prompt_seen": False,
        "new_prompt_seen": False, "confirm_prompt_seen": False,
        "current_password_writes": 0, "new_password_writes": 0,
        "password_change_failure": None, "password_changed": False,
        "password_change_landed": False, "echo_observed": False,
        "login_completed": False,
    })
    outcome_pattern = first_logon_outcome_pattern()
    original = console.timeout
    try:
        try:
            console._wait(LOGIN_PROMPT, "arch-getty-observed")
        except SerialAutomationError as error:
            raise ArchIdentityError(
                GETTY_NEVER_APPEARED_FAILURE, check="arch-joined") from error
        facts["getty_seen"] = True
        console.timeout = min(console.timeout, timeout)
        console._send(username, "arch-login-username-sent")
        try:
            console._wait(PASSWORD_PROMPT, "arch-login-password-prompt")
        except SerialAutomationError as error:
            raise ArchDurableJoinError(
                LOGIN_PROMPT_MISSING_FAILURE) from error
        console._send(password, "arch-login-password-sent")
        facts["login_password_sent"] = True
        current_writes = new_writes = 0
        while True:
            try:
                outcome = console._wait(
                    outcome_pattern, "arch-first-logon-outcome")
            except SerialAutomationError as error:
                if new_writes:
                    facts["password_change_landed"] = None
                raise ArchDurableJoinError(
                    EXCHANGE_STALLED_FAILURE) from error
            if echoed(console, typed):
                facts["echo_observed"] = True
                if new_writes:
                    facts["password_change_landed"] = None
                raise ArchDurableJoinError(ECHO_OBSERVED_FAILURE)
            if outcome.group("expired") is not None:
                facts["expired_notice_seen"] = True
                console.events.append("arch-first-logon-expired-notice")
                if new_password is None:
                    raise ArchDurableJoinError(CHANGE_STILL_PENDING_FAILURE)
                continue
            if outcome.group("current") is not None:
                facts["current_prompt_seen"] = True
                if new_password is None:
                    raise ArchDurableJoinError(CHANGE_STILL_PENDING_FAILURE)
                if current_writes:
                    raise ArchDurableJoinError(CURRENT_REFUSED_FAILURE)
                console._send(password, "arch-first-logon-current-sent")
                current_writes += 1
                facts["current_password_writes"] = current_writes
                continue
            if (outcome.group("new") is not None
                    or outcome.group("retype") is not None):
                if new_password is None:
                    raise ArchDurableJoinError(CHANGE_STILL_PENDING_FAILURE)
                key = ("new_prompt_seen" if outcome.group("new") is not None
                       else "confirm_prompt_seen")
                facts[key] = True
                if new_writes >= NEW_PASSWORD_WRITES:
                    facts["password_change_landed"] = None
                    raise ArchDurableJoinError(CHANGE_REFUSED_FAILURE)
                console._send(new_password, "arch-first-logon-new-sent")
                new_writes += 1
                facts["new_password_writes"] = new_writes
                continue
            if outcome.group("failed") is not None:
                category = _slug(outcome.group("failed"))
                facts["password_change_failure"] = category
                raise ArchDurableJoinError(
                    f"{CHANGE_FAILED_FAILURE} ({category}); nothing further "
                    f"was written")
            if (outcome.group("incorrect") is not None
                    or outcome.group("getty") is not None):
                if new_writes:
                    facts["password_change_landed"] = None
                    raise ArchDurableJoinError(CHANGE_REFUSED_FAILURE)
                raise ArchDurableJoinError(
                    TEMPORARY_REFUSED_FAILURE if new_password is not None
                    else LOGIN_REFUSED_FAILURE)
            # A shell prompt: the login completed.
            if new_password is not None and not new_writes:
                raise ArchDurableJoinError(CHANGE_NOT_REQUESTED_FAILURE)
            facts["login_completed"] = True
            if new_password is not None:
                facts["password_changed"] = True
                facts["password_change_landed"] = True
                return new_password
            return password
    finally:
        console.timeout = original


# -- the root-shell proofs -------------------------------------------------------
_SAFE_WORD = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,252})")


def identity_check_command(token: str) -> tuple[bytes, dict[str, bytes]]:
    """The one root-shell command that proves the join, name-free.

    The command itself carries no name: it turns echo off, proves that with
    a marker, and ``read``s one line -- the domain, then each directory
    account's name -- which canonical, echo-off input never puts on the
    console (a command typed at a readline prompt would be).  It then prints
    only token-scoped values: the seal, the SSSD online state, the node name
    and, per account INDEX, the uid ``id`` resolves.
    """
    tok = token.encode("ascii")
    markers = {
        name: b"__TELOS_ARCH_JOIN_" + name.upper().encode("ascii") + b"_"
        + tok + b"="
        for name in ("sealed", "online", "host", "uid", "done")}
    ready = b"__TELOS_ARCH_JOIN_CHECK_READY_" + tok + b"__"
    markers["ready"] = ready
    seal = shlex.quote(JOIN_ONCE_SEAL_PATH)
    guard = shlex.quote(f"ConditionPathExists=!{JOIN_ONCE_SEAL_PATH}")
    unit = shlex.quote(JOIN_ONCE_UNIT_PATH)

    def emit(marker: bytes, value: str) -> str:
        return f"printf '\\n{marker.decode('ascii')}%s\\n' {value}"

    script = "; ".join((
        f"stty -echo && printf '\\n{ready.decode('ascii')}\\n' && "
        "IFS= read -r __telos_ids",
        "stty echo",
        "set -- $__telos_ids",
        "__telos_domain=$1",
        "shift",
        emit(markers["sealed"],
             f"\"$(test -f {seal} && grep -qxF {guard} {unit} "
             "&& echo 1 || echo 0)\""),
        "__telos_online=0",
        f"for __telos_t in $(seq 1 {CHECK_ONLINE_TRIES}); do if sssctl "
        "domain-status \"$__telos_domain\" 2>/dev/null | grep -qi "
        "'Online status: Online'; then __telos_online=1; break; fi; "
        "sleep 2; done",
        emit(markers["online"], "\"$__telos_online\""),
        emit(markers["host"], "\"$(uname -n)\""),
        "__telos_i=0",
        "for __telos_n in \"$@\"; do printf "
        f"'\\n{markers['uid'].decode('ascii')}%s=%s\\n' \"$__telos_i\" "
        "\"$(id -u -- \"$__telos_n\" 2>/dev/null || echo none)\"; "
        "__telos_i=$((__telos_i + 1)); done",
        "unset __telos_ids __telos_domain __telos_n __telos_i __telos_t "
        "__telos_online",
        "set --",
        emit(markers["done"], "0"),
    ))
    return script.encode("ascii"), markers


def prove_joined_identity(
    console, facts: dict, *, domain: str, accounts: Sequence[Mapping],
    hostname: str, timeout: float = CHECK_TIMEOUT,
) -> None:
    """From the root shell: sealed, online, pinned UIDs, the right host.

    Every result is recorded before any verdict is raised, so one run shows
    every fault; the first failing fact then stops the run by name.
    """
    words = [domain] + [str(account["name"]) for account in accounts]
    if not all(_SAFE_WORD.fullmatch(word) for word in words):
        raise ArchDurableJoinError(
            "a domain or account name cannot be sent as one shell word")
    command, markers = identity_check_command(console.token)
    original = console.timeout
    console.timeout = min(console.timeout, timeout)
    uids: dict[str, dict] = {}
    facts["identity_checks"] = uids
    try:
        console._send(command, "arch-join-checks-sent")
        try:
            console._wait(
                rb"(?:^|\n)" + re.escape(markers["ready"]) + rb"\s*(?:\n|$)",
                "arch-join-checks-echo-off")
        except SerialAutomationError as error:
            raise ArchDurableJoinError(CHECK_ECHO_FAILURE) from error
        facts["checks_echo_suppressed"] = True
        console._send(" ".join(words).encode("ascii"),
                      "arch-join-checks-names-sent")

        def value(name: str, shape: bytes) -> bytes:
            try:
                return console._wait(
                    rb"(?:^|\n)" + re.escape(markers[name]) + shape
                    + rb"(?=[\r\n])", f"arch-join-check-{name}").group(1)
            except SerialAutomationError as error:
                raise ArchDurableJoinError(
                    f"{CHECK_INCOMPLETE_FAILURE} ({name})") from error

        facts["join_once_sealed"] = value("sealed", rb"([01])") == b"1"
        facts["sssd_online"] = value("online", rb"([01])") == b"1"
        observed_host = value(
            "host", rb"([A-Za-z0-9._-]{1,253})").decode("ascii")
        facts["hostname_observed"] = observed_host
        facts["hostname_matches"] = (
            observed_host.split(".", 1)[0].lower() == hostname.lower())
        for index, account in enumerate(accounts):
            try:
                match = console._wait(
                    rb"(?:^|\n)" + re.escape(markers["uid"])
                    + str(index).encode("ascii")
                    + rb"=([0-9]{1,10}|none)(?=[\r\n])",
                    f"arch-join-check-uid-{index}")
            except SerialAutomationError as error:
                raise ArchDurableJoinError(
                    f"{CHECK_INCOMPLETE_FAILURE} "
                    f"({account['contract_role']})") from error
            raw = match.group(1)
            observed = None if raw == b"none" else int(raw)
            uids[str(account["contract_role"])] = {
                "expected_uid": int(account["uidNumber"]),
                "observed_uid": observed,
                "match": observed == int(account["uidNumber"]),
            }
        value("done", rb"([0-9]+)")
    finally:
        console.timeout = original
    facts["uids_pinned"] = bool(uids) and all(
        entry["match"] for entry in uids.values())
    if not facts["join_once_sealed"]:
        raise ArchDurableJoinError(SEALED_FAILURE)
    if not facts["sssd_online"]:
        raise ArchDurableJoinError(DOMAIN_OFFLINE_FAILURE)
    if not facts["uids_pinned"]:
        roles = ", ".join(role for role, entry in uids.items()
                          if not entry["match"])
        raise ArchDurableJoinError(f"{UID_MISMATCH_FAILURE}: {roles}")
    if not facts["hostname_matches"]:
        raise ArchDurableJoinError(HOSTNAME_MISMATCH_FAILURE)


def power_off_workstation(
    console, process, facts: dict, *,
    timeout: float = POWEROFF_TIMEOUT,
    exit_timeout: float = POWEROFF_EXIT_TIMEOUT,
) -> None:
    """``systemctl poweroff`` from the root shell, then wait for QEMU to exit.

    The console is drained while the guest shuts down, so QEMU never blocks
    on a full serial pipe; a closed console is QEMU exiting, which is the
    point.  Clean means QEMU exited 0 within the bound.
    """
    console._send(b"systemctl poweroff", "arch-join-poweroff-sent")
    original = console.timeout
    console.timeout = timeout
    try:
        with contextlib.suppress(SerialAutomationError):
            console._wait(
                rb"(?:reboot: Power down|Reached target [^\n]*Power[- ]?Off)",
                "arch-join-poweroff-observed")
    finally:
        console.timeout = original
    try:
        code = process.wait(timeout=exit_timeout)
    except subprocess.TimeoutExpired:
        code = None
    facts["workstation_exit_code"] = code
    facts["workstation_clean_poweroff"] = code == 0


def scrub(data: bytes, typed: Sequence[bytes]) -> bytes | None:
    """*data* with every typed value removed, or ``None`` if one survives."""
    values = sorted({value for value in typed if value}, key=len,
                    reverse=True)
    for value in values:
        data = data.replace(value, b"[REDACTED]")
    data = redact(data)
    if values and count_secret_occurrences([data], secret_needles(values)):
        return None
    return data


# -- the boundary -----------------------------------------------------------------
class DurableArchJoinBoundary(ArchIdentityBoundary):
    """Gate 8's boundary around the persistent Controller and a kept disk.

    Overrides the fabric (a persistent switch told the instance's own MAC),
    the Controller (a ``PersistentControllerSession`` instead of a disposable
    convergence), the workstation start (boot, then the sealed one-use join)
    and the stop (the Controller powers off over its console before gate 8's
    teardown).  ``finish`` drives the rest: the domain-online gate, the first
    logon, the roster proof, the elevation, the break-glass password, the
    root-shell proofs and a clean poweroff.  The fault hooks gate 8 drives
    are refused: nothing here pauses a durable directory.
    """

    def __init__(
        self, bundle: ArchIdentityBundle, *, binding: DurableBinding,
        target: PersistentControllerInstance, credentials: OwnerCredentials,
        accounts: Sequence[Mapping], hostname: str, mode: str,
        canonical_state: Path = DEFAULT_STATE,
        duration: float = DEFAULT_DURATION,
        session_factory: Callable[..., object] | None = None,
    ) -> None:
        super().__init__(bundle, duration=duration)
        self.binding = binding
        self.target = target
        self.canonical_state = Path(canonical_state)
        self._credentials = credentials
        self.accounts = [dict(account) for account in accounts]
        self.hostname = hostname
        self.mode = mode
        self._session_factory = session_factory or PersistentControllerSession
        self._session = None
        self._persistent_console = None
        self._join_credentials: list[str] = []
        self._workstation_tee = bytearray()
        self.checks: dict[str, object] = {key: False for key in REQUIRED_CHECKS}
        if mode == MODE_FIRST_LOGON:
            self.checks["password_changed"] = False
        self.facts: dict[str, object] = {
            "mode": mode, "directory": {}, "session": {}, "login": {},
            "join_sealed_by_marker": False,
        }

    # -- seams (tests replace these; the real ones are thin) --------------
    def _wait_switch_port(self, name: str, mac: str) -> None:  # pragma: no cover
        assert self._runtime is not None
        wait_for_switch_port(
            self._runtime / "switch.jsonl", name, mac,
            timeout=SWITCH_PORT_TIMEOUT)

    def _join_serial(self, console):
        module = _join_material()
        serial = module.ControllerJoinSerial(
            console.reader, console.writer, timeout=CONSOLE_READY_TIMEOUT)
        serial.console = console
        return serial

    def _workstation_serial(self, process) -> SerialAutomation:
        # Tee'd, so the retained transcript is the whole boot, bounded, and
        # not only SerialAutomation's 64 KiB tail.
        return SerialAutomation(
            _ConsoleTee(process.stdout, self._workstation_tee), process.stdin,
            None, timeout=CONSOLE_READY_TIMEOUT)

    def typed_secrets(self) -> list[bytes]:
        return self._credentials.values() + [
            value.encode("utf-8") for value in self._join_credentials]

    # -- the fault hooks gate 8 drives are refused ---------------------------
    def take_controller_offline(self) -> None:
        raise ArchDurableJoinError(NO_FAULTS_FAILURE)

    def restore_controller(self) -> None:
        raise ArchDurableJoinError(NO_FAULTS_FAILURE)

    def make_storage_unreachable(self) -> None:
        raise ArchDurableJoinError(NO_FAULTS_FAILURE)

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        """Gate 8's start without its stop-on-failure: the caller stops once
        and keeps the teardown's failures."""
        resolved_roster()
        self._start_all()

    def _start_fabric(self) -> None:
        assert self._runtime is not None
        listener = socket.socket()
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(3)
            self._port = int(listener.getsockname()[1])
            self._spawn(
                "switch",
                persistent_switch_command(
                    listener.fileno(), self._runtime / "switch.jsonl",
                    controller_mac=SOCKET_MAC, workstation_mac=MACS["client"],
                    accept_timeout=SWITCH_ACCEPT_TIMEOUT,
                    idle_timeout=self.duration + 60, identity_mode=True),
                pass_fds=(listener.fileno(),))
        finally:
            listener.close()
        self._spawn(
            "gateway",
            gateway_command(
                self._port, controller_mac=SOCKET_MAC, identity_mode=True))
        self._wait_switch_port("gateway", GATEWAY_MAC)
        self.checks["fabric_started"] = True

    def _start_controller(self) -> None:
        """Boot the bound instance in place, log in, prove it is the directory."""
        assert self._port is not None
        self._qmp_root = Path(tempfile.mkdtemp(prefix="telos-arch-join-qmp-"))
        self._qmp_root.chmod(0o700)
        self._session = self._session_factory(
            self.target, port=self._port,
            password=self._credentials.console,
            canonical_state=self.canonical_state)
        _say(f"booting persistent instance {self.binding.instance} in place")
        console = self._session.start(
            attached=lambda: self._wait_switch_port("controller", SOCKET_MAC))
        self.checks["controller_logged_in"] = True
        self.checks["live_argv_audited"] = bool(
            self._session.facts.get("live_argv_audited"))
        # Deliberately NOT ``_controller_console``: gate 8's stop releases
        # that console's password, and this one belongs to the session.
        self._persistent_console = console
        directory: dict[str, object] = {}
        self.facts["directory"] = directory
        # Realm and SID are hard refusals, before anything is written into
        # the directory; the fabric measurements are recorded.
        _probe_directory(console, self.binding, directory)
        self.checks["directory_bound"] = bool(
            directory.get("realm_matches")) and directory.get(
                "domain_sid") in ("match", "repair-needed")
        self._controller_online = True

    def _boot_workstation(self):
        """Gate 8's disk-only boot of the overlay, with its diagnostics."""
        assert self._port is not None and self._qmp_root is not None
        qmp_path = self._qmp_root / "workstation.qmp"
        progress_socket = self._arm_progress()
        firmware_log = (
            self.bundle.evidence_path.parent
            / WORKSTATION_FIRMWARE_LOG_FILENAME)
        private_file(firmware_log, b"")
        command = workstation_boot_command(
            self.bundle.disk, self.bundle.firmware, self._port,
            qmp_socket=qmp_path, firmware_log=firmware_log,
            progress_socket=progress_socket)
        self._boot_facts["firmware_vars_sha256_before"] = _file_sha256(
            self.bundle.firmware)
        private_file(
            self.bundle.bundle / BUNDLE_QEMU_COMMAND,
            (json.dumps({"schema": 1, "argv": command}, indent=2)
             + "\n").encode("utf-8"))
        from .guest_progress_collector import audit_progress_port

        spawned_at = time.monotonic()
        process = self._spawn("workstation", command, stdio=True)
        self._boot_facts["workstation_spawned_at"] = _utc_now()
        self._audit(
            "client", process.pid, allowed_nic_models=("e1000e",),
            allowed_chardevs=audit_progress_port(command))
        try:
            self._workstation_qmp = self._connect_qmp(qmp_path, process.pid)
        except ArchIdentityError as error:
            raise ArchIdentityError(
                "workstation QMP authentication failed",
                check="arch-joined") from error
        console = self._workstation_serial(process)
        console.events = TimestampedEvents(console.events, origin=spawned_at)
        self._workstation_console = console
        self._poll_progress()
        return process, console

    def _start_workstation(self) -> None:
        """One tj- principal, the sealed boot-time join, proof of destruction.

        The principal is staged before the workstation exists; the consumer
        boots it, builds the media, drives the menu, attaches the media after
        the Linux handoff, destroys them at the guest's consumed marker, and
        waits for the verified marker a durable render prints only after the
        seal is on disk.  ``OneUseDomainJoinMaterial`` then destroys the
        principal with proof, whatever happened.
        """
        module = _join_material()
        assert self._runtime is not None
        serial = self._join_serial(self._persistent_console)

        def stage(credential: str):
            # Kept only so every transcript can be proven free of it.
            self._join_credentials.append(credential)
            result = serial.stage(credential)
            self.checks["join_principal_staged"] = True
            _say("one tj- join principal staged")
            return result

        material = module.OneUseDomainJoinMaterial(
            self.binding.kerberos_realm, stage=stage, destroy=serial.destroy)
        iso = self._runtime / JOIN_ISO_NAME
        self._join_iso = iso
        media: dict = {}
        consumed = re.escape(JOIN_MEDIA_CONSUMED_MARKER.encode("ascii"))
        verified = re.escape(JOIN_VERIFIED_MARKER.encode("ascii"))
        consumer_error: list[BaseException] = []

        def consume(values: Mapping[str, str]):
            try:
                process, console = self._boot_workstation()

                def drive(attach_media, consume_media) -> str:
                    drive_boot_menu(
                        console, self._boot_facts,
                        reset=lambda: self._workstation_qmp.execute(
                            "system_reset"),
                        menu_timeout=MENU_RENDER_TIMEOUT,
                        on_stall=self._retain_boot_stall_evidence)
                    # After the handoff: firmware never sees the device.
                    attach_media()
                    original = console.timeout
                    console.timeout = JOIN_TIMEOUT
                    try:
                        console._wait(consumed, "arch-join-media-consumed")
                        consume_media()
                        console._wait(verified, "arch-join-verified")
                    finally:
                        console.timeout = original
                    return bytes(console.transcript).decode("utf-8", "replace")

                return run_join_install(
                    material=values, iso=iso, qmp=self._workstation_qmp,
                    qemu_pid=process.pid, drive=drive, facts=media)
            except BaseException as error:
                consumer_error.append(error)
                raise

        try:
            _value, proof = material.use(consume)
        except module.ControllerJoinMaterialError as error:
            destroyed = "destruction:" not in str(error)
            if not destroyed:
                with contextlib.suppress(
                        module.ControllerJoinMaterialError,
                        SerialAutomationError, OSError):
                    destroyed = material.retry_destruction().destruction_proved
            self.checks["join_principal_destroyed"] = destroyed
            if not destroyed:
                print("error: a one-use join principal may remain in the "
                      f"directory: {getattr(serial, '_principal', 'tj-?')}",
                      file=sys.stderr)
            cause = consumer_error[0] if consumer_error else error
            if isinstance(cause, (ArchIdentityError, RunInterrupted)):
                raise cause from error
            raise ArchIdentityError(
                JOIN_FAILURE + "; " + type(cause).__name__,
                check="arch-joined") from error
        finally:
            for key, fact in (("join_media_built", "built"),
                              ("join_media_attached", "attached"),
                              ("join_media_consumed", "consumed"),
                              ("join_media_destroyed", "destroyed")):
                self.checks[key] = bool(media.get(fact))
                self._boot_facts[key] = bool(media.get(fact))
        # A durable render writes and syncs the seal before this marker.
        self.checks["join_verified"] = True
        self.facts["join_sealed_by_marker"] = True
        self._boot_facts["join_verified"] = True
        self.checks["join_principal_destroyed"] = proof.destruction_proved
        self._boot_facts["join_principal_destroyed"] = (
            proof.destruction_proved)
        if not proof.destruction_proved:
            raise ArchIdentityError(
                JOIN_PRINCIPAL_NOT_DESTROYED_FAILURE, check="arch-joined")
        _say("joined; the join media and the tj- principal are destroyed")

    def finish(self) -> None:
        """Everything after the join, strictly in order, on the one console."""
        console = self._workstation_console
        process = self._processes.get("workstation")
        if console is None or process is None:
            raise ArchDurableJoinError("the workstation console is not open")
        await_domain_online(console, self._boot_facts)
        self.checks["domain_online_observed"] = True
        login: dict[str, object] = {}
        self.facts["login"] = login
        credentials = self._credentials
        live = first_logon_login(
            console, login,
            username=account_name(
                self.accounts, "daily_administrator").encode("ascii"),
            password=credentials.daily,
            new_password=(credentials.new_daily
                           if self.mode == MODE_FIRST_LOGON else None))
        self.checks["login_completed"] = True
        if self.mode == MODE_FIRST_LOGON:
            self.checks["password_changed"] = bool(login["password_changed"])
            _say("the daily administrator's first-logon change landed")
        console.password = live
        observed = ArchIdentityDrive(console).confirm_roster()
        if observed != self.binding.roster_fingerprint:
            raise ArchDurableJoinError(ROSTER_BINDING_FAILURE)
        self.checks["roster_matches"] = True
        elevate_operator(
            console, self._boot_facts, timeout=SUDO_ELEVATION_TIMEOUT)
        self.checks["elevated"] = True
        set_rescue_password(
            console, self._boot_facts, credentials.rescue,
            timeout=RESCUE_PASSWORD_TIMEOUT)
        self.checks["rescue_password_set"] = True
        checks: dict[str, object] = {}
        self.facts["identity"] = checks
        try:
            prove_joined_identity(
                console, checks, domain=self.binding.dns_domain,
                accounts=self.accounts, hostname=self.hostname)
        finally:
            for key in ("sssd_online", "uids_pinned", "join_once_sealed",
                        "hostname_matches"):
                self.checks[key] = bool(checks.get(key))
        _say("sealed, online, every role at its pinned uid; powering off")
        poweroff: dict[str, object] = {}
        power_off_workstation(console, process, poweroff)
        self.facts["workstation_poweroff"] = poweroff
        self.checks["workstation_clean_poweroff"] = bool(
            poweroff["workstation_clean_poweroff"])

    def _retain_workstation_evidence(self, transcript: bytes) -> None:
        data = bytes(self._workstation_tee) or bytes(transcript)
        typed = self.typed_secrets()
        before = (count_secret_occurrences([data], secret_needles(typed))
                  if typed and data else 0)
        login = self.facts.get("login") or {}
        self.checks["echo_never_observed"] = (
            before == 0 and not login.get("echo_observed"))
        cleaned = scrub(data, typed)
        self.facts["workstation_transcript"] = (
            "withheld" if cleaned is None else "retained")
        super()._retain_workstation_evidence(
            cleaned if cleaned is not None else
            b"[withheld: a typed credential could not be proven absent]\n")

    def stop(self) -> list[str]:
        failures: list[str] = []
        session, self._session = self._session, None
        self._persistent_console = None
        if session is not None:
            try:
                session.stop()
            except BaseException as error:  # noqa: BLE001 - reported
                failures.append(
                    f"persistent controller stop: {type(error).__name__}")
            facts = dict(getattr(session, "facts", {}))
            self.facts["session"] = facts
            self.checks["controller_clean_poweroff"] = (
                int(facts.get("clean_poweroffs", 0)) >= 1
                and not facts.get("terminated_fallback"))
            self.checks["controller_lock_released"] = bool(
                facts.get("lock_released"))
            transcript = session.redacted_transcript(self.typed_secrets())
            if transcript is not None:
                try:
                    retained, sizes = redact_and_bound(transcript)
                    private_file(
                        self.bundle.evidence_path.parent
                        / CONTROLLER_TRANSCRIPT_NAME, retained)
                    self.facts["controller_transcript"] = sizes
                except (OSError, RuntimeError) as error:
                    failures.append(
                        "controller transcript retention failed: "
                        + type(error).__name__)
            else:
                self.facts["controller_transcript"] = "withheld"
            with contextlib.suppress(Exception):
                session.close()
            self._controller_online = False
        failures += super().stop()
        self.checks["transcripts_secret_free"] = (
            self.facts.get("controller_transcript") not in (None, "withheld")
            and self.facts.get("workstation_transcript") == "retained")
        return failures


def drive_join(boundary: DurableArchJoinBoundary) -> None:
    """Start, finish, and always stop once; teardown faults are kept."""
    primary: BaseException | None = None
    failures: list[str] = []
    try:
        boundary.start()
        boundary.finish()
    except BaseException as error:  # noqa: BLE001 - re-raised after stop
        primary = error
    finally:
        try:
            failures = boundary.stop()
        except BaseException as error:  # noqa: BLE001
            failures = [f"teardown: {type(error).__name__}"]
    if failures:
        boundary.facts["cleanup_failures"] = failures
    if primary is not None:
        raise primary
    if failures:
        raise ArchDurableJoinError(
            "the durable join's teardown was incomplete: "
            + "; ".join(failures))


def passed(boundary: DurableArchJoinBoundary) -> bool:
    return all(value is True for value in boundary.checks.values())


# -- the kept workstation --------------------------------------------------------
def open_workstation(root: Path, name: str) -> WorkstationInstance:
    return WorkstationInstance(workstation_state(root, name), name=name)


def require_arch_join_next(workstation: WorkstationInstance) -> dict:
    marker = workstation.read_marker()
    name = marker["workstation"]
    pending = marker.get("pending_fold")
    if pending is not None:
        raise ArchDurableJoinError(
            f"kept workstation {name} records an interrupted fold of stage "
            f"{pending['stage']}; inspect it with "
            f"homelab-durable-workstation-status before joining")
    following = workstation.next_stage(marker)
    if following != STAGE:
        raise ArchDurableJoinError(
            f"the next stage for kept workstation {name} is {following!r}, "
            f"not {STAGE!r}")
    return marker


def require_ledger_head(workstation: WorkstationInstance, marker: dict) -> None:
    """Refuse, before any prompt, a disk the fold would refuse after a join.

    The first-logon change cannot be undone, so it is not spent on a disk or
    a variable store that changed outside a fold.
    """
    head = marker["ledger"][-1]
    if (workstation.vars.is_symlink() or not workstation.vars.is_file()):
        raise ArchDurableJoinError(
            "the kept workstation has no firmware variables; stage "
            "arch-install folds the installer-authored ones")
    if sha256(workstation.disk) != head["disk_sha256"]:
        raise ArchDurableJoinError(
            "the kept workstation's disk no longer hashes to its ledger head; "
            "it changed outside a fold")
    if sha256(workstation.vars) != head.get("vars_sha256"):
        raise ArchDurableJoinError(
            "the kept workstation's firmware variables no longer match its "
            "ledger head; they changed outside a fold")


def installed_hostname(marker: dict) -> str | None:
    """The host name step 6 baked, when its bundle's record still exists."""
    entries = [entry for entry in marker["ledger"]
               if entry["stage"] == "arch-install"]
    if not entries:
        return None
    record = Path(entries[-1]["source"]) / "authorization.json"
    try:
        if record.is_symlink():
            return None
        document = json.loads(record.read_text(encoding="utf-8"))
        hostname = document["authorization"]["hostname"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return hostname if isinstance(hostname, str) else None


def _existing_ancestor(path: Path) -> Path:
    for candidate in (Path(path).absolute(), *Path(path).absolute().parents):
        if candidate.is_dir():
            return candidate
    return Path("/")


def space_needs(workstation: WorkstationInstance, run_root: Path) -> list[dict]:
    """The overlay's growth under *run_root*; the fold's copy beside ``W``."""
    allocated = workstation.disk.stat().st_blocks * 512
    needs: dict[int, dict] = {}
    for directory, amount in (
            (workstation.state, allocated + JOIN_GROWTH_BYTES),
            (_existing_ancestor(run_root), JOIN_GROWTH_BYTES)):
        device = directory.stat().st_dev
        entry = needs.setdefault(device, {"path": directory, "needed": 0})
        entry["needed"] += amount
    for entry in needs.values():
        entry["free"] = shutil.disk_usage(entry["path"]).free
    return list(needs.values())


def preflight_problems(binding: DurableBinding) -> list[str]:
    """Every refusal a live run can meet before its first prompt."""
    problems = [f"{tool} is not installed"
                for tool in ("qemu-system-x86_64", "qemu-img")
                if not shutil.which(tool)]
    if ovmf_pair() is None:
        problems.append("OVMF firmware was not found")
    target = PersistentControllerInstance(
        binding.state, instance=binding.instance)
    if _persistent_running(target) is not False:
        problems.append(f"{binding.instance} is already running or its lock "
                        "cannot be probed")
    if not problems:
        try:
            assert_installed(
                target.disk, subject=f"the persistent instance disk "
                f"{target.disk}", remedy="Recreate and converge the instance.")
        except ControllerImageError as error:
            problems.append(str(error))
    return problems


def _create_overlay(backing: Path, overlay: Path) -> None:
    subprocess.run(
        ["qemu-img", "create", "-q", "-f", "qcow2", "-b",
         str(Path(backing).resolve()), "-F", "qcow2", str(overlay)],
        check=True, capture_output=True)
    overlay.chmod(0o600)


def _copy_vars(source: Path, target: Path) -> None:
    shutil.copyfile(source, target)
    target.chmod(0o600)


def _gib(value: int) -> str:
    return f"{value / 1024 ** 3:.1f} GiB"


def _write_result(evidence: Path, result: Mapping[str, object]) -> None:
    private_file(evidence / RESULT_NAME, (
        json.dumps(result, indent=2, sort_keys=True, default=str)
        + "\n").encode("utf-8"))


def _mode(args: argparse.Namespace, record: Mapping) -> str:
    if args.first_logon_done:
        return MODE_CURRENT
    return (MODE_FIRST_LOGON
            if record.get("password_change_at_first_logon") is True
            else MODE_CURRENT)


def print_plan(
    args: argparse.Namespace, workstation: WorkstationInstance, marker: dict,
    binding: DurableBinding, accounts: Sequence[Mapping], mode: str,
    installed: str | None, space: list[dict],
) -> None:
    name = workstation.state.name
    stages = ", ".join(entry["stage"] for entry in marker["ledger"])
    print("Boundary: loopback-only switch; no host or UniFi changes")
    print(f"Kept workstation: {name} at {workstation.state}; stages done: "
          f"{stages}; next stage {STAGE}")
    print(f"Bound instance: {binding.instance}. The workstation's marker, the "
          f"instance's realm, domain SID and staged roster fingerprint are "
          f"compared, never printed")
    print(f"Controller: persistent instance {binding.instance}, its own disk "
          f"booted IN PLACE under its lock on the per-run switch (its own "
          f"MAC {SOCKET_MAC}; no QMP, no medium, no pause); stopped by a "
          f"clean console poweroff")
    print(f"Disk: a fresh overlay backed by {workstation.disk}, booted with a "
          f"copy of the workstation's firmware variables")
    cross = ("matches the host name stage arch-install baked"
             if installed == args.hostname else
             "could not be cross-checked: stage arch-install's bundle record "
             "is gone; the node name is checked on the guest")
    print(f"Arch hostname: {args.hostname} ({cross}); machine account "
          f"{machine_account(args.hostname)} is recorded in the marker "
          f"BEFORE the join, so destroy lists it")
    print("Steps: prove the directory's realm and SID; stage one tj- join "
          "principal; boot the overlay and drive the menu to Arch; attach the "
          "one-use join media after the kernel handoff and destroy them once "
          "the guest consumed them; wait for TELOS ARCH JOIN VERIFIED "
          "(net ads testjoin passed, seal written); destroy the tj- principal "
          "with proof; wait for the domain-online gate; log in on ttyS0 as "
          "the daily administrator; prove the disk's roster; elevate with "
          "sudo; set the Arch local-rescue password; check sssctl online, "
          "every directory role at its pinned uid, the sealed join unit and "
          "the node name; power the workstation, then the Controller, off")
    print("Directory roles checked (uidNumbers from the durable account "
          "record; names are compared on the guest, never printed): "
          + ", ".join(f"{account['contract_role']} uid "
                      f"{account['uidNumber']}" for account in accounts))
    print("Prompts, in order, all at this terminal before any process "
          "starts; none is ever written to a file, argv, the environment, "
          "the evidence or a transcript:")
    print(f"  1. the {CONSOLE_ACCOUNT} console password of persistent "
          f"instance {binding.instance}")
    if mode == MODE_FIRST_LOGON:
        principals = _controller_principals()
        print("  2. the daily administrator's TEMPORARY password (the one "
              "its account was staged with)")
        print(f"  3. the daily administrator's NEW password, twice; the "
              f"directory's default policy applies: at least "
              f"{principals.DIRECTORY_MIN_PASSWORD_LENGTH} characters from "
              f"{principals.DIRECTORY_PASSWORD_CLASSES} classes, not "
              f"containing the account name")
        print("  4. a NEW break-glass password for the Arch local-rescue "
              "account, twice: distinct from every other, never stored")
        print("First logon: pam_sss asks the daily administrator to change "
              "its temporary password; the run answers with the two values "
              "above. If the change lands and a later step fails, repeat "
              "with FIRST_LOGON_DONE=1 and type the NEW password when asked "
              "for the current one")
    else:
        print("  2. the daily administrator's CURRENT password")
        print("  3. a NEW break-glass password for the Arch local-rescue "
              "account, twice: distinct from every other, never stored")
        print("First logon: none. "
              + ("FIRST_LOGON_DONE=1: the change was already made"
                 if args.first_logon_done else
                 "the durable account record does not ask for a change at "
                 "first logon"))
    print(f"On success: the overlay and the firmware variables it booted "
          f"with are folded into {name} as stage {STAGE}; the overlay is "
          f"then removed")
    print(f"On failure: the overlay is removed and {name}'s disk, firmware "
          f"variables and ledger are unchanged; its marker keeps the machine "
          f"account; evidence stays under {args.run_root}")
    for entry in space:
        verdict = "" if entry["free"] >= entry["needed"] else " (INSUFFICIENT)"
        print(f"Free space: {entry['path']} needs about "
              f"{_gib(entry['needed'])}, has {_gib(entry['free'])}{verdict}")
    print(f"Maximum runtime: {args.duration:g} seconds")


def _run_id() -> str:
    return (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            + f"-{os.getpid()}-{secrets.token_hex(4)}")


def execute(
    args: argparse.Namespace, workstation: WorkstationInstance,
    binding: DurableBinding, accounts: Sequence[Mapping], mode: str,
    credentials: OwnerCredentials, *,
    boundary_factory: Callable[..., DurableArchJoinBoundary] | None = None,
) -> int:
    """One join under ``W``'s lock: overlay, join, proofs, fold or nothing."""
    root = Path(args.run_root).absolute()
    private_directory(root)
    run_dir = root / f"run-{_run_id()}"
    run_dir.mkdir(mode=0o700)
    evidence = run_dir / "evidence"
    private_directory(evidence)
    overlay = run_dir / BUNDLE_DISK
    firmware = run_dir / BUNDLE_FIRMWARE
    account = machine_account(args.hostname)
    result: dict[str, object] = {
        "schema": 1, "kind": "durable-arch-join", "stage": STAGE,
        "workstation": workstation.state.name,
        "bound_instance": binding.instance, "mode": mode,
        "hostname": args.hostname, "machine_account": account,
        "started_utc": datetime.now(UTC).isoformat(),
    }
    _say(f"evidence: {evidence}")
    boundary: DurableArchJoinBoundary | None = None
    entry: dict | None = None
    failure: BaseException | None = None
    step = "overlay"
    try:
        _create_overlay(workstation.disk, overlay)
        _copy_vars(workstation.vars, firmware)
        step = "machine-account"
        workstation.record_machine_account(account)
        result["machine_account_recorded"] = True
        step = "join"
        bundle = ArchIdentityBundle(run_dir, args.controller_state)
        bundle.realm = binding.kerberos_realm
        factory = boundary_factory or DurableArchJoinBoundary
        boundary = factory(
            bundle, binding=binding,
            target=PersistentControllerInstance(
                binding.state, instance=binding.instance),
            credentials=credentials, accounts=accounts,
            hostname=args.hostname, mode=mode,
            canonical_state=args.controller_state, duration=args.duration)
        drive_join(boundary)
        if not passed(boundary):
            missing = sorted(key for key, value in boundary.checks.items()
                             if value is not True)
            raise ArchDurableJoinError(
                "the join ran but did not prove: " + ", ".join(missing))
        step = "fold"
        entry = workstation.fold(
            overlay, STAGE, firmware_vars=firmware, source=str(run_dir))
    except BaseException as error:  # noqa: BLE001 - recorded, then raised
        failure = error
    finally:
        discarded = True
        try:
            overlay.unlink(missing_ok=True)
        except OSError:
            discarded = False
        if boundary is not None:
            result["checks"] = dict(boundary.checks)
            result["facts"] = boundary.facts
            login = boundary.facts.get("login") or {}
            result["password_change_landed"] = login.get(
                "password_change_landed")
        result.update({
            "verdict": "pass" if failure is None else "fail",
            "finished_utc": datetime.now(UTC).isoformat(),
            "folded": entry is not None,
            "fold": None if entry is None else {
                key: entry.get(key)
                for key in ("stage", "utc", "disk_sha256", "vars_sha256")},
            "overlay_discarded": discarded,
        })
        if failure is not None:
            result["failure"] = {
                "step": step, "type": type(failure).__name__,
                "check": getattr(failure, "check", None)}
        _write_result(evidence, result)
    if failure is not None:
        landed = result.get("password_change_landed")
        if landed is True:
            print("error: the daily administrator's password change LANDED: "
                  "the new password is live in the directory. Repeat with "
                  "FIRST_LOGON_DONE=1 and type the NEW password when asked "
                  "for the current one", file=sys.stderr)
        elif landed is None and mode == MODE_FIRST_LOGON and boundary and (
                (boundary.facts.get("login") or {}).get("new_password_writes")):
            print("error: the daily administrator's password change MAY have "
                  "landed; try FIRST_LOGON_DONE=1 with the NEW password "
                  "first", file=sys.stderr)
        print(f"error: machine account {account} is recorded in "
              f"{workstation.state.name}'s marker; destroy lists it",
              file=sys.stderr)
        print(f"Evidence: {evidence}", file=sys.stderr)
        raise failure
    print(f"Folded stage {STAGE} into {workstation.state.name}; ledger head "
          f"{entry['disk_sha256']}")
    print(f"Evidence: {evidence}")
    return 0


def run(
    args: argparse.Namespace, *,
    boundary_factory: Callable[..., DurableArchJoinBoundary] | None = None,
) -> int:
    if not 60 <= args.duration <= MAX_DURATION:
        raise ArchDurableJoinError(
            f"duration must be between 60 and {MAX_DURATION:g} seconds")
    if not SAFE_HOSTNAME.fullmatch(args.hostname):
        raise ArchDurableJoinError(
            "the Arch hostname must be lowercase letters, digits and hyphens, "
            "starting with a letter")
    require_netbios_hostname(args.hostname)
    workstation = open_workstation(args.root, args.workstation)
    marker = require_arch_join_next(workstation)
    binding = durable_binding(
        args.persistent_root, args.persistent_dc,
        canonical_state=args.controller_state,
        identity_path=args.directory_identity)
    require_workstation_binding(marker, binding)
    record = directory_account_record(binding)
    accounts = planned_accounts(record)
    require_roster_agreement(binding, accounts)
    installed = installed_hostname(marker)
    if installed is not None and installed != args.hostname:
        raise ArchDurableJoinError(
            f"stage arch-install baked the host name {installed!r}, not "
            f"{args.hostname!r}; the machine account recorded before the join "
            f"must be the one the disk will create")
    mode = _mode(args, record)
    space = space_needs(workstation, args.run_root)
    print_plan(args, workstation, marker, binding, accounts, mode, installed,
               space)
    if not args.apply:
        print("dry run; repeat with --apply")
        return 0
    short = [entry for entry in space if entry["free"] < entry["needed"]]
    if short:
        raise ArchDurableJoinError(
            "not enough free space for the overlay and the fold: "
            + "; ".join(f"{entry['path']} needs about {_gib(entry['needed'])}"
                        for entry in short))
    problems = preflight_problems(binding)
    if problems:
        raise ArchDurableJoinError("; ".join(problems))
    with SignalGuard(), workstation:
        # Re-read under the lock, then prove the disk is still the ledger's
        # head: every refusal precedes the first prompt.
        marker = require_arch_join_next(workstation)
        require_workstation_binding(marker, binding)
        require_ledger_head(workstation, marker)
        credentials = owner_credentials(
            mode, daily_name=account_name(accounts, "daily_administrator"),
            rescue_name=rescue_principal(), instance=binding.instance)
        try:
            return execute(
                args, workstation, binding, accounts, mode, credentials,
                boundary_factory=boundary_factory)
        finally:
            credentials.clear()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Join a kept workstation's Arch to its persistent "
                    "directory (TASK-28 step 7); a dry run unless --apply")
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
        help="the Arch host name stage arch-install baked; its machine "
             "account is recorded before the join")
    result.add_argument(
        "--controller-state", type=Path, default=DEFAULT_STATE,
        help="the disposable acceptance canonical, refused as a persistent "
             "target")
    result.add_argument("--run-root", type=Path, default=DEFAULT_RUNS)
    result.add_argument("--duration", type=float, default=DEFAULT_DURATION)
    result.add_argument(
        "--first-logon-done", action="store_true",
        help="the daily administrator's first-logon change already landed; "
             "ask for its CURRENT password instead of the temporary one")
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(args)
    except RunInterrupted as error:
        print(f"error: {error}", file=sys.stderr)
        return error.exit_code
    except (RuntimeError, OSError, ValueError, EOFError, KeyboardInterrupt,
            subprocess.CalledProcessError) as error:
        print(f"error: {error or type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
