#!/usr/bin/env python3
"""Mint a kept workstation against a persistent directory in ONE command.

Owner request 2026-10-07: the owner should not have to keep entering
passwords, and the whole sequence -- a persistent directory, its accounts, a
fresh Windows install, the durable Arch install, both joins, keep-verify and
the first backup -- should run from one command.  Every step is the existing,
live-proven Make target (``FACTORY-MAKE-TARGETS.md``); this module only
sequences them, resumes from the markers they write, and times each one.

Credential custody is unchanged and decided by the instance's marker:

* **agent** (a throwaway rehearsal instance, ``CUSTODY=agent THROWAWAY=1``):
  nothing is asked; every runner reads the instance's custody store.
* **owner** (the keeper): every value is asked ONCE, here, at the owner's
  controlling terminal, before any step starts -- the console password, the
  new domain Administrator password, each roster account's password, the
  Arch ``local-rescue`` and Windows ``telosadmin`` break-glass passwords.
  They are held in this process's memory only (never a file, argv, the
  environment, a Make variable, a log or the evidence), judged by the
  runners' own host-side checks before anything boots, and typed into each
  step's own prompts through a pseudo-terminal: each step runs as the child
  of a pty and asks exactly as it does for a person.  A secret is written to
  the pty only after a KNOWN prompt appeared and the terminal's echo is off;
  any other prompt stops the step before it can boot anything (every runner
  asks before any process starts).  A rerun after a failure asks again and
  resumes at the first unfinished step.

Accounts are staged with PERMANENT passwords (no change at first logon): the
owner's list is the final one, under the short directory policy the owner
chose (minimum length 4, complexity off), which the policy step records
before staging.

Standard library only.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import getpass
import json
import os
import pty
import re
import select
import shutil
import signal
import subprocess
import sys
import termios
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

REPOSITORY = Path(__file__).resolve().parents[2]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

DEFAULT_PERSISTENT_ROOT = Path("build/homelab/vm/persistent-dc")
DEFAULT_WORKSTATION_ROOT = Path("build/homelab/vm/workstations")
DEFAULT_EVIDENCE_ROOT = Path("homelab/var/factory/mint")
INSTANCE_MARKER = "persistent-instance.json"
WORKSTATION_MARKER = "workstation-instance.json"
WINDOWS_BUNDLE = re.compile(
    rb"(homelab/var/factory/windows-installs/run-[0-9TZ]+-[0-9a-f]+)\s*$")

#: The owner's short directory policy (decision 2026-09-30, kept for minting).
MIN_PASSWORD_LENGTH = 4
PASSWORD_COMPLEXITY = False
#: Durations the live targets need (FACTORY-MAKE-TARGETS.md).
WINDOWS_INSTALL_DURATION = 7200
ARCH_INSTALL_DURATION = 1800
#: Free space a full mint needs: a Windows bundle (~12 GB publication plus a
#: ~20 GB disk), a ~20 GB adopted disk and one ~20-30 GB fold at a time.
MIN_FREE_BYTES = 90 * 1024 ** 3
SECRET_MAX = 512
#: Steps that leave the kept workstation and directory unchanged when they
#: fail, and whose failures include an intermittent firmware boot stall
#: (UAT 2026-10-07; the 2026-10-01 rehearsal needed six Windows-join
#: attempts): the mint repeats them itself, so an owner never retypes.  A
#: gate-5 install that fails (OVMF sometimes cannot read the NVMe after
#: Setup's reboot and PXE-boots again, ``pxe-loop``) is repeated with a
#: freshly prepared bundle, as the repeat driver does.
ATTEMPTS = {"windows-join": 5, "verify": 3, "windows-install": 3}


class MintError(RuntimeError):
    """A refusal or a failed step.  Messages never carry a credential."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# -- state, read from the markers the steps themselves write --------------
def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


@dataclass
class MintState:
    instance: dict | None
    workstation: dict | None

    @property
    def custody(self) -> str:
        return (self.instance or {}).get("credential_custody", "owner")

    def converged(self) -> bool:
        return bool((self.instance or {}).get("converged"))

    def policy_recorded(self) -> bool:
        policy = (self.instance or {}).get("directory_password_policy") or {}
        return (policy.get("min_length") == MIN_PASSWORD_LENGTH
                and policy.get("complexity") is PASSWORD_COMPLEXITY)

    def accounts_staged(self) -> bool:
        return bool((self.instance or {}).get("directory_accounts"))

    def accounts_attempted(self) -> bool:
        return bool((self.instance or {}).get("directory_accounts_attempted"))

    def first_logon(self) -> bool:
        record = (self.instance or {}).get("directory_accounts") or {}
        return record.get("password_change_at_first_logon") is True

    def stages(self) -> list[str]:
        return [entry.get("stage")
                for entry in (self.workstation or {}).get("ledger", [])]

    def publication_retired(self) -> bool:
        publication = (self.workstation or {}).get("publication") or {}
        return bool(publication.get("retired_utc"))

    def last_backup(self) -> dict | None:
        return (self.instance or {}).get("last_backup")


def read_state(persistent_root: Path, instance: str, workstation_root: Path,
               workstation: str) -> MintState:
    return MintState(
        _read_json(persistent_root / instance / INSTANCE_MARKER),
        _read_json(workstation_root / workstation / WORKSTATION_MARKER))


# -- the steps ---------------------------------------------------------------
@dataclass(frozen=True)
class Step:
    name: str
    target: str
    variables: tuple[tuple[str, str], ...]
    #: Credential keys this step's prompts ask for under owner custody.
    asks: frozenset = frozenset()
    note: str = ""


@dataclass
class Options:
    instance: str
    workstation: str
    hostname: str
    persistent_root: Path = DEFAULT_PERSISTENT_ROOT
    workstation_root: Path = DEFAULT_WORKSTATION_ROOT
    windows_run: Path | None = None
    custody: str | None = None
    throwaway: bool = False
    backup: bool = True
    make: str = "make"
    identity_overlay: Path | None = None


def _common(options: Options) -> list[tuple[str, str]]:
    common = [("PERSISTENT_DC", options.instance),
              ("PERSISTENT_DC_ROOT", str(options.persistent_root))]
    if options.identity_overlay is not None:
        common.append(("IDENTITY_OVERLAY", str(options.identity_overlay)))
    return common


def _workstation_vars(options: Options) -> list[tuple[str, str]]:
    return _common(options) + [
        ("WORKSTATION", options.workstation),
        ("DURABLE_WORKSTATION_ROOT", str(options.workstation_root))]


#: Beside a workstation's mint evidence: the gate-5 bundle a mint installed
#: but has not adopted yet, so a rerun after a later failure adopts it
#: instead of spending another 70 minutes installing Windows.
PENDING_BUNDLE = "pending-windows-run"


def finished_bundle(bundle: Path) -> bool:
    """A gate-5 bundle adopt would take: observed, publication retained."""
    try:
        result = json.loads((Path(bundle) / "evidence" / "result.json")
                            .read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return (isinstance(result, dict)
            and result.get("status") == "observed"
            and result.get("phase") == "native-windows-clean-shutdown"
            and result.get("private_publication_retained_for_identity") is True
            and (Path(bundle) / "publication.iso").is_file()
            and (Path(bundle) / "windows.qcow2").is_file())


def pending_bundle(evidence_root: Path, options: Options) -> Path | None:
    record = evidence_root / options.instance / options.workstation \
        / PENDING_BUNDLE
    try:
        bundle = Path(record.read_text(encoding="utf-8").strip())
    except OSError:
        return None
    return bundle if bundle.parts and finished_bundle(bundle) else None


def plan_steps(options: Options, state: MintState) -> list[Step]:
    """The steps still to run, in order, decided from the markers alone."""
    steps: list[Step] = []
    common = tuple(_common(options))
    if state.instance is None and options.custody == "agent":
        steps.append(Step(
            "up", "homelab-factory-persistent-up",
            common + (("CUSTODY", "agent"),)
            + ((("THROWAWAY", "1"),) if options.throwaway else ()),
            note="create a throwaway agent-custody instance"))
    if not state.converged():
        steps.append(Step(
            "converge", "homelab-factory-persistent-converge", common,
            frozenset({"console", "administrator"}),
            note=("provision the directory"
                  + ("; creates the owner-custody instance"
                     if state.instance is None and options.custody != "agent"
                     else ""))))
    if not state.policy_recorded():
        steps.append(Step(
            "password-policy", "homelab-factory-persistent-password-policy",
            common + (("MIN_PASSWORD_LENGTH", str(MIN_PASSWORD_LENGTH)),
                      ("PASSWORD_COMPLEXITY",
                       "on" if PASSWORD_COMPLEXITY else "off")),
            frozenset({"console"}), note="record the owner's short policy"))
    if not state.accounts_staged():
        steps.append(Step(
            "accounts", "homelab-factory-persistent-accounts", common,
            frozenset({"console", "accounts"}),
            note="stage every roster account with its permanent password"))
    stages = state.stages()
    windows = tuple(_workstation_vars(options))
    if "adopt" not in stages:
        steps.append(Step(
            "probe", "homelab-factory-persistent-probe", common,
            frozenset({"console"}),
            note="prove the directory on the per-run fabric"))
        if options.windows_run is None:
            steps.append(Step(
                "windows-install", "homelab-windows-install-run",
                (("FACTORY_DURATION", str(WINDOWS_INSTALL_DURATION)),),
                note="a fresh gate-5 Windows 11 Pro install (about 70 min)"))
        steps.append(Step(
            "adopt", "homelab-durable-workstation-adopt",
            windows + ((("WINDOWS_RUN", str(options.windows_run)),)
                       if options.windows_run is not None else ()),
            note="the Windows disk becomes the kept workstation"))
    host = (("ARCH_HOSTNAME", options.hostname),)
    if "arch-install" not in stages:
        steps.append(Step(
            "arch-install", "homelab-durable-arch-install",
            windows + host
            + (("FACTORY_DURATION", str(ARCH_INSTALL_DURATION)),),
            note="install Arch second, Windows preserved"))
    if "arch-join" not in stages:
        steps.append(Step(
            "arch-join", "homelab-durable-arch-join", windows + host,
            frozenset({"console", "daily", "arch_rescue"}),
            note="join Arch to the directory"))
    if "windows-join" not in stages or (
            state.workstation is not None
            and not state.publication_retired()):
        steps.append(Step(
            "windows-join", "homelab-durable-windows-join", windows,
            frozenset({"console", "windows_local", "daily"}),
            note="join Windows to the directory"))
    steps.append(Step(
        "verify", "homelab-durable-workstation-verify",
        windows + host + (("VERIFY_USERS", "1"),),
        frozenset({"console", "daily", "users"}),
        note=("keep-verify both systems across a Controller relaunch, every "
              "standard account logging in on Arch")))
    if options.backup:
        steps.append(Step(
            "backup", "homelab-factory-persistent-backup", common,
            frozenset({"console"}), note="native Samba backup of the directory"))
    return steps


# -- owner-custody credentials, asked once ----------------------------------
@dataclass
class Account:
    contract_role: str
    name: str


@dataclass
class Credentials:
    """Every value the remaining steps ask for, in memory only."""

    values: dict[str, str] = field(default_factory=dict, repr=False)
    accounts: dict[str, Account] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"Credentials(keys={sorted(self.values)})"

    def secrets(self) -> list[bytes]:
        return [value.encode("utf-8") for value in self.values.values()
                if value]

    def clear(self) -> None:
        for key in list(self.values):
            self.values[key] = ""
        self.values.clear()


def roster_accounts() -> list[Account]:
    """The durable roster's accounts, as account staging will plan them."""
    from homelab.vm import controller_principals as principals
    roster = principals.durable_directory_roster(None)
    plan = principals.directory_account_plan(
        list(principals.DIRECTORY_ROLES), roster=roster)
    return [Account(entry["contract_role"], entry["name"]) for entry in plan]


def needed_keys(steps: Sequence[Step]) -> set[str]:
    keys: set[str] = set()
    for step in steps:
        keys |= set(step.asks)
    return keys


def _typed(prompt: str, *, confirm: bool,
           ask: Callable[[str], str]) -> str:
    value = ask(prompt)
    if confirm and ask("retype: ") != value:
        raise MintError("the two entries did not match; nothing was started")
    if not value or len(value) > SECRET_MAX:
        raise MintError("a credential must be one non-empty line")
    if any(ord(character) < 32 or ord(character) == 127
           for character in value):
        raise MintError("a credential must not contain control characters")
    return value


def collect_credentials(
    keys: set[str], accounts: Sequence[Account], *, instance: str,
    console_is_canonical: bool,
    ask: Callable[[str], str] | None = None,
) -> Credentials:
    """Ask the owner once for every value *keys* needs, then judge them all."""
    ask = ask or (lambda prompt: getpass.getpass(prompt))
    credentials = Credentials()
    values = credentials.values
    print("The values below are asked once and held in memory only; they "
          "are never written to a file, argv, the environment or a log.",
          file=sys.stderr)
    try:
        if "console" in keys:
            whose = ("the canonical Controller image's" if console_is_canonical
                     else f"persistent instance {instance}'s")
            values["console"] = _typed(
                f"{whose} local-rescue console password: ", confirm=True,
                ask=ask)
        if "administrator" in keys:
            values["administrator"] = _typed(
                "new built-in domain Administrator password (7+ characters, "
                "3 of upper/lower/digit/symbol): ", confirm=True, ask=ask)
        if "accounts" in keys:
            for account in accounts:
                values["account:" + account.contract_role] = _typed(
                    f"password for {account.name} "
                    f"({account.contract_role}): ", confirm=True, ask=ask)
                credentials.accounts[account.contract_role] = account
        if "accounts" not in keys:
            # Accounts already exist: ask each needed one's CURRENT password.
            wanted = []
            if "daily" in keys:
                wanted.append("daily_administrator")
            if "users" in keys:
                wanted += [account.contract_role for account in accounts
                           if account.contract_role not in (
                               "daily_administrator", "domain_administrator")]
            for role in wanted:
                account = next(item for item in accounts
                               if item.contract_role == role)
                values["account:" + role] = _typed(
                    f"CURRENT password for {account.name} ({role}): ",
                    confirm=False, ask=ask)
                credentials.accounts[role] = account
        if "arch_rescue" in keys:
            values["arch_rescue"] = _typed(
                "new Arch local-rescue break-glass password: ", confirm=True,
                ask=ask)
        if "windows_local" in keys:
            values["windows_local"] = _typed(
                "new Windows local-administrator (telosadmin) break-glass "
                "password: ", confirm=True, ask=ask)
        problems = judge(credentials)
        if problems:
            raise MintError("; ".join(problems) + ". Nothing was started")
    except BaseException:
        credentials.clear()
        raise
    return credentials


def judge(credentials: Credentials) -> list[str]:
    """The runners' own host-side checks, applied before anything starts."""
    from homelab.vm.controller_principals import directory_password_problem
    from homelab.vm.directory_password_policy import (
        SAMBA_DEFAULT, DirectoryPasswordPolicy)
    from homelab.vm.windows_durable_join import typeable_problem
    short = DirectoryPasswordPolicy(
        min_length=MIN_PASSWORD_LENGTH, complexity=PASSWORD_COMPLEXITY,
        min_age_days=0, source="the minting directory policy")
    values = credentials.values
    problems: list[str] = []

    def check(key: str, label: str, account: str, policy) -> None:
        value = values.get(key)
        if not value:
            return
        for problem in (typeable_problem(value),
                        directory_password_problem(value, account, policy)):
            if problem:
                problems.append(f"{label} {problem}")

    check("administrator", "the domain Administrator password",
          "Administrator", SAMBA_DEFAULT)
    for role, account in credentials.accounts.items():
        check("account:" + role, f"the password for {account.name}",
              account.name, short)
    check("arch_rescue", "the Arch break-glass password", "local-rescue",
          short)
    check("windows_local", "the Windows break-glass password", "telosadmin",
          short)
    given = [value for key, value in values.items()
             if value and key != "console"]
    if values.get("console"):
        given.append(values["console"])
    if len(set(given)) != len(given):
        problems.append("two of the values are equal; every account and "
                        "break-glass password needs its own")
    return problems


# -- answering a step's own prompts through a pseudo-terminal ---------------
@dataclass(frozen=True)
class PromptRule:
    pattern: re.Pattern
    key: Callable[[re.Match], str]


def _rule(pattern: str, key: str | Callable[[re.Match], str]) -> PromptRule:
    return PromptRule(re.compile(pattern.encode() + rb"\s*$"),
                      key if callable(key) else (lambda _match, key=key: key))


_NAME = r"\((?P<name>[^()\r\n]+)\)"
#: Every prompt the minting steps ask under owner custody, verbatim from the
#: runners (bootstrap_dc, persistent_password_policy, persistent_controller_
#: session, persistent_backup, arch_durable_join, windows_durable_join,
#: durable_workstation_verify).  A rule maps a prompt to a credential key; a
#: ``name`` group is checked against the roster account collected for it.
PROMPTS: tuple[PromptRule, ...] = (
    _rule(r"local-rescue console password(?: for persistent instance "
          r"[a-z0-9-]+)?:", "console"),
    _rule(r"new domain Administrator password:", "administrator"),
    _rule(r"retype domain Administrator password:", "administrator"),
    _rule(r"new directory password for (?P<role>[a-z0-9_]+) " + _NAME + ":",
          lambda match: "account:" + match.group("role").decode()),
    _rule(r"retype password for (?P<role>[a-z0-9_]+):",
          lambda match: "account:" + match.group("role").decode()),
    _rule(r"CURRENT password for daily_administrator " + _NAME + ":",
          "account:daily_administrator"),
    _rule(r"(?:current|CURRENT) domain password for (?P<role>[a-z0-9_]+) "
          + _NAME + ":",
          lambda match: "account:" + match.group("role").decode()),
    _rule(r"NEW break-glass password for the Arch [a-z0-9_-]+ account:",
          "arch_rescue"),
    _rule(r"retype the break-glass password:", "arch_rescue"),
    _rule(r"new Windows local-administrator \(telosadmin\) password:",
          "windows_local"),
    _rule(r"retype the new Windows local-administrator password:",
          "windows_local"),
)
#: Anything else that looks like a credential prompt stops the step.
UNKNOWN_PROMPT = re.compile(rb"(?i)(password|passphrase)[^\r\n]*:\s*$")
#: getpass turns echo off BEFORE it writes its prompt; a prompt is real only
#: once echo is off, and no secret is ever typed into an echoing terminal.
ECHO_WAIT = 5.0
#: An unknown prompt must also be the last output for this long.
QUIET_WAIT = 0.5
#: A runner stopped mid-run powers its guests off cleanly (a persistent
#: Controller's QEMU must never be killed: that is a power cut on the
#: directory), so SIGINT gets a long grace before anything harder.
STOP_GRACE = 600.0


def last_line(tail: bytes) -> bytes:
    return tail.rsplit(b"\n", 1)[-1].rsplit(b"\r", 1)[-1]


def match_prompt(tail: bytes) -> tuple[str | None, re.Match | None]:
    """The credential key the output's last line asks for, if any."""
    line = last_line(tail)
    for rule in PROMPTS:
        match = rule.pattern.search(line)
        if match:
            return rule.key(match), match
    return None, None


class Scrubber:
    """Withhold every secret from output, even one split across chunks."""

    def __init__(self, secrets: Iterable[bytes]) -> None:
        self.secrets = sorted({value for value in secrets if value},
                              key=len, reverse=True)
        self.hold = max((len(value) for value in self.secrets), default=1) - 1
        self.pending = b""
        self.found = False

    def feed(self, data: bytes, *, final: bool = False) -> bytes:
        data = self.pending + data
        for value in self.secrets:
            if value in data:
                self.found = True
                data = data.replace(value, b"<withheld>")
        if final or self.hold <= 0:
            self.pending = b""
            return data
        self.pending = data[-self.hold:] if len(data) > self.hold else data
        return data[:-self.hold] if len(data) > self.hold else b""


def _echo_off(fd: int) -> bool:
    try:
        return not termios.tcgetattr(fd)[3] & termios.ECHO
    except termios.error:
        return False


def _wait_echo_off(fd: int, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if _echo_off(fd):
            return True
        time.sleep(0.05)
    return _echo_off(fd)


def _quiet(fd: int, seconds: float) -> bool:
    ready, _, _ = select.select([fd], [], [], seconds)
    return not ready


def _fork_exec(argv: Sequence[str], env: Mapping[str, str]) -> tuple[int, int]:
    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover - the child
        try:
            os.execvpe(argv[0], list(argv), dict(env))
        finally:
            os._exit(127)
    return pid, fd


def run_on_pty(
    argv: Sequence[str], *, credentials: Credentials | None, log: Path,
    env: Mapping[str, str] | None = None, echo: bool = True,
    accounts: Mapping[str, Account] | None = None,
    stop_grace: float = STOP_GRACE,
) -> int:
    """Run one step as the child of a pty; answer its known prompts.

    Returns the child's exit status.  Raises ``MintError`` (after stopping
    the child) on an unknown credential prompt, on a prompt whose value was
    not collected or names another account, or when the terminal still
    echoes at a known prompt.
    """
    pid, fd = _fork_exec(argv, env if env is not None else os.environ)
    scrubber = Scrubber(credentials.secrets() if credentials else ())
    tail = b""
    failure: str | None = None
    log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    sink = open(log, "wb")
    os.chmod(log, 0o600)

    def emit(data: bytes, final: bool = False) -> None:
        clean = scrubber.feed(data, final=final)
        if clean:
            sink.write(clean)
            sink.flush()
            if echo:
                sys.stdout.buffer.write(clean)
                sys.stdout.buffer.flush()

    try:
        while True:
            try:
                ready, _, _ = select.select([fd], [], [], 1.0)
            except InterruptedError:
                continue
            if not ready:
                continue
            try:
                data = os.read(fd, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not data:
                break
            emit(data)
            tail = (tail + data)[-4096:]
            key, match = match_prompt(tail)
            if key is None and not UNKNOWN_PROMPT.search(last_line(tail)):
                continue
            # A real prompt is followed by silence: more output means the
            # line was only logged, and the next read carries on.
            if not _quiet(fd, QUIET_WAIT):
                continue
            if key is None or credentials is None:
                # getpass turns echo off before it prompts; an echoing
                # terminal here means a logged line, not a question.
                if not _wait_echo_off(fd, QUIET_WAIT):
                    continue
                failure = (
                    "the step asked for a credential this command does not "
                    "recognise; nothing was typed and it was stopped"
                    if key is None else
                    "the step asked for a credential, but this instance is "
                    "agent custody and nothing was collected; it was "
                    "stopped")
                break
            value = credentials.values.get(key)
            if not value:
                failure = (f"the step asked for {key.split(':')[-1]}, which "
                           "was not collected; it was stopped")
                break
            named = (match.groupdict().get("name")
                     if match is not None else None)
            if named is not None and key.startswith("account:"):
                expected = (accounts or {}).get(key.split(":", 1)[1])
                if expected is None or named.decode(
                        "utf-8", "replace") != expected.name:
                    failure = (f"the step names another account for "
                               f"{key.split(':', 1)[1]} than the one "
                               "collected; it was stopped")
                    break
            if not _wait_echo_off(fd, ECHO_WAIT):
                failure = ("a prompt appeared while the terminal still "
                           "echoes; nothing was typed and the step was "
                           "stopped")
                break
            os.write(fd, value.encode("utf-8") + b"\n")
            tail = b""
    except KeyboardInterrupt:
        failure = "interrupted; the step was asked to stop"
    finally:
        emit(b"", final=True)
        if failure is not None:
            sink.write(f"\n[mint] {failure}\n".encode())
        sink.close()
    if failure is not None:
        status = _stop_child(pid, fd, stop_grace)
        raise MintError(failure + (f" (exit {status})"
                                   if status is not None else ""))
    _, wait_status = os.waitpid(pid, 0)
    os.close(fd)
    if scrubber.found:
        raise MintError(f"a credential appeared in the step's output; the "
                        f"log {log} holds it withheld, but treat the run as "
                        "suspect")
    return os.waitstatus_to_exitcode(wait_status)


def _stop_child(pid: int, fd: int, grace: float) -> int | None:
    """SIGINT the step's process group as a terminal would, then escalate.

    The pty's session leader is the step's process group; its runners clean
    up their guests on SIGINT, so SIGTERM and SIGKILL come only after
    *grace* seconds without an exit.  Output is drained meanwhile so the
    child never blocks on a full pty.
    """
    for sig, wait in ((signal.SIGINT, grace), (signal.SIGTERM, 30.0),
                      (signal.SIGKILL, 10.0)):
        try:
            os.killpg(pid, sig)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            try:
                done, status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                return None
            if done:
                with contextlib.suppress(OSError):
                    os.close(fd)
                return os.waitstatus_to_exitcode(status)
            with contextlib.suppress(OSError):
                if select.select([fd], [], [], 0.2)[0]:
                    os.read(fd, 65536)
    return None


# -- the run -----------------------------------------------------------------
def lab_busy() -> list[str]:
    """QEMU processes already running: one lab mutation at a time."""
    try:
        output = subprocess.run(
            ["pgrep", "-a", "qemu-system"], capture_output=True, text=True,
            check=False).stdout
    except FileNotFoundError:
        return []
    return [line.split()[0] for line in output.splitlines() if line.strip()]


def step_argv(options: Options, step: Step, *, apply: bool) -> list[str]:
    argv = [options.make, "--no-print-directory", "-C", str(REPOSITORY),
            step.target]
    argv += [f"{name}={value}" for name, value in step.variables]
    if apply:
        argv.append("APPLY=1")
    return argv


def _run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"


def _write_record(path: Path, record: dict) -> None:
    staging = path.with_name("." + path.name + ".new")
    staging.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    os.chmod(staging, 0o600)
    os.replace(staging, path)


def _write_text(path: Path, text: str) -> None:
    staging = path.with_name("." + path.name + ".new")
    staging.write_text(text, encoding="utf-8")
    os.chmod(staging, 0o600)
    os.replace(staging, path)


def print_plan(options: Options, state: MintState,
               steps: Sequence[Step]) -> None:
    print(f"mint: workstation {options.workstation} (Arch host "
          f"{options.hostname}) against persistent instance "
          f"{options.instance}")
    custody = (state.custody if state.instance is not None
               else (options.custody or "owner"))
    print(f"custody: {custody}"
          + (" (throwaway)" if (state.instance or {}).get("throwaway")
             or (state.instance is None and options.throwaway) else ""))
    if options.identity_overlay is not None:
        print(f"roster: {options.identity_overlay} (IDENTITY_OVERLAY)")
    done = [stage for stage in state.stages()]
    if state.converged():
        print("directory: provisioned")
    if done:
        print("workstation stages already folded: " + ", ".join(done))
    print("steps, in order:")
    for number, step in enumerate(steps, 1):
        print(f"  {number:2}. {step.name:16} make {step.target}  "
              f"-- {step.note}")
    if custody == "owner":
        keys = needed_keys(steps)
        print("asked once, before any step starts, at this terminal: "
              + ", ".join(sorted(keys)) if keys else "nothing is asked")
    else:
        print("nothing is asked: the instance's custody store supplies every "
              "credential")


def mint(options: Options, *, apply: bool, allow_busy: bool = False,
         evidence_root: Path = DEFAULT_EVIDENCE_ROOT,
         ask: Callable[[str], str] | None = None) -> int:
    state = read_state(options.persistent_root, options.instance,
                       options.workstation_root, options.workstation)
    if state.instance is not None and options.custody and \
            options.custody != state.custody:
        raise MintError(
            f"{options.instance} is {state.custody} custody, fixed at "
            "creation; CUSTODY cannot change it")
    if state.instance is None and options.custody == "agent" \
            and not options.throwaway:
        raise MintError("CUSTODY=agent creates only a throwaway instance "
                        "(THROWAWAY=1)")
    if state.accounts_attempted() and not state.accounts_staged():
        raise MintError(
            f"{options.instance} has an unfinished account staging run; "
            "inspect it (homelab-factory-persistent-status) before minting")
    if state.accounts_staged() and state.first_logon():
        raise MintError(
            f"{options.instance}'s accounts were staged with a change at "
            "first logon; this command stages permanent passwords only. Use "
            "the per-stage targets for that instance")
    if (state.workstation is not None and options.windows_run is not None
            and "adopt" in state.stages()):
        options.windows_run = None
    if options.windows_run is None and "adopt" not in state.stages():
        options.windows_run = pending_bundle(evidence_root, options)
        if options.windows_run is not None:
            print(f"resuming with the finished, unadopted Windows bundle "
                  f"{options.windows_run}")
    steps = plan_steps(options, state)
    print_plan(options, state, steps)
    if not apply:
        print("dry run; repeat with APPLY=1")
        return 0
    busy = lab_busy()
    if busy and not allow_busy:
        raise MintError(
            "another QEMU is running (pids " + ", ".join(busy) + "); only one "
            "lab mutation may run at a time")
    free = shutil.disk_usage(REPOSITORY).free
    if free < MIN_FREE_BYTES and any(
            step.name in ("windows-install", "adopt", "arch-install",
                          "arch-join", "windows-join") for step in steps):
        raise MintError(
            f"only {free / 1024 ** 3:.0f} GiB free; a mint needs about "
            f"{MIN_FREE_BYTES / 1024 ** 3:.0f} GiB")
    credentials = None
    accounts: dict[str, Account] = {}
    owner = (state.custody == "owner" if state.instance is not None
             else options.custody != "agent")
    if owner:
        keys = needed_keys(steps)
        roster = roster_accounts()
        credentials = collect_credentials(
            keys, roster, instance=options.instance,
            console_is_canonical=not state.converged(), ask=ask)
        accounts = {account.contract_role: account for account in roster}
    run_id = _run_id()
    evidence = evidence_root / options.instance / options.workstation / run_id
    evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    record = {"schema": 1, "kind": "telos-factory-mint", "run_id": run_id,
              "instance": options.instance,
              "workstation": options.workstation,
              "custody": "owner" if owner else "agent",
              "started_utc": _now(), "steps": [], "result": "running"}
    env = dict(os.environ)
    if options.identity_overlay is not None:
        env["TELOS_IDENTITY_OVERLAY"] = str(
            Path(options.identity_overlay).absolute())
    try:
        for number, step in enumerate(steps, 1):
            planned = step
            if step.name == "adopt" and options.windows_run is not None and \
                    not any(name == "WINDOWS_RUN" for name, _ in step.variables):
                step = Step(step.name, step.target,
                            step.variables
                            + (("WINDOWS_RUN", str(options.windows_run)),),
                            step.asks, step.note)
            attempts = ATTEMPTS.get(step.name, 1)
            for attempt in range(1, attempts + 1):
                if planned.name == "windows-install":
                    # Every attempt installs into a fresh bundle.
                    bundle = prepare_windows(options, evidence, env, number)
                    options.windows_run = bundle
                    _write_text(evidence.parent / PENDING_BUNDLE,
                                f"{bundle}\n")
                    step = Step(planned.name, planned.target,
                                planned.variables
                                + (("WINDOWS_RUN", str(bundle)),),
                                planned.asks, planned.note)
                suffix = "" if attempt == 1 else f"-attempt{attempt}"
                log = evidence / f"{number:02}-{step.name}{suffix}.log"
                entry = {"step": step.name, "target": step.target,
                         "attempt": attempt, "log": log.name,
                         "started_utc": _now()}
                record["steps"].append(entry)
                _write_record(evidence / "mint-run.json", record)
                print(f"\n[mint] {number}/{len(steps)} {step.name}"
                      + (f" (attempt {attempt} of {attempts})"
                         if attempt > 1 else "")
                      + f": make {step.target} (log {log})", flush=True)
                began = time.monotonic()
                status = run_on_pty(step_argv(options, step, apply=True),
                                    credentials=credentials, log=log, env=env,
                                    accounts=accounts)
                entry.update(finished_utc=_now(), exit=status,
                             seconds=round(time.monotonic() - began, 1))
                _write_record(evidence / "mint-run.json", record)
                print(f"[mint] {step.name}: exit {status} after "
                      f"{entry['seconds'] / 60:.1f} min", flush=True)
                if status == 0:
                    break
                if attempt < attempts:
                    print(f"[mint] {step.name} failed; it leaves the kept "
                          "workstation unchanged, so it is repeated",
                          flush=True)
            if step.name == "adopt" and status == 0:
                with contextlib.suppress(FileNotFoundError):
                    (evidence.parent / PENDING_BUNDLE).unlink()
            if status != 0:
                raise MintError(
                    f"step {step.name} failed (exit {status}); its log is "
                    f"{log}. Fix the cause and rerun the same command: it "
                    "resumes at the first unfinished step")
        record["result"] = "pass"
    except BaseException as error:
        record["result"] = "fail"
        record["failure"] = str(error) if isinstance(error, MintError) \
            else type(error).__name__
        raise
    finally:
        record["finished_utc"] = _now()
        _write_record(evidence / "mint-run.json", record)
        if credentials is not None:
            credentials.clear()
    print(f"\n[mint] PASS: {options.workstation} is minted and verified "
          f"against {options.instance}; record {evidence / 'mint-run.json'}")
    return 0


def prepare_windows(options: Options, evidence: Path,
                    env: Mapping[str, str], number: int) -> Path:
    """Prepare a fresh gate-5 bundle; returns its path."""
    log = evidence / f"{number:02}-windows-install-prepare.log"
    argv = [options.make, "--no-print-directory", "-C", str(REPOSITORY),
            "homelab-windows-install-prepare", "APPLY=1"]
    print(f"\n[mint] preparing a Windows install bundle (log {log})",
          flush=True)
    status = run_on_pty(argv, credentials=None, log=log, env=env)
    if status != 0:
        raise MintError(f"windows install preparation failed (exit "
                        f"{status}); log {log}")
    found = None
    for line in log.read_bytes().splitlines():
        match = WINDOWS_BUNDLE.search(line.strip())
        if match:
            found = match.group(1).decode()
    if found is None:
        raise MintError(f"windows install preparation named no bundle; log "
                        f"{log}")
    return Path(found)


def parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--persistent-dc", required=True)
    parser.add_argument("--workstation", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--persistent-root", type=Path,
                        default=DEFAULT_PERSISTENT_ROOT)
    parser.add_argument("--root", type=Path, default=DEFAULT_WORKSTATION_ROOT)
    parser.add_argument("--windows-run", type=Path, default=None)
    parser.add_argument("--custody", choices=("owner", "agent"), default=None)
    parser.add_argument("--throwaway", action="store_true")
    parser.add_argument("--identity-overlay", type=Path, default=None)
    parser.add_argument("--no-backup", action="store_true")
    parser.add_argument("--allow-busy-lab", action="store_true")
    parser.add_argument("--evidence-root", type=Path,
                        default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--apply", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if len(args.hostname) > 15 or not re.fullmatch(
            r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", args.hostname):
        print("error: ARCH_HOSTNAME must be 1-15 lowercase letters, digits "
              "or inner hyphens", file=sys.stderr)
        return 2
    options = Options(
        instance=args.persistent_dc, workstation=args.workstation,
        hostname=args.hostname, persistent_root=args.persistent_root,
        workstation_root=args.root, windows_run=args.windows_run,
        custody=args.custody, throwaway=args.throwaway,
        backup=not args.no_backup, identity_overlay=args.identity_overlay)
    try:
        return mint(options, apply=args.apply,
                    allow_busy=args.allow_busy_lab,
                    evidence_root=args.evidence_root)
    except MintError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted; rerun the same command to resume",
              file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
