"""The durable Arch join (TASK-28 step 7), with every guest faked.

Nothing here boots QEMU or reads ``build/``, ``homelab/var/`` or
``homelab/instance/``: the persistent binding, the account record and the
preflight are constructed, the persistent Controller session, the join
principal protocol, the workstation's QEMU and QMP are doubles, the kept
workstation lives in a temporary directory, and the roster overlay is pinned
to a synthetic one written by this module.  Every realm, SID, name and
credential is synthetic.

The workstation double (``Guest``) answers only what it was asked: each
write must arrive while one of its readers is asking, or the write is
recorded as a violation, which is how "nothing is written before its prompt"
is proven rather than assumed.
"""

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.tests.identity_overlay_pin import (
    overlay_document, pinned_identity_overlay)
from homelab.vm import arch_durable_install_run as durable_install
from homelab.vm import arch_durable_join as join
from homelab.vm import arch_install_run
from homelab.vm import workstation_instance as wi
from homelab.vm.arch_identity_run import (
    ArchIdentityBundle, ArchIdentityError, roster_fingerprint)
from homelab.vm.directory_password_policy import DirectoryPasswordPolicy
from homelab.vm.durable_workstation import DurableBinding
from homelab.vm.persistent_controller_session import FORBIDDEN_FAULT_HOOKS
from homelab.vm.secret_scan import count_secret_occurrences, secret_needles
from homelab.vm.serial_automation import ANSI, SerialAutomationError
from homelab.workstations.arch_second import (
    DOMAIN_ONLINE_MARKER, JOIN_MEDIA_CONSUMED_MARKER, JOIN_VERIFIED_MARKER)


DOMAIN = "durable.example.test"
REALM = DOMAIN.upper()
NETBIOS = "DURABLE"
SID = "S-1-5-21-11-22-33"
INSTANCE = "synthetic-dc"
HOSTNAME = "kept-ws1"
NAMES = {
    "standard_user": "zqx-std",
    "daily_administrator": "zqx-daily",
    "domain_administrator": "zqx-da",
    "local_rescue": "zqx-rescue",
}
#: Every typed value is compliant with the directory's default policy and
#: distinct from every other.
CONSOLE = b"Console-Rescue-7!"
TEMPORARY = b"Temporary-Pass-1!"
NEW = b"Brand-New-Pass-2!"
RESCUE = b"Break-Glass-Pass-3!"
TOKEN = "feedfacefeedface"
#: Values that must never reach a plan line, a result or a message.
PRIVATE_VALUES = (DOMAIN, REALM, SID, NETBIOS, *NAMES.values())
TIMELINE: list[str] = []
#: Every join ISO the boundary built, so its destruction can be checked.
BUILT: list[Path] = []
_REAL_BUILD_JOIN_ISO = arch_install_run.build_arch_join_iso
_REAL_CREATE_OVERLAY = join._create_overlay


def setUpModule():
    unittest.enterModuleContext(
        pinned_identity_overlay(overlay_document(NAMES)))


def plan() -> list[dict]:
    """The durable account plan the pinned overlay resolves to."""
    from homelab.vm import controller_principals as principals
    return principals.directory_account_plan(
        list(principals.DIRECTORY_ROLES),
        roster=principals.durable_directory_roster())


def account_record(*, first_logon: bool = True, **uid_overrides) -> dict:
    return {
        "staged_utc": "2026-09-30T00:00:00+00:00",
        "roster_fingerprint": roster_fingerprint(),
        "accounts": [
            {"contract_role": entry["contract_role"], "role": entry["role"],
             "uidNumber": uid_overrides.get(
                 entry["contract_role"], entry["uidNumber"]),
             "gidNumber": entry["gidNumber"]}
            for entry in plan()],
        "password_change_at_first_logon": first_logon,
    }


def binding(state: Path = Path("/nonexistent/persistent/synthetic-dc"),
            **overrides) -> DurableBinding:
    values = dict(
        instance=INSTANCE, state=state, dns_domain=DOMAIN,
        kerberos_realm=REALM, netbios_name=NETBIOS,
        controller_fqdn=f"bootstrap-dc.{DOMAIN}",
        permanent_dc_fqdn=f"dc1.{DOMAIN}", domain_sid=SID,
        roster_fingerprint=roster_fingerprint(), identity_source="a test")
    values.update(overrides)
    return DurableBinding(**values)


def credentials(*, first_logon: bool = True) -> join.OwnerCredentials:
    return join.OwnerCredentials(
        CONSOLE, TEMPORARY, NEW if first_logon else None, RESCUE)


def secret_hits(chunks, values) -> int:
    return count_secret_occurrences(list(chunks), secret_needles(values))


def _digest(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# -- the workstation, as its console sees it ------------------------------------
class GuestConsole:
    """``SerialAutomation``'s surface over a guest that answers each write.

    ``_wait`` searches exactly as the real one does (ANSI stripped, MULTILINE,
    the buffer trimmed past the match, the raw tail kept as ``transcript``);
    a pattern that is not on the console yet is a timeout, never a guess.
    """

    def __init__(self, guest: "Guest") -> None:
        self.guest = guest
        self.password = None
        self.timeout = 5.0
        self.token = TOKEN
        self.buffer = b""
        self.transcript = b""
        self.events: list[str] = []
        self.writer = io.BytesIO()
        self.reader = io.BytesIO()

    def emit(self, data: bytes) -> None:
        self.buffer += data
        self.transcript += data

    def _send(self, value: bytes, event: str) -> None:
        self.events.append(event)
        TIMELINE.append(f"send:{event}")
        self.guest.receive(value, event)

    def _wait(self, pattern: bytes, label: str):
        clean = ANSI.sub(b"", self.buffer)
        match = re.compile(pattern, re.MULTILINE).search(clean)
        if match is None:
            raise SerialAutomationError(f"timed out waiting for {label}")
        self.buffer = clean[match.end():]
        self.events.append(label)
        TIMELINE.append(f"wait:{label}")
        return match

    def release_password(self) -> None:
        self.password = None


class Guest:
    """A joined durable Arch guest: getty, pam_sss, sudo, passwd, a root shell.

    *echo* models a reader that did NOT turn echo off: every credential
    written at a password prompt comes back on the console.  *expired* is
    whether the directory marks the daily administrator's password for a
    change at first logon.
    """

    def __init__(self, accounts, *, echo=False, expired=True,
                 temporary=TEMPORARY, uids=None, sealed=True, online=True,
                 host=HOSTNAME, change_diagnostic=None, fingerprint=None):
        self.console = GuestConsole(self)
        self.accounts = list(accounts)
        self.daily = next(a["name"] for a in self.accounts
                          if a["contract_role"] == "daily_administrator")
        self.echo = echo
        self.expired = expired
        self.password = temporary
        self.uids = uids or {a["name"]: a["uidNumber"] for a in self.accounts}
        self.sealed, self.online, self.host = sealed, online, host
        self.change_diagnostic = change_diagnostic
        self.fingerprint = fingerprint or roster_fingerprint()
        #: The one reader currently asking; a write with none is a violation.
        self.asking: str | None = None
        self.writes: list[tuple[str, bytes]] = []
        self.violations: list[str] = []
        self.names_line: bytes | None = None
        self.checks_command: bytes | None = None
        self.pending_new: bytes | None = None
        self.rescue_password: bytes | None = None
        self.process = None

    # -- the console's input ---------------------------------------------
    def emit(self, data: bytes) -> None:
        self.console.emit(data)

    def ask(self, reader: str, prompt: bytes) -> None:
        self.asking = reader
        self.emit(prompt)

    def boot_to_getty(self) -> None:
        """What the guest prints after the join media were destroyed."""
        self.emit(("\r\n" + JOIN_VERIFIED_MARKER + "\r\n"
                   + DOMAIN_ONLINE_MARKER + "\r\n\r\n").encode())
        self.ask("getty", HOSTNAME.encode() + b" login: ")

    def receive(self, value: bytes, event: str) -> None:
        self.writes.append((event, value))
        reader, self.asking = self.asking, None
        secret_reader = reader in (
            "password", "current", "new", "retype", "sudo", "rescue-new",
            "rescue-retype", "names")
        if reader is None:
            self.violations.append(event)
        # A getty and a shell echo what is typed at them; a password reader
        # echoes only when it is broken, which is what *echo* models.
        if reader in ("getty", "shell", "root") or (
                self.echo and secret_reader):
            self.emit(value + b"\r\n")
        handler = getattr(self, "on_" + event.replace("-", "_"), None)
        if handler is not None:
            handler(value, reader)

    def shell(self, user: bytes) -> None:
        """The first prompt after a login, behind util-linux's lastlog line."""
        self.ask("shell", b"\r\nLast login: never\r\n[" + user + b"@"
                 + HOSTNAME.encode() + b" ~]$ ")

    def prompt(self) -> None:
        self.ask("shell", b"[" + self.daily.encode() + b"@"
                 + HOSTNAME.encode() + b" ~]$ ")

    # -- the getty and pam_sss ----------------------------------------------
    def on_arch_login_username_sent(self, value, reader):
        if reader != "getty" or value != self.daily.encode():
            self.violations.append("username")
        self.ask("password", b"Password: ")

    def on_arch_login_password_sent(self, value, reader):
        if value != self.password:
            self.emit(b"\r\nLogin incorrect\r\n")
            self.ask("getty", HOSTNAME.encode() + b" login: ")
        elif self.expired:
            self.emit(b"\r\nPassword expired. Change your password now.\r\n")
            self.ask("current", b"Current Password: ")
        else:
            self.shell(self.daily.encode())

    def on_arch_first_logon_current_sent(self, value, reader):
        if reader != "current" or value != self.password:
            self.violations.append("current")
        self.ask("new", b"\r\nNew Password: ")

    def on_arch_first_logon_new_sent(self, value, reader):
        if reader == "new":
            self.pending_new = value
            self.ask("retype", b"\r\nReenter new Password: ")
            return
        if reader != "retype" or value != self.pending_new:
            self.violations.append("retype")
            return
        if self.change_diagnostic is not None:
            self.emit(b"\r\n" + self.change_diagnostic + b"\r\n")
            self.ask("getty", HOSTNAME.encode() + b" login: ")
            return
        self.password, self.expired = value, False
        self.shell(self.daily.encode())

    # -- gate 8's roster proof, elevation and break-glass passwd -------------
    def on_arch_probe_roster_sent(self, value, reader):
        self.emit(b"\r\n__TELOS_ARCH_ROSTER_" + TOKEN.encode() + b"="
                  + self.fingerprint.encode() + b"\r\n")
        self.prompt()

    def on_arch_sudo_command_sent(self, value, reader):
        self.emit(b"\r\n__TELOS_ARCH_SUDO_READY_" + TOKEN.encode() + b"__\r\n")
        self.ask("sudo", b"__TELOS_ARCH_SUDO_PROMPT_" + TOKEN.encode() + b"__")

    def on_arch_sudo_password_sent(self, value, reader):
        if value != self.password:
            self.violations.append("sudo-password")
        self.ask("root", b"\r\n[root@" + HOSTNAME.encode() + b" ~]# ")

    def on_arch_root_proof_requested(self, value, reader):
        self.emit(b"\r\n__TELOS_ARCH_ROOT_" + TOKEN.encode() + b"=0\r\n")
        self.ask("root", b"[root@" + HOSTNAME.encode() + b" ~]# ")

    def on_arch_rescue_command_sent(self, value, reader):
        self.emit(b"\r\n__TELOS_ARCH_RESCUE_READY_" + TOKEN.encode()
                  + b"__\r\n")
        self.ask("rescue-new", b"New Password: ")

    def on_arch_rescue_password_sent(self, value, reader):
        if reader == "rescue-new":
            self.ask("rescue-retype", b"\r\nReenter new Password: ")
            return
        self.rescue_password = value
        self.emit(b"\r\npasswd: password updated successfully\r\n"
                  b"__TELOS_ARCH_RESCUE_RC_" + TOKEN.encode() + b"=0\r\n")
        self.ask("root", b"[root@" + HOSTNAME.encode() + b" ~]# ")

    # -- the root-shell proofs and the poweroff --------------------------------
    def on_arch_join_checks_sent(self, value, reader):
        self.checks_command = value
        self.emit(b"\r\n__TELOS_ARCH_JOIN_CHECK_READY_" + TOKEN.encode()
                  + b"__\r\n")
        self.asking = "names"

    def on_arch_join_checks_names_sent(self, value, reader):
        self.names_line = value
        domain, *names = value.decode().split()
        tok = TOKEN.encode()
        lines = [
            b"__TELOS_ARCH_JOIN_SEALED_" + tok + b"="
            + (b"1" if self.sealed else b"0"),
            b"__TELOS_ARCH_JOIN_ONLINE_" + tok + b"="
            + (b"1" if self.online and domain == DOMAIN else b"0"),
            b"__TELOS_ARCH_JOIN_HOST_" + tok + b"=" + self.host.encode(),
        ]
        for index, name in enumerate(names):
            uid = self.uids.get(name)
            lines.append(b"__TELOS_ARCH_JOIN_UID_" + tok + b"="
                         + str(index).encode() + b"="
                         + (b"none" if uid is None else str(uid).encode()))
        lines.append(b"__TELOS_ARCH_JOIN_DONE_" + tok + b"=0")
        self.emit(b"\r\n" + b"\r\n".join(lines) + b"\r\n")
        self.ask("root", b"[root@" + HOSTNAME.encode() + b" ~]# ")

    def on_arch_join_poweroff_sent(self, value, reader):
        self.emit(b"\r\n[  OK  ] Reached target System Power Off.\r\n"
                  b"reboot: Power down\r\n")
        if self.process is not None:
            self.process.exited = True


# -- processes, QMP, the persistent session -------------------------------------
class FakeProcess:
    def __init__(self, role: str, pid: int) -> None:
        self.role = role
        self.pid = pid
        self.stdout = io.BytesIO()
        self.stdin = io.BytesIO()
        self.exited = False
        self.terminated = False

    def poll(self):
        return 0 if (self.exited or self.terminated) else None

    def terminate(self):
        TIMELINE.append(f"terminate:{self.role}")
        self.terminated = True

    def kill(self):
        self.terminated = True

    def wait(self, timeout=None):
        if not (self.exited or self.terminated):
            raise subprocess.TimeoutExpired(self.role, timeout)
        return 0


class FakeQmp:
    """Holds the join ISO's inode like QEMU, and drives the guest's join."""

    def __init__(self, guest: Guest) -> None:
        self.guest = guest
        self.calls: list[str] = []
        self.held: set[tuple[int, int]] = set()

    def execute(self, command, arguments=None, **_kwargs):
        self.calls.append(command)
        if command == "blockdev-add":
            source = Path(arguments["file"]["filename"]).stat()
            self.held.add((source.st_dev, source.st_ino))
        if command == "device_add":
            TIMELINE.append("join-media-attached")
            self.guest.emit(
                ("\r\n" + JOIN_MEDIA_CONSUMED_MARKER + "\r\n").encode())
        if command == "device_del":
            TIMELINE.append("join-media-removed")
        if command == "blockdev-del":
            self.held.clear()
            # The media are gone; the guest joins, seals, and reaches the
            # getty once its domain-online gate passes.
            self.guest.boot_to_getty()
        return {}

    def holds_inode(self, device, inode):
        return (device, inode) in self.held

    def await_device_deleted(self, device, timeout=None):
        return {"event": "DEVICE_DELETED", "data": {"device": device}}

    def close(self):
        self.calls.append("close")


class ControllerConsole:
    def __init__(self) -> None:
        self.reader = io.BytesIO()
        self.writer = io.BytesIO()
        self.password = CONSOLE
        self.timeout = 300.0
        self.events: list[str] = []
        self.transcript = b""


class FakeSession:
    """The persistent session's surface; it records any reach for a fault."""

    instances: list["FakeSession"] = []

    def __init__(self, target, *, port, password, canonical_state):
        object.__setattr__(self, "forbidden", [])
        self.target = target
        self.port = port
        self.password = password
        self.console = ControllerConsole()
        self.facts = {"launches": 0, "logins": 0, "live_argv_audited": False,
                      "clean_poweroffs": 0, "terminated_fallback": False,
                      "lock_released": True}
        self.redaction_secrets: list = []
        self.closed = False
        FakeSession.instances.append(self)

    def __getattr__(self, name):
        if name in FORBIDDEN_FAULT_HOOKS:
            self.forbidden.append(name)
        raise AttributeError(name)

    def start(self, *, attached=None):
        TIMELINE.append("session-start")
        self.facts.update(launches=1, logins=1, live_argv_audited=True,
                          lock_released=False)
        if attached is not None:
            attached()
        return self.console

    def stop(self, label="persistent-session-poweroff"):
        TIMELINE.append("session-stop")
        self.facts.update(clean_poweroffs=1, lock_released=True)

    def redacted_transcript(self, extra_secrets=()):
        self.redaction_secrets = list(extra_secrets)
        return b"bootstrap-dc login: local-rescue\r\nPassword: \r\n$ "

    def close(self):
        self.closed = True


class FakeJoinSerial:
    instances: list["FakeJoinSerial"] = []

    def __init__(self, console) -> None:
        self.console = console
        self._principal = "tj-" + "0" * 16
        self.credential: str | None = None
        FakeJoinSerial.instances.append(self)

    def stage(self, credential):
        from homelab.vm.controller_join_material import ControllerJoinResult
        TIMELINE.append("stage-join-principal")
        self.credential = credential
        return ControllerJoinResult(
            operation="stage", principal=self._principal,
            destruction_proved=False, events=())

    def destroy(self):
        from homelab.vm.controller_join_material import ControllerJoinResult
        TIMELINE.append("destroy-join-principal")
        return ControllerJoinResult(
            operation="destroy", principal=self._principal,
            destruction_proved=True, events=())


def _build_join_iso(output, material, **_kwargs):
    """The real builder, with xorriso stood in for (it is no test dependency)."""
    def runner(argv, **_options):
        Path(argv[argv.index("-o") + 1]).write_bytes(b"iso-image")
        return subprocess.CompletedProcess(argv, 0)

    TIMELINE.append("join-media-built")
    BUILT.append(Path(output))
    return _REAL_BUILD_JOIN_ISO(output, material, runner=runner)


def _drive_boot_menu(console, facts, **_kwargs):
    """Gate 8's menu drive is gate 8's to test; here it only takes its turn."""
    TIMELINE.append("boot-menu-driven")
    facts.update(menu_seen=True, entry_committed=True, handoff_seen=True)


def _probe_directory(console, bound, checks):
    TIMELINE.append("directory-proved")
    checks.update(realm_matches=True, domain_sid="match")
    return SID


class WiredBoundary(join.DurableArchJoinBoundary):
    """The real boundary with only processes, QMP and consoles doubled."""

    def __init__(self, bundle, *, guest: Guest, **options) -> None:
        super().__init__(bundle, session_factory=FakeSession, **options)
        self.guest = guest
        self.spawned: list[tuple[str, list[str]]] = []
        self.qmp = FakeQmp(guest)

    def _spawn(self, role, command, *, pass_fds=(), stdio=False):
        TIMELINE.append(f"spawn:{role}")
        process = FakeProcess(role, 4000 + len(self.spawned))
        self.spawned.append((role, list(command)))
        self._processes[role] = process
        if role == "workstation":
            self.guest.process = process
        return process

    def _audit(self, role, pid, **_kwargs):
        pass

    def _wait_switch_port(self, name, mac):
        TIMELINE.append(f"port:{name}")

    def _connect_qmp(self, path, pid):
        return self.qmp

    def _arm_progress(self):
        return None

    def _join_serial(self, console):
        return FakeJoinSerial(console)

    def _workstation_serial(self, process):
        return self.guest.console


class _Seams(unittest.TestCase):
    """The module-level seams every boundary test replaces."""

    def setUp(self):
        TIMELINE.clear()
        BUILT.clear()
        FakeSession.instances = []
        FakeJoinSerial.instances = []
        for target, value in (
                ("homelab.vm.arch_durable_join.drive_boot_menu",
                 _drive_boot_menu),
                ("homelab.vm.arch_durable_join._probe_directory",
                 _probe_directory),
                ("homelab.vm.arch_install_run.build_arch_join_iso",
                 _build_join_iso)):
            patcher = mock.patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.accounts = join.planned_accounts(account_record())


# -- the owner's credentials ------------------------------------------------------
class Prompter:
    def __init__(self, *values: bytes) -> None:
        self.values = list(values)
        self.asked: list[tuple[str, bool]] = []

    def __call__(self, text, *, confirm=None):
        self.asked.append((text, confirm is not None))
        return self.values.pop(0)


class CredentialTests(unittest.TestCase):
    def ask(self, mode, *values):
        prompter = Prompter(*values)
        result = join.owner_credentials(
            mode, daily_name="zqx-daily", rescue_name="zqx-rescue",
            instance=INSTANCE, prompt=prompter)
        return result, prompter.asked

    def test_first_logon_prompts_in_order_and_confirms_each_new_value(self):
        result, asked = self.ask(
            join.MODE_FIRST_LOGON, CONSOLE, TEMPORARY, NEW, RESCUE)
        self.assertEqual([confirm for _text, confirm in asked],
                         [False, False, True, True])
        texts = [text for text, _confirm in asked]
        self.assertIn("local-rescue console password", texts[0])
        self.assertIn("TEMPORARY password for daily_administrator", texts[1])
        self.assertIn("NEW password for daily_administrator", texts[2])
        self.assertIn("break-glass password for the Arch", texts[3])
        self.assertEqual(result.values(), [CONSOLE, TEMPORARY, NEW, RESCUE])
        self.assertNotIn(TEMPORARY.decode(), repr(result))

    def test_a_retry_asks_for_the_current_password_instead(self):
        result, asked = self.ask(join.MODE_CURRENT, CONSOLE, NEW, RESCUE)
        texts = [text for text, _confirm in asked]
        self.assertEqual(len(texts), 3)
        self.assertIn("CURRENT password for daily_administrator", texts[1])
        self.assertIsNone(result.new_daily)
        self.assertEqual(result.daily, NEW)

    def test_policy_violating_new_passwords_are_refused_by_rule(self):
        cases = (
            ((CONSOLE, TEMPORARY, b"Sh1!", RESCUE), "shorter than"),
            ((CONSOLE, TEMPORARY, b"alllowercase", RESCUE), "fewer than"),
            ((CONSOLE, TEMPORARY, b"Zqx-Daily-99", RESCUE), "account name"),
            ((CONSOLE, TEMPORARY, NEW, b"weakweak"), "break-glass"),
        )
        for values, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(
                        join.ArchDurableJoinError, reason) as caught:
                    self.ask(join.MODE_FIRST_LOGON, *values)
                for value in values[2:]:
                    self.assertNotIn(value.decode(), str(caught.exception))
                self.assertIn("Nothing was booted", str(caught.exception))

    def test_a_recorded_relaxed_policy_takes_short_new_passwords(self):
        """Owner decision 2026-09-30: short passwords on ``rehearsal``."""
        relaxed = DirectoryPasswordPolicy(
            min_length=4, complexity=False, min_age_days=0,
            source=f"{INSTANCE}'s recorded directory policy")

        def ask(*values):
            return join.owner_credentials(
                join.MODE_FIRST_LOGON, daily_name="zqx-daily",
                rescue_name="zqx-rescue", instance=INSTANCE,
                prompt=Prompter(*values), policy=relaxed)

        result = ask(CONSOLE, TEMPORARY, b"q7xz", b"k9wv")
        self.assertEqual(result.values(), [CONSOLE, TEMPORARY, b"q7xz",
                                           b"k9wv"])
        for values, label in (((CONSOLE, TEMPORARY, b"q7x", b"k9wv"),
                               "new daily_administrator"),
                              ((CONSOLE, TEMPORARY, b"q7xz", b"k9w"),
                               "break-glass")):
            with self.subTest(label=label):
                with self.assertRaises(join.ArchDurableJoinError) as caught:
                    ask(*values)
                message = str(caught.exception)
                self.assertIn(f"the {label} password is shorter than 4 "
                              f"characters; {INSTANCE}'s recorded directory "
                              "policy would refuse it. Nothing was booted",
                              message)
                for value in values[2:]:
                    self.assertNotIn(value.decode(), message)
        # Distinctness still holds under any policy.
        with self.assertRaisesRegex(join.ArchDurableJoinError, "distinct"):
            ask(CONSOLE, TEMPORARY, b"q7xz", b"q7xz")

    def test_without_a_record_the_refusal_names_the_default_as_before(self):
        with self.assertRaises(join.ArchDurableJoinError) as caught:
            self.ask(join.MODE_FIRST_LOGON, CONSOLE, TEMPORARY, b"Sh1!",
                     RESCUE)
        self.assertEqual(
            str(caught.exception),
            "the new daily_administrator password is shorter than 7 "
            "characters; the directory's default policy would refuse it. "
            "Nothing was booted")

    def test_every_credential_must_be_distinct(self):
        for values in ((CONSOLE, TEMPORARY, NEW, NEW),
                       (CONSOLE, TEMPORARY, TEMPORARY, RESCUE),
                       (RESCUE, TEMPORARY, NEW, RESCUE)):
            with self.subTest(values=len(set(values))):
                with self.assertRaisesRegex(
                        join.ArchDurableJoinError, "distinct"):
                    self.ask(join.MODE_FIRST_LOGON, *values)


# -- the first-logon exchange -------------------------------------------------------
class FirstLogonTests(unittest.TestCase):
    def setUp(self):
        TIMELINE.clear()

    def login(self, guest: Guest, *, password=TEMPORARY, new=NEW):
        guest.ask("getty", b"\r\n" + HOSTNAME.encode() + b" login: ")
        facts: dict = {}
        return facts, lambda: join.first_logon_login(
            guest.console, facts, username=guest.daily.encode(),
            password=password, new_password=new)

    def guest(self, **options) -> Guest:
        return Guest([{"contract_role": "daily_administrator",
                       "name": "zqx-daily", "uidNumber": 10001}], **options)

    def test_the_expired_password_exchange_answers_each_ask_once(self):
        guest = self.guest()
        facts, login = self.login(guest)
        self.assertEqual(login(), NEW)
        self.assertEqual(guest.violations, [])
        self.assertEqual(guest.writes, [
            ("arch-login-username-sent", b"zqx-daily"),
            ("arch-login-password-sent", TEMPORARY),
            ("arch-first-logon-current-sent", TEMPORARY),
            ("arch-first-logon-new-sent", NEW),
            ("arch-first-logon-new-sent", NEW),
        ])
        self.assertTrue(facts["expired_notice_seen"])
        self.assertTrue(facts["password_changed"])
        self.assertIs(facts["password_change_landed"], True)
        self.assertEqual(facts["new_password_writes"], 2)
        self.assertFalse(facts["echo_observed"])
        self.assertEqual(guest.password, NEW)
        # Nothing typed is on the console: every reader had echo off.
        self.assertEqual(secret_hits([guest.console.transcript],
                                     [TEMPORARY, NEW]), 0)
        self.assertNotIn(TEMPORARY.decode(), json.dumps(facts))

    def test_an_echoing_reader_stops_the_exchange_after_one_write(self):
        guest = self.guest(echo=True)
        facts, login = self.login(guest)
        with self.assertRaisesRegex(join.ArchDurableJoinError, "echoing"):
            login()
        self.assertTrue(facts["echo_observed"])
        # The username and the temporary password, and nothing more: the
        # echo was seen before the next ask was answered.
        self.assertEqual([event for event, _value in guest.writes], [
            "arch-login-username-sent", "arch-login-password-sent"])
        self.assertFalse(facts["password_changed"])

    def test_retry_mode_logs_straight_in_with_the_current_password(self):
        guest = self.guest(expired=False, temporary=NEW)
        facts, login = self.login(guest, password=NEW, new=None)
        self.assertEqual(login(), NEW)
        self.assertEqual([event for event, _value in guest.writes], [
            "arch-login-username-sent", "arch-login-password-sent"])
        self.assertEqual(facts["first_logon_mode"], join.MODE_CURRENT)
        self.assertTrue(facts["login_completed"])
        self.assertFalse(facts["password_changed"])

    def test_retry_mode_refuses_a_change_still_pending_without_writing(self):
        guest = self.guest(expired=True, temporary=NEW)
        facts, login = self.login(guest, password=NEW, new=None)
        with self.assertRaisesRegex(join.ArchDurableJoinError,
                                    "without FIRST_LOGON_DONE"):
            login()
        self.assertEqual(len(guest.writes), 2)

    def test_a_temporary_the_directory_never_expired_is_refused(self):
        guest = self.guest(expired=False)
        facts, login = self.login(guest)
        with self.assertRaisesRegex(join.ArchDurableJoinError,
                                    "was NOT set"):
            login()
        self.assertEqual(len(guest.writes), 2)
        self.assertFalse(facts["password_change_landed"])

    def test_a_refused_temporary_writes_nothing_more(self):
        guest = self.guest(temporary=b"Another-Value-9!")
        facts, login = self.login(guest)
        with self.assertRaisesRegex(join.ArchDurableJoinError,
                                    "TEMPORARY password"):
            login()
        self.assertEqual(len(guest.writes), 2)

    def test_a_failed_change_names_its_category_and_never_its_text(self):
        guest = self.guest(change_diagnostic=(
            b"Password change failed. Server message: Password does not "
            b"meet complexity requirements"))
        facts, login = self.login(guest)
        with self.assertRaisesRegex(join.ArchDurableJoinError,
                                    "password-change-failed"):
            login()
        self.assertEqual(facts["password_change_failure"],
                         "password-change-failed")
        self.assertEqual(len(guest.writes), 5)

    def test_the_outcome_pattern_tells_the_two_new_password_asks_apart(self):
        pattern = re.compile(join.first_logon_outcome_pattern(), re.MULTILINE)
        for text, group in (
                (b"\nNew Password: ", "new"),
                (b"\nReenter new Password: ", "retype"),
                (b"\nRetype new password: ", "retype"),
                (b"\nCurrent Password: ", "current"),
                (b"\nPassword expired. Change your password now.", "expired"),
                (b"\nLogin incorrect", "incorrect"),
                (b"\nkept-ws1 login: ", "getty"),
                (b"\nLast login: never\n[zqx-daily@kept-ws1 ~]$ ", "shell"),
                (b"\n[zqx-daily@kept-ws1 ~]$ ", "shell")):
            with self.subTest(text=text):
                self.assertEqual(pattern.search(text).lastgroup, group)


class RealConsoleFirstLogonTests(unittest.TestCase):
    """The same exchange through the real ``SerialAutomation`` over pipes."""

    def test_a_crlf_transcript_with_escapes_drives_the_real_console(self):
        from homelab.vm.serial_automation import SerialAutomation

        guest_read, guest_write = os.pipe()
        sink_read, sink_write = os.pipe()
        reader = os.fdopen(guest_read, "rb", buffering=0)
        writer = os.fdopen(sink_write, "wb", buffering=0)
        feeder = os.fdopen(guest_write, "wb", buffering=0)
        self.addCleanup(reader.close)
        self.addCleanup(writer.close)
        self.addCleanup(lambda: os.close(sink_read))
        console = SerialAutomation(reader, writer, None, timeout=2.0)
        feeder.write(
            b"\x1b[0m\r\nkept-ws1 login: zqx-daily\r\nPassword: \r\n"
            b"Password expired. Change your password now.\r\n"
            b"Current Password: \r\nNew Password: \r\n"
            b"Reenter new Password: \r\nLast login: never\r\n"
            b"\x1b[1m[zqx-daily@kept-ws1 ~]$ ")
        feeder.close()
        facts: dict = {}
        live = join.first_logon_login(
            console, facts, username=b"zqx-daily", password=TEMPORARY,
            new_password=NEW)
        self.assertEqual(live, NEW)
        os.set_blocking(sink_read, False)
        sent = os.read(sink_read, 4096)
        self.assertEqual(sent, b"zqx-daily\n" + TEMPORARY + b"\n"
                         + TEMPORARY + b"\n" + NEW + b"\n" + NEW + b"\n")
        self.assertTrue(facts["password_changed"])


class ConsoleTeeTests(unittest.TestCase):
    def test_a_short_prompt_on_a_buffered_pipe_is_read_and_kept(self):
        # Gate 8 spawns the workstation with default buffering, so the tee
        # must not ask the pipe for a whole 4 KiB before returning.
        read_end, write_end = os.pipe()
        with os.fdopen(read_end, "rb") as buffered:
            os.write(write_end, b"kept-ws1 login: ")
            sink = bytearray()
            tee = join._ConsoleTee(buffered, sink, limit=8)
            self.assertEqual(tee.read1(4096), b"kept-ws1 login: ")
            self.assertEqual(bytes(sink), b" login: ")
            self.assertEqual(tee.fileno(), buffered.fileno())
            os.close(write_end)
            self.assertEqual(tee.read1(4096), b"")

    def test_the_real_console_reads_through_the_tee(self):
        from homelab.vm.serial_automation import SerialAutomation

        read_end, write_end = os.pipe()
        with os.fdopen(read_end, "rb") as buffered:
            sink = bytearray()
            console = SerialAutomation(
                join._ConsoleTee(buffered, sink), io.BytesIO(), None,
                timeout=2.0)
            os.write(write_end, b"\r\nkept-ws1 login: ")
            console._wait(join.LOGIN_PROMPT, "arch-getty-observed")
            os.close(write_end)
        self.assertIn(b"kept-ws1 login:", bytes(sink))


# -- the root-shell proofs -----------------------------------------------------------
class IdentityCheckTests(unittest.TestCase):
    def setUp(self):
        TIMELINE.clear()
        self.accounts = join.planned_accounts(account_record())

    def prove(self, **guest_options):
        guest = Guest(self.accounts, **guest_options)
        guest.ask("root", b"[root@kept-ws1 ~]# ")
        facts: dict = {}
        try:
            join.prove_joined_identity(
                guest.console, facts, domain=DOMAIN, accounts=self.accounts,
                hostname=HOSTNAME)
        finally:
            self.guest, self.facts = guest, facts
        return guest, facts

    def test_every_role_resolves_at_its_pinned_uid_by_name_free_command(self):
        guest, facts = self.prove()
        self.assertTrue(facts["join_once_sealed"])
        self.assertTrue(facts["sssd_online"])
        self.assertTrue(facts["uids_pinned"])
        self.assertTrue(facts["hostname_matches"])
        self.assertEqual(guest.violations, [])
        self.assertEqual(
            sorted(facts["identity_checks"]),
            sorted(account["contract_role"] for account in self.accounts))
        # The typed command names nobody; the names travel only in the line
        # the echo-off read consumed, and never reach the transcript.
        for value in PRIVATE_VALUES:
            self.assertNotIn(value.encode(), guest.checks_command)
            self.assertNotIn(value.encode(), guest.console.transcript)
        self.assertEqual(guest.names_line.decode().split(),
                         [DOMAIN] + [a["name"] for a in self.accounts])
        self.assertNotIn("zqx", json.dumps(facts))

    def test_a_pinned_uid_mismatch_refuses_naming_the_role_only(self):
        uids = {account["name"]: account["uidNumber"]
                for account in self.accounts}
        uids["zqx-da"] += 7
        with self.assertRaisesRegex(
                join.ArchDurableJoinError,
                "record pins: domain_administrator") as caught:
            self.prove(uids=uids)
        self.assertNotIn("zqx", str(caught.exception))
        entry = self.facts["identity_checks"]["domain_administrator"]
        self.assertFalse(entry["match"])
        self.assertFalse(self.facts["uids_pinned"])

    def test_an_unresolved_role_refuses(self):
        uids = {account["name"]: account["uidNumber"]
                for account in self.accounts}
        del uids["zqx-std"]
        with self.assertRaisesRegex(join.ArchDurableJoinError,
                                    "standard_user"):
            self.prove(uids=uids)
        self.assertIsNone(
            self.facts["identity_checks"]["standard_user"]["observed_uid"])

    def test_unsealed_offline_and_foreign_host_are_each_refused(self):
        for options, reason in (
                ({"sealed": False}, "not sealed"),
                ({"online": False}, "online"),
                ({"host": "other-ws"}, "host name")):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(join.ArchDurableJoinError, reason):
                    self.prove(**options)

    def test_names_that_are_not_one_shell_word_are_never_sent(self):
        accounts = [dict(account, name="two words")
                    if account["contract_role"] == "daily_administrator"
                    else account for account in self.accounts]
        guest = Guest(accounts)
        guest.ask("root", b"# ")
        with self.assertRaisesRegex(join.ArchDurableJoinError, "shell word"):
            join.prove_joined_identity(
                guest.console, {}, domain=DOMAIN, accounts=accounts,
                hostname=HOSTNAME)
        self.assertEqual(guest.writes, [])


class AccountPlanTests(unittest.TestCase):
    def test_the_record_pins_every_directory_role(self):
        accounts = join.planned_accounts(account_record())
        self.assertEqual(
            [account["contract_role"] for account in accounts],
            ["standard_user", "daily_administrator", "domain_administrator"])
        self.assertEqual(join.account_name(accounts, "daily_administrator"),
                         "zqx-daily")

    def test_a_record_pinning_another_uid_is_refused_before_anything(self):
        with self.assertRaisesRegex(
                join.ArchDurableJoinError, "daily_administrator") as caught:
            join.planned_accounts(account_record(daily_administrator=12345))
        self.assertNotIn("zqx", str(caught.exception))

    def test_a_record_with_other_roles_is_refused(self):
        record = account_record()
        record["accounts"] = record["accounts"][:2]
        with self.assertRaisesRegex(join.ArchDurableJoinError, "different"):
            join.planned_accounts(record)


# -- the boundary: ordering, custody, no faults -----------------------------------------
class BoundaryTests(_Seams):
    def boundary(self, *, mode=join.MODE_FIRST_LOGON, **guest_options):
        run_dir = self.tmp / "run"
        run_dir.mkdir(mode=0o700)
        (run_dir / "evidence").mkdir(mode=0o700)
        for name, body in (("arch-workstation.qcow2", b"synthetic overlay"),
                           ("OVMF_VARS.fd", b"synthetic vars")):
            (run_dir / name).write_bytes(body)
            (run_dir / name).chmod(0o600)
        bundle = ArchIdentityBundle(run_dir, self.tmp / "canonical")
        bundle.realm = REALM
        if mode == join.MODE_CURRENT:
            guest_options.setdefault("expired", False)
            guest_options.setdefault("temporary", TEMPORARY)
        self.guest = Guest(self.accounts, **guest_options)
        self.run_dir = run_dir
        return WiredBoundary(
            bundle, guest=self.guest, binding=binding(),
            target=mock.sentinel.persistent_instance,
            credentials=credentials(first_logon=mode == join.MODE_FIRST_LOGON),
            accounts=self.accounts, hostname=HOSTNAME, mode=mode,
            canonical_state=self.tmp / "canonical", duration=600)

    def drive(self, boundary):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(output):
            try:
                join.drive_join(boundary)
            finally:
                self.output = output.getvalue()

    def test_the_join_is_ordered_and_every_check_passes(self):
        boundary = self.boundary()
        self.drive(boundary)
        self.assertTrue(join.passed(boundary), boundary.checks)
        self.assertEqual(self.guest.violations, [])
        order = [
            "spawn:switch", "spawn:gateway", "port:gateway", "session-start",
            "port:controller", "directory-proved", "stage-join-principal",
            "spawn:workstation", "join-media-built", "boot-menu-driven",
            "join-media-attached", "wait:arch-join-media-consumed",
            "join-media-removed", "wait:arch-join-verified",
            "destroy-join-principal", "wait:arch-domain-online-observed",
            "wait:arch-getty-observed", "send:arch-first-logon-new-sent",
            "send:arch-probe-roster-sent", "send:arch-sudo-password-sent",
            "send:arch-rescue-password-sent", "send:arch-join-checks-sent",
            "send:arch-join-poweroff-sent", "session-stop",
            "terminate:switch",
        ]
        positions = [TIMELINE.index(entry) for entry in order]
        self.assertEqual(positions, sorted(positions), TIMELINE)
        # Exactly one principal, staged once and destroyed once.
        self.assertEqual(TIMELINE.count("stage-join-principal"), 1)
        self.assertEqual(TIMELINE.count("destroy-join-principal"), 1)
        self.assertEqual(len(FakeJoinSerial.instances), 1)
        self.assertIs(FakeJoinSerial.instances[0].console,
                      FakeSession.instances[0].console)
        # The ISO is gone and the media were hot-removed and released.
        self.assertEqual(len(BUILT), 1)
        self.assertFalse(BUILT[0].exists())
        self.assertEqual(
            [call for call in self.qmp_calls(boundary)
             if call != "close"],
            ["blockdev-add", "device_add", "device_del", "blockdev-del"])
        self.assertTrue(boundary.facts["join_sealed_by_marker"])
        self.assertEqual(self.guest.rescue_password, RESCUE)
        self.assertTrue(boundary.checks["password_changed"])

    def qmp_calls(self, boundary):
        return boundary.qmp.calls

    def test_the_fabric_is_the_persistent_one_and_the_boot_is_disk_only(self):
        boundary = self.boundary()
        self.drive(boundary)
        commands = dict(boundary.spawned)
        self.assertIn("controller=52:54:00:11:11:11", " ".join(
            commands["switch"]))
        self.assertIn("--identity-mode", commands["gateway"])
        self.assertIn("52:54:00:11:11:11", commands["gateway"])
        self.assertNotIn("controller", commands)
        workstation = commands["workstation"]
        self.assertTrue(any(
            str((self.run_dir / "arch-workstation.qcow2").resolve()) in item
            for item in workstation))
        self.assertIn("order=c,menu=off", workstation)
        self.assertNotIn("-cdrom", workstation)
        recorded = json.loads(
            (self.run_dir / "qemu-command.json").read_text())
        self.assertEqual(recorded["argv"], workstation)

    def test_the_persistent_session_is_never_paused(self):
        boundary = self.boundary()
        self.drive(boundary)
        session = FakeSession.instances[0]
        self.assertEqual(session.forbidden, [])
        for hook in ("take_controller_offline", "restore_controller",
                     "make_storage_unreachable"):
            with self.subTest(hook=hook):
                with self.assertRaisesRegex(join.ArchDurableJoinError,
                                            "never takes"):
                    getattr(boundary, hook)()
        self.assertEqual(session.forbidden, [])
        # Stopped by its own clean poweroff, never terminated.
        self.assertTrue(boundary.checks["controller_clean_poweroff"])
        self.assertTrue(boundary.checks["controller_lock_released"])
        self.assertTrue(session.closed)
        self.assertNotIn("terminate:controller", TIMELINE)

    def test_no_typed_value_reaches_argv_env_evidence_or_output(self):
        boundary = self.boundary()
        before = dict(os.environ)
        self.drive(boundary)
        typed = [CONSOLE, TEMPORARY, NEW, RESCUE,
                 FakeJoinSerial.instances[0].credential.encode()]
        argv = [" ".join(command).encode()
                for _role, command in boundary.spawned]
        self.assertEqual(secret_hits(argv, typed), 0)
        environment = [f"{k}={v}".encode() for k, v in os.environ.items()]
        self.assertEqual(secret_hits(environment, typed), 0)
        self.assertEqual(dict(os.environ), before)
        files = [path for path in self.run_dir.rglob("*") if path.is_file()]
        self.assertIn(self.run_dir / "evidence" / "workstation-serial.log",
                      files)
        self.assertIn(self.run_dir / "evidence" / "controller-transcript.log",
                      files)
        self.assertIn(self.run_dir / "evidence" / "workstation-boot.json",
                      files)
        self.assertEqual(secret_hits(
            [path.read_bytes() for path in files], typed), 0)
        self.assertEqual(secret_hits([self.output.encode()], typed), 0)
        # The Controller transcript was redacted against every typed value.
        self.assertEqual(
            set(FakeSession.instances[0].redaction_secrets), set(typed))
        self.assertTrue(boundary.checks["transcripts_secret_free"])
        self.assertTrue(boundary.checks["echo_never_observed"])

    def test_an_echoed_credential_is_scrubbed_and_fails_the_run(self):
        boundary = self.boundary(echo=True)
        with self.assertRaisesRegex(join.ArchDurableJoinError, "echoing"):
            self.drive(boundary)
        retained = (self.run_dir / "evidence"
                    / "workstation-serial.log").read_bytes()
        self.assertEqual(secret_hits([retained], [TEMPORARY, NEW]), 0)
        self.assertIn(b"[REDACTED]", retained)
        self.assertFalse(boundary.checks["echo_never_observed"])
        self.assertFalse(join.passed(boundary))
        # The Controller still powered off cleanly and the principal died.
        self.assertIn("session-stop", TIMELINE)
        self.assertTrue(boundary.checks["join_principal_destroyed"])

    def test_retry_mode_needs_no_change_and_passes(self):
        boundary = self.boundary(mode=join.MODE_CURRENT)
        self.drive(boundary)
        self.assertNotIn("password_changed", boundary.checks)
        self.assertTrue(join.passed(boundary), boundary.checks)
        self.assertNotIn("send:arch-first-logon-new-sent", TIMELINE)

    def test_a_pinned_uid_mismatch_fails_after_a_clean_teardown(self):
        uids = {account["name"]: account["uidNumber"]
                for account in self.accounts}
        uids["zqx-std"] = 4242
        boundary = self.boundary(uids=uids)
        with self.assertRaisesRegex(join.ArchDurableJoinError,
                                    "record pins: standard_user"):
            self.drive(boundary)
        self.assertFalse(boundary.checks["uids_pinned"])
        self.assertIn("session-stop", TIMELINE)

    def test_a_failed_menu_still_destroys_the_principal_and_stops(self):
        def stalled(console, facts, **_kwargs):
            raise ArchIdentityError("menu never rendered", check="arch-joined")

        boundary = self.boundary()
        with mock.patch("homelab.vm.arch_durable_join.drive_boot_menu",
                        stalled):
            with self.assertRaisesRegex(ArchIdentityError, "menu never"):
                self.drive(boundary)
        self.assertEqual(TIMELINE.count("destroy-join-principal"), 1)
        self.assertTrue(boundary.checks["join_principal_destroyed"])
        self.assertFalse(boundary.checks["join_media_attached"])
        self.assertIn("session-stop", TIMELINE)
        self.assertEqual(len(BUILT), 1)
        self.assertFalse(BUILT[0].exists())


# -- the runner: the kept workstation, its lock and the fold ------------------------------
def write_workstation(root: Path, *, source: str = "/nonexistent/arch-install",
                      ledger_stages=("adopt", "arch-install")) -> Path:
    state = root / "w1"
    state.mkdir(parents=True, mode=0o700)
    disk = state / wi.DISK_NAME
    disk.write_bytes(b"synthetic kept disk\n")
    firmware = state / wi.VARS_NAME
    firmware.write_bytes(b"synthetic installer-authored vars\n")
    (state / wi.PUBLICATION_NAME).write_bytes(b"synthetic publication\n")
    for path in state.iterdir():
        path.chmod(0o600)
    ledger = [{
        "stage": stage, "utc": "2026-09-30T00:00:00+00:00",
        "disk_sha256": _digest(disk), "vars_sha256": _digest(firmware),
        "source": source if stage == "arch-install" else "/nonexistent/gate5"}
        for stage in ledger_stages]
    marker = {
        "schema": wi.MARKER_SCHEMA, "kind": wi.MARKER_KIND, "workstation": "w1",
        "created_utc": "2026-09-30T00:00:00+00:00",
        "binding": {"persistent_instance": INSTANCE, "realm": REALM,
                    "domain_sid": SID},
        "disk": {"format": "qcow2", "name": wi.DISK_NAME, "standalone": True},
        "publication": {"name": wi.PUBLICATION_NAME,
                        "received_utc": "2026-09-30T00:00:00+00:00",
                        "from_bundle": "/nonexistent/gate5", "note": "synthetic"},
        "machine_accounts": [],
        "ledger": ledger,
    }
    (state / wi.MARKER_NAME).write_text(json.dumps(marker, indent=2) + "\n")
    (state / wi.MARKER_NAME).chmod(0o600)
    return state


def snapshot(directory: Path) -> dict:
    return {path.name: _digest(path) for path in sorted(directory.iterdir())
            if path.is_file() and path.name not in (wi.LOCK_NAME,
                                                    wi.MARKER_NAME)}


class FakeBoundary:
    """What the runner hands the join to; it records the world it sees."""

    def __init__(self, test, bundle, **options) -> None:
        self.test = test
        self.bundle = bundle
        self.options = options
        self.checks = {key: True for key in join.REQUIRED_CHECKS}
        self.facts: dict = {"login": {"password_change_landed": True}}
        test.boundaries.append(self)

    def start(self):
        state = self.test.state
        observer = wi.WorkstationInstance(state, name="w1")
        marker = json.loads((state / wi.MARKER_NAME).read_text())
        self.seen = {"locked": observer.locked(),
                     "accounts": list(marker["machine_accounts"])}
        if self.test.start_error is not None:
            raise self.test.start_error

    def finish(self):
        pass

    def stop(self):
        return []


class RunFixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.root = self.tmp / "workstations"
        self.run_root = self.tmp / "runs"
        self.state = write_workstation(self.root)
        self.boundaries: list[FakeBoundary] = []
        self.start_error: BaseException | None = None
        self.record = account_record()
        self.prompter = Prompter(CONSOLE, TEMPORARY, NEW, RESCUE)
        for name, value in (
                ("durable_binding", lambda *a, **k: binding()),
                ("directory_account_record", lambda bound: self.record),
                ("preflight_problems", lambda bound: []),
                ("_typed_secret", self.prompter),
                ("_create_overlay", self.create_overlay)):
            patcher = mock.patch.object(join, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def create_overlay(self, backing, overlay):
        overlay.write_bytes(b"synthetic overlay\n")
        overlay.chmod(0o600)

    def args(self, *extra: str):
        return join.parser().parse_args([
            "--workstation", "w1", "--root", str(self.root),
            "--persistent-dc", INSTANCE,
            "--persistent-root", str(self.tmp / "persistent"),
            "--hostname", HOSTNAME,
            "--controller-state", str(self.tmp / "canonical"),
            "--run-root", str(self.run_root), *extra])

    def factory(self, bundle, **options):
        return FakeBoundary(self, bundle, **options)

    def run_quietly(self, *extra: str) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(output):
            try:
                join.run(self.args(*extra), boundary_factory=self.factory)
            finally:
                self.output = output.getvalue()
        return self.output

    def marker(self) -> dict:
        return json.loads((self.state / wi.MARKER_NAME).read_text())

    def result(self) -> dict:
        found = list(self.run_root.glob("run-*/evidence/result.json"))
        self.assertEqual(len(found), 1)
        return json.loads(found[0].read_text())


class RunTests(RunFixture, unittest.TestCase):
    def test_the_dry_run_prints_the_plan_and_starts_nothing(self):
        before = snapshot(self.state)
        plan_text = self.run_quietly()
        self.assertEqual(snapshot(self.state), before)
        self.assertEqual(self.marker()["machine_accounts"], [])
        self.assertEqual(self.prompter.asked, [])
        self.assertEqual(self.boundaries, [])
        self.assertFalse(self.run_root.exists())
        self.assertFalse(wi.WorkstationInstance(self.state).locked())
        self.assertIn("dry run", plan_text)
        self.assertIn("w1", plan_text)
        self.assertIn(INSTANCE, plan_text)
        self.assertIn("stages done: adopt, arch-install; next stage arch-join",
                      plan_text)
        self.assertIn("KEPT-WS1$", plan_text)
        prompts = [plan_text.index(f"  {n}. ") for n in (1, 2, 3, 4)]
        self.assertEqual(prompts, sorted(prompts))
        self.assertIn("TEMPORARY", plan_text)
        self.assertIn("NEW break-glass", plan_text)
        for value in PRIVATE_VALUES:
            self.assertNotIn(value, plan_text)

    def renamed(self):
        """The bound instance now runs a restored DC under a new name."""
        restored = binding(controller_fqdn=f"dr-2609302105.{DOMAIN}",
                           dc_hostname="dr-2609302105")
        patcher = mock.patch.object(
            join, "durable_binding", lambda *a, **k: restored)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_pinned_only_disk_is_refused_once_the_dc_is_renamed(self):
        """TASK-42: a disk from before SRV-first discovery says why it stops."""
        self.renamed()
        with self.assertRaisesRegex(
                durable_install.DurableInstallError,
                "predates SRV-first discovery"):
            self.run_quietly()
        self.assertEqual(self.prompter.asked, [])
        self.assertFalse(self.run_root.exists())

    def test_an_srv_first_disk_is_accepted_and_the_plan_says_so(self):
        wi.WorkstationInstance(self.state).record_arch_dc_discovery(
            "srv-first", f"bootstrap-dc.{DOMAIN}")
        self.renamed()
        plan_text = self.run_quietly()
        self.assertIn("dry run", plan_text)
        self.assertIn("Directory discovery: kept workstation w1's Arch side "
                      "finds the domain controller by DNS SRV first",
                      plan_text)
        self.assertIn("dr-2609302105", plan_text)
        for value in PRIVATE_VALUES:
            self.assertNotIn(value, plan_text)

    def test_apply_prompts_then_joins_then_folds_arch_join(self):
        entry = {"stage": "arch-join", "utc": "2026-09-30T02:00:00+00:00",
                 "disk_sha256": "cd" * 32, "vars_sha256": "ef" * 32,
                 "source": "synthetic"}
        with mock.patch.object(wi.WorkstationInstance, "fold", autospec=True,
                               return_value=entry) as fold:
            output = self.run_quietly("--apply")
        self.assertEqual(len(self.prompter.asked), 4)
        boundary, = self.boundaries
        self.assertTrue(boundary.seen["locked"])
        # Recorded BEFORE the join started.
        self.assertEqual(boundary.seen["accounts"], ["KEPT-WS1$"])
        self.assertEqual(boundary.options["mode"], join.MODE_FIRST_LOGON)
        self.assertEqual(boundary.options["hostname"], HOSTNAME)
        run_dir = boundary.bundle.bundle
        fold.assert_called_once()
        self.assertEqual(fold.call_args.args[1:],
                         (run_dir / "arch-workstation.qcow2", "arch-join"))
        self.assertEqual(fold.call_args.kwargs["firmware_vars"],
                         run_dir / "OVMF_VARS.fd")
        self.assertEqual(fold.call_args.kwargs["source"], str(run_dir))
        self.assertEqual((run_dir / "OVMF_VARS.fd").read_bytes(),
                         (self.state / wi.VARS_NAME).read_bytes())
        self.assertFalse((run_dir / "arch-workstation.qcow2").exists())
        self.assertFalse(wi.WorkstationInstance(self.state).locked())
        result = self.result()
        self.assertEqual(result["verdict"], "pass")
        self.assertIs(result["folded"], True)
        self.assertEqual(result["stage"], "arch-join")
        self.assertIn("Folded stage arch-join", output)
        text = json.dumps(result)
        for value in PRIVATE_VALUES:
            self.assertNotIn(value, text)
        self.assertEqual(secret_hits(
            [text.encode(), output.encode()],
            [CONSOLE, TEMPORARY, NEW, RESCUE]), 0)

    def test_the_bound_instances_recorded_policy_judges_the_prompts(self):
        relaxed = DirectoryPasswordPolicy(
            min_length=4, complexity=False, min_age_days=0,
            source=f"{INSTANCE}'s recorded directory policy")
        with mock.patch.object(join, "durable_binding",
                               lambda *a, **k: binding(
                                   password_policy=relaxed)):
            plan_text = self.run_quietly()
            self.assertIn(f"{INSTANCE}'s recorded directory policy applies: "
                          "at least 4 characters; complexity off", plan_text)
            self.prompter.values = [CONSOLE, TEMPORARY, b"q7xz", b"k9wv"]
            with mock.patch.object(wi.WorkstationInstance, "fold",
                                   autospec=True, return_value={
                                       "stage": "arch-join",
                                       "disk_sha256": "cd" * 32}) as fold:
                output = self.run_quietly("--apply")
        # Four-character values passed the host check and the join ran.
        self.assertEqual(len(self.prompter.asked), 4)
        self.assertEqual(len(self.boundaries), 1)
        fold.assert_called_once()
        self.assertIn("Folded stage arch-join", output)

    def test_a_failure_leaves_the_ledger_and_keeps_the_machine_account(self):
        self.start_error = join.ArchDurableJoinError("synthetic join fault")
        before = snapshot(self.state)
        ledger = self.marker()["ledger"]
        with mock.patch.object(wi.WorkstationInstance, "fold") as fold:
            with self.assertRaisesRegex(join.ArchDurableJoinError,
                                        "synthetic join fault"):
                self.run_quietly("--apply")
        fold.assert_not_called()
        self.assertEqual(snapshot(self.state), before)
        marker = self.marker()
        self.assertEqual(marker["ledger"], ledger)
        self.assertEqual(marker["machine_accounts"], ["KEPT-WS1$"])
        self.assertIsNone(marker.get("pending_fold"))
        result = self.result()
        self.assertEqual(result["verdict"], "fail")
        self.assertIs(result["folded"], False)
        self.assertEqual(result["failure"]["step"], "join")
        self.assertFalse(any(self.run_root.glob("run-*/arch-workstation.qcow2")))
        self.assertIn("KEPT-WS1$", self.output)
        self.assertIn("destroy lists it", self.output)
        self.assertFalse(wi.WorkstationInstance(self.state).locked())

    def test_unproven_checks_never_fold(self):
        class Unproven(FakeBoundary):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.checks["uids_pinned"] = False

        with mock.patch.object(wi.WorkstationInstance, "fold") as fold:
            with self.assertRaisesRegex(join.ArchDurableJoinError,
                                        "uids_pinned"):
                output = io.StringIO()
                with contextlib.redirect_stdout(output), \
                        contextlib.redirect_stderr(output):
                    join.run(self.args("--apply"), boundary_factory=(
                        lambda bundle, **options: Unproven(
                            self, bundle, **options)))
        fold.assert_not_called()

    def test_a_landed_change_tells_the_owner_how_to_retry(self):
        self.start_error = join.ArchDurableJoinError("synthetic late fault")
        with self.assertRaises(join.ArchDurableJoinError):
            self.run_quietly("--apply")
        self.assertIn("FIRST_LOGON_DONE=1", self.output)
        self.assertIn("LANDED", self.output)

    def test_a_policy_violation_is_refused_before_anything_starts(self):
        self.prompter.values = [CONSOLE, TEMPORARY, b"weak", RESCUE]
        before = snapshot(self.state)
        with self.assertRaisesRegex(join.ArchDurableJoinError, "policy"):
            self.run_quietly("--apply")
        self.assertEqual(self.boundaries, [])
        self.assertFalse(any(self.run_root.glob("run-*")))
        self.assertEqual(snapshot(self.state), before)
        self.assertEqual(self.marker()["machine_accounts"], [])

    def test_first_logon_done_asks_for_the_current_password(self):
        self.prompter.values = [CONSOLE, NEW, RESCUE]
        with mock.patch.object(wi.WorkstationInstance, "fold",
                               return_value={"disk_sha256": "cd" * 32}):
            self.run_quietly("--apply", "--first-logon-done")
        texts = [text for text, _confirm in self.prompter.asked]
        self.assertEqual(len(texts), 3)
        self.assertIn("CURRENT password", texts[1])
        self.assertEqual(self.boundaries[0].options["mode"], join.MODE_CURRENT)

    def test_a_record_without_first_logon_asks_for_the_current_password(self):
        self.record = account_record(first_logon=False)
        self.assertIn("CURRENT password", self.run_quietly())

    def test_a_disk_that_left_the_ledger_is_refused_before_any_prompt(self):
        (self.state / wi.DISK_NAME).write_bytes(b"edited out of band\n")
        with self.assertRaisesRegex(join.ArchDurableJoinError, "ledger head"):
            self.run_quietly("--apply")
        self.assertEqual(self.prompter.asked, [])
        self.assertEqual(self.boundaries, [])

    def test_only_the_next_stage_runs(self):
        shutil.rmtree(self.state)
        self.state = write_workstation(self.root, ledger_stages=("adopt",))
        with self.assertRaisesRegex(join.ArchDurableJoinError,
                                    "'arch-install'"):
            self.run_quietly()

    def test_the_installed_host_name_must_be_the_one_given(self):
        bundle = self.tmp / "arch-install-bundle"
        bundle.mkdir()
        (bundle / "authorization.json").write_text(json.dumps(
            {"authorization": {"hostname": "other-ws"}}))
        shutil.rmtree(self.state)
        self.state = write_workstation(self.root, source=str(bundle))
        with self.assertRaisesRegex(join.ArchDurableJoinError, "other-ws"):
            self.run_quietly()
        (bundle / "authorization.json").write_text(json.dumps(
            {"authorization": {"hostname": HOSTNAME}}))
        self.assertIn("matches the host name", self.run_quietly())

    def test_a_roster_other_than_the_instance_s_is_refused(self):
        with mock.patch.object(join, "durable_binding",
                               lambda *a, **k: binding(
                                   roster_fingerprint="0" * 16)):
            with self.assertRaisesRegex(join.ArchDurableJoinError,
                                        "roster") as caught:
                self.run_quietly()
        for value in PRIVATE_VALUES:
            self.assertNotIn(value, str(caught.exception))

    def test_preflight_problems_stop_the_run_before_any_prompt(self):
        with mock.patch.object(join, "preflight_problems",
                               lambda bound: ["qemu-img is not installed"]):
            with self.assertRaisesRegex(join.ArchDurableJoinError, "qemu-img"):
                self.run_quietly("--apply")
        self.assertEqual(self.prompter.asked, [])

    def test_the_command_line_needs_its_names(self):
        for missing in ("--workstation", "--persistent-dc", "--hostname"):
            argv = ["--workstation", "w1", "--persistent-dc", INSTANCE,
                    "--hostname", HOSTNAME]
            index = argv.index(missing)
            del argv[index:index + 2]
            with self.subTest(missing=missing), contextlib.redirect_stderr(
                    io.StringIO()), self.assertRaises(SystemExit):
                join.parser().parse_args(argv)
        args = join.parser().parse_args([
            "--workstation", "w1", "--persistent-dc", INSTANCE,
            "--hostname", HOSTNAME])
        self.assertFalse(args.apply)
        self.assertFalse(args.first_logon_done)


@unittest.skipUnless(shutil.which("qemu-img"), "qemu-img is required")
class RealFoldTests(RunFixture, unittest.TestCase):
    """One apply against a real qcow2 kept disk, overlay and ``fold``."""

    def setUp(self):
        super().setUp()
        disk = self.state / wi.DISK_NAME
        disk.unlink()
        subprocess.run(
            ["qemu-img", "create", "-q", "-f", "qcow2", str(disk), "64M"],
            check=True, capture_output=True)
        disk.chmod(0o600)
        marker = self.marker()
        for entry in marker["ledger"]:
            entry["disk_sha256"] = _digest(disk)
        (self.state / wi.MARKER_NAME).write_text(json.dumps(marker, indent=2))
        patcher = mock.patch.object(
            join, "_create_overlay", _REAL_CREATE_OVERLAY)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_joined_overlay_becomes_the_kept_disk(self):
        self.run_quietly("--apply")
        marker = self.marker()
        self.assertEqual([entry["stage"] for entry in marker["ledger"]],
                         ["adopt", "arch-install", "arch-join"])
        head = marker["ledger"][-1]
        self.assertEqual(head["disk_sha256"],
                         _digest(self.state / wi.DISK_NAME))
        self.assertEqual(head["vars_sha256"],
                         _digest(self.state / wi.VARS_NAME))
        self.assertEqual(marker["machine_accounts"], ["KEPT-WS1$"])
        self.assertIsNone(marker.get("pending_fold"))
        self.assertFalse(any(self.run_root.glob("run-*/arch-workstation.qcow2")))


if __name__ == "__main__":
    unittest.main()
