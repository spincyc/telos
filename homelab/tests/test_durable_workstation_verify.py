"""The keep-verify (TASK-28 step 9), with every guest faked.

No QEMU guest is launched and nothing reads ``build/``, ``homelab/var/`` or
``homelab/instance/``: the persistent Controller session, the fabric, the
Arch workstation (step 7's ``Guest`` double, answering only what it is
asked), gate 6's Windows boot, sign-in and probe transport are doubles; the
kept workstation, the canonical state, the attempt and the runs live in a
temporary directory; the roster overlay is pinned to a synthetic one naming
every directory role; the firmware variable stores are built byte by byte
here.  Every realm, SID, name and password is synthetic.
"""

import contextlib
import functools
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.tests.identity_overlay_pin import (
    overlay_document, pinned_identity_overlay)
from homelab.tests.ovmf_store_fixture import (
    efi_variable, hddp_variable, load_option_bytes, variable_store)
from homelab.tests.test_arch_durable_join import (
    DOMAIN, HOSTNAME, INSTANCE, NAMES, NETBIOS, REALM, SID, TIMELINE, TOKEN,
    FakeProcess, Guest, account_record, binding)
from homelab.tests.test_windows_durable_prepare import (
    canonical_state, fake_control_iso)
from homelab.vm import arch_durable_join as step7
from homelab.vm import durable_workstation_verify as verify
from homelab.vm import ovmf_vars
from homelab.vm import windows_durable_prepare as prepare
from homelab.vm import workstation_instance as wi
from homelab.vm.bootstrap_dc import SOCKET_MAC
from homelab.vm.durable_workstation import DurableBindingError
from homelab.vm.factory_runner import GATEWAY_MAC
from homelab.vm.persistent_controller_session import FORBIDDEN_FAULT_HOOKS
from homelab.vm.secret_scan import count_secret_occurrences, secret_needles
from homelab.vm.serial_automation import ANSI, SerialAutomationError
from homelab.vm.simulated_topology import MACS
from homelab.vm.windows_identity_run import WindowsIdentityRunError


CONSOLE = b"Console-Rescue-7!"
DAILY = b"Daily-Current-Pass-3!"
TYPED = (CONSOLE, DAILY)
#: Values that must never reach a plan line, a result or a message.
PRIVATE_VALUES = (DOMAIN, REALM, SID, NETBIOS, *NAMES.values())
DAILY_UPN = f"{NAMES['daily_administrator']}@{REALM}"
#: A pid above Linux's pid_max, so no real /proc entry can ever match it.
UNUSED_PID = 4194400


def setUpModule():
    unittest.enterModuleContext(
        pinned_identity_overlay(overlay_document(NAMES)))


def hits(chunks, values=TYPED) -> int:
    return count_secret_occurrences(list(chunks), secret_needles(values))


def digest(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snapshot(directory: Path) -> dict:
    return {path.name: digest(path) for path in sorted(directory.iterdir())
            if path.is_file() and path.name != wi.LOCK_NAME}


def in_order(test: unittest.TestCase, expected: list[str]) -> None:
    """*expected* occurs in TIMELINE as a subsequence, in this order."""
    position = 0
    for entry in expected:
        try:
            position = TIMELINE.index(entry, position) + 1
        except ValueError:
            test.fail(f"{entry!r} missing after position {position}: "
                      f"{TIMELINE}")


# -- firmware variable stores, byte by byte ------------------------------------
def boot_store(order=(1, 0), *, windows_active=True, extra=(),
               authenticated=True) -> bytes:
    """Boot0000 Windows Boot Manager, Boot0001 Linux Boot Manager."""
    glob = ovmf_vars.EFI_GLOBAL_VARIABLE
    return variable_store([
        efi_variable("Boot0000", glob, load_option_bytes(
            "Windows Boot Manager", active=windows_active),
            authenticated=authenticated),
        efi_variable("Boot0001", glob, load_option_bytes(
            "Linux Boot Manager"), authenticated=authenticated),
        efi_variable("BootOrder", glob, struct.pack(f"<{len(order)}H", *order),
                     authenticated=authenticated),
        *extra,
    ], authenticated=authenticated)


# -- the kept workstation ------------------------------------------------------
def write_verified_workstation(root: Path, name: str = "w1", *,
                               stages=wi.FLOW_STAGES, vars_bytes=None,
                               accounts=("KEPT-WS1$", "TELOS-WIN-01"),
                               pending=None) -> Path:
    """A kept workstation with every stage folded and its publication gone."""
    state = root / name
    state.mkdir(parents=True, mode=0o700)
    disk = state / wi.DISK_NAME
    disk.write_bytes(b"synthetic kept dual-boot disk\n")
    variables = state / wi.VARS_NAME
    variables.write_bytes(boot_store() if vars_bytes is None else vars_bytes)
    for item in (disk, variables):
        item.chmod(0o600)
    ledger = [{
        "stage": stage, "utc": "2026-09-30T00:00:00+00:00",
        "disk_sha256": digest(disk), "vars_sha256": digest(variables),
        "source": "/runs/synthetic"} for stage in stages]
    marker = {
        "schema": wi.MARKER_SCHEMA, "kind": wi.MARKER_KIND,
        "workstation": name, "created_utc": "2026-09-30T00:00:00+00:00",
        "binding": {"persistent_instance": INSTANCE, "realm": REALM,
                    "domain_sid": SID},
        "disk": {"format": "qcow2", "name": wi.DISK_NAME, "standalone": True},
        "publication": {"name": wi.PUBLICATION_NAME,
                        "received_utc": "2026-09-30T00:00:00+00:00",
                        "from_bundle": "/runs/gate5", "note": "synthetic",
                        "retired_utc": "2026-09-30T01:00:00+00:00"},
        "machine_accounts": list(accounts), "ledger": ledger,
    }
    if pending is not None:
        marker["pending_fold"] = pending
    (state / wi.MARKER_NAME).write_text(json.dumps(marker, indent=2) + "\n")
    (state / wi.MARKER_NAME).chmod(0o600)
    return state


# -- the fabric, the persistent session, the directory probe ---------------------
class FakeFabric:
    instances: list["FakeFabric"] = []

    def __init__(self, runtime, **_options) -> None:
        self.runtime = Path(runtime)
        self.switch_log = self.runtime / "switch.jsonl"
        self.port = None
        self.gateway_generation = None
        self.stopped = False
        FakeFabric.instances.append(self)

    def start(self):
        TIMELINE.append("fabric-start")
        self.runtime.mkdir(mode=0o700)
        self.switch_log.write_text("")
        self.port = 40123
        self.gateway_generation = 1

    def cursor(self):
        return len(TIMELINE)

    def wait_controller(self, cursor):
        TIMELINE.append("port:controller")

    def stop(self):
        TIMELINE.append("fabric-stop")
        self.stopped = True
        return []


class ControllerConsole:
    def __init__(self) -> None:
        self.reader = io.BytesIO()
        self.writer = io.BytesIO()
        self.password = CONSOLE
        self.timeout = 300.0


class FakeSession:
    """The persistent session's surface; it records any reach for a fault."""

    instances: list["FakeSession"] = []

    def __init__(self, target, *, port, password, canonical_state):
        object.__setattr__(self, "forbidden", [])
        self.target = target
        self.port = port
        self.password = password
        self._console = None
        self.passwords_used: list[bytes] = []
        self.redaction_secrets: list = []
        self.closed = False
        self.facts = {"launches": 0, "logins": 0, "live_argv_audited": False,
                      "clean_poweroffs": 0, "terminated_fallback": False,
                      "lock_released": True}
        FakeSession.instances.append(self)

    def __getattr__(self, name):
        if name in FORBIDDEN_FAULT_HOOKS:
            self.forbidden.append(name)
        raise AttributeError(name)

    @property
    def console(self):
        if self._console is None:
            raise RuntimeError("the persistent Controller is not logged in")
        return self._console

    def start(self, *, attached=None):
        TIMELINE.append("session-start")
        self.facts["launches"] += 1
        self.facts["lock_released"] = False
        if attached is not None:
            attached()
        self.passwords_used.append(self.password)
        self.facts["logins"] += 1
        self.facts["live_argv_audited"] = True
        self._console = ControllerConsole()
        return self._console

    def stop(self, label="persistent-session-poweroff"):
        if self._console is None:
            return
        TIMELINE.append("session-stop")
        self.facts["clean_poweroffs"] += 1
        self.facts["lock_released"] = True
        self._console = None

    def relaunch(self, *, attached=None):
        self.stop()
        return self.start(attached=attached)

    def redacted_transcript(self, extra_secrets=()):
        self.redaction_secrets = list(extra_secrets)
        if self.password is None:
            return None
        return b"bootstrap-dc login: local-rescue\r\nPassword: \r\n$ "

    def close(self):
        self.closed = True
        self.password = None


def probe_directory(console, bound, checks):
    TIMELINE.append("directory-proved")
    checks.update(realm_matches=True, domain_sid="match",
                  clock_within_kerberos_skew=True, clock_skew_seconds=0)
    return SID


# -- the Arch workstation ----------------------------------------------------------
MENU_ROWS = ("Windows 11", "Arch Linux LTS",
             "Reboot Into Firmware Interface")


def menu_render(default: str) -> bytes:
    """systemd-boot's serial render: positioned, padded, one row highlighted."""
    cells = []
    for row, title in enumerate(MENU_ROWS, start=5):
        attributes = (b"\x1b[30m\x1b[47m" if title == default
                      else b"\x1b[37m\x1b[40m")
        cells.append(f"\x1b[{row};30H".encode() + attributes
                     + f"  {title:<34}".encode())
    return b"\x1b[2J" + b"".join(cells) + b"\r\n"


class VerifyGuest(Guest):
    """Step 7's joined guest, plus the verify's testjoin and a menu."""

    def __init__(self, accounts, *, testjoin=True, menu_default="Windows 11",
                 user_passwords=None, **options):
        options.setdefault("expired", False)
        options.setdefault("temporary", DAILY)
        super().__init__(accounts, **options)
        self.testjoin = testjoin
        self.menu_default = menu_default
        self.testjoin_command: bytes | None = None
        #: --verify-users: each standard account's password, by name.
        self.user_passwords = dict(user_passwords or {})
        self.current_user: str | None = None
        self.user_sessions: list[str] = []

    # -- --verify-users: other accounts at the getty ----------------------
    def on_arch_login_username_sent(self, value, reader):
        name = value.decode()
        if name in self.user_passwords:
            if reader != "getty":
                self.violations.append("username")
            self.current_user = name
            self.ask("password", b"Password: ")
            return
        self.current_user = None
        super().on_arch_login_username_sent(value, reader)

    def on_arch_login_password_sent(self, value, reader):
        if self.current_user is None:
            super().on_arch_login_password_sent(value, reader)
            return
        if value != self.user_passwords[self.current_user]:
            self.emit(b"\r\nLogin incorrect\r\n")
            self.ask("getty", HOSTNAME.encode() + b" login: ")
            return
        self.user_sessions.append(self.current_user)
        self.shell(self.current_user.encode())

    def on_arch_verify_user_uid_sent(self, value, reader):
        if reader != "shell" or self.current_user is None:
            self.violations.append("user-uid")
        marker = re.search(rb"__TELOS_VERIFY_UID_[0-9a-z]+=", value).group(0)
        self.emit(b"\r\n" + marker
                  + str(self.uids[self.current_user]).encode() + b"\r\n")
        self.ask("shell", b"[" + self.current_user.encode() + b"@"
                 + HOSTNAME.encode() + b" ~]$ ")

    def on_arch_verify_user_logout(self, value, reader):
        if reader != "shell":
            self.violations.append("user-logout")
        self.current_user = None
        self.emit(b"\r\nlogout\r\n\r\n")
        self.ask("getty", HOSTNAME.encode() + b" login: ")

    def on_arch_verify_testjoin_sent(self, value, reader):
        self.testjoin_command = value
        self.emit(b"\r\n__TELOS_VERIFY_TESTJOIN_" + TOKEN.encode() + b"="
                  + (b"1" if self.testjoin else b"0") + b"\r\n")
        self.ask("root", b"[root@" + HOSTNAME.encode() + b" ~]# ")


def drive_boot_menu(console, facts, **_kwargs):
    """Gate 8's menu drive is gate 8's to test; the guest renders and boots."""
    guest = console.guest
    TIMELINE.append("boot-menu-driven")
    guest.emit(menu_render(guest.menu_default))
    facts.update(menu_seen=True, entry_committed=True, handoff_seen=True)
    # The sealed join stays sealed: the guest reaches its domain-online gate
    # and the getty (step 7's double prints its old join marker too).
    guest.boot_to_getty()


class ArchQmp:
    def __init__(self):
        self.calls: list[str] = []

    def execute(self, command, arguments=None, **_kwargs):
        self.calls.append(command)
        return {}

    def close(self):
        self.calls.append("close")


class WiredVerifyArch(verify.VerifyArchBoundary):
    """The real verify boundary with only processes, QMP and console doubled."""

    def __init__(self, bundle, *, guest: VerifyGuest, observer, **options):
        super().__init__(bundle, **options)
        self.guest = guest
        self.observer = observer
        self.spawned: list[tuple[str, list[str]]] = []
        self.qmp = ArchQmp()

    def _spawn(self, role, command, *, pass_fds=(), stdio=False):
        TIMELINE.append(f"spawn:{role}")
        self.observer("arch-spawn")
        process = FakeProcess(role, UNUSED_PID + len(self.spawned))
        self.spawned.append((role, list(command)))
        self._processes[role] = process
        if role == "workstation":
            self.guest.process = process
        return process

    def _audit(self, role, pid, **_kwargs):
        pass

    def _connect_qmp(self, path, pid):
        return self.qmp

    def _arm_progress(self):
        return None

    def _workstation_serial(self, process):
        return self.guest.console


# -- the Windows workstation ----------------------------------------------------------
class WindowsProcess:
    def __init__(self) -> None:
        self.pid = UNUSED_PID + 99
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        TIMELINE.append("terminate:windows")
        self.returncode = -15

    def kill(self):
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("windows", timeout)
        return self.returncode


class WindowsQmp:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, command, arguments=None, **_kwargs):
        self.calls.append(command)
        return {}

    def close(self):
        self.calls.append("close")


class WiredWindowsBoundary(verify.VerifyWindowsBoundary):
    """Gate 6's boundary, validated for real; only the guest is doubled."""

    def start_windows(self):
        TIMELINE.append("windows-start")
        self.processes["windows"] = WindowsProcess()
        self.qmp = WindowsQmp()
        self.windows_switch_generation = 2
        # Gate 6 releases its validation-only hold once Windows is up.
        os.close(self.control_iso_fd)
        self.control_iso_fd = None

    def authenticate_qmp(self):
        TIMELINE.append("windows-qmp")


def probe_records(*, secure=True, domain=DOMAIN, admin=True) -> dict:
    sid = "S-1-5-21-11-22-33-1105"
    principal = f"{NETBIOS}\\{NAMES['daily_administrator']}"
    return {
        "interactive-operator": {
            "schema_version": 1, "action": "interactive-operator",
            "result": "pass", "observation": {
                "principal": principal, "principal_sid": sid,
                "operator": DAILY_UPN, "operator_sid": sid,
                "console_principal": principal, "console_sid": sid,
                "authenticated": True, "authentication_type": "Kerberos",
                "session_id": 2, "profile_sid": sid, "profile_loaded": True,
                "local_profile": True}},
        "domain-state": {
            "schema_version": 1, "action": "domain-state", "result": "pass",
            "observation": {
                "part_of_domain": True, "domain": domain,
                "secure_channel": secure, "operator": DAILY_UPN,
                "operator_local_administrator": admin}},
    }


def adapter_factory(test):
    class WiredWindowsAdapter(verify.VerifyWindowsAdapter):
        def reauthenticate_domain_operator(self, principal, credential,
                                           nonce):
            TIMELINE.append("windows-sign-in")
            test.signed_in.append((principal, credential))
            if test.sign_in_error is not None:
                raise test.sign_in_error

        def static_probe(self, action):
            TIMELINE.append(f"probe:{action}")
            return json.loads(json.dumps(test.records[action]))

        def launch_guest(self, command):
            TIMELINE.append("windows-shutdown-launched")
            test.launched.append(command)
            self.boundary.processes["windows"].returncode = 0

    return WiredWindowsAdapter


# -- the terminal ----------------------------------------------------------------------
class Prompter:
    def __init__(self, *values: bytes) -> None:
        self.values = list(values)
        self.asked: list[str] = []

    def __call__(self, text, *, confirm=None):
        TIMELINE.append(f"prompt:{len(self.asked) + 1}")
        self.asked.append(text)
        return self.values.pop(0)


# -- unit tests ------------------------------------------------------------------------
class FirmwareVariableTests(unittest.TestCase):
    def test_boot_order_linux_first_in_both_store_formats(self):
        for authenticated in (True, False):
            with self.subTest(authenticated=authenticated), \
                    tempfile.TemporaryDirectory() as name:
                path = Path(name) / "OVMF_VARS.fd"
                path.write_bytes(boot_store(authenticated=authenticated))
                facts = verify.boot_order_facts(path)
                self.assertTrue(facts["parsed"], facts)
                self.assertTrue(facts["linux_first"])
                self.assertTrue(facts["windows_present"])
                self.assertEqual(
                    [entry["description"] for entry in facts["order"]],
                    ["Linux Boot Manager", "Windows Boot Manager"])
                self.assertIsNone(facts["boot_next"])
                self.assertTrue(facts["menu_default_intact"])

    def test_a_windows_promotion_is_a_boot_order_regression(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "OVMF_VARS.fd"
            path.write_bytes(boot_store(order=(0, 1)))
            facts = verify.boot_order_facts(path)
        self.assertTrue(facts["parsed"])
        self.assertFalse(facts["linux_first"])
        self.assertEqual(facts["order"][0]["description"],
                         "Windows Boot Manager")

    def test_only_live_copies_count(self):
        glob = ovmf_vars.EFI_GLOBAL_VARIABLE
        stale = efi_variable("BootOrder", glob, struct.pack("<2H", 0, 1),
                             state=0x3C)
        store = variable_store([
            efi_variable("Boot0000", glob,
                         load_option_bytes("Windows Boot Manager")),
            efi_variable("Boot0001", glob,
                         load_option_bytes("Linux Boot Manager")),
            stale,
            efi_variable("BootOrder", glob, struct.pack("<2H", 0, 1),
                         state=ovmf_vars.VAR_ADDED_IN_TRANSITION),
            efi_variable("BootOrder", glob, struct.pack("<2H", 1, 0)),
        ])
        variables = verify.firmware_variables(store)
        self.assertEqual(variables[(glob, "BootOrder")],
                         struct.pack("<2H", 1, 0))
        # A copy in a deletion transition is live only on its own.
        alone = variable_store([efi_variable(
            "BootOrder", glob, b"\x01\x00",
            state=ovmf_vars.VAR_ADDED_IN_TRANSITION)])
        self.assertEqual(verify.firmware_variables(alone)[
            (glob, "BootOrder")], b"\x01\x00")
        deleted = variable_store([stale])
        self.assertEqual(verify.firmware_variables(deleted), {})

    def test_menu_overrides_and_boot_next_are_recorded(self):
        loader = verify.SYSTEMD_BOOT_VENDOR
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "OVMF_VARS.fd"
            path.write_bytes(boot_store(extra=(
                efi_variable("LoaderEntryDefault", loader,
                             "arch.conf\0".encode("utf-16-le")),
                efi_variable("BootNext", ovmf_vars.EFI_GLOBAL_VARIABLE,
                             b"\x00\x00"))))
            facts = verify.boot_order_facts(path)
        self.assertTrue(facts["linux_first"])
        self.assertEqual(facts["loader_entry_default"], "arch.conf")
        self.assertFalse(facts["menu_default_intact"])
        self.assertEqual(facts["boot_next"], "Boot0000")

    def test_what_is_not_a_store_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "OVMF_VARS.fd"
            path.write_bytes(b"installer-authored vars\n" * 8)
            facts = verify.boot_order_facts(path)
            self.assertFalse(facts["parsed"])
            self.assertFalse(facts["linux_first"])
            self.assertEqual(facts["error"], "FirmwareVariablesError")
            missing = verify.boot_order_facts(Path(name) / "absent.fd")
            self.assertFalse(missing["linux_first"])
        with self.assertRaises(verify.FirmwareVariablesError):
            verify.firmware_variables(boot_store()[:40])
        runaway = bytearray(boot_store())
        # The first variable's data size, inflated past the store's end.
        struct.pack_into("<I", runaway, 100 + 40, 1 << 20)
        with self.assertRaisesRegex(verify.FirmwareVariablesError, "past"):
            verify.firmware_variables(bytes(runaway))


class MenuDefaultTests(unittest.TestCase):
    def test_the_first_highlighted_render_is_the_default(self):
        raw = menu_render("Windows 11") + b"\x1b[5;1H" + menu_render(
            "Arch Linux LTS")
        self.assertEqual(verify.menu_default_entry(raw), "Windows 11")
        self.assertEqual(
            verify.menu_default_entry(menu_render("Arch Linux LTS")),
            "Arch Linux LTS")

    def test_plain_log_text_is_never_a_render(self):
        self.assertIsNone(verify.menu_default_entry(
            b'BdsDxe: starting Boot0000 "Windows 11"\r\n'))


class TestjoinCommandTests(unittest.TestCase):
    class Console:
        """A root shell that echoes what it is sent, then answers."""

        def __init__(self, answer: bytes | None) -> None:
            self.token = TOKEN
            self.timeout = 30.0
            self.buffer = b""
            self.answer = answer
            self.sent: list[bytes] = []

        def _send(self, value, event):
            self.sent.append(value)
            self.buffer += value + b"\r\n"
            if self.answer is not None:
                self.buffer += self.answer

        def _wait(self, pattern, label):
            import re
            clean = ANSI.sub(b"", self.buffer)
            match = re.compile(pattern, re.MULTILINE).search(clean)
            if match is None:
                raise SerialAutomationError(f"timed out waiting for {label}")
            self.buffer = clean[match.end():]
            return match

    def test_the_command_is_name_free_and_its_echo_is_never_the_result(self):
        command, marker = verify.testjoin_command(TOKEN)
        self.assertIn(b"net ads testjoin", command)
        self.assertIn(TOKEN.encode(), marker)
        for value in PRIVATE_VALUES:
            self.assertNotIn(value.encode(), command)
        # The echo alone never proves anything.
        with self.assertRaises(verify.KeepVerifyError):
            verify.prove_testjoin(self.Console(None), {})
        for answer, expected in ((b"1", True), (b"0", False)):
            with self.subTest(answer=answer):
                facts: dict = {}
                console = self.Console(b"\r\n" + marker + answer + b"\r\n")
                self.assertIs(verify.prove_testjoin(console, facts), expected)
                self.assertIs(facts["passed"], expected)
                self.assertEqual(console.timeout, 30.0)


class UserLoginTests(unittest.TestCase):
    def test_only_the_standard_accounts_are_logged_in(self):
        accounts = [{"contract_role": role, "name": role}
                    for role in ("standard_user", "daily_administrator",
                                 "domain_administrator",
                                 "additional_standard_user_10002")]
        self.assertEqual(
            ["standard_user", "additional_standard_user_10002"],
            [a["contract_role"] for a in verify.standard_accounts(accounts)])

    def test_the_uid_command_echo_is_never_the_result(self):
        command, marker = verify.session_uid_command(TOKEN + "u0")
        self.assertIn(b"id -u", command)
        self.assertIn(marker + b"%s", command)
        self.assertIsNone(re.search(
            re.escape(marker) + rb"[0-9]", command))

    def test_each_standard_account_is_asked_after_the_daily_one(self):
        prompter = Prompter(CONSOLE, DAILY, b"Kid-Pass-1", b"Guest-Pass-2")
        users = [{"contract_role": "standard_user", "name": "kid"},
                 {"contract_role": "additional_standard_user_10002",
                  "name": "guest"}]
        secrets = verify.collect_verify_secrets(
            INSTANCE, "zqx-daily", prompt=prompter, users=users)
        self.assertEqual(4, len(prompter.asked))
        self.assertIn("CURRENT domain password for standard_user (kid)",
                      prompter.asked[2])
        self.assertEqual(b"Guest-Pass-2",
                         secrets.users["additional_standard_user_10002"])
        self.assertIn(b"Kid-Pass-1", secrets.values())
        secrets.clear()
        self.assertEqual({}, secrets.users)

    def test_a_user_password_equal_to_the_console_is_refused(self):
        with self.assertRaisesRegex(verify.KeepVerifyError, "console"):
            verify.collect_verify_secrets(
                INSTANCE, "zqx-daily", prompt=Prompter(CONSOLE, DAILY,
                                                       CONSOLE),
                users=[{"contract_role": "standard_user", "name": "kid"}])


class CredentialTests(unittest.TestCase):
    def test_two_prompts_in_order_both_before_anything(self):
        prompter = Prompter(CONSOLE, DAILY)
        secrets = verify.collect_verify_secrets(
            INSTANCE, "zqx-daily", prompt=prompter)
        console, daily = prompter.asked
        self.assertIn("console password", console)
        self.assertIn(INSTANCE, console)
        self.assertIn("CURRENT", daily)
        self.assertEqual((secrets.console, secrets.daily), (CONSOLE, DAILY))
        self.assertNotIn(DAILY.decode(), repr(secrets))
        secrets.clear()
        self.assertEqual(secrets.values(), [])

    def test_untypeable_or_repeated_values_are_refused_quietly(self):
        for values, reason in (((CONSOLE, "Dåily-1!".encode()), "cannot type"),
                               ((CONSOLE, CONSOLE), "must differ")):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(verify.KeepVerifyError,
                                            reason) as caught:
                    verify.collect_verify_secrets(
                        INSTANCE, "zqx-daily", prompt=Prompter(*values))
                for value in values:
                    self.assertNotIn(value.decode(), str(caught.exception))


class FabricTests(unittest.TestCase):
    def test_one_switch_serves_the_controller_and_both_systems(self):
        launched: list[list[str]] = []
        waits: list[tuple] = []

        def popen(argv, **_options):
            launched.append(list(argv))
            return FakeProcess("child", UNUSED_PID + len(launched))

        def wait_port(log, name, mac, *, timeout, after=None):
            waits.append((name, mac, after))
            return 7

        with tempfile.TemporaryDirectory() as name:
            fabric = verify.Fabric(Path(name) / "fabric", popen=popen,
                                   wait_port=wait_port)
            fabric.start()
            fabric.wait_controller("cursor-before-relaunch")
            self.assertEqual(fabric.gateway_generation, 7)
            switch, gateway = launched
            ports = [switch[index + 1] for index, part in enumerate(switch)
                     if part == "--port"]
            self.assertIn(f"controller={SOCKET_MAC.lower()}", ports)
            self.assertIn(f"workstation={MACS['client']}", ports)
            self.assertEqual(len(ports), 3)
            self.assertIn("--identity-mode", switch)
            self.assertEqual(
                gateway[gateway.index("--controller-mac") + 1], SOCKET_MAC)
            self.assertEqual(waits[0][:2], ("gateway", GATEWAY_MAC))
            self.assertEqual(waits[1], ("controller", SOCKET_MAC,
                                        "cursor-before-relaunch"))
            self.assertEqual(
                (Path(name) / "fabric").stat().st_mode & 0o777, 0o700)
            for process in fabric.processes:
                process.exited = True
            self.assertEqual(fabric.stop(), [])
        for argv in launched:
            self.assertEqual(hits(["\0".join(argv).encode()]), 0)


class WindowsBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.fabric = FakeFabric(self.tmp / "fabric")
        self.fabric.start()

    def boundary(self, live=True):
        return verify.VerifyWindowsBoundary(
            self.tmp / "attempt", self.tmp / "canonical",
            target=mock.sentinel.target, fabric=self.fabric,
            controller_live=lambda: live)

    def test_it_attaches_to_the_shared_fabric_and_spawns_nothing(self):
        boundary = self.boundary()
        self.assertEqual(boundary.runtime, self.fabric.runtime)
        with mock.patch.object(boundary, "_validate") as validate, \
                mock.patch("subprocess.Popen") as popen:
            boundary.start_switch()
            boundary.start_controller()
        validate.assert_called_once()
        popen.assert_not_called()
        self.assertEqual((boundary.port, boundary.gateway_switch_generation),
                         (40123, 1))
        self.assertEqual(boundary.processes, {})
        self.assertIs(boundary.persistent_facts["shared_session"], True)
        # Step 8's stop has no session of its own to stop.
        boundary.stop_controller()
        boundary.stop_switch()

    def test_it_needs_the_verify_s_logged_in_controller(self):
        boundary = self.boundary(live=False)
        with mock.patch.object(boundary, "_validate"):
            boundary.start_switch()
        with self.assertRaisesRegex(WindowsIdentityRunError, "not logged in"):
            boundary.start_controller()
        stopped = verify.VerifyWindowsBoundary(
            self.tmp / "attempt", self.tmp / "canonical",
            target=mock.sentinel.target, fabric=FakeFabric(self.tmp / "x"),
            controller_live=lambda: True)
        with mock.patch.object(stopped, "_validate"):
            with self.assertRaisesRegex(WindowsIdentityRunError,
                                        "not running"):
                stopped.start_switch()

    def test_faults_and_directory_writes_are_refused(self):
        boundary = self.boundary()
        boundary.processes["gateway"] = mock.Mock(pid=1)
        with mock.patch("os.kill") as kill:
            for call in (lambda: boundary.set_controller_available(False),
                         lambda: boundary.set_gateway_available(False)):
                with self.assertRaises(WindowsIdentityRunError):
                    call()
            kill.assert_not_called()
        adapter = verify.VerifyWindowsAdapter.__new__(
            verify.VerifyWindowsAdapter)
        for call in (lambda: adapter.stage_join_principal("x"),
                     lambda: adapter.destroy_join_principal()):
            with self.assertRaisesRegex(verify.KeepVerifyError,
                                        "writes nothing"):
                call()


# -- the whole run ------------------------------------------------------------------------
class RunFixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.tmp.chmod(0o700)
        self.root = self.tmp / "workstations"
        self.run_root = self.tmp / "runs"
        self.canonical = canonical_state(self.tmp)
        TIMELINE.clear()
        FakeSession.instances = []
        FakeFabric.instances = []
        self.record = account_record(first_logon=False)
        self.accounts = step7.planned_accounts(self.record)
        self.guest_options: dict = {}
        self.probe = probe_directory
        self.records = probe_records()
        self.sign_in_error: BaseException | None = None
        self.signed_in: list = []
        self.launched: list[str] = []
        self.locks: list[tuple[str, bool | None]] = []
        self.verifies: list[verify.KeepVerify] = []
        self.prompter = Prompter(CONSOLE, DAILY)
        for name, value in (
                ("durable_binding", lambda *a, **k: binding()),
                ("directory_account_record", lambda bound: self.record),
                ("preflight_problems", lambda bound, space: []),
                ("session_command", lambda target, port, **k: [
                    "qemu-system-x86_64", "-name",
                    f"persistent-dc-{INSTANCE}", "127.0.0.1:65535"]),
                ("_image_info", lambda path: {
                    "format": "qcow2", "virtual-size": 64 << 20}),
                ("_create_overlay", self.create_overlay),
                ("prepare_attempt", functools.partial(
                    prepare.prepare, control_iso_builder=fake_control_iso,
                    create_overlay=self.create_overlay)),
                ("drive_boot_menu", drive_boot_menu),
                ("_probe_directory", lambda *a: self.probe(*a))):
            patcher = mock.patch.object(verify, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def workstation(self, **options) -> Path:
        self.state = write_verified_workstation(self.root, **options)
        return self.state

    def create_overlay(self, backing, overlay):
        TIMELINE.append(f"overlay:{Path(overlay).name}")
        overlay.write_bytes(b"synthetic overlay\n")
        overlay.chmod(0o600)

    def observe_lock(self, label):
        self.locks.append(
            (label, wi.WorkstationInstance(self.state).locked()))

    def factory(self, workstation, bound, **options):
        self.guest = VerifyGuest(self.accounts, **self.guest_options)
        instance = verify.KeepVerify(
            workstation, bound, session_factory=FakeSession,
            fabric_factory=FakeFabric,
            arch_boundary_factory=lambda bundle, **o: WiredVerifyArch(
                bundle, guest=self.guest, observer=self.observe_lock, **o),
            windows_boundary_factory=WiredWindowsBoundary,
            windows_adapter_factory=adapter_factory(self), **options)
        self.verifies.append(instance)
        return instance

    def args(self, *extra: str):
        return verify.parser().parse_args([
            "--workstation", "w1", "--root", str(self.root),
            "--persistent-dc", INSTANCE,
            "--persistent-root", str(self.tmp / "persistent"),
            "--hostname", HOSTNAME,
            "--controller-state", str(self.canonical),
            "--run-root", str(self.run_root), "--duration", "600", *extra])

    def run_quietly(self, *extra: str) -> int:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(output):
            try:
                return verify.run(self.args(*extra), prompt=self.prompter,
                                  verify_factory=self.factory)
            finally:
                self.output = output.getvalue()

    def result(self) -> dict:
        found = list(self.run_root.glob("w1/run-*/evidence/result.json"))
        self.assertEqual(len(found), 1)
        return json.loads(found[0].read_text())


class DryRunTests(RunFixture, unittest.TestCase):
    def test_the_dry_run_prints_the_plan_and_starts_nothing(self):
        self.workstation()
        before = snapshot(self.state)
        self.assertEqual(self.run_quietly(), 0)
        plan = self.output
        self.assertEqual(snapshot(self.state), before)
        self.assertEqual(self.prompter.asked, [])
        self.assertEqual(self.verifies, [])
        self.assertFalse(self.run_root.exists())
        self.assertFalse(wi.WorkstationInstance(self.state).locked())
        self.assertIn("dry run", plan)
        self.assertIn("stages done: adopt, arch-install, arch-join, "
                      "windows-join; keep-verify folds nothing", plan)
        self.assertIn("Linux Boot Manager first: yes", plan)
        self.assertIn("KEPT-WS1$", plan)
        self.assertIn("relaunched", plan)
        self.assertIn("net ads testjoin", plan)
        self.assertIn("No ledger entry is recorded", plan)
        prompts = [plan.index(f"  {n}. ") for n in (1, 2)]
        self.assertEqual(prompts, sorted(prompts))
        self.assertIn("127.0.0.1:<per-run port>", plan)
        for value in PRIVATE_VALUES:
            self.assertNotIn(value, plan)

    def test_a_boot_order_regression_is_shown_then_refused_before_prompts(self):
        self.workstation(vars_bytes=boot_store(order=(0, 1)))
        self.run_quietly()
        self.assertIn("Linux Boot Manager first: NO (REGRESSION)", self.output)
        with self.assertRaisesRegex(verify.KeepVerifyError, "BootOrder"):
            self.run_quietly("--apply")
        self.assertEqual(self.prompter.asked, [])
        self.assertEqual(self.verifies, [])
        self.assertFalse((self.run_root / "w1").exists())
        self.assertFalse(wi.WorkstationInstance(self.state).locked())

    def test_only_a_fully_folded_workstation_is_verified(self):
        self.workstation(stages=wi.FLOW_STAGES[:3])
        with self.assertRaisesRegex(verify.KeepVerifyError,
                                    "next stage is 'windows-join'"):
            self.run_quietly()

    def test_an_interrupted_fold_is_refused_naming_reconcile(self):
        self.workstation(stages=wi.FLOW_STAGES[:3], pending={
            "stage": "windows-join", "utc": "2026-09-30T02:00:00+00:00",
            "disk_sha256": "ab" * 32, "vars_sha256": "cd" * 32,
            "source": "/runs/x"})
        with self.assertRaisesRegex(verify.KeepVerifyError, "reconcile"):
            self.run_quietly("--apply")
        self.assertEqual(self.prompter.asked, [])

    def test_the_machine_accounts_must_be_the_joins(self):
        self.workstation(accounts=("TELOS-WIN-01",))
        with self.assertRaisesRegex(verify.KeepVerifyError, "KEPT-WS1"):
            self.run_quietly()

    def test_a_disk_that_left_the_ledger_is_refused_before_any_prompt(self):
        self.workstation()
        (self.state / wi.DISK_NAME).write_bytes(b"changed out of band\n")
        with self.assertRaisesRegex(verify.KeepVerifyError, "ledger head"):
            self.run_quietly("--apply")
        self.assertEqual(self.prompter.asked, [])

    def test_preflight_problems_stop_the_run_before_any_prompt(self):
        self.workstation()
        with mock.patch.object(verify, "preflight_problems",
                               lambda bound, space: ["xorriso is missing"]):
            with self.assertRaisesRegex(verify.KeepVerifyError, "xorriso"):
                self.run_quietly("--apply")
        self.assertEqual(self.prompter.asked, [])


class ApplyTests(RunFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.workstation()
        self.before = snapshot(self.state)

    def apply(self) -> int:
        with mock.patch.object(wi.WorkstationInstance, "fold",
                               side_effect=AssertionError("fold")), \
                mock.patch.object(wi.WorkstationInstance,
                                  "record_machine_account",
                                  side_effect=AssertionError("account")), \
                mock.patch.object(wi.WorkstationInstance,
                                  "retire_publication",
                                  side_effect=AssertionError("retire")):
            return self.run_quietly("--apply")

    def test_both_systems_are_verified_across_one_relaunch(self):
        self.assertEqual(self.apply(), 0, self.output)
        result = self.result()
        self.assertEqual(result["verdict"], "pass", result["checks"])
        self.assertEqual(result["failures"], [])
        self.assertEqual(set(result["checks"]), set(verify.REQUIRED_CHECKS))
        self.assertTrue(all(result["checks"].values()))
        in_order(self, [
            "prompt:1", "prompt:2",
            "overlay:arch-workstation.qcow2", "overlay:windows.qcow2",
            "fabric-start", "session-start", "port:controller",
            "directory-proved", "spawn:workstation", "boot-menu-driven",
            "wait:arch-domain-online-observed",
            "send:arch-login-password-sent", "send:arch-probe-roster-sent",
            "send:arch-sudo-password-sent", "send:arch-verify-testjoin-sent",
            "send:arch-join-checks-sent", "send:arch-join-poweroff-sent",
            # The relaunch: a clean console poweroff, then the same session
            # boots again and the directory is proved again.
            "session-stop", "session-start", "port:controller",
            "directory-proved",
            "windows-start", "windows-sign-in", "probe:interactive-operator",
            "probe:domain-state", "windows-shutdown-launched",
            "session-stop", "fabric-stop"])
        self.assertEqual(TIMELINE.count("session-start"), 2)
        self.assertEqual(TIMELINE.count("directory-proved"), 2)
        session, = FakeSession.instances
        self.assertEqual(session.passwords_used, [CONSOLE, CONSOLE])
        self.assertEqual(session.facts["launches"], 2)
        self.assertEqual(session.facts["clean_poweroffs"], 2)
        self.assertTrue(session.closed)
        # One principal only ever signs in, the durable one, typed as typed.
        self.assertEqual(self.signed_in, [(DAILY_UPN, DAILY.decode())])
        self.assertTrue(self.launched[0].startswith("powershell"))
        self.assertIn("Stop-Computer", self.launched[0])
        # The guest's reader was asked every time before it was written to.
        self.assertEqual(self.guest.violations, [])
        self.assertEqual(result["facts"]["windows"]["shutdown_method"],
                         "stop-computer")
        self.assertEqual(result["facts"]["arch"]["menu_default_entry"],
                         "Windows 11")
        self.assertIs(result["folded"], False)
        self.assertIn("no non-stage annotation", result["ledger_entry"])
        self.assertIn("PASS", self.output)

    def users_setup(self, password=b"Standard-Pass-4!"):
        standard = verify.standard_accounts(self.accounts)
        self.assertTrue(standard)
        self.prompter = Prompter(CONSOLE, DAILY,
                                 *[password] * len(standard))
        self.guest_options["user_passwords"] = {
            account["name"]: b"Standard-Pass-4!" for account in standard}
        return standard

    def test_verify_users_logs_every_standard_account_in_first(self):
        standard = self.users_setup()
        with mock.patch.object(wi.WorkstationInstance, "fold",
                               side_effect=AssertionError("fold")):
            status = self.run_quietly("--apply", "--verify-users")
        self.assertEqual(status, 0, self.output)
        result = self.result()
        self.assertEqual(result["verdict"], "pass", result["checks"])
        self.assertIs(True, result["checks"]["arch_standard_accounts_login"])
        self.assertEqual(
            [account["contract_role"] for account in standard],
            [record["contract_role"]
             for record in result["facts"]["arch"]["user_logins"]])
        self.assertEqual([a["name"] for a in standard],
                         self.guest.user_sessions)
        self.assertEqual(self.guest.violations, [])
        in_order(self, ["prompt:1", "prompt:2", "prompt:3",
                        "wait:arch-domain-online-observed",
                        "send:arch-verify-user-uid-sent",
                        "send:arch-verify-user-logout",
                        "send:arch-probe-roster-sent"])
        payload = json.dumps(result)
        for account in standard:
            self.assertNotIn(account["name"], payload)
        self.assertNotIn("Standard-Pass-4!", payload)

    def test_a_refused_standard_login_fails_the_verdict(self):
        self.users_setup(password=b"Wrong-Pass-9!")
        status = self.run_quietly("--apply", "--verify-users")
        self.assertEqual(status, 2, self.output)
        result = self.result()
        self.assertEqual(result["verdict"], "fail")
        self.assertIs(False, result["checks"]["arch_standard_accounts_login"])
        self.assertEqual("arch", result["failures"][0]["step"])
        # Windows is still verified after the recorded Arch failure.
        self.assertIs(True, result["checks"]["windows_signed_in"])

    def test_without_the_option_nothing_changes(self):
        self.assertEqual(self.apply(), 0, self.output)
        self.assertNotIn("arch_standard_accounts_login",
                         self.result()["checks"])

    def test_the_kept_workstation_is_never_modified(self):
        self.assertEqual(self.apply(), 0, self.output)
        self.assertEqual(snapshot(self.state), self.before)
        result = self.result()
        self.assertTrue(result["checks"]["workstation_unchanged"])
        hashes = result["facts"]["workstation_hashes"]
        self.assertEqual(hashes["before"], hashes["after"])
        # Held throughout, and released after.
        self.assertEqual(self.locks, [("arch-spawn", True)])
        self.assertFalse(wi.WorkstationInstance(self.state).locked())
        # Both overlays are gone; the attempt and evidence stay in the run.
        run_dir, = (self.run_root / "w1").glob("run-*")
        self.assertFalse((run_dir / "arch" / "arch-workstation.qcow2").exists())
        attempt, = (run_dir / "windows" / "w1").glob("attempt-*")
        self.assertFalse((attempt / "windows.qcow2").exists())
        self.assertTrue((attempt / "terminal-teardown.json").is_file())
        authorization = json.loads(
            (attempt / "authorization.json").read_text())
        self.assertEqual(authorization["durable"]["stage"], verify.LABEL)
        self.assertTrue(result["checks"]["overlays_discarded"])

    def test_both_boots_copy_the_variables_without_the_boot_path_cache(self):
        shutil.rmtree(self.state)
        kept = boot_store(extra=(hddp_variable(),))
        self.workstation(vars_bytes=kept)
        before = snapshot(self.state)
        self.assertEqual(self.apply(), 0, self.output)
        self.assertEqual(snapshot(self.state), before)
        self.assertEqual((self.state / wi.VARS_NAME).read_bytes(), kept)
        self.assertTrue(self.result()["checks"]["workstation_unchanged"])
        cleaned, dropped = ovmf_vars.without_hddp(kept)
        self.assertEqual(dropped, 1)
        run_dir, = (self.run_root / "w1").glob("run-*")
        attempt, = (run_dir / "windows" / "w1").glob("attempt-*")
        for copy in (run_dir / "arch" / "OVMF_VARS.fd",
                     attempt / "OVMF_VARS.fd"):
            self.assertEqual(copy.read_bytes(), cleaned, copy)

    def test_nothing_pauses_the_directory_or_injects_a_fault(self):
        recorded: list[str] = []

        def recorder(name):
            def record(*_args, **_kwargs):
                recorded.append(name)
            return record

        with mock.patch.object(
                verify.DurableWindowsBoundary, "_set_process_available",
                recorder("windows-fault")), \
                mock.patch.object(verify.VerifyArchBoundary,
                                  "take_controller_offline",
                                  recorder("arch-offline")), \
                mock.patch.object(verify.VerifyArchBoundary,
                                  "make_storage_unreachable",
                                  recorder("arch-storage")), \
                mock.patch("os.kill", recorder("kill")):
            self.assertEqual(self.apply(), 0, self.output)
        self.assertEqual(recorded, [])
        session, = FakeSession.instances
        self.assertEqual(session.forbidden, [])
        verify_run, = self.verifies
        for hook in ("take_controller_offline", "restore_controller",
                     "make_storage_unreachable"):
            with self.subTest(hook=hook):
                with self.assertRaisesRegex(step7.ArchDurableJoinError,
                                            "never takes"):
                    getattr(verify_run.arch_boundary, hook)()

    def test_no_typed_value_reaches_argv_env_evidence_or_output(self):
        environment = dict(os.environ)
        self.assertEqual(self.apply(), 0, self.output)
        self.assertEqual(dict(os.environ), environment)
        self.assertEqual(hits(
            [f"{k}={v}".encode() for k, v in os.environ.items()]), 0)
        verify_run, = self.verifies
        argv = [" ".join(command).encode()
                for _role, command in verify_run.arch_boundary.spawned]
        self.assertTrue(argv)
        self.assertEqual(hits(argv), 0)
        files = [path for path in self.run_root.rglob("*") if path.is_file()]
        evidence = self.run_root / "w1"
        for expected in ("evidence/result.json",
                         "evidence/controller-transcript.log",
                         "arch/evidence/workstation-serial.log",
                         "arch/evidence/workstation-boot.json"):
            self.assertTrue(any(str(path).endswith(expected)
                                for path in files), expected)
        self.assertEqual(hits([path.read_bytes() for path in files]), 0)
        self.assertEqual(hits([self.output.encode()]), 0)
        result = self.result()
        self.assertTrue(result["checks"]["evidence_secret_free"])
        for value in PRIVATE_VALUES:
            self.assertNotIn(value, json.dumps(result["failures"]))
        # The Controller transcript was redacted against both typed values.
        session, = FakeSession.instances
        self.assertEqual(set(session.redaction_secrets), set(TYPED))
        self.assertTrue(evidence.is_dir())

    def test_a_menu_that_no_longer_defaults_to_windows_fails_the_verdict(self):
        self.guest_options = {"menu_default": "Arch Linux LTS"}
        self.assertEqual(self.apply(), 2)
        result = self.result()
        self.assertEqual(result["verdict"], "fail")
        self.assertFalse(result["checks"]["menu_defaults_to_windows"])
        # Everything else still ran and passed.
        self.assertTrue(result["checks"]["windows_secure_channel"])
        self.assertIn("menu_defaults_to_windows", self.output)

    def test_an_arch_failure_is_recorded_and_windows_still_verified(self):
        self.guest_options = {"testjoin": False}
        self.assertEqual(self.apply(), 2)
        result = self.result()
        self.assertEqual(result["verdict"], "fail")
        self.assertFalse(result["checks"]["arch_testjoin_passed"])
        self.assertTrue(result["checks"]["arch_uids_pinned"])
        self.assertTrue(result["checks"]["arch_workstation_clean_poweroff"])
        self.assertEqual([f["step"] for f in result["failures"]], ["arch"])
        self.assertIn("testjoin", result["failures"][0]["message"])
        self.assertTrue(result["checks"]["controller_relaunched"])
        self.assertTrue(result["checks"]["windows_secure_channel"])
        self.assertIn("windows-start", TIMELINE)
        self.assertEqual(snapshot(self.state), self.before)

    def test_a_broken_secure_channel_fails_after_a_clean_shutdown(self):
        self.records = probe_records(secure=False)
        self.assertEqual(self.apply(), 2)
        result = self.result()
        self.assertFalse(result["checks"]["windows_secure_channel"])
        self.assertTrue(result["checks"]["windows_clean_shutdown"])
        self.assertTrue(result["checks"]["windows_teardown_complete"])
        self.assertEqual([f["step"] for f in result["failures"]],
                         ["windows"])

    def test_a_refused_sign_in_is_recorded_and_the_controller_stops(self):
        self.sign_in_error = RuntimeError(
            f"sign-in refused for {DAILY_UPN} with {DAILY.decode()}")
        self.assertEqual(self.apply(), 2)
        result = self.result()
        self.assertFalse(result["checks"]["windows_signed_in"])
        self.assertTrue(result["checks"]["windows_teardown_complete"])
        self.assertTrue(result["checks"]["controller_clean_poweroffs"])
        message = result["failures"][0]["message"]
        self.assertNotIn(DAILY.decode(), message)
        for value in PRIVATE_VALUES:
            self.assertNotIn(value, message)
        self.assertIn("terminate:windows", TIMELINE)

    def test_a_foreign_directory_stops_everything_before_a_workstation(self):
        def refuse(console, bound, checks):
            TIMELINE.append("directory-refused")
            raise DurableBindingError("a different directory")

        self.probe = refuse
        self.assertEqual(self.apply(), 2)
        result = self.result()
        self.assertEqual([f["step"] for f in result["failures"]],
                         ["controller"])
        self.assertNotIn("spawn:workstation", TIMELINE)
        self.assertNotIn("windows-start", TIMELINE)
        in_order(self, ["session-start", "directory-refused", "session-stop",
                        "fabric-stop"])
        self.assertTrue(result["checks"]["overlays_discarded"])
        self.assertEqual(snapshot(self.state), self.before)


class CommandLineTests(unittest.TestCase):
    def test_the_command_line_needs_its_names(self):
        for missing in ("--workstation", "--persistent-dc", "--hostname"):
            argv = ["--workstation", "w1", "--persistent-dc", INSTANCE,
                    "--hostname", HOSTNAME]
            index = argv.index(missing)
            del argv[index:index + 2]
            with self.subTest(missing=missing), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    verify.parser().parse_args(argv)
        args = verify.parser().parse_args(
            ["--workstation", "w1", "--persistent-dc", INSTANCE,
             "--hostname", HOSTNAME])
        self.assertFalse(args.apply)
        self.assertEqual(args.run_root, verify.DEFAULT_RUNS)


if __name__ == "__main__":
    unittest.main()
