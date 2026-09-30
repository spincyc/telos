"""Resetting one staged durable account's password: program, channel, runner.

``RESTAGE=1`` is create-only (it stops with ``account-exists``), so a lost
temporary password needs a reset: ``make
homelab-factory-persistent-account-password``.  No guest is launched and no
Samba is imported: the guest program runs here against a fake directory, the
console is a socket pair or a fake, the instance is synthetic and lives in a
temporary directory, and nothing here reads ``build/``, ``homelab/var/`` or
``homelab/instance/``.  Every account name is a placeholder (``roster-b``).
"""

import base64
import contextlib
import copy
import io
import json
import re
import socket
import subprocess
import sys
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

from homelab.tests.identity_overlay_pin import (
    overlay_document, pinned_acceptance_state, pinned_identity_overlay)
from homelab.tests.test_persistent_controller_session import (
    BOOTSTRAP, DOMAIN, FINGERPRINT, INSTANCE, PASSWORD, REAL_POPEN, REALM,
    SID, FakeGuest, SessionFixture)
from homelab.vm import (
    bootstrap_dc,
    controller_principals,
    durable_workstation,
    persistent_account_password as runner,
    persistent_controller_session as session_module,
    persistent_password_policy as policy_runner,
    simulated_gateway,
)
from homelab.vm.controller_principals import (
    ControllerPasswordReset,
    ControllerPrincipalError,
    ControllerPrincipalSerial,
    _principal_result_pattern,
    password_reset_program,
    password_reset_proof,
)
from homelab.vm.directory_password_policy import (
    DirectoryPasswordPolicy, policy_record)
from homelab.vm.secret_scan import count_secret_occurrences, secret_needles
from homelab.vm.simulation_overlay import (
    PERSISTENT_ACCOUNTS_KEY, PERSISTENT_PASSWORD_RESETS_KEY,
    PersistentControllerInstance, PersistentInstanceInvalid)


def setUpModule():
    # HANDOFF section 5: no test reads the owner's overlay or build/.
    unittest.enterModuleContext(pinned_identity_overlay())
    unittest.enterModuleContext(pinned_acceptance_state())


#: A synthetic durable roster: positional uidNumbers for the three directory
#: roles and one additional standard user.
NAMES = {"standard_user": "roster-a", "daily_administrator": "roster-b",
         "domain_administrator": "roster-c"}
OVERLAY = {**overlay_document(NAMES), "additional_standard_users": [
    {"name": "roster-e", "uid_number": 10005}]}
STAGED_ACCOUNTS = [
    {"contract_role": "standard_user", "role": "standard",
     "uidNumber": 10000, "gidNumber": 10513},
    {"contract_role": "daily_administrator", "role": "standard",
     "uidNumber": 10001, "gidNumber": 10513},
    {"contract_role": "domain_administrator", "role": "administrator",
     "uidNumber": 10002, "gidNumber": 10513},
    {"contract_role": "additional_standard_user_10005", "role": "standard",
     "uidNumber": 10005, "gidNumber": 10513},
]
VALUE = "Tmp-reset-value-8"
RELAXED = DirectoryPasswordPolicy(
    min_length=4, complexity=False, min_age_days=0,
    source=f"{INSTANCE}'s recorded directory policy")


# -- the guest program, against a fake directory ------------------------------

class LdbError(Exception):
    """Named exactly as Samba's, which is what ``failure_reason`` keys on."""


class FakeElement:
    def __init__(self, value, flags, name):
        self.value, self.flags, self.name = value, flags, name


class FakeMessage(dict):
    dn = None


class FakeRecord(dict):
    def __init__(self, dn, values):
        super().__init__(values)
        self.dn = dn


class FakeDirectory:
    """Just enough of ``SamDB`` for the reset program; it cannot create."""

    EXPRESSION = re.compile(
        r"\(&\(objectClass=user\)\(sAMAccountName=([a-z0-9-]+)\)\)")

    def __init__(self, accounts):
        self.accounts = copy.deepcopy(accounts)
        self.writes = []
        self.transactions = []
        self.refuse_password = False
        self.change_sid = False
        self.stamp = 134000000000000000
        self._snapshot = None

    # -- SamDB -------------------------------------------------------------
    def search(self, expression=None, attrs=None, **_kwargs):
        name = self.EXPRESSION.fullmatch(expression).group(1)
        account = self.accounts.get(name)
        if account is None:
            return []
        values = {
            "sAMAccountName": [name],
            "objectSid": [account["objectSid"]],
            "uidNumber": [str(account["uidNumber"])],
            "pwdLastSet": [str(account["pwdLastSet"])],
            "msDS-User-Account-Control-Computed": [
                str(0x800000 if account["pwdLastSet"] == 0 else 0)],
        }
        return [FakeRecord(f"CN={name},CN=Users,DC=example",
                           {key: values[key] for key in attrs})]

    def modify(self, message):
        name = message.dn.split(",", 1)[0][3:]
        account = self.accounts[name]
        for key, element in message.items():
            self.writes.append(key)
            if key == "unicodePwd":
                if self.refuse_password:
                    raise LdbError(
                        19, "check_password_restrictions: the password is "
                        "too short")
                account["unicodePwd"] = element.value
                # The DC stamps pwdLastSet on every password set.
                account["pwdLastSet"] = self.stamp
                if self.change_sid:
                    account["objectSid"] = b"another"
            elif key == "pwdLastSet":
                account["pwdLastSet"] = int(element.value)
            else:
                raise AssertionError(f"the reset wrote {key}")

    def transaction_start(self):
        self.transactions.append("start")
        self._snapshot = copy.deepcopy(self.accounts)

    def transaction_commit(self):
        self.transactions.append("commit")

    def transaction_cancel(self):
        self.transactions.append("cancel")
        self.accounts = self._snapshot

    def newuser(self, *_args, **_kwargs):
        raise AssertionError("a password reset created an account")


def guest_modules(directory):
    ldb = types.ModuleType("ldb")
    ldb.FLAG_MOD_REPLACE = 2
    ldb.Message = FakeMessage
    ldb.MessageElement = FakeElement
    ldb.LdbError = LdbError
    samba = types.ModuleType("samba")
    auth = types.ModuleType("samba.auth")
    auth.system_session = lambda: "system"
    param = types.ModuleType("samba.param")

    class LoadParm:
        def load_default(self):
            return None

    param.LoadParm = LoadParm
    samdb = types.ModuleType("samba.samdb")
    samdb.SamDB = lambda **_kwargs: directory
    return {"ldb": ldb, "samba": samba, "samba.auth": auth,
            "samba.param": param, "samba.samdb": samdb}


def account(uid=10001, pwd_last_set=0):
    return {"objectSid": b"\x01\x05sid-of-roster-b", "uidNumber": uid,
            "pwdLastSet": pwd_last_set}


class ResetProgramTests(unittest.TestCase):
    def execute(self, directory, *, must_change=True, uid=10001,
                name="roster-b", payload=None):
        program = password_reset_program(name, uid, must_change=must_change)
        stdin = io.StringIO(json.dumps(
            {name: VALUE} if payload is None else payload))
        out = io.StringIO()
        error = None
        with mock.patch.dict(sys.modules, guest_modules(directory)), \
             mock.patch.object(sys, "stdin", stdin), \
             contextlib.redirect_stdout(out):
            try:
                exec(compile(program, "reset", "exec"), {"__name__": "x"})
            except BaseException as raised:  # noqa: BLE001 - the program's
                error = raised
        return out.getvalue(), error

    def result(self, printed, rc):
        """What the host's result pattern reads from this program's output."""
        buffer = (printed.replace("\n", "\r\n")
                  + f"\r\n__RC_tok={rc}\r\n").encode()
        return re.search(
            _principal_result_pattern(b"__RC_tok=", proof=True), buffer,
            re.MULTILINE)

    def test_a_must_change_reset_reads_back_pwdlastset_zero(self):
        directory = FakeDirectory({"roster-b": account(pwd_last_set=0)})
        printed, error = self.execute(directory)
        self.assertIsNone(error)
        match = self.result(printed, 0)
        self.assertEqual(match.group("proof").decode(),
                         password_reset_proof(True))
        self.assertEqual(password_reset_proof(True),
                         "must-change+sid-unchanged+uid-unchanged")
        self.assertIsNone(match.group("reason"))
        stored = directory.accounts["roster-b"]
        self.assertEqual(stored["pwdLastSet"], 0)
        self.assertEqual(stored["unicodePwd"],
                         f'"{VALUE}"'.encode("utf-16-le"))
        self.assertEqual(directory.writes, ["unicodePwd", "pwdLastSet"])
        self.assertEqual(directory.transactions, ["start", "commit"])
        self.assertNotIn(VALUE, printed)

    def test_a_permanent_reset_keeps_the_dcs_timestamp(self):
        directory = FakeDirectory({"roster-b": account(pwd_last_set=0)})
        printed, error = self.execute(directory, must_change=False)
        self.assertIsNone(error)
        self.assertEqual(self.result(printed, 0).group("proof").decode(),
                         "permanent+sid-unchanged+uid-unchanged")
        self.assertEqual(directory.writes, ["unicodePwd"])
        self.assertGreater(directory.accounts["roster-b"]["pwdLastSet"], 0)

    def test_a_missing_account_is_refused_and_never_created(self):
        directory = FakeDirectory({"roster-a": account(uid=10000)})
        printed, error = self.execute(directory)
        self.assertIsInstance(error, RuntimeError)
        match = self.result(printed, 1)
        self.assertEqual(match.group("reason"), b"account-missing")
        self.assertIsNone(match.group("proof"))
        self.assertEqual(directory.writes, [])
        self.assertEqual(directory.transactions, [])
        self.assertEqual(set(directory.accounts), {"roster-a"})

    def test_a_value_the_directory_refuses_is_password_policy(self):
        directory = FakeDirectory({"roster-b": account(pwd_last_set=5)})
        directory.refuse_password = True
        printed, error = self.execute(directory)
        self.assertIsInstance(error, LdbError)
        self.assertEqual(self.result(printed, 1).group("reason"),
                         b"password-policy")
        self.assertEqual(directory.transactions, ["start", "cancel"])
        self.assertEqual(directory.accounts["roster-b"], account(pwd_last_set=5))
        self.assertNotIn(VALUE, printed)

    def test_an_account_without_its_staged_uid_is_not_written(self):
        directory = FakeDirectory({"roster-b": account(uid=10009)})
        printed, error = self.execute(directory)
        self.assertIsNotNone(error)
        self.assertEqual(self.result(printed, 1).group("reason"),
                         b"account-uidnumber-is-not-the-staged-one")
        self.assertEqual(directory.writes, [])

    def test_a_changed_sid_fails_the_read_back(self):
        directory = FakeDirectory({"roster-b": account()})
        directory.change_sid = True
        printed, error = self.execute(directory)
        self.assertIsNotNone(error)
        self.assertEqual(self.result(printed, 1).group("reason"),
                         b"account-sid-changed")

    def test_a_payload_for_another_account_is_refused_before_any_search(self):
        directory = FakeDirectory({"roster-b": account()})
        _, error = self.execute(directory, payload={"roster-a": VALUE})
        self.assertIsInstance(error, ValueError)
        self.assertEqual(directory.writes, [])

    def test_the_program_never_touches_the_domain_policy(self):
        program = password_reset_program("roster-b", 10001, must_change=True)
        for forbidden in ("pwdProperties", "minPwdLength", "passwordsettings",
                          "set_password_policy", "get_default_basedn",
                          "samdb.newuser", "samdb.deleteuser",
                          "samdb.enable_account", "samdb.setpassword"):
            self.assertNotIn(forbidden, program)

    def test_it_reports_the_stage_programs_categories_verbatim(self):
        stage = controller_principals._STAGE_PROGRAM_TEMPLATE
        reason = controller_principals._stage_failure_reason()
        self.assertTrue(reason.startswith("def failure_reason(error):"))
        self.assertIn(reason, stage)
        self.assertIn(reason, password_reset_program(
            "roster-b", 10001, must_change=False))
        self.assertIn('return "password-policy"', reason)

    def test_the_account_substitution_is_refused_when_unsafe(self):
        for name, uid in (("Roster-B", 10001), ("roster'b", 10001),
                          ("roster-b", 99), ("roster-b", True)):
            with self.subTest(name=name, uid=uid):
                with self.assertRaises(ValueError):
                    password_reset_program(name, uid, must_change=True)


# -- the console channel -------------------------------------------------------

class ResetChannelTests(unittest.TestCase):
    """``reset_password`` over the staging protocol, with a socket guest."""

    def setUp(self):
        temporary = self.enterContext(
            __import__("tempfile").TemporaryDirectory())
        self.overlay = Path(temporary) / "principals.json"
        self.overlay.write_text(json.dumps(OVERLAY))
        self.roster = controller_principals.durable_directory_roster(
            self.overlay)

    def run_reset(self, *, printed=b"", returncode=0, must_change=True):
        left, right = socket.socketpair()
        observed = []
        sudo_password = b"console-secret-typed-9"

        def responder():
            stream = right.makefile("rb", buffering=0)
            stream.readline()
            right.sendall(b"[local-rescue@bootstrap-dc ~]$ ")
            command = stream.readline()
            observed.append(command)
            token = command.split(
                b"__TELOS_PRINCIPAL_READY_", 1)[1].split(b"__", 1)[0]
            result = command.split(
                b"__TELOS_PRINCIPAL_RC_", 1)[1].split(b"=", 1)[0]
            prompt = command.split(
                b"__TELOS_PRINCIPAL_SUDO_", 1)[1].split(b"__", 1)[0]
            right.sendall(command)
            right.sendall(b"__TELOS_PRINCIPAL_READY_" + token + b"__\r\n")
            observed.append(stream.readline())
            right.sendall(b"\r\n__TELOS_PRINCIPAL_SUDO_" + prompt + b"__\r\n")
            observed.append(stream.readline())
            right.sendall(printed + b"\r\n__TELOS_PRINCIPAL_RC_" + result
                          + b"=" + str(returncode).encode() + b"\r\n")

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        try:
            serial = ControllerPrincipalSerial(
                left.makefile("rb", buffering=0),
                left.makefile("wb", buffering=0), timeout=2,
                password=sudo_password, roster=self.roster,
                roster_source="a synthetic roster")
            outcome = serial.reset_password(
                "roster-b", VALUE, uid_number=10001, must_change=must_change)
        finally:
            left.close()
            right.close()
            thread.join(timeout=2)
        return outcome, observed

    def test_the_value_crosses_only_on_stdin_with_echo_off(self):
        proof = b"\r\n__TELOS_PRINCIPAL_PROOF=" + password_reset_proof(
            True).encode()
        outcome, observed = self.run_reset(printed=proof)
        self.assertIsInstance(outcome, ControllerPasswordReset)
        self.assertEqual(outcome.proof, password_reset_proof(True))
        self.assertTrue(outcome.must_change)
        command, payload, sudo = observed
        self.assertIn(b"stty -echo || exit 91", command)
        self.assertIn(b"os.close(2)", command)
        self.assertIn(b"sudo -k -p", command)
        self.assertEqual(
            json.loads(base64.b64decode(payload)), {"roster-b": VALUE})
        self.assertEqual(sudo, b"console-secret-typed-9\n")
        needles = secret_needles([VALUE])
        self.assertEqual(count_secret_occurrences([command], needles), 0)
        self.assertNotIn(VALUE, repr(outcome))
        # The encoded program is the reset program, for this account only.
        encoded = command.split(b"b64decode('", 1)[1].split(b"'", 1)[0]
        self.assertEqual(
            base64.b64decode(encoded).decode(),
            password_reset_program("roster-b", 10001, must_change=True))

    def test_success_needs_the_read_back_proof(self):
        for printed in (b"", b"\r\n__TELOS_PRINCIPAL_PROOF="
                        + password_reset_proof(False).encode()):
            with self.subTest(printed=printed):
                with self.assertRaisesRegex(
                        ControllerPrincipalError, "read-back proof"):
                    self.run_reset(printed=printed, must_change=True)

    def test_a_guest_refusal_carries_its_category(self):
        with self.assertRaisesRegex(
                ControllerPrincipalError,
                "password-reset returned 1: account-missing"):
            self.run_reset(
                printed=b"\r\n__TELOS_PRINCIPAL_FAILURE=account-missing",
                returncode=1)

    def test_only_a_durable_roster_member_can_be_reset(self):
        acceptance = ControllerPrincipalSerial(io.BytesIO(), io.BytesIO())
        with self.assertRaisesRegex(ValueError, "durable roster only"):
            acceptance.reset_password(
                acceptance.roles[0], VALUE, uid_number=10000,
                must_change=True)
        durable = ControllerPrincipalSerial(
            io.BytesIO(), io.BytesIO(), roster=self.roster,
            roster_source="a synthetic roster")
        with self.assertRaisesRegex(ValueError, "not in this console") as raised:
            durable.reset_password(
                "roster-z", VALUE, uid_number=10001, must_change=True)
        self.assertNotIn("roster-z", str(raised.exception))
        for value in ("", "two\nlines", "nul\x00"):
            with self.assertRaisesRegex(ValueError, "credential"):
                durable.reset_password(
                    "roster-b", value, uid_number=10001, must_change=True)


# -- the marker ----------------------------------------------------------------

def write_marker(state: Path, **extra) -> None:
    marker = {"schema": 1, "mode": "persistent", "instance": INSTANCE,
              "created_utc": "2026-01-01T00:00:00+00:00",
              "seeded_from": {"disk": "canonical.qcow2",
                              "disk_sha256": "0" * 64},
              PERSISTENT_ACCOUNTS_KEY: {
                  "staged_utc": "2026-01-02T00:00:00+00:00",
                  "roster_fingerprint": FINGERPRINT,
                  "password_change_at_first_logon": True,
                  "accounts": STAGED_ACCOUNTS}}
    marker.update(extra)
    (state / "persistent-instance.json").write_text(json.dumps(marker))


class ResetRecordTests(unittest.TestCase):
    def setUp(self):
        temporary = self.enterContext(
            __import__("tempfile").TemporaryDirectory())
        self.state = Path(temporary) / "persistent" / INSTANCE
        self.state.mkdir(parents=True)
        write_marker(self.state)
        self.target = PersistentControllerInstance(
            self.state, instance=INSTANCE)

    def entry(self, **changes):
        return {"role": "daily_administrator", "utc": "2026-09-30T20:00:00",
                "must_change": True, "run_id": "run-1", **changes}

    def test_entries_are_appended_and_the_staged_record_is_untouched(self):
        before = self.target.directory_accounts()
        self.assertEqual(self.target.directory_account_password_resets(), [])
        self.target.record_directory_account_password_reset(self.entry())
        self.target.record_directory_account_password_reset(
            self.entry(utc="2026-09-30T21:00:00", must_change=False,
                       run_id="run-2"))
        self.assertEqual(
            [entry["run_id"]
             for entry in self.target.directory_account_password_resets()],
            ["run-1", "run-2"])
        self.assertEqual(self.target.directory_accounts(), before)

    def test_an_entry_can_carry_no_name_and_no_value(self):
        for entry in (self.entry(name="roster-b"),
                      self.entry(password=VALUE),
                      self.entry(role="roster-b"),
                      self.entry(role="local_rescue"),
                      self.entry(must_change="yes"),
                      self.entry(utc="")):
            with self.subTest(entry=sorted(entry)):
                with self.assertRaises(PersistentInstanceInvalid):
                    self.target.record_directory_account_password_reset(entry)
        self.assertEqual(self.target.directory_account_password_resets(), [])
        raw = json.loads((self.state / "persistent-instance.json").read_text())
        self.assertNotIn(PERSISTENT_PASSWORD_RESETS_KEY, raw)

    def test_status_prints_the_latest_reset_per_role(self):
        for utc, role, must_change in (
                ("2026-09-30T20:00:00", "daily_administrator", True),
                ("2026-09-30T21:00:00", "standard_user", False),
                ("2026-09-30T22:00:00", "daily_administrator", False)):
            self.target.record_directory_account_password_reset(self.entry(
                utc=utc, role=role, must_change=must_change))
        line = bootstrap_dc._persistent_password_resets_summary(
            self.target, True)
        self.assertEqual(
            line, "daily_administrator 2026-09-30T22:00:00 (permanent); "
                  "standard_user 2026-09-30T21:00:00 (permanent)")
        self.assertNotIn("20:00:00", line)
        fresh = PersistentControllerInstance(self.state, instance=INSTANCE)
        write_marker(self.state)
        self.assertIn("none recorded", bootstrap_dc
                      ._persistent_password_resets_summary(fresh, True))


# -- the runner ----------------------------------------------------------------

class AccountPasswordRunTests(SessionFixture):
    """The target's runner, with the probe's and the policy runner's fakes."""

    def setUp(self):
        super().setUp()
        write_marker(self.state, converged={
            "converged_utc": "2026-01-01T00:00:00+00:00",
            "realm": REALM, "netbios": "EXAMPLEAD", "dns_domain": DOMAIN,
            "domain_sid": SID})
        self.identity = self.root / "directory.json"
        self.identity.write_text(json.dumps({
            "schema_version": 1,
            "identity": {"dns_domain": DOMAIN, "kerberos_realm": REALM,
                         "netbios_name": "EXAMPLEAD"},
            "services": {"bootstrap_dc_fqdn": BOOTSTRAP,
                         "permanent_dc_fqdn": f"dc2.{DOMAIN}"},
            "network": {
                "address": str(simulated_gateway.CONTROLLER_IP),
                "prefix": durable_workstation.FABRIC_PREFIX,
                "gateway": str(simulated_gateway.GATEWAY_IP)},
        }))
        self.overlay = self.root / "principals.json"
        self.overlay.write_text(json.dumps(OVERLAY))
        self.evidence = self.root / "evidence"
        self.live_sid = SID
        self.prompts = []
        self.typed_values = [PASSWORD, VALUE.encode()]
        self.exchanges = []
        self.guest = {"proof": password_reset_proof(True), "rc": 0,
                      "reason": None}
        self.children = []
        self.guest_output = (
            b"bootstrap-dc login: local-rescue\r\nPassword: " + PASSWORD
            + b"\r\n$ ")
        patch = mock.patch.object(
            durable_workstation, "_current_roster_fingerprint",
            return_value=FINGERPRINT)
        patch.start()
        self.addCleanup(patch.stop)

    def run_reset(self, role="daily_administrator", must_change=True,
                  apply=True):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = runner.account_password(
                self.state.parent, INSTANCE, role, must_change, apply,
                canonical_state=self.canonical, identity_path=self.identity,
                overlay_path=self.overlay, evidence_root=self.evidence)
        return code, out.getvalue(), err.getvalue()

    def popen(self, argv, **kwargs):
        argv = list(argv)
        if argv[0] == "qemu-system-x86_64":
            self.calls.append("spawn")
            guest = FakeGuest(argv, self.guest_output)
            self.guests.append(guest)
            return guest
        if argv[0] == runner.sys.executable:
            self.calls.append("fabric")
            child = FakeGuest(argv)
            self.children.append(child)
            return child
        return REAL_POPEN(argv, **kwargs)

    def console_root(self, console, command, label, *, value=None):
        self.calls.append(label)
        return {"reset-realm": REALM.lower().encode(),
                "reset-domain-sid": self.live_sid.encode()}.get(label)

    def typed(self, prompt, **kwargs):
        self.prompts.append((prompt, kwargs.get("confirm")))
        self.calls.append("prompt")
        return self.typed_values[len(self.prompts) - 1]

    def exchange(self, serial, operation, payload, program, *, proof=False):
        self.calls.append(operation)
        self.exchanges.append((operation, payload, program, proof))
        if self.guest["rc"]:
            raise ControllerPrincipalError(
                f"Controller {operation} returned {self.guest['rc']}: "
                f"{self.guest['reason']}")
        line = (b"\r\n__TELOS_PRINCIPAL_PROOF="
                + self.guest["proof"].encode() if self.guest["proof"]
                else b"")
        return re.search(
            _principal_result_pattern(b"__RC=", proof=proof),
            line + b"\r\n__RC=0\r\n", re.MULTILINE)

    @contextlib.contextmanager
    def applied(self):
        patches = [
            mock.patch.object(subprocess, "Popen", side_effect=self.popen),
            mock.patch.object(runner.shutil, "which",
                              return_value="/usr/bin/x"),
            mock.patch.object(
                runner, "ovmf_pair",
                return_value=(Path("/code/OVMF_CODE.fd"), Path("/v"))),
            mock.patch.object(runner, "assert_installed"),
            mock.patch.object(runner, "_typed_secret", side_effect=self.typed),
            mock.patch.object(runner, "wait_for_switch_port"),
            mock.patch.object(session_module, "wait_for_switch_port"),
            mock.patch.object(
                session_module.PersistentControllerSession, "_audit_live",
                lambda session, pid: session.facts.update(
                    live_argv_audited=True)),
            # The realm and SID proof is the policy runner's own helper.
            mock.patch.object(policy_runner, "_console_root",
                              side_effect=self.console_root),
            mock.patch.object(
                ControllerPrincipalSerial, "_exchange",
                lambda serial, *args, **kwargs: self.exchange(
                    serial, *args, **kwargs)),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            stack.enter_context(self.console_fakes())
            yield

    def resets(self):
        return PersistentControllerInstance(
            self.state, instance=INSTANCE).directory_account_password_resets()

    def result(self):
        [run] = list((self.evidence / INSTANCE).iterdir())
        return run, json.loads((run / "result.json").read_text())

    def record_relaxed_policy(self):
        PersistentControllerInstance(
            self.state, instance=INSTANCE).record_directory_password_policy(
                policy_record(RELAXED, run_id="p"))

    def test_the_dry_run_names_the_role_and_starts_nothing(self):
        with mock.patch.object(
                subprocess, "Popen",
                side_effect=AssertionError("a dry run started a process")), \
             mock.patch.object(
                runner, "_typed_secret",
                side_effect=AssertionError("a dry run asked for a password")):
            code, out, err = self.run_reset(apply=False)
        self.assertEqual(code, 0, err)
        self.assertIn("dry run; repeat with APPLY=1", out)
        self.assertIn("account: daily_administrator (directory role "
                      "standard, uidNumber 10001)", out)
        self.assertIn("TEMPORARY", out)
        self.assertIn("not RESTAGE", out)
        for value in ("roster-b", REALM, DOMAIN, SID, BOOTSTRAP,
                      str(simulated_gateway.CONTROLLER_IP)):
            self.assertNotIn(value, out)
        self.assertFalse(self.evidence.exists())
        self.assertEqual(self.resets(), [])
        self.assertEqual(self.calls, [])

    def test_an_unknown_role_is_refused_before_any_prompt(self):
        with self.applied():
            for role in ("roster-b", "local_rescue", "operator", "",
                         "additional_standard_user_10009"):
                with self.subTest(role=role):
                    code, _, err = self.run_reset(role=role)
                    self.assertEqual(code, 2)
                    self.assertIn("ROLE must be one of", err)
                    self.assertIn("daily_administrator", err)
                    if role:
                        self.assertNotIn(role, err)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.evidence.exists())

    def test_the_value_is_judged_by_the_recorded_policy_before_boot(self):
        # Samba's default when none is recorded: four characters are refused.
        self.typed_values = [PASSWORD, b"abcd"]
        with self.applied():
            code, _, err = self.run_reset()
        self.assertEqual(code, 2)
        self.assertIn("shorter than 7 characters", err)
        self.assertIn("the directory's default policy", err)
        self.assertNotIn("abcd", err)
        self.assertNotIn("spawn", self.calls)
        # The recorded relaxed policy takes four and refuses three.
        self.record_relaxed_policy()
        for value, refused in ((b"abc", True), (b"abcd", False)):
            with self.subTest(length=len(value)):
                self.calls.clear()
                self.prompts.clear()
                self.typed_values = [PASSWORD, value]
                with self.applied():
                    code, _, err = self.run_reset()
                self.assertEqual(code, 2 if refused else 0, err)
                self.assertEqual("spawn" in self.calls, not refused)
                if refused:
                    self.assertIn(f"{INSTANCE}'s recorded directory policy",
                                  err)

    def test_a_proven_must_change_reset_is_recorded_and_secret_free(self):
        self.record_relaxed_policy()
        with self.applied():
            code, out, err = self.run_reset()
        self.assertEqual(code, 0, err)
        # Both prompts, the new value confirmed, before any process starts;
        # the account name appears in the prompt and nowhere else.
        self.assertEqual(self.calls[:5],
                         ["prompt", "prompt", "fabric", "fabric", "spawn"])
        self.assertIn("console password", self.prompts[0][0])
        self.assertIn("daily_administrator (roster-b)", self.prompts[1][0])
        self.assertIsNotNone(self.prompts[1][1])
        self.assertEqual(
            [call for call in self.calls if call.startswith("reset-")
             or call in ("password-reset", "poweroff")],
            ["reset-realm", "reset-domain-sid", "password-reset", "poweroff"])
        [(operation, payload, program, proof)] = self.exchanges
        self.assertEqual(payload, {"roster-b": VALUE})
        self.assertTrue(proof)
        self.assertEqual(program, password_reset_program(
            "roster-b", 10001, must_change=True))
        [entry] = self.resets()
        run, result = self.result()
        self.assertEqual(entry, {"role": "daily_administrator",
                                 "utc": entry["utc"], "must_change": True,
                                 "run_id": result["run_id"]})
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["read_back"], password_reset_proof(True))
        self.assertTrue(all(result["checks"][key] is True
                            for key in runner.REQUIRED_CHECKS))
        self.assertEqual(self.guests[0].signals, [])
        self.assertFalse(self.lock_held())
        # The repository's secret scanner, over every retained byte, the
        # marker, every argv and the printed output: no value, no name.
        needles = secret_needles([VALUE, PASSWORD, "roster-b"])
        retained = [path.read_bytes() for path in sorted(run.iterdir())]
        retained.append((self.state / "persistent-instance.json").read_bytes())
        self.assertEqual(count_secret_occurrences(retained, needles), 0)
        argvs = [" ".join(child.argv).encode()
                 for child in self.guests + self.children]
        self.assertEqual(count_secret_occurrences(argvs, needles), 0)
        self.assertEqual(count_secret_occurrences(
            [out.encode(), err.encode()], needles), 0)
        self.assertIn("PASS", out)
        self.assertIn("directory account password resets: "
                      "daily_administrator", self.status())

    def status(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bootstrap_dc.persistent_status(self.state.parent, INSTANCE)
        return out.getvalue()

    def test_a_missing_account_fails_and_records_nothing(self):
        self.record_relaxed_policy()
        self.guest.update(rc=1, reason="account-missing", proof=None)
        with self.applied():
            code, out, err = self.run_reset()
        self.assertEqual(code, 2)
        self.assertIn("account-missing", err)
        self.assertIn("FAIL", out)
        self.assertEqual(self.resets(), [])
        _, result = self.result()
        self.assertEqual(result["failure"]["step"], "reset")
        self.assertIn("account-missing", result["failure"]["message"])
        self.assertFalse(result["recorded"])
        self.assertTrue(result["checks"]["clean_poweroff"])
        self.assertEqual(self.guests[0].signals, [])

    def test_a_transcript_that_would_carry_the_value_is_withheld(self):
        self.record_relaxed_policy()
        self.guest_output += base64.b64encode(
            json.dumps({"roster-b": VALUE}).encode()) + b"\r\n"
        with self.applied():
            code, _, err = self.run_reset()
        self.assertEqual(code, 2)
        self.assertIn("transcript_secret_free", err)
        self.assertIn("new password is in effect", err)
        self.assertEqual(self.resets(), [])
        run, result = self.result()
        self.assertFalse((run / "console-transcript.log").exists())
        self.assertFalse(result["checks"]["transcript_secret_free"])

    def test_another_directory_is_refused_before_the_reset(self):
        self.record_relaxed_policy()
        self.live_sid = "S-1-5-21-4444444444-5555555555-6666666666"
        with self.applied():
            code, _, err = self.run_reset()
        self.assertEqual(code, 2)
        self.assertIn("different directory", err)
        self.assertNotIn("password-reset", self.calls)
        self.assertEqual(self.resets(), [])


if __name__ == "__main__":
    unittest.main()
