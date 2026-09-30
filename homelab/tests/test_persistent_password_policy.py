"""A persistent instance's directory password policy: model, record, runner.

The owner chose short, change-it-later passwords for the throwaway
``rehearsal`` on 2026-09-30.  Samba's default policy refuses them, so the
policy is set explicitly (``make homelab-factory-persistent-password-policy``),
proven by read-back, recorded in the instance marker, and every host-side
pre-check reads it back from there.  No guest is launched: every process is a
fake, the instance is synthetic and lives in a temporary directory, and nothing
here reads ``build/``, ``homelab/var/`` or ``homelab/instance/``.
"""

import contextlib
import io
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.tests.identity_overlay_pin import pinned_acceptance_state
from homelab.tests.test_persistent_controller_session import (
    BOOTSTRAP, DOMAIN, FINGERPRINT, INSTANCE, PASSWORD, REAL_POPEN, REALM,
    SID, TRUNCATED, FakeGuest, SessionFixture)
from homelab.vm import (
    controller_principals,
    directory_password_policy as policy_module,
    durable_workstation,
    persistent_controller_session as session_module,
    persistent_password_policy as runner,
    simulated_gateway,
)
from homelab.vm.directory_password_policy import (
    SAMBA_DEFAULT, DirectoryPasswordPolicy, DirectoryPasswordPolicyError)
from homelab.vm.simulation_overlay import (
    PERSISTENT_PASSWORD_POLICY_KEY, PersistentControllerInstance,
    PersistentInstanceInvalid)


def setUpModule():
    # HANDOFF section 5: every persistent-instance separation check resolves
    # the reserved acceptance state; reserve private spellings of it.
    unittest.enterModuleContext(pinned_acceptance_state())


#: ``samba-tool domain passwordsettings show`` exactly as Samba prints it,
#: header and all.  The DN is Samba's own documentation example.
SHOW_DEFAULT = """\
Password information for domain 'DC=samdom,DC=example,DC=com'

Password complexity: on
Store plaintext passwords: off
Password history length: 24
Minimum password length: 7
Minimum password age (days): 1
Maximum password age (days): 42
Account lockout duration (mins): 30
Account lockout threshold (attempts): 0
Reset account lockout after (mins): 30
"""
SHOW_RELAXED = (SHOW_DEFAULT
                .replace("Password complexity: on", "Password complexity: off")
                .replace("Minimum password length: 7",
                         "Minimum password length: 4")
                .replace("Minimum password age (days): 1",
                         "Minimum password age (days): 0"))
#: The guest-side filter ``SHOW_COMMAND`` applies before joining the lines.
GUEST_FILTER = re.compile(r"^[A-Za-z][A-Za-z ()]*: [0-9A-Za-z-]+$")
RELAXED = DirectoryPasswordPolicy(
    min_length=4, complexity=False, min_age_days=0,
    source=f"{INSTANCE}'s recorded directory policy")


def transported(show: str) -> bytes:
    """What ``SHOW_COMMAND`` prints on the console for *show*."""
    lines = [line for line in show.splitlines() if GUEST_FILTER.match(line)]
    return policy_module.SHOW_SEPARATOR.join(lines).encode("ascii")


class PolicyModelTests(unittest.TestCase):
    def test_the_default_is_sambas_and_names_itself_as_before(self):
        self.assertEqual(SAMBA_DEFAULT.rules, (7, True, 1))
        self.assertFalse(SAMBA_DEFAULT.recorded)
        self.assertEqual(SAMBA_DEFAULT.source, "the directory's default policy")
        self.assertEqual(controller_principals.DIRECTORY_MIN_PASSWORD_LENGTH, 7)
        self.assertEqual(controller_principals.DIRECTORY_PASSWORD_CLASSES, 3)

    def test_a_relaxed_request_also_drops_the_minimum_age_to_zero(self):
        for length, switch, expected in (
                ("4", "off", (4, False, 0)),
                ("4", "on", (4, True, 0)),
                ("9", "off", (9, False, 0)),
                ("7", "on", (7, True, 1)),
                ("14", "on", (14, True, 1)),
                ("1", "off", (1, False, 0))):
            with self.subTest(length=length, complexity=switch):
                policy = policy_module.requested_policy(
                    length, switch, instance=INSTANCE)
                self.assertEqual(policy.rules, expected)
                self.assertTrue(policy.recorded)
                self.assertIn(INSTANCE, policy.source)

    def test_an_unusable_request_is_refused_by_the_variable_it_came_from(self):
        for length, switch, reason in (
                ("0", "off", "from 1 to 14"),
                ("15", "off", "Samba's maximum is 14"),
                ("-1", "off", "whole number"),
                ("4.5", "off", "whole number"),
                ("four", "off", "whole number"),
                ("", "off", "MIN_PASSWORD_LENGTH is required"),
                (None, "off", "MIN_PASSWORD_LENGTH is required"),
                ("4", "", "PASSWORD_COMPLEXITY"),
                ("4", "ON", "PASSWORD_COMPLEXITY"),
                ("4", "yes", "PASSWORD_COMPLEXITY")):
            with self.subTest(length=length, complexity=switch):
                with self.assertRaisesRegex(
                        DirectoryPasswordPolicyError, re.escape(reason)):
                    policy_module.requested_policy(
                        length, switch, instance=INSTANCE)

    def test_a_policy_value_cannot_leave_sambas_bounds(self):
        for values in ({"min_length": 0}, {"min_length": 15},
                       {"min_length": True}, {"complexity": "off"},
                       {"min_age_days": -1}, {"min_age_days": 999},
                       {"source": ""}):
            with self.subTest(values=values):
                with self.assertRaises(DirectoryPasswordPolicyError):
                    DirectoryPasswordPolicy(**values)

    def test_the_set_command_carries_only_the_three_settings(self):
        self.assertEqual(
            policy_module.set_command(RELAXED),
            "/usr/bin/samba-tool domain passwordsettings set "
            "--min-pwd-length=4 --complexity=off --min-pwd-age=0")


class ShowParsingTests(unittest.TestCase):
    def test_sambas_real_output_parses(self):
        self.assertEqual(
            policy_module.parse_passwordsettings_show(SHOW_DEFAULT).rules,
            SAMBA_DEFAULT.rules)
        self.assertEqual(
            policy_module.parse_passwordsettings_show(SHOW_RELAXED).rules,
            RELAXED.rules)

    def test_the_one_console_line_round_trips_without_the_domain_dn(self):
        line = transported(SHOW_RELAXED)
        self.assertNotIn(b"DC=", line)
        self.assertNotIn(b"\n", line)
        self.assertTrue(re.fullmatch(policy_module.SHOW_VALUE, line))
        text = policy_module.transported_show_text(line)
        self.assertEqual(
            policy_module.parse_passwordsettings_show(text).rules,
            RELAXED.rules)

    def test_the_guest_pipeline_drops_the_header_and_fails_to_none(self):
        """``SHOW_COMMAND`` itself, with a stand-in for samba-tool."""
        for tool in ("/usr/bin/grep", "/usr/bin/paste", "/usr/bin/bash"):
            if not Path(tool).exists():
                self.skipTest(f"{tool} is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "samba-tool"
            for body, expected in (
                    (f"cat <<'EOF'\n{SHOW_RELAXED}EOF\n",
                     transported(SHOW_RELAXED)),
                    ("echo 'ERROR: no directory' >&2; exit 1\n", b"NONE")):
                with self.subTest(expected=expected[:16]):
                    fake.write_text("#!/bin/sh\n" + body)
                    fake.chmod(0o700)
                    command = policy_module.SHOW_COMMAND.replace(
                        "/usr/bin/samba-tool", str(fake))
                    output = subprocess.run(
                        ["/usr/bin/bash", "-c", command], check=True,
                        capture_output=True).stdout.strip()
                    self.assertEqual(output, expected)
        with self.assertRaises(DirectoryPasswordPolicyError):
            policy_module.parse_passwordsettings_show(
                policy_module.transported_show_text(b"NONE"))

    def test_a_missing_repeated_or_unknown_setting_is_refused(self):
        for text, reason in (
                (SHOW_DEFAULT.replace("Minimum password length: 7\n", ""),
                 "did not print"),
                (SHOW_DEFAULT + "Password complexity: off\n", "twice"),
                (SHOW_DEFAULT.replace("complexity: on", "complexity: maybe"),
                 "unknown"),
                (SHOW_DEFAULT.replace("length: 7", "length: seven"),
                 "non-numeric"),
                ("", "did not print")):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(
                        DirectoryPasswordPolicyError, reason):
                    policy_module.parse_passwordsettings_show(text)


class JudgementTests(unittest.TestCase):
    problem = staticmethod(controller_principals.directory_password_problem)

    def test_a_recorded_relaxed_policy_takes_four_characters_not_three(self):
        self.assertIsNone(self.problem("abcd", "roster-a", RELAXED))
        self.assertIsNone(self.problem("roster-a!", "roster-a", RELAXED))
        self.assertEqual(self.problem("abc", "roster-a", RELAXED),
                         "is shorter than 4 characters")
        one = DirectoryPasswordPolicy(
            min_length=1, complexity=False, min_age_days=0, source="x")
        self.assertEqual(self.problem("", "roster-a", one),
                         "is shorter than 1 character")

    def test_complexity_on_keeps_the_class_and_name_rules_at_any_length(self):
        short = DirectoryPasswordPolicy(
            min_length=4, complexity=True, min_age_days=0, source="x")
        self.assertIsNone(self.problem("Ab1!", "roster-a", short))
        self.assertIn("fewer than 3", self.problem("abcd", "roster-a", short))
        self.assertIn("account name",
                      self.problem("Roster-A-1", "roster-a", short))

    def test_the_default_argument_is_todays_judgement(self):
        for password in ("Ab1!xy", "lowercaseonly", "My-Roster-A-Pass1",
                         "Short1!", "abcd"):
            with self.subTest(length=len(password)):
                self.assertEqual(
                    self.problem(password, "roster-a"),
                    self.problem(password, "roster-a", SAMBA_DEFAULT))
        self.assertEqual(self.problem("abcd", "roster-a"),
                         "is shorter than 7 characters")

    def test_a_reason_never_repeats_the_password(self):
        for password in ("abc", "ab", "x"):
            reason = self.problem(password, "roster-a", RELAXED)
            self.assertIsNotNone(reason)
            self.assertNotIn(password, reason)


class MarkerRecordTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name) / "persistent" / INSTANCE
        self.state.mkdir(parents=True)
        marker = {"schema": 1, "mode": "persistent", "instance": INSTANCE,
                  "created_utc": "2026-01-01T00:00:00+00:00"}
        (self.state / "persistent-instance.json").write_text(
            json.dumps(marker))
        self.target = PersistentControllerInstance(
            self.state, instance=INSTANCE)

    def test_absence_is_sambas_default(self):
        self.assertIsNone(self.target.directory_password_policy())
        self.assertIs(policy_module.instance_policy(self.target),
                      SAMBA_DEFAULT)

    def test_a_recorded_policy_round_trips_and_names_its_instance(self):
        record = policy_module.policy_record(
            RELAXED, run_id="run-1", now="2026-09-30T20:00:00+00:00")
        self.target.record_directory_password_policy(record)
        raw = json.loads(
            (self.state / "persistent-instance.json").read_text())
        self.assertEqual(raw[PERSISTENT_PASSWORD_POLICY_KEY], record)
        self.assertEqual(raw["instance"], INSTANCE)
        policy = policy_module.instance_policy(self.target)
        self.assertEqual(policy, RELAXED)
        self.assertEqual(policy.source,
                         f"{INSTANCE}'s recorded directory policy")

    def test_an_unusable_record_is_refused_both_ways(self):
        for record in ({"min_length": 0, "complexity": False,
                        "min_age_days": 0, "recorded_utc": "t"},
                       {"min_length": 4, "complexity": "off",
                        "min_age_days": 0, "recorded_utc": "t"},
                       {"min_length": 4, "complexity": False,
                        "min_age_days": 0}):
            with self.subTest(record=record):
                with self.assertRaises(PersistentInstanceInvalid):
                    self.target.record_directory_password_policy(record)
                marker = json.loads(
                    (self.state / "persistent-instance.json").read_text())
                marker[PERSISTENT_PASSWORD_POLICY_KEY] = record
                (self.state / "persistent-instance.json").write_text(
                    json.dumps(marker))
                with self.assertRaises(PersistentInstanceInvalid):
                    self.target.directory_password_policy()


class PolicyRunTests(SessionFixture):
    """The target's runner, with the probe's fakes."""

    def setUp(self):
        super().setUp()
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
        self.evidence = self.root / "evidence"
        self.live_sid = SID
        self.read_back = SHOW_RELAXED
        self.commands = []
        self.children = []
        self.prompts = []
        self.guest_output = (
            b"bootstrap-dc login: local-rescue\r\nPassword: " + PASSWORD
            + b"\r\n$ ")
        patch = mock.patch.object(
            durable_workstation, "_current_roster_fingerprint",
            return_value=FINGERPRINT)
        patch.start()
        self.addCleanup(patch.stop)

    def run_policy(self, length="4", complexity="off", apply=True):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = runner.password_policy(
                self.state.parent, INSTANCE, length, complexity, apply,
                canonical_state=self.canonical,
                identity_path=self.identity, evidence_root=self.evidence)
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
        self.assertNotIn(PASSWORD.decode(), command)
        self.commands.append((label, command))
        self.calls.append(label)
        answers = {
            "policy-realm": REALM.lower().encode(),
            "policy-domain-sid": self.live_sid.encode(),
            "policy-show-before": transported(SHOW_DEFAULT),
            "policy-show-after": transported(self.read_back),
        }
        return answers.get(label)

    def typed(self, prompt, **_kwargs):
        self.prompts.append(prompt)
        self.calls.append("prompt")
        return PASSWORD

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
            mock.patch.object(runner, "_console_root",
                              side_effect=self.console_root),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            stack.enter_context(self.console_fakes())
            yield

    def recorded(self):
        return PersistentControllerInstance(
            self.state, instance=INSTANCE).directory_password_policy()

    def result(self):
        [run] = list((self.evidence / INSTANCE).iterdir())
        return run, json.loads((run / "result.json").read_text())

    def test_the_dry_run_prints_the_recorded_policy_and_starts_nothing(self):
        with mock.patch.object(
                subprocess, "Popen",
                side_effect=AssertionError("a dry run started a process")), \
             mock.patch.object(
                runner, "_typed_secret",
                side_effect=AssertionError("a dry run asked for a password")):
            code, out, _ = self.run_policy(apply=False)
        self.assertEqual(code, 0, out)
        self.assertIn("dry run; repeat with APPLY=1", out)
        self.assertIn("none, so Samba's default applies (minimum length 7, "
                      "complexity on, minimum age 1 day)", out)
        self.assertIn("minimum length 7 -> 4; complexity on -> off; minimum "
                      "age (days) 1 -> 0", out)
        self.assertIn("--min-pwd-length=4 --complexity=off --min-pwd-age=0",
                      out)
        self.assertIn("every account", out)
        for value in (REALM, DOMAIN, SID, BOOTSTRAP,
                      str(simulated_gateway.CONTROLLER_IP)):
            self.assertNotIn(value, out)
        self.assertFalse(self.evidence.exists())
        self.assertIsNone(self.recorded())
        self.assertEqual(self.calls, [])

    def test_a_bad_value_is_refused_before_the_instance_is_even_bound(self):
        with mock.patch.object(
                runner, "durable_binding",
                side_effect=AssertionError("bound a refused request")):
            for length, complexity in (("0", "off"), ("15", "on"),
                                       ("x", "on"), ("4", "maybe")):
                with self.subTest(length=length, complexity=complexity):
                    code, _, err = self.run_policy(length, complexity)
                    self.assertEqual(code, 2)
                    self.assertIn("error:", err)
        self.assertEqual(self.calls, [])

    def test_a_matching_read_back_is_recorded_after_a_clean_poweroff(self):
        with self.applied():
            code, out, err = self.run_policy()
        self.assertEqual(code, 0, err)
        self.assertEqual(self.calls[:4], ["prompt", "fabric", "fabric",
                                          "spawn"])
        self.assertEqual(
            [call for call in self.calls if call.startswith("policy-")
             or call == "poweroff"],
            ["policy-realm", "policy-domain-sid", "policy-show-before",
             "policy-set", "policy-show-after", "poweroff"])
        self.assertEqual(dict(self.commands)["policy-set"],
                         policy_module.set_command(RELAXED))
        self.assertEqual(self.guests[0].signals, [])
        record = self.recorded()
        self.assertEqual((record["min_length"], record["complexity"],
                          record["min_age_days"]), RELAXED.rules)
        run, result = self.result()
        self.assertEqual(result["verdict"], "pass")
        self.assertTrue(result["recorded"])
        self.assertEqual(result["live_before"], SAMBA_DEFAULT.facts())
        self.assertEqual(result["read_back"], RELAXED.facts())
        self.assertEqual(record["run_id"], result["run_id"])
        self.assertTrue(all(result["checks"][key] is True
                            for key in runner.REQUIRED_CHECKS))
        retained = b"".join(path.read_bytes() for path in run.iterdir())
        self.assertNotIn(PASSWORD, retained)
        rendered = (run / "result.json").read_text()
        for value in (REALM, DOMAIN, SID, BOOTSTRAP):
            self.assertNotIn(value, rendered)
        self.assertIn("PASS", out)
        self.assertFalse(self.lock_held())

    def test_a_read_back_mismatch_refuses_and_records_nothing(self):
        self.read_back = SHOW_DEFAULT
        with self.applied():
            code, out, err = self.run_policy()
        self.assertEqual(code, 2)
        self.assertIn("not the requested", err)
        self.assertIn("FAIL", out)
        self.assertIsNone(self.recorded())
        _, result = self.result()
        self.assertEqual(result["verdict"], "fail")
        self.assertFalse(result["recorded"])
        self.assertFalse(result["checks"]["read_back_matches"])
        self.assertEqual(result["failure"]["step"], "read-back")
        # Still a clean stop, never a power cut on the directory.
        self.assertEqual(self.calls[-1], "poweroff")
        self.assertEqual(self.guests[0].signals, [])
        self.assertTrue(result["checks"]["clean_poweroff"])

    def test_an_unclean_stop_after_a_good_read_back_records_nothing(self):
        def refuse(console, password, label):
            self.calls.append("poweroff")
            raise session_module.SerialAutomationError("no poweroff observed")

        with self.applied(), mock.patch.object(
                session_module, "_console_poweroff", side_effect=refuse):
            code, _, err = self.run_policy()
        self.assertEqual(code, 2)
        self.assertIsNone(self.recorded())
        self.assertIn("marker was NOT changed", err)
        self.assertEqual(self.guests[0].signals, ["terminate"])

    def test_a_recorded_policy_is_replaced_only_by_a_proven_one(self):
        target = PersistentControllerInstance(self.state, instance=INSTANCE)
        target.record_directory_password_policy(policy_module.policy_record(
            RELAXED, run_id="earlier", now="2026-09-30T00:00:00+00:00"))
        code, out, _ = self.run_policy("7", "on", apply=False)
        self.assertEqual(code, 0)
        self.assertIn("recorded now: minimum length 4, complexity off, "
                      f"minimum age 0 days ({INSTANCE}'s recorded directory "
                      "policy)", out)
        self.assertIn("1 day, Samba's default", out)
        self.read_back = SHOW_RELAXED  # the directory did not take it
        with self.applied():
            code, _, _ = self.run_policy("7", "on")
        self.assertEqual(code, 2)
        self.assertEqual(self.recorded()["run_id"], "earlier")
        self.read_back = SHOW_DEFAULT
        with self.applied():
            code, _, err = self.run_policy("7", "on")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            policy_module.instance_policy(target).rules, SAMBA_DEFAULT.rules)

    def test_another_directory_is_refused_before_the_policy_is_set(self):
        self.live_sid = "S-1-5-21-4444444444-5555555555-6666666666"
        with self.applied():
            code, _, err = self.run_policy()
        self.assertEqual(code, 2)
        self.assertIn("different directory", err)
        self.assertNotIn("policy-set", self.calls)
        self.assertIsNone(self.recorded())
        _, result = self.result()
        self.assertEqual(result["failure"]["step"], "directory")
        self.assertTrue(result["checks"]["clean_poweroff"])

    def test_a_truncated_recorded_sid_is_sent_to_the_probe_first(self):
        target = PersistentControllerInstance(self.state, instance=INSTANCE)
        record = target.convergence()
        record["domain_sid"] = TRUNCATED
        target.record_convergence(record)
        with self.applied():
            code, _, err = self.run_policy()
        self.assertEqual(code, 2)
        self.assertIn("REPAIR_SID=1", err)
        self.assertNotIn("policy-set", self.calls)
        self.assertIsNone(self.recorded())

    def test_the_binding_carries_the_recorded_policy(self):
        def bind():
            return durable_workstation.durable_binding(
                self.state.parent, INSTANCE, canonical_state=self.canonical,
                identity_path=self.identity)

        self.assertIs(bind().password_policy, SAMBA_DEFAULT)
        PersistentControllerInstance(
            self.state, instance=INSTANCE).record_directory_password_policy(
                policy_module.policy_record(RELAXED, run_id="r"))
        self.assertEqual(bind().password_policy, RELAXED)
        self.assertEqual(repr(bind()), f"DurableBinding(instance={INSTANCE!r})")


if __name__ == "__main__":
    unittest.main()
