"""One-command minting (owner request 2026-10-07): sequencing and prompts.

Nothing here boots QEMU or reads ``build/``, ``homelab/var/`` or
``homelab/instance/``: markers live in temporary directories, ``make`` is a
fake script, and the roster is pinned.  The pseudo-terminal tests run the
RUNNERS' OWN prompt functions (``_typed_secret`` -> ``getpass`` on the
child's controlling terminal) in a child process and prove the mint answers
each with the value collected for it -- by digest, so no test output ever
carries a value.  Every credential is synthetic.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from homelab.tests.identity_overlay_pin import pinned_identity_overlay
from homelab.vm import factory_mint as fm

REPOSITORY = Path(__file__).resolve().parents[2]
ROSTER = {
    "schema_version": 1,
    "principals": {
        "standard_user": {"name": "uat-kid", "uid_number": 10003},
        "daily_administrator": {"name": "uat-parent", "uid_number": 10001},
        "domain_administrator": {"name": "uat-root", "uid_number": 10000},
    },
    "additional_standard_users": [{"name": "uat-guest", "uid_number": 10002}],
}


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def options(root: Path, **changes) -> fm.Options:
    values = dict(instance="uat", workstation="uat-ws", hostname="uat-arch",
                  persistent_root=root / "dc", workstation_root=root / "ws")
    values.update(changes)
    return fm.Options(**values)


def write_marker(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def names(self, opts, state):
        return [step.name for step in fm.plan_steps(opts, state)]

    def test_a_fresh_owner_mint_runs_every_step_in_order(self):
        state = fm.MintState(None, None)
        self.assertEqual(
            ["converge", "password-policy", "accounts", "probe",
             "windows-install", "adopt", "arch-install", "arch-join",
             "windows-join", "verify", "backup"],
            self.names(options(self.temp), state))

    def test_an_agent_throwaway_mint_creates_its_instance_first(self):
        opts = options(self.temp, custody="agent", throwaway=True)
        steps = fm.plan_steps(opts, fm.MintState(None, None))
        self.assertEqual("up", steps[0].name)
        self.assertIn(("CUSTODY", "agent"), steps[0].variables)
        self.assertIn(("THROWAWAY", "1"), steps[0].variables)

    def test_a_given_windows_bundle_skips_the_install(self):
        opts = options(self.temp, windows_run=Path("bundle"))
        steps = fm.plan_steps(opts, fm.MintState(None, None))
        self.assertNotIn("windows-install", [step.name for step in steps])
        adopt = next(step for step in steps if step.name == "adopt")
        self.assertIn(("WINDOWS_RUN", "bundle"), adopt.variables)

    def test_the_markers_decide_where_a_rerun_resumes(self):
        instance = {"credential_custody": "owner", "converged": {"x": 1},
                    "directory_password_policy": {
                        "min_length": 4, "complexity": False},
                    "directory_accounts": {
                        "password_change_at_first_logon": False}}
        workstation = {"ledger": [{"stage": "adopt"},
                                  {"stage": "arch-install"}],
                       "publication": {"name": "publication.iso"}}
        self.assertEqual(
            ["arch-join", "windows-join", "verify", "backup"],
            self.names(options(self.temp),
                       fm.MintState(instance, workstation)))
        workstation["ledger"] += [{"stage": "arch-join"},
                                  {"stage": "windows-join"}]
        # Folded but the publication is still held: the join target retires
        # it, so the step runs again.
        self.assertIn("windows-join", self.names(
            options(self.temp), fm.MintState(instance, workstation)))
        workstation["publication"]["retired_utc"] = "2026-10-07T00:00:00Z"
        self.assertEqual(["verify", "backup"], self.names(
            options(self.temp), fm.MintState(instance, workstation)))

    def test_another_recorded_policy_is_set_again(self):
        instance = {"converged": {"x": 1}, "directory_password_policy": {
            "min_length": 7, "complexity": True}}
        self.assertIn("password-policy", self.names(
            options(self.temp), fm.MintState(instance, None)))

    def test_owner_prompts_are_only_the_remaining_steps(self):
        instance = {"converged": {"x": 1}, "directory_password_policy": {
            "min_length": 4, "complexity": False},
            "directory_accounts": {"x": 1}}
        workstation = {"ledger": [{"stage": stage} for stage in (
            "adopt", "arch-install", "arch-join", "windows-join")],
            "publication": {"retired_utc": "x"}}
        steps = fm.plan_steps(options(self.temp),
                              fm.MintState(instance, workstation))
        self.assertEqual({"console", "daily", "users"}, fm.needed_keys(steps))
        verify = next(step for step in steps if step.name == "verify")
        self.assertIn(("VERIFY_USERS", "1"), verify.variables)

    def test_read_state_reads_both_markers(self):
        opts = options(self.temp)
        write_marker(opts.persistent_root / "uat" / fm.INSTANCE_MARKER,
                     {"credential_custody": "agent"})
        state = fm.read_state(opts.persistent_root, "uat",
                              opts.workstation_root, "uat-ws")
        self.assertEqual("agent", state.custody)
        self.assertIsNone(state.workstation)


class CredentialTests(unittest.TestCase):
    ACCOUNTS = [fm.Account("standard_user", "uat-kid"),
                fm.Account("daily_administrator", "uat-parent"),
                fm.Account("domain_administrator", "uat-root"),
                fm.Account("additional_standard_user_10002", "uat-guest")]

    def answers(self, *values):
        queue = list(values)
        asked = []

        def ask(prompt):
            asked.append(prompt)
            return queue.pop(0)
        return ask, asked

    def test_every_value_is_asked_once_and_confirmed(self):
        values = ["Console-1", "Console-1", "Admin-pw-7", "Admin-pw-7"]
        for number in range(4):
            values += [f"acct{number}", f"acct{number}"]
        values += ["arch-rescue", "arch-rescue", "win-local", "win-local"]
        ask, asked = self.answers(*values)
        keys = {"console", "administrator", "accounts", "daily",
                "arch_rescue", "windows_local"}
        credentials = fm.collect_credentials(
            keys, self.ACCOUNTS, instance="uat", console_is_canonical=True,
            ask=ask)
        self.assertEqual(len(values), len(asked))
        self.assertEqual("acct1",
                         credentials.values["account:daily_administrator"])
        self.assertNotIn("acct1", repr(credentials))
        credentials.clear()
        self.assertEqual({}, credentials.values)

    def test_a_mismatched_confirmation_is_refused(self):
        ask, _ = self.answers("one-value", "two-value")
        with self.assertRaisesRegex(fm.MintError, "did not match"):
            fm.collect_credentials({"console"}, self.ACCOUNTS,
                                   instance="uat",
                                   console_is_canonical=False, ask=ask)

    def test_existing_standard_accounts_are_asked_for_the_verify(self):
        ask, asked = self.answers("Console-1", "Console-1", "daily-pw",
                                  "kid-pw", "guest-pw")
        credentials = fm.collect_credentials(
            {"console", "daily", "users"}, self.ACCOUNTS, instance="uat",
            console_is_canonical=False, ask=ask)
        self.assertEqual(5, len(asked))
        self.assertEqual("guest-pw", credentials.values[
            "account:additional_standard_user_10002"])
        self.assertNotIn("account:domain_administrator", credentials.values)

    def test_the_daily_password_alone_is_asked_when_accounts_exist(self):
        ask, asked = self.answers("Console-1", "Console-1", "daily-pw")
        credentials = fm.collect_credentials(
            {"console", "daily"}, self.ACCOUNTS, instance="uat",
            console_is_canonical=False, ask=ask)
        self.assertIn("CURRENT password for uat-parent", asked[-1])
        self.assertEqual("daily-pw",
                         credentials.values["account:daily_administrator"])

    def test_the_runners_own_checks_judge_every_value(self):
        credentials = fm.Credentials(
            {"administrator": "short", "account:standard_user": "abc",
             "arch_rescue": "same-value", "windows_local": "same-value",
             "console": "Console-1"},
            {"standard_user": fm.Account("standard_user", "uat-kid")})
        problems = " ".join(fm.judge(credentials))
        self.assertIn("domain Administrator password is shorter than 7",
                      problems)
        self.assertIn("uat-kid is shorter than 4", problems)
        self.assertIn("two of the values are equal", problems)
        self.assertNotIn("same-value", problems)
        credentials.values.update(administrator="Admin-pw-7",
                                  windows_local="win-local")
        credentials.values["account:standard_user"] = "abcd"
        self.assertEqual([], fm.judge(credentials))

    def test_an_untypeable_value_is_refused(self):
        credentials = fm.Credentials({"arch_rescue": "café-pw"})
        self.assertIn("cannot type", " ".join(fm.judge(credentials)))


class PromptTableTests(unittest.TestCase):
    def key(self, text):
        return fm.match_prompt(text.encode())[0]

    def test_every_runner_prompt_maps_to_its_value(self):
        cases = {
            "local-rescue console password: ": "console",
            "local-rescue console password for persistent instance keeper: ":
                "console",
            "new domain Administrator password: ": "administrator",
            "retype domain Administrator password: ": "administrator",
            "new directory password for daily_administrator (uat-parent): ":
                "account:daily_administrator",
            "retype password for additional_standard_user_10002: ":
                "account:additional_standard_user_10002",
            "CURRENT password for daily_administrator (uat-parent): ":
                "account:daily_administrator",
            "current domain password for daily_administrator (uat-parent): ":
                "account:daily_administrator",
            "CURRENT domain password for daily_administrator (uat-parent): ":
                "account:daily_administrator",
            "CURRENT domain password for standard_user (uat-kid): ":
                "account:standard_user",
            "NEW break-glass password for the Arch local-rescue account: ":
                "arch_rescue",
            "retype the break-glass password: ": "arch_rescue",
            "new Windows local-administrator (telosadmin) password: ":
                "windows_local",
            "retype the new Windows local-administrator password: ":
                "windows_local",
        }
        for prompt, key in cases.items():
            with self.subTest(prompt=prompt):
                self.assertEqual(key, self.key("log line\n" + prompt))

    def test_first_logon_prompts_are_not_answered(self):
        for prompt in (
                "TEMPORARY password for daily_administrator (uat-parent): ",
                "temporary password for standard_user (uat-kid): "):
            self.assertIsNone(self.key(prompt))
            self.assertTrue(fm.UNKNOWN_PROMPT.search(prompt.encode()))

    def test_a_logged_line_is_not_a_prompt(self):
        self.assertIsNone(self.key(
            "  1. the local-rescue console password of persistent instance "
            "keeper\n"))

    def test_the_prompt_literals_are_still_the_runners(self):
        """A runner that rewords a prompt must fail here, not in a mint."""
        sources = {name: (REPOSITORY / "homelab" / "vm" / name).read_text(
            encoding="utf-8") for name in (
            "bootstrap_dc.py", "arch_durable_join.py",
            "windows_durable_join.py", "durable_workstation_verify.py",
            "persistent_backup.py", "persistent_password_policy.py",
            "persistent_controller_session.py")}
        literals = {
            "bootstrap_dc.py": [
                '"new domain Administrator password: "',
                'confirm="retype domain Administrator password: "',
                'kind = "temporary" if first_logon else "new directory"',
                'f"{kind} password for {entry[\'contract_role\']} "',
                'confirm=f"retype password for {entry[\'contract_role\']}: "',
                'f"{CONSOLE_ACCOUNT} console password: "'],
            "arch_durable_join.py": [
                'ask(f"CURRENT password for daily_administrator "',
                'f"NEW break-glass password for the Arch {rescue_name} '
                'account: "',
                'confirm="retype the break-glass password: "'],
            "windows_durable_join.py": [
                'f"new Windows local-administrator ({LOCAL_ADMINISTRATOR}) "',
                '"password: "',
                'confirm="retype the new Windows local-administrator "',
                'f"current domain password for daily_administrator '
                '({daily_name}): "'],
            "durable_workstation_verify.py": [
                'prompt(f"CURRENT domain password for daily_administrator "',
                'f"CURRENT domain password for {account[\'contract_role\']} "'],
            "persistent_backup.py": [
                'f"{CONSOLE_ACCOUNT} console password: "'],
            "persistent_password_policy.py": [
                'f"{CONSOLE_ACCOUNT} console password: "'],
            "persistent_controller_session.py": [
                'f"{CONSOLE_ACCOUNT} console password: "'],
        }
        for name, expected in literals.items():
            for literal in expected:
                with self.subTest(source=name, literal=literal):
                    self.assertIn(literal, sources[name])


class ScrubberTests(unittest.TestCase):
    def test_a_secret_split_across_chunks_is_withheld(self):
        scrubber = fm.Scrubber([b"Sekrit-value"])
        out = scrubber.feed(b"before Sek") + scrubber.feed(b"rit-value after")
        out += scrubber.feed(b"", final=True)
        self.assertEqual(b"before <withheld> after", out)
        self.assertTrue(scrubber.found)

    def test_clean_output_passes_unchanged(self):
        scrubber = fm.Scrubber([b"abcdef"])
        out = scrubber.feed(b"hello ") + scrubber.feed(b"world", final=True)
        self.assertEqual(b"hello world", out)
        self.assertFalse(scrubber.found)


CHILD = textwrap.dedent("""
    import hashlib, sys
    sys.path.insert(0, __ROOT__)
    from homelab.vm import arch_durable_join as adj
    from homelab.vm import windows_durable_join as wdj
    from homelab.vm import durable_workstation_verify as dwv
    from homelab.vm.bootstrap_dc import _typed_secret
    from homelab.vm.directory_password_policy import DirectoryPasswordPolicy
    policy = DirectoryPasswordPolicy(min_length=4, complexity=False,
                                     min_age_days=0, source="test policy")
    def show(label, value):
        if isinstance(value, str):
            value = value.encode()
        print(label, hashlib.sha256(value).hexdigest(), flush=True)
    which = sys.argv[1]
    if which == "converge":
        show("console", _typed_secret("local-rescue console password: "))
        show("administrator", _typed_secret(
            "new domain Administrator password: ",
            confirm="retype domain Administrator password: "))
        show("daily", _typed_secret(
            "new directory password for daily_administrator (uat-parent): ",
            confirm="retype password for daily_administrator: "))
    elif which == "arch":
        got = adj.owner_credentials(adj.MODE_CURRENT, daily_name="uat-parent",
                                    rescue_name="local-rescue",
                                    instance="uat", policy=policy)
        show("console", got.console)
        show("daily", got.daily)
        show("arch", got.rescue)
    elif which == "windows":
        got = wdj.collect_owner_secrets("uat", "uat-parent", policy=policy)
        show("console", got.console)
        show("windows", got.local_administrator)
        show("daily", got.daily_administrator)
    elif which == "verify":
        got = dwv.collect_verify_secrets(
            "uat", "uat-parent",
            users=[{"contract_role": "standard_user", "name": "uat-kid"}])
        show("console", got.console)
        show("daily", got.daily)
        show("kid", got.users["standard_user"])
    elif which == "rogue":
        _typed_secret("an unexpected password: ")
    elif which == "echoing":
        sys.stdout.write("local-rescue console password: ")
        sys.stdout.flush()
        sys.stdin.readline()
    elif which == "logged":
        # A log line that ends like a prompt, then more output: not a prompt.
        import time
        sys.stdout.write("note: the local-rescue console password:")
        sys.stdout.flush()
        time.sleep(0.1)
        print(" is read from custody", flush=True)
        sys.stdout.write("an echoed line ending in password: ")
        sys.stdout.flush()
        time.sleep(1.5)
        print("done", flush=True)
""")


class PseudoTerminalTests(unittest.TestCase):
    VALUES = {"console": "Console-1", "administrator": "Admin-pw-7",
              "account:daily_administrator": "daily-pw",
              "account:standard_user": "kid-pw",
              "arch_rescue": "arch-rescue", "windows_local": "win-local"}
    ACCOUNTS = {"daily_administrator":
                fm.Account("daily_administrator", "uat-parent"),
                "standard_user": fm.Account("standard_user", "uat-kid")}

    def setUp(self):
        self.temp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.script = self.temp / "child.py"
        self.script.write_text(CHILD.replace("__ROOT__", repr(str(REPOSITORY))),
                               encoding="utf-8")

    def run_child(self, which, values=None, stop_grace=5.0):
        credentials = fm.Credentials(dict(values or self.VALUES))
        log = self.temp / f"{which}.log"
        status = fm.run_on_pty(
            [sys.executable, str(self.script), which],
            credentials=credentials, log=log, echo=False,
            accounts=self.ACCOUNTS, stop_grace=stop_grace)
        return status, log.read_text(encoding="utf-8", errors="replace")

    def expect(self, output, label, key):
        self.assertIn(f"{label} {digest(self.VALUES[key])}", output)

    def test_convergence_and_staging_prompts_are_answered(self):
        status, output = self.run_child("converge")
        self.assertEqual(0, status, output)
        self.expect(output, "console", "console")
        self.expect(output, "administrator", "administrator")
        self.expect(output, "daily", "account:daily_administrator")

    def test_the_arch_join_prompts_are_answered(self):
        status, output = self.run_child("arch")
        self.assertEqual(0, status, output)
        self.expect(output, "console", "console")
        self.expect(output, "daily", "account:daily_administrator")
        self.expect(output, "arch", "arch_rescue")

    def test_the_windows_join_prompts_are_answered(self):
        status, output = self.run_child("windows")
        self.assertEqual(0, status, output)
        self.expect(output, "windows", "windows_local")
        self.expect(output, "daily", "account:daily_administrator")

    def test_the_verify_prompts_are_answered(self):
        status, output = self.run_child("verify")
        self.assertEqual(0, status, output)
        self.expect(output, "daily", "account:daily_administrator")
        self.expect(output, "kid", "account:standard_user")

    def test_no_value_reaches_the_log(self):
        _status, output = self.run_child("windows")
        for value in self.VALUES.values():
            self.assertNotIn(value, output)
        mode = stat.S_IMODE(os.stat(self.temp / "windows.log").st_mode)
        self.assertEqual(0o600, mode)

    def test_an_unknown_prompt_stops_the_step_unanswered(self):
        with self.assertRaisesRegex(fm.MintError, "does not recognise"):
            self.run_child("rogue")

    def test_an_echoing_terminal_is_never_typed_into(self):
        with self.assertRaisesRegex(fm.MintError, "still echoes"):
            self.run_child("echoing")

    def test_a_prompt_naming_another_account_is_refused(self):
        self.ACCOUNTS = {"daily_administrator":
                         fm.Account("daily_administrator", "someone-else"),
                         "standard_user": fm.Account("standard_user",
                                                     "uat-kid")}
        with self.assertRaisesRegex(fm.MintError, "another account"):
            self.run_child("converge")

    def test_a_logged_line_ending_like_a_prompt_is_not_one(self):
        log = self.temp / "logged.log"
        status = fm.run_on_pty([sys.executable, str(self.script), "logged"],
                               credentials=None, log=log, echo=False,
                               stop_grace=5.0)
        self.assertEqual(0, status)
        self.assertIn("done", log.read_text())

    def test_agent_custody_answers_nothing(self):
        log = self.temp / "agent.log"
        with self.assertRaisesRegex(fm.MintError, "agent custody"):
            fm.run_on_pty([sys.executable, str(self.script), "verify"],
                          credentials=None, log=log, echo=False,
                          stop_grace=5.0)


FAKE_MAKE = textwrap.dedent("""\
    #!{python}
    import json, sys
    with open({calls!r}, "a") as stream:
        stream.write(json.dumps(sys.argv[1:]) + "\\n")
    if "homelab-windows-install-prepare" in sys.argv:
        print("homelab/var/factory/windows-installs/run-20261007T000000Z-"
              "abcdef012345")
    failing = {failing!r}
    if failing and failing[0] in sys.argv:
        seen = sum(failing[0] in line
                   for line in open({calls!r}).read().splitlines())
        if seen <= failing[1]:
            sys.exit(2)
    sys.exit({status})
""")


class MintRunTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.calls = self.temp / "calls.jsonl"

    def fake_make(self, status=0, failing=()):
        path = self.temp / "make"
        path.write_text(FAKE_MAKE.format(python=sys.executable,
                                         calls=str(self.calls),
                                         status=status, failing=failing),
                        encoding="utf-8")
        path.chmod(0o700)
        return str(path)

    def targets(self):
        return [next(arg for arg in json.loads(line)
                     if arg.startswith("homelab-"))
                for line in self.calls.read_text().splitlines()]

    def test_an_agent_mint_runs_each_target_and_records_timings(self):
        opts = options(self.temp, custody="agent", throwaway=True,
                       make=self.fake_make())
        result = fm.mint(opts, apply=True, allow_busy=True,
                         evidence_root=self.temp / "evidence")
        self.assertEqual(0, result)
        self.assertEqual(
            ["homelab-factory-persistent-up",
             "homelab-factory-persistent-converge",
             "homelab-factory-persistent-password-policy",
             "homelab-factory-persistent-accounts",
             "homelab-factory-persistent-probe",
             "homelab-windows-install-prepare",
             "homelab-windows-install-run",
             "homelab-durable-workstation-adopt",
             "homelab-durable-arch-install", "homelab-durable-arch-join",
             "homelab-durable-windows-join",
             "homelab-durable-workstation-verify",
             "homelab-factory-persistent-backup"], self.targets())
        calls = [json.loads(line)
                 for line in self.calls.read_text().splitlines()]
        adopt = next(call for call in calls
                     if "homelab-durable-workstation-adopt" in call)
        self.assertIn("WINDOWS_RUN=homelab/var/factory/windows-installs/"
                      "run-20261007T000000Z-abcdef012345", adopt)
        self.assertTrue(all("APPLY=1" in call for call in calls))
        record = json.loads(next(
            (self.temp / "evidence").rglob("mint-run.json")).read_text())
        self.assertEqual("pass", record["result"])
        self.assertEqual(12, len(record["steps"]))
        self.assertTrue(all("seconds" in step for step in record["steps"]))

    def test_a_failed_step_stops_the_mint_and_says_how_to_resume(self):
        opts = options(self.temp, custody="agent", throwaway=True,
                       make=self.fake_make(status=3))
        with self.assertRaisesRegex(fm.MintError, "rerun the same command"):
            fm.mint(opts, apply=True, allow_busy=True,
                    evidence_root=self.temp / "evidence")
        self.assertEqual(["homelab-factory-persistent-up"], self.targets())
        record = json.loads(next(
            (self.temp / "evidence").rglob("mint-run.json")).read_text())
        self.assertEqual("fail", record["result"])

    def test_a_rerun_adopts_the_bundle_an_earlier_mint_installed(self):
        bundle = self.temp / "bundle"
        (bundle / "evidence").mkdir(parents=True)
        (bundle / "evidence" / "result.json").write_text(json.dumps({
            "status": "observed", "phase": "native-windows-clean-shutdown",
            "private_publication_retained_for_identity": True}))
        (bundle / "publication.iso").write_bytes(b"iso")
        (bundle / "windows.qcow2").write_bytes(b"disk")
        evidence = self.temp / "evidence"
        record = evidence / "uat" / "uat-ws" / fm.PENDING_BUNDLE
        record.parent.mkdir(parents=True)
        record.write_text(f"{bundle}\n")
        opts = options(self.temp, custody="agent", throwaway=True,
                       make=self.fake_make())
        fm.mint(opts, apply=True, allow_busy=True, evidence_root=evidence)
        self.assertNotIn("homelab-windows-install-run", self.targets())
        adopt = next(json.loads(line) for line in
                     self.calls.read_text().splitlines()
                     if "homelab-durable-workstation-adopt" in line)
        self.assertIn(f"WINDOWS_RUN={bundle}", adopt)
        self.assertFalse(record.exists())

    def test_an_unfinished_pending_bundle_is_not_reused(self):
        self.assertFalse(fm.finished_bundle(self.temp / "missing"))

    def test_a_flaky_windows_join_is_repeated_without_asking_again(self):
        opts = options(self.temp, custody="agent", throwaway=True,
                       make=self.fake_make(failing=(
                           "homelab-durable-windows-join", 2)))
        result = fm.mint(opts, apply=True, allow_busy=True,
                         evidence_root=self.temp / "evidence")
        self.assertEqual(0, result)
        self.assertEqual(3, self.targets().count(
            "homelab-durable-windows-join"))
        record = json.loads(next(
            (self.temp / "evidence").rglob("mint-run.json")).read_text())
        joins = [step for step in record["steps"]
                 if step["step"] == "windows-join"]
        self.assertEqual([1, 2, 3], [step["attempt"] for step in joins])
        self.assertEqual([2, 2, 0], [step["exit"] for step in joins])

    def test_a_failed_windows_install_is_repeated_in_a_fresh_bundle(self):
        opts = options(self.temp, custody="agent", throwaway=True,
                       make=self.fake_make(failing=(
                           "homelab-windows-install-run", 1)))
        fm.mint(opts, apply=True, allow_busy=True,
                evidence_root=self.temp / "evidence")
        targets = self.targets()
        self.assertEqual(2, targets.count("homelab-windows-install-prepare"))
        self.assertEqual(2, targets.count("homelab-windows-install-run"))
        self.assertEqual(1, targets.count("homelab-durable-workstation-adopt"))

    def test_retries_are_bounded(self):
        opts = options(self.temp, custody="agent", throwaway=True,
                       make=self.fake_make(failing=(
                           "homelab-durable-windows-join", 9)))
        with self.assertRaisesRegex(fm.MintError, "windows-join failed"):
            fm.mint(opts, apply=True, allow_busy=True,
                    evidence_root=self.temp / "evidence")
        self.assertEqual(fm.ATTEMPTS["windows-join"], self.targets().count(
            "homelab-durable-windows-join"))
        self.assertNotIn("homelab-durable-workstation-verify",
                         self.targets())

    def test_a_dry_run_starts_nothing(self):
        opts = options(self.temp, make=self.fake_make())
        self.assertEqual(0, fm.mint(opts, apply=False))
        self.assertFalse(self.calls.exists())

    def test_custody_cannot_be_changed_by_the_mint(self):
        opts = options(self.temp, custody="agent", make=self.fake_make())
        write_marker(opts.persistent_root / "uat" / fm.INSTANCE_MARKER,
                     {"credential_custody": "owner"})
        with self.assertRaisesRegex(fm.MintError, "fixed at creation"):
            fm.mint(opts, apply=True, allow_busy=True)

    def test_a_first_logon_staging_is_left_to_the_stage_targets(self):
        opts = options(self.temp, make=self.fake_make())
        write_marker(opts.persistent_root / "uat" / fm.INSTANCE_MARKER, {
            "converged": {"x": 1},
            "directory_accounts": {"password_change_at_first_logon": True}})
        with self.assertRaisesRegex(fm.MintError, "first logon"):
            fm.mint(opts, apply=True, allow_busy=True)

    def test_an_owner_mint_asks_once_then_runs(self):
        opts = options(self.temp, make=self.fake_make())
        answers = []
        values = iter(["Console-1", "Console-1", "Admin-pw-7", "Admin-pw-7",
                       "kid-pw", "kid-pw", "parent-pw", "parent-pw",
                       "root-pw", "root-pw", "guest-pw", "guest-pw",
                       "arch-rescue", "arch-rescue", "win-local",
                       "win-local"])

        def ask(prompt):
            answers.append(prompt)
            return next(values)
        with pinned_identity_overlay(ROSTER):
            result = fm.mint(opts, apply=True, allow_busy=True,
                             evidence_root=self.temp / "evidence", ask=ask)
        self.assertEqual(0, result)
        self.assertEqual(16, len(answers))
        self.assertTrue(any("uat-guest" in prompt for prompt in answers))
        self.assertEqual("homelab-factory-persistent-converge",
                         self.targets()[0])


if __name__ == "__main__":
    unittest.main()
