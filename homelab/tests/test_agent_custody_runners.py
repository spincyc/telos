"""Every durable runner under agent credential custody (TASK-40).

The owner path of each runner is covered, byte for byte, by its own suite;
these prove the agent path: nothing is ever prompted, every credential comes
from (or is written first to) the custody store, new values are stored
BEFORE a guest can take them and made current only once proven, and the
retained-evidence scans carry every stored value.  Nothing boots QEMU or
reads ``build/``, ``homelab/var/`` or ``homelab/instance/``; every instance,
workstation and store is temporary and every value synthetic or generated.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.tests import fake_image_tools
from homelab.tests.identity_overlay_pin import (
    overlay_document, pinned_acceptance_state, pinned_identity_overlay)
from homelab.tests.test_arch_durable_join import (
    INSTANCE, NAMES, RunFixture, binding)
from homelab.tests.test_credential_custody import write_instance
from homelab.vm import arch_durable_join as arch
from homelab.vm import bootstrap_dc
from homelab.vm import controller_principals
from homelab.vm import credential_custody as cc
from homelab.vm import durable_workstation_verify as verify
from homelab.vm import persistent_account_password as account_password
from homelab.vm import persistent_controller_session as session_module
from homelab.vm import persistent_password_policy as policy_runner
from homelab.vm import simulation_overlay as so
from homelab.vm import windows_durable_join as windows
from homelab.vm import workstation_instance as wi
from homelab.vm.secret_scan import count_secret_occurrences, secret_needles


CONSOLE = "Console0Agent1Stored"
DURABLE_IDENTITY = {
    "schema_version": 1,
    "identity": {"dns_domain": "ad.example.home.arpa",
                 "kerberos_realm": "AD.EXAMPLE.HOME.ARPA",
                 "netbios_name": "EXAMPLEAD"},
    "services": {"bootstrap_dc_fqdn": "bootstrap-dc.ad.example.home.arpa",
                 "permanent_dc_fqdn": "dc2.ad.example.home.arpa"},
    "network": {"address": "10.1.99.2", "prefix": 28, "gateway": "10.1.99.1"},
}


def setUpModule():
    unittest.enterModuleContext(pinned_acceptance_state())
    unittest.enterModuleContext(
        pinned_identity_overlay(overlay_document(NAMES)))


def never_prompted(*_args, **_kwargs):
    raise AssertionError("agent custody prompted at a terminal")


def hits(text: str | bytes, values) -> int:
    data = text.encode() if isinstance(text, str) else text
    values = [value for value in values if value]
    if not values or not data:
        return 0
    return count_secret_occurrences([data], secret_needles(values))


class _Child:
    def __init__(self, *_args, **_kwargs):
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO()

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        raise AssertionError("a finished child must not be signalled")


class BootstrapAgentTests(unittest.TestCase):
    """Converge and accounts on an agent-custody instance: no prompt at all."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.canonical = self.root / "canonical"
        self.canonical.mkdir()
        files = bootstrap_dc.paths(self.canonical)
        for key in ("disk", "vars", "manifest"):
            files[key].write_bytes(b"canonical " + key.encode())
            files[key].chmod(0o600)
        fake_image_tools.installed_image(files["disk"], b" canonical")
        self.persistent_root = self.root / "persistent"
        self.target = write_instance(self.persistent_root, "agent-dc",
                                     console=CONSOLE)
        disk = self.target.state / so.PERSISTENT_DISK_NAME
        fake_image_tools.installed_image(disk, b" instance")
        disk.chmod(0o600)
        self.store = cc.instance_store(self.target)
        self.identity = self.root / "directory.json"
        self.identity.write_text(json.dumps(DURABLE_IDENTITY))
        self.overlay = self.root / "principals.json"
        self.overlay.write_text(json.dumps(overlay_document(NAMES)))
        self.seen: dict = {}

    def call(self, *argv, expect=0):
        out, err = io.StringIO(), io.StringIO()
        test = self

        class Bundle:
            def __init__(self, _repo, output, *, authorization_nonce,
                         password=None, spec=None):
                self.output = Path(output)
                self.password = password
                test.seen["bundle_password"] = password

            def build(self):
                self.output.write_bytes(b"iso")

            @staticmethod
            def guest_command(nonce):
                return f"converge {nonce}"

        with contextlib.ExitStack() as stack:
            for patch in (
                    mock.patch.object(bootstrap_dc, "ovmf_pair", return_value=(
                        Path("/code"), Path("/vars"))),
                    mock.patch.object(bootstrap_dc.shutil, "which",
                                      return_value="/usr/bin/x"),
                    mock.patch.object(bootstrap_dc.subprocess, "run",
                                      side_effect=fake_image_tools.image_tool),
                    mock.patch.object(bootstrap_dc.subprocess, "Popen",
                                      side_effect=_Child),
                    mock.patch.object(bootstrap_dc, "_controlling_terminal",
                                      return_value=False),
                    mock.patch.object(bootstrap_dc.getpass, "getpass",
                                      side_effect=never_prompted),
                    mock.patch.object(bootstrap_dc, "FactoryBundle", Bundle),
                    mock.patch.object(bootstrap_dc, "_attach_simulated_gateway",
                                      return_value=_Child()),
                    mock.patch.object(bootstrap_dc,
                                      "_drive_persistent_convergence",
                                      side_effect=self.converge_drive),
                    mock.patch.object(bootstrap_dc, "_drive_persistent_accounts",
                                      side_effect=self.accounts_drive),
                    contextlib.redirect_stdout(out),
                    contextlib.redirect_stderr(err)):
                stack.enter_context(patch)
            result = bootstrap_dc.main(list(argv))
        self.assertEqual(expect, result, err.getvalue() or out.getvalue())
        return out.getvalue(), err.getvalue()

    def converge_drive(self, process, password, nonce, spec, **kwargs):
        # The Administrator value is in custody BEFORE the guest can take it.
        self.seen["console"] = password
        self.seen["stored_before"] = self.store.read().get("administrator")
        self.seen["agent_custody"] = kwargs.get("agent_custody")
        return {"converged_utc": "2026-09-30T01:00:00+00:00",
                "realm": spec.realm, "netbios": spec.netbios,
                "dns_domain": spec.domain, "domain_sid": "S-1-5-21-1-2-3",
                "administrator": "agent", "console_credential": "agent"}

    def accounts_drive(self, process, password, values, **kwargs):
        self.seen["console"] = password
        self.seen["values"] = dict(values)
        self.seen["stored_before"] = self.store.read()["accounts"]
        return mock.Mock(operation="stage")

    def converge(self):
        return self.call(
            "--state-dir", str(self.canonical), "persistent-converge",
            "--instance", "agent-dc",
            "--persistent-root", str(self.persistent_root),
            "--directory-identity", str(self.identity), "--apply")

    def test_converge_reads_the_console_and_stores_the_administrator_first(self):
        out, err = self.converge()
        administrator = self.store.read()["administrator"]
        self.assertEqual(CONSOLE.encode(), self.seen["console"])
        self.assertEqual(administrator, self.seen["stored_before"])
        self.assertEqual(administrator, self.seen["bundle_password"])
        self.assertIs(True, self.seen["agent_custody"])
        self.assertIsNone(controller_principals.directory_password_problem(
            administrator, "Administrator"))
        marker = self.target.read_marker()
        self.assertIsNotNone(marker.get(so.PERSISTENT_CONVERGENCE_KEY))
        self.assertIn("console: agent custody", out)
        self.assertEqual(0, hits(out + err + json.dumps(marker),
                                 self.store.values()))

    def test_accounts_generate_store_and_stage_each_role_unprompted(self):
        self.target.record_convergence({
            "converged_utc": "2026-09-30T01:00:00+00:00",
            "realm": "AD.EXAMPLE.HOME.ARPA", "domain_sid": "S-1-5-21-1-2-3"})
        out, err = self.call(
            "--state-dir", str(self.canonical), "persistent-accounts",
            "--instance", "agent-dc",
            "--persistent-root", str(self.persistent_root),
            "--identity-overlay", str(self.overlay),
            "--change-at-first-logon", "--apply")
        self.assertEqual(CONSOLE.encode(), self.seen["console"])
        stored = self.store.read()["accounts"]
        self.assertEqual(stored, self.seen["stored_before"])
        by_name = self.seen["values"]
        self.assertEqual(len(stored), len(by_name))
        self.assertEqual(
            sorted(entry["temporary"] for entry in stored.values()),
            sorted(by_name.values()))
        self.assertTrue(all(entry.get("current") is None
                            for entry in stored.values()))
        self.assertEqual(len(set(by_name.values())), len(by_name))
        self.assertNotIn(CONSOLE, by_name.values())
        marker = self.target.read_marker()
        self.assertIn("generated by the harness",
                      marker[so.PERSISTENT_ACCOUNTS_KEY]["credentials"])
        # The store is keyed by contract role and never holds a name.
        store_text = self.store.path.read_text()
        for name in NAMES.values():
            self.assertNotIn(f'"{name}"', store_text)
        self.assertEqual(0, hits(out + err + json.dumps(marker),
                                 self.store.values()))

    def test_permanent_staging_values_meet_the_directory_policy(self):
        self.target.record_convergence({
            "converged_utc": "2026-09-30T01:00:00+00:00",
            "realm": "AD.EXAMPLE.HOME.ARPA", "domain_sid": "S-1-5-21-1-2-3"})
        self.call(
            "--state-dir", str(self.canonical), "persistent-accounts",
            "--instance", "agent-dc",
            "--persistent-root", str(self.persistent_root),
            "--identity-overlay", str(self.overlay), "--apply")
        for name, value in self.seen["values"].items():
            self.assertIsNone(
                controller_principals.directory_password_problem(value, name))
        stored = self.store.read()["accounts"]
        self.assertTrue(all(entry.get("current") and not entry.get("temporary")
                            for entry in stored.values()))


class SessionRunnerAgentTests(unittest.TestCase):
    """Probe, password policy and account password read the store."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = write_instance(self.root / "persistent", INSTANCE,
                                     console=CONSOLE)
        self.store = cc.instance_store(self.target)
        source = cc.AgentCredentialSource(self.store)
        source.staging_value("daily_administrator", temporary=True)
        self.bound = binding(state=self.target.state)
        self.captured: dict = {}

    @contextlib.contextmanager
    def applied(self, module):
        with contextlib.ExitStack() as stack:
            for patch in (
                    mock.patch.object(module, "durable_binding",
                                      return_value=self.bound),
                    mock.patch.object(module.shutil, "which",
                                      return_value="/usr/bin/x"),
                    mock.patch.object(module, "ovmf_pair", return_value=(
                        Path("/code"), Path("/vars"))),
                    mock.patch.object(bootstrap_dc, "ovmf_pair", return_value=(
                        Path("/code"), Path("/vars"))),
                    mock.patch.object(module, "_persistent_running",
                                      return_value=False),
                    mock.patch.object(module, "assert_installed"),
                    mock.patch.object(module, "_typed_secret",
                                      side_effect=never_prompted)):
                stack.enter_context(patch)
            yield

    def run_quietly(self, function, *args, **kwargs):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = function(*args, **kwargs)
        return code, out.getvalue(), err.getvalue()

    def capture(self, binding_, target, password, *rest, **kwargs):
        self.captured["password"] = password
        self.captured["rest"] = rest
        self.captured["kwargs"] = kwargs
        self.captured["store_at_run"] = self.store.read()
        return 0

    def test_the_probe_reads_the_console_from_custody(self):
        with self.applied(session_module), mock.patch.object(
                session_module, "_run_probe", side_effect=self.capture):
            code, out, err = self.run_quietly(
                session_module.probe, self.root / "persistent", INSTANCE, True,
                canonical_state=self.root / "canonical")
        self.assertEqual(0, code, err)
        self.assertEqual(CONSOLE.encode(), self.captured["password"])
        self.assertIn("console: agent custody", out)
        self.assertEqual(0, hits(out + err, self.store.values()))

    def test_the_policy_runner_reads_the_console_from_custody(self):
        with self.applied(policy_runner), mock.patch.object(
                policy_runner, "_run", side_effect=self.capture):
            code, out, err = self.run_quietly(
                policy_runner.password_policy, self.root / "persistent",
                INSTANCE, "4", "off", True,
                canonical_state=self.root / "canonical")
        self.assertEqual(0, code, err)
        self.assertEqual(CONSOLE.encode(), self.captured["password"])
        self.assertEqual(0, hits(out + err, self.store.values()))

    def test_a_reset_is_stored_pending_before_it_runs(self):
        self.target_record()
        with self.applied(account_password), mock.patch.object(
                account_password, "_run", side_effect=self.capture):
            code, out, err = self.run_quietly(
                account_password.account_password, self.root / "persistent",
                INSTANCE, "daily_administrator", True, True,
                canonical_state=self.root / "canonical")
        self.assertEqual(0, code, err)
        self.assertEqual(CONSOLE.encode(), self.captured["password"])
        value = self.captured["rest"][1]
        entry = self.captured["store_at_run"]["accounts"]["daily_administrator"]
        self.assertEqual(value, entry["pending"])
        self.assertEqual(cc.PENDING_RESET, entry["pending_kind"])
        self.assertIs(True, entry["pending_must_change"])
        self.assertIsInstance(self.captured["kwargs"]["custody"],
                              cc.AgentCredentialSource)
        self.assertIsNone(controller_principals.directory_password_problem(
            value, NAMES["daily_administrator"]))
        self.assertIn("new password: agent custody", out)
        self.assertEqual(0, hits(out + err, self.store.values()))

    def target_record(self):
        from homelab.tests.test_arch_durable_join import account_record
        self.target.record_directory_accounts(account_record())

    def test_the_session_scans_its_transcript_for_the_whole_store(self):
        canonical = self.root / "canonical"
        with mock.patch.object(bootstrap_dc, "ovmf_pair", return_value=(
                Path("/code"), Path("/vars"))):
            session = session_module.PersistentControllerSession(
                self.target, port=40000, password=CONSOLE.encode(),
                canonical_state=canonical, spawn=never_prompted)
        daily = self.store.read()["accounts"]["daily_administrator"][
            "temporary"]
        session._transcript.extend(
            b"boot\n" + daily.encode() + b"\nlogin\n")
        redacted = session.redacted_transcript()
        self.assertIsNotNone(redacted)
        self.assertNotIn(daily.encode(), redacted)
        self.assertIn(b"[REDACTED]", redacted)
        self.store.path.chmod(0o644)
        self.assertIsNone(session.redacted_transcript())


class ArchJoinAgentUnitTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = write_instance(self.root, INSTANCE, console=CONSOLE)
        self.store = cc.instance_store(self.target)
        self.wstate = self.root / "w1"
        self.wstate.mkdir()
        self.source = cc.AgentCredentialSource(
            self.store, cc.workstation_store(self.wstate, "w1"))
        self.temporary = self.source.staging_value(
            arch.DAILY_ROLE, temporary=True)

    def credentials(self, plan):
        return arch.agent_credentials(
            self.source, plan, daily_name=NAMES["daily_administrator"],
            rescue_name=NAMES["local_rescue"])

    def boundary(self, **login):
        return mock.Mock(facts={"login": login})

    def test_first_logon_stores_the_new_password_pending_before_the_run(self):
        plan = arch.agent_logon_plan(self.source)
        self.assertEqual(arch.MODE_FIRST_LOGON, plan.mode)
        credentials = self.credentials(plan)
        entry = self.source.account(arch.DAILY_ROLE)
        self.assertEqual(credentials.new_daily.decode(), entry["pending"])
        self.assertEqual(self.temporary.encode(), credentials.daily)
        self.assertEqual(CONSOLE.encode(), credentials.console)
        rescue = self.source.workstation_store.read()["break_glass"][
            cc.ARCH_LOCAL_RESCUE]["pending"]
        self.assertEqual(rescue.encode(), credentials.rescue)
        self.assertEqual(4, len(set(credentials.values())))
        # Every stored value is scanned for, not only the four in use.
        for value in self.source.scan_values():
            self.assertIn(value.encode(), credentials.scan_values())

    def test_a_landed_change_is_promoted_and_the_fold_makes_rescue_current(self):
        plan = arch.agent_logon_plan(self.source)
        credentials = self.credentials(plan)
        arch.AgentArchCustody(self.source, plan).settle(
            self.boundary(password_change_landed=True, new_password_writes=2),
            None, {"stage": "arch-join"})
        entry = self.source.account(arch.DAILY_ROLE)
        self.assertEqual(credentials.new_daily.decode(), entry["current"])
        self.assertIsNone(entry["pending"])
        self.assertEqual(arch.MODE_CURRENT,
                         arch.agent_logon_plan(self.source).mode)
        glass = self.source.workstation_store.read()["break_glass"][
            cc.ARCH_LOCAL_RESCUE]
        self.assertEqual(credentials.rescue.decode(), glass["current"])

    def test_a_crash_after_the_change_retries_with_the_pending_as_current(self):
        plan = arch.agent_logon_plan(self.source)
        credentials = self.credentials(plan)
        # The process died after pam_sss took the new password: no settle.
        retry = arch.agent_logon_plan(self.source)
        self.assertEqual(arch.MODE_CURRENT, retry.mode)
        self.assertTrue(retry.trying_pending)
        self.assertEqual(credentials.new_daily.decode(), retry.login)
        again = self.credentials(retry)
        self.assertIsNone(again.new_daily)
        arch.AgentArchCustody(self.source, retry).settle(
            self.boundary(login_completed=True), None, None)
        self.assertEqual(credentials.new_daily.decode(),
                         self.source.account(arch.DAILY_ROLE)["current"])

    def test_a_refused_pending_means_the_change_never_landed(self):
        plan = arch.agent_logon_plan(self.source)
        credentials = self.credentials(plan)
        retry = arch.agent_logon_plan(self.source)
        arch.AgentArchCustody(self.source, retry).settle(
            self.boundary(login_password_sent=True),
            arch.ArchDurableJoinError(arch.LOGIN_REFUSED_FAILURE), None)
        third = arch.agent_logon_plan(self.source)
        self.assertEqual(arch.MODE_FIRST_LOGON, third.mode)
        self.assertEqual(self.temporary, third.login)
        self.assertEqual(credentials.new_daily.decode(), third.new)
        self.credentials(third)
        self.assertIsNone(self.source.account(arch.DAILY_ROLE)[
            "pending_not_live_utc"])

    def test_a_run_that_never_wrote_the_new_password_marks_it_not_live(self):
        plan = arch.agent_logon_plan(self.source)
        self.credentials(plan)
        arch.AgentArchCustody(self.source, plan).settle(
            self.boundary(), RuntimeError("the join failed"), None)
        again = arch.agent_logon_plan(self.source)
        self.assertEqual(arch.MODE_FIRST_LOGON, again.mode)
        self.assertFalse(again.trying_pending)

    def test_an_unproven_change_is_kept_pending(self):
        plan = arch.agent_logon_plan(self.source)
        self.credentials(plan)
        facts = arch.AgentArchCustody(self.source, plan).settle(
            self.boundary(new_password_writes=2, password_change_landed=None),
            arch.ArchDurableJoinError(arch.EXCHANGE_STALLED_FAILURE), None)
        self.assertIn("unproven", facts[arch.DAILY_ROLE])
        self.assertTrue(arch.agent_logon_plan(self.source).trying_pending)

    def test_a_pending_reset_or_an_empty_record_is_refused(self):
        self.source.begin_pending(arch.DAILY_ROLE, "Reset0Pending1Value",
                                  kind=cc.PENDING_RESET)
        with self.assertRaisesRegex(arch.ArchDurableJoinError, "reset"):
            arch.agent_logon_plan(self.source)
        empty = cc.AgentCredentialSource(self.store)
        self.store.update(lambda doc: doc["accounts"].clear())
        with self.assertRaisesRegex(arch.ArchDurableJoinError, "no password"):
            arch.agent_logon_plan(empty)


class ArchJoinAgentRunTests(RunFixture, unittest.TestCase):
    """The whole ``run`` under agent custody, with gate 8 faked."""

    def setUp(self):
        super().setUp()
        self.target = write_instance(self.tmp / "persistent", INSTANCE,
                                     console=CONSOLE)
        self.store = cc.instance_store(self.target)
        self.temporary = cc.AgentCredentialSource(self.store).staging_value(
            arch.DAILY_ROLE, temporary=True)
        for name, value in (
                ("durable_binding",
                 lambda *a, **k: binding(state=self.target.state)),
                ("_typed_secret", never_prompted)):
            patcher = mock.patch.object(arch, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def factory(self, bundle, **options):
        # The runner clears its credentials when it returns; keep what the
        # boundary was handed.
        credentials = options["credentials"]
        self.handed = (credentials.console, credentials.daily,
                       credentials.new_daily, credentials.rescue,
                       credentials.scan_values())
        return super().factory(bundle, **options)

    def test_first_logon_to_fold_runs_unprompted_and_settles_custody(self):
        entry = {"stage": "arch-join", "utc": "2026-09-30T02:00:00+00:00",
                 "disk_sha256": "cd" * 32, "vars_sha256": "ef" * 32,
                 "source": "synthetic"}
        plan_text = self.run_quietly()
        self.assertIn("Credentials: agent custody", plan_text)
        self.assertNotIn("Prompts, in order", plan_text)
        with mock.patch.object(wi.WorkstationInstance, "fold", autospec=True,
                               return_value=entry):
            output = self.run_quietly("--apply")
        [boundary] = self.boundaries
        console, daily, new, rescue, scanned = self.handed
        self.assertEqual(arch.MODE_FIRST_LOGON, boundary.options["mode"])
        self.assertEqual(CONSOLE.encode(), console)
        self.assertEqual(self.temporary.encode(), daily)
        account = cc.AgentCredentialSource(self.store).account(arch.DAILY_ROLE)
        self.assertIsNone(account["pending"])
        self.assertEqual(new.decode(), account["current"])
        self.assertIsNone(account["temporary"])
        wstore = cc.workstation_store(self.state, "w1")
        self.assertEqual(rescue.decode(), wstore.read()["break_glass"][
            cc.ARCH_LOCAL_RESCUE]["current"])
        for value in (console, daily, new, rescue):
            self.assertIn(value, scanned)
        self.assertEqual(0o700 & wstore.directory.stat().st_mode, 0o700)
        values = self.store.values() + wstore.values()
        self.assertEqual(0, hits(output, values))
        result = self.result()
        self.assertIn(arch.DAILY_ROLE, result["custody"])
        self.assertEqual(0, hits(json.dumps(result), values))

    def test_first_logon_done_is_refused_under_agent_custody(self):
        with self.assertRaisesRegex(arch.ArchDurableJoinError,
                                    "owner custody"):
            self.run_quietly("--first-logon-done")


class WindowsAndVerifyAgentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = write_instance(self.root, INSTANCE, console=CONSOLE)
        self.store = cc.instance_store(self.target)
        self.wstate = self.root / "w1"
        self.wstate.mkdir()
        self.source = cc.AgentCredentialSource(
            self.store, cc.workstation_store(self.wstate, "w1"))
        self.source.staging_value("daily_administrator", temporary=True)

    def prove_daily(self) -> str:
        self.source.begin_pending("daily_administrator", "Daily0Current1Pass",
                                  kind=cc.PENDING_FIRST_LOGON)
        self.source.promote_pending("daily_administrator")
        return "Daily0Current1Pass"

    def test_windows_needs_a_proven_current_daily_password(self):
        with self.assertRaisesRegex(windows.DurableWindowsJoinError,
                                    "no proven current"):
            windows.agent_secrets(self.source)
        self.source.begin_pending("daily_administrator", "Pending0Value1X",
                                  kind=cc.PENDING_FIRST_LOGON)
        with self.assertRaisesRegex(windows.DurableWindowsJoinError,
                                    "pending"):
            windows.agent_secrets(self.source)

    def test_windows_generates_and_stores_the_local_administrator(self):
        daily = self.prove_daily()
        secrets = windows.agent_secrets(self.source)
        self.assertEqual(CONSOLE.encode(), secrets.console)
        self.assertEqual(daily, secrets.daily_administrator)
        self.assertIsNone(windows.local_administrator_password_problem(
            secrets.local_administrator))
        stored = self.source.workstation_store.read()["break_glass"][
            cc.WINDOWS_LOCAL_ADMINISTRATOR]
        self.assertEqual(secrets.local_administrator, stored["pending"])
        self.assertNotIn(secrets.local_administrator, (CONSOLE, daily))
        for value in self.source.scan_values():
            self.assertIn(value, secrets.values())
        self.assertNotIn(secrets.local_administrator, repr(secrets))

    def test_verify_reads_the_console_and_the_proven_daily_password(self):
        daily = self.prove_daily()
        secrets = verify.agent_verify_secrets(self.source)
        self.assertEqual(CONSOLE.encode(), secrets.console)
        self.assertEqual(daily.encode(), secrets.daily)
        for value in self.source.scan_values():
            self.assertIn(value.encode(), secrets.values())
            self.assertIn(value, secrets.texts())

    def test_the_owner_secret_objects_are_unchanged_without_extras(self):
        owner = windows.OwnerSecrets(b"c-1", "l-2", "d-3")
        self.assertEqual(("c-1", "l-2", "d-3"), owner.values())
        self.assertEqual([b"c-1", b"d-3"],
                         verify.VerifySecrets(b"c-1", b"d-3").values())
        credentials = arch.OwnerCredentials(b"c-1", b"d-2", None, b"r-3")
        self.assertEqual(credentials.values(), credentials.scan_values())


if __name__ == "__main__":
    unittest.main()
