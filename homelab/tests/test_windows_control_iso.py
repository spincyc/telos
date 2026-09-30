"""Contracts for the secret-free, read-only Windows control disc."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from homelab.vm.controller_factory import FactorySpec
from homelab.vm.windows_control_iso import (
    ASSET_ROOT,
    MAX_PROBE_LAUNCH_CHARS,
    WindowsControlIsoError,
    audit_payload,
    build_control_iso,
    probe_launch_command,
    probe_launch_marker,
    render_probe_script,
)
from homelab.vm.windows_guest_principals import (
    contract_principals,
    guarded_names,
    principal_pins,
)
from homelab.tests.identity_overlay_pin import pinned_identity_overlay
from homelab.vm import controller_principals


def setUpModule():
    # HANDOFF section 5: no test reads the owner's private overlay.  The
    # roster the code under test reads resolves on first use from the DEFAULT
    # overlay path, so every test here runs with that path pinned to a private
    # one that does not exist -- the synthetic acceptance roster.
    unittest.enterModuleContext(pinned_identity_overlay())


# The roster names these tests drive, read under the same pin, so importing
# this module reads no overlay either.
with pinned_identity_overlay():
    DAILY_ADMINISTRATOR = controller_principals.daily_administrator()
    DOMAIN_ADMINISTRATOR = controller_principals.domain_administrator()
    STANDARD_USER = controller_principals.standard_user()


# Built here rather than written down: ADR 0046 keeps real account names out
# of every tracked file, and every role is renamed so no synthetic default can
# carry a test.
RENAMED = {
    "standard_user": "renamed-user",
    "daily_administrator": "renamed-admin",
    "domain_administrator": "renamed-dadmin",
}


def probe_account_lines(roster):
    """The six lines where the probe names a directory principal."""
    return (
        f"$operator = '{roster['daily_administrator']}@' + "
        "$ControllerDomain.ToUpperInvariant()",
        f"'{roster['standard_user']}', '{roster['daily_administrator']}', "
        f"'{roster['domain_administrator']}' |",
        f"$operator = '{roster['daily_administrator']}@' + (",
        "$standardSid = Resolve-AccountSid ($domain + "
        f"'\\{roster['standard_user']}')",
        "$operatorSid = Resolve-AccountSid ($domain + "
        f"'\\{roster['daily_administrator']}')",
        f"$domain + '\\{roster['domain_administrator']}')",
    )


def staged_payload(test, **kwargs):
    """Build the control ISO with a capturing runner; return staged bytes."""
    observed = {}

    def runner(command, *, check):
        test.assertTrue(check)
        stage = Path(command[-1])
        observed.update({
            item.name: item.read_bytes() for item in stage.iterdir()})
        Path(command[command.index("-o") + 1]).write_bytes(b"iso")

    with tempfile.TemporaryDirectory() as temporary:
        build_control_iso(
            Path(temporary) / "control.iso", runner=runner, **kwargs)
    return observed


class WindowsControlIsoTests(unittest.TestCase):
    def test_tracked_payload_is_allowlisted_read_only_and_secret_free(self):
        manifest = audit_payload()
        script = (
            ASSET_ROOT / "Invoke-TelosIdentityProbe.ps1"
        ).read_text(encoding="utf-8")
        self.assertEqual("serial-jsonl", manifest["transport"]["kind"])
        self.assertIn("ValidateSet", script)
        self.assertIn("[System.IO.Ports.SerialPort]", script)
        self.assertIn("gateway-reachability", manifest["actions"])
        self.assertIn("dependency-reachability", manifest["actions"])
        self.assertIn("controller-readiness", manifest["actions"])
        self.assertIn("current-session-state", manifest["actions"])
        self.assertIn("interactive-operator", manifest["actions"])
        self.assertIn("managed-identity-state", manifest["actions"])
        self.assertIn("'10.1.31.1')) 31337", script)
        self.assertIn("'sim-ok:health'", script)
        self.assertIn("'10.1.31.3')) 31338", script)
        self.assertIn("'update-source:available'", script)
        self.assertIn("'10.1.31.4')) 31339", script)
        self.assertIn("'optional-storage:available'", script)
        self.assertIn("'optional-storage:authorization-denied'", script)
        self.assertIn("GetBytes('authorize')", script)
        # The tracked probe names principals only by roster placeholder; the
        # names are rendered into the staged copy (tests below).
        self.assertIn("'{{daily_administrator}}@'", script)
        self.assertEqual([], principal_pins(script, guarded_names()))
        self.assertIn("'S-1-5-32-544'", script)
        self.assertIn("Get-LocalGroupMember", script)
        spec = FactorySpec()
        self.assertIn(
            f"$ControllerDomain = '{spec.domain}'", script)
        self.assertIn(
            f"$ControllerFqdn = '{spec.fqdn}'", script)
        readiness = script[
            script.index("'controller-readiness' {"):
            script.index("'domain-state' {")
        ]
        self.assertNotIn("PartOfDomain", readiness)
        self.assertIn("$ControllerDomain", readiness)
        self.assertIn("$ControllerFqdn", readiness)
        self.assertIn("Test-TcpPort $ControllerFqdn 88", readiness)
        self.assertIn("Test-TcpPort $ControllerFqdn 389", readiness)
        self.assertIn("Test-TcpPort $ControllerFqdn 445", readiness)
        self.assertNotIn("Password", script)
        self.assertNotIn("Credential", script)

    def test_managed_identity_membership_is_strictmode_safe_and_sid_exact(self):
        """Attempt 35 (20260811T125822Z): the first live
        managed-identity-state probe threw under Set-StrictMode Latest by
        reading .SID on a Win32_GroupUser association REFERENCE (references
        carry only their Domain/Name keys), rendering guest-probe-error.
        Membership must select the group by exact SID and dereference the
        association to full member instances, with every pipeline
        @()-wrapped so an empty result cannot raise on .Count."""
        script = (
            ASSET_ROOT / "Invoke-TelosIdentityProbe.ps1"
        ).read_text(encoding="utf-8")
        # The landmines are gone: no property access on association
        # references and no unfiltered association scan.
        self.assertNotIn("PartComponent.SID", script)
        self.assertNotIn("GroupComponent.Name", script)
        self.assertNotIn("Get-CimInstance Win32_GroupUser", script)
        helper = script[
            script.index("function Test-DomainGroupMemberBySid"):
            script.index("function Test-UdpRole")
        ]
        self.assertIn("\"SID='\" + $GroupSid.Value + \"'\"", helper)
        self.assertIn("Get-CimAssociatedInstance", helper)
        self.assertIn("-Association Win32_GroupUser", helper)
        self.assertIn("$_.PSObject.Properties['SID']", helper)
        # Null SIDs fail closed before any query.
        self.assertIn(
            "if ($null -eq $GroupSid -or $null -eq $MemberSid) {", helper)
        managed = script[
            script.index("'managed-identity-state' {"):
            script.index("'cached-logon-policy' {")
        ]
        # Both domain-membership fields go through the safe helper with the
        # SID-exact arguments; the judged checks depend on real values
        # (domain-admin-separate requires directory-admin membership True).
        self.assertEqual(2, managed.count("Test-DomainGroupMemberBySid"))
        self.assertIn("$domainAdminsSid $operatorSid", managed)
        self.assertIn("$domainAdminsSid $directoryAdminSid", managed)

    def test_serial_opens_before_probe_and_failure_record_is_fixed(self):
        script = (
            ASSET_ROOT / "Invoke-TelosIdentityProbe.ps1"
        ).read_text(encoding="utf-8")
        bind_at = script.index("$serial = $S")
        start_at = script.index("result = 'start'", bind_at)
        start_write_at = script.index("$serial.WriteLine", start_at)
        probe_at = script.index(
            "observation = Get-Probe $Action", bind_at)
        self.assertLess(bind_at, start_at)
        self.assertLess(start_at, start_write_at)
        self.assertLess(start_write_at, probe_at)
        failure = script[
            script.index("catch {", probe_at):
            script.index("$line = $record", probe_at)
        ]
        self.assertIn("result = 'fail'", failure)
        self.assertIn("phase = 'observation'", failure)
        self.assertIn("code = 'guest-probe-error'", failure)
        self.assertNotIn("$_.", failure)
        self.assertNotIn("Exception", failure)
        self.assertNotIn("Message", failure)

    def test_builder_stages_only_static_payload_and_public_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "control.iso"
            observed = {}

            def runner(command, *, check):
                self.assertTrue(check)
                stage = Path(command[-1])
                observed["names"] = sorted(
                    item.name for item in stage.iterdir()
                    if item.name != "control.iso")
                observed["receipt"] = json.loads(
                    (stage / "receipt.json").read_text(encoding="utf-8"))
                Path(command[command.index("-o") + 1]).write_bytes(b"iso")

            self.assertEqual(
                output, build_control_iso(output, runner=runner))
            self.assertEqual(0o444, output.stat().st_mode & 0o777)
            self.assertEqual([
                "Invoke-TelosIdentityProbe.ps1", "manifest.json",
                "receipt.json",
            ], observed["names"])
            self.assertFalse(observed["receipt"]["contains_secrets"])
            self.assertTrue(observed["receipt"]["read_only_actions"])
            self.assertEqual(
                set(observed["receipt"]["actions"]),
                set(audit_payload()["actions"]))

    def test_launch_command_discovers_volume_and_accepts_only_manifest_action(self):
        command = probe_launch_command("domain-state")
        self.assertIn("TELOS_CONTROL", command)
        self.assertIn("Invoke-TelosIdentityProbe.ps1", command)
        self.assertIn("-A 'domain-state'", command)
        self.assertIn("$p.Open();$p.WriteLine(4);", command)
        self.assertLess(
            command.index("$p.WriteLine(4)"),
            command.index("Get-Volume"),
        )
        self.assertLessEqual(len(command), MAX_PROBE_LAUNCH_CHARS)
        with self.assertRaisesRegex(
                WindowsControlIsoError, "not allowlisted"):
            probe_launch_command("domain-state'; Set-LocalUser")

    def test_every_action_has_one_exact_bounded_launch(self):
        actions = audit_payload()["actions"]
        self.assertIsInstance(actions, list)
        for action in actions:
            with self.subTest(action=action):
                command = probe_launch_command(action)
                self.assertLessEqual(
                    len(command), MAX_PROBE_LAUNCH_CHARS)
                self.assertTrue(command.startswith(
                    "powershell.exe -NoP -NonI -EP Bypass -C \""))
                self.assertEqual(
                    1, command.count(
                        "Get-Volume -FileSystemLabel TELOS_CONTROL"))
                self.assertEqual(
                    1, command.count(
                        "\\Invoke-TelosIdentityProbe.ps1"))
                self.assertTrue(
                    command.endswith(f"-A '{action}' -S $p\""))
                self.assertEqual(1, command.count("-A '"))
                marker = probe_launch_marker(action)
                self.assertEqual(
                    1, command.count(f"$p.WriteLine({marker})"))

    def test_existing_destination_and_mutating_script_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "control.iso"
            output.write_bytes(b"existing")
            with self.assertRaisesRegex(
                    WindowsControlIsoError, "destination must be absent"):
                build_control_iso(output)

            assets = root / "assets"
            assets.mkdir()
            for item in ASSET_ROOT.iterdir():
                (assets / item.name).write_bytes(item.read_bytes())
            script = assets / "Invoke-TelosIdentityProbe.ps1"
            script.write_text(
                script.read_text(encoding="utf-8") + "\nSet-LocalUser\n",
                encoding="utf-8")
            with self.assertRaisesRegex(
                    WindowsControlIsoError, "mutating"):
                audit_payload(assets)


class ControlProbeRosterTests(unittest.TestCase):
    """The probe resolves the principals the host roster names, not literals.

    It used to pin the synthetic acceptance names, so a seeded overlay made
    interactive-operator and domain-state report ``operator@...`` while the
    host expected the renamed daily administrator, and managed-identity-state
    resolve accounts the directory no longer had.
    """

    def test_a_renamed_roster_reaches_every_account_the_probe_resolves(self):
        staged = staged_payload(self, roster=RENAMED)
        probe = staged["Invoke-TelosIdentityProbe.ps1"].decode("ascii")
        for line in probe_account_lines(RENAMED):
            with self.subTest(line=line):
                self.assertIn(line, probe)
        # No synthetic name survives as an account, and no placeholder
        # reaches the guest.
        for name in contract_principals().values():
            for shape in (f"'{name}@'", f"\\{name}'", f"'{name}'"):
                self.assertNotIn(shape, probe)
        self.assertNotIn("{{", probe)
        # Rendering touches only those literals.
        tracked = (ASSET_ROOT / "Invoke-TelosIdentityProbe.ps1").read_bytes()
        expected = tracked.decode("ascii")
        for role, name in RENAMED.items():
            expected = expected.replace("{{" + role + "}}", name)
        self.assertEqual(expected, probe)
        # The public receipt describes the bytes that actually ship, and the
        # manifest is copied untouched.
        receipt = json.loads(staged["receipt.json"])
        self.assertEqual(
            hashlib.sha256(staged["Invoke-TelosIdentityProbe.ps1"]).hexdigest(),
            receipt["files"]["Invoke-TelosIdentityProbe.ps1"])
        self.assertEqual(
            (ASSET_ROOT / "manifest.json").read_bytes(),
            staged["manifest.json"])
        # The Run-dialog launch line carries no name, so it is unchanged and
        # still within its bound.
        for action in audit_payload()["actions"]:
            command = probe_launch_command(action)
            self.assertLessEqual(len(command), MAX_PROBE_LAUNCH_CHARS)
            for name in RENAMED.values():
                self.assertNotIn(name, command)

    def test_the_contract_roster_renders_the_synthetic_acceptance_probe(self):
        # With no private overlay the host roster IS the contract, and the
        # staged probe must be the script gate 6 proved: every placeholder
        # becomes the synthetic name and nothing else moves.
        contract = contract_principals()
        roster = {role: contract[role] for role in RENAMED}
        probe = render_probe_script(roster=roster).decode("ascii")
        for line in probe_account_lines(roster):
            with self.subTest(line=line):
                self.assertIn(line, probe)
        self.assertNotIn("{{", probe)

    def test_the_default_build_follows_the_resolved_roster(self):
        # Under the overlay regression this is a renamed roster; without an
        # overlay it is the contract.  Either way the staged probe names
        # exactly what the host will judge.
        resolved = {
            "standard_user": STANDARD_USER,
            "daily_administrator": DAILY_ADMINISTRATOR,
            "domain_administrator": DOMAIN_ADMINISTRATOR,
        }
        probe = staged_payload(self)[
            "Invoke-TelosIdentityProbe.ps1"].decode("ascii")
        for line in probe_account_lines(resolved):
            with self.subTest(line=line):
                self.assertIn(line, probe)

    def test_the_audit_refuses_a_probe_that_pins_or_drops_a_principal(self):
        tracked = (ASSET_ROOT / "Invoke-TelosIdentityProbe.ps1").read_text(
            encoding="utf-8")
        contract = contract_principals()
        cases = (
            # The regression itself: a synthetic name pinned again, in each
            # shape the probe used.
            ("pins a principal name",
             "'{{daily_administrator}}@' + $ControllerDomain",
             f"'{contract['daily_administrator']}@' + $ControllerDomain"),
            ("pins a principal name",
             "($domain + '\\{{standard_user}}')",
             f"($domain + '\\{contract['standard_user']}')"),
            ("pins a principal name",
             "'{{standard_user}}', '{{daily_administrator}}'",
             f"'{contract['standard_user']}', '{{{{daily_administrator}}}}'"),
            # A probe that stops resolving one role at all.
            ("every directory principal",
             "{{domain_administrator}}", "{{daily_administrator}}"),
            ("unknown principal role",
             "'{{standard_user}}', '{{daily_administrator}}'",
             "'{{local_rescue}}', '{{daily_administrator}}'"),
            ("malformed principal placeholder",
             "$domain + '\\{{domain_administrator}}')",
             "$domain + '\\{{domain_administrator}')"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for index, (message, old, new) in enumerate(cases):
                with self.subTest(message=message, new=new):
                    self.assertIn(old, tracked)
                    assets = Path(temporary) / f"assets-{index}"
                    assets.mkdir()
                    for item in ASSET_ROOT.iterdir():
                        (assets / item.name).write_bytes(item.read_bytes())
                    (assets / "Invoke-TelosIdentityProbe.ps1").write_text(
                        tracked.replace(old, new), encoding="utf-8")
                    with self.assertRaisesRegex(
                            WindowsControlIsoError, message):
                        audit_payload(assets)
                    with self.assertRaisesRegex(
                            WindowsControlIsoError, message):
                        build_control_iso(
                            Path(temporary) / f"control-{index}.iso",
                            asset_root=assets,
                            runner=lambda *_args, **_kwargs: self.fail(
                                "xorriso ran for a refused payload"))

    def test_rendering_refuses_a_roster_the_guest_would_not_admit(self):
        for roster in (
            {**RENAMED, "daily_administrator": "Renamed-Admin"},
            {**RENAMED, "daily_administrator": "a" * 21},
            {**RENAMED, "daily_administrator": "renamed'admin"},
            {**RENAMED, "domain_administrator": RENAMED["daily_administrator"]},
            {k: v for k, v in RENAMED.items() if k != "standard_user"},
        ):
            with self.subTest(roster=roster):
                with self.assertRaisesRegex(
                        WindowsControlIsoError, "cannot be rendered"):
                    render_probe_script(roster=roster)
        # A name that would smuggle a forbidden primitive into the rendered
        # text is refused by the same audit the tracked text passed.
        with self.assertRaisesRegex(WindowsControlIsoError, "mutating"):
            render_probe_script(
                roster={**RENAMED, "standard_user": "add-computer"})


if __name__ == "__main__":
    unittest.main()
