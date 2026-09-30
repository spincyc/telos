"""The static guard that keeps principal names out of Windows guest scripts."""

from pathlib import Path
import unittest

from homelab.vm.windows_guest_principals import (
    GUEST_ROLES,
    WindowsGuestPrincipalError,
    audit_guest_script,
    contract_principals,
    guarded_names,
    principal_pins,
    render_guest_script,
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
    DIRECTORY_PRINCIPALS = controller_principals.directory_principals()


VM_ROOT = Path(__file__).resolve().parents[1] / "vm"
# The one script rendered before it ships; every other one ships as tracked.
RENDERED = {"windows_control/Invoke-TelosIdentityProbe.ps1"}
# Listed as well as discovered: a sweep that silently shrank would still pass.
KNOWN_GUEST_SCRIPTS = {
    "windows_control/Invoke-TelosIdentityProbe.ps1",
    "windows_credential_action_control/TelosCredential.ps1",
    "windows_join_control/TelosJoin.ps1",
    "windows_join_control/TelosPostSubmitDiagnostic.ps1",
    "windows_progress_control/TelosProgress.ps1",
}
# Built here rather than written down (ADR 0046), every role renamed.
RENAMED = {
    "standard_user": "renamed-user",
    "daily_administrator": "renamed-admin",
    "domain_administrator": "renamed-dadmin",
}


def contract_names():
    """The synthetic names, whatever overlay this machine has."""
    return guarded_names()


class TrackedGuestScriptTests(unittest.TestCase):
    def test_every_tracked_guest_script_pins_no_principal(self):
        scripts = {
            path.relative_to(VM_ROOT).as_posix(): path
            for path in VM_ROOT.rglob("*.ps1")
        }
        self.assertLessEqual(KNOWN_GUEST_SCRIPTS, set(scripts))
        for relative, path in sorted(scripts.items()):
            with self.subTest(script=relative):
                roles = audit_guest_script(
                    path.read_bytes().decode("ascii"), label=relative,
                    placeholders=relative in RENDERED)
                expected = (
                    frozenset(GUEST_ROLES) if relative in RENDERED
                    else frozenset())
                self.assertEqual(expected, roles)

    def test_the_synthetic_names_are_guarded_whatever_the_roster(self):
        # The contract names, not the resolved ones: a pin of a synthetic
        # name is the regression, and it must fail with or without an
        # overlay present.
        self.assertEqual(
            {name.casefold() for name in contract_principals().values()},
            set(guarded_names()))

    def test_a_valid_short_account_name_cannot_refuse_gate_six(self):
        # Why the RESOLVED names are not guarded beyond the UPN rule: an
        # owner's initials would collide with literals the scripts carry
        # legitimately, and a valid roster would be refused.
        registry = (
            "$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\"
            "WindowsUpdate\\AU'")
        self.assertNotEqual([], principal_pins(registry, {"au": "initials"}))
        self.assertEqual([], principal_pins(registry, guarded_names()))
        # DIRECTORY_PRINCIPALS is whatever this machine resolves, overlay or
        # not; none of it changes what the tracked scripts are judged by.
        self.assertEqual(
            len(GUEST_ROLES), len(set(DIRECTORY_PRINCIPALS)))


class PinShapeTests(unittest.TestCase):
    def pins(self, source, names=None):
        return principal_pins(source, names or contract_names())

    def test_every_account_shape_of_a_synthetic_name_is_refused(self):
        for name in contract_principals().values():
            upper = name.upper()
            for source in (
                f"$operator = '{name}@' + $realm",
                f"$sid = Resolve-AccountSid ($domain + '\\{name}')",
                f"$sid = Resolve-AccountSid 'FACTORY\\{name}'",
                f"if ($config.operator_name -cne '{name}') {{ throw 'x' }}",
                f"$all = @('first', '{name}', 'last')",
                f"$sid = Resolve-AccountSid \"$domain\\{name}\"",
                f"$upn = \"{name}@$realm\"",
                f"$sid = Resolve-AccountSid \"$($computer.Domain)\\{name}\"",
                f"& runas.exe '/user:{name}' cmd",
                f"$x = @'\n{name}@AD.FACTORY.TEST\n'@",
                f"$x = @\"\nFACTORY\\{name}\n\"@",
                f"$x = '{upper}@' + $realm",
                f"Get-LocalUser -Name {name}",
                f"switch ($role) {{ {name} {{ 1 }} }}",
                f"$x = 'a''b' + '{name}@'",
            ):
                with self.subTest(source=source):
                    self.assertNotEqual([], self.pins(source))
                    with self.assertRaisesRegex(
                            WindowsGuestPrincipalError,
                            "pins a principal name"):
                        audit_guest_script(
                            source, label="Pinned.ps1", placeholders=False,
                            names=contract_names())

    def test_words_that_are_not_accounts_are_not_pins(self):
        # Every one of these occurs in a tracked guest script today.
        for source in (
            "throw 'daily operator local Administrators assignment was not "
            "proved'",
            "# the synthetic operator@AD.FACTORY.TEST logs in here",
            "<# student, operator, directory-admin #>",
            "$operator = $null",
            "$script:operator = 1",
            "$config.operator_name",
            "return [ordered]@{ operator = [string]$operator }",
            "'interactive-operator'",
            "'operator-resolution'",
            "'local-rescue-login'",
            "Test-OperatorMatch $x",
            "$x = @'\n    // provisioned\n    // operator, who TelosJoin\n'@",
            "$message = \"the $operator account\"",
        ):
            with self.subTest(source=source):
                self.assertEqual([], self.pins(source))

    def test_any_literal_upn_local_part_is_refused_whatever_the_name(self):
        # A guest script never needs one: realm-qualified names arrive in
        # the per-run document or through a rendered placeholder.  So a
        # renamed or invented name is refused as surely as a synthetic one.
        for source in (
            "$x = 'renamed-admin@' + $realm",
            "$x = 'someone-else@' + $document.realm",
            "$x = \"first.last@$realm\"",
            "$x = 'FACTORY\\renamed-admin@AD'",
        ):
            with self.subTest(source=source):
                self.assertNotEqual([], self.pins(source))
        for source in (
            "$parts = $upn.Split('@')",
            "$upn = [string]$name + '@' + $realm",
            "$upn = \"$user@$realm\"",
            "$x = '{{daily_administrator}}@' + $realm",
        ):
            with self.subTest(source=source):
                self.assertEqual([], self.pins(source))


class FailClosedTests(unittest.TestCase):
    def audit(self, source, *, placeholders=False):
        return audit_guest_script(
            source, label="Script.ps1", placeholders=placeholders,
            names=contract_names())

    def test_text_the_lexer_cannot_account_for_is_refused(self):
        for source, reason in (
            ("$x = 'unterminated\n", "unterminated string"),
            ('$x = "unterminated\n', "unterminated string"),
            ("$x = @'\nno terminator\n", "unterminated here-string"),
            ("$x = @' trailing\n'@", "malformed here-string opener"),
            ("<# never closed\n$x = 1", "unterminated block comment"),
            ('$x = "$(Get-Thing"', "unterminated"),
            # A typographic quote is a quote to PowerShell.
            ("$x = \u2018operator@\u2019", "non-ASCII"),
        ):
            with self.subTest(source=source):
                with self.assertRaisesRegex(
                        WindowsGuestPrincipalError, reason):
                    self.audit(source)

    def test_placeholders_are_audited_as_strictly_as_names(self):
        placeholder = "$x = '{{daily_administrator}}@' + $realm"
        self.assertEqual(
            frozenset({"daily_administrator"}),
            self.audit(placeholder, placeholders=True))
        with self.assertRaisesRegex(WindowsGuestPrincipalError, "unrendered"):
            self.audit(placeholder)
        with self.assertRaisesRegex(
                WindowsGuestPrincipalError, "unknown principal role"):
            self.audit("$x = '{{local_rescue}}'", placeholders=True)
        with self.assertRaisesRegex(
                WindowsGuestPrincipalError, "malformed"):
            self.audit("$x = '{{standard_user}'", placeholders=True)
        with self.assertRaises(WindowsGuestPrincipalError):
            principal_pins("$x = 1", {})


class RenderTests(unittest.TestCase):
    def test_each_placeholder_becomes_the_roster_name(self):
        source = (
            "$a = '{{daily_administrator}}@' + $realm\n"
            "$b = $domain + '\\{{standard_user}}'\n"
            "$c = '{{domain_administrator}}'\n"
        )
        self.assertEqual(
            "$a = 'renamed-admin@' + $realm\n"
            "$b = $domain + '\\renamed-user'\n"
            "$c = 'renamed-dadmin'\n",
            render_guest_script(source, RENAMED))

    def test_a_roster_the_guest_would_not_admit_is_refused(self):
        source = "$a = '{{daily_administrator}}'\n"
        for roster in (
            {**RENAMED, "daily_administrator": "Renamed"},
            {**RENAMED, "daily_administrator": "x" * 21},
            {**RENAMED, "daily_administrator": "renamed'admin"},
            {**RENAMED, "standard_user": RENAMED["daily_administrator"]},
            {k: v for k, v in RENAMED.items() if k != "domain_administrator"},
        ):
            with self.subTest(roster=roster):
                with self.assertRaises(WindowsGuestPrincipalError):
                    render_guest_script(source, roster)
        with self.assertRaisesRegex(WindowsGuestPrincipalError, "unknown"):
            render_guest_script("'{{local_rescue}}'", RENAMED)
        with self.assertRaisesRegex(WindowsGuestPrincipalError, "malformed"):
            render_guest_script("'{{standard_user}'", RENAMED)


if __name__ == "__main__":
    unittest.main()
