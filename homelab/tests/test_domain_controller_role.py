"""Static contract tests for the host-level Samba AD domain-controller role.

These tests deliberately do not provision a domain.  They protect the boundary
around that destructive, credential-bearing operation and require the role to
ship observable acceptance and recovery paths that can later be exercised in
the isolated VM.
"""

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/domain_controller"

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the host
    yaml = None


@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
class TestDomainControllerRole(unittest.TestCase):
    def load(self, relative):
        return yaml.safe_load((ROLE / relative).read_text())

    def tasks(self):
        return self.load("tasks/main.yml")

    def all_tasks(self):
        pending = list(self.tasks())
        flattened = []
        while pending:
            task = pending.pop(0)
            flattened.append(task)
            for section in ("block", "rescue", "always"):
                pending[0:0] = task.get(section, [])
        return flattened

    def role_text(self):
        return "\n".join(
            path.read_text()
            for path in sorted(ROLE.rglob("*"))
            if path.is_file() and path.suffix != ".pyc"
        )

    def test_every_yaml_file_parses(self):
        self.assertTrue(ROLE.is_dir(), "domain_controller role is missing")
        for path in sorted(ROLE.rglob("*.yml")):
            with self.subTest(path=path.relative_to(ROLE)):
                yaml.safe_load(path.read_text())

    def test_instance_identity_has_no_public_default(self):
        defaults = self.load("defaults/main.yml")
        private_values = (
            "homelab_ad_dns_domain",
            "homelab_ad_realm",
            "homelab_ad_netbios_domain",
        )
        for name in private_values:
            with self.subTest(variable=name):
                self.assertEqual(defaults.get(name), "")

        public_text = self.role_text()
        for private_literal in (
            "private.example",
            "PRIVATE.EXAMPLE",
            "EXAMPLELAB",
        ):
            with self.subTest(private_literal=private_literal):
                self.assertNotIn(private_literal, public_text)

    def test_first_domain_creation_is_off_by_default(self):
        defaults = self.load("defaults/main.yml")
        switches = {
            name: value for name, value in defaults.items()
            if "provision" in name.lower() and isinstance(value, bool)
        }
        self.assertTrue(switches, "there is no explicit first-DC switch")
        self.assertTrue(all(value is False for value in switches.values()))

    def test_provisioning_requires_both_opt_in_and_a_secret(self):
        text = (ROLE / "tasks/main.yml").read_text()
        self.assertRegex(text, r"(?i)assert")
        self.assertRegex(text, r"(?i)(first.*(?:dc|domain)|(?:dc|domain).*first)")
        self.assertRegex(text, r"(?i)(password|secret)")

        provisioners = [
            task for task in self.all_tasks()
            if str(task.get("name", "")).lower().startswith("provision ")
            and ("ansible.builtin.command" in task
                 or "ansible.builtin.shell" in task)
        ]
        self.assertTrue(provisioners, "no guarded domain provision task found")
        for task in provisioners:
            with self.subTest(task=task.get("name")):
                self.assertIs(task.get("no_log"), True)
                self.assertTrue(
                    "when" in task or any(
                        parent.get("name")
                        == "Provision with an ephemeral credential feeder"
                        for parent in self.tasks()
                    ),
                    "provisioning must be conditional",
                )

    def test_preflight_precedes_every_mutating_task(self):
        tasks = self.tasks()
        names = [str(task.get("name", "")) for task in tasks]
        package_index = names.index("Install Samba AD dependencies")
        preflight = "\n".join(str(task) for task in tasks[:package_index])
        self.assertIn("ansible_fqdn", preflight)
        self.assertIn("getent", preflight)
        self.assertIn("NTPSynchronized", preflight)
        self.assertIn("ansible_check_mode", preflight)
        self.assertIn("end_host", preflight)
        self.assertIn("Require explicit authorization", preflight)
        self.assertIn("Require a protected one-time password file", preflight)

    def test_credential_feeder_is_removed_even_after_failure(self):
        provisions = [
            task for task in self.tasks()
            if task.get("name") == "Provision with an ephemeral credential feeder"
        ]
        self.assertEqual(1, len(provisions))
        self.assertIn("block", provisions[0])
        self.assertIn("always", provisions[0])
        self.assertIn(
            "state': 'absent",
            str(provisions[0]["always"]),
        )

    def test_password_feeder_rejects_a_blank_first_line(self):
        driver = ROLE / "files/provision-domain.py"
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as secret, \
                tempfile.TemporaryDirectory() as directory:
            secret.write("\nnot-the-first-line\n")
            secret.flush()
            result = subprocess.run(
                [
                    sys.executable, str(driver),
                    "--password-file", secret.name,
                    "--realm", "EXAMPLE.INVALID",
                    "--domain", "EXAMPLE",
                    "--server-role", "dc",
                    "--dns-backend", "SAMBA_INTERNAL",
                    "--diagnostic-file",
                    str(Path(directory) / "status"),
                    "--use-rfc2307",
                ],
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("nonempty first line", result.stderr)

    def test_provision_diagnostic_is_bounded_private_and_redacted(self):
        driver = (ROLE / "files/provision-domain.py").read_text()
        self.assertIn("status.replace(password, \"[REDACTED]\")", driver)
        self.assertIn("status[-16384:]", driver)
        self.assertIn("os.O_NOFOLLOW", driver)
        self.assertIn("0o600", driver)
        self.assertNotRegex(
            driver, r"(?:print|write)\\s*\\(\\s*password\\s*\\)")

    def test_provisioning_password_uses_in_process_samba_api_only(self):
        driver = (ROLE / "files/provision-domain.py").read_text()
        self.assertIn("from samba.provision import provision", driver)
        self.assertIn("adminpass=password", driver)
        self.assertNotIn("pexpect", driver)
        self.assertNotIn("subprocess", driver)
        self.assertNotIn("samba-tool", driver)
        self.assertNotIn("report_logger", driver)

    def test_rfc2307_switches_are_mutually_exclusive_and_required(self):
        driver = (ROLE / "files/provision-domain.py").read_text()
        self.assertIn("add_mutually_exclusive_group(required=True)", driver)

    def test_no_secret_value_is_written_to_a_template(self):
        for path in sorted((ROLE / "templates").glob("*")):
            with self.subTest(path=path.name):
                text = path.read_text()
                self.assertNotRegex(
                    text,
                    r"(?i)(admin|administrator|provision).*(password|secret)"
                    r"|(password|secret).*(admin|administrator|provision)",
                )

    def test_it_installs_samba_and_kerberos_support(self):
        defaults = self.load("defaults/main.yml")
        package_values = [
            value for name, value in defaults.items()
            if "package" in name.lower() and isinstance(value, list)
        ]
        packages = {str(item) for values in package_values for item in values}
        if not packages:
            packages = set(re.findall(
                r"\b(?:samba|krb5|bind|bind-tools|openresolv)\b",
                (ROLE / "tasks/main.yml").read_text(),
            ))
        self.assertIn("samba", packages)
        self.assertIn("krb5", packages)

    def test_conflicting_samba_units_are_disabled(self):
        text = (ROLE / "tasks/main.yml").read_text()
        for unit in ("smb.service", "nmb.service", "winbind.service"):
            with self.subTest(unit=unit):
                self.assertIn(unit, text)
        self.assertRegex(text, r"(?i)(disabled|enabled:\s*false)")

    def test_the_ad_dc_service_is_enabled(self):
        text = (ROLE / "tasks/main.yml").read_text()
        self.assertIn("samba.service", text)
        self.assertRegex(text, r"(?i)enabled:\s*true")

    def test_acceptance_probes_cover_domain_dns_and_kerberos(self):
        text = self.role_text()
        commands = []
        for path in sorted(ROLE.rglob("*.yml")):
            document = yaml.safe_load(path.read_text())
            if not isinstance(document, list):
                continue
            for task in document:
                for module in ("ansible.builtin.command", "ansible.builtin.shell"):
                    value = task.get(module)
                    if isinstance(value, dict) and isinstance(value.get("argv"), list):
                        commands.append(" ".join(str(item) for item in value["argv"]))
                    elif isinstance(value, dict) and value.get("cmd"):
                        commands.append(str(value["cmd"]))
                    elif isinstance(value, str):
                        commands.append(value)
        command_text = "\n".join(commands)
        required = {
            "domain information": r"samba-tool\s+domain\s+info",
            "AD service discovery": r"(?i)(_ldap\._tcp|_kerberos\._tcp|SRV)",
            "Kerberos ticket": r"\bkinit\b",
        }
        for claim, pattern in required.items():
            with self.subTest(claim=claim):
                self.assertRegex(command_text + "\n" + text, pattern)

    def test_acceptance_probes_do_not_embed_credentials(self):
        text = self.role_text()
        self.assertNotRegex(text, r"(?i)kinit\s+.*(?:--password|-w\s+)")
        self.assertNotRegex(
            text,
            r"(?im)^\s*(?:admin_?)?(?:password|secret)\s*[:=]\s*[\"'][^{}]",
        )

    def test_recovery_uses_supported_online_domain_backup(self):
        text = re.sub(r"[\n\r\[\],'\"{}]+", " ", self.role_text())
        self.assertRegex(text, r"samba-tool\s+(?:\\n\s*)?domain\s+backup\s+online")
        self.assertRegex(text, r"(?i)(backup|recovery).*(director|destination|path)")


DURABLE_BLOCK = "Converge the declared durable directory accounts"

# The synthetic acceptance roster, in the order controller_principals.py pins
# it. Declaring it through this role's own variables must reproduce that
# module's POSIX_ALLOCATION exactly; if it ever does not, the workstation would
# see different UIDs than the acceptance path proves and file ownership under
# the per-user share root would break.
ACCEPTANCE_ROSTER = [
    {"name": "student", "role": "standard", "password_file": "/run/one"},
    {"name": "operator", "role": "standard", "password_file": "/run/two"},
    {"name": "directory-admin", "role": "administrator",
     "password_file": "/run/three"},
]


def jinja():
    """A Jinja environment close enough to Ansible's to judge this role.

    Ansible cannot run here -- there is no directory to converge and no Samba
    to converge it -- so the role's expressions are evaluated with Jinja plus
    Ansible's own filter and test plugins. That is what makes the refusals
    below real assertions about the shipped YAML rather than restatements of
    it. The remaining fidelity gap is Ansible's loop and register semantics,
    which the helpers here reproduce explicitly.
    """
    from jinja2.nativetypes import NativeEnvironment
    from ansible.plugins.filter.core import FilterModule as CoreFilters
    from ansible.plugins.filter.mathstuff import FilterModule as MathFilters
    from ansible.plugins.test.core import TestModule as CoreTests

    environment = NativeEnvironment()
    environment.filters.update(CoreFilters().filters())
    environment.filters.update(MathFilters().filters())
    environment.tests.update(CoreTests().tests())
    return environment


try:  # pragma: no cover - depends on the host
    jinja()
    JINJA_REASON = ""
except ImportError as error:  # pragma: no cover - depends on the host
    JINJA_REASON = str(error)


@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
class DurableAccountBase(unittest.TestCase):
    """Shared access to the durable-account section of the role."""

    def tasks(self):
        return yaml.safe_load((ROLE / "tasks/main.yml").read_text())

    def defaults(self):
        return yaml.safe_load((ROLE / "defaults/main.yml").read_text())

    def block(self):
        return next(task for task in self.tasks()
                    if task.get("name") == DURABLE_BLOCK)

    def durable_tasks(self):
        pending = list(self.block()["block"])
        flattened = []
        while pending:
            task = pending.pop(0)
            flattened.append(task)
            for section in ("block", "rescue", "always"):
                pending[0:0] = task.get(section, [])
        return flattened

    def named(self, name):
        return next(task for task in self.durable_tasks()
                    if task.get("name") == name)

    def driver(self):
        return self.named("Create and converge the durable directory accounts")

    def commands(self):
        """Every command/shell invocation anywhere in the role, as argv."""
        pending = list(self.tasks())
        found = []
        while pending:
            task = pending.pop(0)
            for section in ("block", "rescue", "always"):
                pending[0:0] = task.get(section, [])
            for module in ("ansible.builtin.command", "ansible.builtin.shell"):
                value = task.get(module)
                if isinstance(value, dict) and isinstance(value.get("argv"), list):
                    found.append((task, [str(item) for item in value["argv"]]))
                elif isinstance(value, dict) and value.get("cmd"):
                    found.append((task, [str(value["cmd"])]))
                elif isinstance(value, str):
                    found.append((task, [value]))
        return found


class TestDurableAccountsAreInertByDefault(DurableAccountBase):
    """A run that declares no durable account must behave exactly as before.

    The acceptance path depends on this. `controller_principals.py` stages a
    synthetic roster with per-run generated passwords over the Controller
    serial, and gate 8 passes 21/21 with it; the disposable Controller's
    factory variables declare no durable account at all. So every task in this
    section has to be gated on the roster being non-empty, and the default has
    to be empty.
    """

    def test_no_durable_account_is_declared_by_default(self):
        defaults = self.defaults()
        self.assertEqual(defaults["homelab_ad_directory_accounts"], [])
        # A real name in a tracked file would be an instance-data leak
        # (ADR 0046), which is why the roster lives in the overlay.
        self.assertEqual(
            defaults["homelab_ad_account_password_reset_enabled"], False)

    def test_the_whole_section_is_gated_on_a_declared_roster(self):
        self.assertEqual(self.block()["when"],
                         "homelab_ad_directory_accounts | length > 0")

    def test_nothing_outside_that_gate_reads_the_roster_or_its_plan(self):
        # The gate is only worth having if no ungated task depends on it. A
        # task added above the block would run on the disposable Controller.
        for task in self.tasks():
            if task.get("name") == DURABLE_BLOCK:
                continue
            body = str(task)
            for variable in ("homelab_ad_directory_accounts",
                             "homelab_ad_account_plan",
                             "homelab_ad_account_group_plan",
                             "homelab_ad_account_share_root"):
                with self.subTest(task=task.get("name"), variable=variable):
                    self.assertNotIn(variable, body)

    def test_the_disposable_roster_never_moves_into_this_role(self):
        # Stated as a test so a later edit cannot quietly move the disposable
        # roster into this role, where it would outlive the run it belongs to.
        self.assertNotIn("homelab_ad_directory_accounts",
                         (ROLE / "tasks/main.yml").read_text()
                         .split(DURABLE_BLOCK)[0])


class TestDurableAccountPosixAllocation(DurableAccountBase):
    """One allocation rule, honoured in two places.

    `controller_principals.py` owns the rule for the disposable acceptance
    roster; this role applies the same rule to a durable roster. They must
    agree, because the Arch workstation runs SSSD with
    `ldap_id_mapping = False`: the UID a client sees is the uidNumber stored in
    the directory, and two allocations would mean the acceptance path proves
    one set of numbers while the persistent instance serves another.
    """

    def test_the_rule_constants_are_the_same_constants(self):
        from homelab.vm import controller_principals

        defaults = self.defaults()
        self.assertEqual(defaults["homelab_ad_posix_base"],
                         controller_principals._POSIX_BASE)
        self.assertEqual(defaults["homelab_ad_posix_login_shell"],
                         controller_principals._POSIX_LOGIN_SHELL)
        self.assertEqual(defaults["homelab_ad_posix_primary_group"],
                         controller_principals._POSIX_PRIMARY_GROUP)
        self.assertEqual(defaults["homelab_ad_posix_group_rids"],
                         controller_principals._POSIX_GROUP_RIDS)
        self.assertIn(defaults["homelab_ad_posix_admin_group"],
                      controller_principals._POSIX_GROUP_RIDS)

    @unittest.skipIf(JINJA_REASON, JINJA_REASON)
    def test_the_role_reproduces_the_allocation_it_shares(self):
        from homelab.vm import controller_principals as principals

        plan, groups = DurableAccountSimulation(self).allocate(
            ACCEPTANCE_ROSTER)
        base = principals._POSIX_BASE
        self.assertEqual(
            groups,
            {name: base + rid
             for name, rid in principals._POSIX_GROUP_RIDS.items()})
        for position, entry in enumerate(plan):
            with self.subTest(account=entry["name"]):
                self.assertEqual(entry["uidNumber"], base + position)
                self.assertEqual(
                    entry["gidNumber"],
                    base + principals._POSIX_GROUP_RIDS[
                        principals._POSIX_PRIMARY_GROUP])
                self.assertEqual(entry["loginShell"],
                                 principals._POSIX_LOGIN_SHELL)
                self.assertEqual(entry["unixHomeDirectory"],
                                 "/home/" + entry["name"])
        # And, for as long as the disposable roster is the pinned one, against
        # the snapshot that module derives for it. Guarded rather than assumed:
        # the acceptance roster is moving into the private overlay, and the rule
        # above is what must hold, not this particular snapshot of it.
        allocation = getattr(principals, "POSIX_ALLOCATION", None)
        names = {entry["name"] for entry in plan}
        if allocation and set(allocation["users"]) == names:
            self.assertEqual(groups, allocation["groups"])
            for entry in plan:
                expected = allocation["users"][entry["name"]]
                with self.subTest(snapshot=entry["name"]):
                    for attribute, value in expected.items():
                        self.assertEqual(entry[attribute], value)

    @unittest.skipIf(JINJA_REASON, JINJA_REASON)
    def test_position_and_nothing_else_decides_the_identifier(self):
        simulation = DurableAccountSimulation(self)
        plan, groups = simulation.allocate([
            {"name": "first", "role": "standard", "password_file": "/run/a"},
            {"name": "second", "role": "administrator",
             "password_file": "/run/b"},
        ])
        base = self.defaults()["homelab_ad_posix_base"]
        self.assertEqual([entry["uidNumber"] for entry in plan],
                         [base, base + 1])
        # Every user's primary gid is the Domain Users gid, from its RID.
        self.assertEqual({entry["gidNumber"] for entry in plan},
                         {base + 513})
        self.assertEqual(groups, {"Domain Users": base + 513,
                                  "Domain Admins": base + 512})
        self.assertEqual([entry["unixHomeDirectory"] for entry in plan],
                         ["/home/first", "/home/second"])

    @unittest.skipIf(JINJA_REASON, JINJA_REASON)
    def test_the_user_range_cannot_reach_the_group_range(self):
        # gids are base+512 and base+513, so a roster of 512 entries would
        # allocate a uid equal to the Domain Admins gid.
        simulation = DurableAccountSimulation(self)
        roster = [{"name": f"a{index}", "role": "standard",
                   "password_file": "/run/x"} for index in range(512)]
        self.assertFalse(simulation.roster_is_accepted(roster))
        self.assertTrue(simulation.roster_is_accepted(roster[:511]))


class TestDurableAccountRefusals(DurableAccountBase):
    """The role must refuse a roster or a credential file it cannot trust."""

    @unittest.skipIf(JINJA_REASON, JINJA_REASON)
    def test_a_declared_account_is_created_with_its_posix_identity(self):
        simulation = DurableAccountSimulation(self)
        plan, _ = simulation.allocate(
            [{"name": "standard-user", "role": "standard",
              "password_file": "/run/a"},
             {"name": "admin-user", "role": "administrator",
              "password_file": "/run/b"}],
            existing=["standard-user", "Administrator", "krbtgt"])
        # Only the account the directory does not have is created, and the one
        # that survived a relaunch keeps its password: no file is even needed
        # for it.
        self.assertEqual([entry["name"] for entry in plan if entry["create"]],
                         ["admin-user"])
        self.assertEqual([entry["role"] for entry in plan],
                         ["standard", "administrator"])
        # The administrator must land in the well-known privilege group.
        self.assertFalse(simulation.admin_membership_fails(
            plan, ["standard-user", "admin-user"]))
        self.assertTrue(simulation.admin_membership_fails(
            plan, ["standard-user"]))

    @unittest.skipIf(JINJA_REASON, JINJA_REASON)
    def test_an_unusable_roster_stops_convergence(self):
        simulation = DurableAccountSimulation(self)
        for label, roster in (
            ("a repeated name", [
                {"name": "a", "role": "standard", "password_file": "/run/a"},
                {"name": "a", "role": "administrator",
                 "password_file": "/run/b"}]),
            ("an upper-case name", [
                {"name": "Ksh", "role": "standard", "password_file": "/run/a"}]),
            ("an unknown role", [
                {"name": "a", "role": "root", "password_file": "/run/a"}]),
            ("no role at all", [{"name": "a", "password_file": "/run/a"}]),
        ):
            with self.subTest(roster=label):
                self.assertFalse(simulation.roster_is_accepted(roster))

    @unittest.skipIf(JINJA_REASON, JINJA_REASON)
    def test_a_declared_account_without_a_password_file_path_is_refused(self):
        simulation = DurableAccountSimulation(self)
        self.assertTrue(simulation.password_paths_are_accepted(
            [{"name": "a", "role": "standard", "password_file": "/run/a"}]))
        for label, roster in (
            ("an empty path", [
                {"name": "a", "role": "standard", "password_file": ""}]),
            ("no path at all", [{"name": "a", "role": "standard"}]),
        ):
            with self.subTest(roster=label):
                self.assertFalse(
                    simulation.password_paths_are_accepted(roster))

    @unittest.skipIf(JINJA_REASON, JINJA_REASON)
    def test_an_unprotected_password_file_is_refused_by_the_role(self):
        simulation = DurableAccountSimulation(self)
        protected = {"exists": True, "isreg": True, "uid": 0, "mode": "0600",
                     "size": 21}
        self.assertTrue(simulation.password_file_is_accepted(protected))
        for label, stat in (
            ("missing", dict(protected, exists=False)),
            ("group readable", dict(protected, mode="0640")),
            ("world readable", dict(protected, mode="0644")),
            ("not owned by root", dict(protected, uid=1000)),
            ("not a regular file", dict(protected, isreg=False)),
            ("empty", dict(protected, size=0)),
        ):
            with self.subTest(file=label):
                self.assertFalse(simulation.password_file_is_accepted(stat))

    @unittest.skipIf(JINJA_REASON, JINJA_REASON)
    def test_a_resolved_identity_that_is_not_the_directory_s_is_refused(self):
        simulation = DurableAccountSimulation(self)
        entry = {"name": "a", "uidNumber": 10000, "gidNumber": 10513}
        self.assertTrue(simulation.resolution_is_accepted(
            entry, "a:*:10000:10513:A Name:/home/a:/bin/bash"))
        # A display name may legally contain a colon, so the home directory is
        # counted from the end while uid and gid are counted from the start.
        self.assertTrue(simulation.resolution_is_accepted(
            entry, "a:*:10000:10513:Last, First: The Third:/home/a:/bin/bash"))
        for label, line in (
            ("a stale idmap allocation",
             "a:*:3000012:10513::/home/a:/bin/bash"),
            ("no home-directory field for the [homes] clone",
             "a:*:10000:10513:::/bin/bash"),
            ("an unresolvable primary group", "a:*:10000:0::/home/a:/bin/bash"),
        ):
            with self.subTest(resolution=label):
                self.assertFalse(simulation.resolution_is_accepted(entry, line))

    @unittest.skipIf(JINJA_REASON, JINJA_REASON)
    def test_a_storage_directory_the_owner_cannot_use_is_refused(self):
        simulation = DurableAccountSimulation(self)
        entry = {"name": "a", "uidNumber": 10000, "gidNumber": 10513}
        owned = {"exists": True, "isdir": True, "uid": 10000, "gid": 10513,
                 "mode": "0700"}
        self.assertTrue(simulation.share_is_accepted(entry, owned))
        for label, stat in (
            ("owned by root", dict(owned, uid=0, gid=0)),
            ("owned by another account", dict(owned, uid=10001)),
            ("readable by others", dict(owned, mode="0755")),
            ("missing", dict(owned, exists=False)),
        ):
            with self.subTest(directory=label):
                self.assertFalse(simulation.share_is_accepted(entry, stat))


class TestDurableAccountSecrecy(DurableAccountBase):
    """No credential may reach Git, a log, a template, or argv.

    argv is the specific trap: `samba-tool user create <name> <password>` takes
    the password positionally, so it would be readable in the process table by
    every local account and printed in Ansible's task log. Account creation
    therefore goes through the same shape first provisioning uses -- a
    root-owned 0700 driver that opens the protected file itself and hands the
    value to Samba's in-process API -- and the role passes paths only.
    """

    def test_no_command_in_the_role_can_carry_a_credential(self):
        for task, argv in self.commands():
            joined = " ".join(argv)
            with self.subTest(task=task.get("name")):
                self.assertNotRegex(
                    joined,
                    r"samba-tool\s+user\s+(?:create|add|setpassword|password)")
                self.assertNotRegex(joined, r"(?i)--newpassword")
                self.assertNotRegex(joined, r"(?i)--password[= ]")
                for element in argv:
                    if "password" in element.lower():
                        # A path or a switch name, never a value.
                        self.assertRegex(
                            element,
                            r"(password_file|password-file|password-reset"
                            r"|provision-accounts)")

    def test_the_tasks_that_touch_a_credential_file_do_not_log(self):
        # stat returns a checksum of the file it inspected, which for a
        # one-line password file is a hash of the password itself.
        for name in (
            "Inspect the password file of every durable account to be created",
            "Require a protected password file for every new durable account",
            "Create and converge the durable directory accounts",
        ):
            with self.subTest(task=name):
                self.assertIs(self.named(name).get("no_log"), True)
        inspect = self.named(
            "Inspect the password file of every durable account to be created")
        self.assertIs(inspect["ansible.builtin.stat"]["get_checksum"], False)

    def test_the_driver_is_installed_privately_and_always_removed(self):
        feeder = next(
            task for task in self.block()["block"]
            if task.get("name")
            == "Converge the durable accounts with an ephemeral credential feeder")
        self.assertIn("block", feeder)
        self.assertIn("always", feeder)
        install = next(task for task in feeder["block"]
                       if task.get("name") == "Install the durable account driver")
        options = install["ansible.builtin.copy"]
        self.assertEqual(options["src"], "provision-accounts.py")
        self.assertEqual(options["owner"], "root")
        self.assertEqual(options["mode"], "0700")
        self.assertIn("state': 'absent", str(feeder["always"]))

    def test_the_driver_receives_paths_and_not_values(self):
        argv = self.driver()["ansible.builtin.command"]["argv"]
        self.assertIn("--plan-json", argv)
        self.assertIn("--groups-json", argv)
        joined = " ".join(argv)
        self.assertIn("homelab_ad_account_plan | to_json", joined)
        # The plan carries password-file paths; the driver opens them itself.
        self.assertNotIn("lookup(", joined)
        self.assertNotIn("slurp", joined)

    def test_the_driver_never_prints_or_stores_a_credential(self):
        driver = (ROLE / "files/provision-accounts.py").read_text()
        self.assertIn("from samba.samdb import SamDB", driver)
        self.assertIn("status.replace(value, \"[REDACTED]\")", driver)
        self.assertIn("status[-16384:]", driver)
        self.assertIn("os.O_NOFOLLOW", driver)
        self.assertIn("0o600", driver)
        self.assertNotIn("subprocess", driver)
        self.assertNotIn("samba-tool", driver)
        self.assertNotRegex(driver, r"print\([^)]*credential")
        self.assertNotRegex(driver, r"(?:print|write)\s*\(\s*value\s*\)")

    def test_a_durable_account_is_never_deleted_or_rolled_back(self):
        # controller_principals.py rolls back what it created because that
        # Controller is disposable. Deleting a durable account would destroy
        # its SID and silently invalidate every ACL that references it, so a
        # failure here is reported and left for the next run to converge.
        driver = (ROLE / "files/provision-accounts.py").read_text()
        self.assertNotIn("deleteuser", driver)
        self.assertNotIn("delete_group", driver)
        self.assertIn("FLAG_MOD_REPLACE", driver)


@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
class TestDurableAccountDriver(unittest.TestCase):
    """The driver's refusals, exercised by running it.

    Everything below happens before Samba is imported, which is what makes it
    testable on a host with no directory: a plan whose identifiers could
    collide, or a credential file any account other than root could have
    written, must be refused without touching the directory at all.
    """

    DRIVER = ROLE / "files/provision-accounts.py"
    GROUPS = '{"Domain Users": 10513, "Domain Admins": 10512}'

    def entry(self, **overrides):
        base = {"name": "a", "role": "standard", "create": True,
                "uidNumber": 10000, "gidNumber": 10513,
                "loginShell": "/bin/bash", "unixHomeDirectory": "/home/a"}
        base.update(overrides)
        return base

    def run_driver(self, plan, *, groups=None, allow_reset=False,
                   directory=None):
        import json

        with tempfile.TemporaryDirectory() as scratch:
            diagnostic = Path(directory or scratch) / "status"
            result = subprocess.run(
                [sys.executable, str(self.DRIVER),
                 "--plan-json", json.dumps(plan),
                 "--groups-json", groups or self.GROUPS,
                 "--primary-group", "Domain Users",
                 "--admin-group", "Domain Admins",
                 "--posix-base", "10000",
                 "--diagnostic-file", str(diagnostic),
                 "--allow-password-reset" if allow_reset
                 else "--refuse-password-reset"],
                capture_output=True, text=True,
            )
            recorded = diagnostic.read_text() if diagnostic.exists() else ""
            mode = (oct(diagnostic.stat().st_mode & 0o777)
                    if diagnostic.exists() else "")
        return result, recorded, mode

    def staged(self, directory, *, mode=0o600, content="Sup3r-Secret!\n"):
        path = Path(directory) / "credential"
        path.write_text(content)
        path.chmod(mode)
        return path

    def test_it_refuses_a_password_file_it_cannot_trust(self):
        with tempfile.TemporaryDirectory() as scratch:
            protected = self.staged(scratch)
            loose = Path(scratch) / "loose"
            loose.write_text("x\n")
            loose.chmod(0o640)
            folder = Path(scratch) / "folder"
            folder.mkdir()
            cases = {
                "missing or unreadable": str(Path(scratch) / "absent"),
                "not mode 0600": str(loose),
                "not a regular file": str(folder),
                # This process is not root, so a correctly staged file still
                # fails the ownership check -- which is the check itself.
                "not owned by root": str(protected),
            }
            for expected, path in cases.items():
                with self.subTest(refusal=expected):
                    result, recorded, mode = self.run_driver(
                        [self.entry(password_file=path)], directory=scratch)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn(expected, recorded)
                    self.assertIn(expected, result.stdout)
                    self.assertEqual("0o600", mode)
                    self.assertNotIn("Sup3r-Secret", recorded)
                    self.assertNotIn("Sup3r-Secret", result.stdout)
                    self.assertNotIn("Sup3r-Secret", result.stderr)

    def test_it_refuses_an_allocation_that_could_collide(self):
        cases = {
            "uidNumber allocation collides": [
                self.entry(name="a", create=False),
                self.entry(name="b", create=False,
                           unixHomeDirectory="/home/b")],
            "uidNumber is out of range": [
                self.entry(create=False, uidNumber=1000)],
            "identifier ranges collide": [
                self.entry(create=False, uidNumber=10512)],
            "primary group is not an allocated group": [
                self.entry(create=False, gidNumber=10999)],
            "name is invalid": [self.entry(create=False, name="Ksh")],
            "role is invalid": [self.entry(create=False, role="root")],
            "unixHomeDirectory is invalid": [
                self.entry(create=False, unixHomeDirectory="home/a")],
            "plan is empty": [],
        }
        for expected, plan in cases.items():
            with self.subTest(refusal=expected):
                result, recorded, _ = self.run_driver(plan)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(expected, recorded)

    def test_it_refuses_a_group_plan_missing_a_well_known_group(self):
        result, recorded, _ = self.run_driver(
            [self.entry(create=False)], groups='{"Domain Users": 10513}')
        self.assertNotEqual(0, result.returncode)
        self.assertIn("missing a group", recorded)

    def test_it_refuses_to_rotate_a_password_without_the_switch(self):
        # An account that already exists keeps its password. Rewriting one
        # takes two keys: the role-level switch and the per-account flag.
        with tempfile.TemporaryDirectory() as scratch:
            path = str(self.staged(scratch))
            result, recorded, _ = self.run_driver(
                [self.entry(create=False, reset_password=True,
                            password_file=path)], directory=scratch)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("refusing to rotate the password of a", recorded)
            self.assertIn("homelab_ad_account_password_reset_enabled", recorded)
            # With the switch, the same plan gets as far as reading the file --
            # and stops on this unprivileged file's ownership, not on the
            # rotation policy.
            result, recorded, _ = self.run_driver(
                [self.entry(create=False, reset_password=True,
                            password_file=path)],
                allow_reset=True, directory=scratch)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("not owned by root", recorded)

    def test_it_needs_no_credential_for_an_account_that_already_exists(self):
        # The whole point of a persistent directory: after the first run the
        # operator deletes the files and convergence keeps working. Getting past
        # the credential stage into Samba is as far as this host can go, so the
        # claim is that the refusal is not about a credential file.
        result, recorded, _ = self.run_driver(
            [self.entry(create=False, password_file="")])
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn("password file", recorded)
        self.assertNotIn("password-file", recorded)
        self.assertTrue(recorded.startswith("error="), recorded)

    def test_it_requires_an_explicit_rotation_switch(self):
        import json

        result = subprocess.run(
            [sys.executable, str(self.DRIVER),
             "--plan-json", json.dumps([self.entry(create=False)]),
             "--groups-json", self.GROUPS,
             "--primary-group", "Domain Users",
             "--admin-group", "Domain Admins",
             "--posix-base", "10000",
             "--diagnostic-file", "/dev/null"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("one of the arguments", result.stderr)


class DurableAccountSimulation:
    """Evaluate the role's own expressions, reproducing Ansible's loops."""

    def __init__(self, case):
        self.case = case
        self.environment = jinja()
        self.defaults = case.defaults()

    def render(self, expression, variables):
        source = (expression if "{{" in expression
                  else "{{ " + expression + " }}")
        return self.environment.from_string(source).render(**variables)

    def holds(self, name, variables):
        conditions = self.case.named(name)["ansible.builtin.assert"]["that"]
        return all(self.render(condition, variables) is True
                   for condition in conditions)

    def variables(self, roster, existing=()):
        variables = dict(self.defaults)
        variables["homelab_ad_directory_accounts"] = roster
        variables["homelab_ad_existing_users"] = {
            "stdout_lines": list(existing)}
        return variables

    def roster_is_accepted(self, roster):
        return self.holds("Validate the declared durable account roster",
                          self.variables(roster))

    def password_paths_are_accepted(self, roster):
        return self.holds(
            "Require a password-file path for every declared durable account",
            self.variables(roster))

    def password_file_is_accepted(self, stat):
        return self.holds(
            "Require a protected password file for every new durable account",
            dict(self.defaults, item={"stat": stat}))

    def resolution_is_accepted(self, entry, line):
        return self.holds(
            "Require the resolved identity to be the directory's own POSIX one",
            dict(self.defaults,
                 item={"item": entry, "stdout_lines": [line]}))

    def share_is_accepted(self, entry, stat):
        return self.holds(
            "Require each per-user storage directory to be owned and private",
            dict(self.defaults, item={"item": entry, "stat": stat}))

    def admin_membership_fails(self, plan, members):
        task = self.case.named(
            "Verify every durable administrator is a Domain Admins member")
        return bool(self.render(task["failed_when"], dict(
            self.defaults,
            homelab_ad_account_plan=plan,
            homelab_ad_admin_members={"rc": 0, "stdout_lines": members})))

    def allocate(self, roster, existing=()):
        """Run the two set_fact loops the way Ansible would."""
        variables = self.variables(roster, existing)
        reset = self.case.named(
            "Start the durable POSIX allocation from an empty plan")
        for key, value in reset["ansible.builtin.set_fact"].items():
            variables[key] = value
        for name in (
            "Derive the durable POSIX group allocation from the well-known RIDs",
            "Derive the durable POSIX allocation from the declared roster order",
        ):
            task = self.case.named(name)
            index_var = task.get("loop_control", {}).get("index_var")
            for position, item in enumerate(
                    self.render(task["loop"], variables)):
                local = dict(variables, item=item)
                if index_var:
                    local[index_var] = position
                for key, expression in task[
                        "ansible.builtin.set_fact"].items():
                    variables[key] = self.render(expression, local)
        return (variables["homelab_ad_account_plan"],
                variables["homelab_ad_account_group_plan"])


if __name__ == "__main__":
    unittest.main()
