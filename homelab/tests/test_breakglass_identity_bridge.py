"""One declaration of the break-glass administrator, and no way for two to disagree.

ADR 0055 and ADR 0063 make the break-glass administrator the only way into a
machine while the directory is down: a separately named LOCAL account, never
``root``, with passworded sudo and a dedicated key pair.  Its name was declared
TWICE, in two documents read by two different readers, and nothing checked that
they agreed:

  * ``homelab/instance/identity/principals.json`` -> ``local_rescue.name``,
    resolved by ``workstations/arch_second.identity_roster`` and baked onto an
    installed workstation DISK -- the ``useradd``, the sudoers rule and the
    acceptance probe;
  * ``inventory/group_vars/all.yml`` -> ``homelab_breakglass_user``, read by
    ``roles/common``, which creates the account and its
    ``/etc/sudoers.d/10-<name>`` on every CONVERGED host.

Two names that disagree means the account you can log in as is not the account
the disk was built to trust, discovered at exactly the moment you needed it.
That is the last unchecked pair the owner knew about, and the worst one to
leave, which is why three families of test live here:

  * the derivation happens, from the one roster, through the one loader;
  * every refusal fires, in both directions -- a roster that disagrees with the
    variable is refused by name, and an ABSENT roster derives nothing at all,
    because quietly substituting the tracked contract's synthetic
    ``local-rescue`` for the role's ``labadmin`` default would rename the
    break-glass account on every host that has no overlay;
  * the disposable acceptance path is untouched, twice over: it has no overlay,
    and ``playbooks/bootstrap-controller.yml`` -- the play the factory bundle
    runs inside the Controller -- carries no ``common`` role at all.

Every fixture is written into a temporary directory and every invocation names
its roster explicitly.  Nothing here reads ``homelab/instance/``: that is the
owner's real private overlay, and a suite that consulted it would pass or fail
depending on whose machine it ran on -- and would print their real account
names in a failure message, which is exactly what ADR 0046 exists to prevent.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parent
ANSIBLE = ROOT / "ansible"
RESOLVER = ANSIBLE / "files/resolve-breakglass-identity.py"
BRIDGE_TASKS = ANSIBLE / "tasks/breakglass-identity.yml"
COMMON = ANSIBLE / "roles/common"

# The repository root makes ``homelab.workstations`` importable; ``homelab``
# itself must stay AHEAD of it so that ``tests`` resolves to this suite rather
# than to the repository's own root-level ``tests`` package, which carries no
# module of that name.
sys.path.insert(0, str(REPOSITORY))
sys.path.insert(0, str(ROOT))

from homelab.workstations.arch_second import identity_roster  # noqa: E402

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the host
    yaml = None

from tests.test_domain_controller_role import JINJA_REASON, jinja  # noqa: E402

#: The synthetic break-glass name the TRACKED contract carries, and therefore
#: the name an acceptance workstation disk is built with.  Frozen here as a
#: literal so a test can prove the no-overlay path never produces it in place
#: of the role's own default.
CONTRACT_NAME = "local-rescue"

#: The role default, frozen as a literal.  With no roster this is the name
#: `roles/common` creates, exactly as it was before this bridge existed.
ROLE_DEFAULT = "labadmin"

#: A private roster that renames the break-glass administrator and nothing
#: else -- the sparse patch the template documents.  Synthetic, and unlike the
#: contract name in every character, so a passing assertion can never be a
#: silent fallback to the acceptance roster.
OVERLAY = {
    "schema_version": 1,
    "principals": {"local_rescue": {"name": "backstop"}},
}
DERIVED = "backstop"

SOURCE = "the Ansible inventory (/nowhere/hosts.yml and its group_vars)"


def resolver_module():
    """The resolver imported as a module, WITHOUT leaving bytecode behind.

    Its two constants -- which contract role the break-glass administrator is,
    and which Ansible variable names it -- are the statement that the two
    documents are about one account, and are worth asserting on directly.
    Importing a program that lives under ``ansible/`` would ordinarily drop a
    ``__pycache__`` into a tree that is copied verbatim onto the medium a
    Controller converges from.
    """
    from importlib import util

    specification = util.spec_from_file_location(
        "resolve_breakglass_identity", RESOLVER)
    module = util.module_from_spec(specification)
    remembered = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        specification.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = remembered
    return module


class ResolverCase(unittest.TestCase):
    """Run the real control-host resolver, always against our own fixture."""

    def resolve(self, declared, overlay, *, program=RESOLVER, source=SOURCE):
        # The child's import path is pinned, not inherited. Whether the staged
        # factory payload can reach the roster loader is the thing two of these
        # tests assert, and a developer with PYTHONPATH pointed at the
        # repository would otherwise make it reachable from anywhere -- turning
        # a real property into an accident of whoever ran the suite.
        environment = {key: value for key, value in os.environ.items()
                       if key != "PYTHONPATH"}
        result = subprocess.run(
            [sys.executable, str(program),
             "--declared-json", json.dumps(declared),
             "--overlay", str(overlay),
             "--declared-source", source],
            capture_output=True, text=True, env=environment)
        resolved = (json.loads(result.stdout) if result.returncode == 0
                    else None)
        return result, resolved

    def accept(self, declared, overlay, **kwargs):
        result, resolved = self.resolve(declared, overlay, **kwargs)
        self.assertEqual(0, result.returncode, result.stderr)
        return resolved

    def refuse(self, declared, overlay, **kwargs):
        result, _ = self.resolve(declared, overlay, **kwargs)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertEqual("", result.stdout,
                         "a refusal must print no name at all")
        return result.stderr

    def overlay(self, scratch, body=None):
        path = Path(scratch) / "principals.json"
        path.write_text(json.dumps(OVERLAY if body is None else body),
                        encoding="utf-8")
        return path

    def absent(self, scratch):
        return Path(scratch) / "there-is-no-such-roster.json"


class TestTheRosterIsTheOneDeclaration(ResolverCase):
    """With a roster present, the break-glass name derives from it."""

    def test_the_break_glass_name_is_derived_from_the_one_roster(self):
        with tempfile.TemporaryDirectory() as scratch:
            resolved = self.accept({}, self.overlay(scratch))
        self.assertEqual(DERIVED, resolved["breakglass_user"])
        self.assertEqual("local_rescue", resolved["contract_role"])
        self.assertTrue(resolved["roster"])

    def test_the_derived_name_is_the_name_the_disk_is_built_with(self):
        # The point of the whole lane. `arch_second.identity_roster` is what
        # bakes the useradd, the sudoers rule and the acceptance probe onto an
        # installed workstation disk; the resolver calls that same function
        # rather than re-reading the JSON, so the account this convergence
        # creates cannot be a different account.
        with tempfile.TemporaryDirectory() as scratch:
            overlay = self.overlay(scratch)
            resolved = self.accept({}, overlay)
            disk = identity_roster(overlay_path=overlay)
        self.assertEqual(disk["local_rescue"], resolved["breakglass_user"])

    def test_the_two_documents_are_about_one_account(self):
        module = resolver_module()
        self.assertEqual("local_rescue", module.CONTRACT_ROLE)
        self.assertEqual("homelab_breakglass_user", module.DECLARED_VARIABLE)
        self.assertEqual(("homelab_breakglass_user",),
                         module.DECLARED_VARIABLES)

    def test_a_variable_that_agrees_is_merely_redundant(self):
        with tempfile.TemporaryDirectory() as scratch:
            resolved = self.accept(
                {"homelab_breakglass_user": DERIVED}, self.overlay(scratch))
        self.assertEqual(DERIVED, resolved["breakglass_user"])

    def test_a_variable_that_disagrees_names_both_values_and_both_files(self):
        # Neither declaration is silently preferred: an owner who edited one of
        # two copies must be told which two disagree, because one of them is
        # already wrong about the one account that has to work when the
        # directory is down.
        with tempfile.TemporaryDirectory() as scratch:
            overlay = self.overlay(scratch)
            message = self.refuse(
                {"homelab_breakglass_user": ROLE_DEFAULT}, overlay)
        self.assertIn("homelab_breakglass_user", message)
        self.assertIn(repr(ROLE_DEFAULT), message)
        self.assertIn(repr(DERIVED), message)
        self.assertIn(str(overlay), message)
        self.assertIn("principals.local_rescue.name", message)
        self.assertIn("Ansible inventory", message)
        self.assertIn("/nowhere/hosts.yml", message)
        self.assertIn("Nothing has been changed on any host", message)

    def test_a_roster_that_renames_nobody_is_still_authoritative(self):
        # The template `make homelab-instance` seeds has an EMPTY principals
        # block, so the usual first state of a real overlay is "present and
        # mentions nothing". It still decides the name: the roster resolves to
        # the tracked contract's own local_rescue, which is exactly what the
        # installed disk gets. Treating that as "no declaration" would leave
        # the pair unchecked in the commonest state of all.
        with tempfile.TemporaryDirectory() as scratch:
            overlay = self.overlay(
                scratch, {"schema_version": 1, "principals": {}})
            resolved = self.accept({}, overlay)
            message = self.refuse(
                {"homelab_breakglass_user": ROLE_DEFAULT}, overlay)
        self.assertEqual(CONTRACT_NAME, resolved["breakglass_user"])
        self.assertIn(repr(CONTRACT_NAME), message)

    def test_a_roster_that_names_root_is_refused_on_the_control_host(self):
        # ADR 0055/0063: the break-glass administrator is a SEPARATELY named
        # account with its own sudo rule. `roles/common` refuses this at the
        # moment of use; refusing it here means no host is touched at all, and
        # the message can name the file the name actually came from.
        with tempfile.TemporaryDirectory() as scratch:
            overlay = self.overlay(
                scratch,
                {"schema_version": 1,
                 "principals": {"local_rescue": {"name": "root"}}})
            message = self.refuse({}, overlay)
        self.assertIn("root", message)
        self.assertIn(str(overlay), message)
        self.assertIn("local_rescue", message)

    def test_a_roster_the_one_loader_refuses_is_refused_here_too(self):
        # The roster's rules are not restated: an unversioned overlay is the
        # loader's own refusal, arriving through this bridge rather than beside
        # it.
        with tempfile.TemporaryDirectory() as scratch:
            overlay = self.overlay(
                scratch, {"schema_version": 2, "principals": {}})
            message = self.refuse({}, overlay)
        self.assertIn("schema_version", message)

    def test_an_unsafe_name_is_refused_by_the_one_loader(self):
        with tempfile.TemporaryDirectory() as scratch:
            overlay = self.overlay(
                scratch,
                {"schema_version": 1,
                 "principals": {"local_rescue": {"name": "Back Stop"}}})
            message = self.refuse({}, overlay)
        self.assertIn("safely representable", message)

    def test_a_roster_whose_state_is_unknown_is_a_refusal(self):
        # Absent is permitted; unknown is not. A roster under a directory this
        # process cannot search must never read as "there is none", because
        # "there is none" switches the whole derivation off.
        if os.geteuid() == 0:  # pragma: no cover - depends on the host
            self.skipTest("root can search any directory")
        with tempfile.TemporaryDirectory() as scratch:
            closed = Path(scratch) / "closed"
            closed.mkdir()
            (closed / "principals.json").write_text(json.dumps(OVERLAY))
            closed.chmod(0o000)
            try:
                message = self.refuse({}, closed / "principals.json")
            finally:
                closed.chmod(0o700)
        self.assertIn("never a fallback", message)


class TestAnAbsentRosterInventsNothing(ResolverCase):
    """The other direction, and the one every existing host depends on."""

    def test_nothing_is_derived_and_no_fallback_is_invented(self):
        with tempfile.TemporaryDirectory() as scratch:
            resolved = self.accept({}, self.absent(scratch))
        self.assertEqual("", resolved["roster"])
        self.assertEqual("", resolved["breakglass_user"])

    def test_the_declared_value_passes_through_byte_identically(self):
        with tempfile.TemporaryDirectory() as scratch:
            resolved = self.accept(
                {"homelab_breakglass_user": ROLE_DEFAULT},
                self.absent(scratch))
        self.assertEqual("", resolved["roster"])
        self.assertEqual(ROLE_DEFAULT, resolved["breakglass_user"])

    def test_an_absent_roster_never_means_the_contract_synthetic_name(self):
        # The failure this must never have: a host whose break-glass account is
        # silently renamed to `local-rescue` because the fix decided an absent
        # roster meant the tracked contract. Every host with no overlay already
        # has an account named by the role default or by its inventory, and
        # renaming it is the very outage this bridge exists to prevent.
        with tempfile.TemporaryDirectory() as scratch:
            result, _ = self.resolve(
                {"homelab_breakglass_user": ROLE_DEFAULT},
                self.absent(scratch))
        self.assertNotIn(CONTRACT_NAME, result.stdout)


class TestTheStagedFactoryPayload(ResolverCase):
    """What the resolver does where only ``homelab/ansible`` exists.

    The factory bundle copies ``homelab/ansible`` alone to
    ``/opt/telos-factory/ansible`` and runs the play inside the guest, so
    ``delegate_to: localhost`` is the guest.  There is no repository above the
    payload and no private overlay inside a guest: that is the no-roster case.
    """

    def staged(self, scratch):
        bundle = Path(scratch) / "opt/telos-factory"
        bundle.mkdir(parents=True)
        shutil.copytree(ANSIBLE, bundle / "ansible")
        return bundle / "ansible/files" / RESOLVER.name

    def test_a_staged_payload_has_no_roster_and_invents_nothing(self):
        with tempfile.TemporaryDirectory() as scratch:
            resolved = self.accept(
                {"homelab_breakglass_user": ROLE_DEFAULT}, "",
                program=self.staged(scratch))
        self.assertEqual("", resolved["roster"])
        self.assertEqual(ROLE_DEFAULT, resolved["breakglass_user"])

    def test_a_named_roster_it_cannot_resolve_is_a_refusal(self):
        # The one loader is unreachable from a staged payload by construction.
        # Being asked for a roster anyway is not a case to guess at.
        with tempfile.TemporaryDirectory() as scratch:
            program = self.staged(scratch)
            overlay = self.overlay(scratch)
            message = self.refuse({}, overlay, program=program)
        self.assertIn("loader", message)


@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
class TestTheCommonRoleDerivesFromTheOneDeclaration(unittest.TestCase):
    """The wiring: who runs the bridge, where, and what they adopt."""

    def load(self, relative):
        return yaml.safe_load((ANSIBLE / relative).read_text())

    def bridge_tasks(self):
        return self.load("tasks/breakglass-identity.yml")

    def named(self, name):
        return next(task for task in self.bridge_tasks()
                    if task.get("name") == name)

    def common_tasks(self):
        return self.load("roles/common/tasks/main.yml")

    def test_the_role_that_creates_the_account_includes_the_bridge_first(self):
        # `common` is the role that actually runs the useradd and writes
        # /etc/sudoers.d/10-<name>, it is carried by every play that converges
        # a machine, and it is carried by no other. Including the bridge as its
        # FIRST task is what makes the role's own safety assert judge the
        # DERIVED name rather than only the inventory's.
        tasks = self.common_tasks()
        include = tasks[0]
        self.assertIn("ansible.builtin.include_tasks", include)
        self.assertIn("tasks/breakglass-identity.yml",
                      include["ansible.builtin.include_tasks"]["file"])
        self.assertTrue(BRIDGE_TASKS.is_file())
        self.assertFalse((COMMON / "files").exists(),
                         "the resolver belongs to the identity scheme, not to "
                         "one role, and a new role would owe "
                         "package-contract.json a layer it does not need")

    def test_the_bridge_runs_only_on_the_ansible_control_host(self):
        # The same shape the permanent-identity bridge and the durable-account
        # resolver use, and for the same reason: the derivation must happen
        # where the repository and the private overlay are, never in a guest.
        task = self.named(
            "Resolve the break-glass administrator on the Ansible control "
            "host")
        self.assertEqual("localhost", task["delegate_to"])
        self.assertIs(False, task["become"])
        self.assertIs(True, task["run_once"])
        self.assertIs(False, task["changed_when"])
        self.assertIs(False, task["check_mode"])
        argv = task["ansible.builtin.command"]["argv"]
        self.assertEqual("/usr/bin/python3", argv[0])
        self.assertIn(RESOLVER.name, argv[1])
        self.assertNotIn("roles/", argv[1])

    def test_the_bridge_hands_over_every_variable_it_reconciles(self):
        module = resolver_module()
        task = self.named(
            "Resolve the break-glass administrator on the Ansible control "
            "host")
        argv = task["ansible.builtin.command"]["argv"]
        payload = argv[argv.index("--declared-json") + 1]
        for name in module.DECLARED_VARIABLES:
            with self.subTest(variable=name):
                self.assertIn(f"'{name}'", payload)

    def test_only_the_break_glass_name_is_derived_and_only_with_a_roster(self):
        task = self.named(
            "Derive the break-glass administrator from the one roster "
            "declaration")
        self.assertEqual({"homelab_breakglass_user"},
                         set(task["ansible.builtin.set_fact"]))
        self.assertIn("homelab_breakglass_identity.roster | length > 0",
                      str(task["when"]))

    def test_the_existing_safety_assert_survives_unchanged(self):
        # ADR 0055 and the useradd/sudoers interpolation gate are not relaxed
        # because the name now has a provenance: a roster is still a
        # hand-edited file, and the name still lands in a filename, a sudoers
        # rule and a shell word.
        tasks = self.common_tasks()
        guard = next(task for task in tasks
                     if task.get("name", "").startswith(
                         "Refuse a break-glass administrator name"))
        conditions = guard["ansible.builtin.assert"]["that"]
        self.assertIn("homelab_breakglass_user is string", conditions)
        self.assertIn(
            "homelab_breakglass_user is match('^[a-z_][a-z0-9_-]{0,31}$')",
            conditions)
        self.assertIn("homelab_breakglass_user != 'root'", conditions)
        names = [str(task.get("name", "")) for task in tasks]
        self.assertLess(names.index(guard["name"]),
                        names.index("Create the break-glass administrator"))
        self.assertEqual(0, names.index(
            "Derive the break-glass administrator from its one declaration"))

    def test_the_sudo_rule_keeps_its_passworded_shape(self):
        tasks = self.common_tasks()
        rule = next(task for task in tasks
                    if task.get("name")
                    == "Grant the break-glass administrator sudo")["ansible.builtin.copy"]
        self.assertEqual(
            "{{ homelab_breakglass_user }} ALL=(ALL:ALL) ALL\n",
            rule["content"])
        self.assertNotIn("NOPASSWD", rule["content"])
        self.assertEqual("0440", rule["mode"])


@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
class TestTheAcceptancePathIsUntouched(ResolverCase):
    """Gates 3 through 12 must not move because the durable path grew a check."""

    def load(self, relative):
        return yaml.safe_load((ANSIBLE / relative).read_text())

    def test_the_factory_play_carries_no_common_role(self):
        # The first of the two reasons the acceptance path cannot move. The
        # disposable Controller is converged by this play, from the factory
        # bundle's factory-vars.json, and this play has never carried the role
        # that creates the break-glass account.
        play = self.load("playbooks/bootstrap-controller.yml")[0]
        roles = [role["role"] if isinstance(role, dict) else role
                 for role in play["roles"]]
        self.assertEqual(["domain_controller"], roles)

    def test_every_play_that_does_carry_common_is_a_host_side_play(self):
        carriers = []
        for path in sorted((ANSIBLE / "playbooks").glob("*.yml")):
            for play in yaml.safe_load(path.read_text()):
                roles = [role["role"] if isinstance(role, dict) else role
                         for role in play.get("roles", [])]
                if "common" in roles:
                    carriers.append(path.name)
        self.assertEqual(["controller.yml", "workstation.yml"], carriers)

    def test_the_role_default_is_frozen_and_is_not_the_contract_name(self):
        # The second reason. With no overlay the derivation is inert, so this
        # literal is the name `roles/common` creates -- byte-identical to what
        # it created before this bridge existed.
        defaults = self.load("roles/common/defaults/main.yml")
        self.assertEqual(ROLE_DEFAULT, defaults["homelab_breakglass_user"])
        self.assertNotEqual(CONTRACT_NAME, defaults["homelab_breakglass_user"])
        self.assertEqual([], defaults["homelab_breakglass_authorized_keys"])

    def test_the_whole_default_document_is_byte_identical_to_today(self):
        # Frozen as a literal rather than compared field by field: a variable
        # ADDED to this role's defaults would otherwise slip past every check
        # above, and every one of them lands on every managed machine.
        self.assertEqual(
            {"homelab_breakglass_user": "labadmin",
             "homelab_breakglass_authorized_keys": [],
             "homelab_timezone": "UTC"},
            self.load("roles/common/defaults/main.yml"))

    @unittest.skipIf(JINJA_REASON, JINJA_REASON)
    def test_with_no_roster_the_derivation_does_not_run(self):
        environment = jinja()
        task = next(task for task in self.load("tasks/breakglass-identity.yml")
                    if task.get("name") == "Derive the break-glass "
                    "administrator from the one roster declaration")

        def runs(roster):
            return environment.from_string(
                "{{ " + task["when"] + " }}").render(
                    homelab_breakglass_identity={"roster": roster}) is True

        self.assertFalse(runs(""))
        self.assertTrue(runs("/overlay/principals.json"))

    def test_the_resolver_leaves_an_acceptance_shaped_run_alone(self):
        # End to end, with the real program: no overlay anywhere, the role
        # default declared, and the answer is the role default and no roster.
        with tempfile.TemporaryDirectory() as scratch:
            resolved = self.accept(
                {"homelab_breakglass_user": ROLE_DEFAULT},
                self.absent(scratch))
        self.assertEqual(
            {"schema": 1, "roster": "", "source": SOURCE,
             "contract_role": "local_rescue",
             "breakglass_user": ROLE_DEFAULT},
            resolved)


@unittest.skipUnless(shutil.which("ansible-playbook"),
                     "ansible-playbook is not installed on this host")
class TestTheBridgeRunUnderRealAnsible(unittest.TestCase):
    """Run the shipped task file under ansible-core itself.

    Every other test here judges YAML, or the resolver alone.  Neither can see
    the one property the whole lane depends on: that a ``set_fact`` inside a
    file included by ``roles/common`` actually replaces the value the role's
    later tasks read.  Nothing is converged -- the play is the bridge and a
    debug, ``become: false`` throughout, and the only host is a local
    connection to this machine.
    """

    PLAY = """---
- name: Prove the bridge derives what roles/common then reads
  hosts: localhost
  connection: local
  gather_facts: false
  become: false
  vars:
    role_path: {role_path}
    homelab_identity_roster_overlay: {overlay}
{declared}
  tasks:
    - ansible.builtin.include_tasks:
        file: "{{{{ role_path }}}}/../../tasks/breakglass-identity.yml"
    - ansible.builtin.debug:
        msg: "BREAKGLASS=<<{{{{ homelab_breakglass_user }}}}>>"
"""

    def run_play(self, overlay, declared=None):
        import re

        environment = {key: value for key, value in os.environ.items()
                       if key != "PYTHONPATH"}
        with tempfile.TemporaryDirectory() as scratch:
            # An empty configuration, so whatever ansible.cfg this machine
            # carries cannot point the run at a real inventory.
            configuration = Path(scratch) / "ansible.cfg"
            configuration.write_text("[defaults]\n", encoding="utf-8")
            environment["ANSIBLE_CONFIG"] = str(configuration)
            play = Path(scratch) / "play.yml"
            play.write_text(self.PLAY.format(
                role_path=COMMON, overlay=overlay,
                declared=("" if declared is None
                          else f"    homelab_breakglass_user: {declared}")),
                encoding="utf-8")
            result = subprocess.run(
                ["ansible-playbook", "-i", "localhost,", str(play)],
                capture_output=True, text=True, cwd=scratch, env=environment)
        found = re.search(r"BREAKGLASS=<<(.*?)>>", result.stdout)
        return result, (found.group(1) if found else None)

    def roster(self, scratch, body=None):
        path = Path(scratch) / "principals.json"
        path.write_text(json.dumps(OVERLAY if body is None else body),
                        encoding="utf-8")
        return path

    def test_the_derived_name_reaches_the_role_that_creates_the_account(self):
        with tempfile.TemporaryDirectory() as scratch:
            result, name = self.run_play(self.roster(scratch))
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(DERIVED, name)

    def test_with_no_roster_the_role_reads_exactly_what_it_read_before(self):
        # The acceptance-shaped run, under real Ansible: no overlay, the role
        # default declared, and the value the role goes on to use is that
        # default, byte for byte.
        with tempfile.TemporaryDirectory() as scratch:
            result, name = self.run_play(
                Path(scratch) / "there-is-no-such-roster.json",
                declared=ROLE_DEFAULT)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(ROLE_DEFAULT, name)
        self.assertIn("No private identity roster", result.stdout)

    def test_a_disagreement_stops_the_play_before_anything_is_converged(self):
        with tempfile.TemporaryDirectory() as scratch:
            result, name = self.run_play(
                self.roster(scratch), declared=ROLE_DEFAULT)
        self.assertNotEqual(0, result.returncode)
        self.assertIsNone(name, "the play must not reach a later task")
        self.assertIn("declarations disagree", result.stdout)
        self.assertIn("homelab_breakglass_user", result.stdout)
        self.assertIn(DERIVED, result.stdout)


@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
class TestTheInstanceTemplateSaysWhatHappens(unittest.TestCase):
    """The tracked template must stop telling the owner to keep two copies."""

    TEMPLATE = ROOT / "instance-example"

    def test_the_template_comments_the_derived_variable_out(self):
        text = (self.TEMPLATE
                / "inventory/group_vars/all.yml").read_text()
        supplied = yaml.safe_load(text)
        self.assertNotIn(
            "homelab_breakglass_user", supplied,
            "the break-glass name is declared once, in "
            "identity/principals.json, and derived from there")
        self.assertIn("# homelab_breakglass_user:", text,
                      "the template must still show the shape, and say when "
                      "setting it is the right thing to do")
        self.assertIn("identity/principals.json", text)
        # The key list is not derived from anything and must stay declared.
        self.assertIn("homelab_breakglass_authorized_keys", supplied)

    def test_the_readme_no_longer_says_nothing_checks_that(self):
        text = (self.TEMPLATE / "identity/README.md").read_text()
        self.assertNotIn("Nothing checks that today", text)
        self.assertIn("homelab_breakglass_user", text)
        self.assertIn("breakglass-identity.yml", text)
        self.assertIn("roles/common", text)


if __name__ == "__main__":
    unittest.main()
