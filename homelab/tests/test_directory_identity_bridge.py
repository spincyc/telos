"""One declaration of the permanent identity, and no way for two to disagree.

ADR 0065 freezes the DNS domain, its Kerberos realm, the NetBIOS name and the
two Controller FQDNs before the first domain is provisioned, and records the
realm and NetBIOS name as effectively permanent.  ``directory.json`` is that
declaration and ``homelab/vm/directory_identity.py`` is its one loader.

The host-side Ansible path used to declare the same permanent values a second
and a third time, in YAML -- ``homelab_ad_{dns_domain,realm,netbios_domain}``
for the domain controller and ``homelab_identity_{domain,realm,netbios_domain}``
for every client -- with nothing checking that any of them agreed.  In physical
UAT that stops being theoretical: a real Controller converged under one realm
while the workstations render another into their ``sssd.conf`` fails at the
first login, after the expensive part, and the recovery is a directory
migration rather than a re-run.

So three families of test live here, and all three matter:

  * the derivation happens, from the one document, for BOTH roles;
  * every refusal fires, in both directions -- a document that disagrees with a
    variable is refused by name, and an ABSENT document invents nothing;
  * the disposable acceptance path is untouched.  Gates 3 through 12 converge a
    throwaway Controller under ``ad.factory.test``/``FACTORY`` from the factory
    bundle's ``factory-vars.json``, which has no document at all, and none of
    that may move because the durable path grew a single declaration.

Every fixture is written into a temporary directory and every invocation names
its document explicitly.  Nothing here reads ``homelab/instance/``: that is the
owner's real private overlay, and a suite that consulted it would pass or fail
depending on whose machine it ran on -- and would print their permanent realm
in a failure message, which is exactly what ADR 0046 exists to prevent.
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
ANSIBLE = ROOT / "ansible"
RESOLVER = ANSIBLE / "files/resolve-directory-identity.py"
BRIDGE_TASKS = ANSIBLE / "tasks/directory-identity.yml"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vm"))

import controller_factory  # noqa: E402

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the host
    yaml = None

from tests.test_domain_controller_role import JINJA_REASON, jinja  # noqa: E402

#: A complete, well-formed permanent identity.  Synthetic on purpose, and
#: deliberately unlike ``FactorySpec()``'s defaults in every field so a passing
#: assertion can never be a silent fallback to the acceptance realm.  The
#: addresses sit in the sanctioned 10.1/16 synthetic range the site leak scan
#: excuses.
DOCUMENT = {
    "schema_version": 1,
    "identity": {
        "dns_domain": "ad.example.home.arpa",
        "kerberos_realm": "AD.EXAMPLE.HOME.ARPA",
        "netbios_name": "EXAMPLEAD",
    },
    "services": {
        "bootstrap_dc_fqdn": "bootstrap-dc.ad.example.home.arpa",
        "permanent_dc_fqdn": "dc2.ad.example.home.arpa",
    },
    "network": {"address": "10.1.99.2", "prefix": 28, "gateway": "10.1.99.1"},
}

#: What the document says each YAML variable must become.
DERIVED = {
    "homelab_ad_dns_domain": "ad.example.home.arpa",
    "homelab_identity_domain": "ad.example.home.arpa",
    "homelab_ad_realm": "AD.EXAMPLE.HOME.ARPA",
    "homelab_identity_realm": "AD.EXAMPLE.HOME.ARPA",
    "homelab_ad_netbios_domain": "EXAMPLEAD",
    "homelab_identity_netbios_domain": "EXAMPLEAD",
}

#: The identity half of the factory bundle's ``factory-vars.json``: every value
#: the DISPOSABLE acceptance Controller is converged under, and the whole
#: reason an absent document may not invent a fallback.
ACCEPTANCE = {
    "homelab_ad_dns_domain": "ad.factory.test",
    "homelab_ad_realm": "AD.FACTORY.TEST",
    "homelab_ad_netbios_domain": "FACTORY",
    "homelab_ad_expected_hostname": "bootstrap-dc",
}

SOURCE = "the Ansible inventory (/nowhere/hosts.yml and its group_vars)"


def resolver_module():
    """The resolver imported as a module, WITHOUT leaving bytecode behind.

    Its tables are worth asserting on directly -- they are the statement that
    six YAML variables are three values. Importing a program that lives inside
    an Ansible role would ordinarily drop a ``__pycache__`` into the role, and
    a role tree is copied verbatim onto the medium a Controller converges from.
    """
    from importlib import util

    specification = util.spec_from_file_location(
        "resolve_directory_identity", RESOLVER)
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

    def resolve(self, declared, document, *, program=RESOLVER,
                source=SOURCE):
        # The child's import path is pinned, not inherited. Whether the staged
        # factory payload can reach the durable loader is the thing several of
        # these tests assert, and a developer with PYTHONPATH pointed at the
        # repository would otherwise make it reachable from anywhere -- turning
        # a real property into an accident of whoever ran the suite.
        environment = {key: value for key, value in os.environ.items()
                       if key != "PYTHONPATH"}
        result = subprocess.run(
            [sys.executable, str(program),
             "--declared-json", json.dumps(declared),
             "--document", str(document),
             "--declared-source", source],
            capture_output=True, text=True, env=environment)
        resolved = (json.loads(result.stdout) if result.returncode == 0
                    else None)
        return result, resolved

    def accept(self, declared, document, **kwargs):
        result, resolved = self.resolve(declared, document, **kwargs)
        self.assertEqual(0, result.returncode, result.stderr)
        return resolved

    def refuse(self, declared, document, **kwargs):
        result, _ = self.resolve(declared, document, **kwargs)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertEqual("", result.stdout,
                         "a refusal must print no plan at all")
        return result.stderr

    def document(self, scratch, patch=None):
        body = json.loads(json.dumps(DOCUMENT))
        for section, values in (patch or {}).items():
            body[section].update(values)
        path = Path(scratch) / "directory.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        return path

    def absent(self, scratch):
        return Path(scratch) / "there-is-no-such-document.json"


class TestTheDocumentIsTheOneDeclaration(ResolverCase):
    """With a document present, every YAML variable derives from it."""

    def test_every_identity_variable_is_derived_from_the_one_document(self):
        with tempfile.TemporaryDirectory() as scratch:
            resolved = self.accept({}, self.document(scratch))
        self.assertEqual(resolved["dns_domain"], "ad.example.home.arpa")
        self.assertEqual(resolved["kerberos_realm"], "AD.EXAMPLE.HOME.ARPA")
        self.assertEqual(resolved["netbios_name"], "EXAMPLEAD")
        self.assertEqual(resolved["controller_fqdns"],
                         ["bootstrap-dc.ad.example.home.arpa",
                          "dc2.ad.example.home.arpa"])
        self.assertEqual(resolved["controller_hostnames"],
                         ["bootstrap-dc", "dc2"])
        self.assertTrue(resolved["document"])

    def test_the_two_roles_read_one_field_and_cannot_diverge(self):
        # The point of the whole lane. `identity_client` renders the realm into
        # every workstation's krb5.conf and sssd.conf; `domain_controller`
        # provisions the directory under it. They are now the same field of the
        # same document, resolved in the same invocation.
        module = resolver_module()
        self.assertEqual(
            module.IDENTITY_FIELDS["kerberos_realm"],
            ("homelab_ad_realm", "homelab_identity_realm"))
        self.assertEqual(
            module.IDENTITY_FIELDS["netbios_name"],
            ("homelab_ad_netbios_domain", "homelab_identity_netbios_domain"))
        self.assertEqual(
            module.IDENTITY_FIELDS["dns_domain"],
            ("homelab_ad_dns_domain", "homelab_identity_domain"))

    def test_a_variable_that_agrees_is_merely_redundant(self):
        with tempfile.TemporaryDirectory() as scratch:
            resolved = self.accept(DERIVED, self.document(scratch))
        self.assertEqual(resolved["kerberos_realm"], "AD.EXAMPLE.HOME.ARPA")

    def test_a_variable_that_disagrees_names_both_values_and_both_files(self):
        # Neither declaration is silently preferred: an owner who edited one of
        # two copies must be told which two disagree, because one of them is
        # already wrong about a domain that cannot be renamed.
        for variable, correct in DERIVED.items():
            with self.subTest(variable=variable), \
                    tempfile.TemporaryDirectory() as scratch:
                document = self.document(scratch)
                wrong = "wrong-" + correct.lower()
                message = self.refuse({variable: wrong}, document)
                self.assertIn(variable, message)
                self.assertIn(repr(wrong), message)
                self.assertIn(repr(correct), message)
                self.assertIn(str(document), message)
                self.assertIn("Ansible inventory", message)
                self.assertIn("/nowhere/hosts.yml", message)

    def test_a_machine_that_is_neither_declared_controller_is_refused(self):
        with tempfile.TemporaryDirectory() as scratch:
            document = self.document(scratch)
            message = self.refuse(
                {"homelab_ad_expected_hostname": "some-other-host"}, document)
            self.assertIn("homelab_ad_expected_hostname", message)
            self.assertIn("bootstrap-dc", message)
            self.assertIn("dc2", message)
            # Either declared Controller is accepted.
            for hostname in ("bootstrap-dc", "dc2"):
                with self.subTest(hostname=hostname):
                    self.accept(
                        {"homelab_ad_expected_hostname": hostname}, document)

    def test_a_client_pinned_to_an_undeclared_controller_is_refused(self):
        with tempfile.TemporaryDirectory() as scratch:
            document = self.document(scratch)
            message = self.refuse(
                {"homelab_identity_domain_controller":
                 "dc9.ad.example.home.arpa"}, document)
            self.assertIn("homelab_identity_domain_controller", message)
            self.assertIn("bootstrap_dc_fqdn", message)
            self.assertIn("permanent_dc_fqdn", message)
            for fqdn in DOCUMENT["services"].values():
                with self.subTest(fqdn=fqdn):
                    self.accept(
                        {"homelab_identity_domain_controller": fqdn}, document)

    def test_a_document_the_one_loader_refuses_is_refused_here_too(self):
        # The loader's rules are not restated: a realm that is not the
        # upper-case DNS domain is ADR 0065's own refusal, arriving through
        # this bridge rather than beside it.
        with tempfile.TemporaryDirectory() as scratch:
            document = self.document(
                scratch, {"identity": {"kerberos_realm": "SOMETHING.ELSE"}})
            message = self.refuse({}, document)
        self.assertIn("kerberos_realm", message)
        self.assertIn("upper-case", message)

    def test_a_document_whose_state_is_unknown_is_a_refusal(self):
        # Absent is permitted; unknown is not. A document under a directory
        # this process cannot search must never read as "there is none".
        if os.geteuid() == 0:  # pragma: no cover - depends on the host
            self.skipTest("root can search any directory")
        with tempfile.TemporaryDirectory() as scratch:
            closed = Path(scratch) / "closed"
            closed.mkdir()
            (closed / "directory.json").write_text(json.dumps(DOCUMENT))
            closed.chmod(0o000)
            try:
                message = self.refuse({}, closed / "directory.json")
            finally:
                closed.chmod(0o700)
        self.assertIn("never a fallback", message)


class TestAnAbsentDocumentInventsNothing(ResolverCase):
    """The other direction, and the one the acceptance gates depend on."""

    def test_nothing_is_derived_and_no_fallback_is_invented(self):
        with tempfile.TemporaryDirectory() as scratch:
            resolved = self.accept({}, self.absent(scratch))
        self.assertEqual("", resolved["document"])
        for key in ("dns_domain", "kerberos_realm", "netbios_name",
                    "bootstrap_dc_fqdn", "permanent_dc_fqdn"):
            with self.subTest(key=key):
                self.assertEqual("", resolved[key])
        self.assertEqual([], resolved["controller_fqdns"])

    def test_an_absent_document_never_means_the_acceptance_realm(self):
        # The failure this must never have: a permanent domain provisioned
        # under ad.factory.test, whose SID cannot be renamed afterwards.
        specification = controller_factory.FactorySpec()
        with tempfile.TemporaryDirectory() as scratch:
            result, _ = self.resolve({}, self.absent(scratch))
        self.assertNotIn(specification.realm, result.stdout)
        self.assertNotIn(specification.domain, result.stdout)
        self.assertNotIn(specification.netbios, result.stdout)

    def test_the_declared_values_pass_through_byte_identically(self):
        # The disposable acceptance Controller, exactly: its identity comes
        # from the factory bundle and there is no document anywhere.
        with tempfile.TemporaryDirectory() as scratch:
            resolved = self.accept(ACCEPTANCE, self.absent(scratch))
        self.assertEqual(resolved["dns_domain"], ACCEPTANCE["homelab_ad_dns_domain"])
        self.assertEqual(resolved["kerberos_realm"], ACCEPTANCE["homelab_ad_realm"])
        self.assertEqual(resolved["netbios_name"],
                         ACCEPTANCE["homelab_ad_netbios_domain"])
        self.assertEqual("", resolved["document"])

    def test_two_hand_set_copies_that_disagree_are_still_refused(self):
        # Two copies of a permanent realm can disagree whether or not a third
        # declaration exists, and that disagreement IS the physical-UAT
        # failure: a workstation built against one realm, a Controller
        # provisioned under another.
        for ad_variable, client_variable in (
                ("homelab_ad_realm", "homelab_identity_realm"),
                ("homelab_ad_dns_domain", "homelab_identity_domain"),
                ("homelab_ad_netbios_domain",
                 "homelab_identity_netbios_domain")):
            with self.subTest(variable=client_variable), \
                    tempfile.TemporaryDirectory() as scratch:
                message = self.refuse(
                    {ad_variable: "AAA.HOME.ARPA",
                     client_variable: "BBB.HOME.ARPA"},
                    self.absent(scratch))
                self.assertIn(ad_variable, message)
                self.assertIn(client_variable, message)
                self.assertIn("'AAA.HOME.ARPA'", message)
                self.assertIn("'BBB.HOME.ARPA'", message)

    def test_the_two_families_agreeing_is_accepted(self):
        with tempfile.TemporaryDirectory() as scratch:
            resolved = self.accept(
                {"homelab_ad_realm": "AAA.HOME.ARPA",
                 "homelab_identity_realm": "AAA.HOME.ARPA"},
                self.absent(scratch))
        self.assertEqual("AAA.HOME.ARPA", resolved["kerberos_realm"])


class TestTheStagedFactoryPayload(ResolverCase):
    """What the resolver does where a Controller actually runs it.

    The factory bundle copies ``homelab/ansible`` alone to
    ``/opt/telos-factory/ansible`` and runs the play inside the guest, so
    ``delegate_to: localhost`` is the guest.  There is no repository above the
    payload and no private overlay inside a guest: that is the no-document
    case, and it is what keeps gates 3 through 12 exactly as they were.
    """

    def staged(self, scratch):
        bundle = Path(scratch) / "opt/telos-factory"
        bundle.mkdir(parents=True)
        shutil.copytree(ANSIBLE, bundle / "ansible")
        return bundle / "ansible/files" / RESOLVER.name

    def test_a_staged_payload_has_no_document_and_invents_nothing(self):
        with tempfile.TemporaryDirectory() as scratch:
            resolved = self.accept(ACCEPTANCE, "",
                                   program=self.staged(scratch))
        self.assertEqual("", resolved["document"])
        self.assertEqual(ACCEPTANCE["homelab_ad_realm"],
                         resolved["kerberos_realm"])
        self.assertEqual(ACCEPTANCE["homelab_ad_netbios_domain"],
                         resolved["netbios_name"])

    def test_a_named_document_it_cannot_validate_is_a_refusal(self):
        # The one loader is unreachable from a staged payload by construction.
        # Being asked for a document anyway is not a case to guess at.
        with tempfile.TemporaryDirectory() as scratch:
            program = self.staged(scratch)
            document = self.document(scratch)
            message = self.refuse({}, document, program=program)
        self.assertIn("loader", message)


@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
class TestBothRolesDeriveFromTheOneDeclaration(unittest.TestCase):
    """The wiring: who runs the bridge, where, and what they adopt."""

    def load(self, relative):
        return yaml.safe_load((ANSIBLE / relative).read_text())

    def bridge_tasks(self):
        return self.load("tasks/directory-identity.yml")

    def named(self, name):
        return next(task for task in self.bridge_tasks()
                    if task.get("name") == name)

    def test_both_identity_bearing_roles_include_the_same_bridge(self):
        # ONE included file, from both roles, so there is no second invocation
        # for the two realms to disagree across. The relative path resolves to
        # homelab/ansible from either role, on a control host and in the staged
        # factory payload alike.
        included = []
        for role in ("domain_controller", "identity_client"):
            tasks = self.load(f"roles/{role}/tasks/main.yml")
            with self.subTest(role=role):
                include = next(
                    task for task in tasks
                    if "ansible.builtin.include_tasks" in task)
                self.assertIs(tasks[0], include,
                              "the identity must be resolved before the "
                              "role's own first assert reads it")
                included.append(
                    include["ansible.builtin.include_tasks"]["file"])
        self.assertEqual(included[0], included[1])
        self.assertIn("tasks/directory-identity.yml", included[0])
        self.assertTrue(BRIDGE_TASKS.is_file())

    def test_the_bridge_runs_only_on_the_ansible_control_host(self):
        # The same shape roles/domain_controller uses for the durable account
        # roster, and for the same reason: the derivation must happen where the
        # repository and the private overlay are, never in a guest.
        task = self.named(
            "Resolve the permanent directory identity on the Ansible "
            "control host")
        self.assertEqual("localhost", task["delegate_to"])
        self.assertIs(False, task["become"])
        self.assertIs(True, task["run_once"])
        self.assertIs(False, task["changed_when"])
        self.assertIs(False, task["check_mode"])
        argv = task["ansible.builtin.command"]["argv"]
        self.assertEqual("/usr/bin/python3", argv[0])
        self.assertIn(RESOLVER.name, argv[1])
        self.assertNotIn("roles/", argv[1],
                         "the resolver belongs to neither role")

    def test_the_bridge_reconciles_every_variable_the_roles_declare(self):
        # The anti-dangling check. Any identity-shaped variable either role
        # DECLARES must be one the resolver has an opinion about; a fourth
        # spelling added later fails here rather than at somebody's first
        # login. `homelab_ad_expected_hostname` and
        # `homelab_identity_domain_controller` are reconciled without being
        # derived, which is why the resolver's list is wider than the six.
        import re

        module = resolver_module()
        declared = set()
        for role in ("domain_controller", "identity_client"):
            for name in self.load(f"roles/{role}/defaults/main.yml"):
                if re.search(r"realm|netbios|domain|expected_hostname", name):
                    declared.add(name)
        self.assertEqual(declared, set(module.DECLARED_VARIABLES))

        # And every one of them is actually handed over at run time.
        task = self.named(
            "Resolve the permanent directory identity on the Ansible "
            "control host")
        argv = task["ansible.builtin.command"]["argv"]
        payload = argv[argv.index("--declared-json") + 1]
        for name in module.DECLARED_VARIABLES:
            with self.subTest(variable=name):
                self.assertIn(f"'{name}'", payload)

    def test_the_derivation_is_inert_without_a_document(self):
        task = self.named(
            "Derive every identity variable from the one permanent "
            "declaration")
        self.assertIn("homelab_directory_identity.document | length > 0",
                      str(task["when"]))
        self.assertEqual(
            set(task["ansible.builtin.set_fact"]),
            {"homelab_ad_dns_domain", "homelab_ad_realm",
             "homelab_ad_netbios_domain", "homelab_identity_domain",
             "homelab_identity_realm", "homelab_identity_netbios_domain"})

    def test_the_two_roles_adopt_the_same_field(self):
        derived = self.named(
            "Derive every identity variable from the one permanent "
            "declaration")["ansible.builtin.set_fact"]
        for ad_variable, client_variable in (
                ("homelab_ad_realm", "homelab_identity_realm"),
                ("homelab_ad_dns_domain", "homelab_identity_domain"),
                ("homelab_ad_netbios_domain",
                 "homelab_identity_netbios_domain")):
            with self.subTest(variable=client_variable):
                self.assertEqual(derived[ad_variable].strip(),
                                 derived[client_variable].strip())

    def test_the_roles_keep_no_public_default_for_a_permanent_value(self):
        for role, names in (
                ("domain_controller",
                 ("homelab_ad_dns_domain", "homelab_ad_realm",
                  "homelab_ad_netbios_domain",
                  "homelab_ad_expected_hostname")),
                ("identity_client",
                 ("homelab_identity_domain", "homelab_identity_realm",
                  "homelab_identity_netbios_domain"))):
            defaults = self.load(f"roles/{role}/defaults/main.yml")
            for name in names:
                with self.subTest(role=role, variable=name):
                    self.assertEqual("", defaults[name])


@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
@unittest.skipUnless(not JINJA_REASON, JINJA_REASON)
class TestTheControllerMustBeOneOfTheTwo(unittest.TestCase):
    """The per-host half of the tightening, judged on the shipped YAML."""

    ROLE = ANSIBLE / "roles/domain_controller"

    def setUp(self):
        self.environment = jinja()
        self.tasks = yaml.safe_load(
            (self.ROLE / "tasks/main.yml").read_text())

    def named(self, name):
        return next(task for task in self.tasks
                    if task.get("name") == name)

    def render(self, expression, variables):
        source = (expression if "{{" in expression
                  else "{{ " + expression + " }}")
        return self.environment.from_string(source).render(**variables)

    def identity(self, document="/overlay/directory.json"):
        return {
            "document": document,
            "controller_fqdns": ["bootstrap-dc.ad.example.home.arpa",
                                 "dc2.ad.example.home.arpa"],
            "controller_hostnames": ["bootstrap-dc", "dc2"],
        }

    def refusal_holds(self, fqdn, identity):
        task = self.named("Refuse a machine that is neither Controller "
                          "ADR 0065 froze")
        variables = {"ansible_fqdn": fqdn,
                     "homelab_directory_identity": identity}
        return all(self.render(condition, variables) is True
                   for condition in task["ansible.builtin.assert"]["that"])

    def refusal_runs(self, identity):
        task = self.named("Refuse a machine that is neither Controller "
                          "ADR 0065 froze")
        return self.render(
            task["when"], {"homelab_directory_identity": identity}) is True

    def test_either_declared_controller_passes(self):
        for fqdn in self.identity()["controller_fqdns"]:
            with self.subTest(fqdn=fqdn):
                self.assertTrue(self.refusal_holds(fqdn, self.identity()))

    def test_any_other_machine_is_refused_before_anything_is_installed(self):
        self.assertFalse(self.refusal_holds(
            "laptop.ad.example.home.arpa", self.identity()))
        names = [str(task.get("name", "")) for task in self.tasks]
        self.assertLess(
            names.index("Refuse a machine that is neither Controller "
                        "ADR 0065 froze"),
            names.index("Install Samba AD dependencies"))

    def test_the_refusal_does_not_run_without_a_document(self):
        # The acceptance path: no document, so the closed set of two
        # Controllers does not exist and this check is skipped entirely.
        self.assertFalse(self.refusal_runs(self.identity(document="")))
        self.assertTrue(self.refusal_runs(self.identity()))

    def test_the_short_name_is_derived_only_for_a_declared_controller(self):
        task = self.named(
            "Adopt this Controller's own short name from the one declaration")
        def runs(hostname, declared, document="/overlay/directory.json"):
            variables = {"ansible_hostname": hostname,
                         "homelab_ad_expected_hostname": declared,
                         "homelab_directory_identity":
                             self.identity(document=document)}
            return all(self.render(condition, variables) is True
                       for condition in task["when"])

        self.assertTrue(runs("dc2", ""))
        self.assertTrue(runs("bootstrap-dc", ""))
        self.assertFalse(runs("laptop", ""))
        self.assertFalse(runs("dc2", "", document=""))
        # An explicitly declared name is never quietly replaced: the resolver
        # already refused one that is neither Controller, and the assert below
        # it still requires it to be this machine's.
        self.assertFalse(runs("dc2", "bootstrap-dc"))


if __name__ == "__main__":
    unittest.main()
