"""Tests for the day-2 convergence layer (ADR 0053).

Two kinds of check live here.

The first is that the configuration bridge does not drift. `bin/homelab-render`
exists so the Controller's dnsmasq, nginx and iPXE configuration is produced by
the same generators the installer and the bootstrap host use, rather than by an
Ansible template that quietly diverges from them. If that stops being true, the
decisions those generators encode stop applying to running machines, and nothing
would notice.

The second is a set of structural invariants the playbooks must keep: that a
profile can never be converged with the wrong playbook, that convergence cannot
strand a machine behind a directory outage, and that nothing here enables the
Controller's network services directly. Those are properties recorded in ADRs;
a test is how they survive an edit made in a hurry.

The YAML-parsing tests are skipped where PyYAML is absent, because `make check`
must stay runnable on a machine that has not installed Ansible.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / "ansible"
sys.path.insert(0, str(ROOT / "lib"))

import artifacts  # noqa: E402
import dnsmasq    # noqa: E402
import netplan    # noqa: E402

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the host
    yaml = None


MANIFEST = {
    "profile": "controller",
    "hostname": "controller-a",
    "development_proof": True,
    "managed_interface": {"stable_name": "lan0",
                          "permanent_mac": "60:cf:84:77:c6:6f"},
    "network": {"entered": {"managed_ipv4_cidr": "10.0.7.0/24",
                            "controller_ipv4_address": "10.0.7.2",
                            "dhcp_pool_start": "10.0.7.100",
                            "dhcp_pool_end": "10.0.7.200"}},
}


def render(document=MANIFEST):
    result = subprocess.run(
        [str(ROOT / "bin/homelab-render"), "--manifest-json", json.dumps(document)],
        capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


class TestRenderBridge(unittest.TestCase):
    """`bin/homelab-render` must be a pass-through, not a second implementation."""

    def test_it_renders_every_configuration_the_role_installs(self):
        self.assertEqual(sorted(render()), ["dnsmasq", "ipxe", "nginx"])

    def test_the_dnsmasq_configuration_is_the_generator_s_own_output(self):
        plan = netplan.build_plan(MANIFEST["network"]["entered"])
        expected = dnsmasq.render(
            plan, interface="lan0", controller_hostname="controller-a",
            lease_time=dnsmasq.DEFAULT_LEASE_TIME,
            http_base_url="http://10.0.7.2/boot")
        self.assertEqual(render()["dnsmasq"], expected)

    def test_the_nginx_configuration_is_the_generator_s_own_output(self):
        self.assertEqual(render()["nginx"],
                         artifacts.render_nginx(listen_address="10.0.7.2"))

    def test_the_ipxe_script_is_the_generator_s_own_output(self):
        self.assertEqual(render()["ipxe"],
                         artifacts.render_ipxe(base_url="http://10.0.7.2/boot"))

    def test_the_rendered_configuration_still_passes_its_own_refusals(self):
        # The generator's refusal checks are what catch a decision violation
        # `dnsmasq --test` cannot see. Running them on what Ansible will install
        # closes the loop.
        plan = netplan.build_plan(MANIFEST["network"]["entered"])
        self.assertEqual(dnsmasq.refusals(plan, render()["dnsmasq"]), [])

    def test_a_controller_that_owns_no_network_renders_nothing(self):
        # ADR 0008: where external infrastructure already owns DHCP, this
        # Controller has no services to configure, and that is a success.
        document = dict(MANIFEST)
        document.pop("network")
        self.assertEqual(render(document), {})

    def test_the_lease_time_reaches_the_configuration(self):
        result = subprocess.run(
            [str(ROOT / "bin/homelab-render"), "--manifest-json", json.dumps(MANIFEST),
             "--lease-time", "48h"],
            capture_output=True, text=True, check=True)
        self.assertIn("255.255.255.0,48h", json.loads(result.stdout)["dnsmasq"])


@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
class TestPlaybooks(unittest.TestCase):
    def load(self, relative):
        return yaml.safe_load((ANSIBLE / relative).read_text())

    def test_every_yaml_file_parses(self):
        for path in sorted(ANSIBLE.rglob("*.yml")):
            with self.subTest(path=path.relative_to(ANSIBLE)):
                yaml.safe_load(path.read_text())

    def test_each_playbook_refuses_the_wrong_profile(self):
        # Converging a Workstation with the Controller playbook would start
        # DHCP on it, which is the one thing ADR 0008 forbids everywhere.
        for playbook, profile in (("playbooks/controller.yml", "controller"),
                                  ("playbooks/workstation.yml", "workstation")):
            with self.subTest(playbook=playbook):
                play = self.load(playbook)[0]
                asserts = [task for task in play["pre_tasks"]
                           if "ansible.builtin.assert" in task]
                self.assertTrue(asserts, f"{playbook} has no profile guard")
                conditions = " ".join(
                    " ".join(task["ansible.builtin.assert"]["that"])
                    if isinstance(task["ansible.builtin.assert"]["that"], list)
                    else task["ansible.builtin.assert"]["that"]
                    for task in asserts)
                self.assertIn(f"homelab_manifest.profile == '{profile}'", conditions)

    def test_optional_roles_are_off_unless_enabled(self):
        for playbook in ("playbooks/controller.yml", "playbooks/workstation.yml"):
            for role in self.load(playbook)[0]["roles"]:
                if isinstance(role, dict) and role["role"] in ("services",
                                                               "identity_client"):
                    with self.subTest(playbook=playbook, role=role["role"]):
                        self.assertIn("default(false)", role["when"])

    def test_the_common_role_demands_a_break_glass_key(self):
        # ADR 0055: the directory is a bootstrap dependency, so a local way back
        # in is mandatory rather than optional.
        tasks = self.load("roles/common/tasks/main.yml")
        conditions = [task["ansible.builtin.assert"]["that"] for task in tasks
                      if "ansible.builtin.assert" in task]
        self.assertTrue(any("homelab_breakglass_authorized_keys" in str(condition)
                            for condition in conditions))

    def test_the_break_glass_key_list_starts_empty(self):
        # An inherited default key would be a credential in Git.
        defaults = self.load("roles/common/defaults/main.yml")
        self.assertEqual(defaults["homelab_breakglass_authorized_keys"], [])

    def test_identity_client_refuses_to_join_without_a_way_back_in(self):
        tasks = self.load("roles/identity_client/tasks/main.yml")
        conditions = str([task.get("ansible.builtin.assert") for task in tasks])
        self.assertIn("homelab_breakglass_authorized_keys", conditions)

    def test_identity_client_does_not_automate_the_join(self):
        # Joining needs directory-administrator credentials. Automating it would
        # require storing them somewhere this playbook can read unattended.
        tasks = self.load("roles/identity_client/tasks/main.yml")
        self.assertTrue(any("ansible.builtin.fail" in task for task in tasks),
                        "the join must stop and ask for a person")
        text = (ANSIBLE / "roles/identity_client/tasks/main.yml").read_text()
        self.assertNotIn("-U ", text.replace("net ads join -U <directory-administrator>", ""))

    def test_identity_client_uses_only_official_arch_join_packages(self):
        tasks = self.load("roles/identity_client/tasks/main.yml")
        package_task = next(
            task for task in tasks
            if task.get("name") == "Install the directory client"
        )
        packages = package_task["ansible.builtin.package"]["name"]
        self.assertEqual(packages, ["sssd", "samba", "krb5", "pam"])
        self.assertNotIn("adcli", packages)
        self.assertNotIn("oddjob-mkhomedir", packages)

    def test_identity_client_tests_the_samba_join_and_uses_pam_homes(self):
        tasks = self.load("roles/identity_client/tasks/main.yml")
        commands = [
            task["ansible.builtin.command"]
            for task in tasks if "ansible.builtin.command" in task
        ]
        self.assertIn("/usr/bin/net ads testjoin", commands)
        text = (ANSIBLE / "roles/identity_client/tasks/main.yml").read_text()
        self.assertIn("pam_mkhomedir.so", text)
        samba = (
            ANSIBLE / "roles/identity_client/templates/smb.conf.j2"
        ).read_text()
        self.assertIn("security = ADS", samba)
        self.assertIn("homelab_identity_netbios_domain", samba)

    def test_identity_client_sets_indefinite_offline_lifetime(self):
        # ADR 0071: SSSD defines zero as no expiration.
        defaults = self.load("roles/identity_client/defaults/main.yml")
        self.assertEqual(
            defaults["homelab_identity_offline_credentials_expiration_days"], 0)
        template = (
            ANSIBLE / "roles/identity_client/templates/sssd.conf.j2"
        ).read_text()
        self.assertIn(
            "offline_credentials_expiration = "
            "{{ homelab_identity_offline_credentials_expiration_days }}",
            template,
        )

    def test_controller_network_does_not_enable_the_network_services(self):
        # ADR 0009: dnsmasq and nginx start only after first-boot activation has
        # proved this machine is the sole DHCP authority on its segment.
        # Enabling them here would route around that.
        tasks = self.load("roles/controller_network/tasks/main.yml")
        enabled = [task["ansible.builtin.systemd"]["name"] for task in tasks
                   if "ansible.builtin.systemd" in task
                   and task["ansible.builtin.systemd"].get("enabled")]
        self.assertEqual(enabled, ["homelab-first-boot.service"])

    def test_the_services_role_is_empty_by_default(self):
        # ADR 0054: disabled by default, enabled per instance. The application
        # list itself lives in the gitignored overlay (ADR 0046).
        defaults = self.load("roles/services/defaults/main.yml")
        self.assertEqual(defaults["homelab_services"], [])

    def test_the_services_role_requires_digest_pinned_images(self):
        tasks = self.load("roles/services/tasks/main.yml")
        conditions = str([task.get("ansible.builtin.assert") for task in tasks])
        self.assertIn("@sha256:", conditions)



@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
class TestDomainControllerStorage(unittest.TestCase):
    """Gate 9: the converged Controller serves the optional per-user UNAS share.

    A live gate-8 Arch identity run proves three storage checks against this
    service: arch-storage-attached (the operator's own share mounts),
    arch-storage-denied (a foreign user's share is refused), and
    arch-storage-absent-login (login stays bounded once the target is gone).
    The first two can only pass if the Controller actually exports a
    per-user [homes]-style share, maps directory rfc2307 identifiers so the
    share owner reaches their uidNumber-owned files, and publishes the `unas`
    authority name so the share is reachable by default.  These are the
    controller-side properties that make those checks provable.
    """

    ROLE = ANSIBLE / "roles/domain_controller"

    def defaults(self):
        return yaml.safe_load((self.ROLE / "defaults/main.yml").read_text())

    def tasks(self):
        return yaml.safe_load((self.ROLE / "tasks/main.yml").read_text())

    def named(self, name):
        return next(
            task for task in self.tasks() if task.get("name") == name)

    def test_per_user_homes_share_is_exported(self):
        # A [homes]-style per-user share whose valid-users is the connecting
        # service name (%S) grants only the share owner and refuses everyone
        # else, which is exactly the genuine denial arch-storage-denied needs.
        task = self.named("Export optional per-user UNAS home shares")
        block = task["ansible.builtin.blockinfile"]["block"]
        self.assertIn("[homes]", block)
        self.assertIn("path = /srv/unas/%S", block)
        self.assertIn("valid users = %S", block)
        self.assertIn("read only = no", block)
        self.assertIn("browseable = no", block)

    def test_the_share_root_directory_is_created(self):
        task = self.named("Create the optional per-user UNAS share root")
        options = task["ansible.builtin.file"]
        self.assertEqual(options["path"], "/srv/unas")
        self.assertEqual(options["state"], "directory")

    def test_rfc2307_idmap_lets_the_share_owner_read_their_files(self):
        # Without smbd mapping SIDs through directory rfc2307 attributes, the
        # uidNumber-owned share directories staged by controller_principals
        # would be unreadable by their owners and arch-storage-attached would
        # fail even with the share exported and reachable.
        task = self.named(
            "Map directory rfc2307 identifiers into DC file access")
        line = task["ansible.builtin.lineinfile"]["line"]
        self.assertIn("idmap_ldb:use rfc2307 = yes", line)
        self.assertEqual(task["when"], "homelab_ad_enable_rfc2307 | bool")
        self.assertTrue(self.defaults()["homelab_ad_enable_rfc2307"])

    def test_provisioning_enables_rfc2307_in_the_directory_schema(self):
        # The smb.conf idmap line only resolves if the directory schema
        # actually stores the NIS attributes, which the provision run enables.
        text = (self.ROLE / "tasks/main.yml").read_text()
        self.assertIn("'--use-rfc2307' if homelab_ad_enable_rfc2307", text)

    def test_the_unas_name_is_published_when_an_address_is_set(self):
        task = self.named("Publish the storage authority name in domain DNS")
        argv = task["ansible.builtin.command"]["argv"]
        self.assertEqual(
            argv[:5],
            ["/usr/bin/samba-tool", "dns", "add", "127.0.0.1",
             "{{ homelab_ad_dns_domain }}"])
        self.assertIn("{{ homelab_storage_host_label }}", argv)
        self.assertIn("A", argv)
        self.assertIn("{{ homelab_storage_address }}", argv)
        self.assertEqual(task["when"], "homelab_storage_address | length > 0")
        # A record that already exists is idempotent, not a failure.
        self.assertIn("already exists", task["failed_when"])

    def test_the_storage_label_defaults_to_unas_with_no_address(self):
        defaults = self.defaults()
        self.assertEqual(defaults["homelab_storage_host_label"], "unas")
        # The role default publishes nothing; the disposable Controller's
        # factory vars supply its own address so the share is reachable by
        # default, and the gate-8 drive repoints it to prove absence.
        self.assertEqual(defaults["homelab_storage_address"], "")

    def test_the_share_is_applied_before_the_name_is_published(self):
        # The name must resolve to a Controller already serving the share, so
        # the share config is flushed (samba restarted) before publication.
        names = [str(task.get("name", "")) for task in self.tasks()]
        export = names.index("Export optional per-user UNAS home shares")
        flush = names.index(
            "Apply share changes before publishing the storage name")
        publish = names.index(
            "Publish the storage authority name in domain DNS")
        self.assertLess(export, flush)
        self.assertLess(flush, publish)


@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
class TestInstanceTemplate(unittest.TestCase):
    """The tracked template must stay in step with what the roles read.

    The real overlay is gitignored, so nothing else would catch a variable
    being renamed in a role while the template kept offering the old name. The
    failure mode is quiet: convergence falls back to the role default -- an
    empty break-glass key list -- and stops with a message about a key the
    operator believes they supplied.
    """

    TEMPLATE = ROOT / "instance-example"

    def load(self, relative):
        return yaml.safe_load((self.TEMPLATE / relative).read_text())

    def role_defaults(self, role):
        return yaml.safe_load(
            (ANSIBLE / "roles" / role / "defaults" / "main.yml").read_text())

    def test_the_template_exists_and_parses(self):
        for path in sorted(self.TEMPLATE.rglob("*.yml")):
            with self.subTest(path=path.relative_to(self.TEMPLATE)):
                self.assertIsInstance(yaml.safe_load(path.read_text()), dict)

    def test_it_supplies_every_variable_the_common_role_leaves_empty(self):
        supplied = self.load("group_vars/all.yml")
        for name, value in self.role_defaults("common").items():
            if value in ([], "", None):
                with self.subTest(variable=name):
                    self.assertIn(name, supplied)

    def test_the_controller_group_names_the_optional_role_switches(self):
        supplied = self.load("group_vars/controllers.yml")
        for switch in ("homelab_services_enabled", "homelab_identity_enabled"):
            self.assertIn(switch, supplied)
            self.assertFalse(supplied[switch], f"{switch} must default to off")

    def test_the_inventory_has_the_groups_the_playbooks_target(self):
        inventory = self.load("inventory/hosts.yml")
        groups = inventory["all"]["children"]
        self.assertIn("controllers", groups)
        self.assertIn("workstations", groups)

    def test_the_template_carries_no_key_material(self):
        # A template with a real-looking key in it is a key somebody will use.
        for path in sorted(self.TEMPLATE.rglob("*")):
            if not path.is_file():
                continue
            text = path.read_text()
            with self.subTest(path=path.relative_to(self.TEMPLATE)):
                self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", text)
                self.assertNotIn("BEGIN RSA PRIVATE KEY", text)
                # A public key body is base64; the placeholder is not.
                self.assertNotRegex(text, r"ssh-ed25519 AAAA")
                self.assertNotRegex(text, r"ssh-rsa AAAA")

    def test_the_ansible_configuration_points_at_the_overlay_it_seeds(self):
        configuration = (ANSIBLE / "ansible.cfg").read_text()
        self.assertIn("../instance/inventory/hosts.yml", configuration)
        self.assertTrue((self.TEMPLATE / "inventory/hosts.yml").exists())


class TestNoInstanceData(unittest.TestCase):
    """ADR 0046: nothing here may name a real machine."""

    def test_the_inventory_lives_in_the_gitignored_overlay(self):
        configuration = (ANSIBLE / "ansible.cfg").read_text()
        self.assertIn("../instance/inventory/hosts.yml", configuration)

    def test_no_role_or_playbook_carries_an_address_or_hostname(self):
        import re
        address = re.compile(r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\."
                             r"\d{1,3}\.\d{1,3}(?:\.\d{1,3})?\b")
        for path in sorted(ANSIBLE.rglob("*")):
            if not path.is_file():
                continue
            with self.subTest(path=path.relative_to(ANSIBLE)):
                self.assertIsNone(address.search(path.read_text()),
                                  f"{path} contains an address literal")


if __name__ == "__main__":
    unittest.main()
