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
                          "permanent_mac": "52:54:00:10:00:01"},
    "network": {"entered": {"managed_ipv4_cidr": "10.1.31.0/24",
                            "controller_ipv4_address": "10.1.31.2",
                            "dhcp_pool_start": "10.1.31.100",
                            "dhcp_pool_end": "10.1.31.200"}},
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
            http_base_url="http://10.1.31.2/boot")
        self.assertEqual(render()["dnsmasq"], expected)

    def test_the_nginx_configuration_is_the_generator_s_own_output(self):
        self.assertEqual(render()["nginx"],
                         artifacts.render_nginx(listen_address="10.1.31.2"))

    def test_the_ipxe_script_is_the_generator_s_own_output(self):
        self.assertEqual(render()["ipxe"],
                         artifacts.render_ipxe(base_url="http://10.1.31.2/boot"))

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
        # In the [pam] section, where SSSD reads it.  It sat in [domain/...]
        # until 2026-08-14, where SSSD ignores it: the gate-8 transcript printed
        # `sssctl config-check` reporting "[rule/allowed_domain_options]:
        # Attribute 'offline_credentials_expiration' is not allowed", and the
        # shipped /usr/share/sssd/cfg_rules.ini lists the option under
        # [rule/allowed_pam_options] alone.  An ignored option states nothing.
        self.assertLess(template.index("[pam]"),
                        template.index("offline_credentials_expiration"))
        self.assertLess(template.index("offline_credentials_expiration"),
                        template.index("[domain/{{ homelab_identity_domain }}]"))
        # The option SSSD 2.13 removed outright, absent as an assignment.
        self.assertNotRegex(template, r"(?m)^config_file_version")

    def test_identity_client_can_name_the_domain_controller(self):
        # SSSD's AD provider locates a domain controller ONLY by DNS SRV lookup;
        # Samba's `net ads` also falls back to a NetBIOS broadcast.  So a join
        # that verifies proves nothing about whether SSSD can find the same
        # controller, which is exactly the gap the gate-8 run of 2026-08-14 fell
        # into -- the join succeeded and SSSD reported "AD Domain Controller: not
        # connected" for two minutes.  Naming the controller removes SRV and
        # CLDAP site discovery from the login path.
        defaults = self.load("roles/identity_client/defaults/main.yml")
        self.assertIn("homelab_identity_domain_controller", defaults)
        # Empty by default: SRV discovery is the correct mechanism for a site
        # with several controllers, and a wrong name is worse than none.
        self.assertEqual(defaults["homelab_identity_domain_controller"], "")
        template = (
            ANSIBLE / "roles/identity_client/templates/sssd.conf.j2"
        ).read_text()
        self.assertIn(
            "{% if homelab_identity_domain_controller | length > 0 %}",
            template)
        self.assertIn(
            "ad_server = {{ homelab_identity_domain_controller }}", template)
        # The client's own fully qualified name, composed the same way the
        # workstation installer composes it, because hostname(5) carries the
        # short name and sssd-ad(5) requires ad_hostname to match the hostname
        # the keytab was issued for.
        self.assertIn(
            "ad_hostname = {{ ansible_hostname }}."
            "{{ homelab_identity_domain }}", template)
        # A name, never an address: SSSD warns that an ad_server which looks
        # like an IP address breaks GSSAPI/GSS-SPNEGO, because the SASL bind
        # needs a principal to ask the KDC for.
        self.assertIn("GSS-SPNEGO", template)

    def test_identity_client_leaves_the_bind_principal_to_the_keytab(self):
        # A standing invitation to a wrong fix: on a Samba-joined machine the
        # keytab carries UPPERCASE HOST/<FQDN> entries while ad_hostname is the
        # lowercase DNS name, which reads like a case-sensitive Kerberos
        # mismatch.  It is not one.  SSSD does not bind as ad_hostname: it forks
        # ldap_child to pick a principal OUT of the keytab, and that pattern list
        # includes "%S$", which uppercases the short hostname and appends "$" --
        # so the bind principal is the machine account and no case can disagree.
        # Pinning ldap_sasl_authid to the FQDN would only make SSSD log
        # "Configured SASL auth ID not found in keytab" and then use the machine
        # account anyway, so the option stays absent WITH its reason attached.
        template = (
            ANSIBLE / "roles/identity_client/templates/sssd.conf.j2"
        ).read_text()
        self.assertNotRegex(template, r"(?m)^ldap_sasl_authid")
        self.assertIn("ldap_sasl_authid", template)
        self.assertIn("%S$", template)
        # Named so a reader can check the derivation against the installer that
        # shares it, rather than re-deriving it from the keytab.
        self.assertIn("_machine_principal", template)

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

    def test_the_storage_alias_gets_kerberos_service_principals(self):
        # A Kerberos SMB client asks the KDC for a service ticket named after
        # the UNC host it was handed, so an A record alone cannot make this
        # share mountable with sec=krb5.  The 2026-08-14 gate-8 run proved it
        # live: every //unas.<domain>/<user> mount failed with -ENOKEY
        # ("Send error in SessSetup = -126") while the share, the rfc2307
        # idmap, the A record and the client's own closure were all correct,
        # because nothing had ever registered an SPN for the alias and Samba's
        # provisioning registers only the DC's own names.
        task = self.named(
            "Register the storage authority name as a Kerberos service alias")
        argv = task["ansible.builtin.command"]["argv"]
        self.assertEqual(argv[:3], ["/usr/bin/samba-tool", "spn", "add"])
        # cifs is the class mount.cifs asks for; host is the class AD's default
        # sPNMappings expands to every other service class on the same alias.
        self.assertEqual(task["loop"], ["cifs", "host"])
        self.assertIn("{{ item }}/{{ homelab_storage_host_label }}", argv[3])
        self.assertIn("homelab_ad_dns_domain", argv[3])
        # The alias goes on this DC's own computer account, so the ticket is
        # backed by the machine key smbd already accepts with -- no second
        # account and no second keytab.
        self.assertEqual(argv[4], "{{ homelab_ad_expected_hostname }}$")
        # Gated exactly like the DNS publication: no address, no storage.
        self.assertEqual(task["when"], "homelab_storage_address | length > 0")
        # An SPN the account already holds is convergence, not a failure.
        self.assertIn("already", task["failed_when"])

    def test_the_storage_alias_spn_precedes_its_dns_publication(self):
        # The name must never resolve to a host that cannot serve Kerberos SMB
        # under it, so the alias is registered before it is published.
        names = [str(task.get("name", "")) for task in self.tasks()]
        spn = names.index(
            "Register the storage authority name as a Kerberos service alias")
        publish = names.index(
            "Publish the storage authority name in domain DNS")
        self.assertLess(spn, publish)

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
class TestDomainControllerShareNameResolution(unittest.TestCase):
    """A [homes] share only resolves for a name the DC can look up itself.

    smb.conf(5): when no explicit section matches a tree connect, "the
    requested section name is treated as a username and looked up in the local
    password file".  The domain accounts of an AD DC are not local accounts, so
    that lookup can only succeed through a directory source in nsswitch.conf.

    The gate-8 run of 2026-08-14 is the live proof.  Both reachable-storage
    checks failed with "mount error(2): No such file or directory" and
    "CIFS: VFS: cifs_mount failed w/return code = -2" AFTER the session had
    authenticated: the client held a TGT, the KDC issued cifs/unas.<domain>
    (kvno = 1), the cifs.spnego upcall helper and its request-key rule were
    present, the name resolved and SSSD was Online.  -2 is ENOENT, which on an
    authenticated CIFS session is the server answering bad network name -- the
    share `operator` did not exist as far as smbd was concerned.  Arch ships
    `passwd: files systemd`; nothing had ever given the Controller a way to see
    a domain user, and no task anywhere asked whether it could.
    """

    ROLE = ANSIBLE / "roles/domain_controller"

    def tasks(self):
        return yaml.safe_load((self.ROLE / "tasks/main.yml").read_text())

    def named(self, name):
        return next(
            task for task in self.tasks() if task.get("name") == name)

    def test_the_identity_databases_gain_a_directory_source(self):
        task = self.named(
            "Resolve directory identities in the Controller's own name service")
        options = task["ansible.builtin.lineinfile"]
        self.assertEqual(options["path"], "/etc/nsswitch.conf")
        # Both databases: smbd needs the passwd entry for the share clone and
        # the group entry for the owner's primary group.
        self.assertEqual(task["loop"], ["passwd", "group"])
        self.assertIn("{{ item }}:", options["regexp"])
        # Appended, never rewritten: /etc/passwd and nss-systemd keep answering
        # first, so a directory account can never shadow a local one, and only
        # a lookup miss reaches winbind.
        self.assertTrue(options["backrefs"])
        self.assertEqual(options["line"], r"\1 winbind")
        # Idempotent by lookahead rather than by rewriting the line.
        self.assertIn(r"(?!.*\bwinbind\b)", options["regexp"])
        # glibc reads nsswitch.conf once per process, so an smbd started before
        # this edit would keep the old database list.
        self.assertEqual(task["notify"], "restart samba ad dc")

    def test_the_nsswitch_edit_is_proven_rather_than_assumed(self):
        # backrefs makes a regexp that matches nothing a silent no-op, which is
        # exactly the shape of failure that hid for a day: convergence reports
        # ok and the fault surfaces in a guest serial log instead.
        task = self.named(
            "Require both Controller identity databases to consult the "
            "directory")
        argv = task["ansible.builtin.command"]["argv"]
        self.assertEqual(argv[:2], ["/usr/bin/grep", "-Eq"])
        self.assertIn("winbind", argv[2])
        self.assertIn("{{ item }}", argv[2])
        self.assertEqual(argv[3], "/etc/nsswitch.conf")
        self.assertEqual(task["loop"], ["passwd", "group"])
        # Fail-closed: grep exits non-zero when the source is absent.
        self.assertNotIn("failed_when", task)
        self.assertNotIn("ignore_errors", task)
        self.assertIs(task["changed_when"], False)

    def test_unqualified_names_are_what_the_share_lookup_receives(self):
        # winbindd's default name form is DOMAIN\user, so getpwnam("operator")
        # misses even with the database in place, while a client mounting
        # //unas/operator can only ever send the bare account name.  The same
        # setting makes `valid users = %S` compare bare name against bare name,
        # which is what keeps the foreign-share refusal an authorization
        # decision rather than a name mismatch that would refuse the owner too.
        task = self.named(
            "Present directory identities unqualified to the Controller")
        options = task["ansible.builtin.lineinfile"]
        self.assertEqual(options["path"], "{{ homelab_ad_smb_conf }}")
        self.assertIn("winbind use default domain = yes", options["line"])
        self.assertEqual(options["insertafter"], r"^\[global\]")
        self.assertEqual(task["notify"], "restart samba ad dc")

    def test_the_nss_change_precedes_the_restart_that_applies_it(self):
        names = [str(task.get("name", "")) for task in self.tasks()]
        flush = names.index(
            "Apply share changes before publishing the storage name")
        for name in (
            "Resolve directory identities in the Controller's own name service",
            "Present directory identities unqualified to the Controller",
        ):
            self.assertLess(names.index(name), flush)

    def test_the_share_section_is_verified_against_the_staged_path(self):
        # A blockinfile that parsed as something other than a service section,
        # or a path that no longer matches where controller_principals.py
        # creates and chowns the per-user directories, would serve somewhere the
        # share owner does not own.
        task = self.named(
            "Verify the per-user share exists as a service with the staged path")
        argv = task["ansible.builtin.command"]["argv"]
        self.assertEqual(argv[0], "/usr/bin/testparm")
        self.assertIn("--section-name=homes", argv)
        self.assertIn("--parameter-name=path", argv)
        self.assertIn("/srv/unas/%S", task["failed_when"])
        self.assertIn("rc != 0", task["failed_when"])
        self.assertIs(task["changed_when"], False)

    def test_the_domain_identity_lookup_is_verified_on_the_controller(self):
        task = self.named(
            "Verify the Controller resolves an unqualified directory identity")
        argv = task["ansible.builtin.command"]["argv"]
        self.assertEqual(argv[:3], [
            "/usr/bin/getent", "passwd",
            "{{ homelab_ad_nss_probe_principal }}"])
        # The samba restart takes the internal winbindd down with it, so a
        # single shot could fail for a reason that is not a defect.
        self.assertIn("rc == 0", task["until"])
        self.assertGreater(task["retries"], 1)
        self.assertGreater(task["delay"], 0)
        self.assertIs(task["changed_when"], False)
        self.assertNotIn("ignore_errors", task)
        # An account that exists at convergence time: the acceptance principals
        # are staged much later, over the Controller serial.
        defaults = yaml.safe_load(
            (self.ROLE / "defaults/main.yml").read_text())
        self.assertEqual(
            defaults["homelab_ad_nss_probe_principal"], "Administrator")

    def test_the_home_directory_field_the_clone_needs_is_asserted(self):
        # smbd reads pw_dir before cloning [homes] and refuses the clone when
        # that field is empty, even though the served path comes from
        # `path = /srv/unas/%S` and never from pw_dir.  A passwd entry alone is
        # therefore not proof.
        task = self.named(
            "Require a home-directory field the per-user share can clone from")
        conditions = str(task["ansible.builtin.assert"]["that"])
        self.assertIn("homelab_ad_nss_probe.stdout_lines", conditions)
        # Counted from the end: a directory display name may legally contain a
        # colon, which would shift every index before the GECOS field.
        self.assertIn("split(':')[-2] | length > 0", conditions)

    def test_resolution_is_proven_before_the_name_is_published(self):
        # The storage name must never resolve to a Controller that cannot serve
        # a share under it, which is the same rule the alias SPN already obeys.
        names = [str(task.get("name", "")) for task in self.tasks()]
        publish = names.index(
            "Publish the storage authority name in domain DNS")
        for name in (
            "Verify the per-user share exists as a service with the staged path",
            "Verify the Controller resolves an unqualified directory identity",
            "Require a home-directory field the per-user share can clone from",
        ):
            self.assertLess(names.index(name), publish)


@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
class TestDomainControllerDiscovery(unittest.TestCase):
    """A directory its clients cannot discover must fail convergence.

    The gate-8 run of 2026-08-14 got a joined Arch workstation that read the
    operator out of this directory over LDAP -- uidNumber, gidNumber, shell,
    home -- while SSSD reported "AD Domain Controller: not connected" and
    refused every login.  SSSD's AD provider locates a controller by DNS SRV
    lookup and nothing else, whereas Samba's `net ads` can fall back to a
    NetBIOS broadcast, so the join proved nothing about the SRV path.  The role
    verified `_ldap._tcp.<domain>` on loopback only, which proves the records
    exist in the zone but not that Samba's internal DNS answers them on the
    address a client actually queries.  Nothing anywhere asked that question.
    """

    ROLE = ANSIBLE / "roles/domain_controller"

    def tasks(self):
        return yaml.safe_load((self.ROLE / "tasks/main.yml").read_text())

    def named(self, name):
        return next(
            task for task in self.tasks() if task.get("name") == name)

    def test_srv_discovery_is_verified_from_the_client_facing_address(self):
        task = self.named(
            "Verify LDAP service discovery from the client-facing address")
        argv = task["ansible.builtin.command"]["argv"]
        self.assertEqual(argv[:4], [
            "/usr/bin/host", "-t", "SRV",
            "_ldap._tcp.{{ homelab_ad_dns_domain }}"])
        # Asked by name, not by address: this host's own fully qualified name
        # resolves to its client-facing address, so the query leaves loopback
        # without putting an address literal in the role (ADR 0046).
        self.assertEqual(
            argv[4],
            "{{ homelab_ad_expected_hostname }}.{{ homelab_ad_dns_domain }}")
        self.assertNotIn("127.0.0.1", argv)
        # Fail-closed: no failed_when and no ignore_errors, so NXDOMAIN,
        # SERVFAIL, REFUSED and timeout all stop convergence.  `host` exits
        # non-zero on each.
        self.assertNotIn("failed_when", task)
        self.assertNotIn("ignore_errors", task)
        self.assertIs(task["changed_when"], False)

    def test_the_loopback_srv_check_is_kept_as_well(self):
        # The two checks answer different questions and neither subsumes the
        # other: loopback says the zone holds the records, the client-facing
        # address says a client can get them.  The 2026-08-14 failure lived
        # precisely in the gap between those two statements.
        loopback = self.named("Verify LDAP service discovery")
        self.assertIn("127.0.0.1", loopback["ansible.builtin.command"]["argv"])
        names = [str(task.get("name", "")) for task in self.tasks()]
        self.assertLess(
            names.index("Verify LDAP service discovery"),
            names.index(
                "Verify LDAP service discovery from the client-facing address"))

    def test_the_dns_backend_that_serves_those_records_is_pinned(self):
        # SAMBA_INTERNAL is what makes the SRV records the DC's own responsibility
        # rather than a separate BIND instance's, so the checks above are checks
        # on this role's output.  The role asserts it rather than assuming it.
        defaults = yaml.safe_load(
            (self.ROLE / "defaults/main.yml").read_text())
        self.assertEqual(defaults["homelab_ad_dns_backend"], "SAMBA_INTERNAL")
        conditions = str([task.get("ansible.builtin.assert")
                          for task in self.tasks()])
        self.assertIn("homelab_ad_dns_backend == 'SAMBA_INTERNAL'", conditions)
        # And UDP/TCP 53 stay in the documented port set the surrounding
        # firewall role consumes; a client that cannot reach 53 cannot discover.
        self.assertIn(53, defaults["homelab_ad_udp_ports"])
        self.assertIn(53, defaults["homelab_ad_tcp_ports"])


@unittest.skipUnless(yaml, "PyYAML is not installed on this host")
class TestDurableDirectoryAccounts(unittest.TestCase):
    """A persistent instance must keep accounts that can actually log in.

    The acceptance path stages a synthetic roster over the serial console and
    destroys it with the Controller. A persistent instance keeps its directory
    across bring-ups, so the accounts have to be converged by the role -- and
    every property gate 8 proved necessary for the disposable roster is
    necessary for them too: rfc2307 POSIX attributes in the directory (SSSD
    runs with `ldap_id_mapping = False`, so an account without them cannot log
    in at all), a per-user storage directory owned by the account's own
    uidNumber, and a name this Controller can itself resolve.

    These tests protect the ordering and the coupling to the [homes] share.
    The account contract itself, its refusals and its allocation rule live in
    test_domain_controller_role.py.
    """

    ROLE = ANSIBLE / "roles/domain_controller"
    BLOCK = "Converge the declared durable directory accounts"

    def tasks(self):
        return yaml.safe_load((self.ROLE / "tasks/main.yml").read_text())

    def defaults(self):
        return yaml.safe_load((self.ROLE / "defaults/main.yml").read_text())

    def block(self):
        return next(task for task in self.tasks()
                    if task.get("name") == self.BLOCK)

    def named(self, name):
        pending = list(self.block()["block"])
        while pending:
            task = pending.pop(0)
            for section in ("block", "rescue", "always"):
                pending[0:0] = task.get(section, [])
            if task.get("name") == name:
                return task
        raise AssertionError(name)

    def order(self):
        return [str(task.get("name", "")) for task in self.tasks()]

    def test_the_durable_accounts_share_the_root_the_homes_service_serves(self):
        # If these two ever diverge, the share would serve a directory the
        # account does not own -- the same class of fault as a path that no
        # longer matches where controller_principals.py chowns its own.
        export = next(task for task in self.tasks()
                      if task.get("name")
                      == "Export optional per-user UNAS home shares")
        served = export["ansible.builtin.blockinfile"]["block"]
        root = self.defaults()["homelab_ad_account_share_root"]
        self.assertIn(f"path = {root}/%S", served)
        create = self.named(
            "Create each durable account's per-user storage directory")
        options = create["ansible.builtin.file"]
        self.assertEqual(
            options["path"],
            "{{ homelab_ad_account_share_root }}/{{ item.name }}")
        # Numeric owner and group, from the directory-stored POSIX identity:
        # the same chown controller_principals.py performs, and it must not
        # depend on the name service being warm.
        self.assertEqual(options["owner"], "{{ item.uidNumber }}")
        self.assertEqual(options["group"], "{{ item.gidNumber }}")
        self.assertEqual(options["mode"], "0700")

    def test_the_accounts_are_converged_after_the_directory_is_proven(self):
        # Everything the section depends on -- a running directory, the winbind
        # source in nsswitch.conf, the flushed restart, and the refusal of a
        # directory that is not the declared one -- happens above it.
        order = self.order()
        for earlier in (
            "Enable the Samba AD DC",
            "Resolve directory identities in the Controller's own name service",
            "Apply share changes before publishing the storage name",
            "Verify the Controller resolves an unqualified directory identity",
            "Refuse an existing directory with a different realm",
        ):
            with self.subTest(after=earlier):
                self.assertLess(order.index(earlier), order.index(self.BLOCK))

    def test_the_accounts_are_verified_in_the_directory_and_in_the_name_service(self):
        # Two different questions, and the 2026-08-14 gate-8 failure lived in
        # exactly this kind of gap: what the directory stores is what an SSSD
        # client reads over LDAP, while what this host resolves is what smbd
        # uses to clone [homes]. Neither answers the other.
        posix = self.named(
            "Verify each durable account's POSIX attributes in the directory")
        argv = posix["ansible.builtin.command"]["argv"]
        self.assertEqual(argv[:3], ["/usr/bin/samba-tool", "user", "show"])
        for attribute in ("uidNumber", "gidNumber", "loginShell",
                          "unixHomeDirectory"):
            with self.subTest(attribute=attribute):
                self.assertIn(attribute, argv[4])
                self.assertIn(f"'{attribute}: '", posix["failed_when"])
        self.assertIn("rc != 0", posix["failed_when"])
        self.assertIs(posix["changed_when"], False)
        self.assertNotIn("ignore_errors", posix)

        resolution = self.named(
            "Verify the Controller resolves every durable account by name")
        self.assertEqual(resolution["ansible.builtin.command"]["argv"][:2],
                         ["/usr/bin/getent", "passwd"])
        # The samba restart above takes the internal winbindd down with it, so
        # a single shot could fail for a reason that is not a defect.
        self.assertIn("rc == 0", resolution["until"])
        self.assertGreater(resolution["retries"], 1)
        self.assertGreater(resolution["delay"], 0)
        self.assertIs(resolution["changed_when"], False)
        self.assertNotIn("ignore_errors", resolution)

    def test_the_privilege_group_membership_is_verified_not_assumed(self):
        # ADR 0055/0063: the domain administrator is a Domain Admins member,
        # never root and never the local break-glass account. A created but
        # unprivileged administrator looks like a working account until the day
        # it is needed.
        task = self.named(
            "Verify every durable administrator is a Domain Admins member")
        argv = task["ansible.builtin.command"]["argv"]
        self.assertEqual(argv[:3],
                         ["/usr/bin/samba-tool", "group", "listmembers"])
        self.assertEqual(argv[3], "{{ homelab_ad_posix_admin_group }}")
        self.assertIn("administrator", task["failed_when"])
        self.assertIs(task["changed_when"], False)
        self.assertNotIn("ignore_errors", task)

    def test_both_well_known_groups_carry_a_posix_gid(self):
        # A user's primary gid comes from Domain Users, and the Arch identity
        # probe resolves Domain Admins by name, so both need a gidNumber before
        # any client with ldap_id_mapping = False can resolve either.
        task = self.named(
            "Verify the well-known groups carry the POSIX gid clients resolve")
        self.assertEqual(task["ansible.builtin.command"]["argv"][:3],
                         ["/usr/bin/samba-tool", "group", "show"])
        self.assertIn("gidNumber", task["failed_when"])
        self.assertEqual(set(self.defaults()["homelab_ad_posix_group_rids"]),
                         {"Domain Users", "Domain Admins"})

    def test_no_durable_account_task_can_run_without_a_declared_roster(self):
        # The disposable Controller's factory variables declare no durable
        # account, so this gate is what keeps the acceptance path -- 21 of 21
        # checks as of 2026-08-14 -- byte-for-byte unchanged.
        self.assertEqual(self.block()["when"],
                         "homelab_ad_directory_accounts | length > 0")
        self.assertEqual(self.defaults()["homelab_ad_directory_accounts"], [])


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

    def test_it_does_not_name_a_callback_that_was_removed(self):
        """`stdout_callback = yaml` resolved to community.general's copy, which
        that collection removed in 12.0.0 -- and a removed stdout callback is
        fatal, not a warning, so every host-side run aborted before its first
        task. The in-guest factory configuration already named the builtin; only
        this file did not, which is why acceptance kept passing while the
        persistent path could not start."""
        import re
        configuration = (ANSIBLE / "ansible.cfg").read_text()
        callback = re.search(r"^stdout_callback\s*=\s*(\S+)$",
                             configuration, re.MULTILINE)
        self.assertIsNotNone(callback, "no stdout_callback is declared")
        self.assertIn(callback.group(1), ("default", "ansible.builtin.default"))
        # The replacement only renders as YAML with this option set.
        self.assertRegex(configuration, r"(?m)^result_format\s*=\s*yaml$",
                         msg="result_format=yaml is what restores the YAML "
                             "output the removed callback used to give")


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
