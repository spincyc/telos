import configparser
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vm"))

import controller_factory  # noqa: E402


def _script_text():
    """The convergence payload for the default spec."""
    return controller_factory._script(controller_factory.FactorySpec())

NONCE = "a" * 64
GUEST_MAC = "52:54:00:11:11:11"

@mock.patch.object(controller_factory, "stage_dns_repair", new=lambda *_: {})
class ControllerFactoryBundleTests(unittest.TestCase):
    def test_synthetic_identity_is_fixed_and_non_private(self):
        spec = controller_factory.FactorySpec()
        self.assertEqual("ad.factory.test", spec.domain)
        self.assertEqual("FACTORY", spec.netbios)
        self.assertEqual("10.1.31.2", spec.address)
        self.assertNotIn("home.arpa", spec.domain)

    def test_convergence_publishes_reachable_unas_storage_by_default(self):
        # Gate 9: the disposable Controller is itself the optional UNAS
        # storage authority.  The convergence vars must set
        # homelab_storage_address to the Controller's own address so the
        # domain_controller role publishes `unas -> 10.1.31.2`, making the
        # per-user [homes] share reachable by default.  Left empty the role
        # skips publication and arch-storage-attached could never mount.  The
        # gate-8 drive later repoints the record to make storage absent.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, root / "factory.iso",
                authorization_nonce=NONCE)
            stage = bundle.stage(root / "stage")
            variables = json.loads((stage / "factory-vars.json").read_text())
        self.assertEqual(
            variables["homelab_storage_address"],
            controller_factory.FactorySpec().address)
        self.assertEqual("10.1.31.2", variables["homelab_storage_address"])

    def test_the_acceptance_convergence_variables_are_byte_identical(self):
        """The whole factory bundle, frozen, so a durable-path change shows here.

        Gates 3 through 12 converge the DISPOSABLE Controller from exactly this
        document and nothing else: it is written from ``FactorySpec`` and there
        is no permanent-identity declaration anywhere on the medium, in the
        guest, or reachable from the payload the guest runs Ansible against.

        That is why the host-side path may derive its identity from
        ``homelab/instance/identity/directory.json`` (ADR 0065) without
        touching acceptance, and why an ABSENT declaration may never invent a
        fallback: a fallback either moves these values, breaking every gate, or
        -- far worse -- lets a real domain be provisioned under the synthetic
        realm, whose SID cannot be renamed afterwards. Written out in full
        rather than spot-checked so that adding, removing or renaming any
        convergence variable is a deliberate edit to this list.
        """
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, root / "factory.iso",
                authorization_nonce=NONCE)
            stage = bundle.stage(root / "stage")
            variables = json.loads((stage / "factory-vars.json").read_text())
        self.assertEqual(variables, {
            "homelab_ad_admin_password_file": "/run/secrets/factory-ad-admin",
            "homelab_ad_development_clock_receipt_file":
                "/run/telos-factory-state/clock.receipt",
            "homelab_ad_directory_accounts": [],
            "homelab_ad_dns_domain": "ad.factory.test",
            "homelab_ad_expected_hostname": "bootstrap-dc",
            "homelab_ad_manage_packages": False,
            "homelab_ad_dns_repair_source":
                "/opt/telos-factory/ansible/roles/domain_controller/files/samba-dns",
            "homelab_ad_netbios_domain": "FACTORY",
            "homelab_ad_ntp_upstreams": ["198.51.100.10"],
            "homelab_ad_provision_enabled": True,
            "homelab_ad_realm": "AD.FACTORY.TEST",
            "homelab_storage_address": "10.1.31.2",
        })

    def test_the_bundle_carries_no_permanent_identity_declaration(self):
        # The acceptance medium must not gain one by accident. The staged tree
        # is homelab/ansible alone: no repository above it, so the resolver the
        # roles now run finds nothing to consult and every value stays exactly
        # as factory-vars.json declares it.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, root / "factory.iso",
                authorization_nonce=NONCE)
            stage = bundle.stage(root / "stage")
            self.assertEqual(
                [], [path for path in stage.rglob("directory.json")])
            self.assertFalse((stage / "homelab").exists())
            self.assertFalse((stage / "ansible/../vm").exists())
            self.assertTrue(
                (stage / "ansible/files"
                 / "resolve-directory-identity.py").is_file())

    def test_dedicated_tftp_service_has_no_dhcp_implementation(self):
        text = controller_factory.tftp_unit(ControllerFactoryBundleTests.spec())
        self.assertIn("/usr/bin/in.tftpd", text)
        self.assertNotIn("dnsmasq", text)
        self.assertNotIn("dhcp", text.lower())

    @staticmethod
    def spec():
        return controller_factory.FactorySpec()

    def test_bundle_contains_local_ansible_and_no_secret_in_arguments(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            secret = "Synthetic-Only-Password-47!"
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, root / "factory.iso", password=secret,
                authorization_nonce=NONCE)
            stage = bundle.stage(root / "stage")
            self.assertTrue((stage / "ansible/playbooks/bootstrap-controller.yml").is_file())
            self.assertTrue((stage / "converge-controller").is_file())
            self.assertTrue(
                (stage / "controller-auth-diagnostic.py").is_file())
            variables = (stage / "factory-vars.json").read_text()
            factory_ansible = (stage / "factory-ansible.cfg").read_text()
            self.assertIn(
                "stdout_callback = ansible.builtin.default", factory_ansible)
            self.assertIn(
                "callback_result_format = yaml", factory_ansible)
            self.assertIn('"homelab_ad_ntp_upstreams": ["198.51.100.10"]',
                          variables)
            self.assertIn(
                '"homelab_ad_development_clock_receipt_file": '
                '"/run/telos-factory-state/clock.receipt"', variables)
            self.assertIn('"homelab_ad_manage_packages": false', variables)
            self.assertEqual(0o600, (stage / "secret/ad-admin").stat().st_mode & 0o777)
            for path in stage.rglob("*"):
                if path.is_file() and path != stage / "secret/ad-admin":
                    self.assertNotIn(secret, path.read_text(errors="ignore"))
            command = bundle.guest_command(NONCE)
            self.assertNotIn(secret, command)
            self.assertIn("TELOS_FACTORY", command)
            self.assertNotIn("touch /run/telos-factory-authorized", command)
            script = (stage / "converge-controller").read_text()
            self.assertIn('/etc/homelab/manifest.json', script)
            self.assertIn("authorization nonce mismatch", script)
            self.assertIn(
                'probe.sendto(request, ("198.51.100.10", 123))', script)
            self.assertIn(
                "candidate[24:32] == request[40:48]", script)
            self.assertIn("candidate[0] >> 6 != 3", script)
            self.assertIn("(candidate[0] >> 3) & 0x7 == 4", script)
            self.assertIn("1 <= candidate[1] <= 15", script)
            self.assertIn(
                "time.clock_settime(time.CLOCK_REALTIME, measured)", script)
            self.assertLess(
                script.index("time-sync-response"),
                script.index("time-sync-clock"))
            self.assertLess(
                script.index("time-sync-clock"),
                script.index("payload-stage"))
            self.assertLess(
                script.index("payload-stage"),
                script.index("package-preflight"))
            self.assertLess(
                script.index("package-preflight"),
                script.index("TELOS FACTORY STEP ansible"))
            self.assertIn(
                'check verify-01 "samba-tool domain info 127.0.0.1"',
                script)
            self.assertIn("check verify-10 ", script)
            self.assertIn(
                "TELOS FACTORY STEP administrator-disable", script)
            self.assertIn(
                "--attributes=userAccountControl", script)
            self.assertIn(
                '[[ "$administrator_uac" =~ ^[0-9]+$ ]]', script)
            self.assertIn("(( administrator_uac & 2 ))", script)
            self.assertNotIn("accountFlags:.*D", script)
            self.assertIn(
                "for package in samba krb5 ntp python-cryptography", script)
            self.assertIn(
                'TELOS FACTORY STEP package-missing-$package', script)
            self.assertIn(
                "log level = 0 auth_json_audit:3@"
                "/run/telos-factory-auth-audit/auth.jsonl",
                script,
            )
            self.assertNotIn(
                "log file = /run/telos-factory-auth-audit", script)
            self.assertIn(
                "auth_audit_line=$'\\tlog level = 0 auth_json_audit:3@",
                script)
            self.assertIn('grep -Fxc "$auth_audit_line"', script)
            # CONTRACT CHANGED 2026-08-17. This used to require the literal
            # `! grep -Eq ... auth_json_audit` pre-check. Bash exempts a
            # `!`-prefixed pipeline from `set -e`, so that line could never
            # fail closed: on a persistent instance's second convergence it
            # passed, a second copy of the audit line was written, and the
            # verify below then failed -- after the write, leaving the durable
            # smb.conf unusable by every later run.
            self.assertNotIn(
                "! grep -Eq '^[[:space:]]*[^#;].*auth_json_audit'",
                script,
            )
            self.assertIn(
                'if [[ "$auth_audit_any" != "$auth_audit_ours" ]]; then',
                script)
            self.assertIn('grep -Fxv "$auth_audit_line"', script)
            self.assertIn(
                "testparm -s /etc/samba/smb.conf >/dev/null 2>&1", script)
            self.assertNotIn("--parameter-name='log level'", script)
            self.assertIn(
                "auth_audit_live=$(smbcontrol all debuglevel)", script)
            self.assertIn(
                "mapfile -t auth_audit_levels", script)
            self.assertIn(
                'if (token == "auth_json_audit:")', script)
            self.assertIn(
                '[[ ${#auth_audit_levels[@]} -gt 0 ]]', script)
            self.assertIn(
                'for auth_audit_level in "${auth_audit_levels[@]}"', script)
            self.assertIn("smbd -b | awk", script)
            self.assertIn(
                '$1 == "HAVE_JSON_OBJECT" && NF == 1', script)
            self.assertNotIn("auth_audit_tokens", script)
            self.assertIn(
                "test -d /run/telos-factory-auth-audit", script)
            self.assertIn(
                "test -f /run/telos-factory-auth-audit/auth.jsonl", script)
            self.assertIn(
                "stat -c '%u:%g:%a:%h'", script)
            self.assertNotIn("stat -Lc '%U:%G:%a:%F:%h'", script)
            auth_markers = (
                "auth-audit-preflight",
                "auth-audit-sink-create",
                "auth-audit-config-write",
                "auth-audit-config-verify",
                "auth-audit-restart",
                "auth-audit-sink-verify",
            )
            for marker in auth_markers:
                self.assertIn(f"TELOS FACTORY STEP {marker}", script)
            for before, after in zip(auth_markers, auth_markers[1:]):
                self.assertLess(
                    script.index(f"TELOS FACTORY STEP {before}"),
                    script.index(f"TELOS FACTORY STEP {after}"),
                )
            self.assertIn(
                "/usr/share/ipxe/x86_64/ipxe.efi", script)
            self.assertLess(
                script.index("systemctl stop ntpd.service"),
                script.index("probe.sendto"))
            self.assertLess(
                script.index("probe.sendto"),
                script.index("clock.receipt"))

    def audit_step(self):
        """The payload's auth-audit config step, retargeted at a scratch file.

        Executed rather than pattern-matched: this is the step that poisoned a
        persistent instance's durable /etc/samba/smb.conf, and the fault was
        not visible in the text -- it was in `set -e` semantics.
        """
        script = _script_text()
        start = script.index("echo 'TELOS FACTORY STEP auth-audit-config-write'")
        end = script.index("echo 'TELOS FACTORY STEP auth-audit-restart'")
        body = script[start:end].replace("/etc/samba/smb.conf", '"$CONF"')
        body = body.replace('testparm -s "$CONF" >/dev/null 2>&1', "true")
        return "set -euo pipefail\n" + body

    def run_audit_step(self, directory, content):
        conf = Path(directory) / "smb.conf"
        conf.write_text(content)
        step = Path(directory) / "audit-step.sh"
        step.write_text(self.audit_step())
        result = subprocess.run(
            ["bash", str(step)], capture_output=True, text=True,
            env=dict(os.environ, CONF=str(conf)))
        return result, conf.read_text()

    AUDIT_LINE = ("\tlog level = 0 auth_json_audit:3@"
                  "/run/telos-factory-auth-audit/auth.jsonl\n")

    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_the_audit_configuration_step_converges_instead_of_appending(self):
        # A persistent instance keeps /etc/samba/smb.conf across bring-ups and
        # no role ever templates it, so `make ... RECONVERGE=1` ran this step a
        # second time against a file that already carried the line. The old
        # pre-check was `! grep -Eq ...`, which bash exempts from errexit, so
        # it could not stop anything: the second run inserted a SECOND copy and
        # only then failed its own verify -- after the write. Every later run
        # failed identically, and the only way out was hand-editing smb.conf
        # over the console. With no --reconverge a converged instance is
        # refused outright, so there was no working way to run the play at all.
        with tempfile.TemporaryDirectory() as scratch:
            content = "[global]\n\tworkgroup = FACTORY\n"
            for run in (1, 2, 3):
                with self.subTest(run=run):
                    result, content = self.run_audit_step(scratch, content)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual(1, content.count(self.AUDIT_LINE))
                    self.assertEqual(1, content.count("auth_json_audit"))
            self.assertTrue(content.startswith("[global]\n"))
            self.assertIn("\tworkgroup = FACTORY\n", content)

    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_the_audit_configuration_step_repairs_a_poisoned_file(self):
        # The state a pre-2026-08-17 payload left behind. Converging it costs
        # nothing extra and is the difference between a persistent instance
        # that can be re-run and one that needs console surgery.
        with tempfile.TemporaryDirectory() as scratch:
            result, content = self.run_audit_step(
                scratch,
                "[global]\n" + self.AUDIT_LINE + self.AUDIT_LINE
                + "\tworkgroup = FACTORY\n")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(1, content.count(self.AUDIT_LINE))
        self.assertIn("\tworkgroup = FACTORY\n", content)

    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_the_audit_configuration_step_refuses_a_foreign_setting(self):
        # The property the vacuous pre-check was reaching for, now able to
        # fail: an auth_json_audit setting this payload did not write is
        # somebody else's decision about where authentication events go, and it
        # is refused BEFORE anything is written.
        foreign = "\tlog level = 3 auth_json_audit:5@/var/log/elsewhere\n"
        with tempfile.TemporaryDirectory() as scratch:
            result, content = self.run_audit_step(
                scratch, "[global]\n" + foreign + "\tworkgroup = FACTORY\n")
        self.assertEqual(2, result.returncode)
        self.assertIn("did not write", result.stderr)
        # Nothing was written: the file is exactly as it was found.
        self.assertEqual(
            content, "[global]\n" + foreign + "\tworkgroup = FACTORY\n")

    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_the_audit_configuration_step_refuses_a_missing_global_section(self):
        with tempfile.TemporaryDirectory() as scratch:
            result, _ = self.run_audit_step(scratch, "[homes]\n")
        self.assertNotEqual(0, result.returncode)

    def test_the_payload_declares_no_durable_directory_account(self):
        # The property that keeps this payload hermetic, stated rather than
        # inherited: the disposable Controller's roster is synthetic, per-run
        # and staged over the serial console by controller_principals.py, and
        # the role's whole durable-account section is gated on this list being
        # non-empty. Durable accounts travel the host-side path instead --
        # playbooks/bootstrap-controller.yml from a control host that has the
        # private identity overlay and an operator who can stage a credential
        # file -- so nothing here may ever put a real account name, or a
        # credential per account, onto a medium built for a disposable guest.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, root / "factory.iso",
                authorization_nonce=NONCE)
            stage = bundle.stage(root / "stage")
            variables = json.loads((stage / "factory-vars.json").read_text())
            staged = sorted(
                path.name for path in stage.rglob("*") if path.is_file())
        self.assertEqual(variables["homelab_ad_directory_accounts"], [])
        # One credential on the medium, the synthetic domain Administrator's.
        self.assertEqual(1, sum(1 for name in staged if name == "ad-admin"))

    def test_verifier_covers_ad_dns_pxe_http_and_authority_split(self):
        checks = "\n".join(controller_factory.verification_commands(
            self.spec()))
        for needle in (
            "samba-tool domain info", "samba-tool dbcheck", "_ldap._tcp",
            "telos-factory-tftp", "nginx -t", "boot.ipxe", "69", "53",
        ):
            self.assertIn(needle, checks)

    def test_bundle_refuses_symlink_output(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            target = root / "target"
            target.write_text("")
            (root / "factory.iso").symlink_to(target)
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, root / "factory.iso", password="x",
                authorization_nonce=NONCE)
            with self.assertRaises(ValueError):
                bundle.build()

    def test_stage_refuses_symlink_and_tightens_existing_directory(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            real = root / "real"
            real.mkdir()
            link = root / "stage-link"
            link.symlink_to(real, target_is_directory=True)
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, root / "factory.iso", password="synthetic",
                authorization_nonce=NONCE)
            with self.assertRaisesRegex(ValueError, "real directory"):
                bundle.stage(link)
            stage = root / "stage"
            stage.mkdir(mode=0o755)
            bundle.stage(stage)
            self.assertEqual(0o700, stage.stat().st_mode & 0o777)

    def test_iso_builder_forces_root_ownership_inside_guest(self):
        source = Path(controller_factory.__file__).read_text()
        self.assertIn('"-uid", "0"', source)
        self.assertIn('"-gid", "0"', source)

    def test_context_cleanup_removes_secret_bearing_output(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "factory.iso"
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, output, password="synthetic",
                authorization_nonce=NONCE)
            bundle.build = lambda: output.write_bytes(b"iso") or output
            with bundle:
                self.assertTrue(output.exists())
            self.assertFalse(output.exists())


class DurableNetworkIdentityTests(unittest.TestCase):
    """The Controller's address must survive a reboot without re-convergence.

    The convergence payload used to configure the interface imperatively (link
    rename, ``ip addr add``, ``ip route replace``) and only stop the two network
    managers. Nothing but the hostname and /etc/hosts was durable, so a
    persistent instance brought up a second time came back with no address while
    every console-side check still passed -- a silent, misleading failure.
    """

    def spec(self):
        return controller_factory.FactorySpec()

    def script(self):
        return controller_factory._script(self.spec())

    def test_durable_unit_is_a_networkd_network_matching_by_mac(self):
        spec = self.spec()
        unit = controller_factory.network_unit(spec, GUEST_MAC)
        self.assertTrue(
            controller_factory.NETWORK_UNIT_PATH.startswith(
                "/etc/systemd/network/"))
        self.assertTrue(
            controller_factory.NETWORK_UNIT_PATH.endswith(".network"))
        self.assertIn("[Match]", unit)
        self.assertIn(f"MACAddress={GUEST_MAC}", unit)
        self.assertIn(f"Address={spec.address}/{spec.prefix}", unit)
        self.assertIn(f"Gateway={spec.gateway}", unit)
        # Matching by MAC is what makes the rename unnecessary; a Name= match
        # would need a .link file to persist a rename nothing depends on.
        self.assertNotIn("Name=", unit)

    def test_the_durable_unit_is_a_well_formed_networkd_configuration(self):
        # No guest is available to load it, so the shape is proved offline: it
        # must parse as the INI systemd-networkd reads, and carry only the two
        # sections and the directives that systemd's own .network parser knows.
        parser = configparser.RawConfigParser()
        parser.optionxform = str
        parser.read_string(
            controller_factory.network_unit(self.spec(), GUEST_MAC))
        self.assertEqual(["Match", "Network"], parser.sections())
        self.assertEqual(["MACAddress"], parser.options("Match"))
        self.assertEqual(
            ["Address", "Gateway", "DHCP", "DHCPServer", "IPv6AcceptRA",
             "LinkLocalAddressing"],
            parser.options("Network"))

    def test_the_payload_writes_the_durable_unit_before_it_needs_the_network(self):
        script = self.script()
        self.assertIn(
            f"network_unit={controller_factory.NETWORK_UNIT_PATH}", script)
        self.assertIn(
            f"printf '{controller_factory.network_unit(self.spec())}' \"$mac\"",
            script)
        # The NTP measurement is the first step that needs the address, so the
        # durable configuration has to be applied before it.
        self.assertLess(
            script.index("network_unit="),
            script.index("TELOS FACTORY STEP time-sync"))

    def test_the_durable_unit_is_a_printf_format_safe_to_embed(self):
        # The payload embeds the unit as a single-quoted printf format and fills
        # the MAC in on the guest, because only the guest knows it. That is only
        # safe while the text carries exactly one conversion and no quote,
        # backslash or other percent.
        text = controller_factory.network_unit(self.spec())
        self.assertEqual(1, text.count("%"))
        self.assertIn("MACAddress=%s", text)
        self.assertNotIn("'", text)
        self.assertNotIn("\\", text)

    def test_exactly_one_manager_owns_the_interface(self):
        script = self.script()
        # NetworkManager is enabled on the canonical Controller image, so
        # stopping it is not enough: it must be masked or a reboot brings a
        # second manager back onto the link.
        self.assertIn(
            "systemctl mask NetworkManager.service "
            "NetworkManager-wait-online.service", script)
        self.assertIn(
            'if systemctl is-active --quiet NetworkManager.service; then',
            script)
        # Stop before mask: whether a masked unit may be stopped is
        # version-dependent, while a tolerated stop of an already-masked unit
        # plus the fail-closed check above is not.
        self.assertLess(
            script.index("systemctl stop NetworkManager.service"),
            script.index("systemctl mask NetworkManager.service"))
        self.assertLess(
            script.index("systemctl mask NetworkManager.service"),
            script.index(
                "if systemctl is-active --quiet NetworkManager.service"))
        # systemd-networkd is the one owner, and it owns the link on every
        # later boot too.
        self.assertIn("systemctl enable systemd-networkd.service", script)
        # No second manager is ever started, and no separate DHCP client is
        # introduced by the durable configuration.
        self.assertNotIn("systemctl start NetworkManager", script)
        self.assertNotIn("dhcpcd", script)
        self.assertNotIn("dhclient", script)
        # The link is only ever flushed while no manager is running.
        self.assertLess(
            script.index("systemctl stop systemd-networkd.service 2>/dev/null"),
            script.index('ip addr flush dev "$iface"'))
        self.assertLess(
            script.index('ip addr flush dev "$iface"'),
            script.index("systemctl restart systemd-networkd.service"))

    def test_no_interface_rename_survives_anywhere(self):
        # sim0 was a runtime-only name that nothing in the repository referred
        # to, so the durable configuration matches by MAC and leaves the kernel
        # name alone rather than persisting a rename with a .link file. The name
        # may still be named in a comment explaining why it is gone.
        executable = [
            line for line in self.script().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        for line in executable:
            self.assertNotIn("sim0", line)
        self.assertNotIn(".link", controller_factory.network_unit(self.spec()))
        self.assertNotIn("ip link set", self.script())

    def test_the_durable_configuration_refuses_dhcp_in_both_directions(self):
        # Gate 4 proves the simulated gateway is the sole DHCP authority and
        # that the Controller emits no DHCP. A durable configuration that
        # started a DHCP client, or answered DHCP, would break that gate.
        unit = controller_factory.network_unit(self.spec(), GUEST_MAC)
        self.assertIn("DHCP=no", unit)
        self.assertIn("DHCPServer=no", unit)
        self.assertIn("IPv6AcceptRA=no", unit)
        self.assertNotIn("DHCP=yes", unit)
        self.assertNotIn("DHCP=ipv4", unit)
        self.assertNotIn("DHCPServer=yes", unit)
        # And the payload proves it on the running system rather than trusting
        # the file: a DHCP client would hold UDP 68, a server UDP 67 or 4011.
        self.assertIn(
            "if ss -H -lun | grep -Eq ':(67|68|4011)[[:space:]]'; then",
            self.script())

    def test_the_payload_still_fails_closed_on_address_and_route(self):
        spec = self.spec()
        script = self.script()
        self.assertIn(
            f"default route via {spec.gateway} was not installed", script)
        self.assertIn(
            f"{spec.address}/{spec.prefix} was not installed on $iface",
            script)


class DurableNetworkStepExecutionTests(unittest.TestCase):
    """Run the payload's network step offline against stub tools.

    No guest is available, so the step is executed with /sys/class/net,
    /etc/systemd/network and /etc/hosts redirected into a temporary tree and
    with systemctl, ip, ss and hostnamectl replaced by recording stubs. That
    proves the shell logic itself -- what is written, what is started, and what
    a second run does -- rather than only the generated text.
    """

    STUBS = {
        "systemctl": """#!/usr/bin/bash
printf '%s\\n' "systemctl $*" >>"$TELOS_LOG"
case "$*" in
  "is-active --quiet NetworkManager.service")
    exit 1 ;;
  "is-active --quiet systemd-networkd.service")
    if [ -f "$TELOS_STATE/networkd-active" ]; then exit 0; fi
    exit 1 ;;
  "restart systemd-networkd.service")
    : >"$TELOS_STATE/networkd-active"
    : >"$TELOS_STATE/configured" ;;
  "stop systemd-networkd.service")
    rm -f "$TELOS_STATE/networkd-active" ;;
esac
exit 0
""",
        "ip": """#!/usr/bin/bash
printf '%s\\n' "ip $*" >>"$TELOS_LOG"
case "$*" in
  "addr flush dev "*)
    rm -f "$TELOS_STATE/configured" ;;
  "-4 addr show dev "*)
    if [ -f "$TELOS_STATE/configured" ]; then
      printf '    inet 10.1.31.2/28 scope global %s\\n' "${*##* }"
    fi ;;
  "-4 addr show")
    printf '1: lo: <LOOPBACK>\\n' ;;
  "route show default")
    if [ -f "$TELOS_STATE/configured" ]; then
      printf 'default via 10.1.31.1 dev enp0s2 proto static\\n'
    fi ;;
  "route show")
    printf '10.1.31.0/28 dev enp0s2 proto kernel\\n' ;;
esac
exit 0
""",
        "ss": """#!/usr/bin/bash
printf '%s\\n' "ss $*" >>"$TELOS_LOG"
if [ -n "${TELOS_FAKE_DHCP:-}" ]; then
  printf 'UNCONN 0 0 0.0.0.0:68 0.0.0.0:*\\n'
fi
exit 0
""",
        "hostnamectl": """#!/usr/bin/bash
printf '%s\\n' "hostnamectl $*" >>"$TELOS_LOG"
exit 0
""",
    }

    def build(self, root: Path, *, mac: str = GUEST_MAC):
        spec = controller_factory.FactorySpec()
        script = controller_factory._script(spec)
        start = script.index("echo 'TELOS FACTORY STEP network'")
        end = script.index("echo 'TELOS FACTORY STEP time-sync'")
        region = script[start:end]
        sysnet = root / "sys/class/net"
        (sysnet / "lo").mkdir(parents=True)
        (sysnet / "enp0s2").mkdir(parents=True)
        (sysnet / "enp0s2/address").write_text(mac + "\n")
        (sysnet / "lo/address").write_text("00:00:00:00:00:00\n")
        etcnet = root / "etc/systemd/network"
        etcnet.parent.mkdir(parents=True)
        hosts = root / "etc/hosts"
        region = region.replace("/sys/class/net", str(sysnet))
        region = region.replace("/etc/systemd/network", str(etcnet))
        region = region.replace(">/etc/hosts", f">{hosts}")
        runner = root / "network-step"
        runner.write_text("#!/usr/bin/bash\nset -euo pipefail\numask 077\n"
                          + region)
        runner.chmod(0o755)
        stubs = root / "bin"
        stubs.mkdir()
        for name, body in self.STUBS.items():
            stub = stubs / name
            stub.write_text(body)
            stub.chmod(0o755)
        state = root / "state"
        state.mkdir()
        return {
            "runner": runner,
            "unit": etcnet / Path(controller_factory.NETWORK_UNIT_PATH).name,
            "hosts": hosts,
            "log": root / "log",
            "state": state,
            "stubs": stubs,
        }

    def run_step(self, paths, **extra):
        paths["log"].write_text("")
        environment = dict(os.environ)
        environment.update({
            "PATH": f"{paths['stubs']}:{environment['PATH']}",
            "TELOS_LOG": str(paths["log"]),
            "TELOS_STATE": str(paths["state"]),
        })
        environment.update(extra)
        completed = subprocess.run(
            [shutil.which("bash"), str(paths["runner"])],
            env=environment, capture_output=True, text=True)
        return completed, paths["log"].read_text()

    def test_the_step_writes_the_durable_unit_and_hands_the_link_to_networkd(self):
        with tempfile.TemporaryDirectory() as name:
            paths = self.build(Path(name))
            completed, log = self.run_step(paths)
            self.assertEqual(0, completed.returncode, completed.stderr)
            unit = paths["unit"].read_text()
            self.assertEqual(
                controller_factory.network_unit(
                    controller_factory.FactorySpec(), GUEST_MAC),
                unit)
            self.assertEqual(0o644, paths["unit"].stat().st_mode & 0o777)
            self.assertFalse(
                paths["unit"].with_suffix(".network.new").exists())
            self.assertIn(
                "systemctl mask NetworkManager.service "
                "NetworkManager-wait-online.service", log)
            self.assertIn("systemctl stop NetworkManager.service", log)
            self.assertIn("systemctl enable systemd-networkd.service", log)
            self.assertIn("systemctl restart systemd-networkd.service", log)
            self.assertIn("ip addr flush dev enp0s2", log)
            self.assertNotIn("ip link set", log)
            self.assertIn("hostnamectl hostname bootstrap-dc", log)
            self.assertIn(
                "10.1.31.2 bootstrap-dc.ad.factory.test bootstrap-dc",
                paths["hosts"].read_text())

    def test_a_second_convergence_does_not_thrash_the_interface(self):
        with tempfile.TemporaryDirectory() as name:
            paths = self.build(Path(name))
            first, _ = self.run_step(paths)
            self.assertEqual(0, first.returncode, first.stderr)
            before = paths["unit"].read_text()
            second, log = self.run_step(paths)
            self.assertEqual(0, second.returncode, second.stderr)
            self.assertEqual(before, paths["unit"].read_text())
            # Already converged: the unit is unchanged, networkd owns the link
            # and the address and route are present, so nothing is flushed and
            # nothing is restarted.
            self.assertNotIn("systemctl restart systemd-networkd.service", log)
            self.assertNotIn("ip addr flush", log)
            self.assertNotIn("systemctl stop systemd-networkd.service", log)
            # Masking and enabling are idempotent and are still asserted.
            self.assertIn("systemctl mask NetworkManager.service", log)
            self.assertIn("systemctl enable systemd-networkd.service", log)

    def test_a_drifted_interface_is_reconverged(self):
        with tempfile.TemporaryDirectory() as name:
            paths = self.build(Path(name))
            first, _ = self.run_step(paths)
            self.assertEqual(0, first.returncode, first.stderr)
            (paths["state"] / "configured").unlink()
            second, log = self.run_step(paths)
            self.assertEqual(0, second.returncode, second.stderr)
            self.assertIn("systemctl restart systemd-networkd.service", log)

    def test_the_step_fails_closed_on_a_dhcp_socket(self):
        with tempfile.TemporaryDirectory() as name:
            paths = self.build(Path(name))
            completed, _ = self.run_step(paths, TELOS_FAKE_DHCP="1")
            self.assertEqual(2, completed.returncode)
            self.assertIn("a DHCP socket is open", completed.stderr)

    def test_the_step_fails_closed_without_a_usable_mac(self):
        with tempfile.TemporaryDirectory() as name:
            paths = self.build(Path(name), mac="not-a-mac")
            completed, _ = self.run_step(paths)
            self.assertEqual(2, completed.returncode)
            self.assertIn("no usable MAC address", completed.stderr)
            self.assertFalse(paths["unit"].exists())


PXE_UNITS = ("telos-factory-tftp.service", "telos-factory-http.service")

#: Every stage marker the payload announces, in order. Live gates and the
#: identity-run diagnostic allowlist (windows_identity_run.py) key on these, so
#: making PXE durable must not add, drop or reorder one.
FROZEN_MARKERS = [
    "network", "time-sync", "time-sync-response", "time-sync-clock",
    "payload-stage", "package-preflight", "package-missing-$package",
    "ansible", "services", "auth-audit", "auth-audit-preflight",
    "auth-audit-sink-create", "auth-audit-config-write",
    "auth-audit-config-verify", "auth-audit-restart",
    "auth-audit-sink-verify", "verify", "$1", "administrator-disable",
    "administrator-disabled-proof",
]


@mock.patch.object(controller_factory, "stage_dns_repair", new=lambda *_: {})
class DurablePxeServiceTests(unittest.TestCase):
    """PXE (TFTP + HTTP boot) must come back after a Controller reboots.

    The payload used to install the TFTP unit and only ``systemctl restart`` it,
    and to start nginx ad hoc with ``nginx -c``. The seed image masks every
    packaged TFTP and nginx unit, so a persistent instance (``rehearsal``, later
    the keeper) served PXE until its first reboot and then never again, while
    every in-run check still passed. Unit-tested only: reboot survival itself
    needs a live boot of a persistent instance.
    """

    def spec(self):
        return controller_factory.FactorySpec()

    def script(self):
        return controller_factory._script(self.spec())

    def units(self):
        return {
            "telos-factory-tftp.service":
                controller_factory.tftp_unit(self.spec()),
            "telos-factory-http.service": controller_factory.http_unit(),
        }

    @staticmethod
    def parse(text):
        parser = configparser.RawConfigParser(strict=True)
        parser.optionxform = str
        parser.read_string(text)
        return parser

    def test_both_units_install_into_the_boot_and_wait_for_the_address(self):
        # WantedBy= is what `systemctl enable` turns into a boot-time start.
        # Both daemons bind the Controller's own address, which exists only
        # once networkd has configured the link, so each unit pulls in AND
        # orders after network-online.target; After= alone orders against it
        # only if some other unit happens to pull it in.
        for name, text in self.units().items():
            with self.subTest(unit=name):
                unit = self.parse(text)
                self.assertEqual(
                    ["Unit", "Service", "Install"], unit.sections())
                self.assertEqual(
                    "multi-user.target", unit.get("Install", "WantedBy"))
                self.assertEqual(
                    "network-online.target", unit.get("Unit", "Wants"))
                self.assertEqual(
                    "network-online.target", unit.get("Unit", "After"))
                self.assertEqual(
                    "on-failure", unit.get("Service", "Restart"))

    def test_nginx_runs_under_its_unit_on_the_factory_configuration(self):
        unit = self.parse(controller_factory.http_unit())
        self.assertEqual("telos-factory-http.service",
                         controller_factory.HTTP_UNIT_NAME)
        self.assertEqual(
            "/usr/bin/nginx -c /etc/homelab/factory-nginx.conf",
            unit.get("Service", "ExecStart"))
        # Forking is what keeps the ad hoc start's fail-closed property: nginx
        # binds before it daemonizes, so a listener it cannot open fails the
        # restart itself. It needs the pid file the configuration declares.
        self.assertEqual("forking", unit.get("Service", "Type"))
        pid = unit.get("Service", "PIDFile")
        self.assertIn(
            f"pid {pid};\n",
            controller_factory.nginx_config(self.spec()))
        self.assertNotIn("daemon off", controller_factory.http_unit())

    def test_no_pxe_unit_implements_or_listens_for_dhcp(self):
        # ADR 0066: the gateway is the sole DHCP authority, so nothing enabled
        # here may answer DHCP or ProxyDHCP (UDP 67 / 4011).
        for name, text in self.units().items():
            with self.subTest(unit=name):
                self.assertNotIn("dhcp", text.lower())
                self.assertNotIn("dnsmasq", text)
                self.assertNotIn(":67", text)
                self.assertNotIn("4011", text)
        self.assertIn(
            f"--address {self.spec().address}:69 ",
            controller_factory.tftp_unit(self.spec()))
        self.assertIn(
            f"listen {self.spec().address}:80;",
            controller_factory.nginx_config(self.spec()))

    def test_the_bundle_stages_both_units_the_payload_installs(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = controller_factory.FactoryBundle(
                ROOT.parent, root / "factory.iso",
                authorization_nonce=NONCE)
            stage = bundle.stage(root / "stage")
            for unit, text in self.units().items():
                with self.subTest(unit=unit):
                    self.assertEqual(text, (stage / unit).read_text())
        script = self.script()
        for unit in PXE_UNITS:
            self.assertIn(
                f'install -m 0644 "$root/{unit}" /etc/systemd/system/{unit}\n',
                script)
            self.assertLess(
                script.index(f"/etc/systemd/system/{unit}"),
                script.index("systemctl daemon-reload"))

    def test_the_payload_enables_both_pxe_units(self):
        script = self.script()
        enable = ("systemctl enable telos-factory-tftp.service "
                  "telos-factory-http.service\n")
        restart = ("systemctl restart telos-factory-tftp.service "
                   "telos-factory-http.service\n")
        self.assertIn(enable, script)
        self.assertIn(restart, script)
        services = script.index("echo 'TELOS FACTORY STEP services'")
        audit = script.index("echo 'TELOS FACTORY STEP auth-audit'\n")
        self.assertLess(services, script.index("systemctl daemon-reload"))
        self.assertLess(script.index("systemctl daemon-reload"),
                        script.index(enable))
        self.assertLess(script.index(enable), script.index(restart))
        self.assertLess(script.index(restart), audit)
        # Enablement is proved on the guest, not trusted from the command.
        self.assertIn(
            '[[ $(systemctl is-enabled "$unit") == enabled ]]', script)

    def test_nginx_is_never_started_ad_hoc(self):
        # The only direct nginx invocation left is the configuration test in
        # the verifier; anything else would be a second nginx outside systemd.
        executable = [
            line.strip() for line in self.script().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        direct = [line for line in executable
                  if re.match(r"(?:\S*/)?nginx\s", line)]
        self.assertEqual([], direct)
        self.assertNotIn("nginx -c /etc/homelab/factory-nginx.conf\n",
                         self.script())
        self.assertIn(
            'check verify-05 "nginx -t -c /etc/homelab/factory-nginx.conf"',
            self.script())

    def test_no_marker_or_verify_label_changed(self):
        script = self.script()
        self.assertEqual(
            FROZEN_MARKERS,
            re.findall(r"TELOS FACTORY STEP ([a-z0-9$-]+)", script))
        self.assertEqual(1, script.count("TELOS FACTORY CONTROLLER PASS"))
        # windows_identity_run.py allowlists exactly verify-01..verify-10.
        self.assertEqual(
            10, len(controller_factory.verification_commands(self.spec())))
        self.assertIn("check verify-10 ", script)
        self.assertNotIn("check verify-11 ", script)


class PxeServiceStepExecutionTests(unittest.TestCase):
    """Run the payload's services step offline against a stub systemctl.

    Proves the shell logic -- that both units are enabled and restarted, that
    nginx is never invoked directly, and that a unit left disabled or stopped
    fails the step closed -- rather than only the generated text.
    """

    SYSTEMCTL = """#!/usr/bin/bash
printf '%s\\n' "systemctl $*" >>"$TELOS_LOG"
case "$1" in
  is-enabled)
    if [ "$2" = "${TELOS_NOT_ENABLED:-}" ]; then echo disabled; exit 1; fi
    echo enabled ;;
  is-active)
    if [ "$3" = "${TELOS_NOT_ACTIVE:-}" ]; then exit 3; fi ;;
esac
exit 0
"""
    NGINX = """#!/usr/bin/bash
printf '%s\\n' "nginx $*" >>"$TELOS_LOG"
exit 0
"""

    def run_step(self, **extra):
        script = controller_factory._script(controller_factory.FactorySpec())
        start = script.index("echo 'TELOS FACTORY STEP services'")
        end = script.index("echo 'TELOS FACTORY STEP auth-audit'\n")
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            stubs = root / "bin"
            stubs.mkdir()
            for tool, body in (("systemctl", self.SYSTEMCTL),
                               ("nginx", self.NGINX)):
                (stubs / tool).write_text(body)
                (stubs / tool).chmod(0o755)
            runner = root / "services-step"
            runner.write_text("#!/usr/bin/bash\nset -euo pipefail\n"
                              + script[start:end])
            log = root / "log"
            log.write_text("")
            environment = dict(os.environ)
            environment.update({
                "PATH": f"{stubs}:{environment['PATH']}",
                "TELOS_LOG": str(log),
            })
            environment.update(extra)
            completed = subprocess.run(
                [shutil.which("bash"), str(runner)],
                env=environment, capture_output=True, text=True)
            return completed, log.read_text()

    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_the_step_enables_and_starts_both_units_under_systemd(self):
        completed, log = self.run_step()
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("TELOS FACTORY STEP services", completed.stdout)
        self.assertIn(
            "systemctl enable telos-factory-tftp.service "
            "telos-factory-http.service\n", log)
        self.assertIn(
            "systemctl restart telos-factory-tftp.service "
            "telos-factory-http.service\n", log)
        for unit in PXE_UNITS:
            self.assertIn(f"systemctl is-enabled {unit}\n", log)
            self.assertIn(f"systemctl is-active --quiet {unit}\n", log)
        self.assertIn("systemctl restart samba.service ntpd.service\n", log)
        self.assertNotIn("nginx ", log)
        # Nothing DHCP-shaped is enabled or started.
        self.assertNotIn("dnsmasq", log)
        self.assertNotIn("dhcp", log.lower())

    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_a_unit_left_disabled_fails_the_step_closed(self):
        for unit in PXE_UNITS:
            with self.subTest(unit=unit):
                completed, _ = self.run_step(TELOS_NOT_ENABLED=unit)
                self.assertEqual(2, completed.returncode)
                self.assertIn(
                    f"{unit} is not enabled, so PXE would not survive a "
                    "reboot", completed.stderr)

    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_a_unit_that_is_not_running_fails_the_step_closed(self):
        for unit in PXE_UNITS:
            with self.subTest(unit=unit):
                completed, log = self.run_step(TELOS_NOT_ACTIVE=unit)
                self.assertEqual(2, completed.returncode)
                self.assertIn(f"{unit} is not running", completed.stderr)
                self.assertIn(
                    f"systemctl --no-pager --full status {unit}\n", log)


class DnsRepairBundleTests(unittest.TestCase):
    def test_a_fifo_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            os.mkfifo(root / "libndr-nbt.so.0")
            with self.assertRaisesRegex(ValueError, "regular single-link"):
                controller_factory.dns_repair_identity(root)

    def test_verified_artifact_is_staged_only_in_the_payload_copy(self):
        with tempfile.TemporaryDirectory() as name:
            stage = Path(name) / "stage"
            with mock.patch.object(controller_factory, "stage_dns_repair") as repair:
                controller_factory.FactoryBundle(
                    ROOT.parent, Path(name) / "factory.iso",
                    authorization_nonce=NONCE).stage(stage)
            repair.assert_called_once_with(
                ROOT.parent.resolve(),
                stage / "ansible/roles/domain_controller/files/samba-dns")
            variables = json.loads((stage / "factory-vars.json").read_text())
            self.assertEqual(
                "/opt/telos-factory/ansible/roles/domain_controller/files/samba-dns",
                variables["homelab_ad_dns_repair_source"])

    def test_missing_or_corrupt_artifact_prevents_payload_completion(self):
        with tempfile.TemporaryDirectory() as name:
            stage = Path(name) / "stage"
            with mock.patch.object(controller_factory, "stage_dns_repair",
                                   side_effect=ValueError("invalid DNS repair")):
                with self.assertRaisesRegex(ValueError, "invalid DNS repair"):
                    controller_factory.FactoryBundle(
                        ROOT.parent, Path(name) / "factory.iso",
                        authorization_nonce=NONCE).stage(stage)
            self.assertFalse((stage / "factory-vars.json").exists())
            self.assertFalse((stage / "secret").exists())


class ExpectedDnsRepairTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache, self.destination = self.root / "cache", self.root / "staged"
        self.cache.mkdir()
        (self.cache / "libndr-nbt.so.0").write_bytes(b"verified original candidate")
        (self.cache / "receipt.json").write_text('{"verified": true}')
        self.expected = controller_factory.dns_repair_identity(self.cache)
        environment = mock.patch.dict(os.environ, {
            "TELOS_SAMBA_DNS_CACHE": str(self.cache),
            controller_factory.DNS_REPAIR_EXPECTED_ENV: json.dumps(self.expected)})
        environment.start()
        self.addCleanup(environment.stop)
        sys.path.insert(0, str(ROOT / "lib"))
        import samba_dns
        self.samba_dns = samba_dns

    def copy(self, source, destination):
        shutil.copytree(source, destination)
        return {"verified": True}

    def test_expected_pair_is_preserved_across_staging(self):
        with mock.patch.object(self.samba_dns, "stage", side_effect=self.copy):
            controller_factory.stage_dns_repair(self.root, self.destination)
        self.assertEqual(controller_factory.dns_repair_identity(self.destination), self.expected)

    def test_changed_pair_refuses_before_staging(self):
        (self.cache / "libndr-nbt.so.0").write_bytes(b"another verified candidate")
        (self.cache / "receipt.json").write_text('{"verified": "another"}')
        with mock.patch.object(self.samba_dns, "stage") as stage:
            with self.assertRaisesRegex(ValueError, "pinned inputs"):
                controller_factory.stage_dns_repair(self.root, self.destination)
        stage.assert_not_called()

    def test_cache_swap_during_staging_refuses_even_if_copied_pair_was_correct(self):
        def swapped(source, destination):
            result = self.copy(source, destination)
            (source / "receipt.json").write_text('{"verified": "new"}')
            return result
        with mock.patch.object(self.samba_dns, "stage", side_effect=swapped):
            with self.assertRaisesRegex(ValueError, "changed while staging"):
                controller_factory.stage_dns_repair(self.root, self.destination)

    def test_staged_pair_swap_refuses_even_if_source_stays_correct(self):
        def swapped(source, destination):
            result = self.copy(source, destination)
            (destination / "libndr-nbt.so.0").write_bytes(b"wrong staged candidate")
            return result
        with mock.patch.object(self.samba_dns, "stage", side_effect=swapped):
            with self.assertRaisesRegex(ValueError, "changed while staging"):
                controller_factory.stage_dns_repair(self.root, self.destination)

    def test_incomplete_or_malformed_expected_pair_is_not_ignored(self):
        for expected in ("not-json", "{}", '{"library_sha256": "bad"}'):
            with self.subTest(expected=expected), mock.patch.dict(os.environ, {
                    controller_factory.DNS_REPAIR_EXPECTED_ENV: expected}), \
                    mock.patch.object(self.samba_dns, "stage") as stage:
                with self.assertRaisesRegex(ValueError, "invalid expected"):
                    controller_factory.stage_dns_repair(self.root, self.destination)
                stage.assert_not_called()


if __name__ == "__main__":
    unittest.main()
