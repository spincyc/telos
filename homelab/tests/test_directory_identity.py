"""The PERMANENT directory identity a durable Controller is provisioned under.

ADR 0065 requires the private overlay to freeze the realm, NetBIOS name, DNS
domain and both controller FQDNs before the first domain is provisioned, and
records the realm and NetBIOS name as effectively permanent.  Two families of
test follow from that, and both matter:

  * every refusal fires.  A validator that is never tested against its own
    failure cases is indistinguishable from no validator at all, and the
    failure this one prevents is unrecoverable rather than merely wrong -- the
    domain SID and every account SID derive from these values.
  * acceptance is untouched.  Gates 3 through 12 build the DISPOSABLE
    Controller from ``FactorySpec()``'s synthetic defaults, gate 6 and gate 8
    receipts name ``ad.factory.test``, and none of that may move because the
    durable path grew a private overlay.

Every fixture is written into a temporary directory.  Nothing here reads or
writes ``homelab/instance/``: that is the owner's real private overlay, and a
suite that consulted it would pass or fail depending on whose machine it ran
on.
"""

import ipaddress
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vm"))

import controller_factory  # noqa: E402
from vm import directory_identity  # noqa: E402
from vm.directory_identity import (  # noqa: E402
    DirectoryIdentityError,
    durable_directory_identity,
)

#: A complete, well-formed document.  Synthetic on purpose: a tracked fixture
#: naming the owner's real realm would put an effectively permanent private
#: value into Git, which is exactly what the gitignored overlay exists to
#: prevent.  Also deliberately unlike ``FactorySpec()``'s defaults in every
#: field, so a passing assertion cannot be a silent fallback to them.
COMPLETE = {
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

TEMPLATE = ROOT / "instance-example" / "identity" / "directory.json"
PRIVATE_CONTRACT = (
    ROOT.parent / "src" / "homelab" / "private-contract"
    / "instance.schema.json")


def deep(document, **sections):
    """One copy of COMPLETE with named sections patched.

    ``None`` removes a key, so a test can express "this document is missing
    exactly one required value" without restating the other seven.
    """
    result = json.loads(json.dumps(document))
    for section, patch in sections.items():
        for key, value in patch.items():
            if value is None:
                result.setdefault(section, {}).pop(key, None)
            else:
                result.setdefault(section, {})[key] = value
    return result


class DirectoryIdentityFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, document, name="directory.json"):
        path = self.root / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def refuse(self, document, pattern, **sections):
        """Assert one document is refused, and that the message says why."""
        path = self.write(deep(document, **sections) if sections else document)
        with self.assertRaisesRegex(DirectoryIdentityError, pattern) as caught:
            durable_directory_identity(path)
        # Every refusal names the file. A serial transcript is all the reader
        # of a failed provisioning run has, and "invalid identity" in it would
        # not tell them which file to fix.
        self.assertIn(str(path), str(caught.exception))
        return str(caught.exception)


class WellFormedDocumentTests(DirectoryIdentityFixture):
    """What a complete document resolves to, and what it derives."""

    def test_a_complete_document_resolves_to_its_declared_values(self):
        identity = durable_directory_identity(self.write(COMPLETE))
        self.assertEqual("ad.example.home.arpa", identity.dns_domain)
        self.assertEqual("AD.EXAMPLE.HOME.ARPA", identity.kerberos_realm)
        self.assertEqual("EXAMPLEAD", identity.netbios_name)
        self.assertEqual(
            "bootstrap-dc.ad.example.home.arpa", identity.bootstrap_dc_fqdn)
        self.assertEqual("dc2.ad.example.home.arpa", identity.permanent_dc_fqdn)
        self.assertEqual("10.1.99.2", identity.address)
        self.assertEqual(28, identity.prefix)
        self.assertEqual("10.1.99.1", identity.gateway)

    def test_the_factory_spec_carries_the_permanent_identity_not_acceptance(self):
        spec = durable_directory_identity(self.write(COMPLETE)).factory_spec()
        acceptance = controller_factory.FactorySpec()
        self.assertEqual("AD.EXAMPLE.HOME.ARPA", spec.realm)
        self.assertNotEqual(acceptance.realm, spec.realm)
        self.assertNotEqual(acceptance.domain, spec.domain)
        self.assertNotEqual(acceptance.netbios, spec.netbios)
        self.assertNotEqual(acceptance.address, spec.address)
        # The realm the payload uses is FactorySpec.realm, which is the domain
        # upper-cased. The loader refuses a mismatched pair precisely so these
        # two derivations of the realm can never disagree.
        self.assertEqual(spec.realm, spec.domain.upper())

    def test_subnet_and_mask_are_arithmetic_not_a_second_declaration(self):
        spec = durable_directory_identity(self.write(COMPLETE)).factory_spec()
        subnet = ipaddress.IPv4Network((spec.address, spec.prefix),
                                       strict=False)
        self.assertEqual(str(subnet.network_address), spec.network)
        self.assertEqual(str(subnet.netmask), spec.mask)
        self.assertEqual("10.1.99.0", spec.network)
        self.assertEqual("255.255.255.240", spec.mask)

    def test_the_bootstrap_host_name_comes_from_its_declared_fqdn(self):
        identity = durable_directory_identity(self.write(COMPLETE))
        self.assertEqual("bootstrap-dc", identity.hostname)
        self.assertEqual(identity.hostname, identity.factory_spec().hostname)
        self.assertEqual(
            "bootstrap-dc.ad.example.home.arpa",
            identity.factory_spec().fqdn)

    def test_ntp_stays_the_fabric_default_because_adr_0065_does_not_freeze_it(self):
        # A simulated persistent instance can reach no NTP server but the one
        # the userspace gateway answers for, so this is deliberately NOT an
        # overlay key. A real Controller's upstreams are Ansible inventory.
        spec = durable_directory_identity(self.write(COMPLETE)).factory_spec()
        self.assertEqual(
            controller_factory.FactorySpec().ntp_upstream, spec.ntp_upstream)

    def test_documentation_keys_are_ignored_everywhere(self):
        document = deep(COMPLETE)
        document["_documentation"] = "JSON has no comments"
        document["identity"]["_note"] = "this realm is permanent"
        identity = durable_directory_identity(self.write(document))
        self.assertEqual("AD.EXAMPLE.HOME.ARPA", identity.kerberos_realm)


class AbsentOrUnreadableTests(DirectoryIdentityFixture):
    """The durable path has no fallback: absence is a refusal too."""

    def test_an_absent_document_refuses_and_names_the_file_and_every_key(self):
        missing = self.root / "no-such-directory.json"
        with self.assertRaises(DirectoryIdentityError) as caught:
            durable_directory_identity(missing)
        message = str(caught.exception)
        self.assertIn(str(missing), message)
        for key in directory_identity.REQUIRED_KEYS:
            self.assertIn(key, message)
        # It must say what it refused to do, not merely that a file is absent:
        # the reason this is not a fallback is that the SIDs are permanent.
        self.assertIn("AD.FACTORY.TEST", message)
        self.assertIn("instance-example/identity/directory.json", message)

    def test_an_incomplete_document_names_every_missing_key_at_once(self):
        message = self.refuse(
            COMPLETE, "declares no",
            identity={"netbios_name": None},
            services={"permanent_dc_fqdn": None},
            network={"prefix": None})
        for key in ("identity.netbios_name", "services.permanent_dc_fqdn",
                    "network.prefix"):
            self.assertIn(key, message)
        # An owner filling this in for the first time is told the whole shape
        # once, not made to rediscover it one failed run at a time.
        self.assertNotIn("identity.dns_domain,", message.split(". ")[0])

    def test_an_empty_string_is_missing_not_declared(self):
        self.refuse(COMPLETE, "declares no identity.netbios_name",
                    identity={"netbios_name": "   "})

    def test_a_directory_in_place_of_the_document_is_refused(self):
        (self.root / "directory.json").mkdir()
        with self.assertRaisesRegex(
                DirectoryIdentityError, "must be a regular file"):
            durable_directory_identity(self.root / "directory.json")

    def test_unreadable_json_is_a_refusal_never_a_fallback(self):
        path = self.root / "directory.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaisesRegex(
                DirectoryIdentityError, "unreadable JSON"):
            durable_directory_identity(path)

    def test_a_json_array_is_not_a_document(self):
        path = self.root / "directory.json"
        path.write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(
                DirectoryIdentityError, "not a JSON object"):
            durable_directory_identity(path)

    def test_the_schema_version_must_be_declared_and_current(self):
        for value in (None, 0, 2, "1"):
            document = deep(COMPLETE)
            if value is None:
                document.pop("schema_version")
            else:
                document["schema_version"] = value
            with self.subTest(schema_version=value):
                self.refuse(document, "must declare schema_version 1")

    def test_an_unknown_key_fails_closed_rather_than_reverting_to_a_default(self):
        document = deep(COMPLETE)
        document["identiy"] = {}
        self.refuse(document, "unknown key 'identiy'")

    def test_the_netbios_domain_misspelling_is_named_with_its_correction(self):
        # The Ansible variable and the cross-OS acceptance contract both say
        # "netbios_domain" for this value, so an owner copying from either will
        # try it here. Ignoring it would leave the permanent NetBIOS name
        # undeclared while the document looked complete.
        document = deep(COMPLETE, identity={"netbios_name": None})
        document["identity"]["netbios_domain"] = "EXAMPLEAD"
        message = self.refuse(document, "unknown key 'identity.netbios_domain'")
        self.assertIn("'identity.netbios_name'", message)

    def test_an_unknown_key_inside_a_section_is_refused_with_the_permitted_set(self):
        message = self.refuse(
            COMPLETE, "unknown key 'network.netmask'",
            network={"netmask": "255.255.255.240"})
        self.assertIn("network.address", message)
        self.assertIn("network.prefix", message)

    def test_a_section_that_is_not_an_object_is_refused(self):
        document = deep(COMPLETE)
        document["services"] = "bootstrap-dc.ad.example.home.arpa"
        self.refuse(document, "services is not a JSON object")


class PermanentValueTests(DirectoryIdentityFixture):
    """Everything ADR 0065 makes permanent, refused when it is wrong."""

    def test_a_dns_domain_outside_home_arpa_is_refused(self):
        for domain in ("ad.example.test", "ad.factory.test", "ad.home.arpa.uk",
                       "example.arpa"):
            with self.subTest(dns_domain=domain):
                self.refuse(
                    COMPLETE, "is not beneath the reserved home.arpa suffix",
                    identity={"dns_domain": domain,
                              "kerberos_realm": domain.upper()},
                    services={
                        "bootstrap_dc_fqdn": f"bootstrap-dc.{domain}",
                        "permanent_dc_fqdn": f"dc2.{domain}"})

    def test_the_reserved_suffix_itself_is_not_an_identity_domain(self):
        self.refuse(
            COMPLETE, "is not beneath the reserved home.arpa suffix",
            identity={"dns_domain": "home.arpa", "kerberos_realm": "HOME.ARPA"},
            services={"bootstrap_dc_fqdn": "bootstrap-dc.home.arpa",
                      "permanent_dc_fqdn": "dc2.home.arpa"})

    def test_an_upper_case_dns_domain_is_not_a_dns_name(self):
        self.refuse(
            COMPLETE, "is not a lower-case DNS name",
            identity={"dns_domain": "AD.EXAMPLE.HOME.ARPA"})

    def test_a_realm_that_is_not_the_upper_case_domain_is_refused(self):
        # The class of misconfiguration that provisions cleanly and only
        # surfaces at the first Kerberos login.
        for realm in ("AD.EXAMPLE.HOME.ARPA.", "ad.example.home.arpa",
                      "EXAMPLE.HOME.ARPA", "AD.FACTORY.TEST",
                      "AD.EXAMPLEE.HOME.ARPA"):
            with self.subTest(kerberos_realm=realm):
                message = self.refuse(
                    COMPLETE, "is not the upper-case form of",
                    identity={"kerberos_realm": realm})
                self.assertIn("AD.EXAMPLE.HOME.ARPA", message)

    def test_an_over_long_or_illegal_netbios_name_is_refused(self):
        for netbios in ("A" * 16, "EXAMPLE.AD", "example-ad", "EXAMPLE AD",
                        "EXAMPLE_AD", ""):
            with self.subTest(netbios_name=netbios):
                self.refuse(
                    COMPLETE,
                    "netbios_name|declares no identity.netbios_name",
                    identity={"netbios_name": netbios})

    def test_a_fifteen_character_netbios_name_is_accepted(self):
        # The boundary is the real limit, not one short of it.
        identity = durable_directory_identity(self.write(
            deep(COMPLETE, identity={"netbios_name": "A" * 15})))
        self.assertEqual("A" * 15, identity.netbios_name)

    def test_a_controller_fqdn_outside_the_identity_domain_is_refused(self):
        for key in ("bootstrap_dc_fqdn", "permanent_dc_fqdn"):
            for value in ("bootstrap-dc.ad.other.home.arpa",
                          "ad.example.home.arpa", "bootstrap-dc"):
                with self.subTest(key=key, value=value):
                    self.refuse(
                        COMPLETE, "is not beneath the identity domain",
                        services={key: value})

    def test_an_over_long_controller_host_label_is_refused(self):
        # 16 characters: samba truncates a NetBIOS machine name past 15 and
        # the machine account would not match the host.
        self.refuse(
            COMPLETE, "is not a legal 1-15 character machine name",
            services={"permanent_dc_fqdn": "d" * 16 + ".ad.example.home.arpa"})

    def test_one_name_for_both_controllers_is_refused(self):
        self.refuse(
            COMPLETE, "same FQDN",
            services={"permanent_dc_fqdn": "bootstrap-dc.ad.example.home.arpa"})

    def test_a_malformed_address_or_prefix_is_refused(self):
        for address in ("10.1.99", "10.1.99.2.1", "010.1.99.2", "not-an-address",
                        "10.1.99.300", "2001:db8::1"):
            with self.subTest(address=address):
                self.refuse(COMPLETE, "network.address",
                            network={"address": address})
        for prefix in ("28", 33, -1, 28.0, True):
            with self.subTest(prefix=prefix):
                self.refuse(COMPLETE, "network.prefix",
                            network={"prefix": prefix})

    def test_an_address_that_is_not_a_usable_host_is_refused(self):
        # The network and broadcast addresses of the subnet the declared
        # address and prefix describe.
        self.refuse(COMPLETE, "network.address.*network address",
                    network={"address": "10.1.99.0"})
        self.refuse(COMPLETE, "network.address.*broadcast address",
                    network={"address": "10.1.99.15"})
        # /31 and /32 have no usable host addresses at all, so a Controller
        # plus a gateway cannot fit in one.
        self.refuse(COMPLETE, "network.address",
                    network={"prefix": 32})

    def test_the_subnet_is_derived_from_the_address_so_a_split_pair_is_caught(self):
        # The subnet is arithmetic on the declared address and prefix rather
        # than a third declaration, so an address moved into a different /28
        # surfaces as a gateway that is no longer inside it.
        self.refuse(COMPLETE, "network.gateway.*is not inside 10.1.99.16/28",
                    network={"address": "10.1.99.20"})

    def test_a_gateway_outside_the_subnet_or_equal_to_the_controller(self):
        self.refuse(COMPLETE, "network.gateway",
                    network={"gateway": "10.1.99.20"})
        self.refuse(COMPLETE, "same address",
                    network={"gateway": "10.1.99.2"})


class ShippedTemplateTests(DirectoryIdentityFixture):
    """The tracked placeholder template: inert, and free of real values."""

    def test_the_template_is_a_refusal_that_names_every_required_key(self):
        with self.assertRaises(DirectoryIdentityError) as caught:
            durable_directory_identity(TEMPLATE)
        message = str(caught.exception)
        for key in directory_identity.REQUIRED_KEYS:
            self.assertIn(key, message)

    def test_the_template_carries_placeholders_and_no_real_value(self):
        document = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        self.assertEqual(
            directory_identity.SCHEMA_VERSION, document["schema_version"])
        # Every live section is absent: copying the template must provision
        # nothing and must not look like a working default.
        for section in directory_identity.SECTIONS:
            self.assertNotIn(section, document)
        text = TEMPLATE.read_text(encoding="utf-8")
        example = document["_example"]
        self.assertEqual(
            sorted(example), sorted(directory_identity.SECTIONS))
        for section, keys in directory_identity.SECTIONS.items():
            self.assertEqual(sorted(example[section]), sorted(keys))
        for value in ("<domain>.home.arpa", "<DOMAIN>.HOME.ARPA", "<NETBIOS>"):
            self.assertIn(value, text)
        # No real address, and not the owner's realm.
        self.assertNotRegex(text, r"\b\d{1,3}(\.\d{1,3}){3}\b")
        self.assertNotIn("ad.home.arpa", text)
        self.assertNotIn("AD.HOME.ARPA", text)


class SchemaAgreementTests(unittest.TestCase):
    """The patterns are the private contract's, pinned so they cannot drift.

    ``src/homelab/private-contract/instance.schema.json`` already models ADR
    0065's overlay for the sibling private repository, using exactly these key
    names.  This loader restates its patterns rather than importing across the
    ``src/`` boundary at run time, so this test is what keeps the two honest.
    """

    def setUp(self):
        self.schema = json.loads(
            PRIVATE_CONTRACT.read_text(encoding="utf-8"))

    def test_the_patterns_match_the_private_contract(self):
        defs = self.schema["$defs"]
        self.assertEqual(
            defs["dnsName"]["pattern"], directory_identity.DNS_NAME_PATTERN)
        self.assertEqual(
            defs["dnsLabel"]["pattern"], directory_identity.DNS_LABEL_PATTERN)
        self.assertEqual(
            self.schema["properties"]["identity"]["properties"]
            ["netbios_name"]["pattern"],
            directory_identity.NETBIOS_NAME_PATTERN)

    def test_the_key_names_are_the_private_contract_and_adr_0065_spelling(self):
        properties = self.schema["properties"]
        self.assertEqual(
            sorted(properties["identity"]["required"]),
            sorted(directory_identity.SECTIONS["identity"]))
        # The private contract additionally freezes services.boot_fqdn, which
        # is the PXE service rather than a directory controller and is not
        # ADR 0065's concern here; every key this document does declare is one
        # of that contract's.
        self.assertLessEqual(
            set(directory_identity.SECTIONS["services"]),
            set(properties["services"]["required"]))
        self.assertIn("netbios_name", properties["identity"]["properties"])
        self.assertNotIn("netbios_domain", properties["identity"]["properties"])


class AcceptanceIsUnaffectedTests(DirectoryIdentityFixture):
    """With no overlay present, every acceptance value is what it was.

    Gates 3-12 build the disposable Controller from ``FactorySpec()``.  Gate 6
    and gate 8 receipts name ``ad.factory.test``.  The synthetic realm appears
    in ``vm/simulated_gateway``, ``workstations/arch_second`` and the reference
    frames.  None of that may move because the durable path grew an overlay.
    """

    #: The acceptance identity, restated literally rather than derived, so a
    #: change to FactorySpec's defaults fails here instead of silently
    #: redefining what "unchanged" means.
    ACCEPTANCE = {
        "hostname": "bootstrap-dc",
        "domain": "ad.factory.test",
        "netbios": "FACTORY",
        "address": "10.1.31.2",
        "prefix": 28,
        "gateway": "10.1.31.1",
        "ntp_upstream": "198.51.100.10",
        "network": "10.1.31.0",
        "mask": "255.255.255.240",
    }

    def test_the_disposable_spec_is_byte_identical_with_no_overlay(self):
        spec = controller_factory.FactorySpec()
        for field, value in self.ACCEPTANCE.items():
            with self.subTest(field=field):
                self.assertEqual(value, getattr(spec, field))
        self.assertEqual("AD.FACTORY.TEST", spec.realm)
        self.assertEqual("bootstrap-dc.ad.factory.test", spec.fqdn)

    def test_the_default_spec_needs_no_overlay_and_reads_none(self):
        # Constructing the acceptance spec must not touch the filesystem at
        # all: the disposable path is what runs on a machine with no private
        # overlay, and it may never depend on one existing.
        opened = []
        real_open = Path.open

        def watched(self, *args, **kwargs):
            opened.append(str(self))
            return real_open(self, *args, **kwargs)

        Path.open = watched
        try:
            spec = controller_factory.FactorySpec()
            payload = controller_factory._script(spec)
        finally:
            Path.open = real_open
        self.assertEqual([], opened)
        self.assertIn("ad.factory.test", payload)
        self.assertIn("10.1.31.2/28", payload)

    def test_the_synthetic_realm_is_still_what_the_fabric_expects(self):
        from vm import simulated_gateway
        spec = controller_factory.FactorySpec()
        self.assertEqual(spec.domain, simulated_gateway.IDENTITY_DNS_SUFFIX)

    def test_importing_the_loader_reads_no_overlay(self):
        # The roster loader resolves at import; this one deliberately does not,
        # so importing anything on the durable path can never fail on, or
        # depend on, whatever private overlay a machine happens to carry.
        self.assertFalse(
            hasattr(directory_identity, "_IDENTITY"),
            "the permanent identity must not be resolved at import time")
        self.assertTrue(
            str(directory_identity.directory_identity_path()).endswith(
                "homelab/instance/identity/directory.json"))

    def test_the_loader_refuses_rather_than_returning_the_acceptance_values(self):
        # The single most important negative: no input to this loader can ever
        # yield the acceptance identity, because ad.factory.test is not under
        # home.arpa.
        self.refuse(
            COMPLETE, "is not beneath the reserved home.arpa suffix",
            identity={"dns_domain": "ad.factory.test",
                      "kerberos_realm": "AD.FACTORY.TEST",
                      "netbios_name": "FACTORY"},
            services={"bootstrap_dc_fqdn": "bootstrap-dc.ad.factory.test",
                      "permanent_dc_fqdn": "dc2.ad.factory.test"},
            network={"address": "10.1.31.2", "prefix": 28,
                     "gateway": "10.1.31.1"})


class SourcePhraseTests(unittest.TestCase):
    def test_the_source_phrase_names_the_file_it_describes(self):
        phrase = directory_identity.directory_identity_source(
            Path("/tmp/example/directory.json"))
        self.assertIn("/tmp/example/directory.json", phrase)
        self.assertIn("private overlay", phrase)

    def test_the_default_source_phrase_is_the_overlay_path(self):
        self.assertIn(
            str(directory_identity.directory_identity_path()),
            directory_identity.directory_identity_source())

    def test_every_required_key_belongs_to_a_declared_section(self):
        for dotted in directory_identity.REQUIRED_KEYS:
            section, _, key = dotted.partition(".")
            self.assertIn(section, directory_identity.SECTIONS)
            self.assertIn(key, directory_identity.SECTIONS[section])
        # And every declared key is required: an optional key on a document
        # whose whole purpose is to FREEZE values would be a fallback in
        # disguise.
        declared = {f"{section}.{key}"
                    for section, keys in directory_identity.SECTIONS.items()
                    for key in keys}
        self.assertEqual(declared, set(directory_identity.REQUIRED_KEYS))
        self.assertEqual(
            re.compile(directory_identity.NETBIOS_NAME_PATTERN).pattern,
            directory_identity.NETBIOS_NAME_PATTERN)


if __name__ == "__main__":
    unittest.main()
