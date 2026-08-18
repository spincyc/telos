#!/usr/bin/env python3
"""Resolve the PERMANENT directory identity a durable Controller is given.

ADR 0065 requires the private instance overlay to *freeze* five values before
the first domain is provisioned: ``identity.dns_domain`` (beneath ADR 0005's
reserved ``home.arpa`` suffix), ``identity.kerberos_realm`` (the upper-case
form of that DNS domain), ``identity.netbios_name``,
``services.bootstrap_dc_fqdn`` and ``services.permanent_dc_fqdn``.  This module
is that requirement as executable code.

Why a loader exists at all.  ``vm/controller_factory.FactorySpec`` carries the
synthetic acceptance identity -- ``ad.factory.test``/``FACTORY`` -- and gates 3
through 12 build the disposable Controller from it.  ``persistent_converge``
used to construct a bare ``FactorySpec()``, so the *durable* directory would
have been provisioned under the acceptance realm, permanently: the domain SID
and every account SID derive from the realm and NetBIOS name, and ADR 0065
records both as "effectively permanent".  There is no rename afterwards, only a
migration.  So the durable path REFUSES the acceptance defaults, exactly as
``workstations/arch_second.identity_roster(require_overlay=True)`` refuses the
synthetic account roster for the same reason and with the same consequence.

Why JSON, and why here.  Every reader on this path is Python that reads JSON
contracts and has no YAML dependency -- the reason
``arch_second.identity_overlay_path`` gives for the sibling roster document.
This document sits beside it, under the gitignored ``homelab/instance/``
overlay (ADR 0046), because a realm and a Controller address are instance data
that must never enter Git or the published site.
``homelab/instance-example/identity/`` carries the documented placeholder
template.

Why these key names.  ``src/homelab/private-contract/instance.schema.json``
already models ADR 0065's overlay for the sibling private repository, with
exactly ``identity.{dns_domain,kerberos_realm,netbios_name}`` and
``services.{bootstrap_dc_fqdn,permanent_dc_fqdn}``.  This document is a subset
of that one's shape so an owner can lift the block straight across, and so
there is one spelling of each key rather than two.  ``workstations/acceptance``
spells the third key ``netbios_domain``, but that is a *different* document
(the tracked cross-OS acceptance contract) with its own schema and its own
readers; ADR 0065 and the private contract agree on ``netbios_name`` and they
govern this one.  A document that says ``netbios_domain`` here is refused by
name rather than quietly ignored.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat as stat_module
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    from .controller_factory import FactorySpec
except ImportError:  # Direct execution from homelab/vm.
    from controller_factory import FactorySpec

HOMELAB_ROOT = Path(__file__).resolve().parents[1]
# ADR 0005's reserved suffix and the ADR 0045 address rules are already written
# once, in lib/netplan.py.  Imported by path for the same reason
# vm/controller_principals.py imports the roster loader by path: this module is
# imported both as ``homelab.vm.directory_identity`` and as
# ``vm.directory_identity``, and ``homelab/lib`` is not a package.
_LIB = HOMELAB_ROOT / "lib"
if str(_LIB) not in sys.path:
    sys.path.insert(0, str(_LIB))
from netplan import (  # noqa: E402
    DNS_SUFFIX,
    NetworkPlanError,
    check_usable_address,
)

#: Bumped only when a key is removed, changes meaning, or becomes required.
SCHEMA_VERSION = 1

#: The private contract's own patterns, restated here so this module has no
#: runtime dependency on ``src/``.  ``test_controller_factory`` pins all three
#: to ``src/homelab/private-contract/instance.schema.json`` so they cannot
#: drift.  ``dnsLabel``'s 15-character cap is not cosmetic: it is the NetBIOS
#: machine-name limit ``vm/arch_install_prepare.require_netbios_hostname``
#: enforces for a workstation, and samba truncates a longer name silently.
DNS_NAME_PATTERN = r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$"
DNS_LABEL_PATTERN = r"^[a-z0-9][a-z0-9-]{0,14}$"
NETBIOS_NAME_PATTERN = r"^[A-Z0-9-]{1,15}$"
_DNS_NAME = re.compile(DNS_NAME_PATTERN)
_DNS_LABEL = re.compile(DNS_LABEL_PATTERN)
_NETBIOS_NAME = re.compile(NETBIOS_NAME_PATTERN)

#: Every key the durable path requires, in the order a refusal lists them.
#: ADR 0065 names the first five; the last three are what a Samba AD DC needs
#: to be reachable at all, and the address is baked into the guest's
#: systemd-networkd unit, its ``/etc/hosts`` and every A record it serves.
REQUIRED_KEYS = (
    "identity.dns_domain",
    "identity.kerberos_realm",
    "identity.netbios_name",
    "services.bootstrap_dc_fqdn",
    "services.permanent_dc_fqdn",
    "network.address",
    "network.prefix",
    "network.gateway",
)
#: Section -> the keys it may declare.  Anything else is refused, so a typo
#: fails closed instead of leaving a permanent value at its acceptance default.
SECTIONS = {
    "identity": ("dns_domain", "kerberos_realm", "netbios_name"),
    "services": ("bootstrap_dc_fqdn", "permanent_dc_fqdn"),
    "network": ("address", "prefix", "gateway"),
}
TOP_LEVEL_KEYS = ("schema_version",) + tuple(SECTIONS)
#: The one misspelling worth naming outright: the Ansible variable and the
#: cross-OS acceptance contract both say "netbios_domain", so an owner copying
#: from either will try it here.
_MISSPELLINGS = {"netbios_domain": "netbios_name"}


class DirectoryIdentityError(RuntimeError):
    """The permanent directory identity cannot be resolved from the overlay.

    Distinctly named on purpose.  A missing or malformed private overlay must
    never look like a bring-up failure, and it must never fall back to the
    synthetic acceptance realm: the domain SID and every account SID derive
    from the realm and the NetBIOS name, so a fallback is not a wrong run, it
    is a permanent one under somebody else's name.
    """


def directory_identity_path() -> Path:
    """The owner's gitignored declaration of the permanent directory identity.

    Beside ``identity/principals.json``, which declares the account names of
    the same directory, and for the same reason: ADR 0046 keeps real identity
    data out of Git entirely.
    """
    return HOMELAB_ROOT / "instance" / "identity" / "directory.json"


def _documentation_key(key: object) -> bool:
    """A leading underscore marks a key that exists only to be read.

    JSON has no comments and this is a file an owner edits by hand, so the
    template ships its worked example under ``_``-prefixed keys.  Every other
    unknown key is refused.
    """
    return isinstance(key, str) and key.startswith("_")


@dataclass(frozen=True)
class DirectoryIdentity:
    """One validated, permanent directory identity.

    Frozen because every field is: ADR 0065 records the realm and NetBIOS name
    as effectively permanent, and the address is written into the guest's
    durable network unit.
    """

    dns_domain: str
    kerberos_realm: str
    netbios_name: str
    bootstrap_dc_fqdn: str
    permanent_dc_fqdn: str
    address: str
    prefix: int
    gateway: str
    source: Path

    @property
    def hostname(self) -> str:
        """The bootstrap DC's SHORT name: the first label of its FQDN."""
        return self.bootstrap_dc_fqdn.split(".", 1)[0]

    @property
    def subnet(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(
            (self.address, self.prefix), strict=False)

    def factory_spec(self) -> FactorySpec:
        """The convergence payload's spec, under the PERMANENT identity.

        Everything ADR 0065 freezes comes from the overlay.  ``network`` and
        ``mask`` are arithmetic on the declared address and prefix, not a
        second declaration, so they cannot disagree with it.
        ``ntp_upstream`` deliberately keeps ``FactorySpec``'s default: it is
        fabric rather than identity, ADR 0065 does not freeze it, and a
        *simulated* persistent instance can reach no NTP server other than the
        one the userspace gateway answers for.  A real Controller's upstreams
        are Ansible inventory (``homelab_ad_ntp_upstreams``), not this file.
        """
        subnet = self.subnet
        return FactorySpec(
            hostname=self.hostname,
            domain=self.dns_domain,
            netbios=self.netbios_name,
            address=self.address,
            prefix=self.prefix,
            gateway=self.gateway,
            network=str(subnet.network_address),
            mask=str(subnet.netmask),
        )


def _read_document(path: Path) -> dict:
    """Read the overlay, or refuse.  There is no third answer here.

    The roster loader distinguishes "genuinely absent" from "unreadable"
    because absence is its ONE permitted fallback.  This loader has none: an
    absent document is a refusal too.  The distinction is still made, because
    the two refusals need different words -- "seed it from the template"
    against "your overlay is broken" -- and because ``Path.exists()`` answers
    ``False`` for a file it merely cannot stat.  On Python 3.13 and later
    ``exists()``/``is_file()`` swallow every ``OSError``, so a document under a
    directory the caller cannot search reads as "not there"; ``os.lstat`` says
    which it actually was, and settles the symlink question in the same call.
    """
    try:
        status = os.lstat(path)
    except FileNotFoundError:
        raise DirectoryIdentityError(
            f"the permanent directory identity is not declared: {path} does "
            f"not exist. ADR 0065 requires this overlay to freeze "
            f"{', '.join(REQUIRED_KEYS)} BEFORE the first domain is "
            f"provisioned, and this path may not fall back to the synthetic "
            f"acceptance realm {FactorySpec().realm} -- the domain SID and "
            f"every account SID derive from it and cannot be renamed "
            f"afterwards. Seed it from "
            f"homelab/instance-example/identity/directory.json") from None
    except OSError as error:
        # Unknown is not absent.  Refuse rather than provision a permanent
        # domain under a realm nobody chose.
        raise DirectoryIdentityError(
            f"directory identity overlay {path} could not be examined "
            f"({error.strerror or type(error).__name__}); an overlay whose "
            f"state is unknown is a refusal, never a fallback") from error
    if not stat_module.S_ISREG(status.st_mode):
        raise DirectoryIdentityError(
            f"directory identity overlay {path} must be a regular file")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DirectoryIdentityError(
            f"directory identity overlay {path} is unreadable JSON "
            f"({error})") from error
    if not isinstance(document, dict):
        raise DirectoryIdentityError(
            f"directory identity overlay {path} is not a JSON object")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise DirectoryIdentityError(
            f"directory identity overlay {path} must declare schema_version "
            f"{SCHEMA_VERSION}")
    _refuse_unknown(path, document, TOP_LEVEL_KEYS, "")
    for section in SECTIONS:
        body = document.get(section)
        if body is None:
            continue
        if not isinstance(body, dict):
            raise DirectoryIdentityError(
                f"directory identity overlay {path} {section} is not a JSON "
                f"object")
        _refuse_unknown(path, body, SECTIONS[section], f"{section}.")
    return document


def _refuse_unknown(
    path: Path, body: dict, permitted: tuple[str, ...], prefix: str,
) -> None:
    unknown = sorted(
        key for key in body
        if key not in permitted and not _documentation_key(key))
    if not unknown:
        return
    hint = _MISSPELLINGS.get(unknown[0])
    correction = (
        f"; ADR 0065 spells it '{prefix}{hint}'" if hint else
        f"; permitted keys are "
        f"{', '.join(prefix + name for name in permitted)}")
    raise DirectoryIdentityError(
        f"directory identity overlay {path} has unknown key "
        f"{prefix + unknown[0]!r}{correction}")


def _collect(path: Path, document: dict) -> dict[str, object]:
    """Every required key, or a refusal that names ALL of the missing ones.

    Named together rather than one at a time on purpose: an owner filling this
    in for the first time must be told the whole shape once, not made to
    rediscover it one failed run at a time.
    """
    values: dict[str, object] = {}
    missing: list[str] = []
    for dotted in REQUIRED_KEYS:
        section, _, key = dotted.partition(".")
        body = document.get(section)
        value = body.get(key) if isinstance(body, dict) else None
        if value is None or (isinstance(value, str) and not value.strip()):
            missing.append(dotted)
            continue
        values[dotted] = value
    if missing:
        raise DirectoryIdentityError(
            f"directory identity overlay {path} declares no "
            f"{', '.join(missing)}. ADR 0065 requires the overlay to freeze "
            f"every one of {', '.join(REQUIRED_KEYS)} before the first domain "
            f"is provisioned; this path may not fall back to the synthetic "
            f"acceptance identity for any of them")
    return values


def _require_dns_name(path: Path, dotted: str, value: object) -> str:
    if not isinstance(value, str) or not _DNS_NAME.match(value):
        raise DirectoryIdentityError(
            f"directory identity overlay {path} {dotted} {value!r} is not a "
            f"lower-case DNS name (letters, digits, hyphens and dots; "
            f"{DNS_NAME_PATTERN})")
    return value


def _require_beneath(path: Path, dotted: str, value: str, domain: str) -> str:
    """An FQDN under the identity domain, whose host label is legal.

    The same rule ``src/homelab/private-contract/validate.py`` applies to
    ``services.*``: a DC that is not beneath the identity domain would not be
    found through the AD DNS SRV records domain members are told to use.
    """
    _require_dns_name(path, dotted, value)
    suffix = "." + domain
    if not value.endswith(suffix) or len(value) <= len(suffix):
        raise DirectoryIdentityError(
            f"directory identity overlay {path} {dotted} {value!r} is not "
            f"beneath the identity domain {domain!r}")
    label = value[:-len(suffix)]
    if not _DNS_LABEL.match(label):
        raise DirectoryIdentityError(
            f"directory identity overlay {path} {dotted} host name {label!r} "
            f"is not a legal 1-15 character machine name ({DNS_LABEL_PATTERN}); "
            f"samba truncates a longer NetBIOS machine name silently, so the "
            f"machine account would not match the host")
    return value


def directory_identity_source(path: Path | None = None) -> str:
    """Name, in one short phrase, WHERE a permanent identity came from.

    Every refusal and every plan quotes this.  A reader of a serial transcript
    must be able to tell which file the realm they are about to make permanent
    was read from.
    """
    if path is None:
        path = directory_identity_path()
    return f"private overlay {path}"


def durable_directory_identity(
    path: Path | None = None,
) -> DirectoryIdentity:
    """Resolve the identity a DURABLE directory may be provisioned under.

    There is no ``require_overlay`` switch and no default: this function has
    exactly one behaviour, because there is no caller for whom the synthetic
    acceptance realm would be an acceptable answer.  The disposable acceptance
    Controller never calls it -- gates 3 through 12 keep constructing
    ``FactorySpec()`` directly, so with no overlay present every acceptance
    value stays byte-identical.

    *path* exists for the same reason the durable roster loader takes one: a
    test must be able to resolve an identity it wrote itself, without reading
    whatever private overlay the developer's own machine happens to carry.
    """
    if path is None:
        path = directory_identity_path()
    path = Path(path)
    document = _read_document(path)
    values = _collect(path, document)

    domain = _require_dns_name(path, "identity.dns_domain",
                               values["identity.dns_domain"])
    # ADR 0005 reserves home.arpa for the internal namespace and ADR 0065 makes
    # the identity domain a child of it.  The suffix itself is not a domain.
    suffix = "." + DNS_SUFFIX
    if not domain.endswith(suffix) or len(domain) <= len(suffix):
        raise DirectoryIdentityError(
            f"directory identity overlay {path} identity.dns_domain "
            f"{domain!r} is not beneath the reserved {DNS_SUFFIX} suffix "
            f"(ADR 0005, ADR 0065); it must be <name>.{DNS_SUFFIX}")

    realm = values["identity.kerberos_realm"]
    if not isinstance(realm, str) or realm != domain.upper():
        raise DirectoryIdentityError(
            f"directory identity overlay {path} identity.kerberos_realm "
            f"{realm!r} is not the upper-case form of identity.dns_domain "
            f"{domain!r}; ADR 0065 requires exactly {domain.upper()!r}. A "
            f"mismatched pair provisions cleanly and only surfaces at the "
            f"first Kerberos login")

    netbios = values["identity.netbios_name"]
    if not isinstance(netbios, str) or not _NETBIOS_NAME.match(netbios):
        raise DirectoryIdentityError(
            f"directory identity overlay {path} identity.netbios_name "
            f"{netbios!r} is not 1-15 upper-case letters, digits or hyphens "
            f"({NETBIOS_NAME_PATTERN}); a longer name is truncated silently "
            f"and the pre-Windows-2000 domain name is permanent")

    bootstrap = _require_beneath(
        path, "services.bootstrap_dc_fqdn",
        values["services.bootstrap_dc_fqdn"], domain)
    permanent = _require_beneath(
        path, "services.permanent_dc_fqdn",
        values["services.permanent_dc_fqdn"], domain)
    if bootstrap == permanent:
        raise DirectoryIdentityError(
            f"directory identity overlay {path} gives the bootstrap and "
            f"permanent controllers the same FQDN {bootstrap!r}; ADR 0065 "
            f"exists so clients survive replacing the first controller, which "
            f"needs two names")

    prefix = values["network.prefix"]
    if isinstance(prefix, bool) or not isinstance(prefix, int):
        raise DirectoryIdentityError(
            f"directory identity overlay {path} network.prefix {prefix!r} "
            f"must be a JSON number, not a string")
    if not 0 <= prefix <= 32:
        raise DirectoryIdentityError(
            f"directory identity overlay {path} network.prefix /{prefix} is "
            f"out of range")
    address = values["network.address"]
    gateway = values["network.gateway"]
    try:
        subnet = ipaddress.IPv4Network((str(address), prefix), strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError,
            ValueError) as error:
        raise DirectoryIdentityError(
            f"directory identity overlay {path} network.address {address!r} "
            f"and network.prefix /{prefix} are not an IPv4 address and "
            f"prefix ({error})") from error
    try:
        # One implementation of the ADR 0045 address rules, in lib/netplan:
        # four unambiguous decimal octets, inside the subnet, and neither the
        # network nor the broadcast address.
        check_usable_address(
            str(address), subnet.with_prefixlen, "network.address")
        check_usable_address(
            str(gateway), subnet.with_prefixlen, "network.gateway")
    except NetworkPlanError as error:
        raise DirectoryIdentityError(
            f"directory identity overlay {path} {error}") from error
    if str(address) == str(gateway):
        raise DirectoryIdentityError(
            f"directory identity overlay {path} gives network.address and "
            f"network.gateway the same address {address!r}")

    return DirectoryIdentity(
        dns_domain=domain,
        kerberos_realm=realm,
        netbios_name=netbios,
        bootstrap_dc_fqdn=bootstrap,
        permanent_dc_fqdn=permanent,
        address=str(address),
        prefix=prefix,
        gateway=str(gateway),
        source=path,
    )
