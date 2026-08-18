#!/usr/bin/env python3
"""Render the identity variables from the ONE permanent declaration.

Why this program exists at all
------------------------------
ADR 0065 freezes five values before the first domain is provisioned: the DNS
domain beneath ADR 0005's reserved ``home.arpa`` suffix, its upper-case
Kerberos realm, the NetBIOS name, and the bootstrap and permanent DC FQDNs.
The owner declares them once, in the gitignored private overlay

    homelab/instance/identity/directory.json

and ``homelab/vm/directory_identity.py`` is the single loader that validates
them.  The SIMULATED persistent Controller is converged over its serial console
from exactly that document.

Until this program existed the HOST-SIDE Ansible path declared the same
permanent values a second and a third time, in YAML, and nothing checked that
any of them agreed:

    roles/domain_controller/defaults  homelab_ad_dns_domain
                                      homelab_ad_realm
                                      homelab_ad_netbios_domain
                                      homelab_ad_expected_hostname
    roles/identity_client/defaults    homelab_identity_domain
                                      homelab_identity_realm
                                      homelab_identity_netbios_domain
                                      homelab_identity_domain_controller

That is not a tidiness problem.  ``identity_client`` renders
``homelab_identity_realm`` into every workstation's ``sssd.conf`` and
``krb5.conf``, and ``homelab_identity_netbios_domain`` into its ``smb.conf``
workgroup; ``domain_controller`` provisions the directory from
``homelab_ad_realm`` and ``homelab_ad_netbios_domain``.  A workstation built
against one realm and a Controller converged under another fails at the first
login -- after the expensive part -- and the realm and the NetBIOS name are the
two values ADR 0065 records as effectively permanent, so the recovery is a
directory migration and not a re-run.  In physical UAT the host-side path stops
being theoretical, which is why the agreement is now proved rather than
maintained by hand.

The bridge this program IS
--------------------------
The same shape as ``roles/domain_controller/files/resolve-directory-accounts.py``
and for the same reason.  It sits beside the roles rather than inside one
because it belongs to neither: ``tasks/directory-identity.yml`` next to it is
included by both, so a single invocation reconciles both families at once.
That placement is what makes divergence impossible rather than merely
unlikely -- there is no second invocation to disagree with.  The Controller carries only ``homelab/ansible``, so
nothing inside a guest can import the loader -- and it must not: staging the
owner's private overlay into a guest would spread instance data (ADR 0046) for
no reason.  The derivation therefore runs on the Ansible CONTROL HOST, where
the whole repository is present, and the target receives nothing but the
finished values as ordinary Ansible data.  That is why the role invokes this
program with ``delegate_to: localhost``.

It prints ONE JSON document on stdout and nothing else.  It reads no credential.

Fail closed in BOTH directions
------------------------------
* ``directory.json`` present -> it is authoritative.  A YAML variable that is
  *also* set, to a *different* value, is refused by name, quoting both values
  and naming both files.  Neither declaration is silently preferred: an owner
  who edits one of two copies must be told which two disagree, not have their
  edit discarded.
* ``directory.json`` absent -> nothing is invented.  The variables stay exactly
  as declared and each role's own first task keeps requiring them, precisely as
  before this program existed.  An absent document must never mean "use the
  acceptance realm": the disposable acceptance Controller has no document, and
  gates 3 through 12 converge it under ``ad.factory.test``/``FACTORY`` from the
  factory bundle's ``factory-vars.json``.  Inventing a fallback here would
  either break every gate or, far worse, provision a real domain under the
  synthetic realm, whose SID cannot be renamed afterwards.
* The two YAML families are cross-checked against each other even with no
  document at all, because two hand-set copies of a realm can disagree whether
  or not a third declaration exists.

Where it is running
-------------------
The repository is found from this file's own location.  Reached from a control
host it resolves; reached from the payload a factory bundle stages inside a
guest (``/opt/telos-factory/ansible/files/...``) it does not, and there is no
private overlay in a guest to consult either.  That case is the "no document"
case above and is exactly what keeps the acceptance path untouched.  An
explicitly named ``--document`` that cannot be validated is a refusal, never a
fallback.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# files/ -> ansible -> homelab -> repository.
_REPOSITORY = Path(__file__).resolve().parent.parents[2]
_LOADER = _REPOSITORY / "homelab" / "vm" / "directory_identity.py"

#: Bumped only when a key is removed or changes meaning.  The roles assert it.
SCHEMA = 1

#: The one table that says the six YAML variables are three values.  Both
#: families are reconciled in a single invocation, which is what makes it
#: impossible for the ``identity_client`` realm and the ``domain_controller``
#: realm to diverge: they are compared against each other here, and against the
#: document, before either role renders a template.
IDENTITY_FIELDS = {
    "dns_domain": ("homelab_ad_dns_domain", "homelab_identity_domain"),
    "kerberos_realm": ("homelab_ad_realm", "homelab_identity_realm"),
    "netbios_name": (
        "homelab_ad_netbios_domain", "homelab_identity_netbios_domain"),
}
#: field -> the dotted key the document spells it with, for the refusal text.
DOCUMENT_KEYS = {
    "dns_domain": "identity.dns_domain",
    "kerberos_realm": "identity.kerberos_realm",
    "netbios_name": "identity.netbios_name",
}
#: Every variable this program has an opinion about, so the roles can pass one
#: dictionary and a test can prove none is forgotten.
DECLARED_VARIABLES = tuple(
    name for names in IDENTITY_FIELDS.values() for name in names
) + ("homelab_ad_expected_hostname", "homelab_identity_domain_controller")


class IdentityResolverError(RuntimeError):
    """The identity cannot be resolved; convergence must stop before mutating."""


def _loader():
    """Import the one directory-identity loader, or say it is out of reach."""
    if str(_REPOSITORY) not in sys.path:
        sys.path.insert(0, str(_REPOSITORY))
    try:
        from homelab.vm import directory_identity
    except Exception as error:  # noqa: BLE001 - reported, never swallowed
        raise IdentityResolverError(
            f"the permanent directory identity loader could not be imported "
            f"from {_LOADER}: {type(error).__name__}: {error}") from error
    return directory_identity


def _document_path(argument: str | None) -> Path | None:
    """Which document to read, or ``None`` for "there is none to read".

    An explicit ``--document`` is honoured wherever this runs, so a test can
    resolve a fixture it wrote itself rather than whatever private overlay the
    developer's machine happens to carry -- the same reason
    ``resolve-directory-accounts.py`` takes ``--identity-overlay``.
    """
    if argument:
        return Path(argument)
    if not _LOADER.is_file():
        # The staged factory payload: only homelab/ansible is present, there is
        # no repository above it and no private overlay inside a guest. Nothing
        # to consult, and nothing invented.
        return None
    return _REPOSITORY / "homelab" / "instance" / "identity" / "directory.json"


def _read(path: Path):
    """The validated identity, or ``None`` when the document is simply absent.

    ``os.lstat`` rather than ``Path.exists()`` for the reason the loader gives:
    on Python 3.13 and later ``exists()`` swallows every ``OSError``, so a
    document under a directory this process cannot search would read as "not
    there".  Absent is permitted; unknown is a refusal.
    """
    try:
        os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise IdentityResolverError(
            f"the permanent directory identity document {path} could not be "
            f"examined ({error.strerror or type(error).__name__}); a document "
            f"whose state is unknown is a refusal, never a fallback") from error
    loader = _loader()
    try:
        return loader.durable_directory_identity(path)
    except loader.DirectoryIdentityError as error:
        raise IdentityResolverError(str(error)) from error


def _declared(raw: str) -> dict[str, str]:
    try:
        declared = json.loads(raw)
    except ValueError as error:
        raise IdentityResolverError(
            f"--declared-json is not valid JSON: {error}") from error
    if not isinstance(declared, dict):
        raise IdentityResolverError("--declared-json is not a JSON object")
    unknown = sorted(set(declared) - set(DECLARED_VARIABLES))
    if unknown:
        raise IdentityResolverError(
            f"--declared-json carries {unknown[0]!r}, which is not one of the "
            f"identity variables this program reconciles "
            f"({', '.join(DECLARED_VARIABLES)})")
    # Ansible renders an undefined variable's default as an empty string, and
    # an empty string is "not declared here" for every one of these.
    return {name: str(value).strip()
            for name, value in declared.items()
            if str(value).strip()}


def _disagree(variable, value, expected, dotted, document, source) -> str:
    return (
        f"the permanent directory identity is declared twice and the two "
        f"declarations disagree.\n"
        f"  {variable} = {value!r}\n"
        f"      declared in {source}\n"
        f"  {dotted} = {expected!r}\n"
        f"      declared in {document}\n"
        f"ADR 0065 freezes this value, so one of the two is already wrong "
        f"about a domain that cannot be renamed. {document} is the single "
        f"declaration: either correct it, or delete {variable} from the "
        f"inventory and let it be derived. Nothing has been changed on any "
        f"host.")


def _reconcile_against_document(identity, declared, source) -> dict:
    """The document wins, but only after every disagreement has been named."""
    document = identity.source
    expected = {
        "dns_domain": identity.dns_domain,
        "kerberos_realm": identity.kerberos_realm,
        "netbios_name": identity.netbios_name,
    }
    for field, variables in IDENTITY_FIELDS.items():
        for variable in variables:
            value = declared.get(variable)
            if value is not None and value != expected[field]:
                raise IdentityResolverError(_disagree(
                    variable, value, expected[field], DOCUMENT_KEYS[field],
                    document, source))

    controllers = (identity.bootstrap_dc_fqdn, identity.permanent_dc_fqdn)
    hostnames = [fqdn.split(".", 1)[0] for fqdn in controllers]

    # ADR 0065 froze exactly two Controllers, so "the machine this play is
    # aimed at" is a closed set of two rather than a free-form string. In
    # physical UAT the play reaches a real machine over SSH for the first time,
    # and a hostname that is neither of them is a machine nobody decided to
    # make a domain controller.
    hostname = declared.get("homelab_ad_expected_hostname")
    if hostname is not None and hostname not in hostnames:
        raise IdentityResolverError(
            f"homelab_ad_expected_hostname = {hostname!r}, declared in "
            f"{source}, is neither Controller ADR 0065 froze in {document}: "
            f"services.bootstrap_dc_fqdn {identity.bootstrap_dc_fqdn!r} "
            f"(short name {hostnames[0]!r}) and services.permanent_dc_fqdn "
            f"{identity.permanent_dc_fqdn!r} (short name {hostnames[1]!r}). "
            f"Delete the variable to have the Controller's own short name "
            f"derived from whichever of the two it is.")

    controller = declared.get("homelab_identity_domain_controller")
    if controller is not None and controller not in controllers:
        raise IdentityResolverError(
            f"homelab_identity_domain_controller = {controller!r}, declared "
            f"in {source}, is neither Controller ADR 0065 froze in "
            f"{document}: services.bootstrap_dc_fqdn "
            f"{identity.bootstrap_dc_fqdn!r} and services.permanent_dc_fqdn "
            f"{identity.permanent_dc_fqdn!r}. SSSD's ad_server must name a "
            f"controller this domain actually has, or every login depends on "
            f"a name nothing publishes.")

    return {
        "schema": SCHEMA,
        "document": str(document),
        "source": f"private overlay {document}",
        "dns_domain": identity.dns_domain,
        "kerberos_realm": identity.kerberos_realm,
        "netbios_name": identity.netbios_name,
        "bootstrap_dc_fqdn": identity.bootstrap_dc_fqdn,
        "permanent_dc_fqdn": identity.permanent_dc_fqdn,
        "controller_fqdns": list(controllers),
        "controller_hostnames": hostnames,
    }


def _reconcile_without_document(declared, source) -> dict:
    """No document: invent nothing, but still refuse two copies that disagree.

    The document is the single declaration once it exists.  Until it does, the
    two YAML families are still two copies of one permanent value, and a
    workstation whose ``sssd.conf`` names a different realm than the Controller
    was provisioned under is the same first-login failure.  Each role's own
    first task keeps requiring the values it needs, so this function never
    turns an empty variable into a refusal -- that would break the disposable
    acceptance path, which declares only the ``homelab_ad_*`` family.
    """
    resolved = {}
    for field, (ad_variable, client_variable) in IDENTITY_FIELDS.items():
        ad_value = declared.get(ad_variable)
        client_value = declared.get(client_variable)
        if (ad_value is not None and client_value is not None
                and ad_value != client_value):
            raise IdentityResolverError(
                f"the permanent directory identity is declared twice in "
                f"{source} and the two declarations disagree.\n"
                f"  {ad_variable} = {ad_value!r}\n"
                f"      provisions the directory (roles/domain_controller)\n"
                f"  {client_variable} = {client_value!r}\n"
                f"      is rendered into every client's sssd.conf, krb5.conf "
                f"and smb.conf (roles/identity_client)\n"
                f"A client pointed at a different realm than the Controller "
                f"was provisioned under fails at the first login, and ADR 0065 "
                f"records the realm and NetBIOS name as effectively permanent. "
                f"Declare the identity once, in "
                f"homelab/instance/identity/directory.json, and both are "
                f"derived from it.")
        resolved[field] = ad_value or client_value or ""
    return {
        "schema": SCHEMA,
        "document": "",
        "source": source,
        "dns_domain": resolved["dns_domain"],
        "kerberos_realm": resolved["kerberos_realm"],
        "netbios_name": resolved["netbios_name"],
        "bootstrap_dc_fqdn": "",
        "permanent_dc_fqdn": "",
        "controller_fqdns": [],
        "controller_hostnames": [],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Derive the Ansible identity variables from ADR 0065's "
                    "one permanent declaration, or prove they agree with it.")
    parser.add_argument(
        "--declared-json", required=True,
        help="the identity variables the inventory declares, as a JSON "
             "object. An empty value means the variable is not declared.")
    parser.add_argument(
        "--document", default="",
        help="read this permanent-identity document instead of the one this "
             "checkout's instance/ holds. A path that does not exist is the "
             "no-document case, which is what makes a test of this program "
             "independent of whatever private overlay the developer's own "
             "machine happens to carry.")
    parser.add_argument(
        "--declared-source", default="the Ansible inventory",
        help="how to name the place the YAML variables came from, in a "
             "refusal. The inventory file, where the run knows it.")
    arguments = parser.parse_args(argv)

    declared = _declared(arguments.declared_json)
    source = arguments.declared_source.strip() or "the Ansible inventory"
    path = _document_path(arguments.document)
    identity = _read(path) if path is not None else None

    document = (_reconcile_against_document(identity, declared, source)
                if identity is not None
                else _reconcile_without_document(declared, source))
    json.dump(document, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except IdentityResolverError as failure:
        print(f"error: {failure}", file=sys.stderr)
        raise SystemExit(2) from failure
