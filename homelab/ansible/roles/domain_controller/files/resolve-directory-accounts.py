#!/usr/bin/env python3
"""Render this role's durable-account variables from the ONE identity roster.

Why this program exists at all
------------------------------
Real account names are instance data (ADR 0046), so they are declared exactly
once, in the owner's gitignored private overlay:

    homelab/instance/identity/principals.json

``homelab/workstations/arch_second.identity_roster`` is the single loader that
resolves that overlay against the tracked identity-lifecycle contract, and
``homelab/vm/controller_principals.directory_account_plan`` is the single rule
that turns a resolved roster into directory POSIX identities.  The workstation
disk, the disposable acceptance Controller and this role therefore all follow
one declaration and one UID rule.

The bridge this program IS
--------------------------
This role's *provisioning driver* (files/provision-accounts.py) runs INSIDE the
Controller, where only ``homelab/ansible`` has been staged, so it cannot import
either module -- and it must not: staging the owner's private identity overlay
into a guest would spread instance data for no reason.  So the derivation runs
on the Ansible CONTROL HOST, where the whole repository is present, and the
guest receives nothing but the finished plan as ordinary Ansible data.  That is
why the role invokes this program with ``delegate_to: localhost``.

It prints ONE JSON document on stdout and nothing else.  It reads no credential
and takes no password argument: a durable account's credential reaches Samba
only through the driver, which opens a root-owned 0600 file on the target
itself.

Besides the declared roles, the plan always carries every ADDITIONAL standard
user the overlay lists under ``additional_standard_users``: durable-only
accounts with no contract role, planned as plain ``standard`` accounts under a
name-free ``contract_role`` label (``additional_standard_user_<uidNumber>``)
and reported again, as labels, in the document's ``additional_standard_users``
so the role can check the plan against both declarations.

Refusals are named and fail closed.  In particular it refuses ``local_rescue``:
ADR 0055/0063 keep the break-glass administrator a LOCAL account at UID 1000 on
the workstation, never a directory principal.  And it refuses to fill a
declared role from the synthetic acceptance roster: the accounts it plans are
permanent, so a missing overlay, or one that leaves a declared role unnamed,
stops convergence rather than minting the acceptance accounts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# files/ -> domain_controller -> roles -> ansible -> homelab -> repository root.
_REPOSITORY = Path(__file__).resolve().parent.parents[4]
_LOADER = _REPOSITORY / "homelab" / "vm" / "controller_principals.py"


# The same two constants files/provision-accounts.py enforces at the moment of
# use, restated here so a roster that names a reserved directory object is
# refused on the CONTROL HOST -- before a driver is installed on the target and
# before anything is looked up in the directory. A unit test asserts the two
# copies agree. See the driver for why each entry is on the list.
RESERVED_NAMES = frozenset({
    "administrator", "guest", "krbtgt",
    "root", "daemon", "bin", "sys", "nobody",
})
RESERVED_PREFIXES = ("dns-",)


class ResolverError(RuntimeError):
    """The plan cannot be rendered; convergence must stop before mutating."""


def _principals():
    """Import the one roster loader, or refuse with a diagnosable reason."""
    if not _LOADER.is_file():
        raise ResolverError(
            f"the identity roster loader is not reachable at {_LOADER}. This "
            "role's durable-account variables must be rendered on an Ansible "
            "control host that holds the whole repository; they are never "
            "derived inside the Controller, which carries only "
            "homelab/ansible.")
    if str(_REPOSITORY) not in sys.path:
        sys.path.insert(0, str(_REPOSITORY))
    try:
        from homelab.vm import controller_principals
    except Exception as error:  # noqa: BLE001 - reported, never swallowed
        raise ResolverError(
            f"the identity roster could not be resolved: "
            f"{type(error).__name__}: {error}") from error
    return controller_principals


def _roles(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _reserved(name: str) -> bool:
    """True when *name* is a directory object no roster may adopt."""
    folded = str(name).strip().lower()
    return (folded in RESERVED_NAMES
            or any(folded.startswith(prefix)
                   for prefix in RESERVED_PREFIXES))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render durable directory accounts from the one roster.")
    parser.add_argument(
        "--roles", required=True,
        help="comma-separated contract roles to converge as directory accounts")
    parser.add_argument(
        "--admin-group", required=True,
        help="the well-known group an `administrator` account must belong to")
    parser.add_argument(
        "--group-rids-json", required=True,
        help="the well-known groups that must carry a gidNumber, as "
             "{name: Active Directory RID}")
    parser.add_argument(
        "--identity-overlay", type=Path, default=None,
        help="resolve the roster against this private overlay instead of "
             "the one this checkout's instance/ holds, so a test of this "
             "program is independent of whatever overlay the developer's own "
             "machine happens to carry. Reads names, never a credential. A "
             "path that does not exist, or an overlay that leaves a declared "
             "role unnamed, is a refusal.")
    arguments = parser.parse_args(argv)

    principals = _principals()
    try:
        rids = json.loads(arguments.group_rids_json)
    except ValueError as error:
        raise ResolverError(
            f"--group-rids-json is not valid JSON: {error}") from error
    # The RIDs and the privilege-group name are declared by the role and checked
    # here rather than trusted: they are externally fixed Active Directory
    # constants, and a role whose declaration disagreed with the allocation
    # would verify a gidNumber nothing had staged.  The gidNumber ARITHMETIC is
    # not restated -- controller_principals owns the allocation, over the
    # numbers the roster loader judges.
    if rids != principals.POSIX_GROUP_RIDS:
        raise ResolverError(
            "the role's declared well-known group RIDs disagree with "
            f"{sorted(principals.POSIX_GROUP_RIDS)}; the directory POSIX "
            "allocation is owned by homelab/vm/controller_principals.py")
    if arguments.admin_group != principals.POSIX_ADMIN_GROUP:
        raise ResolverError(
            "the role's declared privilege group disagrees with "
            f"{principals.POSIX_ADMIN_GROUP!r}")

    # The role runs this program only when durable accounts are declared, so
    # the roster is the DURABLE one: the overlay must exist and must itself
    # name every declared directory role. Falling back to the synthetic
    # acceptance names here would mint permanent accounts nobody asked for.
    #
    # It is the whole durable DECLARATION, passed on as one object: each
    # directory role's uidNumber (the overlay's uid_number pin, else its
    # positional default) and every additional standard user the overlay lists
    # travel with the names, so the plan below cannot fall back to positional
    # numbers or drop one of those users.
    try:
        roster = principals.durable_directory_roster(
            arguments.identity_overlay, roles=_roles(arguments.roles))
    except Exception as error:  # noqa: BLE001 - reported, never swallowed
        raise ResolverError(
            f"the durable identity roster could not be resolved: "
            f"{type(error).__name__}: {error}") from error

    try:
        accounts = principals.directory_account_plan(
            _roles(arguments.roles), roster=roster)
    except principals.DirectoryPlanError as error:
        raise ResolverError(str(error)) from error

    # Refused here rather than only in the guest: this is the last point at
    # which nothing has been installed on the Controller and nothing has been
    # looked up in the directory. A reserved name is a roster fault, and a
    # roster fault must fail where the roster lives.
    for account in accounts:
        if _reserved(account["name"]):
            raise ResolverError(
                f"the account declared for {account['contract_role']} names a "
                "reserved directory object. The built-in domain accounts "
                "(Administrator, Guest, krbtgt), the per-DC DNS service "
                "account and the local UNIX system accounts belong to the "
                "directory and to every managed machine, not to a roster: "
                "adopting one would rewrite an account this domain depends "
                "on. Rename it in the private identity overlay.")

    document = {
        "schema": 1,
        "posix_base": principals.POSIX_BASE,
        "primary_group": principals.POSIX_PRIMARY_GROUP,
        "admin_group": principals.POSIX_ADMIN_GROUP,
        "groups": principals.directory_group_allocation(),
        "accounts": accounts,
        # The labels of the durable-only standard users the overlay declares,
        # reported apart from ``accounts`` so the role can require the plan to
        # hold exactly the declared roles PLUS exactly these -- no fewer, and
        # none it cannot account for. Empty when the overlay lists none.
        "additional_standard_users": [
            principals.additional_standard_user_label(user.uid_number)
            for user in roster.additional_standard_users
        ],
    }
    json.dump(document, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ResolverError as failure:
        print(f"error: {failure}", file=sys.stderr)
        raise SystemExit(2) from failure
