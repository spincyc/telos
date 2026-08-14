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

Refusals are named and fail closed.  In particular it refuses ``local_rescue``:
ADR 0055/0063 keep the break-glass administrator a LOCAL account at UID 1000 on
the workstation, never a directory principal.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# files/ -> domain_controller -> roles -> ansible -> homelab -> repository root.
_REPOSITORY = Path(__file__).resolve().parent.parents[4]
_LOADER = _REPOSITORY / "homelab" / "vm" / "controller_principals.py"


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
    # not restated -- it lives only in controller_principals.
    if rids != principals.POSIX_GROUP_RIDS:
        raise ResolverError(
            "the role's declared well-known group RIDs disagree with "
            f"{sorted(principals.POSIX_GROUP_RIDS)}; the directory POSIX "
            "allocation is owned by homelab/vm/controller_principals.py")
    if arguments.admin_group != principals.POSIX_ADMIN_GROUP:
        raise ResolverError(
            "the role's declared privilege group disagrees with "
            f"{principals.POSIX_ADMIN_GROUP!r}")

    try:
        accounts = principals.directory_account_plan(_roles(arguments.roles))
    except principals.DirectoryPlanError as error:
        raise ResolverError(str(error)) from error

    document = {
        "schema": 1,
        "posix_base": principals.POSIX_BASE,
        "primary_group": principals.POSIX_PRIMARY_GROUP,
        "admin_group": principals.POSIX_ADMIN_GROUP,
        "groups": principals.directory_group_allocation(),
        "accounts": accounts,
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
