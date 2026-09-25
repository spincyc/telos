#!/usr/bin/env python3
"""Stage and destroy disposable Samba principals over a serial console."""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
import json
from pathlib import Path
import re
import sys
from typing import BinaryIO, Mapping, Sequence
import uuid

from .serial_automation import SerialAutomation, SerialAutomationError

# The gate-7 installer renderer under workstations/ owns the ONE roster loader:
# the same resolution that bakes the principal names onto an installed disk also
# fixes which principals this module stages in the directory, so the two cannot
# drift.  Imported by path, exactly as vm/arch_identity_run.py imports the judge
# beside it, because this module is imported both as
# ``homelab.vm.controller_principals`` and as ``vm.controller_principals`` and a
# ``..workstations`` relative import reaches beyond the top-level package in the
# second case.
_WORKSTATIONS = Path(__file__).resolve().parents[1] / "workstations"
if str(_WORKSTATIONS) not in sys.path:
    sys.path.insert(0, str(_WORKSTATIONS))
from arch_second import (  # noqa: E402
    CONTRACT_ROLES,
    DIRECTORY_GROUP_RIDS,
    DIRECTORY_ROLES,
    DIRECTORY_UID_BASE,
    DIRECTORY_UID_MAX,
    IdentityRosterError,
    directory_group_gids,
    directory_uid_numbers,
    identity_declaration,
    identity_roster_fingerprint,
    identity_roster_source,
    validate_directory_identifiers,
)


class ControllerPrincipalError(RuntimeError):
    """The Controller did not prove a principal operation completed."""


@dataclass(frozen=True)
class ControllerPrincipalResult:
    """Secret-free facts from one Controller principal operation."""

    operation: str
    principals: tuple[str, ...]
    events: tuple[str, ...]


# The three DIRECTORY principals, resolved by the one roster loader that also
# bakes the names onto the installed workstation disk
# (workstations/arch_second.identity_roster: the tracked identity-lifecycle
# contract, optionally patched by the owner's gitignored private overlay).
# Reading them here instead of pinning a second hardcoded tuple is what stops
# the two historical sources of principal names from drifting apart; with no
# overlay present these are exactly ("student", "operator", "directory-admin").
_DECLARATION = identity_declaration()
_ROSTER = dict(_DECLARATION.roster)
# What every DISPOSABLE lane stages: the overlay's names AND its uid_number
# pins -- so a rehearsal exercises the numbers production will hold, and gate
# 8's storage check compares against them -- but never its additional standard
# users.  Those exist only in the owner's durable directory; an acceptance run
# neither creates nor checks them.
_ACCEPTANCE = replace(_DECLARATION, additional_standard_users=())
_ROLES = tuple(_ROSTER[role] for role in DIRECTORY_ROLES)
_DOMAIN_ADMIN = _ROSTER["domain_administrator"]
# Where _ROSTER came from, for every refusal below.  A rejected roster used to
# be reported as a bare "Controller principal roster is invalid", which named
# neither the contract nor the owner's private overlay -- and the Windows lane
# hit it from inside stage_controller_principals, where a transcript is all the
# reader has.
ROSTER_SOURCE = identity_roster_source()
# The SINGLE public name for each directory principal, and the tuple of all
# three in DIRECTORY_ROLES order.  The Windows lane (windows_identity_run,
# windows_identity_orchestrator, windows_identity_adapter, windows_join_iso,
# controller_join_material) reads these instead of restating
# ("student", "operator", "directory-admin") -- the hardcoded literals that
# made an overlay-renamed roster fail at stage_controller_principals with
# "Controller principal roster is invalid".  Same derivation the Arch lane
# already used through POSIX_ALLOCATION["users"]; these constants just spell
# one role's name where the whole allocation is not wanted.
DIRECTORY_PRINCIPALS = _ROLES
STANDARD_USER = _ROSTER["standard_user"]
DAILY_ADMINISTRATOR = _ROSTER["daily_administrator"]
DOMAIN_ADMINISTRATOR = _ROSTER["domain_administrator"]
# The second gate on the same names.  arch_second's SAFE_PRINCIPAL already
# refused anything that would need quoting; this one is deliberately kept as
# well, because these names are substituted into a Python program that runs
# inside the Controller and into JSON that travels as one shell word.
_SAFE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
if any(not _SAFE_NAME.fullmatch(name) for name in _ROLES) \
        or len(set(_ROLES)) != len(_ROLES):
    # Import-time and unconditional: a roster this module could not safely bake
    # into a guest program must stop the process here, not at the serial console
    # inside a disposable VM.
    raise ValueError(
        f"Controller principal roster is invalid; source: {ROSTER_SOURCE}")

# ADR 0055: UID and GID come from the directory.  The Arch Workstation lane
# runs SSSD with ``ldap_id_mapping = False`` (identity_client role), so a
# principal without directory-stored POSIX attributes cannot log in at all.
#
# THIS IS THE ONE DIRECTORY POSIX ALLOCATION RULE.  It is deterministic and
# public:
#
#   users:  uidNumber = the ``uid_number`` the owner's private overlay pins for
#           the role, if it pins one; otherwise 10000 + the principal's ROLE
#           position in arch_second.DIRECTORY_ROLES (standard user, daily
#           administrator, domain administrator -- the same order the old
#           hardcoded roster had, so with no pin the numbers are unchanged).
#           A durable-only additional standard user carries its own, required,
#           ``uid_number``.
#   groups: gidNumber = 10000 + the group's well-known Active Directory RID
#           (Domain Admins 512 -> 10512, Domain Users 513 -> 10513)
#
# The NUMBERS -- base, ceiling, group RIDs, pin-or-position, and every refusal
# of a number that cannot work -- are written once, beside the roster loader
# (arch_second.directory_uid_numbers and validate_directory_identifiers),
# because a pin is declared in the overlay and must be judged where the overlay
# is read.  This module turns them into ACCOUNTS: primary group, shell, home,
# durable plans and guest programs.
#
# Keying the default on the ROLE rather than on the NAME is what makes it safe
# for the owner to rename a principal: renaming standard_user moves no UID,
# because "10000" belongs to the standard-user role and not to the string
# "student".  Appending a role appends a UID and moves none of the existing
# ones, because the position of every earlier role is unchanged.  A pin moves
# only the role that carries it, and never silently shifts another: a pin equal
# to another role's number is refused.
#
# Both consumers derive their numbers from ``directory_account_plan`` below and
# neither restates the arithmetic:
#
#   * the disposable acceptance roster this module stages over the Controller
#     serial (POSIX_ALLOCATION, _STAGE_PROGRAM);
#   * the DURABLE roster ansible/roles/domain_controller converges on a
#     persistent instance, whose variables are rendered on the Ansible control
#     host by that role's files/resolve-directory-accounts.py -- the role's own
#     YAML no longer keys anything on declaration order.
#
# Every user's gidNumber is the Domain Users gidNumber because Domain Users
# (RID 513) is each account's Active Directory primary group.  The base sits
# far above the workstations' first local ordinary-user UID (1000, the
# break-glass account), which ADR 0055 requires to stay local.
_POSIX_BASE = DIRECTORY_UID_BASE
_POSIX_UID_MAX = DIRECTORY_UID_MAX
_POSIX_LOGIN_SHELL = "/bin/bash"
_POSIX_HOME_ROOT = "/home"
_POSIX_PRIMARY_GROUP = "Domain Users"
# "Domain Admins" is the privilege group the Arch identity probe resolves
# with getent (workstations/arch_second.py); both groups must own a
# gidNumber before any SSSD client can resolve them.
_POSIX_GROUP_RIDS = dict(DIRECTORY_GROUP_RIDS)
_POSIX_ADMIN_GROUP = "Domain Admins"

# The public names of the same constants, for readers outside this module (the
# domain_controller role's control-host resolver).  Underscored aliases are kept
# because this module's own tests and templates already read them.
POSIX_BASE = _POSIX_BASE
POSIX_UID_MAX = _POSIX_UID_MAX
POSIX_LOGIN_SHELL = _POSIX_LOGIN_SHELL
POSIX_HOME_ROOT = _POSIX_HOME_ROOT
POSIX_PRIMARY_GROUP = _POSIX_PRIMARY_GROUP
POSIX_ADMIN_GROUP = _POSIX_ADMIN_GROUP
POSIX_GROUP_RIDS = dict(_POSIX_GROUP_RIDS)

# Which contract roles are DIRECTORY administrators, in the ``standard`` /
# ``administrator`` vocabulary the domain_controller role and its provisioning
# driver speak.  ``daily_administrator`` is deliberately absent: ADR 0055 makes
# the everyday elevated account a passworded-sudo administrator on the
# WORKSTATION and never a Domain Admins member, which is exactly the separation
# gate 8's ``domain-admin-separate`` check proves from the group's member list.
# The driver (files/provision-accounts.py) asserts the membership in BOTH
# directions, so a ``standard`` account that somehow held Domain Admins fails
# convergence rather than passing quietly.
DIRECTORY_ADMIN_ROLES = ("domain_administrator",)
# ``local_rescue`` never appears here at all.  DIRECTORY_ROLES already excludes
# it (ADR 0055/0063 keep the break-glass administrator a LOCAL account at UID
# 1000), and ``directory_account_plan`` refuses it by name so a hand-written
# instance variable cannot smuggle it into the directory.
LOCAL_ONLY_ROLES = tuple(
    role for role in CONTRACT_ROLES if role not in DIRECTORY_ROLES)

# How a durable plan names an ADDITIONAL standard user wherever the plan's
# ``contract_role`` goes: prompts, the plan printout, the instance marker, the
# domain_controller role's loop labels and its driver's diagnostic.  Such a
# user has no contract role, and its real name is instance data (ADR 0046), so
# it is labelled by its uidNumber instead -- unique by validation, stable when
# the overlay is reordered or the person renamed, and already public.  The
# domain_controller role matches the same pattern; a test holds the two equal.
ADDITIONAL_STANDARD_USER_LABEL = "additional_standard_user_{uid_number}"
ADDITIONAL_STANDARD_USER_PATTERN = r"^additional_standard_user_[0-9]+$"


def additional_standard_user_label(uid_number: int) -> str:
    """The name-free label an additional standard user is planned under."""
    return ADDITIONAL_STANDARD_USER_LABEL.format(uid_number=uid_number)


class DirectoryPlanError(ValueError):
    """A durable directory roster cannot be derived from the contract roles.

    Distinctly named so the domain_controller role's control-host resolver can
    report a roster fault as a roster fault.  A refusal here stops convergence
    before anything is installed on the Controller, which is the only place a
    misdeclared role is cheap to diagnose.
    """


def _validated_roster(roster: Mapping[str, str]) -> dict[str, str]:
    """Refuse a caller-supplied roster before it can collapse an allocation.

    ``identity_roster`` already applies exactly these gates, so the resolved
    roster arrives pre-checked.  But *roster* is a PUBLIC parameter of
    ``directory_account_plan``, and the durable path (the domain_controller
    role's control-host resolver) reaches it with a mapping this module never
    loaded.  Without this, two roles sharing a name collapsed silently: the
    allocation keys ``users`` by NAME, so the second role overwrote the first,
    the plan came back one account short, and every downstream check still
    passed.
    """
    missing = [role for role in DIRECTORY_ROLES if role not in roster]
    if missing:
        raise DirectoryPlanError(
            f"directory roster declares no name for {missing[0]!r}; "
            f"roster source: {ROSTER_SOURCE}")
    names = [roster[role] for role in DIRECTORY_ROLES]
    for role, name in zip(DIRECTORY_ROLES, names):
        if not isinstance(name, str) or not _SAFE_NAME.fullmatch(name):
            raise DirectoryPlanError(
                f"directory roster name for {role!r} is not safely "
                f"representable; roster source: {ROSTER_SOURCE}")
    if len(set(names)) != len(names):
        raise DirectoryPlanError(
            "directory roster names are not distinct, so the POSIX allocation "
            f"would silently collapse two roles into one account; roster "
            f"source: {ROSTER_SOURCE}")
    return {role: roster[role] for role in DIRECTORY_ROLES}


def _declared(
    roster: object = None,
) -> tuple[dict[str, str], dict[str, int], tuple]:
    """``(names, uidNumbers, additional users)`` for one *roster* argument.

    Every public entry point below takes one *roster*, in one of three shapes:

    * ``None`` -- the disposable acceptance declaration resolved at import:
      the overlay's names and ``uid_number`` pins, never its additional
      standard users.
    * a DECLARATION -- ``durable_directory_roster()``'s result, or anything
      else carrying ``roster``, ``uid_numbers`` and
      ``additional_standard_users`` attributes.  Its pins and its additional
      users go wherever it goes, so a durable caller cannot drop them by
      forgetting a second argument.  Recognised by those attributes rather than
      by class: ``arch_second`` is imported under more than one module name,
      and an ``isinstance`` miss here would silently fall through to
      positional numbers.
    * a bare ``{contract role: name}`` mapping -- a test's hand-built roster.
      It declares no pin and no additional user, so it gets exactly the
      positional numbers.

    Whatever the shape, the names and numbers are re-judged by the loader's
    own rule (``validate_directory_identifiers``), because a declaration is a
    public argument and the loader may never have seen it.
    """
    if roster is None:
        roster = _ACCEPTANCE
    uid_numbers = getattr(roster, "uid_numbers", None)
    if uid_numbers is None:
        names: Mapping[str, str] = roster  # type: ignore[assignment]
        uid_numbers = directory_uid_numbers()
        additional: tuple = ()
        source = ROSTER_SOURCE
    else:
        names = roster.roster  # type: ignore[attr-defined]
        additional = tuple(
            roster.additional_standard_users)  # type: ignore[attr-defined]
        source = getattr(roster, "source", ROSTER_SOURCE)
    validated = _validated_roster(names)
    try:
        validate_directory_identifiers(
            {role: names[role] for role in CONTRACT_ROLES if role in names},
            dict(uid_numbers), additional, source=source)
    except IdentityRosterError as error:
        raise DirectoryPlanError(str(error)) from error
    return validated, dict(uid_numbers), additional


def _allocation(
    names: Mapping[str, str],
    uid_numbers: Mapping[str, int],
    additional: Sequence,
) -> dict[str, dict]:
    """The POSIX records for one judged declaration, directory roles first."""
    groups = directory_group_gids()
    accounts = [(names[role], uid_numbers[role]) for role in DIRECTORY_ROLES]
    accounts += [(user.name, user.uid_number) for user in additional]
    users = {
        name: {
            "uidNumber": uid,
            "gidNumber": groups[_POSIX_PRIMARY_GROUP],
            "loginShell": _POSIX_LOGIN_SHELL,
            "unixHomeDirectory": _POSIX_HOME_ROOT + "/" + name,
        }
        for name, uid in accounts
    }
    return {"users": users, "groups": groups}


def _posix_allocation(roster: object = None) -> dict[str, dict]:
    """Derive the deterministic POSIX allocation from a resolved roster.

    *roster* is any shape ``_declared`` accepts.  It is a parameter so a test
    can prove the allocation for a renamed or pinned roster without reloading
    this module; the acceptance lanes always use the one resolved at import.
    """
    return _allocation(*_declared(roster))


def _validated_posix_allocation(
    allocation: Mapping[str, dict], accounts: int = len(DIRECTORY_ROLES),
) -> dict:
    """Refuse any POSIX allocation whose identifiers could collide.

    *accounts* is how many users the allocation must hold: the directory roles,
    plus a durable declaration's additional standard users.
    """
    users = allocation["users"]
    groups = allocation["groups"]
    uids = [user["uidNumber"] for user in users.values()]
    gids = list(groups.values())
    if any(not isinstance(uid, int) or isinstance(uid, bool)
           or not _POSIX_BASE <= uid <= _POSIX_UID_MAX for uid in uids):
        raise ValueError("Controller POSIX uidNumber is out of range")
    if any(not isinstance(gid, int) or gid < _POSIX_BASE for gid in gids):
        raise ValueError("Controller POSIX gidNumber is out of range")
    if len(set(uids)) != len(uids):
        raise ValueError("Controller POSIX uidNumber allocation collides")
    if len(set(gids)) != len(gids):
        raise ValueError("Controller POSIX gidNumber allocation collides")
    if set(uids) & set(gids):
        raise ValueError(
            "Controller POSIX user and group identifier ranges collide")
    if len(users) != accounts:
        raise ValueError(
            f"Controller POSIX allocation holds {len(users)} accounts for "
            f"{accounts} declared accounts")
    for user in users.values():
        if user["gidNumber"] not in gids:
            raise ValueError(
                "Controller POSIX primary group is not a staged group")
    return {"users": dict(users), "groups": dict(groups)}


POSIX_ALLOCATION = _validated_posix_allocation(_posix_allocation())


def directory_role(contract_role: str) -> str:
    """Map one contract role onto the directory's ``standard``/``administrator``.

    ``daily_administrator`` maps to ``standard`` on purpose (see
    DIRECTORY_ADMIN_ROLES): it is the workstation's passworded-sudo account and
    must NOT be a Domain Admins member.
    """
    if contract_role not in DIRECTORY_ROLES:
        raise DirectoryPlanError(
            f"{contract_role!r} is not a directory role")
    return ("administrator" if contract_role in DIRECTORY_ADMIN_ROLES
            else "standard")


def directory_account_plan(
    contract_roles: Sequence[str],
    roster: object = None,
) -> list[dict]:
    """Derive the durable directory accounts for *contract_roles*.

    The single derivation both lanes use.  *contract_roles* names WHICH contract
    roles become directory principals on this instance; it never names an
    account and never influences a uidNumber, because the returned list is
    ordered by each role's position in ``arch_second.DIRECTORY_ROLES`` and
    numbered by ``arch_second.directory_uid_numbers`` (the overlay's pin, else
    that position).  So the order the caller writes its roles in is immaterial,
    renaming an account in the private overlay moves no UID, and declaring one
    more role appends one UID.

    *roster* is any shape ``_declared`` accepts.  A DURABLE declaration
    (``durable_directory_roster()``) also contributes every additional standard
    user its overlay lists, after the roles and in the overlay's order, each a
    plain ``standard`` account whose ``contract_role`` is its name-free label
    (``additional_standard_user_label``).  They are planned whatever
    *contract_roles* says: they belong to no role, and a durable path that
    plans accounts at all plans every one the overlay declares.  The
    acceptance default (``None``) never carries any.
    """
    if isinstance(contract_roles, str):
        raise DirectoryPlanError("directory roles must be a list of roles")
    requested = list(contract_roles)
    if not requested:
        raise DirectoryPlanError("no directory role was declared")
    for role in requested:
        if not isinstance(role, str):
            raise DirectoryPlanError("directory role is not a string")
        if role in LOCAL_ONLY_ROLES:
            raise DirectoryPlanError(
                f"{role} is a LOCAL account (ADR 0055/0063) and must never "
                "become a directory principal")
        if role not in DIRECTORY_ROLES:
            raise DirectoryPlanError(
                f"{role!r} is not one of the contract's directory roles "
                f"{list(DIRECTORY_ROLES)}")
    if len(set(requested)) != len(requested):
        raise DirectoryPlanError("a directory role is declared twice")
    names, uid_numbers, additional = _declared(roster)
    allocation = _validated_posix_allocation(
        _allocation(names, uid_numbers, additional),
        accounts=len(DIRECTORY_ROLES) + len(additional))
    plan = []
    for role in DIRECTORY_ROLES:
        if role not in requested:
            continue
        name = names[role]
        unix = allocation["users"][name]
        plan.append({
            "contract_role": role,
            "name": name,
            "role": directory_role(role),
            "uidNumber": unix["uidNumber"],
            "gidNumber": unix["gidNumber"],
            "loginShell": unix["loginShell"],
            "unixHomeDirectory": unix["unixHomeDirectory"],
        })
    for user in additional:
        unix = allocation["users"][user.name]
        plan.append({
            "contract_role": additional_standard_user_label(user.uid_number),
            "name": user.name,
            # Never an administrator: nothing in the overlay can say otherwise,
            # and both durable paths verify Domain Admins membership in both
            # directions, so an additional user found in it fails convergence.
            "role": "standard",
            "uidNumber": unix["uidNumber"],
            "gidNumber": unix["gidNumber"],
            "loginShell": unix["loginShell"],
            "unixHomeDirectory": unix["unixHomeDirectory"],
        })
    return plan


def directory_group_allocation() -> dict[str, int]:
    """The well-known groups every SSSD client must be able to resolve."""
    return dict(_validated_posix_allocation(_posix_allocation())["groups"])


#: Samba AD's default password policy, which nothing in this repository
#: changes (no ``samba-tool domain passwordsettings`` anywhere): at least
#: seven characters, drawn from at least three character classes.
DIRECTORY_MIN_PASSWORD_LENGTH = 7
DIRECTORY_PASSWORD_CLASSES = 3


def directory_password_problem(password: str, account: str) -> str | None:
    """Why the directory would refuse *password* for *account*, or ``None``.

    A durable account's password is typed by the operator, and the directory
    judges it only inside the Controller, where the stage program's stderr is
    deliberately closed so no traceback can carry a credential. A refused
    password therefore used to surface as a bare "Controller stage returned 1"
    after a full boot (2026-09-25). This applies the same default rules on the
    host, before anything boots. The reason names the rule, never the value.
    """
    if len(password) < DIRECTORY_MIN_PASSWORD_LENGTH:
        return (f"is shorter than {DIRECTORY_MIN_PASSWORD_LENGTH} "
                "characters")
    classes = sum((
        any(character.isupper() for character in password),
        any(character.islower() for character in password),
        any(character.isdigit() for character in password),
        any(not character.isalnum() for character in password),
        any(character.isalpha() and not (
            character.isupper() or character.islower())
            for character in password),
    ))
    if classes < DIRECTORY_PASSWORD_CLASSES:
        return (f"uses fewer than {DIRECTORY_PASSWORD_CLASSES} of: uppercase "
                "letters, lowercase letters, digits, symbols")
    if len(account) >= 3 and account.casefold() in password.casefold():
        return "contains the account name"
    return None


def durable_directory_roster(
    overlay_path: Path | None = None,
    roles: Sequence[str] = DIRECTORY_ROLES,
):
    """Resolve the declaration a DURABLE directory may be provisioned from.

    ``identity_declaration(require_named=...)`` and nothing else, returned
    WHOLE: its ``roster`` (names), each directory role's ``uid_numbers``
    (pinned or positional) and the overlay's ``additional_standard_users``.
    Hand it, as one object, to ``directory_account_plan``, ``_programs`` or
    ``ControllerPrincipalSerial``; a caller that passes only ``.roster`` gets
    positional numbers and no additional users, which is the acceptance
    answer and never the durable one.

    The module roster resolved at import (``_ROSTER``) is deliberately NOT
    reused: it is allowed to fall back to the tracked contract's synthetic
    acceptance names, which is right for the disposable Controller every gate
    throws away and catastrophic for a persistent instance, where the resulting
    SIDs are permanent.  An operator who has not seeded the private overlay — or who
    mistyped its path — gets a refusal naming the exact file, never a
    directory full of ``student``/``operator`` accounts reported as a success.

    An overlay that EXISTS is not enough either.  It is a sparse patch, and the
    template ``make homelab-instance`` copies names nobody, so every directory
    role in *roles* must be named by the overlay itself.  Roles that are not
    directory roles are left to ``directory_account_plan`` to refuse, with its
    own reason.

    *overlay_path* exists for the same reason the domain_controller role's
    control-host resolver has ``--identity-overlay``: a test must be able to
    resolve a roster it wrote itself, without reading or writing whatever
    private overlay the developer's own machine happens to carry.
    """
    return identity_declaration(
        overlay_path=overlay_path, require_overlay=True,
        require_named=tuple(role for role in DIRECTORY_ROLES if role in roles))


PRINCIPAL_FAILURE_MARKER = b"__TELOS_PRINCIPAL_FAILURE="


def _principal_result_pattern(result: bytes) -> bytes:
    """The program's return code, and the failure category printed before it.

    Both are anchored on a real line ending (a serial read can stop mid-line;
    see ``arch_identity_run.measured_probe_pattern``). The category is
    diagnostic only: the return code alone decides success.
    """
    return (
        rb"(?:(?:^|\n)" + re.escape(PRINCIPAL_FAILURE_MARKER)
        + rb"(?P<reason>[a-z0-9+-]{1,96})(?=[\r\n])[\s\S]*?)?"
        + rb"(?:^|\n)" + re.escape(result) + rb"(?P<rc>[0-9]+)(?=[\r\n])")


def _programs(
    roster: object, *, first_logon: bool = False,
) -> tuple[str, str, tuple[str, ...]]:
    """Bake one resolved roster into the two guest programs, plus its order.

    The single place a roster becomes a guest program.  The module constants
    below are this function applied to the import-time acceptance declaration;
    a durable path applies it to the overlay-required declaration instead, so
    the two can differ in NAMES -- and a durable one by its additional standard
    users -- without ever differing in RULE: same POSIX allocation, same
    validation, same Domain Admins membership derived from the same role.

    The order is the directory roles, then any additional standard users.
    Those are created, verified and given a share root exactly like the
    standard user; the program adds ``roster["domain_administrator"]`` alone to
    Domain Admins, so no overlay can make one an administrator.
    """
    names, uid_numbers, additional = _declared(roster)
    roles = (tuple(names[role] for role in DIRECTORY_ROLES)
             + tuple(user.name for user in additional))
    allocation = _validated_posix_allocation(
        _allocation(names, uid_numbers, additional), accounts=len(roles))
    roster_json = _roster_json(
        roles, names["domain_administrator"], first_logon)
    return (
        _substituted(_STAGE_PROGRAM_TEMPLATE, roster_json, allocation),
        _substituted(_DESTROY_PROGRAM_TEMPLATE, roster_json, allocation),
        roles,
    )

# These programs run inside the disposable Controller.  Their source is
# encoded only to make it safe to place in one shell word; it contains no
# credential.  The @POSIX_JSON@ and @ROSTER_JSON@ tokens are substituted below
# with the public, deterministic POSIX_ALLOCATION and the resolved roster;
# secrets still travel exclusively over stdin.
#
# The roster is substituted rather than written literally so that renaming a
# principal in the private overlay cannot leave a stale hardcoded name behind
# in the guest program -- which would have failed as "unexpected principal
# roster" from inside a disposable VM, the least diagnosable place available.
#: The per-user share root gate 9 proves. The Ansible role declares the same
#: path as ``homelab_ad_share_root``; a guest program staged over the serial
#: console cannot read an Ansible variable, so the two are separate copies held
#: honest by a parity test rather than one import. Substituted as a JSON string
#: literal, so it can only ever be data in the program text.
SHARE_ROOT = "/srv/unas"

_STAGE_PROGRAM_TEMPLATE = r"""
import json
import sys

from ldb import FLAG_MOD_REPLACE, SCOPE_BASE, Message, MessageElement
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB

roster = json.loads('@ROSTER_JSON@')
order = roster["order"]
# Change-at-first-logon staging: the passwords typed are temporary, each
# account must change its password at its first logon, and the domain policy
# is lifted ONLY while these accounts are created, then restored and verified.
first_logon = roster.get("first_logon") is True
policy_saved = None
values = json.load(sys.stdin)
expected = set(order)
if set(values) != expected or len(order) != len(expected):
    raise ValueError("unexpected principal roster")
posix = json.loads('@POSIX_JSON@')
lp = LoadParm()
lp.load_default()
samdb = SamDB(session_info=system_session(), lp=lp)
created = []
realm = str(lp.get("realm")).upper()
attributes = [
    "sAMAccountName",
    "userPrincipalName",
    "userAccountControl",
    "msDS-User-Account-Control-Computed",
    "accountExpires",
    "lockoutTime",
    "badPwdCount",
    "pwdLastSet",
    "objectSid",
    "uidNumber",
    "gidNumber",
    "loginShell",
    "unixHomeDirectory",
]

def integers(record, attribute):
    return [int(str(value)) for value in record.get(attribute, [])]

def strings(record, attribute):
    return [str(value) for value in record.get(attribute, [])]

def password_policy():
    results = samdb.search(
        base=samdb.get_default_basedn(), scope=SCOPE_BASE,
        attrs=["pwdProperties", "minPwdLength"])
    if len(results) != 1:
        raise RuntimeError("domain password policy is not readable")
    properties = integers(results[0], "pwdProperties")
    length = integers(results[0], "minPwdLength")
    if len(properties) != 1 or len(length) != 1:
        raise RuntimeError("domain password policy is not readable")
    return properties[0], length[0]

def set_password_policy(properties, length):
    update = Message()
    update.dn = samdb.get_default_basedn()
    update["pwdProperties"] = MessageElement(
        str(properties), FLAG_MOD_REPLACE, "pwdProperties")
    update["minPwdLength"] = MessageElement(
        str(length), FLAG_MOD_REPLACE, "minPwdLength")
    samdb.modify(update)
    if password_policy() != (properties, length):
        raise RuntimeError("domain password policy did not take effect")

def failure_reason(error):
    # Printed on stdout because stderr is closed: a category, never a value.
    # The program's own raises carry fixed, name-free messages; an LdbError's
    # text can carry a DN, so only its code and a classification cross.
    import re as _re
    arguments = getattr(error, "args", ())
    if type(error).__name__ == "LdbError" and len(arguments) >= 2:
        code, message = arguments[0], str(arguments[1]).lower()
        if code == 19 and "password" in message:
            return "password-policy"
        if code == 68:
            return "account-exists"
        return "ldb-" + str(code) if isinstance(code, int) else "ldb"
    if (type(error) in (RuntimeError, ValueError) and arguments
            and isinstance(arguments[0], str)):
        return _re.sub(r"[^a-z0-9]+", "-", arguments[0].lower()).strip("-")[:80]
    return type(error).__name__.lower()

try:
    if first_logon:
        # Complexity is bit 1 of pwdProperties; every other bit is kept.
        policy_saved = password_policy()
        set_password_policy(policy_saved[0] & ~1, 0)
    # Groups first, so no staged user ever carries a gidNumber the
    # directory cannot resolve.  Replacing a deterministic gidNumber is
    # idempotent, so a failed stage needs no group rollback: the next
    # stage rewrites identical numbers and the Controller is disposable.
    for group in sorted(posix["groups"]):
        gid = posix["groups"][group]
        expression = "(&(objectClass=group)(sAMAccountName=" + group + "))"
        results = samdb.search(
            expression=expression, attrs=["sAMAccountName", "gidNumber"])
        if len(results) != 1:
            raise RuntimeError("posix group is not stored exactly once")
        update = Message()
        update.dn = results[0].dn
        update["gidNumber"] = MessageElement(
            str(gid), FLAG_MOD_REPLACE, "gidNumber")
        samdb.modify(update)
        results = samdb.search(expression=expression, attrs=["gidNumber"])
        if len(results) != 1 or integers(results[0], "gidNumber") != [gid]:
            raise RuntimeError("posix group gidNumber is invalid")
    for name in order:
        unix = posix["users"][name]
        samdb.newuser(
            name, values[name],
            force_password_change_at_next_login_req=first_logon,
            uidnumber=unix["uidNumber"],
            gidnumber=unix["gidNumber"],
            loginshell=unix["loginShell"],
            unixhome=unix["unixHomeDirectory"],
        )
        created.append(name)
        expression = "(sAMAccountName=" + name + ")"
        results = samdb.search(expression=expression, attrs=attributes)
        if len(results) != 1:
            raise RuntimeError("staged principal was not stored exactly once")
        expected_upn = name + "@" + realm
        observed_upns = [
            str(value) for value in results[0].get("userPrincipalName", [])
        ]
        if observed_upns != [expected_upn]:
            update = Message()
            update.dn = results[0].dn
            update["userPrincipalName"] = MessageElement(
                expected_upn, FLAG_MOD_REPLACE, "userPrincipalName")
            samdb.modify(update)
    samdb.add_remove_group_members(
        "Domain Admins", [roster["domain_administrator"]],
        add_members_operation=True,
    )
    sids = set()
    for name in order:
        expected_upn = name + "@" + realm
        results = samdb.search(
            expression="(sAMAccountName=" + name + ")",
            attrs=attributes,
        )
        if len(results) != 1:
            raise RuntimeError("staged principal was not stored exactly once")
        record = results[0]
        if [str(value) for value in record.get("sAMAccountName", [])] != [name]:
            raise RuntimeError("staged principal name is invalid")
        if [
            str(value) for value in record.get("userPrincipalName", [])
        ] != [expected_upn]:
            raise RuntimeError("staged principal UPN is invalid")
        controls = integers(record, "userAccountControl")
        computed = integers(record, "msDS-User-Account-Control-Computed")
        # UF_PASSWORD_EXPIRED (0x800000) is computed, and is exactly what a
        # change-at-first-logon account must show; any other account, never.
        expired = 0x800000 if first_logon else 0
        if (
            len(controls) != 1
            or controls[0] & 0x0200 == 0
            or controls[0] & (0x0002 | 0x0020 | 0x800000) != 0
            or len(computed) != 1
            or computed[0] & 0x0010 != 0
            or computed[0] & 0x800000 != expired
        ):
            raise RuntimeError("staged principal account control is invalid")
        expires = integers(record, "accountExpires")
        if expires not in ([], [0], [9223372036854775807]):
            raise RuntimeError("staged principal account expiry is invalid")
        lockout = integers(record, "lockoutTime")
        if lockout not in ([], [0]):
            raise RuntimeError("staged principal is locked out")
        bad_passwords = integers(record, "badPwdCount")
        if bad_passwords not in ([], [0]):
            raise RuntimeError("staged principal bad-password count is invalid")
        password_set = integers(record, "pwdLastSet")
        if first_logon:
            if password_set != [0]:
                raise RuntimeError(
                    "staged principal is not due to change its password")
        elif len(password_set) != 1 or password_set[0] <= 0:
            raise RuntimeError("staged principal password state is invalid")
        sid_values = [bytes(value) for value in record.get("objectSid", [])]
        if len(sid_values) != 1 or not sid_values[0] or sid_values[0] in sids:
            raise RuntimeError("staged principal SID is invalid")
        sids.add(sid_values[0])
        unix = posix["users"][name]
        if integers(record, "uidNumber") != [unix["uidNumber"]]:
            raise RuntimeError("staged principal uidNumber is invalid")
        if integers(record, "gidNumber") != [unix["gidNumber"]]:
            raise RuntimeError("staged principal gidNumber is invalid")
        if strings(record, "loginShell") != [unix["loginShell"]]:
            raise RuntimeError("staged principal login shell is invalid")
        if strings(record, "unixHomeDirectory") != [unix["unixHomeDirectory"]]:
            raise RuntimeError("staged principal unix home is invalid")
    # Gate 9: each staged user owns an optional per-user UNAS share root on
    # the DC, owned by the directory-stored POSIX identity so smbd's rfc2307
    # mapping grants the share owner and nobody else.
    import os
    for name in order:
        unix = posix["users"][name]
        path = @SHARE_ROOT@ + "/" + name
        os.makedirs(path, mode=0o700, exist_ok=True)
        os.chown(path, unix["uidNumber"], unix["gidNumber"])
        os.chmod(path, 0o700)
except BaseException as error:
    reason = failure_reason(error)
    rollback_failures = []
    for name in reversed(created):
        try:
            samdb.deleteuser(name)
        except BaseException as error:
            rollback_failures.append(type(error).__name__)
    for name in created:
        try:
            results = samdb.search(
                expression="(sAMAccountName=" + name + ")",
                attrs=["sAMAccountName"],
            )
            if results:
                rollback_failures.append("PrincipalRemains")
        except BaseException as error:
            rollback_failures.append(type(error).__name__)
    if rollback_failures:
        print("\n__TELOS_PRINCIPAL_FAILURE=" + reason + "+rollback-failed",
              flush=True)
        raise RuntimeError(
            "staged principal rollback failed: "
            + ",".join(rollback_failures))
    print("\n__TELOS_PRINCIPAL_FAILURE=" + reason, flush=True)
    raise
finally:
    # Restored on success and on failure alike, and proven, before the
    # program's return code can report anything.
    if policy_saved is not None:
        try:
            set_password_policy(*policy_saved)
        except BaseException:
            print("\n__TELOS_PRINCIPAL_FAILURE=password-policy-not-restored",
                  flush=True)
            raise
"""

_DESTROY_PROGRAM_TEMPLATE = r"""
import json
import sys

from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB

roster = json.loads('@ROSTER_JSON@')
order = roster["order"]
names = json.load(sys.stdin)
expected = set(order)
if set(names) != expected or len(names) != len(expected):
    raise ValueError("unexpected principal roster")
lp = LoadParm()
lp.load_default()
samdb = SamDB(session_info=system_session(), lp=lp)
failures = []
for name in reversed(names):
    try:
        samdb.deleteuser(name)
    except BaseException as error:
        failures.append(type(error).__name__)
for name in names:
    results = samdb.search(
        expression="(sAMAccountName=" + name + ")",
        attrs=["sAMAccountName"],
    )
    if results:
        failures.append("PrincipalRemains")
import shutil
for name in names:
    shutil.rmtree(@SHARE_ROOT@ + "/" + name, ignore_errors=True)
if failures:
    raise RuntimeError("principal destruction failed: " + ",".join(failures))
"""


# The roster is validated host-side (safely representable, distinct) and the
# allocation is validated host-side (collision-free) before either is baked
# into a guest program.  SAFE_PRINCIPAL/_SAFE_NAME admit only ``[a-z0-9-]``, so
# neither JSON document can contain a single quote and each substitution stays
# one safe Python string literal -- checked rather than assumed, because the
# whole point of the private overlay is that these names are no longer literals
# a reader of this file can see.
def _roster_json(
    roles: tuple[str, ...], domain_administrator: str,
    first_logon: bool = False,
) -> str:
    fields: dict[str, object] = {
        "order": list(roles), "domain_administrator": domain_administrator}
    if first_logon:
        # Only when asked for, so every existing program is byte-identical.
        fields["first_logon"] = True
    document = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    if "'" in document or "\\" in document:
        raise ValueError(
            "Controller principal roster is not one safe string literal")
    return document


def _substituted(
    template: str, roster_json: str, allocation: Mapping[str, dict],
) -> str:
    return template.replace("@ROSTER_JSON@", roster_json).replace(
        "@POSIX_JSON@",
        json.dumps(allocation, sort_keys=True, separators=(",", ":")),
    ).replace("@SHARE_ROOT@", json.dumps(SHARE_ROOT))


_ROSTER_JSON = _roster_json(_ROLES, _DOMAIN_ADMIN)
_STAGE_PROGRAM, _DESTROY_PROGRAM, _PROGRAM_ROLES = _programs(_ACCEPTANCE)
if _PROGRAM_ROLES != _ROLES:
    # Structural, and unconditional like the roster gate above: the programs
    # baked at import and the names this module publishes must be one
    # derivation of one roster, or a caller would validate against names the
    # guest program does not create.
    raise ValueError(
        f"Controller principal programs disagree with the resolved roster; "
        f"source: {ROSTER_SOURCE}")


def _encoded_program(source: str) -> bytes:
    return base64.b64encode(source.encode("utf-8"))


class ControllerPrincipalSerial:
    """Drive secret-safe principal operations on an autologin Controller TTY."""

    def __init__(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
        *,
        timeout: float = 90.0,
        password: bytes | None = None,
        roster: object = None,
        roster_source: str | None = None,
        first_logon: bool = False,
    ) -> None:
        """Bind one console to one roster.

        *password* is the console account's own sudo credential.  ``None`` — the
        disposable default — selects ``sudo -n``, which is right for the
        acceptance Controller, whose ``local-rescue`` account this harness set
        itself.  A DURABLE instance has no such account: its console password
        was typed by the operator into the offline installer, so the durable
        caller supplies it and the protocol answers sudo's own private prompt
        instead.

        *roster* is how a durable caller says "these names, not the ones this
        module resolved at import".  ``None`` keeps every existing caller on
        the module constants, byte for byte.  A supplied roster is baked into
        this instance's own guest programs by ``_programs``, so the names this
        object validates are exactly the names its programs create.  A durable
        DECLARATION (``durable_directory_roster()``) brings its uid_number pins
        and its additional standard users with it: ``roles`` then lists those
        users after the directory roles, and ``stage`` requires a credential
        for each.

        *first_logon* stages every account with a TEMPORARY password it must
        change at its first logon; the domain password policy is lifted only
        while the accounts are created, then restored and proven. Durable
        rosters only: the disposable acceptance lanes log in as these accounts
        and must never meet an expired password.
        """
        if first_logon and roster is None:
            raise ValueError(
                "change-at-first-logon staging is for a durable roster only")
        self.console = SerialAutomation(
            reader, writer, password, timeout=timeout)
        self.first_logon = bool(first_logon)
        if roster is None:
            self.roles = _ROLES
            self.roster_source = ROSTER_SOURCE
            self._stage_program = _STAGE_PROGRAM
            self._destroy_program = _DESTROY_PROGRAM
        else:
            stage, destroy, roles = _programs(
                roster, first_logon=first_logon)
            self.roles = roles
            self.roster_source = (
                ROSTER_SOURCE if roster_source is None else roster_source)
            self._stage_program = stage
            self._destroy_program = destroy

    def _names(self, names: tuple[str, ...]) -> tuple[str, ...]:
        if (set(names) != set(self.roles) or len(names) != len(self.roles)
                or any(not _SAFE_NAME.fullmatch(name) for name in names)):
            raise ValueError("Controller principal roster is invalid")
        return names

    def _values(self, values: Mapping[str, str]) -> dict[str, str]:
        if set(values) != set(self.roles):
            # Name both rosters and where the expected one came from.  Bare,
            # this refusal was the whole message a caller got for handing over
            # the old hardcoded ("student", "operator", "directory-admin")
            # while the owner's overlay had renamed the roster -- from inside
            # stage_controller_principals, with a serial transcript as the only
            # evidence.  Principal names are already baked into the guest
            # program and echoed on that transcript, so naming them here leaks
            # nothing; the credentials they map to are never touched.
            raise ValueError(
                "Controller principal roster is invalid: expected exactly "
                f"{list(self.roles)}, got {sorted(values)}; "
                f"roster source: {self.roster_source}")
        copied = dict(values)
        for name, password in copied.items():
            if not _SAFE_NAME.fullmatch(name):
                raise ValueError("Controller principal name is invalid")
            if (not isinstance(password, str) or not password
                    or "\n" in password or "\r" in password
                    or "\x00" in password):
                raise ValueError("Controller principal credential is invalid")
        if len(set(copied.values())) != len(copied):
            raise ValueError("Controller principal credentials must be distinct")
        return copied

    def _run(
        self,
        operation: str,
        payload: object,
        program: str,
        names: tuple[str, ...],
    ) -> ControllerPrincipalResult:
        console = self.console
        token = uuid.uuid4().hex.encode("ascii")
        ready = b"__TELOS_PRINCIPAL_READY_" + token + b"__"
        result = b"__TELOS_PRINCIPAL_RC_" + token + b"="
        sudo_prompt = b"__TELOS_PRINCIPAL_SUDO_" + token + b"__"
        encoded = _encoded_program(program)
        sudo = (
            b"sudo -n"
            if console.password is None
            else b"sudo -k -p '" + sudo_prompt + b"'"
        )
        command = (
            b"trap 'stty echo' INT TERM EXIT; "
            b"stty -echo || exit 91; "
            b"printf '\\n" + ready + b"\\n'; "
            b"IFS= read -r __telos_payload; "
            b"stty echo; trap - INT TERM EXIT; "
            b"printf '%s' \"$__telos_payload\" | base64 -d | "
            + sudo + b" python3 -c \"import os;os.close(2);import base64;"
            b"exec(base64.b64decode('" + encoded + b"'))\" "
            b"; "
            b"__telos_rc=$?; unset __telos_payload; "
            b"printf '\\n" + result + b"%s\\n' \"$__telos_rc\""
        )
        try:
            console._send(b"", operation + "-shell-prompt-requested")
            console._wait(
                rb"(?:^|\n)[^\n]*\$\s*$", "controller-shell-ready")
            console._send(command, operation + "-command-sent")
            console._wait(
                rb"(?:^|\n)" + re.escape(ready) + rb"\s*(?:\n|$)",
                operation + "-secret-input-ready")
            wire = base64.b64encode(
                json.dumps(
                    payload, sort_keys=True, separators=(",", ":"),
                ).encode("utf-8"))
            console._send(wire, operation + "-secret-input-sent")
            if console.password is not None:
                console._wait(
                    rb"(?:^|\n)" + re.escape(sudo_prompt) + rb"\s*$",
                    operation + "-sudo-password-prompt",
                )
                console._send(
                    console.password, operation + "-sudo-password-sent")
            match = console._wait(
                _principal_result_pattern(result),
                operation + "-return-code-observed")
        except SerialAutomationError as error:
            raise ControllerPrincipalError(
                f"Controller {operation} protocol failed") from error
        returncode = int(match.group("rc"))
        if returncode:
            reason = match.group("reason")
            raise ControllerPrincipalError(
                f"Controller {operation} returned {returncode}"
                + (f": {reason.decode('ascii')}" if reason else ""))
        return ControllerPrincipalResult(
            operation, names, tuple(console.events))

    def stage(
        self, values: Mapping[str, str],
    ) -> ControllerPrincipalResult:
        """Create exactly this console's directory principals."""
        copied = self._values(values)
        names = tuple(copied)
        return self._run("stage", copied, self._stage_program, names)

    def destroy(
        self, names: tuple[str, ...],
    ) -> ControllerPrincipalResult:
        """Destroy exactly this console's directory principals."""
        checked = self._names(names)
        return self._run(
            "destroy", list(checked), self._destroy_program, checked)
