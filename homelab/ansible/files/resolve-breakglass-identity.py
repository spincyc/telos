#!/usr/bin/env python3
"""Render the break-glass administrator's name from the ONE roster declaration.

Why this program exists at all
------------------------------
ADR 0055 and ADR 0063 make the break-glass administrator the only way into a
machine while the directory is down: a separately named LOCAL account at UID
1000, never ``root``, never a directory principal, with passworded sudo.  Its
name was declared TWICE, in two documents read by two different readers, and
nothing checked that they agreed:

    homelab/instance/identity/principals.json   principals.local_rescue.name
        read by the Python path
        (``homelab/workstations/arch_second.identity_roster``), which bakes the
        name onto an installed workstation DISK -- the ``useradd``, the
        sudoers rule and the acceptance probe.

    homelab/instance/inventory/group_vars/all.yml   homelab_breakglass_user
        read by ``roles/common``, which creates the account and its
        ``/etc/sudoers.d/10-<name>`` entry on a CONVERGED host.

``homelab/instance-example/identity/README.md`` said so outright.  Two names
that disagree means the account you can log in as is not the account the disk
was built to trust, and that is discovered at exactly the moment you needed it:
the directory is down, the cached credentials are gone, and the one local
account the installer put on the disk is not the one convergence created.  This
is the same class of defect commit ``2d6354c`` closed for ADR 0065's permanent
identity and ``e683683`` closed for the share root.

The bridge this program IS
--------------------------
The same shape as ``files/resolve-directory-identity.py`` beside it, and as
``roles/domain_controller/files/resolve-directory-accounts.py``, for the same
reason.  ``roles/common`` runs INSIDE a target that carries only
``homelab/ansible`` when it runs from the staged factory payload, so nothing
there can import the roster loader -- and it must not: staging the owner's
private identity overlay into a guest would spread instance data (ADR 0046) for
no reason.  The derivation therefore runs on the Ansible CONTROL HOST, where
the whole repository is present, and the target receives nothing but the
finished name as ordinary Ansible data.  That is why
``tasks/breakglass-identity.yml`` invokes this program with
``delegate_to: localhost``.

It reuses ``identity_roster`` rather than re-reading the JSON: the roster's
rules -- the sparse-patch shape, the safe-name pattern, the four roles being
distinct, "a file that exists but cannot be understood is a refusal" -- keep
exactly one implementation, and a name this program derives is by construction
the same name the disk was built with.

It prints ONE JSON document on stdout and nothing else.  It reads no credential.

Fail closed in BOTH directions
------------------------------
* The private roster overlay is PRESENT -> it is authoritative, for every one
  of the four roles including a role it does not itself mention (an overlay
  that renames nobody still resolves ``local_rescue`` to the tracked contract's
  ``local-rescue``, which is what the disk gets).  A ``homelab_breakglass_user``
  that is *also* set, to a *different* value, is refused by name, quoting both
  values and naming both files.  Neither declaration is silently preferred: an
  owner who edited one of two copies must be told which two disagree, not have
  their edit discarded on the one account that has to work when nothing else
  does.
* The overlay is ABSENT -> nothing is derived and nothing is invented.
  ``homelab_breakglass_user`` keeps the value the inventory declared and the
  role's own default, and ``roles/common``'s first assert keeps judging it,
  exactly as before this program existed.  This is not a tidiness concession:
  with no overlay the tracked contract resolves ``local_rescue`` to the
  SYNTHETIC ``local-rescue``, and quietly substituting that for the role's
  ``labadmin`` default would rename the break-glass account on every host that
  has no overlay -- which is the very failure this program exists to prevent,
  merely committed by the fix instead of by the owner.

Where it is running
-------------------
The repository is found from this file's own location.  Reached from a control
host it resolves; reached from the payload a factory bundle stages inside a
guest (``/opt/telos-factory/ansible/files/...``) it does not, and there is no
private overlay in a guest to consult either.  That is the "no overlay" case
above, and it is one of the two reasons the disposable acceptance path cannot
move -- the other being that ``playbooks/bootstrap-controller.yml``, the play
the factory bundle runs, carries no ``common`` role at all.  An explicitly
named ``--overlay`` that cannot be resolved is a refusal, never a fallback.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# files/ -> ansible -> homelab -> repository.
_REPOSITORY = Path(__file__).resolve().parent.parents[2]
_LOADER = _REPOSITORY / "homelab" / "workstations" / "arch_second.py"

#: Bumped only when a key is removed or changes meaning.  The bridge asserts it.
SCHEMA = 1

#: The contract role that IS the break-glass administrator, and the one Ansible
#: variable that names it.  One row, written down once, so a test can prove the
#: two halves of the bridge are talking about the same account.
CONTRACT_ROLE = "local_rescue"
DECLARED_VARIABLE = "homelab_breakglass_user"
DECLARED_VARIABLES = (DECLARED_VARIABLE,)

#: ADR 0055/0063: the break-glass administrator is a separately named account
#: with its own sudo rule.  ``roles/common`` refuses this too, at the moment of
#: use; refusing it HERE means a roster that names it is refused on the control
#: host, before a single host is touched, and the message can name the file the
#: name actually came from.
FORBIDDEN_NAMES = frozenset({"root"})


class BreakglassResolverError(RuntimeError):
    """The name cannot be resolved; convergence must stop before mutating."""


def _roster_loader():
    """Import the one identity-roster loader, or say it is out of reach."""
    if str(_REPOSITORY) not in sys.path:
        sys.path.insert(0, str(_REPOSITORY))
    try:
        from homelab.workstations import arch_second
    except Exception as error:  # noqa: BLE001 - reported, never swallowed
        raise BreakglassResolverError(
            f"the identity roster loader could not be imported from "
            f"{_LOADER}: {type(error).__name__}: {error}. The break-glass "
            f"administrator's name is rendered on an Ansible control host "
            f"that holds the whole repository; it is never derived inside a "
            f"target, which carries only homelab/ansible.") from error
    return arch_second


def _overlay_path(argument: str | None) -> Path | None:
    """Which roster overlay to read, or ``None`` for "there is none to read".

    An explicit ``--overlay`` is honoured wherever this runs, so a test can
    resolve a fixture it wrote itself rather than whatever private overlay the
    developer's machine happens to carry -- the same reason
    ``resolve-directory-accounts.py`` takes ``--identity-overlay`` and
    ``resolve-directory-identity.py`` takes ``--document``.
    """
    if argument:
        return Path(argument)
    if not _LOADER.is_file():
        # The staged factory payload: only homelab/ansible is present, there is
        # no repository above it and no private overlay inside a guest.
        return None
    return _REPOSITORY / "homelab" / "instance" / "identity" / "principals.json"


def _resolve(path: Path) -> str | None:
    """The roster's break-glass name, or ``None`` when there is no overlay.

    ``os.lstat`` rather than ``Path.exists()`` for the reason the roster loader
    gives: on Python 3.13 and later ``exists()`` swallows every ``OSError``, so
    an overlay under a directory this process cannot search would read as "not
    there" and the derivation would silently switch off.  Absent is permitted;
    unknown is a refusal.
    """
    try:
        os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise BreakglassResolverError(
            f"the private identity roster {path} could not be examined "
            f"({error.strerror or type(error).__name__}); a roster whose "
            f"state is unknown is a refusal, never a fallback") from error
    loader = _roster_loader()
    try:
        # require_overlay: we have just proved the file is there, so an
        # absence reported from inside the loader is a race or a lie, not the
        # no-overlay case, and must not resolve to the synthetic roster.
        roster = loader.identity_roster(overlay_path=path, require_overlay=True)
    except loader.IdentityRosterError as error:
        raise BreakglassResolverError(str(error)) from error
    return roster[CONTRACT_ROLE]


def _declared(raw: str) -> dict[str, str]:
    try:
        declared = json.loads(raw)
    except ValueError as error:
        raise BreakglassResolverError(
            f"--declared-json is not valid JSON: {error}") from error
    if not isinstance(declared, dict):
        raise BreakglassResolverError("--declared-json is not a JSON object")
    unknown = sorted(set(declared) - set(DECLARED_VARIABLES))
    if unknown:
        raise BreakglassResolverError(
            f"--declared-json carries {unknown[0]!r}, which is not one of the "
            f"break-glass variables this program reconciles "
            f"({', '.join(DECLARED_VARIABLES)})")
    # Ansible renders an undefined variable's default as an empty string, and
    # an empty string is "not declared here".
    return {name: str(value).strip()
            for name, value in declared.items()
            if str(value).strip()}


def _reconcile_against_roster(name: str, declared, overlay, source) -> dict:
    """The roster wins, but only after a disagreement has been named."""
    if name.lower() in FORBIDDEN_NAMES:
        raise BreakglassResolverError(
            f"the private identity roster {overlay} names the break-glass "
            f"administrator {name!r}. ADR 0055 and ADR 0063 make it a "
            f"SEPARATELY named local account with its own sudo rule, "
            f"precisely so that the account which survives a directory outage "
            f"is not the account every attacker already knows the name of. "
            f"Rename {CONTRACT_ROLE} in {overlay}.")

    value = declared.get(DECLARED_VARIABLE)
    if value is not None and value != name:
        raise BreakglassResolverError(
            f"the break-glass administrator is declared twice and the two "
            f"declarations disagree.\n"
            f"  {DECLARED_VARIABLE} = {value!r}\n"
            f"      declared in {source}\n"
            f"      creates the account and /etc/sudoers.d/10-{value} on every "
            f"converged host (roles/common)\n"
            f"  principals.{CONTRACT_ROLE}.name = {name!r}\n"
            f"      declared in {overlay}\n"
            f"      is baked onto the installed workstation disk -- the "
            f"useradd, the sudoers rule and the acceptance probe\n"
            f"ADR 0055 and ADR 0063 make this account the ONLY way into a "
            f"machine while the directory is down, so two names that disagree "
            f"means the account you can log in as is not the account the disk "
            f"was built to trust, discovered at the moment you needed it. "
            f"{overlay} is the single declaration: either correct it, or "
            f"delete {DECLARED_VARIABLE} from the inventory and let it be "
            f"derived. Nothing has been changed on any host.")

    return {
        "schema": SCHEMA,
        "roster": str(overlay),
        "source": f"private overlay {overlay}",
        "contract_role": CONTRACT_ROLE,
        "breakglass_user": name,
    }


def _reconcile_without_roster(declared, source) -> dict:
    """No overlay: invent nothing at all.

    There is exactly one YAML declaration of this name, so unlike the permanent
    identity there is no second copy to cross-check here.  The value is echoed
    back so a caller -- and a test -- can see that it passed through untouched,
    and the bridge's derivation is gated on ``roster`` being non-empty so that
    the echo can never be applied to a host.
    """
    return {
        "schema": SCHEMA,
        "roster": "",
        "source": source,
        "contract_role": CONTRACT_ROLE,
        "breakglass_user": declared.get(DECLARED_VARIABLE, ""),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Derive the break-glass administrator's name from the one "
                    "identity roster, or prove the inventory agrees with it.")
    parser.add_argument(
        "--declared-json", required=True,
        help="the break-glass variables the inventory declares, as a JSON "
             "object. An empty value means the variable is not declared.")
    parser.add_argument(
        "--overlay", default="",
        help="read this private identity roster instead of the one this "
             "checkout's instance/ holds. A path that does not exist is the "
             "no-overlay case, which is what makes a test of this program "
             "independent of whatever private overlay the developer's own "
             "machine happens to carry.")
    parser.add_argument(
        "--declared-source", default="the Ansible inventory",
        help="how to name the place the YAML variable came from, in a "
             "refusal. The inventory file, where the run knows it.")
    arguments = parser.parse_args(argv)

    declared = _declared(arguments.declared_json)
    source = arguments.declared_source.strip() or "the Ansible inventory"
    overlay = _overlay_path(arguments.overlay)
    name = _resolve(overlay) if overlay is not None else None

    document = (_reconcile_against_roster(name, declared, overlay, source)
                if name is not None
                else _reconcile_without_roster(declared, source))
    json.dump(document, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BreakglassResolverError as failure:
        print(f"error: {failure}", file=sys.stderr)
        raise SystemExit(2) from failure
