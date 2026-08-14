#!/usr/bin/env python3
"""Converge durable directory accounts without placing a credential in argv.

The plan on the command line carries account names, the deterministic POSIX
identifiers derived from the declared roster order, and the PATH of a
root-owned 0600 file per account. It never carries a credential value: this
program opens the file itself, hands what it reads straight to Samba's
in-process API, and redacts every value it read out of the bounded diagnostic
it writes. Nothing therefore reaches argv, the process table, the environment,
an Ansible variable, a template, or a transcript.

Two properties matter more here than in the disposable acceptance path:

* Idempotence. An account that already exists is never re-created and its
  password is never rewritten unless the caller passed both
  --allow-password-reset and `reset_password: true` for that account. Its SID,
  its Kerberos keys and its group memberships survive re-convergence.
* No rollback. `controller_principals.py` deletes what it created when staging
  fails, because that Controller is disposable. Doing that here would destroy a
  durable account's SID and silently invalidate every ACL that references it,
  so a failure is reported and the half-converged state is left for the next
  run to finish. Every attribute this program writes is written with
  FLAG_MOD_REPLACE, so the next run converges rather than compounds.
"""

import argparse
import json
import os
import re
import stat as stat_module
from pathlib import Path

SAFE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
POSIX_ATTRIBUTES = ("uidNumber", "gidNumber", "loginShell", "unixHomeDirectory")

parser = argparse.ArgumentParser()
parser.add_argument("--plan-json", required=True)
parser.add_argument("--groups-json", required=True)
parser.add_argument("--primary-group", required=True)
parser.add_argument("--admin-group", required=True)
parser.add_argument("--posix-base", required=True, type=int)
parser.add_argument("--diagnostic-file", required=True)
rotation = parser.add_mutually_exclusive_group(required=True)
rotation.add_argument("--allow-password-reset", action="store_true")
rotation.add_argument("--refuse-password-reset", action="store_true")
args = parser.parse_args()


def parsed(text, what):
    try:
        return json.loads(text)
    except ValueError as error:
        raise ValueError(f"{what} is not valid JSON: {error}") from error


def validated(plan, groups, base):
    """Refuse any plan whose identifiers could collide or misname an account.

    The same refusals `controller_principals._validated_posix_allocation` makes
    for the acceptance roster, restated where the durable roster is applied. A
    plan is data from an overlay this program cannot see reviewed, so it is
    checked rather than trusted.
    """
    if not isinstance(plan, list) or not plan:
        raise ValueError("durable account plan is empty")
    if not isinstance(groups, dict) or not groups:
        raise ValueError("durable POSIX group plan is empty")
    names = [entry.get("name") for entry in plan]
    if any(not isinstance(name, str) or not SAFE_NAME.fullmatch(name)
           for name in names):
        raise ValueError("durable account name is invalid")
    if len(set(names)) != len(names):
        raise ValueError("durable account roster repeats a name")
    for entry in plan:
        if entry.get("role") not in ("standard", "administrator"):
            raise ValueError("durable account role is invalid")
        for attribute in ("loginShell", "unixHomeDirectory"):
            value = entry.get(attribute)
            if (not isinstance(value, str) or not value.startswith("/")
                    or len(value.splitlines()) != 1):
                raise ValueError(f"durable account {attribute} is invalid")
    uids = [entry.get("uidNumber") for entry in plan]
    gids = list(groups.values())
    if any(not isinstance(uid, int) or isinstance(uid, bool) or uid < base
           for uid in uids):
        raise ValueError("durable account uidNumber is out of range")
    if any(not isinstance(gid, int) or isinstance(gid, bool) or gid < base
           for gid in gids):
        raise ValueError("durable account gidNumber is out of range")
    if len(set(uids)) != len(uids):
        raise ValueError("durable account uidNumber allocation collides")
    if len(set(gids)) != len(gids):
        raise ValueError("durable account gidNumber allocation collides")
    if set(uids) & set(gids):
        raise ValueError(
            "durable account user and group identifier ranges collide")
    for entry in plan:
        if entry.get("gidNumber") not in gids:
            raise ValueError(
                "durable account primary group is not an allocated group")
    for group in (args.primary_group, args.admin_group):
        if group not in groups:
            raise ValueError("durable POSIX group plan is missing a group")
    return plan, groups


def credential(entry):
    """Read one account's credential from its own protected file.

    The mode, ownership and regularity of the file are checked here as well as
    in the role, because this is the process that actually opens it: the role's
    stat proves the operator staged the file correctly, and this check is the
    one that holds at the moment of use. lstat, not stat, so a symlink pointed
    at somebody else's file is a refusal rather than a silent redirect. The
    order is shape, then mode, then ownership, then content: nothing is read
    out of a file that any account other than root could have written.
    """
    path = entry.get("password_file") or ""
    if not path:
        raise ValueError(
            f"{entry['name']} does not exist and no password-file path was "
            "declared for it")
    try:
        info = os.lstat(path)
    except OSError as error:
        raise ValueError(
            f"password file for {entry['name']} is missing or unreadable: "
            f"{error.strerror}") from error
    if not stat_module.S_ISREG(info.st_mode):
        raise ValueError(f"password file for {entry['name']} is not a regular file")
    if stat_module.S_IMODE(info.st_mode) != 0o600:
        raise ValueError(f"password file for {entry['name']} is not mode 0600")
    if info.st_uid != 0:
        raise ValueError(f"password file for {entry['name']} is not owned by root")
    try:
        first_line = Path(path).read_text(encoding="utf-8").splitlines()[0]
    except (OSError, IndexError, UnicodeError) as error:
        raise ValueError(
            f"cannot read a first line from the password file for "
            f"{entry['name']}: {error}") from error
    value = first_line.strip()
    if not value:
        raise ValueError(
            f"password file for {entry['name']} must have a nonempty first line")
    return value


status = ""
returncode = 1
credentials = {}
summary = {"changed": False, "created": [], "updated": [], "verified": []}
try:
    plan, groups = validated(
        parsed(args.plan_json, "--plan-json"),
        parsed(args.groups_json, "--groups-json"),
        args.posix_base,
    )

    # Read every credential this run is allowed to use before Samba is
    # imported, so a missing or unprotected file is refused without touching
    # the directory at all. Nothing else is read: an account that exists and is
    # not being rotated needs no credential, which is what lets the operator
    # delete the file once the account exists.
    for entry in plan:
        wants_reset = bool(entry.get("reset_password"))
        if wants_reset and not args.allow_password_reset:
            raise ValueError(
                f"refusing to rotate the password of {entry['name']}: set "
                "homelab_ad_account_password_reset_enabled for that deliberate "
                "run and return it to false immediately afterwards")
        if entry.get("create") or wants_reset:
            credentials[entry["name"]] = credential(entry)

    from ldb import FLAG_MOD_REPLACE, Message, MessageElement
    from samba.auth import system_session
    from samba.param import LoadParm
    from samba.samdb import SamDB

    load_parameters = LoadParm()
    load_parameters.load_default()
    samdb = SamDB(session_info=system_session(), lp=load_parameters)
    realm = str(load_parameters.get("realm")).upper()

    def integers(record, attribute):
        return [int(str(value)) for value in record.get(attribute, [])]

    def strings(record, attribute):
        return [str(value) for value in record.get(attribute, [])]

    def replace(dn, attribute, value):
        update = Message()
        update.dn = dn
        update[attribute] = MessageElement(
            str(value), FLAG_MOD_REPLACE, attribute)
        samdb.modify(update)

    def one(expression, attrs):
        results = samdb.search(expression=expression, attrs=attrs)
        if len(results) > 1:
            raise RuntimeError(
                "directory object is not stored exactly once: " + expression)
        return results[0] if results else None

    # Groups first, so no account is ever created carrying a gidNumber the
    # directory cannot resolve. Replacing a deterministic gidNumber is
    # idempotent, so this is safe on every re-run.
    for group in sorted(groups):
        gid = groups[group]
        expression = f"(&(objectClass=group)(sAMAccountName={group}))"
        record = one(expression, ["sAMAccountName", "gidNumber"])
        if record is None:
            raise RuntimeError(f"well-known group is missing: {group}")
        if integers(record, "gidNumber") != [gid]:
            replace(record.dn, "gidNumber", gid)
            summary["changed"] = True
            summary["updated"].append(group)
        verified = one(expression, ["gidNumber"])
        if verified is None or integers(verified, "gidNumber") != [gid]:
            raise RuntimeError(f"gidNumber of {group} is invalid")

    admin_expression = (
        f"(&(objectClass=group)(sAMAccountName={args.admin_group}))")
    for entry in plan:
        name = entry["name"]
        expression = f"(sAMAccountName={name})"
        record = one(expression, ["sAMAccountName"] + list(POSIX_ATTRIBUTES)
                     + ["userPrincipalName"])
        if record is None:
            samdb.newuser(
                name, credentials[name],
                force_password_change_at_next_login_req=False,
                uidnumber=entry["uidNumber"],
                gidnumber=entry["gidNumber"],
                loginshell=entry["loginShell"],
                unixhome=entry["unixHomeDirectory"],
            )
            summary["changed"] = True
            summary["created"].append(name)
        elif name in credentials:
            # Only reachable with --allow-password-reset and an explicit
            # per-account reset_password, both checked above.
            samdb.setpassword(
                expression, credentials[name],
                force_change_at_next_login=False)
            summary["changed"] = True
            summary["updated"].append(name)

        record = one(expression, ["sAMAccountName", "objectSid",
                                  "userPrincipalName", "userAccountControl",
                                  "msDS-User-Account-Control-Computed",
                                  "pwdLastSet"] + list(POSIX_ATTRIBUTES))
        if record is None:
            raise RuntimeError(f"durable account was not stored: {name}")
        for attribute in POSIX_ATTRIBUTES:
            wanted = entry[attribute]
            if isinstance(wanted, int):
                observed = integers(record, attribute)
            else:
                observed = strings(record, attribute)
            if observed != [wanted]:
                replace(record.dn, attribute, wanted)
                summary["changed"] = True
                if name not in summary["updated"]:
                    summary["updated"].append(name)
        expected_upn = f"{name}@{realm}"
        if strings(record, "userPrincipalName") != [expected_upn]:
            replace(record.dn, "userPrincipalName", expected_upn)
            summary["changed"] = True
            if name not in summary["updated"]:
                summary["updated"].append(name)

        if entry["role"] == "administrator":
            group_record = one(admin_expression, ["member"])
            if group_record is None:
                raise RuntimeError(
                    f"well-known group is missing: {args.admin_group}")
            members = [value.lower() for value in strings(group_record, "member")]
            if str(record.dn).lower() not in members:
                samdb.add_remove_group_members(
                    args.admin_group, [name], add_members_operation=True)
                summary["changed"] = True
                if name not in summary["updated"]:
                    summary["updated"].append(name)

    # Fail-closed verification of the end state, so a half-converged account
    # stops the run instead of producing a workstation nobody can log in to.
    admin_record = one(admin_expression, ["member"])
    admin_members = [
        value.lower() for value in strings(admin_record or {}, "member")]
    for entry in plan:
        name = entry["name"]
        record = one(
            f"(sAMAccountName={name})",
            ["sAMAccountName", "objectSid", "userPrincipalName",
             "userAccountControl", "msDS-User-Account-Control-Computed",
             "pwdLastSet"] + list(POSIX_ATTRIBUTES),
        )
        if record is None:
            raise RuntimeError(f"durable account is missing: {name}")
        if strings(record, "sAMAccountName") != [name]:
            raise RuntimeError(f"durable account name is invalid: {name}")
        if strings(record, "userPrincipalName") != [f"{name}@{realm}"]:
            raise RuntimeError(f"durable account UPN is invalid: {name}")
        for attribute in POSIX_ATTRIBUTES:
            wanted = entry[attribute]
            observed = (integers(record, attribute) if isinstance(wanted, int)
                        else strings(record, attribute))
            if observed != [wanted]:
                raise RuntimeError(
                    f"durable account {attribute} is invalid: {name}")
        controls = integers(record, "userAccountControl")
        computed = integers(record, "msDS-User-Account-Control-Computed")
        if (len(controls) != 1
                or controls[0] & 0x0200 == 0
                or controls[0] & (0x0002 | 0x0020 | 0x800000) != 0
                or len(computed) != 1
                or computed[0] & (0x0010 | 0x800000) != 0):
            raise RuntimeError(
                f"durable account is disabled, locked or passwordless: {name}")
        password_set = integers(record, "pwdLastSet")
        if len(password_set) != 1 or password_set[0] <= 0:
            raise RuntimeError(f"durable account has no password set: {name}")
        sids = [bytes(value) for value in record.get("objectSid", [])]
        if len(sids) != 1 or not sids[0]:
            raise RuntimeError(f"durable account has no SID: {name}")
        is_admin = str(record.dn).lower() in admin_members
        if is_admin != (entry["role"] == "administrator"):
            raise RuntimeError(
                f"durable account {args.admin_group} membership is wrong: "
                f"{name}")
        summary["verified"].append(name)
    returncode = 0
    status = "exit=0\n"
except BaseException as error:  # noqa: BLE001 - reported, never swallowed
    status = f"error={type(error).__name__}: {error}\n"
finally:
    for value in credentials.values():
        status = status.replace(value, "[REDACTED]")
    diagnostic = Path(args.diagnostic_file)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(diagnostic, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(status[-16384:])
    if returncode == 0:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(status[-16384:], end="")
raise SystemExit(returncode)
