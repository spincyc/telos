#!/usr/bin/env python3
"""Reset one staged durable account's password, prove it, record it.

``make homelab-factory-persistent-account-password`` (TASK-28).  Staging
(``make homelab-factory-persistent-accounts``) CREATES accounts, and with
``RESTAGE=1`` it stops on the first one the directory already holds
(``account-exists``): it cannot give an owner who lost a temporary password a
new one.  On 2026-09-30 the owner no longer held the daily administrator's
temporary password, so this resets exactly one existing account:

* ``ROLE`` names the account by its contract role, and must be one of the
  roles the instance's staged roster record lists (``directory_accounts``).
  The account NAME comes from the same private roster the staging used
  (``controller_principals.durable_directory_roster``) and appears only in the
  password prompt at the owner's terminal -- never in argv, the evidence, the
  marker or the transcript;
* the dry run (the default) binds the instance exactly as the probe does,
  prints the plan and starts nothing;
* ``--apply`` asks, after every refusal and before any process starts, for
  the ``local-rescue`` console password and the new password twice, judges
  the new one against the instance's recorded directory password policy
  (``instance_policy``; Samba's default when none) and refuses it there;
  then boots the instance in place on a per-run switch and gateway with no
  workstation (``PersistentControllerSession``), proves the realm and domain
  SID are the bound directory's, runs the reset program
  (``controller_principals.password_reset_program``) over the staging
  channel, and powers the guest off over its console;
* the guest program refuses an account that does not exist (it never creates
  one), replaces ``unicodePwd`` as an administrator's reset, sets
  ``pwdLastSet=0`` with ``--change-at-first-logon``, and reads back
  ``pwdLastSet`` and the account's objectSid and uidNumber before it prints
  its proof.  It never touches the domain password policy;
* only when the proof is the expected one and the run ended cleanly is an
  entry appended to the marker's ``directory_account_password_resets``
  (role, time, must_change, run id), atomically.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

if not __package__:  # Direct execution by the Make recipe (PEP 366).
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "homelab.vm"

from . import controller_principals as principals  # noqa: E402
from . import persistent_password_policy as policy_runner  # noqa: E402
from .bootstrap_dc import (  # noqa: E402
    CONSOLE_ACCOUNT,
    DEFAULT_PERSISTENT_ROOT,
    DEFAULT_STATE,
    PERSISTENT_CONSOLE_TIMEOUT,
    SOCKET_MAC,
    _persistent_running,
    _typed_secret,
    ovmf_pair,
)
from .controller_image import (  # noqa: E402
    ControllerImageError, assert_installed)
from .credential_custody import (  # noqa: E402
    AGENT, PENDING_RESET, AgentCredentialSource, credential_source,
    generate_password, instance_custody)
from .directory_password_policy import (  # noqa: E402
    DirectoryPasswordPolicy, instance_policy)
from .durable_workstation import (  # noqa: E402
    DurableBinding, DurableBindingError, durable_binding)
from .factory_runner import wait_for_switch_port  # noqa: E402
from .persistent_controller_session import (  # noqa: E402
    CUSTODY_CONSOLE_LINE,
    PersistentControllerSession,
    PersistentControllerSessionError,
    _finish_session,
    _start_fabric,
    session_command,
)
from .secure_artifacts import atomic_write, private_directory  # noqa: E402
from .signal_cleanup import SignalGuard, terminate_children  # noqa: E402
from .simulation_overlay import PersistentControllerInstance  # noqa: E402


#: Retained evidence, beside the probe's and the policy runner's under the
#: gitignored homelab/var (ADR 0046): never in the instance directory.
DEFAULT_EVIDENCE_ROOT = Path("homelab/var/factory/persistent-account-password")
#: The reset program's bound, once sudo has its password: one search, one
#: transaction, one read-back.  Seconds, not staging's minutes.
RESET_TIMEOUT = 180.0
#: Every boolean a run must prove before its reset is recorded.
REQUIRED_CHECKS = (
    "fabric_started", "controller_attached", "live_argv_audited",
    "console_login", "ad_service_live", "realm_matches", "domain_sid_matches",
    "password_reset", "read_back_matches", "clean_poweroff", "lock_released",
    "transcript_secret_free",
)


class AccountPasswordError(RuntimeError):
    """One durable account's password could not be reset and proven."""


def _say(message: str) -> None:
    print(f"account-password: {message}", flush=True)


def planned_account(
    role: str, staged: dict, roster: object, *, instance: str,
) -> dict:
    """The durable plan entry for *role*, or a refusal that names no account.

    *role* must be a contract role the staged record lists; the entry comes
    from the same derivation staging used (``directory_account_plan`` over the
    durable declaration), and a uidNumber the staged record carries must be
    the plan's.  A refusal never repeats *role* back: an operator who typed a
    real name into ``ROLE`` must not see it land in a log.
    """
    staged_roles = [
        str(account.get("contract_role")) for account in staged["accounts"]]
    if not isinstance(role, str) or role not in staged_roles:
        raise AccountPasswordError(
            f"ROLE must be one of {instance}'s staged contract roles: "
            f"{', '.join(staged_roles)}")
    plan = principals.directory_account_plan(
        list(principals.DIRECTORY_ROLES), roster=roster)
    entry = next(
        (item for item in plan if item["contract_role"] == role), None)
    if entry is None:
        raise AccountPasswordError(
            f"the private roster no longer declares {role}, which {instance} "
            "staged; nothing was changed")
    recorded = next(
        account for account in staged["accounts"]
        if account.get("contract_role") == role)
    if ("uidNumber" in recorded
            and recorded["uidNumber"] != entry["uidNumber"]):
        raise AccountPasswordError(
            f"{instance} staged {role} with uidNumber {recorded['uidNumber']}, "
            f"but the private roster now plans {entry['uidNumber']}; nothing "
            "was changed")
    return entry


def _passed(checks: dict[str, object]) -> bool:
    return (all(checks.get(key) is True for key in REQUIRED_CHECKS)
            and checks.get("terminated_fallback") is False)


def _reset(
    console, account: dict, value: str, *, must_change: bool,
    roster: object, source: str,
) -> principals.ControllerPasswordReset:
    """The reset program over the already authenticated console.

    The same shared-console substitution staging and the probe's join
    principal make: the protocol runs over the session that logged in.
    """
    serial = principals.ControllerPrincipalSerial(
        console.reader, console.writer, timeout=console.timeout,
        roster=roster, roster_source=source)
    serial.console = console
    original = console.timeout
    console.timeout = RESET_TIMEOUT
    try:
        return serial.reset_password(
            account["name"], value, uid_number=account["uidNumber"],
            must_change=must_change)
    finally:
        console.timeout = original


def _run(
    binding: DurableBinding,
    target: PersistentControllerInstance,
    password: bytes,
    account: dict,
    value: str,
    *,
    must_change: bool,
    roster: object,
    source: str,
    policy: DirectoryPasswordPolicy,
    canonical_state: Path,
    evidence_root: Path,
    custody: AgentCredentialSource | None = None,
) -> int:
    role = account["contract_role"]
    run_id = (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
              + f"-{os.getpid()}-{secrets.token_hex(4)}")
    root = Path(evidence_root).absolute()
    private_directory(root, parents=True)
    private_directory(root / binding.instance)
    evidence = private_directory(root / binding.instance / run_id)
    switch_log = evidence / "switch.jsonl"
    checks: dict[str, object] = {key: False for key in REQUIRED_CHECKS}
    checks.update(terminated_fallback=False, lock_released=True)
    expected = principals.password_reset_proof(must_change)
    # Secret-free facts only: the role, never the name; no value; no SID.
    result: dict[str, object] = {
        "schema": 1,
        "kind": "persistent-account-password",
        "run_id": run_id,
        "instance": binding.instance,
        "role": role,
        "uidNumber": account["uidNumber"],
        "must_change": must_change,
        "policy": {**policy.facts(), "source": policy.source},
        "started_utc": datetime.now(UTC).isoformat(),
        "expected_proof": expected,
        "read_back": None,
        "recorded": False,
        "checks": checks,
    }
    _say(f"evidence: {evidence}")
    children: list[subprocess.Popen[bytes]] = []
    session: PersistentControllerSession | None = None
    credentials = [value]
    value = ""
    failure: BaseException | None = None
    transcript: bytes | None = None
    step = "fabric"

    def attached() -> None:
        wait_for_switch_port(switch_log, "controller", SOCKET_MAC, timeout=60.0)
        checks["controller_attached"] = True

    with SignalGuard():
        try:
            port = _start_fabric(switch_log, evidence / "fabric.log", children)
            checks["fabric_started"] = True
            step = "session"
            session = PersistentControllerSession(
                target, port=port, password=password,
                canonical_state=canonical_state)
            password = b""
            _say(f"booting {binding.instance} in place; waiting up to "
                 f"{PERSISTENT_CONSOLE_TIMEOUT:g}s for its login prompt")
            console = session.start(attached=attached)
            checks["live_argv_audited"] = bool(
                session.facts["live_argv_audited"])
            checks["console_login"] = checks["ad_service_live"] = True
            _say("logged in; samba is live")
            step = "directory"
            policy_runner._prove_bound_directory(
                console, binding, checks, label="reset")
            _say("realm and domain SID are the bound directory's")
            step = "reset"
            outcome = _reset(
                console, account, credentials[0], must_change=must_change,
                roster=roster, source=source)
            checks["password_reset"] = True
            result["read_back"] = outcome.proof
            checks["read_back_matches"] = outcome.proof == expected
            _say(f"{role}: the directory read back {outcome.proof}")
            step = "poweroff"
            session.stop()
        except BaseException as error:  # noqa: BLE001 - evidence still lands
            failure = error
        finally:
            password = b""
            if session is not None:
                transcript, stopped = _finish_session(
                    session, checks, credentials)
                failure = failure or stopped
            credentials.clear()
            problems = terminate_children(
                children, terminate_timeout=10.0, kill_timeout=2.0)
            if problems and failure is None:
                failure = AccountPasswordError("; ".join(problems))
        checks["transcript_secret_free"] = transcript is not None
        passed = failure is None and _passed(checks)
        if failure is None and not passed:
            failure = AccountPasswordError(
                "the run did not prove: " + ", ".join(
                    key for key in REQUIRED_CHECKS
                    if checks.get(key) is not True))
        if (custody is not None and checks["password_reset"] is True
                and checks["read_back_matches"] is True):
            # The directory proved the reset, so the stored pending value is
            # now the account's, whether or not the run ended cleanly.
            try:
                custody.promote_pending(role)
                result["custody_promoted"] = True
            except (RuntimeError, OSError, ValueError) as error:
                failure = failure or error
                passed = False
        if passed:
            # The durable claim trails the durable fact: only a proven reset,
            # on a run that powered off cleanly, is appended.
            try:
                target.record_directory_account_password_reset({
                    "role": role,
                    "utc": datetime.now(UTC).isoformat(),
                    "must_change": must_change,
                    "run_id": run_id,
                })
                result["recorded"] = True
            except (RuntimeError, OSError, ValueError) as error:
                failure = error
                passed = False
        result["verdict"] = "pass" if passed else "fail"
        result["finished_utc"] = datetime.now(UTC).isoformat()
        if failure is not None:
            # The category the guest printed is in the message (never a
            # value); the step and the type say where it stopped.
            result["failure"] = {"step": step, "type": type(failure).__name__,
                                 "message": _failure_text(failure)}
        if transcript is not None:
            atomic_write(evidence / "console-transcript.log", transcript)
        atomic_write(
            evidence / "result.json",
            (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    if failure is not None:
        print(f"error: the password reset run failed at {step}: "
              f"{_failure_text(failure)}", file=sys.stderr)
        if checks["password_reset"] is True and not result["recorded"]:
            print(f"error: {binding.instance}'s directory PROVED the reset of "
                  f"{role}, so the new password is in effect, but the run did "
                  "not end cleanly and the marker was NOT changed. Log in "
                  "with the new password; repeating this target resets it "
                  "again", file=sys.stderr)
        elif step == "reset":
            print(f"error: the reset of {role} was not proven. The guest "
                  "program commits its writes in one transaction, so a "
                  "refusal before its commit changed nothing; repeat this "
                  "target", file=sys.stderr)
    if passed:
        print(f"{binding.instance}: reset the password of {role} "
              + ("(temporary: it must be changed at the next logon)"
                 if must_change else "(permanent)")
              + "; recorded in the instance marker")
    print(f"{binding.instance}: account password "
          f"{'PASS' if passed else 'FAIL'}; evidence {evidence}")
    return 0 if passed else 2


def generate_reset_value(
    credentials: AgentCredentialSource, name: str,
    policy: DirectoryPasswordPolicy, *, avoid: tuple[bytes, ...] = (),
) -> str:
    """A new value for an agent-custody reset, held to the directory's policy."""
    return generate_password(
        checks=(lambda value: principals.directory_password_problem(
            value, name, policy),),
        avoid=(*credentials.store.values(), *avoid))


def _failure_text(error: BaseException) -> str:
    """A failure's own words, which on this path name no account and no value.

    ``ControllerPrincipalError`` carries the guest's category, the binding
    and session errors name no value; anything else is reported by type.
    """
    if isinstance(error, (principals.ControllerPrincipalError,
                          AccountPasswordError,
                          PersistentControllerSessionError,
                          DurableBindingError)):
        return str(error)
    return type(error).__name__


def account_password(
    root: Path,
    instance: str,
    role: str,
    must_change: bool,
    apply: bool,
    *,
    canonical_state: Path = DEFAULT_STATE,
    identity_path: Path | None = None,
    overlay_path: Path | None = None,
    evidence_root: Path = DEFAULT_EVIDENCE_ROOT,
) -> int:
    """Plan, or apply, one durable account's password reset."""
    try:
        binding = durable_binding(
            root, instance, canonical_state=canonical_state,
            identity_path=identity_path, overlay_path=overlay_path)
        target = PersistentControllerInstance(binding.state, instance=instance)
        staged = target.directory_accounts()
        policy = instance_policy(target)
        roster = principals.durable_directory_roster(overlay_path)
        source = principals.identity_roster_source(overlay_path)
        account = planned_account(role, staged, roster, instance=instance)
        preview = session_command(
            target, 65535, canonical_state=canonical_state)
    except (principals.IdentityRosterError, principals.DirectoryPlanError,
            RuntimeError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"persistent directory account password reset: {instance}")
    print(f"state: {binding.state}")
    print(f"binding: the convergence record agrees with "
          f"{binding.identity_source}; the declared Controller address, "
          "prefix and gateway are the per-run fabric's; the staged roster "
          "fingerprint is current (values are compared, not printed)")
    print(f"account: {role} (directory role {account['role']}, uidNumber "
          f"{account['uidNumber']}), staged {staged['staged_utc']}. Its name "
          f"comes from {source} and appears only in the password prompt at "
          "your terminal; never in argv, the evidence, the marker or the "
          "transcript")
    print("new password: "
          + ("TEMPORARY: the account must change it at its next logon "
             "(pwdLastSet=0)" if must_change else
             "permanent (pwdLastSet stamped now); give CHANGE_AT_FIRST_LOGON=1 "
             "for a temporary one"))
    try:
        agent = instance_custody(target) == AGENT
    except (RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if (not must_change and not agent
            and staged.get("password_change_at_first_logon") is True):
        print("note: the staged record asks for a first-logon change, which "
              "is what arch-join expects by default; after a permanent reset "
              "give arch-join FIRST_LOGON_DONE=1 and this password as the "
              "current one")
    print(f"policy: it must meet {policy.source} ({policy.describe()}; "
          f"{policy.requirement()}), checked at your terminal before "
          "anything boots. The domain policy is NOT changed; a value the "
          "directory refuses anyway fails as password-policy")
    print("not RESTAGE: staging creates accounts and stops on the first one "
          "the directory already holds (account-exists). This resets one "
          "account that exists and refuses one that does not; it never "
          "creates")
    print("steps: log in; prove samba live; prove the realm and domain SID "
          "are the bound directory's; find the account (refuse if missing), "
          "require its staged uidNumber; replace unicodePwd as an "
          "administrator's reset"
          + (" and set pwdLastSet=0" if must_change else "")
          + " in one transaction; read back pwdLastSet, objectSid and "
          "uidNumber; power off over the console; append the reset to the "
          "instance marker ONLY if the read-back proved it and the run ended "
          "cleanly")
    if agent:
        print(CUSTODY_CONSOLE_LINE)
        print("new password: agent custody; generated to meet the policy "
              "above and stored as PENDING in the custody store before "
              "anything boots, then made the account's own once the "
              "directory proves the reset")
    else:
        print(f"console: this asks at your terminal for the "
              f"{CONSOLE_ACCOUNT} password, then the new password twice, "
              "before anything starts. Both are held in memory only, the new "
              "one crosses the console echo-suppressed on the guest shell's "
              "stdin exactly as staging's do, and neither is written to a "
              "file, argv, the environment, the marker or the evidence")
    print(f"evidence: {Path(evidence_root) / instance}/<run id>/ "
          "(console-transcript.log, redacted; switch.jsonl; fabric.log; "
          "result.json of secret-free facts)")
    print(" ".join(preview).replace(
        "127.0.0.1:65535", "127.0.0.1:<per-run port>"))
    if not apply:
        print("dry run; repeat with APPLY=1")
        return 0

    problems = [f"{tool} is not installed" for tool in ("qemu-system-x86_64",)
                if not shutil.which(tool)]
    if ovmf_pair() is None:
        problems.append("OVMF firmware was not found")
    if _persistent_running(target) is not False:
        problems.append(f"{instance} is already running or its lock cannot "
                        "be probed")
    if not problems:
        try:
            assert_installed(
                target.disk, subject=f"the persistent instance disk "
                f"{target.disk}", remedy="Recreate and converge the instance.")
        except ControllerImageError as error:
            problems.append(str(error))
    # Every refusal happens before the prompts: a typed credential is never
    # spent on a run that cannot start.
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2
    password = b""
    value = ""
    custody: AgentCredentialSource | None = None
    try:
        credentials = credential_source(target, prompt=_typed_secret)
        password = credentials.console(f"{CONSOLE_ACCOUNT} console password: ")
        if credentials.agent:
            custody = credentials
            name = account["name"]
            value = generate_reset_value(
                credentials, name, policy, avoid=(password,))
        else:
            kind = "temporary" if must_change else "new"
            typed = credentials.ask(
                f"{kind} password for {role} ({account['name']}): ",
                confirm=f"retype the {kind} password for {role}: ")
            # The guest reads a JSON document, so the value becomes a
            # ``str`` here, once; every reference is dropped when the run
            # ends.
            value = typed.decode("utf-8")
            typed = b""
        # Judged here, before anything boots, by the policy the directory
        # really holds: the reset program does not lift it.
        problem = principals.directory_password_problem(
            value, account["name"], policy)
        if problem is not None:
            raise ValueError(
                f"the new password for {role} {problem}; {policy.source} "
                "would refuse it. Nothing was booted")
        if custody is not None:
            # Stored BEFORE the reset can set it.
            custody.begin_pending(
                role, value, kind=PENDING_RESET, must_change=must_change)
    except (ValueError, RuntimeError, EOFError, KeyboardInterrupt) as error:
        password, value = b"", ""
        print(f"error: {error or type(error).__name__}", file=sys.stderr)
        return 2
    try:
        return _run(
            binding, target, password, account, value,
            must_change=must_change, roster=roster, source=source,
            policy=policy, canonical_state=canonical_state,
            evidence_root=evidence_root, custody=custody)
    except PersistentControllerSessionError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    finally:
        password, value = b"", ""


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Reset, prove and record one staged durable account's "
                    "password on a persistent Controller instance; a dry run "
                    "unless --apply")
    result.add_argument(
        "--state-dir", type=Path, default=DEFAULT_STATE,
        help="the disposable acceptance canonical, refused as a persistent "
             "target")
    result.add_argument("--instance", required=True)
    result.add_argument(
        "--persistent-root", type=Path, default=DEFAULT_PERSISTENT_ROOT)
    result.add_argument(
        "--role", required=True,
        help="the account's contract role, one of the instance's staged "
             "roles (never an account name)")
    result.add_argument(
        "--change-at-first-logon", action="store_true",
        help="the new password is temporary: the account must change it at "
             "its next logon")
    result.add_argument(
        "--directory-identity", type=Path, default=None,
        help="the permanent directory identity instead of "
             "homelab/instance/identity/directory.json")
    result.add_argument(
        "--identity-overlay", type=Path, default=None,
        help="the durable roster instead of "
             "homelab/instance/identity/principals.json")
    result.add_argument(
        "--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return account_password(
        args.persistent_root, args.instance, args.role,
        args.change_at_first_logon, args.apply,
        canonical_state=args.state_dir,
        identity_path=args.directory_identity,
        overlay_path=args.identity_overlay,
        evidence_root=args.evidence_root)


if __name__ == "__main__":
    raise SystemExit(main())
