#!/usr/bin/env python3
"""Set a persistent instance's directory password policy, prove it, record it.

``make homelab-factory-persistent-password-policy`` (TASK-28,
``homelab/DURABLE-WORKSTATION-FLOW.md``).  Samba enforces its domain's password
settings on every password set or changed, and the durable stages judge each
typed password against them on the host before anything boots.  Provisioning
leaves Samba's default -- seven characters, three character classes, a one-day
minimum age -- which refuses the short, change-it-later passwords the owner
chose for the throwaway ``rehearsal`` on 2026-09-30.  This changes the policy
explicitly, and records what it changed:

* the dry run (the default) binds the instance exactly as the probe does,
  prints the policy the instance records (Samba's default when none), the
  requested one and the change, and starts nothing;
* ``--apply`` asks once for the ``local-rescue`` console password, after every
  refusal and before any process starts, boots the instance in place on a
  per-run switch and gateway with no workstation (``PersistentControllerSession``,
  the probe's shape), proves the realm and domain SID are the bound
  directory's, reads the live policy, runs ``samba-tool domain passwordsettings
  set`` as root, reads it back with ``samba-tool domain passwordsettings
  show``, and powers the guest off over its console;
* only when the read-back is the requested policy and the run ended cleanly
  is it written into the instance marker, atomically
  (``PersistentControllerInstance.record_directory_password_policy``).  The
  durable stages then judge against it and name it in every refusal.

A policy weaker than Samba's default (shorter than seven characters, or
complexity off) also sets the minimum password age to 0 days, so a password
set under it can be changed again at once; any other policy sets Samba's
default of 1 day.  The policy is the DOMAIN's: it applies to every account in
the directory, which is why the keeper's policy is a separate decision.
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

from .bootstrap_dc import (  # noqa: E402
    CONSOLE_ACCOUNT,
    DEFAULT_PERSISTENT_ROOT,
    DEFAULT_STATE,
    DOMAIN_SID_COMMAND,
    DOMAIN_SID_VALUE,
    PERSISTENT_CONSOLE_TIMEOUT,
    SOCKET_MAC,
    _console_root,
    _persistent_running,
    _typed_secret,
    ovmf_pair,
)
from .controller_image import (  # noqa: E402
    ControllerImageError, assert_installed)
from .credential_custody import (  # noqa: E402
    AGENT, credential_source, instance_custody)
from .directory_password_policy import (  # noqa: E402
    SHOW_COMMAND,
    SHOW_VALUE,
    DirectoryPasswordPolicy,
    DirectoryPasswordPolicyError,
    parse_passwordsettings_show,
    policy_record,
    requested_policy,
    set_command,
    transported_show_text,
)
from .durable_workstation import (  # noqa: E402
    SID_MATCH,
    DurableBinding,
    DurableBindingError,
    check_live_directory,
    durable_binding,
)
from .factory_runner import wait_for_switch_port  # noqa: E402
from .persistent_controller_session import (  # noqa: E402
    CUSTODY_CONSOLE_LINE,
    REALM_COMMAND,
    REALM_VALUE,
    PersistentControllerSession,
    PersistentControllerSessionError,
    _finish_session,
    _start_fabric,
    session_command,
)
from .secure_artifacts import atomic_write, private_directory  # noqa: E402
from .signal_cleanup import SignalGuard, terminate_children  # noqa: E402
from .simulation_overlay import PersistentControllerInstance  # noqa: E402


#: Retained evidence, beside the probe's under the gitignored homelab/var
#: (ADR 0046): never in the instance directory, whose destroy refuses
#: unexpected files.
DEFAULT_EVIDENCE_ROOT = Path("homelab/var/factory/persistent-password-policy")
#: Every boolean a run must prove before its policy is recorded.
REQUIRED_CHECKS = (
    "fabric_started", "controller_attached", "live_argv_audited",
    "console_login", "ad_service_live", "realm_matches", "domain_sid_matches",
    "policy_set", "read_back_matches", "clean_poweroff", "lock_released",
    "transcript_secret_free",
)


class PasswordPolicyError(RuntimeError):
    """The directory password policy could not be set and proven."""


def _say(message: str) -> None:
    print(f"password-policy: {message}", flush=True)


def _prove_bound_directory(
    console, binding: DurableBinding, checks: dict[str, object],
    *, label: str = "policy",
) -> None:
    """The realm and the SID, before anything is written into the directory.

    Unlike the probe, a SID that only needs repair is refused too: this run
    records into the same marker, and the repair has its own target.
    ``persistent_account_password`` proves its directory the same way, under
    its own *label*.
    """
    realm = _console_root(
        console, REALM_COMMAND, f"{label}-realm", value=REALM_VALUE)
    checks["realm_matches"] = (
        realm is not None
        and realm.decode("ascii").upper() == binding.kerberos_realm)
    if not checks["realm_matches"]:
        raise DurableBindingError(
            "the live directory does not serve the bound realm; nothing was "
            "written to it")
    raw_sid = _console_root(
        console, DOMAIN_SID_COMMAND, f"{label}-domain-sid",
        value=DOMAIN_SID_VALUE)
    live = "" if raw_sid is None else raw_sid.decode("ascii")
    if check_live_directory(binding.domain_sid, live) != SID_MATCH:
        raise DurableBindingError(
            "the recorded domain SID is a truncated prefix of the live one; "
            "repair it first with make homelab-factory-persistent-probe "
            "REPAIR_SID=1. Nothing was written to the directory")
    checks["domain_sid_matches"] = True


def _live_policy(console, label: str) -> DirectoryPasswordPolicy:
    raw = _console_root(console, SHOW_COMMAND, label, value=SHOW_VALUE)
    return parse_passwordsettings_show(
        transported_show_text(raw or b""), source="the live directory")


def _passed(checks: dict[str, object]) -> bool:
    return (all(checks.get(key) is True for key in REQUIRED_CHECKS)
            and checks.get("terminated_fallback") is False)


def _run(
    binding: DurableBinding,
    target: PersistentControllerInstance,
    password: bytes,
    policy: DirectoryPasswordPolicy,
    *,
    canonical_state: Path,
    evidence_root: Path,
) -> int:
    run_id = (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
              + f"-{os.getpid()}-{secrets.token_hex(4)}")
    root = Path(evidence_root).absolute()
    private_directory(root, parents=True)
    private_directory(root / binding.instance)
    evidence = private_directory(root / binding.instance / run_id)
    switch_log = evidence / "switch.jsonl"
    checks: dict[str, object] = {key: False for key in REQUIRED_CHECKS}
    checks.update(terminated_fallback=False, lock_released=True)
    result: dict[str, object] = {
        "schema": 1,
        "kind": "persistent-password-policy",
        "run_id": run_id,
        "instance": binding.instance,
        "started_utc": datetime.now(UTC).isoformat(),
        "recorded_before": (binding.password_policy.facts()
                            if binding.password_policy.recorded else None),
        "requested": policy.facts(),
        "set_command": set_command(policy),
        "live_before": None,
        "read_back": None,
        "recorded": False,
        "checks": checks,
    }
    _say(f"evidence: {evidence}")
    children: list[subprocess.Popen[bytes]] = []
    session: PersistentControllerSession | None = None
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
            _prove_bound_directory(console, binding, checks)
            _say("realm and domain SID are the bound directory's")
            step = "read-live"
            try:
                before = _live_policy(console, "policy-show-before")
                result["live_before"] = before.facts()
                _say(f"live policy before: {before.describe()}")
            except DirectoryPasswordPolicyError as error:
                # Evidence only: the read-back below is what is judged.
                result["live_before"] = f"unparsed: {error}"
            step = "set"
            _console_root(console, set_command(policy), "policy-set")
            checks["policy_set"] = True
            step = "read-back"
            after = _live_policy(console, "policy-show-after")
            result["read_back"] = after.facts()
            checks["read_back_matches"] = after.rules == policy.rules
            if not checks["read_back_matches"]:
                raise PasswordPolicyError(
                    f"the directory read back {after.describe()}, not the "
                    f"requested {policy.describe()}; nothing was recorded")
            _say(f"read back: {after.describe()}")
            step = "poweroff"
            session.stop()
        except BaseException as error:  # noqa: BLE001 - evidence still lands
            failure = error
        finally:
            password = b""
            if session is not None:
                transcript, stopped = _finish_session(session, checks, [])
                failure = failure or stopped
            problems = terminate_children(
                children, terminate_timeout=10.0, kill_timeout=2.0)
            if problems and failure is None:
                failure = PasswordPolicyError("; ".join(problems))
        checks["transcript_secret_free"] = transcript is not None
        passed = failure is None and _passed(checks)
        if failure is None and not passed:
            failure = PasswordPolicyError(
                "the run did not prove: " + ", ".join(
                    key for key in REQUIRED_CHECKS
                    if checks.get(key) is not True))
        if passed:
            # The durable claim trails the durable fact: only a read-back
            # that matched, on a run that powered off cleanly, is recorded.
            try:
                target.record_directory_password_policy(
                    policy_record(policy, run_id=run_id))
                result["recorded"] = True
            except (RuntimeError, OSError, ValueError) as error:
                failure = error
                passed = False
        result["verdict"] = "pass" if passed else "fail"
        result["finished_utc"] = datetime.now(UTC).isoformat()
        if failure is not None:
            result["failure"] = {"step": step, "type": type(failure).__name__}
        if transcript is not None:
            atomic_write(evidence / "console-transcript.log", transcript)
        atomic_write(
            evidence / "result.json",
            (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    if failure is not None:
        print(f"error: the password policy run failed at {step}: {failure}",
              file=sys.stderr)
        if checks["read_back_matches"] is True and not result["recorded"]:
            print(f"error: {binding.instance}'s directory read back the "
                  "requested policy, but the run did not end cleanly, so the "
                  "marker was NOT changed; the durable stages still judge by "
                  "the old record. Repeat this target: setting the same "
                  "policy again is harmless", file=sys.stderr)
        elif checks["policy_set"] is True:
            print(f"error: samba-tool accepted the change but it was not "
                  f"proven; {binding.instance}'s directory may hold a policy "
                  "its marker does not record. Repeat this target",
                  file=sys.stderr)
    if passed:
        print(f"{binding.instance}: recorded {policy.source}: "
              f"{policy.describe()}. The durable stages now judge every "
              "typed password against it")
    print(f"{binding.instance}: password policy "
          f"{'PASS' if passed else 'FAIL'}; evidence {evidence}")
    return 0 if passed else 2


def _change(recorded: DirectoryPasswordPolicy,
            requested: DirectoryPasswordPolicy) -> str:
    parts = []
    for label, before, after in (
            ("minimum length", recorded.min_length, requested.min_length),
            ("complexity", "on" if recorded.complexity else "off",
             "on" if requested.complexity else "off"),
            ("minimum age (days)", recorded.min_age_days,
             requested.min_age_days)):
        if before != after:
            parts.append(f"{label} {before} -> {after}")
    if not parts:
        return ("none: the instance already records this policy; applying "
                "sets it again and proves it by read-back")
    return "; ".join(parts)


def password_policy(
    root: Path,
    instance: str,
    min_length: object,
    complexity: object,
    apply: bool,
    *,
    canonical_state: Path = DEFAULT_STATE,
    identity_path: Path | None = None,
    overlay_path: Path | None = None,
    evidence_root: Path = DEFAULT_EVIDENCE_ROOT,
) -> int:
    """Plan, or apply, one directory password policy for a persistent instance."""
    try:
        policy = requested_policy(min_length, complexity, instance=instance)
    except DirectoryPasswordPolicyError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    try:
        binding = durable_binding(
            root, instance, canonical_state=canonical_state,
            identity_path=identity_path, overlay_path=overlay_path)
        target = PersistentControllerInstance(binding.state, instance=instance)
        preview = session_command(
            target, 65535, canonical_state=canonical_state)
    except (RuntimeError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    recorded = binding.password_policy
    print(f"persistent directory password policy: {instance}")
    print(f"state: {binding.state}")
    print(f"binding: the convergence record agrees with "
          f"{binding.identity_source}; the declared Controller address, "
          "prefix and gateway are the per-run fabric's; the staged roster "
          "fingerprint is current (values are compared, not printed)")
    print("recorded now: "
          + (f"{recorded.describe()} ({recorded.source})" if recorded.recorded
             else f"none, so Samba's default applies ({recorded.describe()})"))
    print(f"requested: {policy.describe()}")
    print(f"change: {_change(recorded, policy)}")
    print("minimum age: "
          + ("0 days, because this policy is weaker than Samba's default: a "
             "password set under it can be changed again at once"
             if policy.relaxed else
             "1 day, Samba's default, because this policy is not weaker "
             "than it"))
    print(f"scope: the whole domain. The policy applies to every account in "
          f"{instance}'s directory, and the durable stages judge the daily "
          "administrator's new password and both break-glass passwords by "
          "it; a keeper instance's policy is a separate decision")
    print("steps: log in; prove samba live; prove the realm and domain SID "
          "are the bound directory's; read the live policy; run as root: "
          f"{set_command(policy)}; read it back with samba-tool domain "
          "passwordsettings show; power off over the console; record it in "
          "the instance marker ONLY if the read-back matches and the run "
          "ended cleanly")
    try:
        agent = instance_custody(target) == AGENT
    except (RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if agent:
        print(CUSTODY_CONSOLE_LINE)
    else:
        print(f"console: this asks at your terminal for the {CONSOLE_ACCOUNT} "
              "password once, before anything starts; it is held in memory "
              "only and never written to a file, argv, the environment or the "
              "evidence")
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
    # Every refusal happens before the prompt: a typed credential is never
    # spent on a run that cannot start.
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2
    try:
        password = credential_source(target, prompt=_typed_secret).console(
            f"{CONSOLE_ACCOUNT} console password: ")
    except (ValueError, RuntimeError, EOFError, KeyboardInterrupt) as error:
        print(f"error: {error or type(error).__name__}", file=sys.stderr)
        return 2
    try:
        return _run(
            binding, target, password, policy,
            canonical_state=canonical_state, evidence_root=evidence_root)
    except PersistentControllerSessionError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    finally:
        password = b""


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Set, prove and record a persistent Controller "
                    "instance's directory password policy; a dry run unless "
                    "--apply")
    result.add_argument(
        "--state-dir", type=Path, default=DEFAULT_STATE,
        help="the disposable acceptance canonical, refused as a persistent "
             "target")
    result.add_argument("--instance", required=True)
    result.add_argument(
        "--persistent-root", type=Path, default=DEFAULT_PERSISTENT_ROOT)
    result.add_argument(
        "--min-length", required=True,
        help="minimum password length, a whole number from 1 to 14")
    result.add_argument(
        "--complexity", required=True, help="password complexity: on or off")
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
    return password_policy(
        args.persistent_root, args.instance, args.min_length,
        args.complexity, args.apply,
        canonical_state=args.state_dir,
        identity_path=args.directory_identity,
        overlay_path=args.identity_overlay,
        evidence_root=args.evidence_root)


if __name__ == "__main__":
    raise SystemExit(main())
