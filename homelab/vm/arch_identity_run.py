#!/usr/bin/env python3
"""Live Arch identity login harness and identity-lifecycle evidence producer.

Gate 8. This drives a *real*, already installed and joined Arch workstation
over its serial console through the ordered identity lifecycle that
``homelab/workstations/identity_lifecycle.py`` judges, and emits the exact
JSONL evidence events that judge grades. It replaces the hand-authored
``valid_events`` fixture with evidence produced from an actual guest.

The Arch side of the lifecycle is console/SSSD, not GUI: the joined guest
presents a login on ``/dev/ttyS0`` and every proof is a bounded serial
exchange whose result the guest prints as an allowlisted marker. No secret is
ever recorded; only the pass/fail of each marker is retained.

Structure:

* ``ArchIdentityBundle`` validates a prepared, isolated bundle fail-closed.
* ``ArchIdentityDrive`` drives one serial console through the seven Arch
  lifecycle proofs, returning only booleans.
* ``run_lifecycle`` orchestrates an ``ArchIdentitySession`` (boundary +
  controller outage control + peer Windows evidence) and assembles the full
  ordered 18-check evidence stream.
* ``run`` validates the bundle, gates on ``--apply``, produces the evidence
  file, and self-judges it with the real ``identity_lifecycle`` judge.

The disposable-controller boot, the loopback fabric and the live Arch guest
are produced by the neighbouring gates; the live session is behind an
injectable factory so this module is fully unit-tested without QEMU.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Protocol

from .signal_cleanup import RunInterrupted, SignalGuard

# The judge lives under workstations/ and is imported by path so the producer
# and the judge stay in lockstep on the contract (order, checks, fields).
_WORKSTATIONS = Path(__file__).resolve().parents[1] / "workstations"
if str(_WORKSTATIONS) not in sys.path:
    sys.path.insert(0, str(_WORKSTATIONS))
import identity_lifecycle as lifecycle  # noqa: E402

CONTRACT = lifecycle.load_json(lifecycle.CONTRACT)
REQUIRED_CHECKS: tuple[str, ...] = tuple(CONTRACT["required_checks"])
WINDOWS_CHECKS: tuple[str, ...] = tuple(
    check for check in REQUIRED_CHECKS if check.startswith("windows-"))
ARCH_CHECKS: tuple[str, ...] = tuple(
    check for check in REQUIRED_CHECKS if check.startswith("arch-"))
CONTROLLER_CHECKS: tuple[str, ...] = (
    "controller-ready", "controller-offline", "controller-restored")

# The exact per-check evidence fields the judge requires, mirroring
# homelab/tests/test_identity_lifecycle.valid_events. Every emitted event also
# carries result and external_access. These are the single source of truth for
# the fields this producer writes and for validating peer Windows evidence.
CHECK_DETAILS: dict[str, dict[str, object]] = {
    "controller-ready": {
        "samba_ad": True, "dns": True, "kerberos": True, "time": True,
        "synthetic_directory": True},
    "windows-joined": {
        "domain_joined": True, "secure_channel": True, "machine_account": True},
    "arch-joined": {
        "domain_joined": True, "secure_channel": True, "machine_account": True},
    "windows-standard-online": {
        "principal_role": "standard", "elevated": False},
    "arch-standard-online": {
        "principal_role": "standard", "elevated": False},
    "windows-daily-admin": {
        "principal_role": "daily-administrator", "local_admin": True,
        "domain_admin": False},
    "arch-daily-admin": {
        "principal_role": "daily-administrator", "local_admin": True,
        "domain_admin": False},
    "domain-admin-separate": {"same_principal": False},
    "controller-offline": {"authority_reachable": False},
    "windows-cached-login": {"controller_online": False, "cached": True},
    "arch-cached-login": {"controller_online": False, "cached": True},
    "windows-uncached-denied": {"controller_online": False, "login": "denied"},
    "arch-uncached-denied": {"controller_online": False, "login": "denied"},
    "windows-local-rescue": {"scope": "local", "local_admin": True},
    "arch-local-rescue": {"scope": "local", "local_admin": True},
    "controller-restored": {"authority_reachable": True},
    "windows-secure-channel-restored": {"secure_channel": True},
    "arch-identity-restored": {"identity_lookup": True},
}

# The joined guest exposes a fixed, secret-free probe helper. Each invocation
# runs exactly one lifecycle check and prints a token-scoped marker. The probe
# owns the SSSD/Kerberos/sudo commands; this host only reads its verdict.
PROBE_HELPER = "/usr/local/sbin/homelab-arch-identity-probe"


class ArchIdentityError(RuntimeError):
    """The Arch identity lifecycle could not be produced safely.

    ``check`` names the lifecycle stage a failure is bound to, when one
    applies, so a failure teaches the next run where it stopped.
    """

    def __init__(self, message: str, *, check: str | None = None) -> None:
        super().__init__(message)
        self.check = check


def event(check: str, result: str, **fields: object) -> dict[str, object]:
    """Build one evidence event in the exact judged shape."""
    return {"check": check, "result": result, "external_access": False,
            **fields}


# --------------------------------------------------------------------------
# Bundle: a prepared, isolated Arch identity attempt.
# --------------------------------------------------------------------------

# gate 7 produces the installed+joined disk into the bundle; these are the
# artifacts that must be present, private, and isolation-preserving.
BUNDLE_DISK = "arch-workstation.qcow2"
BUNDLE_FIRMWARE = "OVMF_VARS.fd"
BUNDLE_AUTHORIZATION = "authorization.json"
BUNDLE_WINDOWS_EVIDENCE = "windows-evidence.jsonl"
EVIDENCE_DIRNAME = "evidence"
EVIDENCE_FILENAME = "identity-lifecycle.jsonl"

_AUTHORIZATION_EXPECTED = {
    "status": "prepared",
    "external_access": False,
    "installation_media_attached": False,
    "pxe_boot_enabled": False,
    "domain_joined": True,
}


@dataclass
class ArchIdentityBundle:
    """Fail-closed view of a prepared Arch identity acceptance bundle."""

    bundle: Path
    controller_state: Path
    realm: str = ""

    def __post_init__(self) -> None:
        self.bundle = Path(self.bundle).absolute()
        self.controller_state = Path(self.controller_state).absolute()

    @property
    def disk(self) -> Path:
        return self.bundle / BUNDLE_DISK

    @property
    def firmware(self) -> Path:
        return self.bundle / BUNDLE_FIRMWARE

    @property
    def windows_evidence_path(self) -> Path:
        return self.bundle / BUNDLE_WINDOWS_EVIDENCE

    @property
    def evidence_path(self) -> Path:
        return self.bundle / EVIDENCE_DIRNAME / EVIDENCE_FILENAME

    def _require_private_dir(self, path: Path, what: str) -> None:
        if path.is_symlink() or not path.is_dir():
            raise ArchIdentityError(f"{what} must be a real directory")
        if path.stat().st_mode & 0o077:
            raise ArchIdentityError(f"{what} must be private (mode 0700)")

    def _require_private_file(self, path: Path, what: str) -> None:
        if path.is_symlink() or not path.is_file():
            raise ArchIdentityError(f"{what} must be a regular file")
        if path.stat().st_mode & 0o077:
            raise ArchIdentityError(f"{what} must be mode 0600")

    def validate(self) -> None:
        """Prove the bundle is a private, isolated, joined attempt or refuse."""
        self._require_private_dir(self.bundle, "identity bundle")
        # The live disk is produced by gate 7; a bundle without it cannot run.
        self._require_private_file(self.disk, BUNDLE_DISK)
        self._require_private_file(self.firmware, BUNDLE_FIRMWARE)

        authorization_path = self.bundle / BUNDLE_AUTHORIZATION
        if authorization_path.is_symlink() or not authorization_path.is_file():
            raise ArchIdentityError(
                f"{BUNDLE_AUTHORIZATION} must be a regular file")
        try:
            authorization = json.loads(
                authorization_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ArchIdentityError(
                "identity authorization is unreadable") from error
        if not isinstance(authorization, dict):
            raise ArchIdentityError("identity authorization is not an object")
        for key, expected in _AUTHORIZATION_EXPECTED.items():
            if authorization.get(key) != expected:
                raise ArchIdentityError(
                    "identity authorization does not preserve joined isolation "
                    f"({key} must be {expected!r})")
        realm = authorization.get("realm")
        if not isinstance(realm, str) or not realm:
            raise ArchIdentityError(
                "identity authorization must name the Kerberos realm")
        self.realm = realm

        # Peer Windows evidence is a bundle input; the joined Arch harness does
        # not drive Windows, it merges the Windows lane's produced evidence.
        peer = self.windows_evidence_path
        if peer.is_symlink() or not peer.is_file():
            raise ArchIdentityError(
                f"{BUNDLE_WINDOWS_EVIDENCE} must be a regular file "
                "(the Windows lane's produced evidence)")

        # The Controller state is disposable but must be a real private dir.
        self._require_private_dir(self.controller_state, "controller state")

    def read_windows_evidence(self) -> list[dict[str, object]]:
        """Load and fail-closed validate the peer Windows evidence events."""
        try:
            with self.windows_evidence_path.open(encoding="utf-8") as source:
                events = lifecycle.load_events(source)
        except (OSError, lifecycle.EvidenceError) as error:
            raise ArchIdentityError(
                f"peer Windows evidence is unreadable: {error}") from error
        return validate_windows_evidence(events)


def validate_windows_evidence(
    events: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Fail-closed check that peer evidence proves every Windows check.

    The joined Arch harness never fabricates Windows facts. It merges the
    Windows lane's evidence verbatim, but refuses to emit a combined stream
    unless that evidence actually proves each Windows check with the fields the
    judge requires.
    """
    by_check: dict[str, dict[str, object]] = {}
    for candidate in events:
        check = candidate.get("check")
        if check in WINDOWS_CHECKS:
            if check in by_check:
                raise ArchIdentityError(
                    f"peer Windows evidence duplicates {check}")
            by_check[str(check)] = candidate
    ordered: list[dict[str, object]] = []
    for check in WINDOWS_CHECKS:
        candidate = by_check.get(check)
        if candidate is None:
            raise ArchIdentityError(
                f"peer Windows evidence is missing {check}")
        if candidate.get("result") != "pass":
            raise ArchIdentityError(
                f"peer Windows evidence for {check} did not pass")
        if candidate.get("external_access") is not False:
            raise ArchIdentityError(
                f"peer Windows evidence for {check} allows external access")
        for name, value in CHECK_DETAILS[check].items():
            if candidate.get(name) != value:
                raise ArchIdentityError(
                    f"peer Windows evidence for {check} lacks {name}={value!r}")
        ordered.append(candidate)
    return ordered


# --------------------------------------------------------------------------
# Serial drive: seven bounded Arch proofs.
# --------------------------------------------------------------------------

class SerialChannel(Protocol):
    """The bounded serial console surface this drive needs.

    ``homelab.vm.serial_automation.SerialAutomation`` satisfies it; tests
    provide a scripted double.
    """

    token: str

    def _send(self, value: bytes, event: str) -> None: ...

    def _wait(self, pattern: bytes, label: str): ...


class ArchIdentityDrive:
    """Drive one joined Arch guest through the seven lifecycle proofs.

    Each proof runs the guest probe helper for a single check and reads its
    token-scoped marker. Only the pass/fail verdict is retained. A missing
    marker (a timed-out or closed console) propagates as a serial error, which
    the caller binds to the pursued check; a ``FAIL`` marker is a genuine
    lifecycle failure and returns ``False`` so the judge rejects the evidence.
    """

    def __init__(self, channel: SerialChannel) -> None:
        self.channel = channel

    def _marker_key(self, check: str) -> str:
        return check.upper().replace("-", "_")

    def _probe(self, check: str) -> bool:
        token = self.channel.token
        command = f"{PROBE_HELPER} {check} {token}".encode("ascii")
        self.channel._send(command, f"arch-probe-{check}-sent")
        prefix = f"__TELOS_ARCH_{self._marker_key(check)}_{token}=".encode(
            "ascii")
        match = self.channel._wait(
            re.escape(prefix) + rb"(PASS|FAIL)\b",
            f"arch-probe-{check}-observed",
        )
        return match.group(1) == b"PASS"

    def prove_joined(self) -> bool:
        """`net ads testjoin`: a live secure channel and machine account."""
        return self._probe("arch-joined")

    def prove_standard_online(self) -> bool:
        """SSSD resolves and logs in the synthetic standard user, unelevated."""
        return self._probe("arch-standard-online")

    def prove_daily_admin(self) -> bool:
        """The daily administrator gets sudo via the domain admin group."""
        return self._probe("arch-daily-admin")

    def prove_domain_admin_separate(self) -> bool:
        """The daily and directory administrators are distinct principals."""
        return self._probe("domain-admin-separate")

    def prove_cached_login(self) -> bool:
        """With the Controller offline, the primed user logs in from cache."""
        return self._probe("arch-cached-login")

    def prove_uncached_denied(self) -> bool:
        """With the Controller offline, an unprimed user is denied."""
        return self._probe("arch-uncached-denied")

    def prove_local_rescue(self) -> bool:
        """The local break-glass administrator logs in independently."""
        return self._probe("arch-local-rescue")

    def prove_identity_restored(self) -> bool:
        """After reconnect, SSSD resolves the directory identity again."""
        return self._probe("arch-identity-restored")


# --------------------------------------------------------------------------
# Session orchestration.
# --------------------------------------------------------------------------

class ArchIdentitySession(Protocol):
    """A live boundary the lifecycle is driven over.

    The real implementation boots the loopback fabric, the disposable Samba AD
    Controller and the joined Arch workstation, and controls the Controller
    outage. Tests provide a deterministic double.
    """

    def start(self) -> None: ...

    def open_channel(self) -> SerialChannel: ...

    def observe_controller_ready(self) -> bool: ...

    def take_controller_offline(self) -> None: ...

    def observe_controller_offline(self) -> bool: ...

    def restore_controller(self) -> None: ...

    def observe_controller_restored(self) -> bool: ...

    def windows_evidence(self) -> list[dict[str, object]]: ...

    def stop(self) -> list[str]: ...


def assemble_evidence(
    outcomes: Mapping[str, bool],
    windows_events: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Compose the full ordered 18-check evidence stream.

    Arch and Controller checks come from ``outcomes`` (live observations);
    Windows checks are merged verbatim from validated peer evidence. The order
    is the contract's required order, so a well-formed pass stream is exactly
    the shape the judge accepts.
    """
    windows_by_check = {str(item["check"]): item for item in windows_events}
    events: list[dict[str, object]] = []
    for check in REQUIRED_CHECKS:
        if check in WINDOWS_CHECKS:
            events.append(windows_by_check[check])
            continue
        if check not in outcomes:
            raise ArchIdentityError(
                f"lifecycle observation is missing for {check}", check=check)
        result = "pass" if outcomes[check] else "fail"
        events.append(event(check, result, **CHECK_DETAILS[check]))
    return events


def _probe_check(
    outcomes: dict[str, bool], check: str, prove: Callable[[], bool],
) -> None:
    """Run one bounded proof, binding a serial failure to its check."""
    try:
        outcomes[check] = prove()
    except lifecycle.EvidenceError:
        raise
    except ArchIdentityError:
        raise
    except Exception as error:  # bounded serial failure: name the stage
        raise ArchIdentityError(
            f"{check} proof failed on the console: {type(error).__name__}",
            check=check,
        ) from error


def run_lifecycle(
    session: ArchIdentitySession,
) -> list[dict[str, object]]:
    """Drive the ordered Arch lifecycle and return the evidence stream.

    Teardown is always attempted and bounded. Any lifecycle failure is raised
    after teardown so a live guest is never left running.
    """
    primary: BaseException | None = None
    cleanup_errors: list[str] = []
    events: list[dict[str, object]] = []
    started = False
    try:
        session.start()
        started = True
        outcomes: dict[str, bool] = {}
        outcomes["controller-ready"] = session.observe_controller_ready()
        drive = ArchIdentityDrive(session.open_channel())

        _probe_check(outcomes, "arch-joined", drive.prove_joined)
        _probe_check(
            outcomes, "arch-standard-online", drive.prove_standard_online)
        _probe_check(outcomes, "arch-daily-admin", drive.prove_daily_admin)
        _probe_check(
            outcomes, "domain-admin-separate",
            drive.prove_domain_admin_separate)

        session.take_controller_offline()
        outcomes["controller-offline"] = session.observe_controller_offline()
        _probe_check(outcomes, "arch-cached-login", drive.prove_cached_login)
        _probe_check(
            outcomes, "arch-uncached-denied", drive.prove_uncached_denied)
        _probe_check(outcomes, "arch-local-rescue", drive.prove_local_rescue)

        session.restore_controller()
        outcomes["controller-restored"] = session.observe_controller_restored()
        _probe_check(
            outcomes, "arch-identity-restored", drive.prove_identity_restored)

        events = assemble_evidence(outcomes, session.windows_evidence())
    except BaseException as error:  # noqa: BLE001 - re-raised after teardown
        primary = error
    finally:
        if started:
            try:
                cleanup_errors = session.stop()
            except BaseException as error:  # noqa: BLE001
                cleanup_errors = [f"teardown: {type(error).__name__}"]

    if primary is not None:
        if isinstance(primary, RunInterrupted) and not cleanup_errors:
            raise primary
        if isinstance(primary, ArchIdentityError) and not cleanup_errors:
            raise primary
        detail = f"lifecycle: {type(primary).__name__}"
        raise ArchIdentityError(
            "Arch identity lifecycle failed; "
            + "; ".join([detail, *cleanup_errors]),
            check=getattr(primary, "check", None),
        ) from primary
    if cleanup_errors:
        raise ArchIdentityError(
            "Arch identity teardown was incomplete; " + "; ".join(
                cleanup_errors))
    return events


def write_evidence(path: Path, events: list[dict[str, object]]) -> None:
    """Write the evidence stream as one private JSONL file."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    body = "".join(
        json.dumps(item, sort_keys=True) + "\n" for item in events)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o600)


def self_judge(path: Path) -> tuple[bool, str]:
    """Grade the produced evidence with the real lifecycle judge."""
    try:
        with path.open(encoding="utf-8") as source:
            result = lifecycle.judge(CONTRACT, lifecycle.load_events(source))
    except (OSError, lifecycle.EvidenceError) as error:
        return False, str(error)
    return True, (
        f"{result['checks']} checks, external_access="
        f"{result['external_access']}")


SessionFactory = Callable[[ArchIdentityBundle], ArchIdentitySession]


class ArchIdentityBoundary:
    """Live loopback session: fabric, disposable Samba AD, joined Arch guest.

    This is the real, unattended path. It boots a loopback userspace switch
    and gateway, the disposable converged Samba AD Controller (the same
    disposable-controller convergence the Windows lane uses), and the joined
    Arch workstation from the bundle disk, then drives the guest over serial.

    Every heavy dependency is imported inside ``start`` so importing this
    module (for the producer/judge unit tests) never needs QEMU. Because the
    joined disk is produced by gate 7 and the converged Controller by gate 6,
    the live path binds to those artifacts; the producer logic above is proven
    independently against an injected session.
    """

    #: Gate 7 must ship these on the joined disk for the live drive to work.
    GATE7_CONTRACT = (
        f"a secret-free probe helper at {PROBE_HELPER} that runs one lifecycle "
        "check and prints __TELOS_ARCH_<CHECK>_<token>=PASS|FAIL, plus a "
        "console-login contract for the local break-glass administrator"
    )

    def __init__(self, bundle: ArchIdentityBundle) -> None:
        self.bundle = bundle
        self._runtime = None
        self._processes: dict[str, object] = {}
        self._controller_console = None
        self._channel: SerialChannel | None = None
        self._controller_online = True

    def start(self) -> None:
        # Imported lazily: these pull QEMU/topology helpers that the pure
        # producer path (and its tests) must never require.
        import socket
        import tempfile

        from .factory_runner import (
            GATEWAY_MAC, gateway_command, switch_command, wait_for_switch_port,
        )

        runtime = Path(tempfile.mkdtemp(prefix="telos-arch-identity-"))
        runtime.chmod(0o700)
        self._runtime = runtime

        listener = socket.socket()
        try:
            import subprocess

            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(3)
            self._port = int(listener.getsockname()[1])
            self._processes["switch"] = subprocess.Popen(
                switch_command(listener.fileno(), runtime / "switch.jsonl"),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT, pass_fds=(listener.fileno(),))
            self._processes["gateway"] = subprocess.Popen(
                gateway_command(self._port), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            wait_for_switch_port(
                runtime / "switch.jsonl", "gateway", GATEWAY_MAC)
        finally:
            listener.close()

        self._start_controller()
        self._start_workstation()

    def _start_controller(self) -> None:
        # The disposable converged Samba AD Controller bring-up (seed install
        # then offline convergence over the private serial console) is the same
        # machinery the Windows identity lane uses; gate 6 owns it. It is bound
        # here rather than duplicated. Until it is wired into this lane, refuse
        # loudly instead of pretending the directory is ready.
        raise ArchIdentityError(
            "live disposable Samba AD Controller bring-up is not wired into "
            "the Arch lane yet; it reuses the gate-6 converged-controller "
            "helpers. Run the producer against an injected session until then.",
            check="controller-ready",
        )

    def _start_workstation(self) -> None:  # pragma: no cover - live path
        raise ArchIdentityError(
            "live joined Arch workstation boot requires gate 7: "
            + self.GATE7_CONTRACT,
            check="arch-joined",
        )

    def open_channel(self) -> SerialChannel:  # pragma: no cover - live path
        if self._channel is None:
            raise ArchIdentityError("Arch serial console is not open")
        return self._channel

    def observe_controller_ready(self) -> bool:  # pragma: no cover
        return self._controller_online

    def take_controller_offline(self) -> None:  # pragma: no cover - live path
        import signal as signal_module

        process = self._processes.get("controller")
        if process is not None:
            process.send_signal(signal_module.SIGSTOP)  # type: ignore[attr-defined]
        self._controller_online = False

    def observe_controller_offline(self) -> bool:  # pragma: no cover
        return not self._controller_online

    def restore_controller(self) -> None:  # pragma: no cover - live path
        import signal as signal_module

        process = self._processes.get("controller")
        if process is not None:
            process.send_signal(signal_module.SIGCONT)  # type: ignore[attr-defined]
        self._controller_online = True

    def observe_controller_restored(self) -> bool:  # pragma: no cover
        return self._controller_online

    def windows_evidence(self) -> list[dict[str, object]]:
        return self.bundle.read_windows_evidence()

    def stop(self) -> list[str]:  # pragma: no cover - live path
        from .signal_cleanup import terminate_children

        failures: list[str] = []
        processes = [
            proc for proc in self._processes.values() if proc is not None]
        if processes:
            failures = terminate_children(processes)  # type: ignore[arg-type]
        return failures


def _default_session_factory(bundle: ArchIdentityBundle) -> ArchIdentitySession:
    return ArchIdentityBoundary(bundle)


def run(
    bundle: Path,
    *,
    apply: bool,
    controller_state: Path,
    session_factory: SessionFactory | None = None,
) -> int:
    """Validate the bundle, gate on ``--apply``, produce and judge evidence."""
    prepared = ArchIdentityBundle(bundle, controller_state)
    prepared.validate()

    print("Boundary: loopback-only live Arch identity acceptance")
    print(f"Bundle: {prepared.bundle}")
    print(f"Controller state: {prepared.controller_state}")
    print(f"Realm: {prepared.realm}")
    print("Installation media, PXE, host networking and UniFi: disabled")
    if not apply:
        print("dry run; repeat with --apply to drive the identity lifecycle")
        return 0

    factory = session_factory or _default_session_factory
    with SignalGuard():
        session = factory(prepared)
        events = run_lifecycle(session)
        write_evidence(prepared.evidence_path, events)

    ok, summary = self_judge(prepared.evidence_path)
    if ok:
        print(f"PASS: {summary}")
        print(f"Evidence: {prepared.evidence_path}")
        return 0
    print(f"FAIL: {summary}", file=sys.stderr)
    print(f"Evidence: {prepared.evidence_path}", file=sys.stderr)
    return 2


def parser() -> argparse.ArgumentParser:
    from .bootstrap_dc import DEFAULT_STATE
    result = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    result.add_argument("--bundle", type=Path, required=True)
    result.add_argument(
        "--controller-state", type=Path, default=DEFAULT_STATE)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(
            args.bundle,
            apply=args.apply,
            controller_state=args.controller_state,
        )
    except RunInterrupted as error:
        print(f"arch identity run: {error}", file=sys.stderr)
        return error.exit_code
    except ArchIdentityError as error:
        print(f"arch identity run: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
