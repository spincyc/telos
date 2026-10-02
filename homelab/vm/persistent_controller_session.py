#!/usr/bin/env python3
"""Boot a persistent Controller instance, in place, on a per-run fabric.

TASK-28, steps 2 and 3 (``homelab/DURABLE-WORKSTATION-FLOW.md``).  Installs
stay on the disposable Controller; the persistent one serves joins and logins
only, so a durable run attaches the instance's OWN disk to the per-run
loopback switch instead of a ``DisposableBootDisk`` copy.

``PersistentControllerSession`` owns that one guest.  Its properties are the
point, not its mechanism:

* *in place, under the instance lock.*  The instance's own qcow2 and
  variables, never the acceptance canonical (refused before anything starts),
  and a closed-allowlist argv audit before and after launch
  (``simulated_topology.audit_persistent_controller``).
* *its own MAC.*  Convergence wrote a systemd-networkd unit that matches the
  MAC the instance was converged with, so the session keeps ``SOCKET_MAC`` and
  the switch and gateway are told that MAC rather than the other way round.
* *no QMP, no medium, no pause.*  The class has no pause, suspend or signal
  method at all; asking for one raises.  Gate 6's controller-outage faults
  therefore cannot reach a durable directory through it.
* *a clean stop.*  It stops by a console ``poweroff``; terminating QEMU is a
  power cut on the directory and is only a recorded fallback.  QEMU runs in
  its own session so an operator's Ctrl-C reaches this process, which then
  powers the guest off, and not the guest directly.
* *one typed credential.*  The owner's ``local-rescue`` password is typed
  once, after every refusal and before any process starts, held in memory
  only to log in again after a relaunch, and dropped when the session closes.

``make homelab-factory-persistent-probe`` drives one session with no
workstation (``probe`` below): log in, prove AD live, read the realm and SID,
check the fabric-facing address, gateway, DNS records and clock, stage and
destroy one ``tj-`` join principal, power off.  It retires the risk of the
persistent Controller on the per-run fabric before any workstation depends on
it.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Iterable

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
    _console_poweroff,
    _console_root,
    _persistent_running,
    _typed_secret,
    ovmf_pair,
    paths,
    persistent_console_login,
    persistent_paths,
    persistent_switch_command,
    qemu_command,
)
from .controller_image import (  # noqa: E402
    ControllerImageError, assert_installed)
from .credential_custody import (  # noqa: E402
    AGENT, CustodyError, credential_source, custody_scan_values,
    instance_custody)
from .durable_workstation import (  # noqa: E402
    FABRIC_CONTROLLER_ADDRESS,
    FABRIC_GATEWAY_ADDRESS,
    FABRIC_PREFIX,
    SID_MATCH,
    DurableBinding,
    DurableBindingError,
    check_live_directory,
    durable_binding,
    repaired_convergence,
)
from .factory_runner import (  # noqa: E402
    GATEWAY_MAC, gateway_command, wait_for_switch_port)
from .network import socket_network_args  # noqa: E402
from .secret_scan import (  # noqa: E402
    count_secret_occurrences, secret_needles)
from .secure_artifacts import atomic_write, private_directory  # noqa: E402
from .serial_automation import (  # noqa: E402
    SerialAutomation, SerialAutomationError)
from .signal_cleanup import SignalGuard, terminate_children  # noqa: E402
from .simulated_topology import (  # noqa: E402
    BACKUP_INPUT, audit_persistent_controller, backup_disk_args, live_qemu_argv)
from .simulation_evidence import redact  # noqa: E402
from .simulation_overlay import PersistentControllerInstance  # noqa: E402


#: Retained probe evidence, beside the other factory run directories under the
#: gitignored ``homelab/var`` (ADR 0046): never in the instance directory,
#: whose ``destroy`` refuses unexpected files.
DEFAULT_EVIDENCE_ROOT = Path("homelab/var/factory/persistent-probe")
#: After a console poweroff is observed, QEMU exits on its own; this bounds it.
POWEROFF_EXIT_TIMEOUT = 120.0
TERMINATE_TIMEOUT = 20.0
KILL_TIMEOUT = 10.0
#: The switch waits for the gateway and the Controller within this bound.
SWITCH_ACCEPT_TIMEOUT = 120.0
#: A quiet directory emits few frames; the switch must not exit under it.
SWITCH_IDLE_TIMEOUT = 3600.0
#: Kerberos' default tolerance for clock skew between client and KDC.
KERBEROS_MAX_SKEW_SECONDS = 300
#: Console bytes retained for the redacted transcript (the tail is kept).
TRANSCRIPT_LIMIT = 16 * 1024 * 1024
REDACTED = b"[REDACTED]"
#: Fault hooks gate 6 and gate 8 call on a disposable boundary.  None exists
#: here; each is refused by name so a runner that reaches for one learns why.
FORBIDDEN_FAULT_HOOKS = frozenset({
    "pause", "resume", "suspend", "freeze", "thaw", "sigstop", "sigcont",
    "send_signal", "kill", "take_controller_offline", "restore_controller",
    "set_controller_available",
})
#: The live realm, from the loader the join-principal program itself trusts.
REALM_COMMAND = (
    "/usr/bin/python3 -c 'from samba.param import LoadParm; "
    "lp = LoadParm(); lp.load_default(); "
    "print(str(lp.get(\"realm\") or \"NONE\").upper())' 2>/dev/null "
    "|| echo NONE")
REALM_VALUE = rb"[A-Z0-9](?:[A-Z0-9.-]{0,251}[A-Z0-9])?"
COUNT_VALUE = rb"[0-9]{1,6}"
#: The plan's console line for an agent-custody instance (TASK-40).
CUSTODY_CONSOLE_LINE = (
    f"console: agent custody; the {CONSOLE_ACCOUNT} password is read from "
    "this throwaway instance's custody store, nothing is asked at a "
    "terminal, and every stored value is scanned for in the evidence")
#: Every boolean the probe must prove.  ``domain_sid`` is a state string and
#: ``clock_skew_seconds`` an integer; neither carries a value from the
#: directory.
REQUIRED_CHECKS = (
    "fabric_started", "controller_attached", "live_argv_audited",
    "console_login", "ad_service_live", "realm_matches",
    "interface_address", "gateway_reachable", "a_record", "srv_ldap",
    "srv_kerberos", "clock_within_kerberos_skew", "join_principal_staged",
    "join_principal_destroyed", "clean_poweroff", "lock_released",
    "transcript_secret_free",
)


class PersistentControllerSessionError(RuntimeError):
    """The persistent Controller session cannot proceed safely."""


class _TeeReader:
    """The guest's console as ``SerialAutomation`` reads it, also retained.

    ``SerialAutomation.transcript`` keeps only the last 64 KiB, which loses
    the boot log a fabric failure is diagnosed from.  This keeps the tail of
    everything read, bounded, for the redacted transcript.
    """

    def __init__(self, raw, sink: bytearray) -> None:
        self._raw = raw
        self._sink = sink

    def fileno(self) -> int:
        return self._raw.fileno()

    def read1(self, size: int = -1) -> bytes:
        chunk = self._raw.read(size) or b""
        self._sink.extend(chunk)
        if len(self._sink) > TRANSCRIPT_LIMIT:
            del self._sink[:len(self._sink) - TRANSCRIPT_LIMIT]
        return chunk

    read = read1


def session_command(
    target: PersistentControllerInstance,
    port: int,
    *,
    canonical_state: Path = DEFAULT_STATE,
    backup_disk: Path | None = None,
    backup_mode: str | None = None,
) -> list[str]:
    """The instance's own boot, attached to the per-run switch, audited.

    Exactly ``bootstrap_dc.qemu_command``'s persistent shape -- same machine,
    disk serial and firmware as every earlier boot of this directory -- with
    its listening socket NIC replaced by one that connects to the switch.

    *backup_disk* and *backup_mode* (ADR 0081, ``persistent_backup``) add the
    one raw backup disk ``simulated_topology.backup_disk_args`` describes,
    before the NIC; the audit admits it only when both are given.  A restore
    (``BACKUP_INPUT``) drops the NIC, so its guest has no network at all.
    """
    if not PersistentControllerInstance.valid_instance_name(target.instance):
        raise PersistentControllerSessionError(
            "a persistent session needs a named instance")
    canonical = paths(canonical_state)
    target.assert_separate(canonical["disk"])
    files = persistent_paths(target.state)
    for key in ("disk", "vars"):
        if Path(files[key]).resolve() == Path(canonical[key]).resolve():
            raise PersistentControllerSessionError(
                f"refusing the acceptance canonical {canonical[key]} as a "
                f"persistent {key}")
    base = qemu_command(
        target.state, None, None, files=files, socket_port=port,
        name=f"persistent-dc-{target.instance}")
    listen = socket_network_args(role="listen", mac=SOCKET_MAC, port=port)
    if base[-len(listen):] != listen:
        raise PersistentControllerSessionError(
            "the persistent command shape changed; refusing to guess where "
            "its NIC is")
    extra = ([] if backup_disk is None
             else backup_disk_args(Path(backup_disk), str(backup_mode)))
    nic = socket_network_args(role="connect", mac=SOCKET_MAC, port=port)
    if backup_mode == BACKUP_INPUT:
        # A restore boots with no network device at all (ADR 0081): nothing
        # it lays down may reach a network before convergence gives it its
        # own.  ``-nodefaults`` stays, or QEMU would add a default NIC.
        if nic[0] != "-nodefaults" or "-nodefaults" in nic[1:]:
            raise PersistentControllerSessionError(
                "the persistent NIC shape changed; refusing to guess how to "
                "drop it")
        nic = nic[:1]
    argv = base[:-len(listen)] + extra + nic
    audit_persistent_controller(
        argv, disk=files["disk"], vars_file=files["vars"], port=port,
        mac=SOCKET_MAC, forbidden_paths=(canonical["disk"], canonical["vars"]),
        backup_disk=backup_disk, backup_mode=backup_mode)
    return argv


def _spawn_guest(argv: list[str]) -> subprocess.Popen[bytes]:
    # Its own session: a terminal's Ctrl-C must reach this process, which
    # powers the guest off, and never the guest's QEMU, which would cut its
    # power.
    return subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, bufsize=0, start_new_session=True)


class PersistentControllerSession:
    """One persistent Controller guest on a per-run switch."""

    def __init__(
        self,
        target: PersistentControllerInstance,
        *,
        port: int,
        password: bytes,
        canonical_state: Path = DEFAULT_STATE,
        console_timeout: float = PERSISTENT_CONSOLE_TIMEOUT,
        spawn: Callable[[list[str]], subprocess.Popen[bytes]] | None = None,
        proc_root: Path = Path("/proc"),
        backup_disk: Path | None = None,
        backup_mode: str | None = None,
    ) -> None:
        if (not isinstance(password, bytes) or not password
                or b"\n" in password or b"\r" in password):
            raise ValueError("the console credential must be one non-empty line")
        self._target = target
        self._port = port
        self._backup = {"backup_disk": backup_disk, "backup_mode": backup_mode}
        # Built, and so audited and checked against the canonical, before any
        # process can start.
        self._argv = session_command(
            target, port, canonical_state=canonical_state, **self._backup)
        self._files = persistent_paths(target.state)
        self._canonical = paths(canonical_state)
        # The recorded DC name (TASK-42): the canonical image's own until a
        # restore renames the guest (ADR 0081).  Read once, before any boot.
        self._dc_hostname = target.dc_hostname()
        self._password: bytes | None = password
        self._console_timeout = console_timeout
        self._spawn = spawn or _spawn_guest
        self._proc_root = Path(proc_root)
        self._process: subprocess.Popen[bytes] | None = None
        self._console: SerialAutomation | None = None
        self._logged_in = False
        self._locked = False
        self._transcript = bytearray()
        self.facts: dict[str, object] = {
            "launches": 0,
            "logins": 0,
            "live_argv_audited": False,
            "clean_poweroffs": 0,
            "terminated_fallback": False,
            "lock_released": True,
        }

    def __getattr__(self, name: str):
        if name in FORBIDDEN_FAULT_HOOKS:
            raise AttributeError(
                f"{name}: a persistent Controller session has no pause, "
                "suspend or signal method. Its disk is a durable directory; "
                "it stops only by a clean console poweroff")
        raise AttributeError(name)

    @property
    def command(self) -> list[str]:
        return list(self._argv)

    @property
    def dc_hostname(self) -> str:
        """The host name this session logs in at (``<name> login:``)."""
        return self._dc_hostname

    @property
    def console(self) -> SerialAutomation:
        if self._console is None or not self._logged_in:
            raise PersistentControllerSessionError(
                "the persistent Controller is not logged in")
        return self._console

    def start(
        self, *, attached: Callable[[], None] | None = None,
        require_ad: bool = True,
    ) -> SerialAutomation:
        """Take the lock, boot in place, log in, and prove AD live.

        *require_ad* is ``False`` only for a restore (ADR 0081): a freshly
        created instance holds an installed Controller with no directory
        yet, so the restore proves samba live itself once it has put one
        there.
        """
        if self._password is None:
            raise PersistentControllerSessionError(
                "this session is closed and its credential was dropped")
        if self._process is not None or self._locked:
            raise PersistentControllerSessionError(
                "the persistent Controller is already running")
        self._target.prepare()
        self._locked = True
        self.facts["lock_released"] = False
        try:
            process = self._spawn(list(self._argv))
            self._process = process
            self.facts["launches"] = int(self.facts["launches"]) + 1
            self._audit_live(process.pid)
            if attached is not None:
                attached()
            if process.stdout is None or process.stdin is None:
                raise PersistentControllerSessionError(
                    "persistent controller serial pipes were not created")
            console = SerialAutomation(
                _TeeReader(process.stdout, self._transcript), process.stdin,
                self._password, timeout=self._console_timeout)
            self._console = console
            persistent_console_login(
                console, "persistent-session", hostname=self._dc_hostname)
            self._logged_in = True
            self.facts["logins"] = int(self.facts["logins"]) + 1
            if require_ad:
                console._wait_controller_ad()
        except BaseException:
            with contextlib.suppress(Exception):
                self.stop()
            raise
        return console

    def stop(self, label: str = "persistent-session-poweroff") -> None:
        """Power the guest off over its console, then release the lock."""
        process, console = self._process, self._console
        try:
            if process is not None:
                self._stop_process(process, console, label)
        finally:
            self._process = None
            self._console = None
            self._logged_in = False
            if self._locked:
                self._release()

    def relaunch(
        self, *, attached: Callable[[], None] | None = None,
    ) -> SerialAutomation:
        """Cold-restart the directory and log in again with the held credential."""
        self.stop()
        return self.start(attached=attached)

    def close(self) -> None:
        """Stop if running, then drop the credential for good."""
        try:
            self.stop()
        finally:
            self._password = None

    def __enter__(self) -> "PersistentControllerSession":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def redacted_transcript(
        self, extra_secrets: Iterable[str | bytes] = (),
    ) -> bytes | None:
        """The retained console bytes with every known credential removed.

        ``None`` when absence cannot be proven -- after ``close`` dropped the
        credential, or when a credential survives redaction (for example
        base64-wrapped) -- so a caller withholds the transcript rather than
        retaining a secret.
        """
        data = bytes(self._transcript)
        known = [
            value.encode("utf-8") if isinstance(value, str) else value
            for value in extra_secrets if value
        ]
        if self._password is None:
            return None if data else b""
        known.append(self._password)
        # An agent-custody instance's whole store is scanned for too
        # (TASK-40); a store that cannot be read withholds the transcript.
        try:
            known += [value.encode("utf-8")
                      for value in custody_scan_values(self._target)]
        except (CustodyError, RuntimeError, OSError, ValueError):
            return None
        for value in sorted(known, key=len, reverse=True):
            data = data.replace(value, REDACTED)
        data = redact(data)
        if count_secret_occurrences([data], secret_needles(known)):
            return None
        return data

    # -- internals -------------------------------------------------------
    def _audit_live(self, pid: int) -> None:
        try:
            live = live_qemu_argv(pid, "persistent controller", self._proc_root)
        except RuntimeError as error:
            raise PersistentControllerSessionError(
                "the live QEMU process is not the audited persistent command") from error
        if live != self._argv:
            raise PersistentControllerSessionError(
                "the live QEMU process is not the audited persistent command")
        audit_persistent_controller(
            live, disk=self._files["disk"], vars_file=self._files["vars"],
            port=self._port, mac=SOCKET_MAC,
            forbidden_paths=(self._canonical["disk"], self._canonical["vars"]),
            **self._backup)
        self.facts["live_argv_audited"] = True

    def _stop_process(
        self, process: subprocess.Popen[bytes],
        console: SerialAutomation | None, label: str,
    ) -> None:
        interrupted: BaseException | None = None
        requested = observed = False
        if (process.poll() is None and self._logged_in
                and console is not None and self._password):
            requested = True
            try:
                _console_poweroff(console, self._password, label)
                observed = True
                self.facts["clean_poweroffs"] = (
                    int(self.facts["clean_poweroffs"]) + 1)
            except (SerialAutomationError, OSError, ValueError):
                pass
            except BaseException as error:  # An interrupt mid-shutdown.
                interrupted = error
        if requested and (observed or interrupted is not None):
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=POWEROFF_EXIT_TIMEOUT)
        if process.poll() is None:
            # The recorded fallback, never the plan: this is a power cut on a
            # durable directory, recovered by its journal and Samba's own
            # ldb/tdb recovery on the next boot.
            self.facts["terminated_fallback"] = True
            process.terminate()
            try:
                process.wait(timeout=TERMINATE_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=KILL_TIMEOUT)
        if interrupted is not None:
            raise interrupted

    def _release(self) -> None:
        # QEMU may stay visible in /proc for an instant after it exits, so
        # retry exactly as ``persistent_up`` does rather than failing a good
        # stop on a teardown race.
        for attempt in range(6):
            try:
                self._target.close()
                break
            except (RuntimeError, OSError) as error:
                if attempt == 5:
                    raise PersistentControllerSessionError(
                        f"the instance lock could not be released: {error}"
                    ) from error
                time.sleep(0.1)
        self._locked = False
        self.facts["lock_released"] = True


# -- the probe ------------------------------------------------------------

def _say(message: str) -> None:
    print(f"probe: {message}", flush=True)


def _count(console: SerialAutomation, command: str, label: str) -> int:
    return int(_console_root(console, command, label, value=COUNT_VALUE))


def _probe_directory(
    console: SerialAutomation, binding: DurableBinding,
    checks: dict[str, object],
) -> str:
    """Identity first, then everything a client on the fabric will rely on.

    The realm and the SID are hard: a directory that is not the bound one is
    refused before anything is written into it.  The rest are measured and
    recorded, so one run shows every fabric fault at once.  Returns the live
    SID, which only the repair path uses; it is never retained.
    """
    realm = _console_root(
        console, REALM_COMMAND, "probe-realm", value=REALM_VALUE)
    checks["realm_matches"] = (
        realm is not None
        and realm.decode("ascii").upper() == binding.kerberos_realm)
    if not checks["realm_matches"]:
        raise DurableBindingError(
            "the live directory does not serve the bound realm; nothing was "
            "written to it")
    raw_sid = _console_root(
        console, DOMAIN_SID_COMMAND, "probe-domain-sid",
        value=DOMAIN_SID_VALUE)
    live = "" if raw_sid is None else raw_sid.decode("ascii")
    try:
        state = check_live_directory(binding.domain_sid, live)
    except DurableBindingError:
        checks["domain_sid"] = "mismatch"
        raise
    checks["domain_sid"] = "match" if state == SID_MATCH else "repair-needed"
    _say(f"realm agrees; domain SID {checks['domain_sid']}")

    address = str(FABRIC_CONTROLLER_ADDRESS)
    quoted = shlex.quote
    checks["interface_address"] = _count(
        console,
        "/usr/bin/ip -4 -o addr show | /usr/bin/grep -cF "
        + quoted(f" inet {address}/{FABRIC_PREFIX} "),
        "probe-interface-address") >= 1
    checks["gateway_reachable"] = _console_root(
        console,
        f"/usr/bin/ping -c 2 -W 2 {quoted(str(FABRIC_GATEWAY_ADDRESS))} "
        ">/dev/null 2>&1 && echo 1 || echo 0",
        "probe-gateway", value=rb"[01]") == b"1"
    fqdn = binding.controller_fqdn
    checks["a_record"] = _count(
        console,
        f"/usr/bin/host -t A {quoted(fqdn)} {quoted(address)} 2>/dev/null "
        f"| /usr/bin/grep -cixF {quoted(f'{fqdn} has address {address}')}",
        "probe-a-record") >= 1
    for key, service in (("srv_ldap", "_ldap._tcp"),
                         ("srv_kerberos", "_kerberos._tcp")):
        checks[key] = _count(
            console,
            f"/usr/bin/host -t SRV {quoted(f'{service}.{binding.dns_domain}')}"
            f" {quoted(address)} 2>/dev/null | /usr/bin/grep -ciF "
            f"{quoted(f' {fqdn}.')}",
            f"probe-{key.replace('_', '-')}") >= 1
    before = time.time()
    guest = _console_root(
        console, "/usr/bin/date -u +%s", "probe-clock",
        value=rb"[0-9]{9,11}")
    after = time.time()
    skew = int(guest or b"0") - (before + after) / 2
    checks["clock_skew_seconds"] = round(skew)
    checks["clock_within_kerberos_skew"] = (
        abs(skew) + (after - before) / 2 <= KERBEROS_MAX_SKEW_SECONDS)
    return live


def _join_material():
    """``controller_join_material``, deferred: it resolves the roster on import."""
    from . import controller_join_material
    return controller_join_material


def _probe_join_principal(
    console: SerialAutomation, binding: DurableBinding,
    checks: dict[str, object], credentials: list[str],
) -> None:
    """Stage one ``tj-`` principal and prove its destruction.

    The same one-use lifecycle every gate's join uses, over the already
    authenticated console.  The generated credential is recorded in
    *credentials* only so the transcript can be proven free of it.
    """
    module = _join_material()
    serial = module.ControllerJoinSerial(
        console.reader, console.writer, timeout=console.timeout)
    serial.console = console

    def stage(credential: str):
        credentials.append(credential)
        result = serial.stage(credential)
        checks["join_principal_staged"] = True
        return result

    material = module.OneUseDomainJoinMaterial(
        binding.kerberos_realm, stage=stage, destroy=serial.destroy)
    try:
        _value, proof = material.use(
            lambda values: values["principal"].startswith("tj-"))
    except module.ControllerJoinMaterialError as error:
        destroyed = "destruction:" not in str(error)
        if not destroyed:
            with contextlib.suppress(
                    module.ControllerJoinMaterialError,
                    SerialAutomationError, OSError):
                destroyed = material.retry_destruction().destruction_proved
        checks["join_principal_destroyed"] = destroyed
        if not destroyed:
            print("error: a one-use join principal may remain in the "
                  f"directory: {getattr(serial, '_principal', 'tj-?')}",
                  file=sys.stderr)
        raise
    checks["join_principal_destroyed"] = proof.destruction_proved
    _say("join principal staged and its destruction proved")


def _passed(checks: dict[str, object]) -> bool:
    return (all(checks.get(key) is True for key in REQUIRED_CHECKS)
            and checks.get("terminated_fallback") is False
            and checks.get("domain_sid") in ("match", "repaired"))


def _start_fabric(
    switch_log: Path, fabric_log: Path,
    children: list[subprocess.Popen[bytes]],
) -> int:
    """Start the per-run switch and gateway, told the instance's own MAC."""
    descriptor = os.open(
        fabric_log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
        0o600)
    # Each child keeps its own copy of the log descriptor; this one closes
    # as soon as both are started.
    with os.fdopen(descriptor, "wb") as log, socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        port = int(listener.getsockname()[1])
        children.append(subprocess.Popen(
            persistent_switch_command(
                listener.fileno(), switch_log,
                accept_timeout=SWITCH_ACCEPT_TIMEOUT,
                idle_timeout=SWITCH_IDLE_TIMEOUT),
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            pass_fds=(listener.fileno(),)))
        listener.close()
        children.append(subprocess.Popen(
            gateway_command(port, controller_mac=SOCKET_MAC,
                            identity_mode=True),
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT))
    wait_for_switch_port(switch_log, "gateway", GATEWAY_MAC, timeout=30.0)
    return port


def _finish_session(
    session: PersistentControllerSession, checks: dict[str, object],
    credentials: list[str],
) -> tuple[bytes | None, BaseException | None]:
    """Stop cleanly, record how, and take the transcript before the credential goes."""
    failure: BaseException | None = None
    try:
        session.stop()
    except BaseException as error:  # noqa: BLE001 - recorded, not hidden
        failure = error
    checks["clean_poweroff"] = (
        int(session.facts["clean_poweroffs"]) >= 1
        and not session.facts["terminated_fallback"])
    checks["terminated_fallback"] = bool(session.facts["terminated_fallback"])
    checks["lock_released"] = bool(session.facts["lock_released"])
    transcript = session.redacted_transcript(credentials)
    session.close()
    return transcript, failure


def _run_probe(
    binding: DurableBinding,
    target: PersistentControllerInstance,
    password: bytes,
    *,
    canonical_state: Path,
    repair_sid: bool,
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
    checks.update(domain_sid=None, clock_skew_seconds=None,
                  terminated_fallback=False, lock_released=True)
    result: dict[str, object] = {
        "schema": 1,
        "kind": "persistent-controller-probe",
        "run_id": run_id,
        "instance": binding.instance,
        "repair_sid_requested": repair_sid,
        "started_utc": datetime.now(UTC).isoformat(),
        "checks": checks,
    }
    _say(f"evidence: {evidence}")
    children: list[subprocess.Popen[bytes]] = []
    session: PersistentControllerSession | None = None
    credentials: list[str] = []
    failure: BaseException | None = None
    transcript: bytes | None = None
    step = "fabric"
    live_sid = ""

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
            live_sid = _probe_directory(console, binding, checks)
            step = "join-principal"
            _probe_join_principal(console, binding, checks, credentials)
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
                failure = PersistentControllerSessionError("; ".join(problems))
        checks["transcript_secret_free"] = transcript is not None
        if failure is None and checks["domain_sid"] == "repair-needed":
            if repair_sid:
                try:
                    target.record_convergence(repaired_convergence(
                        target.convergence() or {}, live_sid))
                    checks["domain_sid"] = "repaired"
                    _say("the truncated recorded domain SID was repaired")
                except (RuntimeError, OSError, ValueError) as error:
                    failure = error
            else:
                print("error: the recorded domain SID is a truncated prefix "
                      "of the live one; repeat with REPAIR_SID=1 to repair "
                      "the instance marker", file=sys.stderr)
        live_sid = ""
        passed = failure is None and _passed(checks)
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
        print(f"error: probe failed at {step}: {failure}", file=sys.stderr)
    print(f"{binding.instance}: probe {'PASS' if passed else 'FAIL'}; "
          f"evidence {evidence}")
    return 0 if passed else 2


def probe(
    root: Path,
    instance: str,
    apply: bool,
    *,
    canonical_state: Path = DEFAULT_STATE,
    identity_path: Path | None = None,
    overlay_path: Path | None = None,
    repair_sid: bool = False,
    evidence_root: Path = DEFAULT_EVIDENCE_ROOT,
) -> int:
    """Plan, or run, one probe of a persistent instance on the fabric."""
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
    print(f"persistent controller probe: {instance}")
    print(f"state: {binding.state}")
    print(f"binding: the convergence record agrees with "
          f"{binding.identity_source}; the declared Controller address, "
          "prefix and gateway are the per-run fabric's; the staged roster "
          "fingerprint is current (values are compared, not printed)")
    print(f"fabric: a per-run loopback switch and simulated gateway, no "
          f"workstation; the instance keeps its own MAC {SOCKET_MAC} because "
          "its network unit matches it")
    print("controller: the instance's own disk booted in place under its "
          "lock; no QMP, no medium, no pause; stopped by a clean console "
          "poweroff, with terminate only as a recorded fallback")
    print("steps: log in; prove samba live; read the realm and domain SID; "
          "check the interface address, the gateway, the A and SRV records "
          "and the clock; stage and destroy one tj- join principal; power "
          "off")
    print("domain SID: "
          + ("REPAIR_SID given; a recorded SID that is a strict prefix of the "
             "live one is completed in the marker after a passing probe"
             if repair_sid else
             "a recorded SID that is a strict prefix of the live one fails "
             "the probe unless REPAIR_SID=1; any other difference is always "
             "refused"))
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
          "result.json of secret-free checks)")
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
        return _run_probe(
            binding, target, password, canonical_state=canonical_state,
            repair_sid=repair_sid, evidence_root=evidence_root)
    finally:
        password = b""


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Run a persistent Controller instance on the per-run "
                    "loopback fabric")
    result.add_argument(
        "--state-dir", type=Path, default=DEFAULT_STATE,
        help="the disposable acceptance canonical, refused as a persistent "
             "target")
    commands = result.add_subparsers(dest="command", required=True)
    probe_parser = commands.add_parser("probe")
    probe_parser.add_argument("--instance", required=True)
    probe_parser.add_argument(
        "--persistent-root", type=Path, default=DEFAULT_PERSISTENT_ROOT)
    probe_parser.add_argument(
        "--directory-identity", type=Path, default=None,
        help="the permanent directory identity instead of "
             "homelab/instance/identity/directory.json")
    probe_parser.add_argument(
        "--identity-overlay", type=Path, default=None,
        help="the durable roster instead of "
             "homelab/instance/identity/principals.json")
    probe_parser.add_argument(
        "--repair-sid", action="store_true",
        help="complete a recorded domain SID that is a strict prefix of the "
             "live one; any other difference is still refused")
    probe_parser.add_argument(
        "--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    probe_parser.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return probe(
        args.persistent_root, args.instance, args.apply,
        canonical_state=args.state_dir,
        identity_path=args.directory_identity,
        overlay_path=args.identity_overlay,
        repair_sid=args.repair_sid, evidence_root=args.evidence_root)


if __name__ == "__main__":
    raise SystemExit(main())
