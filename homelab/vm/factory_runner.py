#!/usr/bin/env python3
"""Bounded loopback-only Controller and workstation factory skeleton."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import re
import secrets
import select
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

try:
    from .automated_controller import DisposableBootDisk
    from .bootstrap_dc import DEFAULT_STATE, ovmf_pair, paths
    from .factory_publication import stage as stage_publication
    from .guest_progress_host import (
        attach_progress_port, classify, progress_record)
    from .guest_progress_protocol import (
        DeadlineError, GuestProgressError, ProtocolConfig, ReceiverState)
    from .guest_progress_transport import GuestProgressTransport
    from .signal_cleanup import terminate_children
    from .simulated_topology import (
        MACS, _base, audit_live_process, audit_qemu_argv, socket_nic)
except ImportError:
    from automated_controller import DisposableBootDisk
    from bootstrap_dc import DEFAULT_STATE, ovmf_pair, paths
    from factory_publication import stage as stage_publication
    from signal_cleanup import terminate_children
    from simulated_topology import (
        MACS, _base, audit_live_process, audit_qemu_argv, socket_nic)
    # The guest-progress modules import siblings only relatively, so a
    # direct-script run reaches them through the repository root package.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from homelab.vm.guest_progress_host import (
        attach_progress_port, classify, progress_record)
    from homelab.vm.guest_progress_protocol import (
        DeadlineError, GuestProgressError, ProtocolConfig, ReceiverState)
    from homelab.vm.guest_progress_transport import GuestProgressTransport


WORKSTATION_SIZE = "40G"
DEFAULT_DURATION = 120.0
PUBLICATION_LABEL = "TELOS_PXE_RELEASE"
GATEWAY_MAC = "52:54:00:31:11:01"
DEFAULT_FAILURE_EVIDENCE = Path("homelab/var/factory/evidence")
DEFAULT_SEED_ISO = Path("homelab/var/seed/telos-controller-seed.iso")
EVIDENCE_LIMIT = 1024 * 1024


@dataclass(frozen=True)
class SwitchEvidenceCursor:
    """Immutable boundary before a new authenticated switch session."""

    device: int | None
    inode: int | None
    offset: int


def capture_switch_evidence_cursor(evidence: Path) -> SwitchEvidenceCursor:
    try:
        descriptor = os.open(
            evidence, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return SwitchEvidenceCursor(None, None, 0)
    except OSError as error:
        raise RuntimeError("switch evidence cannot be opened safely") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("switch evidence is not a regular file")
        return SwitchEvidenceCursor(info.st_dev, info.st_ino, info.st_size)
    finally:
        os.close(descriptor)


def _switch_events_after(
    evidence: Path, cursor: SwitchEvidenceCursor | None,
) -> list[dict[str, object]]:
    try:
        descriptor = os.open(
            evidence, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return []
    except OSError as error:
        raise RuntimeError("switch evidence cannot be opened safely") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("switch evidence is not a regular file")
        offset = 0 if cursor is None else cursor.offset
        if cursor is not None and cursor.device is not None and (
            info.st_dev != cursor.device or info.st_ino != cursor.inode
        ):
            raise RuntimeError("switch evidence identity changed")
        if info.st_size < offset:
            raise RuntimeError("switch evidence was truncated")
        raw = os.pread(descriptor, info.st_size - offset, offset)
    finally:
        os.close(descriptor)
    # An event becomes evidence only after its newline-delimited append is
    # complete.  Ignore a concurrently written suffix.
    complete = raw.rsplit(b"\n", 1)[0] if b"\n" in raw else b""
    events: list[dict[str, object]] = []
    for line in complete.splitlines():
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _redact(value: bytes) -> bytes:
    return re.sub(
        rb"(?i)(password|passphrase|token|secret)(\s*[:=]\s*)\S+",
        rb"\1\2[REDACTED]", value)


def retain_evidence(
    runtime: Path, evidence_root: Path, *, status: str,
    error: BaseException | None = None,
    progress: dict | None = None,
) -> Path:
    evidence_root = Path(evidence_root)
    if evidence_root.is_symlink():
        raise RuntimeError("evidence root must not be a symlink")
    evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    evidence_root.chmod(0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = evidence_root / f"{stamp}-{os.getpid()}-pxe-handoff"
    destination.mkdir(mode=0o700)
    retained = []
    for name in (
        "controller-publication.log", "workstation-serial.log", "switch.jsonl",
    ):
        source = Path(runtime) / name
        if not source.is_file() or source.is_symlink():
            continue
        output = destination / name
        output.write_bytes(
            _redact(source.read_bytes()[-EVIDENCE_LIMIT:])[-EVIDENCE_LIMIT:])
        output.chmod(0o600)
        retained.append(name)
    result = destination / "result.json"
    result.write_text(json.dumps({
        "schema": 1,
        "status": status,
        **({"error": _redact(str(error).encode()).decode(
            "utf-8", "replace")} if error is not None else {}),
        # Diagnostic observation only; it never alters the status verdict.
        **({"progress": progress} if progress is not None else {}),
        "retained": retained,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result.chmod(0o600)
    return destination


def retain_failure_evidence(
    runtime: Path, evidence_root: Path, error: BaseException,
    *, progress: dict | None = None,
) -> Path:
    return retain_evidence(
        runtime, evidence_root, status="fail", error=error, progress=progress)


def publication_bootstrap_command() -> bytes:
    """Publish verified media from the disposable init shell, then boot."""
    return (
        b"/usr/bin/mount -o remount,rw / && "
        b"/usr/bin/mkdir -p /run/telos-pxe-release && "
        b"/usr/bin/mount -L " + PUBLICATION_LABEL.encode("ascii")
        + b" /run/telos-pxe-release && "
        b"/run/telos-pxe-release/publish && "
        b"exec /usr/lib/systemd/systemd\n"
    )


def _at_root_prompt(transcript: bytes | bytearray) -> bool:
    """Match a root shell prompt, never package-manager progress hashes."""
    return re.search(
        rb"\[root@[^]\r\n]+ [^]\r\n]*\]#[ \t]*$", transcript) is not None


def activate_publication(
    process: subprocess.Popen[bytes], capture: Path, *, timeout: float = 90.0,
) -> None:
    """Wait for the disposable init shell and require publication success."""
    if process.stdin is None or process.stdout is None:
        raise RuntimeError("Controller publication requires captured serial I/O")
    deadline = time.monotonic() + timeout
    transcript = bytearray()
    command_sent = False
    command_transcript = bytearray()
    publication_passed = False
    capture.touch(mode=0o600)
    capture.chmod(0o600)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Controller exited before PXE publication")
        ready, _, _ = select.select(
            [process.stdout], [], [], min(0.25, deadline - time.monotonic()))
        if not ready:
            continue
        chunk = os.read(process.stdout.fileno(), 4096)
        if not chunk:
            continue
        transcript.extend(chunk)
        if command_sent:
            command_transcript.extend(chunk)
            if len(command_transcript) > 64 * 1024:
                del command_transcript[:-64 * 1024]
        if len(transcript) > 1024 * 1024:
            del transcript[:-1024 * 1024]
        capture.write_bytes(transcript)
        capture.chmod(0o600)
        if not command_sent and _at_root_prompt(transcript):
            process.stdin.write(publication_bootstrap_command())
            process.stdin.flush()
            command_sent = True
        if b"TELOS PXE PUBLICATION PASS" in transcript:
            publication_passed = True
        if command_sent and b"TELOS PXE SERVICES READY" in transcript:
            def drain() -> None:
                assert process.stdout is not None
                while process.poll() is None:
                    chunk = os.read(process.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    with capture.open("ab") as stream:
                        stream.write(chunk)
            threading.Thread(
                target=drain, name="controller-serial-drain", daemon=True,
            ).start()
            return
        if (
            command_sent
            and _at_root_prompt(command_transcript)
        ):
            raise RuntimeError(
                "Controller returned to its shell before services were ready")
    if publication_passed:
        raise RuntimeError(
            "verified PXE publication completed, but Controller services "
            "did not become ready")
    raise RuntimeError("timed out waiting for verified PXE publication")


def declared_chardevs(argv: list[str]) -> tuple[str, ...]:
    """Chardev values from an already audited plan, for the live re-audit."""
    return tuple(
        argv[index + 1] for index, item in enumerate(argv)
        if item == "-chardev")


def qemu_commands(
    controller_disk: Path,
    controller_vars: Path,
    workstation_disk: Path,
    workstation_vars: Path,
    port: int,
    workstation_iso: Path | None,
    publication_iso: Path | None = None,
    progress_socket: Path | None = None,
) -> dict[str, list[str]]:
    controller = _base("controller", controller_vars, 4096)
    controller += [
        "-drive",
        f"if=virtio,format=raw,cache=none,file={controller_disk.resolve()}",
    ]
    controller += socket_nic(
        "factory", "connect", port, MACS["controller"])
    if publication_iso is not None:
        controller += [
            "-device", "virtio-scsi-pci,id=publicationbus",
            "-drive",
            (
                "if=none,id=publicationmedia,media=cdrom,readonly=on,"
                f"file={publication_iso.resolve()}"
            ),
            "-device",
            "scsi-cd,bus=publicationbus.0,drive=publicationmedia",
        ]

    workstation = _base("client", workstation_vars, 4096)
    workstation[workstation.index("telos-sim-client")] = (
        "telos-sim-workstation")
    workstation += [
        "-drive",
        f"if=virtio,format=qcow2,cache=none,file={workstation_disk.resolve()}",
    ]
    if workstation_iso is not None:
        workstation += [
            "-device", "virtio-scsi-pci,id=mediabus",
            "-drive",
            (
                "if=none,id=installmedia,media=cdrom,readonly=on,"
                f"file={workstation_iso.resolve()}"
            ),
            "-device",
            "scsi-cd,bus=mediabus.0,drive=installmedia,bootindex=1",
        ]
    workstation += socket_nic(
        "factory", "connect", port, MACS["client"])
    workstation_chardevs: tuple[str, ...] = ()
    if progress_socket is not None:
        # Diagnostic-only channel; the audit allowlist stays closed otherwise.
        workstation, chardev = attach_progress_port(
            workstation, progress_socket)
        workstation_chardevs = (chardev,)
    audit_qemu_argv("controller", controller)
    audit_qemu_argv(
        "client", workstation, allowed_chardevs=workstation_chardevs)
    return {"controller": controller, "workstation": workstation}


def switch_command(
    listener_fd: int, evidence: Path, *, accept_timeout: float = 20,
    idle_timeout: float = 120,
    identity_mode: bool = False,
) -> list[str]:
    command = [
        sys.executable,
        str(Path(__file__).with_name("simulated_switch.py")),
        "--listener-fd", str(listener_fd),
        "--port", f"gateway={GATEWAY_MAC}",
        "--port", f"controller={MACS['controller']}",
        "--port", f"workstation={MACS['client']}",
        "--evidence", str(evidence),
        "--accept-timeout", f"{accept_timeout:g}",
        "--idle-timeout", f"{idle_timeout:g}",
    ]
    if identity_mode:
        command.append("--identity-mode")
    return command


def gateway_command(
    port: int, *, controller_mac: str | None = None,
    identity_mode: bool = False,
) -> list[str]:
    command = [
        sys.executable,
        str(Path(__file__).with_name("simulated_gateway.py")),
        "--port", str(port), "--connect",
    ]
    if controller_mac is not None:
        command.extend(["--controller-mac", controller_mac])
    if identity_mode:
        command.append("--identity-mode")
    return command


def wait_for_switch_port(
    evidence: Path, name: str, expected_mac: str, *, timeout: float = 10.0,
    after: SwitchEvidenceCursor | None = None,
    abort: Callable[[], str | None] | None = None,
) -> int:
    expected_mac = expected_mac.casefold()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if abort is not None:
            reason = abort()
            if reason:
                raise RuntimeError(reason)
        try:
            events = _switch_events_after(evidence, after)
        except FileNotFoundError:
            events = []
        for event in events:
            if (
                event.get("event") == "port-connected"
                and event.get("port") == name
                and event.get("mac") == expected_mac
                and type(event.get("generation")) is int
                and int(event["generation"]) > 0
            ):
                return int(event["generation"])
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for pinned switch port: {name}")


def wait_for_plain_dhcp_transaction(
    evidence: Path, peer: str, expected_mac: str, *, timeout: float = 90.0,
    after: SwitchEvidenceCursor | None = None,
    generation: int | None = None,
    gateway_generation: int | None = None,
    abort: Callable[[], str | None] | None = None,
) -> None:
    """Require one exact, no-PXE DHCP D/O/R/A transaction for a peer."""
    if generation is not None and (
        type(generation) is not int or generation <= 0
    ):
        raise ValueError(
            "workstation switch generation must be a positive integer")
    if gateway_generation is not None and (
        type(gateway_generation) is not int or gateway_generation <= 0
    ):
        raise ValueError(
            "gateway switch generation must be a positive integer")
    expected_mac = expected_mac.casefold()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if abort is not None:
            reason = abort()
            if reason:
                raise RuntimeError(reason)
        progress: dict[str, int] = {}
        tainted: set[str] = set()
        sequence = ("DISCOVER", "OFFER", "REQUEST", "ACK")
        try:
            events = _switch_events_after(evidence, after)
        except FileNotFoundError:
            events = []
        for event in events:
            if event.get("event") != "dhcp":
                continue
            transaction = event.get("transaction")
            kind = event.get("kind")
            if (
                not isinstance(transaction, str)
                or re.fullmatch(r"[0-9a-f]{8}", transaction) is None
            ):
                continue
            if kind == "NAK":
                tainted.add(transaction)
                continue
            if kind not in sequence:
                continue
            request = kind in {"DISCOVER", "REQUEST"}
            matches = event.get("client_mac") == expected_mac
            if request:
                matches = matches and (
                    event.get("peer") == peer
                    and event.get("source_mac") == expected_mac
                )
                if generation is not None:
                    matches = matches and (
                        type(event.get("peer_generation")) is int
                        and event.get("peer_generation") == generation)
                if kind == "REQUEST":
                    matches = (
                        matches
                        and event.get("requested_ip") == "10.1.31.11"
                    )
            else:
                matches = matches and (
                    event.get("peer") == "gateway"
                    and event.get("source_mac") == GATEWAY_MAC
                    and event.get("delivered_to") == peer
                    and event.get("offered_ip") == "10.1.31.11"
                )
                if generation is not None:
                    matches = matches and (
                        type(event.get("delivered_to_generation")) is int
                        and event.get("delivered_to_generation") == generation)
                if gateway_generation is not None:
                    matches = matches and (
                        type(event.get("peer_generation")) is int
                        and event.get("peer_generation") == gateway_generation)
            expected_index = progress.get(transaction, 0)
            if (
                transaction in tainted
                or "boot_file" in event
                or "next_server" in event
                or "architecture" in event
                or not matches
                or expected_index >= len(sequence)
                or kind != sequence[expected_index]
            ):
                tainted.add(transaction)
                continue
            progress[transaction] = expected_index + 1
        if any(
            transaction not in tainted and index == len(sequence)
            for transaction, index in progress.items()
        ):
            return
        time.sleep(0.1)
    raise RuntimeError(
        f"timed out waiting for plain DHCP readiness: {peer} {expected_mac}")


def wait_for_switch_disconnect(
    evidence: Path, name: str, expected_mac: str, generation: int, *,
    timeout: float = 10.0,
    after: SwitchEvidenceCursor | None = None,
) -> None:
    """Wait for teardown of exactly one authenticated port generation."""
    if type(generation) is not int or generation <= 0:
        raise ValueError("switch generation must be a positive integer")
    expected_mac = expected_mac.casefold()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for event in _switch_events_after(evidence, after):
            if (
                event.get("event") == "port-disconnected"
                and event.get("port") == name
                and event.get("mac") == expected_mac
                and event.get("generation") == generation
            ):
                return
        time.sleep(0.05)
    raise RuntimeError(
        f"timed out waiting for switch port disconnect: {name} "
        f"generation {generation}")


def assess_handoff(
    switch_evidence: Path, controller_serial: Path, workstation_serial: Path,
    version: str, target: str = "arch-workstation",
) -> list[str]:
    compact = switch_evidence.read_text(
        encoding="utf-8", errors="replace").replace(" ", "")
    problems = [
        f"missing DHCP {kind} evidence"
        for kind in ("DISCOVER", "OFFER", "REQUEST", "ACK")
        if f'"kind":"{kind}"' not in compact
    ]
    if '"peer":"gateway"' not in compact:
        problems.append("simulated gateway was not observed as DHCP authority")
    controller = controller_serial.read_text(
        encoding="utf-8", errors="replace")
    workstation = workstation_serial.read_text(
        encoding="utf-8", errors="replace")
    if (
        "GET /boot/boot.ipxe " not in controller
        and "http://10.1.31.2/boot/boot.ipxe" not in workstation
    ):
        problems.append("selected /boot/boot.ipxe was not requested")
    if "TELOS PXE SERVICES READY" not in controller:
        problems.append("selected boot.ipxe exact-byte HTTP probe was not proven")
    prefix = f"/arch-workstation/{version}/"
    arch_requests = all(
        f"GET {prefix}{value} " in controller
        or f"http://10.1.31.2{prefix}{value}" in workstation
        for value in (
            "boot.ipxe",
            "payload/arch/boot/x86_64/vmlinuz-linux",
            "payload/arch/boot/x86_64/initramfs-linux.img",
        )
    )
    arch_serial = any(marker in workstation for marker in (
        "archiso login:", "Welcome to Arch Linux",
    ))
    phases = arch_handoff_phases(workstation)
    root_request = (
        f"GET {prefix}payload/arch/x86_64/airootfs." in controller
        or f"http://10.1.31.2{prefix}payload/arch/x86_64/airootfs."
        in workstation
    )
    windows_prefix = f"/windows/{version}/"
    winpe_requests = all(
        f"GET {windows_prefix}{value} " in controller
        or f"http://10.1.31.2{windows_prefix}{value}" in workstation
        for value in (
            "boot.ipxe", "wimboot", "bootmgr", "boot/BCD",
            "boot/boot.sdi", "sources/boot.wim",
        )
    )
    winpe = (
        winpe_requests
        and "Windows Imaging Format bootloader" in workstation
        and "...found WIM file boot.wim" in workstation
    )
    accepted = (
        arch_requests and arch_serial and root_request
        if target == "arch-workstation" else winpe
    )
    if not accepted:
        if phases["kernel_init"] and phases["archiso_network_hook"]:
            problems.append(
                "Arch kernel/init and PXE hook were observed, but network-root "
                "did not complete")
        else:
            problems.append("no Arch or WinPE handoff was observed")
    return problems


def arch_handoff_phases(workstation: str) -> dict[str, bool]:
    """Report milestones without confusing pre-boot with gate completion."""
    return {
        "ipxe_preboot": "TELOS IPXE PRE-BOOT" in workstation,
        "kernel_init": "Run /init as init process" in workstation,
        "archiso_network_hook": ":: running hook [archiso_pxe_common]"
        in workstation,
        "network_root_ready": any(marker in workstation for marker in (
            "archiso login:", "Welcome to Arch Linux",
        )),
    }


# Closed guest-progress vocabularies: exactly the observed handoff
# milestones plus the guest-supervised installer phase, and every closed
# v1 event status.  Diagnostic only; no verdict reads them.
PROGRESS_PRODUCER = "arch-installer"
PROGRESS_PHASES = tuple(arch_handoff_phases("")) + ("installer",)
PROGRESS_STATUSES = ("starting", "active", "complete", "failed", "ready")
PROGRESS_SOCKET_NAME = "progress.sock"
PROGRESS_CONNECT_TIMEOUT = 0.05


def _remove_progress_root(root: Path) -> list[str]:
    """Remove the per-run progress socket root and prove its absence."""
    failures: list[str] = []
    try:
        shutil.rmtree(root)
    except FileNotFoundError:
        pass
    except OSError as error:
        failures.append(f"progress socket root removal failed: {error}")
    if root.is_symlink() or root.exists():
        failures.append(f"progress socket root was not removed: {root}")
    return failures


class _WorkstationProgress:
    """Opportunistic diagnostic collector for the workstation progress port.

    Never load-bearing: an absent peer, transport fault, or protocol error
    only shapes the retained "progress" evidence block.  Verdicts, gates,
    and deadlines are untouched, and nothing secret leaves this object.
    """

    def __init__(
        self, socket_root: Path, *, deadline: float,
        attempt: str | None = None, nonce: str | None = None,
        key: bytes | None = None,
    ) -> None:
        self.socket_root = Path(socket_root)
        self.socket_path = self.socket_root / PROGRESS_SOCKET_NAME
        # Credential delivery gap: the PXE payload is a sealed, hash-verified
        # release with no per-run overlay hook, so the guest cannot yet learn
        # this attempt's key/nonce; an absent stream is still proved honestly.
        key = key if key is not None else secrets.token_bytes(32)
        config = ProtocolConfig(
            attempt=attempt if attempt is not None
            else f"factory-{os.getpid()}-{secrets.token_hex(4)}",
            producer=PROGRESS_PRODUCER,
            nonce=nonce if nonce is not None else secrets.token_hex(16),
            phases=PROGRESS_PHASES,
            statuses=PROGRESS_STATUSES,
        )
        self._receiver = ReceiverState(config, key, deadline=deadline)
        self._connection: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._result = None
        self._error: BaseException | None = None
        self._stopping = False

    def poll(self) -> None:
        """Try one bounded connect to the QEMU-owned progress socket.

        QEMU is the socket server (``server=on,wait=off``), so the host is
        the connecting peer.  A missing or refusing socket is tolerated
        forever; a successful connect hands the stream to a background
        collector so the run-loop cadence never blocks.
        """
        if self._stopping or self._thread is not None:
            return
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(PROGRESS_CONNECT_TIMEOUT)
        try:
            connection.connect(str(self.socket_path))
        except OSError:
            connection.close()
            return
        self._connection = connection
        transport = GuestProgressTransport(connection, self._receiver)
        self._thread = threading.Thread(
            target=self._collect, args=(transport,),
            name="workstation-progress", daemon=True)
        self._thread.start()

    def _collect(self, transport: GuestProgressTransport) -> None:
        try:
            self._result = transport.collect()
        except BaseException as error:
            # A deliberate stop tears the socket down under the reader;
            # that fault is not a guest observation.
            if not self._stopping:
                self._error = error

    def stop(self) -> None:
        """Stop collecting; idempotent and bounded."""
        self._stopping = True
        if self._connection is not None:
            try:
                self._connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)

    def record(self) -> dict:
        """Compose the secret-free evidence block; never raises."""
        self.stop()
        try:
            return self._compose()
        except Exception:
            # Composition can never mask a run verdict; fall back to the
            # weakest honest observation.
            return progress_record(
                liveness="absent", classification="unavailable")

    def _compose(self) -> dict:
        if self._result is not None:
            events = self._result.events
            phases = [
                event.envelope["phase"] for event in events
                if event.envelope["phase"] is not None
            ]
            return progress_record(
                liveness=self._result.liveness,
                classification=(
                    None if self._error is None else classify(self._error)),
                last_phase=phases[-1] if phases else None,
                last_sequence=(
                    events[-1].envelope["sequence"] if events else None),
                events_accepted=len(events),
            )
        if self._connection is None:
            # No peer ever connected: the device was unavailable and the
            # stream is absent.
            return progress_record(
                liveness="absent", classification="unavailable")
        last_sequence = self._receiver.last_sequence
        events_accepted = 0 if last_sequence is None else last_sequence + 1
        try:
            liveness = self._receiver.liveness(now=time.monotonic())
        except GuestProgressError:
            liveness = "absent" if events_accepted == 0 else "stalled"
        if self._error is None:
            classification = None
        elif isinstance(self._error, DeadlineError) and events_accepted == 0:
            # An empty stream at the deadline is absence, not a stall.
            classification = "absent"
        else:
            classification = classify(self._error)
        return progress_record(
            liveness=liveness,
            classification=classification,
            last_phase=(
                self._receiver.active_phase if events_accepted else None),
            last_sequence=last_sequence,
            events_accepted=events_accepted,
        )

    def close(self) -> list[str]:
        """Stop collection, destroy key state, and remove the socket root."""
        failures: list[str] = []
        self.stop()
        if self._thread is not None and self._thread.is_alive():
            failures.append("progress collector thread did not stop")
        if self._connection is not None:
            try:
                self._connection.close()
            except OSError as error:
                failures.append(f"progress connection close failed: {error}")
        try:
            self._receiver.close()
        except Exception as error:
            failures.append(f"progress receiver close failed: {error}")
        failures += _remove_progress_root(self.socket_root)
        return failures


def capture_serial(
    process: subprocess.Popen[bytes], path: Path,
) -> threading.Thread:
    if process.stdout is None:
        raise RuntimeError("serial capture requires a pipe")
    path.touch(mode=0o600)
    path.chmod(0o600)

    def capture() -> None:
        assert process.stdout is not None
        with path.open("ab") as stream:
            while True:
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    return
                stream.write(chunk)
                stream.flush()

    thread = threading.Thread(target=capture, daemon=True)
    thread.start()
    return thread


def _problems(
    controller_state: Path, workstation_iso: Path | None,
    releases: Path | None, seed_iso: Path,
) -> list[str]:
    files = paths(controller_state)
    result = []
    for key in ("disk", "vars"):
        if not files[key].is_file() or files[key].is_symlink():
            result.append(f"invalid Controller {key}: {files[key]}")
    if workstation_iso is not None and not workstation_iso.resolve().is_file():
        result.append(f"invalid workstation ISO: {workstation_iso}")
    if releases is not None:
        if not releases.resolve().is_dir():
            result.append(f"invalid PXE releases root: {releases}")
        if shutil.which("xorriso") is None:
            result.append("xorriso was not found")
        if not seed_iso.resolve().is_file() or seed_iso.is_symlink():
            result.append(f"invalid Controller seed ISO: {seed_iso}")
    if ovmf_pair() is None:
        result.append("OVMF firmware was not found")
    for command in ("qemu-img", "qemu-system-x86_64"):
        if shutil.which(command) is None:
            result.append(f"{command} was not found")
    return result


def run(
    controller_state: Path,
    *,
    apply: bool,
    workstation_iso: Path | None = None,
    releases: Path | None = None,
    seed_iso: Path = DEFAULT_SEED_ISO,
    evidence_root: Path = DEFAULT_FAILURE_EVIDENCE,
    duration: float = DEFAULT_DURATION,
    target: str = "arch-workstation",
) -> int:
    if not 1 <= duration <= 3600:
        print("error: duration must be between 1 and 3600 seconds",
              file=sys.stderr)
        return 2
    problems = _problems(controller_state, workstation_iso, releases, seed_iso)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2
    print("Boundary: loopback-only userspace switch; no host or UniFi changes")
    print("Controller: disposable standalone sparse raw disk")
    print("Workstation: disposable blank qcow2 disk")
    print(f"Maximum runtime: {duration:g} seconds")
    if workstation_iso is None:
        print("Workstation install: deferred; no boot media selected")
    if not apply:
        print("dry run; repeat with --apply")
        return 0

    canonical = paths(controller_state)
    with tempfile.TemporaryDirectory(prefix="telos-factory-") as temp, \
            DisposableBootDisk(
                canonical["disk"], canonical["vars"],
                run_root=Path(temp) / "controller") as overlay:
        runtime = Path(temp)
        runtime.chmod(0o700)
        workstation_disk = runtime / "workstation.qcow2"
        workstation_vars = runtime / "workstation-vars.fd"
        publication_iso = None
        if releases is not None:
            publication = runtime / "publication"
            receipt = stage_publication(
                releases, publication, seed_iso=seed_iso, target=target)
            publication_iso = runtime / "publication.iso"
            subprocess.run(
                [
                    "xorriso", "-as", "mkisofs", "-quiet",
                    "-V", PUBLICATION_LABEL, "-o", str(publication_iso),
                    str(publication),
                ],
                check=True, capture_output=True,
            )
            publication_iso.chmod(0o600)
            print(
                "Selected PXE release: "
                f"{receipt['version']} ({receipt['selected_manifest_sha256']})")
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2",
             str(workstation_disk), WORKSTATION_SIZE],
            check=True, capture_output=True)
        workstation_disk.chmod(0o600)
        pair = ovmf_pair()
        assert pair is not None
        shutil.copyfile(pair[1], workstation_vars)
        workstation_vars.chmod(0o600)

        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(3)
        port = listener.getsockname()[1]
        processes: dict[str, subprocess.Popen[bytes]] = {}
        controller_serial = runtime / "controller-publication.log"
        workstation_serial = runtime / "workstation-serial.log"
        serial_thread: threading.Thread | None = None
        # Separate short private root: the socket path must fit sockaddr_un.
        progress_root = Path(tempfile.mkdtemp(prefix="telos-progress-"))
        progress_channel: _WorkstationProgress | None = None
        try:
            plans = qemu_commands(
                overlay.disk, overlay.vars, workstation_disk,
                workstation_vars, port, workstation_iso, publication_iso,
                progress_socket=progress_root / PROGRESS_SOCKET_NAME)
            processes["switch"] = subprocess.Popen(
                switch_command(listener.fileno(), runtime / "switch.jsonl"),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT, pass_fds=(listener.fileno(),))
            listener.close()
            processes["gateway"] = subprocess.Popen(
                gateway_command(port), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            wait_for_switch_port(
                runtime / "switch.jsonl", "gateway", GATEWAY_MAC)
            for role in ("controller", "workstation"):
                publication_io = role == "controller" and publication_iso is not None
                workstation_io = role == "workstation" and publication_iso is not None
                processes[role] = subprocess.Popen(
                    plans[role],
                    stdin=subprocess.PIPE if publication_io else subprocess.DEVNULL,
                    stdout=subprocess.PIPE
                    if publication_io or workstation_io else subprocess.DEVNULL,
                    stderr=subprocess.STDOUT)
                audit_live_process(
                    processes[role].pid,
                    "controller" if role == "controller" else "client",
                    allowed_chardevs=declared_chardevs(plans[role]),
                    disposable_disk=overlay.disk if role == "controller" else None,
                    disposable_vars=overlay.vars if role == "controller" else None,
                    forbidden_paths=(canonical["disk"], canonical["vars"])
                    if role == "controller" else (),
                )
                if publication_io:
                    activate_publication(
                        processes[role], controller_serial)
                if workstation_io:
                    serial_thread = capture_serial(
                        processes[role], workstation_serial)
            deadline = time.monotonic() + duration
            progress_channel = _WorkstationProgress(
                progress_root, deadline=deadline)
            while time.monotonic() < deadline:
                failed = [
                    role for role, process in processes.items()
                    if process.poll() not in (None, 0)
                ]
                if failed:
                    raise RuntimeError(
                        "factory process failed: " + ", ".join(failed))
                progress_channel.poll()
                time.sleep(min(0.25, max(0, deadline - time.monotonic())))
            if publication_iso is not None:
                problems = assess_handoff(
                    runtime / "switch.jsonl", controller_serial,
                    workstation_serial, receipt["version"], target)
                if problems:
                    raise RuntimeError(
                        "PXE handoff acceptance failed:\n- "
                        + "\n- ".join(problems))
                evidence = retain_evidence(
                    runtime, evidence_root, status="pass",
                    progress=progress_channel.record())
                print(f"PXE handoff evidence retained at {evidence}")
            return 0
        except BaseException as error:
            evidence = retain_failure_evidence(
                runtime, evidence_root, error,
                progress=progress_channel.record()
                if progress_channel is not None else None)
            print(f"Failure evidence retained at {evidence}", file=sys.stderr)
            raise
        finally:
            listener.close()
            failures = terminate_children(
                processes.values(), terminate_timeout=5, kill_timeout=2)
            if progress_channel is not None:
                failures += progress_channel.close()
            else:
                failures += _remove_progress_root(progress_root)
            if failures:
                raise RuntimeError(
                    "factory cleanup failed:\n- " + "\n- ".join(failures))
            if serial_thread is not None:
                serial_thread.join(timeout=2)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--controller-state", type=Path, default=DEFAULT_STATE)
    result.add_argument("--workstation-iso", type=Path)
    result.add_argument(
        "--releases", type=Path,
        help="PXE root containing a verified selected-release-set.json")
    result.add_argument(
        "--evidence-root", type=Path, default=DEFAULT_FAILURE_EVIDENCE)
    result.add_argument("--seed-iso", type=Path, default=DEFAULT_SEED_ISO)
    result.add_argument("--duration", type=float, default=DEFAULT_DURATION)
    result.add_argument(
        "--target", choices=("arch-workstation", "windows"),
        default="arch-workstation")
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return run(
        args.controller_state, apply=args.apply,
        workstation_iso=args.workstation_iso, releases=args.releases,
        seed_iso=args.seed_iso, evidence_root=args.evidence_root,
        duration=args.duration, target=args.target)


if __name__ == "__main__":
    raise SystemExit(main())
