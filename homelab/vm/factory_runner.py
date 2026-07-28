#!/usr/bin/env python3
"""Bounded loopback-only Controller and workstation factory skeleton."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

try:
    from .automated_controller import DisposableBootDisk
    from .bootstrap_dc import DEFAULT_STATE, ovmf_pair, paths
    from .factory_publication import stage as stage_publication
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


WORKSTATION_SIZE = "40G"
DEFAULT_DURATION = 120.0
PUBLICATION_LABEL = "TELOS_PXE_RELEASE"
GATEWAY_MAC = "52:54:00:31:11:01"
DEFAULT_FAILURE_EVIDENCE = Path("homelab/var/factory/evidence")
DEFAULT_SEED_ISO = Path("homelab/var/seed/telos-controller-seed.iso")
EVIDENCE_LIMIT = 1024 * 1024


def _redact(value: bytes) -> bytes:
    return re.sub(
        rb"(?i)(password|passphrase|token|secret)(\s*[:=]\s*)\S+",
        rb"\1\2[REDACTED]", value)


def retain_evidence(
    runtime: Path, evidence_root: Path, *, status: str,
    error: BaseException | None = None,
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
        "retained": retained,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result.chmod(0o600)
    return destination


def retain_failure_evidence(
    runtime: Path, evidence_root: Path, error: BaseException,
) -> Path:
    return retain_evidence(
        runtime, evidence_root, status="fail", error=error)


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


def qemu_commands(
    controller_disk: Path,
    controller_vars: Path,
    workstation_disk: Path,
    workstation_vars: Path,
    port: int,
    workstation_iso: Path | None,
    publication_iso: Path | None = None,
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
    audit_qemu_argv("controller", controller)
    audit_qemu_argv("client", workstation)
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
    evidence: Path, name: str, *, timeout: float = 10.0,
) -> None:
    marker = f'"event":"port-connected"'
    named = f'"port":"{name}"'
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            text = evidence.read_text(encoding="utf-8").replace(" ", "")
        except FileNotFoundError:
            text = ""
        if marker in text and named in text:
            return
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for pinned switch port: {name}")


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
        plans = qemu_commands(
            overlay.disk, overlay.vars, workstation_disk, workstation_vars,
            port, workstation_iso, publication_iso)
        processes: dict[str, subprocess.Popen[bytes]] = {}
        controller_serial = runtime / "controller-publication.log"
        workstation_serial = runtime / "workstation-serial.log"
        serial_thread: threading.Thread | None = None
        try:
            processes["switch"] = subprocess.Popen(
                switch_command(listener.fileno(), runtime / "switch.jsonl"),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT, pass_fds=(listener.fileno(),))
            listener.close()
            processes["gateway"] = subprocess.Popen(
                gateway_command(port), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            wait_for_switch_port(runtime / "switch.jsonl", "gateway")
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
            while time.monotonic() < deadline:
                failed = [
                    role for role, process in processes.items()
                    if process.poll() not in (None, 0)
                ]
                if failed:
                    raise RuntimeError(
                        "factory process failed: " + ", ".join(failed))
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
                    runtime, evidence_root, status="pass")
                print(f"PXE handoff evidence retained at {evidence}")
            return 0
        except BaseException as error:
            evidence = retain_failure_evidence(runtime, evidence_root, error)
            print(f"Failure evidence retained at {evidence}", file=sys.stderr)
            raise
        finally:
            listener.close()
            failures = terminate_children(
                processes.values(), terminate_timeout=5, kill_timeout=2)
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
