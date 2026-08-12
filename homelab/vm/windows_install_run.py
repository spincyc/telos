#!/usr/bin/env python3
"""Run one prepared Windows installation bundle on the loopback-only fabric."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time

try:
    from .automated_controller import DisposableBootDisk
    from .bootstrap_dc import DEFAULT_STATE, paths
    from .factory_runner import (
        GATEWAY_MAC, activate_publication, capture_serial, gateway_command, qemu_commands,
        switch_command, wait_for_switch_port)
    from .signal_cleanup import SignalGuard, terminate_children
    from .simulation_evidence import private_file, redact
    from .simulated_topology import audit_live_process
    from .windows_gui import QmpClient, WindowsGuiError
    from .windows_install_contract import (
        audit_qemu_disk_boundary, inspect_qcow2)
except ImportError:
    from automated_controller import DisposableBootDisk
    from bootstrap_dc import DEFAULT_STATE, paths
    from factory_runner import (
        GATEWAY_MAC, activate_publication, capture_serial, gateway_command, qemu_commands,
        switch_command, wait_for_switch_port)
    from signal_cleanup import SignalGuard, terminate_children
    from simulation_evidence import private_file, redact
    from simulated_topology import audit_live_process
    from windows_gui import QmpClient, WindowsGuiError
    from windows_install_contract import audit_qemu_disk_boundary, inspect_qcow2


MAX_DURATION = 10800
NATIVE_READY_MARKER = "TELOS WINDOWS NATIVE READY"


def _screenshot_interval(duration: float) -> int:
    return 30 if duration > 3600 else 10


def _bundle(path: Path) -> tuple[dict, list[str]]:
    if path.is_symlink():
        raise RuntimeError("Windows bundle must be a private non-symlink directory")
    path = path.resolve(strict=True)
    if path.stat().st_mode & 0o077:
        raise RuntimeError("Windows bundle must be a private non-symlink directory")
    authorization = json.loads(
        (path / "authorization.json").read_text(encoding="utf-8"))
    command_record = json.loads(
        (path / "qemu-command.json").read_text(encoding="utf-8"))
    command = command_record["argv"]
    disk = path / "windows.qcow2"
    authorized = authorization["authorization"]
    serial = authorized["disk_serial"]
    command_digest = hashlib.sha256(
        json.dumps(command, separators=(",", ":")).encode()).hexdigest()
    if command_digest != authorized["qemu_argv_sha256"]:
        raise RuntimeError("Windows QEMU command differs from authorization")
    if inspect_qcow2(disk) != authorized["disk"]:
        raise RuntimeError("Windows disk differs from authorization")
    audit_qemu_disk_boundary(command, disk=disk, serial=serial)
    required = (
        disk, path / "OVMF_VARS.fd", path / "publication.iso")
    if any(item.is_symlink() or not item.is_file() for item in required):
        raise RuntimeError("Windows bundle is incomplete or unsafe")
    return authorization, command


def _sanitize_log(path: Path, *, maximum: int = 4 * 1024 * 1024) -> None:
    """Retain a bounded, redacted tail after all writers have stopped."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return
    private_file(path, redact(data[-maximum:]))


def _destroy_private_publication(path: Path) -> str | None:
    """Remove the ISO that embeds per-run unattend and SMB credentials."""
    try:
        if path.is_symlink():
            return "private publication became a symlink"
        path.unlink(missing_ok=True)
    except OSError as error:
        return f"private publication cleanup failed: {type(error).__name__}"
    return None


def _connect_qmp(
        path: Path, *, expected_peer_pid: int, timeout: float = 10,
) -> QmpClient:
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            return QmpClient.connect(
                path, timeout=1, expected_peer_pid=expected_peer_pid)
        except (OSError, WindowsGuiError) as error:
            last_error = error
            time.sleep(0.05)
    raise RuntimeError("Windows QMP socket did not become ready") from last_error


def _validate_lifecycle(serial: str) -> None:
    required = (
        "/private/run-", "install.bat", "winpeshl.ini",
        "Windows Imaging Format bootloader",
    )
    if not all(marker in serial for marker in required):
        raise RuntimeError("private WinPE overlay handoff was not fully observed")
    if NATIVE_READY_MARKER not in serial:
        raise RuntimeError(
            "native Windows readiness and clean shutdown were not observed")
    pxe_starts = sum(
        line.startswith("BdsDxe: starting ")
        and '"UEFI PXEv4' in line
        for line in serial.splitlines()
    )
    if pxe_starts != 1:
        raise RuntimeError(
            "workstation did not use exactly one PXE firmware boot")


def _qmp_socket_path(command: list[str]) -> Path:
    """Recover the pinned QMP socket path from the authorized argv."""
    try:
        value = command[command.index("-qmp") + 1]
    except (ValueError, IndexError):
        raise RuntimeError("authorized command carries no QMP socket")
    if not value.startswith("unix:") or ",server=on" not in value:
        raise RuntimeError("authorized QMP socket shape is invalid")
    path = Path(value[len("unix:"):].split(",", 1)[0])
    if not path.is_absolute() or len(str(path).encode()) > 100:
        raise RuntimeError("authorized QMP socket path is invalid")
    return path


def run(
    bundle: Path, *, controller_state: Path, duration: float, apply: bool,
) -> int:
    if not 60 <= duration <= MAX_DURATION:
        raise RuntimeError(
            f"duration must be between 60 and {MAX_DURATION} seconds")
    authorization, workstation_command = _bundle(bundle)
    bundle = bundle.resolve()
    print("Boundary: loopback-only switch; no host or UniFi changes")
    print(f"Bundle: {bundle}")
    print("Workstation: persistent authorized NVMe; no attached Windows ISO")
    print(f"Maximum runtime: {duration:g} seconds")
    if not apply:
        print("dry run; repeat with --apply")
        return 0

    evidence = bundle / "evidence"
    if evidence.exists():
        raise RuntimeError("bundle already has execution evidence")
    evidence.mkdir(mode=0o700)
    qmp_socket = _qmp_socket_path(workstation_command)
    owned_qmp_root: Path | None = None
    if qmp_socket.parent != bundle:
        # Exclusive creation refuses a squatted or stale runtime root.
        qmp_socket.parent.mkdir(mode=0o700, exist_ok=False)
        owned_qmp_root = qmp_socket.parent
    elif qmp_socket.exists():
        raise RuntimeError("bundle QMP socket path is already occupied")
    canonical = paths(controller_state)
    processes: dict[str, subprocess.Popen[bytes]] = {}
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 31415))
    listener.listen(3)
    serial_thread = None
    result = {"schema": 1, "status": "fail", "phase": "starting"}
    try:
        with SignalGuard(), DisposableBootDisk(
                canonical["disk"], canonical["vars"],
                run_root=evidence / "controller") as overlay:
            controller_command = qemu_commands(
                overlay.disk, overlay.vars,
                bundle / "windows.qcow2", bundle / "OVMF_VARS.fd",
                31415, None, bundle / "publication.iso")["controller"]
            processes["switch"] = subprocess.Popen(
                switch_command(
                    listener.fileno(), evidence / "switch.jsonl",
                    accept_timeout=360,
                    idle_timeout=duration + 60),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT, pass_fds=(listener.fileno(),))
            listener.close()
            processes["gateway"] = subprocess.Popen(
                gateway_command(31415), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            wait_for_switch_port(
                evidence / "switch.jsonl", "gateway", GATEWAY_MAC)
            processes["controller"] = subprocess.Popen(
                controller_command, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            audit_live_process(
                processes["controller"].pid, "controller",
                disposable_disk=overlay.disk, disposable_vars=overlay.vars,
                forbidden_paths=(canonical["disk"], canonical["vars"]))
            activate_publication(
                processes["controller"],
                evidence / "controller-publication.log", timeout=300)
            processes["workstation"] = subprocess.Popen(
                workstation_command, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            audit_live_process(
                processes["workstation"].pid, "client",
                allowed_nic_models=("e1000e",))
            serial_thread = capture_serial(
                processes["workstation"], evidence / "workstation-serial.log")
            screens = evidence / "screens"
            screens.mkdir(mode=0o700)
            qmp = _connect_qmp(
                qmp_socket,
                expected_peer_pid=processes["workstation"].pid)
            result["phase"] = "windows-setup"
            deadline = time.monotonic() + duration
            next_screen = time.monotonic()
            screen_interval = _screenshot_interval(duration)
            screen_number = 0
            try:
                while time.monotonic() < deadline:
                    failed = [
                        role for role, process in processes.items()
                        if role != "workstation" and process.poll() is not None
                    ]
                    if failed:
                        raise RuntimeError(
                            "Windows lifecycle process failed: "
                            + ", ".join(failed))
                    if processes["workstation"].poll() is not None:
                        serial_thread.join(timeout=2)
                        serial = (
                            evidence / "workstation-serial.log").read_text(
                                encoding="utf-8", errors="replace")
                        if NATIVE_READY_MARKER not in serial:
                            raise RuntimeError(
                                "workstation exited before native Windows "
                                "readiness")
                        break
                    now = time.monotonic()
                    if now >= next_screen:
                        screen_number += 1
                        screen = screens / f"{screen_number:03d}.ppm"
                        qmp.screenshot(screen)
                        os.chmod(screen, 0o600)
                        next_screen = now + screen_interval
                    time.sleep(min(1, max(0, deadline - time.monotonic())))
            finally:
                qmp.close()
            serial = (evidence / "workstation-serial.log").read_text(
                encoding="utf-8", errors="replace")
            _validate_lifecycle(serial)
            result = {
                "schema": 1, "status": "observed",
                "phase": "native-windows-clean-shutdown",
                "pxe_firmware_boots": 1,
                "release_version":
                    authorization["authorization"]["release_version"],
            }
            return 0
    except BaseException as error:
        result["error_type"] = type(error).__name__
        result["error"] = redact(
            str(error).encode("utf-8", errors="replace")).decode(
                "utf-8", errors="replace")
        raise
    finally:
        listener.close()
        failures = terminate_children(
            processes.values(), terminate_timeout=8, kill_timeout=3)
        if owned_qmp_root is not None:
            qmp_socket.unlink(missing_ok=True)
            try:
                owned_qmp_root.rmdir()
            except OSError:
                failures.append("QMP runtime root was not removed")
        if serial_thread is not None:
            serial_thread.join(timeout=2)
        _sanitize_log(evidence / "controller-publication.log")
        _sanitize_log(evidence / "workstation-serial.log")
        publication_failure = _destroy_private_publication(
            bundle / "publication.iso")
        if publication_failure:
            failures.append(publication_failure)
        result["private_publication_destroyed"] = publication_failure is None
        if failures:
            result["cleanup_failures"] = failures
        output = evidence / "result.json"
        output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        os.chmod(output, 0o600)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--bundle", type=Path, required=True)
    result.add_argument(
        "--controller-state", type=Path, default=DEFAULT_STATE)
    # A real Windows 11 Setup needs ~68 minutes to reach native readiness (the
    # 2026-07-28 success ran 138 screenshot frames at 30 s each ~= 4111 s), so
    # the old 900 s default could never complete an install and silently cut
    # Setup mid-image. Default to a budget comfortably above the observed run.
    result.add_argument("--duration", type=float, default=7200)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return run(
        args.bundle, controller_state=args.controller_state,
        duration=args.duration, apply=args.apply)


if __name__ == "__main__":
    raise SystemExit(main())
