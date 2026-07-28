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
        activate_publication, capture_serial, gateway_command, qemu_commands,
        switch_command, wait_for_switch_port)
    from .signal_cleanup import SignalGuard, terminate_children
    from .simulation_evidence import private_file, redact
    from .simulated_topology import audit_live_process
    from .windows_install_contract import (
        audit_qemu_disk_boundary, inspect_qcow2)
except ImportError:
    from automated_controller import DisposableBootDisk
    from bootstrap_dc import DEFAULT_STATE, paths
    from factory_runner import (
        activate_publication, capture_serial, gateway_command, qemu_commands,
        switch_command, wait_for_switch_port)
    from signal_cleanup import SignalGuard, terminate_children
    from simulation_evidence import private_file, redact
    from simulated_topology import audit_live_process
    from windows_install_contract import audit_qemu_disk_boundary, inspect_qcow2


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


def run(
    bundle: Path, *, controller_state: Path, duration: float, apply: bool,
) -> int:
    if not 60 <= duration <= 3600:
        raise RuntimeError("duration must be between 60 and 3600 seconds")
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
                    idle_timeout=duration + 60),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT, pass_fds=(listener.fileno(),))
            listener.close()
            processes["gateway"] = subprocess.Popen(
                gateway_command(31415), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            wait_for_switch_port(evidence / "switch.jsonl", "gateway")
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
            result["phase"] = "windows-setup"
            deadline = time.monotonic() + duration
            while time.monotonic() < deadline:
                failed = [
                    role for role, process in processes.items()
                    if process.poll() is not None
                ]
                if failed:
                    raise RuntimeError(
                        "Windows lifecycle process failed: " + ", ".join(failed))
                time.sleep(min(1, max(0, deadline - time.monotonic())))
            serial = (evidence / "workstation-serial.log").read_text(
                encoding="utf-8", errors="replace")
            required = (
                "/private/run-", "install.bat", "winpeshl.ini",
                "Windows Imaging Format bootloader",
            )
            if not all(marker in serial for marker in required):
                raise RuntimeError(
                    "private WinPE overlay handoff was not fully observed")
            result = {
                "schema": 1, "status": "observed",
                "phase": "private-winpe-overlay",
                "release_version":
                    authorization["authorization"]["release_version"],
            }
            return 0
    except BaseException as error:
        result["error_type"] = type(error).__name__
        raise
    finally:
        listener.close()
        failures = terminate_children(
            processes.values(), terminate_timeout=8, kill_timeout=3)
        if serial_thread is not None:
            serial_thread.join(timeout=2)
        _sanitize_log(evidence / "controller-publication.log")
        _sanitize_log(evidence / "workstation-serial.log")
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
    result.add_argument("--duration", type=float, default=900)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return run(
        args.bundle, controller_state=args.controller_state,
        duration=args.duration, apply=args.apply)


if __name__ == "__main__":
    raise SystemExit(main())
