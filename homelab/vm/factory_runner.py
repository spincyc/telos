#!/usr/bin/env python3
"""Bounded loopback-only Controller and workstation factory skeleton."""

from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    from .automated_controller import DisposableBootDisk
    from .bootstrap_dc import DEFAULT_STATE, ovmf_pair, paths
    from .signal_cleanup import terminate_children
    from .simulated_topology import (
        MACS, _base, audit_live_process, audit_qemu_argv, socket_nic)
except ImportError:
    from automated_controller import DisposableBootDisk
    from bootstrap_dc import DEFAULT_STATE, ovmf_pair, paths
    from signal_cleanup import terminate_children
    from simulated_topology import (
        MACS, _base, audit_live_process, audit_qemu_argv, socket_nic)


WORKSTATION_SIZE = "40G"
DEFAULT_DURATION = 120.0


def qemu_commands(
    controller_disk: Path,
    controller_vars: Path,
    workstation_disk: Path,
    workstation_vars: Path,
    port: int,
    workstation_iso: Path | None,
) -> dict[str, list[str]]:
    controller = _base("controller", controller_vars, 4096)
    controller += [
        "-drive",
        f"if=virtio,format=raw,cache=none,file={controller_disk.resolve()}",
    ]
    controller += socket_nic(
        "factory", "connect", port, MACS["controller"])

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


def switch_command(listener_fd: int, evidence: Path) -> list[str]:
    return [
        sys.executable,
        str(Path(__file__).with_name("simulated_switch.py")),
        "--listener-fd", str(listener_fd),
        "--port", f"controller={MACS['controller']}",
        "--port", f"workstation={MACS['client']}",
        "--evidence", str(evidence),
        "--accept-timeout", "20",
        "--idle-timeout", "120",
    ]


def _problems(
    controller_state: Path, workstation_iso: Path | None,
) -> list[str]:
    files = paths(controller_state)
    result = []
    for key in ("disk", "vars"):
        if not files[key].is_file() or files[key].is_symlink():
            result.append(f"invalid Controller {key}: {files[key]}")
    if workstation_iso is not None and not workstation_iso.resolve().is_file():
        result.append(f"invalid workstation ISO: {workstation_iso}")
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
    duration: float = DEFAULT_DURATION,
) -> int:
    if not 1 <= duration <= 3600:
        print("error: duration must be between 1 and 3600 seconds",
              file=sys.stderr)
        return 2
    problems = _problems(controller_state, workstation_iso)
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
        listener.listen(2)
        port = listener.getsockname()[1]
        plans = qemu_commands(
            overlay.disk, overlay.vars, workstation_disk, workstation_vars,
            port, workstation_iso)
        processes: dict[str, subprocess.Popen[bytes]] = {}
        try:
            processes["switch"] = subprocess.Popen(
                switch_command(listener.fileno(), runtime / "switch.jsonl"),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT, pass_fds=(listener.fileno(),))
            listener.close()
            for role in ("controller", "workstation"):
                processes[role] = subprocess.Popen(
                    plans[role], stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                audit_live_process(
                    processes[role].pid,
                    "controller" if role == "controller" else "client",
                    disposable_disk=overlay.disk if role == "controller" else None,
                    disposable_vars=overlay.vars if role == "controller" else None,
                    forbidden_paths=(canonical["disk"], canonical["vars"])
                    if role == "controller" else (),
                )
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
            return 0
        finally:
            listener.close()
            failures = terminate_children(
                processes.values(), terminate_timeout=5, kill_timeout=2)
            if failures:
                raise RuntimeError(
                    "factory cleanup failed:\n- " + "\n- ".join(failures))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--controller-state", type=Path, default=DEFAULT_STATE)
    result.add_argument("--workstation-iso", type=Path)
    result.add_argument("--duration", type=float, default=DEFAULT_DURATION)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return run(
        args.controller_state, apply=args.apply,
        workstation_iso=args.workstation_iso, duration=args.duration)


if __name__ == "__main__":
    raise SystemExit(main())
