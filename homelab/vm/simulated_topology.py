#!/usr/bin/env python3
"""Run a three-guest lab without attaching anything to a host network."""

from __future__ import annotations

import argparse
import io
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:
    from .automated_controller import AutomatedSerial, DisposableBootDisk
    from .bootstrap_dc import DEFAULT_STATE, ovmf_pair, paths
    from .dhcp_provenance import assess, load
    from .host_network_evidence import capture, compare_cycle, write
    from .manual_verification import HELPER, SerialVerificationGate
    from .qemu_boundary import audit_disposable_controller
    from .secure_artifacts import atomic_write_text, private_directory
    from .simulation_evidence import write_result, write_serial_events
    from .signal_cleanup import (
        RunInterrupted, SignalGuard, terminate_children)
    from .simulated_client import run as run_synthetic_client
    from .simulation_overlay import ControllerOverlay
except ImportError:
    from automated_controller import AutomatedSerial, DisposableBootDisk
    from bootstrap_dc import DEFAULT_STATE, ovmf_pair, paths
    from dhcp_provenance import assess, load
    from host_network_evidence import capture, compare_cycle, write
    from manual_verification import HELPER, SerialVerificationGate
    from qemu_boundary import audit_disposable_controller
    from secure_artifacts import atomic_write_text, private_directory
    from simulation_evidence import write_result, write_serial_events
    from signal_cleanup import RunInterrupted, SignalGuard, terminate_children
    from simulated_client import run as run_synthetic_client
    from simulation_overlay import ControllerOverlay


PORT_CONTROLLER = 12971
PORT_CLIENT = 12972
MACS = {
    "gateway-controller": "52:54:00:31:11:11",
    "controller": "52:54:00:31:11:12",
    "gateway-client": "52:54:00:31:12:11",
    "client": "52:54:00:31:12:12",
}
NIC_COUNTS = {"gateway": 2, "controller": 1, "client": 1}
GATEWAY_EXIT_TIMEOUT = 10
CONTROLLER_RUNTIME_TIMEOUT = 3600
CLIENT_RUNTIME_TIMEOUT = 15
SOCKET_NETDEV = re.compile(
    r"socket,id=([A-Za-z0-9_.-]+),"
    r"(?:listen|connect)=127\.0\.0\.1:([1-9][0-9]{0,4})\Z")


def socket_nic(
    netdev: str, role: str, port: int, mac: str,
) -> list[str]:
    if role not in {"listen", "connect"}:
        raise ValueError("socket role must be listen or connect")
    endpoint = (
        f"listen=127.0.0.1:{port}"
        if role == "listen"
        else f"connect=127.0.0.1:{port}"
    )
    return [
        "-netdev", f"socket,id={netdev},{endpoint}",
        "-device", f"virtio-net-pci,netdev={netdev},mac={mac}",
    ]


def _base(name: str, vars_file: Path, memory: int) -> list[str]:
    pair = ovmf_pair()
    code = pair[0] if pair else Path("/missing/OVMF_CODE.fd")
    return [
        "qemu-system-x86_64",
        "-name", f"telos-sim-{name}",
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-smp", "2",
        "-m", str(memory),
        "-nodefaults",
        "-display", "none",
        "-serial", "mon:stdio" if name == "controller" else "stdio",
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={vars_file}",
    ]


def commands(
    controller_state: Path, arch_iso: Path, runtime: Path,
    *, controller_disk: Path | None = None,
    controller_vars: Path | None = None,
) -> dict[str, list[str]]:
    controller = paths(controller_state)
    disposable_disk = controller_disk is not None
    controller_disk = controller_disk or controller["disk"]
    controller_vars = controller_vars or runtime / "controller-vars.fd"
    result = {
        "gateway": _base("gateway", runtime / "gateway-vars.fd", 2048),
        "controller": _base(
            "controller", controller_vars, 4096),
        "client": _base("client", runtime / "client-vars.fd", 2048),
    }
    for role in ("gateway", "client"):
        result[role] += [
            "-boot", "d",
            "-device", "virtio-scsi-pci,id=mediabus",
            "-drive",
            (
                "if=none,id=installmedia,media=cdrom,readonly=on,"
                f"file={arch_iso.resolve()}"
            ),
            "-device",
            "scsi-cd,bus=mediabus.0,drive=installmedia,bootindex=1",
            "-snapshot",
        ]
    result["controller"] += [
        "-drive",
        (
            "if=virtio,format=qcow2,"
            f"{'' if disposable_disk else 'snapshot=on,'}cache=none,"
            f"file={controller_disk.resolve()}"
        ),
    ]
    result["gateway"] += socket_nic(
        "controller_side", "listen", PORT_CONTROLLER,
        MACS["gateway-controller"])
    result["gateway"] += socket_nic(
        "client_side", "listen", PORT_CLIENT, MACS["gateway-client"])
    result["controller"] += socket_nic(
        "simnet", "connect", PORT_CONTROLLER, MACS["controller"])
    result["client"] += socket_nic(
        "simnet", "connect", PORT_CLIENT, MACS["client"])
    assert_isolated(result)
    return result


def controller_command(
    controller_state: Path,
    controller_disk: Path,
    controller_vars: Path,
    port: int,
    *,
    disk_format: str = "qcow2",
) -> list[str]:
    """Build the only QEMU command used by the real simulation cycle."""
    if disk_format not in {"qcow2", "raw"}:
        raise ValueError("controller disk format must be qcow2 or raw")
    result = _base("controller", controller_vars, 4096)
    result += [
        "-drive",
        (
            f"if=virtio,format={disk_format},cache=none,"
            f"file={controller_disk.resolve()}"
        ),
    ]
    result += socket_nic(
        "simnet", "connect", port, MACS["controller"])
    audit_qemu_argv("controller", result)
    return result


def relay_controller_serial(
    process: subprocess.Popen[bytes],
    gate: SerialVerificationGate,
    destination: io.BufferedWriter | None = None,
) -> int:
    """Relay the foreground console while collecting exact helper evidence."""
    if process.stdout is None:
        raise RuntimeError("controller serial output was not captured")
    destination = destination or sys.stdout.buffer
    while True:
        chunk = process.stdout.read(4096)
        if not chunk:
            break
        destination.write(chunk)
        destination.flush()
        gate.feed(chunk)
    return process.wait()


def relay_controller_bounded(
    process: subprocess.Popen[bytes],
    gate: SerialVerificationGate,
    timeout: float = CONTROLLER_RUNTIME_TIMEOUT,
) -> int:
    """Relay the console without leaving an unattended guest forever."""
    expired = threading.Event()

    def stop() -> None:
        if process.poll() is None:
            expired.set()
            process.terminate()

    timer = threading.Timer(timeout, stop)
    timer.daemon = True
    timer.start()
    try:
        result = relay_controller_serial(process, gate)
    finally:
        timer.cancel()
    if expired.is_set():
        raise subprocess.TimeoutExpired("controller", timeout)
    return result


def run_client_bounded(
    port: int,
    transcript: Path,
    timeout: float = CLIENT_RUNTIME_TIMEOUT,
) -> None:
    """Bound a wedged synthetic client without process-wide signals."""
    finished = threading.Event()
    failure: list[BaseException] = []

    def run_client() -> None:
        try:
            run_synthetic_client(port, transcript)
        except BaseException as error:
            failure.append(error)
        finally:
            finished.set()

    worker = threading.Thread(
        target=run_client, name="telos-sim-client", daemon=True)
    worker.start()
    if not finished.wait(timeout):
        raise subprocess.TimeoutExpired("synthetic client", timeout)
    if failure:
        raise failure[0]


def audit_qemu_argv(
    role: str, argv: list[str], *,
    allowed_nic_models: tuple[str, ...] = ("virtio-net-pci",),
    allowed_chardevs: tuple[str, ...] = (),
) -> None:
    """Fail closed unless argv describes the intended guest-only NICs."""
    if role not in NIC_COUNTS:
        raise ValueError(f"unknown simulation role: {role}")
    if "-nodefaults" not in argv:
        raise ValueError(f"{role}: QEMU defaults are not disabled")

    forbidden_options = {
        "-nic", "-net", "-tap", "-bridge", "-vde", "-virtfs", "-fsdev",
        "-virtiofsd", "-chardev",
    }
    forbidden_text = (
        "tap,", "bridge,", "user,", "slirp", "passt", "vde,",
        "0.0.0.0", "virtiofs", "virtio-9p", "9pnet", "guest_agent",
        "guest-agent", "qemu-ga", "org.qemu.guest_agent",
    )
    lowered = [item.lower() for item in argv]
    for index, item in enumerate(lowered):
        if item in forbidden_options:
            if (
                item == "-chardev"
                and index + 1 < len(argv)
                and argv[index + 1] in allowed_chardevs
                and argv.count("-chardev") == len(allowed_chardevs)
            ):
                continue
            raise ValueError(f"{role}: forbidden QEMU option {item}")
        for term in forbidden_text:
            if term in item:
                raise ValueError(f"{role}: forbidden host link {term}")

    netdevs = []
    devices = []
    for index, item in enumerate(argv):
        if item not in {"-netdev", "-device"}:
            continue
        if index + 1 >= len(argv):
            raise ValueError(f"{role}: {item} has no value")
        if item == "-netdev":
            netdevs.append(argv[index + 1])
        else:
            devices.append(argv[index + 1])
    expected = NIC_COUNTS[role]
    if len(netdevs) != expected:
        raise ValueError(f"{role}: expected exactly {expected} netdev(s)")
    ids = []
    for value in netdevs:
        match = SOCKET_NETDEV.fullmatch(value)
        if not match or int(match.group(2)) > 65535:
            raise ValueError(
                f"{role}: every NIC must use a loopback socket")
        ids.append(match.group(1))
    nic_devices = [
        value for value in devices
        if any(value.startswith(model + ",") for model in allowed_nic_models)
    ]
    network_models = (
        "virtio-net", "e1000", "e1000e", "rtl8139", "vmxnet3",
        "i8255", "ne2k", "pcnet", "rocker",
    )
    if any(value.lower().startswith(network_models)
           and value not in nic_devices for value in devices):
        raise ValueError(f"{role}: unapproved NIC device")
    if any("netdev=" in value and value not in nic_devices
           for value in devices):
        raise ValueError(f"{role}: NIC model is not allowed")
    if len(nic_devices) != expected:
        raise ValueError(f"{role}: expected exactly {expected} NIC device(s)")
    for netdev_id in ids:
        if sum(f"netdev={netdev_id}" in value.split(",")
               for value in nic_devices) != 1:
            raise ValueError(f"{role}: netdev {netdev_id} is not used once")


def assert_isolated(plans: dict[str, list[str]]) -> None:
    if set(plans) != set(NIC_COUNTS):
        raise ValueError("simulation must contain gateway, controller, client")
    for role, argv in plans.items():
        audit_qemu_argv(role, argv)


def audit_live_process(
    pid: int, role: str, proc_root: Path = Path("/proc"),
    *,
    allowed_nic_models: tuple[str, ...] = ("virtio-net-pci",),
    allowed_chardevs: tuple[str, ...] = (),
    disposable_disk: Path | None = None,
    disposable_vars: Path | None = None,
    forbidden_paths: tuple[Path, ...] = (),
) -> None:
    """Re-audit the kernel's view of a newly started QEMU process."""
    cmdline = proc_root / str(pid) / "cmdline"
    raw = b""
    error: OSError | None = None
    for _attempt in range(20):
        try:
            raw = cmdline.read_bytes()
            error = None
        except OSError as caught:
            error = caught
        if raw:
            break
        time.sleep(0.01)
    if error is not None:
        raise RuntimeError(
            f"{role}: cannot audit live QEMU process {pid}: {error}") from error
    argv_bytes = [part for part in raw.split(b"\0") if part]
    if not argv_bytes:
        raise RuntimeError(f"{role}: live QEMU process has empty cmdline")
    argv = [os.fsdecode(part) for part in argv_bytes]
    executable = Path(argv[0]).name
    if executable not in {"qemu-system-x86_64", "qemu-kvm"}:
        raise RuntimeError(
            f"{role}: live process is not approved QEMU: {executable}")
    audit_qemu_argv(
        role, argv, allowed_nic_models=allowed_nic_models,
        allowed_chardevs=allowed_chardevs)
    if disposable_disk is not None or disposable_vars is not None:
        if disposable_disk is None or disposable_vars is None:
            raise RuntimeError(
                "strict live audit requires both disposable paths")
        audit_disposable_controller(
            argv, disk=disposable_disk, vars_file=disposable_vars,
            forbidden_paths=forbidden_paths)


def _validate(controller_state: Path) -> list[str]:
    problems = []
    files = paths(controller_state)
    if not files["disk"].is_file() or files["disk"].is_symlink():
        problems.append(f"controller disk is not a regular file: {files['disk']}")
    if not files["vars"].is_file() or files["vars"].is_symlink():
        problems.append(f"controller firmware is not a regular file: {files['vars']}")
    if not ovmf_pair():
        problems.append("OVMF firmware was not found")
    if not shutil.which("qemu-system-x86_64"):
        problems.append("qemu-system-x86_64 was not found")
    return problems


def run(
    controller_state: Path,
    apply: bool,
    *,
    evidence_root: Path | None = None,
    acceptance: Callable[[dict[str, list[str]], dict[str, object]], int]
    | None = None,
    automated: bool = False,
) -> int:
    problems = _validate(controller_state)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2
    if not apply:
        controller = paths(controller_state)
        command = _base("controller", controller["vars"], 4096) + [
            "-drive",
            (
                "if=virtio,format=qcow2,snapshot=on,cache=none,"
                f"file={controller['disk'].resolve()}"
            ),
        ] + socket_nic(
            "simnet", "connect", PORT_CONTROLLER, MACS["controller"])
        audit_qemu_argv("controller", command)
        print("Boundary: QEMU loopback sockets only; no host or UniFi changes")
        print("gateway: host userspace DHCP/DNS/NTP/probe simulator")
        if automated:
            print(
                "controller: unattended rehearsal using a disposable sparse "
                "raw disk and an ephemeral serial-only credential")
            print(
                "credential: generated in memory; never written to argv, "
                "files, transcripts, or evidence")
        else:
            print(f"controller: {' '.join(command)}")
            print("controller verification: foreground manual console")
        print("client: synthetic wire-level DHCP/DNS/NTP/probe client")
        print("sequence: gateway -> controller (foreground) -> client -> judge")
        print("dry run; repeat with --apply")
        return 0

    evidence_root = evidence_root or (
        Path(__file__).resolve().parents[1]
        / "var" / "simulation" / "evidence")
    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + f"-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    evidence_root = evidence_root.expanduser().absolute()
    private_directory(evidence_root, parents=True)
    evidence = evidence_root / run_id
    private_directory(evidence, parents=True)
    before = capture()
    write(before, evidence / "before.json")
    print(f"Evidence: {evidence}")

    with tempfile.TemporaryDirectory(prefix="telos-sim-") as temp:
        runtime = Path(temp)
        runtime.chmod(0o700)
        transcript = evidence / "transcript.jsonl"
        controller_audit = evidence / "controller-dhcp-server.jsonl"
        gateway_log = evidence / "gateway.log"
        for record in (transcript, controller_audit, gateway_log):
            atomic_write_text(record, "")
        controller_files = paths(controller_state)
        state = (
            DisposableBootDisk(
                controller_files["disk"], controller_files["vars"],
                run_root=runtime / "controller")
            if automated else
            ControllerOverlay(
                controller_files["disk"], controller_files["vars"],
                run_root=runtime / "controller")
        )
        # Enter the signal guard first so it remains active through state.close:
        # canonical hashing, disposable deletion, and lock release all finish
        # before the original signal handlers are restored.
        with SignalGuard(), state as overlay:
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            plans = {"controller": controller_command(
                controller_state, overlay.disk, overlay.vars, port,
                disk_format="raw" if automated else "qcow2")}
            if automated:
                audit_disposable_controller(
                    plans["controller"],
                    disk=overlay.disk,
                    vars_file=overlay.vars,
                    forbidden_paths=(
                        controller_files["disk"], controller_files["vars"]),
                )
            print("Boundary: one QEMU loopback socket; no host or UniFi changes")
            if automated:
                print("Controller console verification is automated with a "
                      "disposable in-memory credential")
            else:
                print("The controller is foreground. Log in and run exactly:")
                print(f"  sudo {HELPER}")
                print("Only RESULT PASS opens the gate. Then run: sudo poweroff")
            children: dict[str, subprocess.Popen[bytes]] = {}
            during: dict[str, object] | None = None
            primary_error: BaseException | None = None
            cleanup_error: BaseException | None = None
            controller_exit_code: int | None = None
            helper_passed = False
            serial_events: tuple[str, ...] = ()
            outcome = 0
            try:
                with gateway_log.open("wb") as gateway_output:
                    gateway_process = subprocess.Popen(
                        [
                            sys.executable,
                            str(Path(__file__).with_name(
                                "simulated_gateway.py")),
                            "--connections", "2",
                            "--listener-fd", str(listener.fileno()),
                            "--audit-first", str(controller_audit),
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=gateway_output,
                        stderr=subprocess.STDOUT,
                        pass_fds=(listener.fileno(),),
                    )
                listener.close()
                children["gateway"] = gateway_process
                time.sleep(0.25)
                if gateway_process.poll() is not None:
                    raise RuntimeError("userspace gateway failed to start")
                gate = SerialVerificationGate()
                controller_process = subprocess.Popen(
                    plans["controller"],
                    stdin=subprocess.PIPE if automated else None,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, bufsize=0)
                children["controller"] = controller_process
                audit_live_process(
                    controller_process.pid, "controller",
                    disposable_disk=overlay.disk if automated else None,
                    disposable_vars=overlay.vars if automated else None,
                    forbidden_paths=(
                        controller_files["disk"], controller_files["vars"])
                    if automated else (),
                )
                time.sleep(0.25)
                during = capture()
                write(during, evidence / "during.json")
                if acceptance is not None:
                    outcome = acceptance(plans, children)
                elif automated:
                    if controller_process.stdout is None:
                        raise RuntimeError(
                            "controller serial output was not captured")
                    if controller_process.stdin is None:
                        raise RuntimeError(
                            "controller serial input was not captured")
                    password = secrets.token_urlsafe(24).encode("ascii")
                    try:
                        serial_result = AutomatedSerial(
                            controller_process.stdout,
                            controller_process.stdin,
                            password,
                            timeout=120,
                        ).run()
                    finally:
                        password = b""
                    serial_events = serial_result.events
                    controller_exit_code = controller_process.wait(timeout=20)
                    helper_passed = (
                        serial_result.helper_passed
                        and serial_result.helper_returncode == 0
                        and serial_result.powered_off
                        and controller_exit_code == 0
                    )
                    if not helper_passed:
                        raise RuntimeError(
                            "automated controller verification failed")
                else:
                    controller_exit_code = relay_controller_bounded(
                        controller_process, gate)
                    if controller_exit_code != 0:
                        raise RuntimeError(
                            "controller QEMU exited unsuccessfully")
                    gate.write_receipt(
                        evidence / "manual-verification.json")
                    helper_passed = True
                if acceptance is None:
                    if (controller_audit.exists()
                            and controller_audit.stat().st_size):
                        raise RuntimeError(
                            "controller emitted a DHCP server message")
                    atomic_write_text(
                        transcript,
                        '{"sequence":1,"kind":"POWEROFF",'
                        '"actor":"controller"}\n')
                    run_client_bounded(port, transcript)
                    if gateway_process.wait(
                            timeout=GATEWAY_EXIT_TIMEOUT) != 0:
                        raise RuntimeError(
                            "userspace gateway exited unsuccessfully")
                    failures = assess(
                        load(transcript), gateway="gateway",
                        controller="controller", client="client")
                    if failures:
                        raise RuntimeError(
                            "simulation acceptance failed:\n- "
                            + "\n- ".join(failures))
            except BaseException as error:
                primary_error = error
            finally:
                try:
                    listener.close()
                    cleanup_problems = terminate_children(
                        children.values(),
                        terminate_timeout=GATEWAY_EXIT_TIMEOUT,
                        kill_timeout=2)
                    after = capture()
                    write(after, evidence / "after.json")
                    if during is not None:
                        cleanup_problems.extend(compare_cycle(
                            before, during, after,
                            allowed_ports=frozenset({port})))
                    if cleanup_problems:
                        raise RuntimeError(
                            "host cleanup/evidence failed:\n- "
                            + "\n- ".join(cleanup_problems))
                except BaseException as error:
                    cleanup_error = error
                finally:
                    write_serial_events(
                        evidence,
                        qemu_exit_code=controller_exit_code,
                        helper_passed=helper_passed,
                        events=serial_events)
            # A PASS is not publishable until canonical hashes are verified,
            # disposable state is removed, and the simulation lock is released.
            # Closing here makes the surrounding context exit idempotent.
            try:
                state.close()
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
                else:
                    cleanup_error = RuntimeError(
                        "cleanup/invariant verification failed and "
                        f"state close also failed: {error}")
            if primary_error is not None:
                if cleanup_error is not None:
                    combined = RuntimeError(
                        "simulation failed and cleanup/invariant verification "
                        f"also failed: {cleanup_error}")
                    write_result(
                        evidence, status="fail", run_id=run_id,
                        checks={
                            "controller_preflight": helper_passed,
                            "host_unchanged": False,
                        },
                        error=combined)
                    raise combined from primary_error
                write_result(
                    evidence, status="fail", run_id=run_id,
                    checks={
                        "controller_preflight": helper_passed,
                        "host_unchanged": cleanup_error is None,
                    },
                    error=primary_error)
                raise primary_error
            if cleanup_error is not None:
                write_result(
                    evidence, status="fail", run_id=run_id,
                    checks={
                        "controller_preflight": helper_passed,
                        "host_unchanged": False,
                    },
                    error=cleanup_error)
                raise cleanup_error
            write_result(
                evidence, status="pass", run_id=run_id,
                checks={
                    "controller_preflight": helper_passed,
                    "dhcp_authority": acceptance is None,
                    "client_continuity": acceptance is None,
                    "host_unchanged": True,
                })
            print("PASS gateway is sole DHCP authority")
            print("PASS client DHCP, DNS, NTP and probe survived controller poweroff")
            print("PASS observable host network state was unchanged")
            if any(
                    item["command"]
                    == ["nft", "-j", "--stateless", "list", "ruleset"]
                    and item["returncode"] != 0
                    for item in before["observations"]):
                print("NOTE host firewall rules were unavailable to this user")
            return outcome


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Plan or run a loopback-isolated controller test cycle")
    result.add_argument("--controller-state", type=Path, default=DEFAULT_STATE)
    result.add_argument("--evidence-root", type=Path)
    result.add_argument("--apply", action="store_true")
    mode = result.add_mutually_exclusive_group()
    mode.add_argument(
        "--automated", action="store_true",
        help="use an ephemeral serial-only credential in disposable state")
    mode.add_argument(
        "--manual", action="store_true",
        help="require an operator at the controller console (default)")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(
            args.controller_state, args.apply,
            evidence_root=args.evidence_root,
            automated=args.automated)
    except RunInterrupted as error:
        print(f"simulation {error}; cleanup and evidence completed",
              file=sys.stderr)
        return error.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
