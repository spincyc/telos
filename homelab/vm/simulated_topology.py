#!/usr/bin/env python3
"""Run a three-guest lab without attaching anything to a host network."""

from __future__ import annotations

import argparse
import io
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:
    from .bootstrap_dc import DEFAULT_STATE, ovmf_pair, paths
    from .dhcp_provenance import assess, load
    from .host_network_evidence import capture, compare_cycle, write
    from .manual_verification import HELPER, SerialVerificationGate
    from .simulated_client import run as run_synthetic_client
    from .simulation_overlay import ControllerOverlay
except ImportError:
    from bootstrap_dc import DEFAULT_STATE, ovmf_pair, paths
    from dhcp_provenance import assess, load
    from host_network_evidence import capture, compare_cycle, write
    from manual_verification import HELPER, SerialVerificationGate
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
) -> list[str]:
    """Build the only QEMU command used by the real simulation cycle."""
    result = _base("controller", controller_vars, 4096)
    result += [
        "-drive",
        (
            "if=virtio,format=qcow2,cache=none,"
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


def audit_qemu_argv(role: str, argv: list[str]) -> None:
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
    for item in lowered:
        if item in forbidden_options:
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
        value for value in devices if value.startswith("virtio-net-pci,")
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
        raise ValueError(f"{role}: only virtio-net-pci NICs are allowed")
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
) -> None:
    """Re-audit the kernel's view of a newly started QEMU process."""
    cmdline = proc_root / str(pid) / "cmdline"
    try:
        raw = cmdline.read_bytes()
    except OSError as error:
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
    audit_qemu_argv(role, argv)


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
        print(f"controller: {' '.join(command)}")
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
    evidence = evidence_root.resolve() / run_id
    evidence.mkdir(parents=True, mode=0o700)
    evidence.chmod(0o700)
    before = capture()
    write(before, evidence / "before.json")
    print(f"Evidence: {evidence}")

    with tempfile.TemporaryDirectory(prefix="telos-sim-") as temp:
        runtime = Path(temp)
        runtime.chmod(0o700)
        transcript = runtime / "transcript.jsonl"
        controller_audit = runtime / "controller-dhcp-server.jsonl"
        controller_files = paths(controller_state)
        with ControllerOverlay(
                controller_files["disk"], controller_files["vars"],
                run_root=runtime / "controller") as overlay:
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            plans = {"controller": controller_command(
                controller_state, overlay.disk, overlay.vars, port)}
            print("Boundary: one QEMU loopback socket; no host or UniFi changes")
            print("The controller is foreground. Log in and run exactly:")
            print(f"  sudo {HELPER}")
            print("Only RESULT PASS opens the gate. Then run: sudo poweroff")
            children: dict[str, subprocess.Popen[bytes]] = {}
            during: dict[str, object] | None = None
            primary_error: BaseException | None = None
            cleanup_error: BaseException | None = None
            outcome = 0
            try:
                gateway_process = subprocess.Popen(
                    [
                        sys.executable,
                        str(Path(__file__).with_name("simulated_gateway.py")),
                        "--connections", "2",
                        "--listener-fd", str(listener.fileno()),
                        "--audit-first", str(controller_audit),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
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
                    plans["controller"], stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, bufsize=0)
                children["controller"] = controller_process
                audit_live_process(
                    controller_process.pid, "controller")
                time.sleep(0.25)
                during = capture()
                write(during, evidence / "during.json")
                if acceptance is not None:
                    outcome = acceptance(plans, children)
                else:
                    if relay_controller_serial(
                            controller_process, gate) != 0:
                        raise RuntimeError(
                            "controller QEMU exited unsuccessfully")
                    gate.write_receipt(
                        evidence / "manual-verification.json")
                    if (controller_audit.exists()
                            and controller_audit.stat().st_size):
                        raise RuntimeError(
                            "controller emitted a DHCP server message")
                    transcript.write_text(
                        '{"sequence":1,"kind":"POWEROFF",'
                        '"actor":"controller"}\n')
                    run_synthetic_client(port, transcript)
                    if gateway_process.wait(timeout=5) != 0:
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
                    for child in reversed(tuple(children.values())):
                        if child.poll() is None:
                            child.terminate()
                    for child in reversed(tuple(children.values())):
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait()
                    after = capture()
                    write(after, evidence / "after.json")
                    if during is not None:
                        violations = compare_cycle(
                            before, during, after,
                            allowed_ports=frozenset({port}))
                        if violations:
                            raise RuntimeError(
                                "host evidence failed:\n- "
                                + "\n- ".join(violations))
                except BaseException as error:
                    cleanup_error = error
            if primary_error is not None:
                if cleanup_error is not None:
                    raise RuntimeError(
                        "simulation failed and cleanup/invariant verification "
                        f"also failed: {cleanup_error}") from primary_error
                raise primary_error
            if cleanup_error is not None:
                raise cleanup_error
            print("PASS gateway is sole DHCP authority")
            print("PASS client DHCP, DNS, NTP and probe survived controller poweroff")
            print("PASS host network state was unchanged")
            return outcome


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Plan or run a loopback-isolated controller test cycle")
    result.add_argument("--controller-state", type=Path, default=DEFAULT_STATE)
    result.add_argument("--evidence-root", type=Path)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return run(
        args.controller_state, args.apply, evidence_root=args.evidence_root)


if __name__ == "__main__":
    raise SystemExit(main())
