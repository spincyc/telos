#!/usr/bin/env python3
"""Run one prepared Arch-second installation bundle on the loopback fabric.

The persistent Windows disk is exposed through the authorized qcow2 overlay; a
disposable Controller PXE-publishes the selected Arch archiso release; the
workstation one-shot PXE-boots the Arch live shell, and this runner drives the
Windows-preserving installer over the serial console.  Nothing here touches a
physical disk, host networking, or UniFi.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
from typing import Callable

try:
    from .arch_install_prepare import (
        DISK_SERIAL, INSTALLER_NAME, OVERLAY_NAME, VARS_NAME, VERIFY_NAME,
        audit_arch_boot_boundary, inspect_overlay)
    from .automated_controller import DisposableBootDisk
    from .bootstrap_dc import DEFAULT_STATE, paths
    from .factory_publication import stage as stage_publication
    from .factory_runner import (
        DEFAULT_SEED_ISO, GATEWAY_MAC, PUBLICATION_LABEL, _at_root_prompt,
        activate_publication, gateway_command, qemu_commands,
        switch_command, wait_for_switch_port)
    from .signal_cleanup import SignalGuard, terminate_children
    from .simulation_evidence import private_file, redact
    from .simulated_topology import audit_live_process
    from .windows_gui import QmpClient, WindowsGuiError
    from .windows_install_contract import sha256
except ImportError:  # Direct execution from homelab/vm.
    from arch_install_prepare import (
        DISK_SERIAL, INSTALLER_NAME, OVERLAY_NAME, VARS_NAME, VERIFY_NAME,
        audit_arch_boot_boundary, inspect_overlay)
    from automated_controller import DisposableBootDisk
    from bootstrap_dc import DEFAULT_STATE, paths
    from factory_publication import stage as stage_publication
    from factory_runner import (
        DEFAULT_SEED_ISO, GATEWAY_MAC, PUBLICATION_LABEL, _at_root_prompt,
        activate_publication, gateway_command, qemu_commands,
        switch_command, wait_for_switch_port)
    from signal_cleanup import SignalGuard, terminate_children
    from simulation_evidence import private_file, redact
    from simulated_topology import audit_live_process
    from windows_gui import QmpClient, WindowsGuiError
    from windows_install_contract import sha256


MAX_DURATION = 10800
GUEST_VERIFY_PATH = "/usr/local/lib/telos/arch-second-verify.py"
GUEST_INSTALLER_PATH = "/root/arch-install.sh"
BEGIN_MARKER = "TELOS ARCH INSTALL BEGIN"
COMPLETE_MARKER = "TELOS ARCH INSTALL COMPLETE"
FAIL_MARKER = "TELOS ARCH INSTALL FAIL"
DISK_ATTACHED_MARKER = "TELOS ARCH DISK ATTACHED"
NVME_DEVICE_ID = "osdisk-nvme"
NVME_BACKEND_ID = "osdisk"
ATTACH_TIMEOUT = 30.0
VERIFY_PASS_MARKER = (
    "PASS: Windows-first GPT matches the approved Arch install contract")
PRESERVED_MARKER = (
    "Arch installed; Windows partitions and filesystems were not modified.")
ARCH_LIVE_MARKERS = ("Welcome to Arch Linux", "archiso login:")


def _bundle(path: Path) -> tuple[dict, list[str]]:
    if path.is_symlink():
        raise RuntimeError("Arch bundle must be a private non-symlink directory")
    path = path.resolve(strict=True)
    if path.stat().st_mode & 0o077:
        raise RuntimeError("Arch bundle must be a private non-symlink directory")
    authorization = json.loads(
        (path / "authorization.json").read_text(encoding="utf-8"))
    command = json.loads(
        (path / "qemu-command.json").read_text(encoding="utf-8"))["argv"]
    authorized = authorization["authorization"]
    serial = authorized["disk_serial"]
    if _argv_digest(command) != authorized["qemu_argv_sha256"]:
        raise RuntimeError("Arch QEMU command differs from authorization")
    overlay = path / OVERLAY_NAME
    info = inspect_overlay(overlay)
    if info["sha256"] != authorized["overlay"]["sha256"]:
        raise RuntimeError("Arch overlay differs from authorization")
    if info["backing"] != authorized["backing_windows_disk"]["path"]:
        raise RuntimeError("Arch overlay backs a different disk than authorized")
    # Proving the retained base digest is what preserves Windows: the run
    # refuses to boot if the persistent disk changed since authorization.
    backing = Path(info["backing"])
    if backing.is_symlink() or not backing.is_file():
        raise RuntimeError("persistent Windows disk is missing or unsafe")
    if sha256(backing) != authorized["backing_windows_disk"]["sha256"]:
        raise RuntimeError("persistent Windows disk differs from authorization")
    audit_arch_boot_boundary(command, disk=overlay, serial=serial)
    for entry in authorization["guest_inputs"]:
        staged = path / entry["name"]
        if staged.is_symlink() or not staged.is_file():
            raise RuntimeError("Arch bundle is missing an authorized guest input")
        if sha256(staged) != entry["sha256"]:
            raise RuntimeError("Arch guest input differs from authorization")
    required = (
        overlay, path / VARS_NAME, path / VERIFY_NAME, path / INSTALLER_NAME)
    if any(item.is_symlink() or not item.is_file() for item in required):
        raise RuntimeError("Arch bundle is incomplete or unsafe")
    return authorization, command


def _argv_digest(command: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(command, separators=(",", ":")).encode()).hexdigest()


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


def _switch_port(command: list[str]) -> int:
    """Recover the loopback switch port the workstation NIC connects to."""
    for index, item in enumerate(command):
        if item != "-netdev" or index + 1 >= len(command):
            continue
        match = re.fullmatch(
            r"socket,id=factory,connect=127\.0\.0\.1:([1-9][0-9]{0,4})",
            command[index + 1])
        if match:
            return int(match.group(1))
    raise RuntimeError("authorized command has no loopback switch port")


def _connect_qmp(
        path: Path, *, expected_peer_pid: int, timeout: float = 30,
) -> QmpClient:
    """Connect the codebase QMP client to the pinned, bounded socket."""
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            return QmpClient.connect(
                path, timeout=1, expected_peer_pid=expected_peer_pid)
        except (OSError, WindowsGuiError) as error:
            last_error = error
            time.sleep(0.05)
    raise RuntimeError("Arch QMP socket did not become ready") from last_error


def hot_attach_disk(
    qmp: QmpClient, serial: str, *, timeout: float = ATTACH_TIMEOUT,
) -> None:
    """Hot-attach the install-target NVMe once archiso is live.

    The overlay is already present as the detached ``osdisk`` block backend
    (the boot argv carries no ``-device nvme``).  A single bounded
    ``device_add`` realises it as an NVMe device exposing *serial*, which is
    exactly the serial the arch_second installer greps out of lsblk.  Any QMP
    fault raises, so the caller tears the run down fail-closed.
    """
    try:
        qmp.execute("device_add", {
            "driver": "nvme",
            "drive": NVME_BACKEND_ID,
            "serial": serial,
            "id": NVME_DEVICE_ID,
        }, timeout=timeout)
    except WindowsGuiError as error:
        raise RuntimeError(
            "install-target NVMe hot-attach failed") from error


def _sanitize_log(path: Path, *, maximum: int = 4 * 1024 * 1024) -> None:
    """Retain a bounded, redacted tail after all writers have stopped."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return
    private_file(path, redact(data[-maximum:]))


def _destroy_runtime_publication(path: Path) -> str | None:
    """Remove the runtime-built Arch publication ISO."""
    try:
        if path.is_symlink():
            return "runtime publication became a symlink"
        path.unlink(missing_ok=True)
    except OSError as error:
        return f"runtime publication cleanup failed: {type(error).__name__}"
    return None


def _validate_lifecycle(serial: str, disk_serial: str = DISK_SERIAL) -> None:
    """Accept only a one-PXE, disk-detached, Windows-preserving transcript."""
    if FAIL_MARKER in serial:
        raise RuntimeError("Arch installer reported failure")
    attached = f"{DISK_ATTACHED_MARKER} serial={disk_serial}"
    required = (
        BEGIN_MARKER,
        attached,
        VERIFY_PASS_MARKER,
        PRESERVED_MARKER,
        COMPLETE_MARKER,
        "Windows Boot Manager",
        "Linux Boot Manager",
        "default auto-windows",
    )
    missing = [marker for marker in required if marker not in serial]
    if missing:
        raise RuntimeError(
            "Arch install lifecycle markers missing: " + ", ".join(missing))
    live_positions = [
        serial.index(marker) for marker in ARCH_LIVE_MARKERS if marker in serial
    ]
    if not live_positions:
        raise RuntimeError("Arch live environment was not observed")
    # The install target must appear only AFTER archiso is live: a disk-serial
    # detection that precedes the live environment would mean the NVMe was
    # cold-plugged into the boot path rather than hot-attached.
    if serial.index(attached) < min(live_positions):
        raise RuntimeError(
            "install target was detected before archiso was live")
    pxe_starts = sum(
        line.startswith("BdsDxe: starting ") and '"UEFI PXEv4' in line
        for line in serial.splitlines()
    )
    if pxe_starts != 1:
        raise RuntimeError(
            "workstation did not use exactly one PXE firmware boot")


# archiso's PXE image reaches a getty `login:` prompt on ttyS0 with no serial
# autologin drop-in; its live root has an empty password. These matchers mirror
# _at_root_prompt (end-of-transcript anchored, no MULTILINE) so login is only
# answered while the prompt is the last thing the guest emitted.
_LOGIN_PROMPT = re.compile(rb"[\w.-]+ login:[ \t]*$")
_PASSWORD_PROMPT = re.compile(rb"[Pp]assword:[ \t]*$")


def _at_login_prompt(transcript: bytes | bytearray) -> bool:
    """Match a getty ``<hostname> login:`` prompt awaiting a username."""
    return _LOGIN_PROMPT.search(transcript) is not None


def _at_password_prompt(transcript: bytes | bytearray) -> bool:
    """Match a login ``Password:`` prompt awaiting the (empty) live password."""
    return _PASSWORD_PROMPT.search(transcript) is not None


def _heredoc(target: str, payload: str) -> bytes:
    """Deliver an exact file into the guest via a base64 heredoc."""
    encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    body = "\n".join(
        encoded[offset:offset + 76] for offset in range(0, len(encoded), 76))
    return (
        f"base64 -d > {target} <<'TELOS_B64_EOF'\n{body}\nTELOS_B64_EOF\n"
    ).encode("ascii")


def drive_installer(
    process: subprocess.Popen[bytes], capture: Path, *,
    verify_script: str, installer_script: str, serial: str,
    attach: Callable[[], None], timeout: float,
) -> str:
    """Drive the Arch live shell and return the captured serial transcript.

    The PXE archiso boots to a getty ``archiso login:`` prompt on ttyS0 with no
    serial autologin, so this first answers that login (username ``root``; the
    live root has an empty password).  Shell readiness is then proven with a
    sentinel-echo handshake rather than an end-of-transcript prompt match: the
    kernel console shares ttyS0 and keeps printing audit/printk lines after the
    prompt, so an end-anchored matcher would never fire.  An image that already
    dropped straight to a root shell is honoured without a spurious login.
    Once the sentinel surfaces the install-target NVMe is still absent (it was
    never cold-plugged).  *attach*
    hot-plugs it over QMP before any installer step runs; a bounded in-guest
    lsblk gate then proves the authorized serial is present, so the destructive
    installer only ever sees the one intended target.  An *attach* failure
    propagates for fail-closed teardown, and a login that never yields a shell
    within *timeout* fails closed with a clear error.
    """
    import select
    if process.stdin is None or process.stdout is None:
        raise RuntimeError("Arch install requires captured serial I/O")
    deadline = time.monotonic() + timeout
    transcript = bytearray()
    capture.touch(mode=0o600)
    capture.chmod(0o600)
    confirm_disk = (
        f"for _ in $(seq 1 30); do "
        f"lsblk -dno SERIAL | grep -qx {serial} && break; sleep 1; done; "
        f"lsblk -dno SERIAL | grep -qx {serial} "
        f"&& echo {DISK_ATTACHED_MARKER} serial={serial} "
        f"|| echo {FAIL_MARKER} rc=disk-serial-missing\n"
    ).encode("ascii")
    steps = [
        f"echo {BEGIN_MARKER}\n".encode("ascii"),
        b"mkdir -p /usr/local/lib/telos\n",
        confirm_disk,
        _heredoc(GUEST_VERIFY_PATH, verify_script),
        _heredoc(GUEST_INSTALLER_PATH, installer_script),
        (
            f"bash {GUEST_INSTALLER_PATH} "
            f"&& echo {COMPLETE_MARKER} "
            f"|| echo {FAIL_MARKER} rc=$?\n"
        ).encode("ascii"),
        b"efibootmgr || true\n",
        b"grep -H '^default' /mnt/boot/loader/loader.conf || true\n",
        b"echo TELOS ARCH TEARDOWN; sync; systemctl poweroff -i "
        b"|| poweroff -f\n",
    ]
    # Shell readiness is proven with a sentinel-echo handshake, never with an
    # end-of-transcript prompt match: archiso boots the kernel console on the
    # same ttyS0, so audit/printk lines keep printing AFTER the root prompt and
    # a prompt anchored to end-of-transcript would never be the last bytes. We
    # echo a unique nonce and substring-search for it anywhere in the buffer,
    # which interleaved kernel spam cannot defeat. The sentinel resolves to
    # ``...=ready``; the echoed command carries ``...=%s``, so the command's own
    # terminal echo can never be mistaken for the shell's ``ready`` output.
    token = os.urandom(16).hex()
    sentinel = f"TELOS_ARCH_SHELL_READY_{token}=ready"
    probe = (
        f"printf '\\nTELOS_ARCH_SHELL_READY_{token}=%s\\n' ready\n"
    ).encode("ascii")
    began = False
    dispatched = False
    login_sent = False
    password_sent = False
    probe_sent = False
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        ready, _, _ = select.select(
            [process.stdout], [], [], min(0.25, deadline - time.monotonic()))
        if ready:
            chunk = os.read(process.stdout.fileno(), 4096)
            if chunk:
                transcript.extend(chunk)
                if len(transcript) > 8 * 1024 * 1024:
                    del transcript[:-8 * 1024 * 1024]
                capture.write_bytes(transcript)
                capture.chmod(0o600)
        text = transcript.decode("utf-8", errors="replace")
        if not began:
            if probe_sent:
                if sentinel in text:
                    # The sentinel proves the root shell is live and reading
                    # stdin despite interleaved kernel spam: hot-attach the
                    # install target before any step so its serial is present
                    # when the installer greps lsblk, then drive the installer.
                    attach()
                    for command in steps:
                        process.stdin.write(command)
                    process.stdin.flush()
                    began = True
                    dispatched = True
            elif not login_sent and _at_login_prompt(transcript):
                # Answer the getty login; the live root has no password, so this
                # yields the root shell the sentinel handshake then confirms.
                process.stdin.write(b"root\n")
                process.stdin.flush()
                login_sent = True
            elif (login_sent and not password_sent
                    and _at_password_prompt(transcript)):
                # The PXE live image should not ask for a password, but if a
                # variant does the live root's password is empty: answer with a
                # bare line rather than stalling until the deadline.
                process.stdin.write(b"\n")
                process.stdin.flush()
                password_sent = True
            elif login_sent or _at_root_prompt(transcript):
                # The getty login was answered (or an autologin image dropped
                # straight to a root shell): echo the readiness sentinel and
                # wait for it to surface anywhere in the transcript. Sending it
                # before attaching keeps the ordering root -> ready -> attach ->
                # installer; the shell buffers our line through login, so the
                # nonce prints as soon as it is actually accepting commands.
                process.stdin.write(probe)
                process.stdin.flush()
                probe_sent = True
        if dispatched and (COMPLETE_MARKER in text or FAIL_MARKER in text):
            # Give the boot-entry proof and teardown lines a brief moment to
            # arrive before the guest powers off.
            grace = time.monotonic() + 15
            while time.monotonic() < grace and process.poll() is None:
                more, _, _ = select.select([process.stdout], [], [], 0.25)
                if not more:
                    continue
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                transcript.extend(chunk)
                capture.write_bytes(transcript)
                capture.chmod(0o600)
            break
    capture.write_bytes(transcript)
    capture.chmod(0o600)
    if not began:
        raise RuntimeError(
            "Arch live root shell was never reached: the archiso getty login "
            "was answered but the readiness sentinel never surfaced in the "
            "serial transcript before the deadline")
    return transcript.decode("utf-8", errors="replace")


def run(
    bundle: Path, *, controller_state: Path, releases: Path, seed_iso: Path,
    duration: float, apply: bool,
) -> int:
    if not 60 <= duration <= MAX_DURATION:
        raise RuntimeError(
            f"duration must be between 60 and {MAX_DURATION} seconds")
    authorization, workstation_command = _bundle(bundle)
    bundle = bundle.resolve()
    authorized = authorization["authorization"]
    print("Boundary: loopback-only switch; no host or UniFi changes")
    print(f"Bundle: {bundle}")
    print(
        "Workstation: PXE-boots disk-detached; the authorized NVMe overlay is "
        "hot-attached once archiso is live; Windows preserved")
    print(f"Arch release: {authorized['release_version']}")
    print(f"Maximum runtime: {duration:g} seconds")
    if not apply:
        print("dry run; repeat with --apply")
        return 0

    evidence = bundle / "evidence"
    if evidence.exists():
        raise RuntimeError("bundle already has execution evidence")
    evidence.mkdir(mode=0o700)
    qmp_socket = _qmp_socket_path(workstation_command)
    port = _switch_port(workstation_command)
    owned_qmp_root: Path | None = None
    if qmp_socket.parent != bundle:
        qmp_socket.parent.mkdir(mode=0o700, exist_ok=False)
        owned_qmp_root = qmp_socket.parent
    elif qmp_socket.exists():
        raise RuntimeError("bundle QMP socket path is already occupied")

    verify_script = (bundle / VERIFY_NAME).read_text(encoding="utf-8")
    installer_script = (bundle / INSTALLER_NAME).read_text(encoding="utf-8")
    canonical = paths(controller_state)
    processes: dict[str, subprocess.Popen[bytes]] = {}
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(3)
    publication_iso = evidence / "publication.iso"
    result = {"schema": 1, "status": "fail", "phase": "starting"}
    try:
        with SignalGuard(), DisposableBootDisk(
                canonical["disk"], canonical["vars"],
                run_root=evidence / "controller") as overlay:
            publication = evidence / "publication"
            receipt = stage_publication(
                releases, publication, seed_iso=seed_iso,
                target="arch-workstation")
            if (receipt["version"] != authorized["release_version"]
                    or receipt["selected_manifest_sha256"]
                    != authorized["release_manifest_sha256"]):
                raise RuntimeError(
                    "published Arch release differs from the authorized release")
            subprocess.run([
                "xorriso", "-as", "mkisofs", "-quiet", "-iso-level", "3",
                "-V", PUBLICATION_LABEL, "-o", str(publication_iso),
                str(publication),
            ], check=True, capture_output=True)
            publication_iso.chmod(0o600)

            controller_command = qemu_commands(
                overlay.disk, overlay.vars,
                bundle / OVERLAY_NAME, bundle / VARS_NAME,
                port, None, publication_iso)["controller"]
            processes["switch"] = subprocess.Popen(
                switch_command(
                    listener.fileno(), evidence / "switch.jsonl",
                    accept_timeout=360, idle_timeout=duration + 60),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT, pass_fds=(listener.fileno(),))
            listener.close()
            processes["gateway"] = subprocess.Popen(
                gateway_command(port), stdin=subprocess.DEVNULL,
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
            result["phase"] = "arch-publication-ready"
            processes["workstation"] = subprocess.Popen(
                workstation_command, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            audit_live_process(
                processes["workstation"].pid, "client",
                allowed_nic_models=("e1000e",))
            result["phase"] = "arch-install-driving"
            disk_serial = authorized["disk_serial"]
            qmp = _connect_qmp(
                qmp_socket, expected_peer_pid=processes["workstation"].pid)
            try:
                serial = drive_installer(
                    processes["workstation"],
                    evidence / "workstation-serial.log",
                    verify_script=verify_script,
                    installer_script=installer_script,
                    serial=disk_serial,
                    attach=lambda: hot_attach_disk(qmp, disk_serial),
                    timeout=duration)
            finally:
                qmp.close()
            failed = [
                role for role, process in processes.items()
                if role != "workstation" and process.poll() not in (None, 0)
            ]
            if failed:
                raise RuntimeError(
                    "Arch lifecycle process failed: " + ", ".join(failed))
            _validate_lifecycle(serial, disk_serial)
            result = {
                "schema": 1, "status": "observed",
                "phase": "arch-installed-windows-preserved",
                "pxe_firmware_boots": 1,
                "windows_preserved": True,
                "release_version": authorized["release_version"],
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
        _sanitize_log(evidence / "controller-publication.log")
        _sanitize_log(evidence / "workstation-serial.log")
        publication_failure = _destroy_runtime_publication(publication_iso)
        if publication_failure:
            failures.append(publication_failure)
        result["runtime_publication_destroyed"] = publication_failure is None
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
    result.add_argument(
        "--releases", type=Path, default=Path("homelab/var/pxe"))
    result.add_argument("--seed-iso", type=Path, default=DEFAULT_SEED_ISO)
    result.add_argument("--duration", type=float, default=1800)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return run(
        args.bundle, controller_state=args.controller_state,
        releases=args.releases, seed_iso=args.seed_iso,
        duration=args.duration, apply=args.apply)


if __name__ == "__main__":
    raise SystemExit(main())
