#!/usr/bin/env python3
"""Ordered, fail-closed lifecycle for native Windows identity acceptance."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Mapping
from types import MappingProxyType
from pathlib import Path

from .automated_controller import DisposableBootDisk
from .bootstrap_dc import paths
from .factory_runner import (
    gateway_command,
    switch_command,
    wait_for_switch_port,
)
from .signal_cleanup import RunInterrupted, terminate_children
from .simulated_topology import audit_live_process, controller_command
from .windows_gui import QmpClient
from .windows_identity_contract import qemu_identity_command
from .windows_identity_prepare import CONTROL_ISO_NAME
from .windows_identity_recovery import RecoveredLocalCredential
from .windows_identity_dependency import DEPENDENCIES


class WindowsIdentityRunError(RuntimeError):
    """The native identity lifecycle did not reach a safe terminal state."""


@dataclass(repr=False)
class IdentityOperations:
    """Secret-owning operations supplied by the native runner adapter."""

    start_switch: Callable[[], None]
    start_controller: Callable[[], None]
    start_windows: Callable[[], None]
    authenticate_qmp: Callable[[], None]
    rotate_local_credential: Callable[[], None]
    destroy_private_publication: Callable[[], None]
    stage_controller_principals: Callable[[], None]
    run_acceptance_phases: Callable[[], None]
    destroy_controller_principals: Callable[[], None]
    stop_windows: Callable[[], None]
    stop_controller: Callable[[], None]
    stop_switch: Callable[[], None]

    def __repr__(self) -> str:
        return "IdentityOperations(<private callbacks>)"


@dataclass
class IdentityReceipt:
    """Secret-free lifecycle facts retained by the caller."""

    phases: list[str] = field(default_factory=list)
    local_credential_rotated: bool = False
    private_publication_destroyed: bool = False
    controller_principals_staged: bool = False
    controller_principals_destroyed: bool = False
    acceptance_complete: bool = False
    teardown_complete: bool = False


class NativeProcessBoundary:
    """Own the isolated switch, disposable Controller, Windows VM, and QMP."""

    def __init__(self, attempt: Path, controller_state: Path) -> None:
        self.attempt = Path(attempt).absolute()
        self.controller_state = Path(controller_state).absolute()
        self.runtime = self.attempt / "runtime"
        self.processes: dict[str, subprocess.Popen[bytes]] = {}
        self.controller_overlay: DisposableBootDisk | None = None
        self.qmp: QmpClient | None = None
        self.qmp_root: Path | None = None
        self.serial_socket: Path | None = None
        self.port: int | None = None
        self.authorized_command: list[str] | None = None
        self.suspended_processes: set[str] = set()
        self.dependency_endpoints: dict[str, tuple[str, int]] = {}

    @staticmethod
    def _normalized_command(command: list[str]) -> list[str]:
        normalized = []
        for value in command:
            if value.startswith("unix:") and value.endswith(
                    ",server=on,wait=off"):
                normalized.append("unix:<PRIVATE-QMP>,server=on,wait=off")
            elif re.fullmatch(
                    r"socket,id=telosidentity,path=[^,]+,"
                    r"server=on,wait=off", value):
                normalized.append(
                    "socket,id=telosidentity,path=<PRIVATE-SERIAL>,"
                    "server=on,wait=off")
            elif re.fullmatch(
                    r"socket,id=factory,connect=127\.0\.0\.1:"
                    r"[1-9][0-9]{0,4}", value):
                normalized.append(
                    "socket,id=factory,connect=127.0.0.1:<PORT>")
            else:
                normalized.append(value)
        return normalized

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def _validate(self) -> None:
        if (self.attempt.is_symlink() or not self.attempt.is_dir()
                or self.attempt.stat().st_mode & 0o077):
            raise WindowsIdentityRunError(
                "identity attempt must be a private real directory")
        for name in (
                "windows.qcow2", "OVMF_VARS.fd", "authorization.json",
                "qemu-command.json"):
            item = self.attempt / name
            if item.is_symlink() or not item.is_file():
                raise WindowsIdentityRunError(
                    f"identity attempt lacks regular {name}")
            if item.stat().st_mode & 0o077:
                raise WindowsIdentityRunError(f"{name} must be mode 0600")
        control_iso = self.attempt / CONTROL_ISO_NAME
        if control_iso.is_symlink() or not control_iso.is_file():
            raise WindowsIdentityRunError(
                "identity attempt lacks regular control.iso")
        if stat.S_IMODE(control_iso.stat().st_mode) != 0o444:
            raise WindowsIdentityRunError("control.iso must be mode 0444")
        try:
            authorization = json.loads(
                (self.attempt / "authorization.json").read_text(
                    encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise WindowsIdentityRunError(
                "identity authorization is unreadable") from error
        expected = {
            "status": "prepared",
            "external_access": False,
            "installation_media_attached": False,
            "pxe_boot_enabled": False,
        }
        if any(authorization.get(key) != value
               for key, value in expected.items()):
            raise WindowsIdentityRunError(
                "identity authorization does not preserve native isolation")
        try:
            command_document = json.loads(
                (self.attempt / "qemu-command.json").read_text(
                    encoding="utf-8"))
            command = command_document["argv"]
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
            raise WindowsIdentityRunError(
                "authorized QEMU command is unreadable") from error
        if (not isinstance(command_document, dict)
                or set(command_document) != {"schema", "argv"}
                or command_document["schema"] != 1
                or not isinstance(command, list)
                or any(not isinstance(value, str) for value in command)):
            raise WindowsIdentityRunError(
                "authorized QEMU command has an invalid schema")
        command_digest = hashlib.sha256(
            json.dumps(command, separators=(",", ":")).encode()).hexdigest()
        if authorization.get("qemu_argv_sha256") != command_digest:
            raise WindowsIdentityRunError(
                "authorized QEMU command digest does not match")
        self.authorized_command = command
        if authorization.get("controller_state") != str(
                self.controller_state.resolve()):
            raise WindowsIdentityRunError(
                "identity authorization names a different Controller state")
        overlay = authorization.get("overlay")
        firmware = authorization.get("firmware_copy")
        control_media = authorization.get("control_media")
        serial_transport = authorization.get("serial_transport")
        serial_arguments = [
            value for value in command
            if re.fullmatch(
                r"socket,id=telosidentity,path=[^,]+,"
                r"server=on,wait=off", value)
        ]
        if (
            not isinstance(overlay, dict)
            or overlay.get("path") != str(
                (self.attempt / "windows.qcow2").resolve())
            or overlay.get("format") != "qcow2"
            or not isinstance(firmware, dict)
            or firmware.get("path") != str(
                (self.attempt / "OVMF_VARS.fd").resolve())
        ):
            raise WindowsIdentityRunError(
                "identity authorization paths do not match the attempt")
        if (
            not isinstance(control_media, dict)
            or set(control_media) != {
                "path", "sha256", "read_only", "contains_secrets"}
            or control_media.get("path") != str(control_iso.resolve())
            or control_media.get("read_only") is not True
            or control_media.get("contains_secrets") is not False
            or control_media.get("sha256") != self._sha256(control_iso)
        ):
            raise WindowsIdentityRunError(
                "control ISO differs from the authorized static artifact")
        if (
            not isinstance(serial_transport, dict)
            or set(serial_transport) != {
                "kind", "authorized_path", "contains_secrets"}
            or serial_transport.get("kind") != "private-unix-socket-jsonl"
            or serial_transport.get("contains_secrets") is not False
            or len(serial_arguments) != 1
            or serial_transport.get("authorized_path")
            != serial_arguments[0].split(",path=", 1)[1].split(",", 1)[0]
        ):
            raise WindowsIdentityRunError(
                "serial transport differs from the authorized boundary")
        controller = paths(self.controller_state)
        if (self.controller_state.is_symlink()
                or not self.controller_state.is_dir()
                or self.controller_state.stat().st_mode & 0o077):
            raise WindowsIdentityRunError(
                "Controller state must be a private real directory")
        for key in ("disk", "vars"):
            item = controller[key]
            if item.is_symlink() or not item.is_file():
                raise WindowsIdentityRunError(
                    f"Controller {key} must be a regular file")
            if item.stat().st_mode & 0o077:
                raise WindowsIdentityRunError(
                    f"Controller {key} must be mode 0600")

    def start_switch(self) -> None:
        self._validate()
        if self.runtime.exists():
            raise WindowsIdentityRunError(
                "identity runtime already exists")
        self.runtime.mkdir(mode=0o700)
        listener = socket.socket()
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(3)
            self.port = int(listener.getsockname()[1])
            command = switch_command(
                listener.fileno(), self.runtime / "switch.jsonl",
                idle_timeout=3600)
            for role, spec in DEPENDENCIES.items():
                command.extend([
                    "--port",
                    f"{role}={bytes(spec['mac']).hex(':')}",
                ])
            self.processes["switch"] = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                pass_fds=(listener.fileno(),),
            )
        except BaseException:
            self._stop("switch")
            raise
        finally:
            listener.close()
        try:
            assert self.port is not None
            self.processes["gateway"] = subprocess.Popen(
                gateway_command(self.port),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
            )
            wait_for_switch_port(self.runtime / "switch.jsonl", "gateway")
        except BaseException:
            self._stop("gateway", "switch")
            raise

    def _start_dependency(self, role: str) -> None:
        """Attach one separately owned service to its pinned isolated L2 port."""
        if role in self.processes or role in self.dependency_endpoints:
            raise WindowsIdentityRunError(
                f"{role} dependency runtime already exists")
        if self.port is None:
            raise WindowsIdentityRunError("switch must start before dependency")
        spec = DEPENDENCIES[role]
        process = subprocess.Popen(
            [
                sys.executable,
                "-m", "homelab.vm.windows_identity_dependency",
                "--role", role,
                "--switch-port", str(self.port),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        self.processes[role] = process
        self.dependency_endpoints[role] = (
            str(spec["ip"]), int(spec["port"]))
        try:
            wait_for_switch_port(self.runtime / "switch.jsonl", role)
            if process.poll() is not None:
                raise WindowsIdentityRunError(
                    f"{role} dependency exited during readiness")
        except BaseException:
            try:
                self._stop(role)
            finally:
                self.dependency_endpoints.pop(role, None)
            raise

    def start_controller(self) -> None:
        if self.port is None:
            raise WindowsIdentityRunError("switch must start before Controller")
        canonical = paths(self.controller_state)
        try:
            self.controller_overlay = DisposableBootDisk(
                canonical["disk"], canonical["vars"],
                run_root=self.runtime / "controller").prepare()
            command = controller_command(
                self.controller_state,
                self.controller_overlay.disk,
                self.controller_overlay.vars,
                self.port,
                disk_format="raw",
            )
            process = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
            self.processes["controller"] = process
            audit_live_process(
                process.pid, "controller",
                disposable_disk=self.controller_overlay.disk,
                disposable_vars=self.controller_overlay.vars,
                forbidden_paths=(canonical["disk"], canonical["vars"]),
            )
            wait_for_switch_port(self.runtime / "switch.jsonl", "controller")
        except BaseException:
            self.stop_controller()
            raise

    def start_windows(self) -> None:
        if self.port is None:
            raise WindowsIdentityRunError("switch must start before Windows")
        if self.qmp_root is not None:
            raise WindowsIdentityRunError(
                "Windows QMP runtime is already allocated")
        self.qmp_root = Path(tempfile.mkdtemp(
            prefix="telos-win-id-qmp-"))
        self.qmp_root.chmod(0o700)
        qmp_socket = self.qmp_root / "windows.qmp"
        self.serial_socket = self.qmp_root / "windows.serial"
        try:
            command = qemu_identity_command(
                disk=self.attempt / "windows.qcow2",
                variables=self.attempt / "OVMF_VARS.fd",
                qmp_socket=qmp_socket,
                serial_socket=self.serial_socket,
                switch_port=self.port,
                control_iso=self.attempt / CONTROL_ISO_NAME,
            )
        except BaseException:
            self._cleanup_qmp_root()
            raise
        if (
            self.authorized_command is None
            or self._normalized_command(command)
            != self._normalized_command(self.authorized_command)
        ):
            self._cleanup_qmp_root()
            raise WindowsIdentityRunError(
                "runtime QEMU command differs from the authorized template")
        try:
            qemu_log = self.runtime / "windows-qemu.log"
            with qemu_log.open("xb") as output:
                qemu_log.chmod(0o600)
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=output,
                    stderr=subprocess.STDOUT)
            self.processes["windows"] = process
            chardevs = (
                (command[command.index("-chardev") + 1],)
                if "-chardev" in command else ()
            )
            audit_live_process(
                process.pid, "client", allowed_nic_models=("e1000e",),
                allowed_chardevs=chardevs)
            wait_for_switch_port(self.runtime / "switch.jsonl", "workstation")
            self._start_dependency("update-source")
            self._start_dependency("optional-storage")
        except BaseException:
            self.stop_windows()
            raise

    def authenticate_qmp(self) -> None:
        if "windows" not in self.processes:
            raise WindowsIdentityRunError("Windows must start before QMP")
        deadline = time.monotonic() + 30
        error: OSError | None = None
        while time.monotonic() < deadline:
            if self.processes["windows"].poll() is not None:
                raise WindowsIdentityRunError(
                    "Windows exited before QMP authentication")
            try:
                if self.qmp_root is None:
                    raise WindowsIdentityRunError(
                        "Windows QMP runtime is unavailable")
                self.qmp = QmpClient.connect(
                    self.qmp_root / "windows.qmp", timeout=2)
                return
            except OSError as caught:
                error = caught
                time.sleep(0.1)
        raise WindowsIdentityRunError(
            "timed out authenticating Windows QMP") from error

    def _stop(self, *roles: str) -> None:
        resume_failures = []
        for role in roles:
            if role not in self.suspended_processes:
                continue
            process = self.processes.get(role)
            if process is not None and process.poll() is not None:
                # A dead child cannot remain suspended. Drop only the stale
                # availability state and continue through normal reap/removal.
                self.suspended_processes.remove(role)
                continue
            try:
                self._set_process_available(role, True)
            except BaseException as error:
                resume_failures.append(
                    f"{role} resume before teardown: {type(error).__name__}")
        if resume_failures:
            raise WindowsIdentityRunError("; ".join(resume_failures))
        selected = [
            (role, self.processes[role]) for role in roles
            if role in self.processes
        ]
        children = [process for _, process in selected]
        failures = terminate_children(children)
        if failures:
            raise WindowsIdentityRunError("; ".join(failures))
        for role, process in selected:
            if process.poll() is None:
                raise WindowsIdentityRunError(
                    f"{role} process remained live after teardown")
            self.processes.pop(role, None)

    def _set_process_available(self, role: str, available: bool) -> None:
        """Suspend or resume one separately owned dependency process.

        SIGSTOP/SIGCONT provide a host-enforced, reversible outage without
        changing the isolated switch, guest disks, or dependency state.  A
        dependency must have its own live process: aliases would make the
        individual and combined fault phases indistinguishable.
        """
        if not isinstance(available, bool):
            raise WindowsIdentityRunError(
                f"{role} dependency availability must be boolean")
        process = self.processes.get(role)
        if process is None:
            raise WindowsIdentityRunError(
                f"{role} dependency has no separately owned process")
        if process.poll() is not None:
            raise WindowsIdentityRunError(
                f"{role} dependency process is not live")
        is_suspended = role in self.suspended_processes
        if available == (not is_suspended):
            raise WindowsIdentityRunError(
                f"{role} dependency is already "
                f"{'available' if available else 'offline'}")
        os.kill(process.pid, signal.SIGCONT if available else signal.SIGSTOP)
        if available:
            self.suspended_processes.remove(role)
        else:
            self.suspended_processes.add(role)

    def set_controller_available(self, available: bool) -> None:
        self._set_process_available("controller", available)

    def set_gateway_available(self, available: bool) -> None:
        self._set_process_available("gateway", available)

    def set_update_source_available(self, available: bool) -> None:
        self._set_process_available("update-source", available)

    def set_optional_storage_available(self, available: bool) -> None:
        self._set_process_available("optional-storage", available)

    def _cleanup_qmp_root(self) -> None:
        if self.qmp_root is None:
            return
        if (self.qmp_root.is_symlink() or not self.qmp_root.is_dir()
                or self.qmp_root.stat().st_mode & 0o077):
            raise WindowsIdentityRunError(
                "private QMP runtime identity changed")
        entries = list(self.qmp_root.iterdir())
        for entry in entries:
            metadata = entry.lstat()
            if entry.name not in {"windows.qmp", "windows.serial"} or not stat.S_ISSOCK(
                    metadata.st_mode):
                raise WindowsIdentityRunError(
                    "private QMP runtime contains an unexpected entry")
            entry.unlink()
        self.qmp_root.rmdir()
        self.qmp_root = None
        self.serial_socket = None

    def stop_windows(self) -> None:
        failures = []
        if {
            "optional-storage", "update-source"
        }.intersection(self.processes):
            try:
                self._stop("optional-storage", "update-source")
            except BaseException as error:
                failures.append(
                    f"dependency processes: {type(error).__name__}")
        if not {
            "optional-storage", "update-source"
        }.intersection(self.processes):
            self.dependency_endpoints.clear()
        if self.qmp is not None:
            try:
                self.qmp.close()
            except BaseException as error:
                failures.append(f"QMP close: {type(error).__name__}")
            else:
                self.qmp = None
        try:
            self._stop("windows")
        except BaseException as error:
            failures.append(f"Windows process: {type(error).__name__}")
        if self.qmp is None and "windows" not in self.processes:
            try:
                self._cleanup_qmp_root()
            except BaseException as error:
                failures.append(f"QMP runtime: {type(error).__name__}")
        if failures:
            raise WindowsIdentityRunError("; ".join(failures))

    def stop_controller(self) -> None:
        failures = []
        try:
            self._stop("controller")
        except BaseException as error:
            failures.append(f"Controller process: {type(error).__name__}")
        if self.controller_overlay is not None:
            try:
                self.controller_overlay.close()
            except BaseException as error:
                failures.append(f"Controller overlay: {type(error).__name__}")
            else:
                self.controller_overlay = None
        if failures:
            raise WindowsIdentityRunError("; ".join(failures))

    def stop_switch(self) -> None:
        roles = [
            role for role in (
                "optional-storage", "update-source", "gateway", "switch")
            if role in self.processes
        ]
        if roles:
            self._stop(*roles)
        if not {
            "optional-storage", "update-source"
        }.intersection(self.processes):
            self.dependency_endpoints.clear()


class PrivateIdentityMaterial:
    """Own recovered and generated credentials without exposing their values."""

    def __init__(
        self,
        publication: Path,
        private_parent: Path,
        *,
        rotate_guest: Callable[[str, str], None],
        stage_principals: Callable[[dict[str, str]], None],
        destroy_principals: Callable[[tuple[str, ...]], None],
    ) -> None:
        self.recovery = RecoveredLocalCredential(
            publication, private_parent)
        self.rotate_guest = rotate_guest
        self.stage_guest_principals = stage_principals
        self.destroy_guest_principals = destroy_principals
        self._recovery_context: RecoveredLocalCredential | None = None
        self._old_local: str | None = None
        self._new_local: str | None = None
        self._principals: dict[str, str] = {}

    @staticmethod
    def _credential() -> str:
        return "Synthetic-" + secrets.token_urlsafe(24) + "-47!"

    def rotate_local_credential(self) -> None:
        if self._recovery_context is not None:
            raise WindowsIdentityRunError(
                "local credential recovery is already active")
        self._recovery_context = self.recovery
        self._old_local = self._recovery_context.__enter__()
        self._new_local = self._credential()
        try:
            self.rotate_guest(self._old_local, self._new_local)
        except BaseException:
            self.close()
            raise

    def generate_replacement_credential(self) -> str:
        """Generate and retain one replacement for a progressive rotation."""
        if self._new_local is not None:
            raise WindowsIdentityRunError(
                "replacement credential is already owned")
        self._new_local = self._credential()
        return self._new_local

    def run_scoped_acceptance(
        self,
        replacement: str,
        acceptance: Callable[[str, Mapping[str, str]], None],
    ) -> None:
        """Keep all credentials memory-owned through one acceptance callback.

        The callback receives a read-only principal mapping at runtime.  On a
        successful acceptance and principal teardown, every retained
        credential reference owned by this object is released.
        """
        if replacement is not self._new_local:
            raise WindowsIdentityRunError(
                "acceptance replacement is not the owned credential")
        if self._old_local is not None or self._recovery_context is not None:
            raise WindowsIdentityRunError(
                "recovered credential remains active during acceptance")
        self.stage_controller_principals()
        primary: BaseException | None = None
        cleanup: BaseException | None = None
        try:
            acceptance(
                self._new_local,
                MappingProxyType(self._principals),
            )
        except BaseException as error:
            primary = error
        try:
            self.destroy_controller_principals()
        except BaseException as error:
            cleanup = error
        if cleanup is None:
            self._new_local = None
        if primary is not None or cleanup is not None:
            details = []
            if primary is not None:
                details.append(f"acceptance: {type(primary).__name__}")
            if cleanup is not None:
                details.append(
                    f"principal destruction: {type(cleanup).__name__}")
            raise WindowsIdentityRunError(
                "scoped identity acceptance failed; " + "; ".join(details)
            ) from None

    def destroy_private_publication(self) -> None:
        if (self._recovery_context is None or self._old_local is None
                or self._new_local is None):
            raise WindowsIdentityRunError(
                "guest rotation must precede publication destruction")
        self._recovery_context.destroy_publication()
        self._old_local = None
        self._new_local = None
        self._recovery_context.__exit__(None, None, None)
        self._recovery_context = None

    def stage_controller_principals(self) -> None:
        if self._old_local is not None or self._recovery_context is not None:
            raise WindowsIdentityRunError(
                "recovered credential must be destroyed before staging")
        if self._principals:
            raise WindowsIdentityRunError(
                "Controller principals are already staged")
        self._principals = {
            name: self._credential()
            for name in ("student", "operator", "directory-admin")
        }
        try:
            self.stage_guest_principals(self._principals)
        except BaseException as stage_error:
            try:
                self.destroy_guest_principals(tuple(self._principals))
            except BaseException as destroy_error:
                raise WindowsIdentityRunError(
                    "Controller principal staging and rollback both failed: "
                    f"{type(stage_error).__name__}; "
                    f"{type(destroy_error).__name__}") from stage_error
            self._principals.clear()
            raise

    def destroy_controller_principals(self) -> None:
        names = tuple(self._principals)
        if not names:
            raise WindowsIdentityRunError(
                "Controller principals were not staged")
        self.destroy_guest_principals(names)
        self._principals.clear()

    def close(self, *, controller_destroyed: bool = False) -> None:
        self._old_local = None
        self._new_local = None
        if self._principals and not controller_destroyed:
            raise WindowsIdentityRunError(
                "Controller principal cleanup remains unresolved")
        self._principals.clear()
        if self._recovery_context is not None:
            self._recovery_context.__exit__(None, None, None)
            self._recovery_context = None


def run_lifecycle(operations: IdentityOperations) -> IdentityReceipt:
    """Run identity proof in the only ordering that may consume credentials."""
    receipt = IdentityReceipt()
    started: list[str] = []
    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []
    try:
        started.append("switch")
        operations.start_switch()
        receipt.phases.append("switch-started")
        started.append("controller")
        operations.start_controller()
        receipt.phases.append("controller-started")
        started.append("windows")
        operations.start_windows()
        receipt.phases.append("windows-started")
        operations.authenticate_qmp()
        receipt.phases.append("qmp-authenticated")
        operations.rotate_local_credential()
        receipt.local_credential_rotated = True
        receipt.phases.append("local-credential-rotated")
        operations.destroy_private_publication()
        receipt.private_publication_destroyed = True
        receipt.phases.append("private-publication-destroyed")
        operations.stage_controller_principals()
        receipt.controller_principals_staged = True
        receipt.phases.append("controller-principals-staged")
        operations.run_acceptance_phases()
        receipt.acceptance_complete = True
        receipt.phases.append("acceptance-complete")
    except BaseException as error:
        primary_error = error
    finally:
        if receipt.controller_principals_staged:
            try:
                operations.destroy_controller_principals()
                receipt.controller_principals_destroyed = True
                receipt.phases.append("controller-principals-destroyed")
            except BaseException as error:
                cleanup_errors.append(
                    f"controller principal destruction: {type(error).__name__}")
        for role, stop in (
            ("windows", operations.stop_windows),
            ("controller", operations.stop_controller),
            ("switch", operations.stop_switch),
        ):
            if role not in started:
                continue
            try:
                stop()
                receipt.phases.append(f"{role}-stopped")
            except BaseException as error:
                cleanup_errors.append(f"{role} teardown: {type(error).__name__}")
        receipt.teardown_complete = not cleanup_errors
    if primary_error is not None or cleanup_errors:
        if isinstance(primary_error, RunInterrupted) and not cleanup_errors:
            raise primary_error
        details = []
        if primary_error is not None:
            details.append(f"lifecycle: {type(primary_error).__name__}")
        details.extend(cleanup_errors)
        raise WindowsIdentityRunError(
            "native identity lifecycle failed; " + "; ".join(details))
    required = (
        receipt.local_credential_rotated,
        receipt.private_publication_destroyed,
        receipt.controller_principals_staged,
        receipt.controller_principals_destroyed,
        receipt.acceptance_complete,
        receipt.teardown_complete,
    )
    if not all(required):
        raise WindowsIdentityRunError(
            "native identity lifecycle ended without complete destruction proof")
    return receipt
