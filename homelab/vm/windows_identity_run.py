#!/usr/bin/env python3
"""Ordered, fail-closed lifecycle for native Windows identity acceptance."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import secrets
import socket
import subprocess
from typing import Callable
from pathlib import Path

from .automated_controller import DisposableBootDisk
from .bootstrap_dc import paths
from .factory_runner import (
    gateway_command,
    switch_command,
    wait_for_switch_port,
)
from .signal_cleanup import terminate_children
from .simulated_topology import audit_live_process, controller_command
from .windows_gui import QmpClient
from .windows_identity_contract import qemu_identity_command
from .windows_identity_recovery import RecoveredLocalCredential


class WindowsIdentityRunError(RuntimeError):
    """The native identity lifecycle did not reach a safe terminal state."""


@dataclass
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


@dataclass
class IdentityReceipt:
    """Secret-free lifecycle facts retained by the caller."""

    phases: list[str] = field(default_factory=list)
    local_credential_rotated: bool = False
    private_publication_destroyed: bool = False
    controller_principals_staged: bool = False
    controller_principals_destroyed: bool = False
    teardown_complete: bool = False


class NativeProcessBoundary:
    """Own the isolated switch, disposable Controller, Windows VM, and QMP."""

    def __init__(self, attempt: Path, controller_state: Path) -> None:
        self.attempt = Path(attempt).resolve()
        self.controller_state = Path(controller_state).resolve()
        self.runtime = self.attempt / "runtime"
        self.processes: dict[str, subprocess.Popen[bytes]] = {}
        self.controller_overlay: DisposableBootDisk | None = None
        self.qmp: QmpClient | None = None
        self.port: int | None = None

    def _validate(self) -> None:
        if (self.attempt.is_symlink() or not self.attempt.is_dir()
                or self.attempt.stat().st_mode & 0o077):
            raise WindowsIdentityRunError(
                "identity attempt must be a private real directory")
        for name in ("windows.qcow2", "OVMF_VARS.fd", "authorization.json"):
            item = self.attempt / name
            if item.is_symlink() or not item.is_file():
                raise WindowsIdentityRunError(
                    f"identity attempt lacks regular {name}")
            if item.stat().st_mode & 0o077:
                raise WindowsIdentityRunError(f"{name} must be mode 0600")
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
        controller = paths(self.controller_state)
        for key in ("disk", "vars"):
            item = controller[key]
            if item.is_symlink() or not item.is_file():
                raise WindowsIdentityRunError(
                    f"Controller {key} must be a regular file")

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
            self.processes["switch"] = subprocess.Popen(
                switch_command(
                    listener.fileno(), self.runtime / "switch.jsonl",
                    idle_timeout=3600),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                pass_fds=(listener.fileno(),),
            )
        finally:
            listener.close()
        assert self.port is not None
        self.processes["gateway"] = subprocess.Popen(
            gateway_command(self.port),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        wait_for_switch_port(self.runtime / "switch.jsonl", "gateway")

    def start_controller(self) -> None:
        if self.port is None:
            raise WindowsIdentityRunError("switch must start before Controller")
        canonical = paths(self.controller_state)
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

    def start_windows(self) -> None:
        if self.port is None:
            raise WindowsIdentityRunError("switch must start before Windows")
        qmp_socket = self.runtime / "windows.qmp"
        command = qemu_identity_command(
            disk=self.attempt / "windows.qcow2",
            variables=self.attempt / "OVMF_VARS.fd",
            qmp_socket=qmp_socket,
            switch_port=self.port,
        )
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT)
        self.processes["windows"] = process
        audit_live_process(
            process.pid, "client", allowed_nic_models=("e1000e",))
        wait_for_switch_port(self.runtime / "switch.jsonl", "workstation")

    def authenticate_qmp(self) -> None:
        if "windows" not in self.processes:
            raise WindowsIdentityRunError("Windows must start before QMP")
        self.qmp = QmpClient.connect(self.runtime / "windows.qmp", timeout=30)

    def _stop(self, *roles: str) -> None:
        selected = [
            self.processes.pop(role) for role in roles
            if role in self.processes
        ]
        failures = terminate_children(selected)
        if failures:
            raise WindowsIdentityRunError("; ".join(failures))

    def stop_windows(self) -> None:
        if self.qmp is not None:
            self.qmp.close()
            self.qmp = None
        self._stop("windows")

    def stop_controller(self) -> None:
        self._stop("controller")
        if self.controller_overlay is not None:
            self.controller_overlay.close()
            self.controller_overlay = None

    def stop_switch(self) -> None:
        self._stop("gateway", "switch")


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

    def destroy_private_publication(self) -> None:
        if (self._recovery_context is None or self._old_local is None
                or self._new_local is None):
            raise WindowsIdentityRunError(
                "guest rotation must precede publication destruction")
        self._recovery_context.destroy_publication()
        self._old_local = None
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
        except BaseException:
            self._principals.clear()
            raise

    def destroy_controller_principals(self) -> None:
        names = tuple(self._principals)
        if not names:
            raise WindowsIdentityRunError(
                "Controller principals were not staged")
        try:
            self.destroy_guest_principals(names)
        finally:
            self._principals.clear()

    def close(self) -> None:
        self._old_local = None
        self._new_local = None
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
        operations.start_switch()
        started.append("switch")
        receipt.phases.append("switch-started")
        operations.start_controller()
        started.append("controller")
        receipt.phases.append("controller-started")
        operations.start_windows()
        started.append("windows")
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
        receipt.teardown_complete,
    )
    if not all(required):
        raise WindowsIdentityRunError(
            "native identity lifecycle ended without complete destruction proof")
    return receipt
