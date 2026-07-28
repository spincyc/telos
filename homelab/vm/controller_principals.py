#!/usr/bin/env python3
"""Stage and destroy disposable Samba principals over a serial console."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import re
from typing import BinaryIO, Mapping
import uuid

from .serial_automation import SerialAutomation, SerialAutomationError


class ControllerPrincipalError(RuntimeError):
    """The Controller did not prove a principal operation completed."""


@dataclass(frozen=True)
class ControllerPrincipalResult:
    """Secret-free facts from one Controller principal operation."""

    operation: str
    principals: tuple[str, ...]
    events: tuple[str, ...]


_ROLES = ("student", "operator", "directory-admin")
_SAFE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")

# These programs run inside the disposable Controller.  Their source is
# encoded only to make it safe to place in one shell word; it contains no
# instance data or credential.
_STAGE_PROGRAM = r"""
import json
import sys

from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB

values = json.load(sys.stdin)
expected = {"student", "operator", "directory-admin"}
if set(values) != expected:
    raise ValueError("unexpected principal roster")
lp = LoadParm()
lp.load_default()
samdb = SamDB(session_info=system_session(), lp=lp)
created = []
try:
    for name in ("student", "operator", "directory-admin"):
        samdb.newuser(
            name, values[name],
            force_password_change_at_next_login_req=False,
        )
        created.append(name)
    samdb.add_remove_group_members(
        "Domain Admins", ["directory-admin"], add_members_operation=True,
    )
except BaseException:
    for name in reversed(created):
        try:
            samdb.deleteuser(name)
        except BaseException:
            pass
    raise
"""

_DESTROY_PROGRAM = r"""
import json
import sys

from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB

names = json.load(sys.stdin)
expected = {"student", "operator", "directory-admin"}
if set(names) != expected or len(names) != len(expected):
    raise ValueError("unexpected principal roster")
lp = LoadParm()
lp.load_default()
samdb = SamDB(session_info=system_session(), lp=lp)
failures = []
for name in reversed(names):
    try:
        samdb.deleteuser(name)
    except BaseException as error:
        failures.append(type(error).__name__)
if failures:
    raise RuntimeError("principal destruction failed: " + ",".join(failures))
"""


def _encoded_program(source: str) -> bytes:
    return base64.b64encode(source.encode("utf-8"))


class ControllerPrincipalSerial:
    """Drive secret-safe principal operations on an autologin Controller TTY."""

    def __init__(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
        *,
        timeout: float = 90.0,
    ) -> None:
        self.console = SerialAutomation(
            reader, writer, None, timeout=timeout)

    @staticmethod
    def _names(names: tuple[str, ...]) -> tuple[str, ...]:
        if (set(names) != set(_ROLES) or len(names) != len(_ROLES)
                or any(not _SAFE_NAME.fullmatch(name) for name in names)):
            raise ValueError("Controller principal roster is invalid")
        return names

    @staticmethod
    def _values(values: Mapping[str, str]) -> dict[str, str]:
        if set(values) != set(_ROLES):
            raise ValueError("Controller principal roster is invalid")
        copied = dict(values)
        for name, password in copied.items():
            if not _SAFE_NAME.fullmatch(name):
                raise ValueError("Controller principal name is invalid")
            if (not isinstance(password, str) or not password
                    or "\n" in password or "\r" in password
                    or "\x00" in password):
                raise ValueError("Controller principal credential is invalid")
        if len(set(copied.values())) != len(copied):
            raise ValueError("Controller principal credentials must be distinct")
        return copied

    def _run(
        self,
        operation: str,
        payload: object,
        program: str,
        names: tuple[str, ...],
    ) -> ControllerPrincipalResult:
        console = self.console
        token = uuid.uuid4().hex.encode("ascii")
        ready = b"__TELOS_PRINCIPAL_READY_" + token + b"__"
        result = b"__TELOS_PRINCIPAL_RC_" + token + b"="
        encoded = _encoded_program(program)
        command = (
            b"trap 'stty echo' INT TERM EXIT; "
            b"stty -echo || exit 91; "
            b"printf '\\n" + ready + b"\\n'; "
            b"IFS= read -r __telos_payload; "
            b"stty echo; trap - INT TERM EXIT; "
            b"printf '%s' \"$__telos_payload\" | base64 -d | "
            b"sudo -n python3 -c \"import base64;"
            b"exec(base64.b64decode('" + encoded + b"'))\" "
            b"2>/dev/null; "
            b"__telos_rc=$?; unset __telos_payload; "
            b"printf '\\n" + result + b"%s\\n' \"$__telos_rc\""
        )
        try:
            console._wait(
                rb"(?:^|\n)[^\n]*\$\s*$", "controller-shell-ready")
            console._send(command, operation + "-command-sent")
            console._wait(
                rb"(?:^|\n)" + re.escape(ready) + rb"\s*(?:\n|$)",
                operation + "-secret-input-ready")
            wire = base64.b64encode(
                json.dumps(
                    payload, sort_keys=True, separators=(",", ":"),
                ).encode("utf-8"))
            console._send(wire, operation + "-secret-input-sent")
            match = console._wait(
                rb"(?:^|\n)" + re.escape(result)
                + rb"([0-9]+)\s*(?:\n|$)",
                operation + "-return-code-observed")
        except SerialAutomationError as error:
            raise ControllerPrincipalError(
                f"Controller {operation} protocol failed") from error
        returncode = int(match.group(1))
        if returncode:
            raise ControllerPrincipalError(
                f"Controller {operation} returned {returncode}")
        return ControllerPrincipalResult(
            operation, names, tuple(console.events))

    def stage(
        self, values: Mapping[str, str],
    ) -> ControllerPrincipalResult:
        """Create exactly the disposable identity-acceptance principals."""
        copied = self._values(values)
        names = tuple(copied)
        return self._run("stage", copied, _STAGE_PROGRAM, names)

    def destroy(
        self, names: tuple[str, ...],
    ) -> ControllerPrincipalResult:
        """Destroy exactly the disposable identity-acceptance principals."""
        checked = self._names(names)
        return self._run("destroy", list(checked), _DESTROY_PROGRAM, checked)
