#!/usr/bin/env python3
"""One-use domain-join material over the private Controller serial channel."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import re
import secrets
from types import MappingProxyType
from typing import BinaryIO, Callable, Mapping, TypeVar
import uuid

from .serial_automation import SerialAutomation, SerialAutomationError


class ControllerJoinMaterialError(RuntimeError):
    """The Controller did not prove the join-material lifecycle completed."""


@dataclass(frozen=True)
class ControllerJoinResult:
    """Secret-free facts proved by one Controller operation."""

    operation: str
    principal: str
    destruction_proved: bool
    events: tuple[str, ...]


_PRINCIPAL_PREFIX = "tj-"
_SAFE_REALM = re.compile(
    r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")

_STAGE_PROGRAM = r"""
import json
import re
import sys

from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB

values = json.load(sys.stdin)
if set(values) != {"principal", "credential", "ownership_token"}:
    raise ValueError("unexpected join-material payload")
if not re.fullmatch(r"tj-[0-9a-f]{16}", values["principal"]):
    raise ValueError("unexpected join principal")
if not re.fullmatch(r"[0-9a-f]{64}", values["ownership_token"]):
    raise ValueError("unexpected ownership token")
marker = "telos-join-owner:" + values["ownership_token"]
lp = LoadParm()
lp.load_default()
samdb = SamDB(session_info=system_session(), lp=lp)
expression = "(sAMAccountName=" + values["principal"] + ")"
results = samdb.search(expression=expression, attrs=["description"])
if results:
    descriptions = [str(value) for value in results[0].get("description", [])]
    if descriptions != [marker]:
        raise RuntimeError("join principal ownership mismatch")
created = False
try:
    if not results:
        samdb.newuser(
            values["principal"],
            values["credential"],
            force_password_change_at_next_login_req=False,
            description=marker,
        )
        created = True
    samdb.add_remove_group_members(
        "Domain Admins", [values["principal"]], add_members_operation=True,
    )
    results = samdb.search(expression=expression, attrs=["description"])
    if len(results) != 1:
        raise RuntimeError("join principal was not stored")
    descriptions = [str(value) for value in results[0].get("description", [])]
    if descriptions != [marker]:
        raise RuntimeError("join principal ownership was not stored")
except BaseException:
    if created:
        try:
            samdb.deleteuser(values["principal"])
        except BaseException:
            pass
    raise
"""

_DESTROY_PROGRAM = r"""
import json
import re
import sys

from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB

values = json.load(sys.stdin)
if set(values) != {"principal", "ownership_token"}:
    raise ValueError("unexpected join-material payload")
if not re.fullmatch(r"tj-[0-9a-f]{16}", values["principal"]):
    raise ValueError("unexpected join principal")
if not re.fullmatch(r"[0-9a-f]{64}", values["ownership_token"]):
    raise ValueError("unexpected ownership token")
marker = "telos-join-owner:" + values["ownership_token"]
lp = LoadParm()
lp.load_default()
samdb = SamDB(session_info=system_session(), lp=lp)
expression = "(sAMAccountName=" + values["principal"] + ")"
results = samdb.search(
    expression=expression,
    attrs=["description"],
)
if not results:
    sys.exit(0)
descriptions = [str(value) for value in results[0].get("description", [])]
if descriptions != [marker]:
    raise RuntimeError("join principal ownership mismatch")
samdb.deleteuser(values["principal"])
results = samdb.search(expression=expression, attrs=["sAMAccountName"])
if results:
    raise RuntimeError("join principal remains after destruction")
"""


def _encoded_program(source: str) -> bytes:
    return base64.b64encode(source.encode("utf-8"))


class ControllerJoinSerial:
    """Stage and destroy one attempt-unique, ownership-bound join principal."""

    def __init__(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
        *,
        timeout: float = 90.0,
    ) -> None:
        self.console = SerialAutomation(
            reader, writer, None, timeout=timeout)
        self._principal = _PRINCIPAL_PREFIX + secrets.token_hex(8)
        self._ownership_token = secrets.token_hex(32)

    @staticmethod
    def _credential(value: str) -> str:
        if (not isinstance(value, str) or not value
                or "\n" in value or "\r" in value or "\x00" in value):
            raise ValueError("join credential is invalid")
        return value

    def _run(
        self, operation: str, payload: object, program: str,
    ) -> ControllerJoinResult:
        token = uuid.uuid4().hex.encode("ascii")
        ready = b"__TELOS_JOIN_READY_" + token + b"__"
        result = b"__TELOS_JOIN_RC_" + token + b"="
        sudo_prompt = b"__TELOS_JOIN_SUDO_" + token + b"__"
        sudo = (
            b"sudo -n"
            if self.console.password is None
            else b"sudo -k -p '" + sudo_prompt + b"'"
        )
        command = (
            b"trap 'stty echo' INT TERM EXIT; "
            b"stty -echo || exit 91; "
            b"printf '\\n" + ready + b"\\n'; "
            b"IFS= read -r __telos_payload; "
            b"stty echo; trap - INT TERM EXIT; "
            b"printf '%s' \"$__telos_payload\" | base64 -d | "
            + sudo + b" python3 -c \"import os;os.close(2);import base64;"
            b"exec(base64.b64decode('"
            + _encoded_program(program) + b"'))\"; "
            b"__telos_rc=$?; unset __telos_payload; "
            b"printf '\\n" + result + b"%s\\n' \"$__telos_rc\""
        )
        try:
            self.console._send(
                b"", operation + "-shell-prompt-requested")
            self.console._wait(
                rb"(?:^|\n)[^\n]*\$\s*$", "controller-shell-ready")
            self.console._send(command, operation + "-command-sent")
            self.console._wait(
                rb"(?:^|\n)" + re.escape(ready) + rb"\s*(?:\n|$)",
                operation + "-secret-input-ready")
            wire = base64.b64encode(json.dumps(
                payload, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8"))
            self.console._send(wire, operation + "-secret-input-sent")
            if self.console.password is not None:
                self.console._wait(
                    rb"(?:^|\n)" + re.escape(sudo_prompt) + rb"\s*$",
                    operation + "-sudo-password-prompt",
                )
                self.console._send(
                    self.console.password,
                    operation + "-sudo-password-sent",
                )
            match = self.console._wait(
                rb"(?:^|\n)" + re.escape(result)
                + rb"([0-9]+)\s*(?:\n|$)",
                operation + "-return-code-observed")
        except SerialAutomationError as error:
            raise ControllerJoinMaterialError(
                f"Controller join {operation} protocol failed") from None
        returncode = int(match.group(1))
        if returncode:
            raise ControllerJoinMaterialError(
                f"Controller join {operation} returned {returncode}")
        return ControllerJoinResult(
            operation=operation,
            principal=self._principal,
            destruction_proved=operation == "destroy",
            events=tuple(self.console.events),
        )

    def stage(self, credential: str) -> ControllerJoinResult:
        """Create or reconcile this attempt's principal without argv secrets."""
        checked = self._credential(credential)
        return self._run(
            "stage",
            {
                "principal": self._principal,
                "credential": checked,
                "ownership_token": self._ownership_token,
            },
            _STAGE_PROGRAM,
        )

    def destroy(self) -> ControllerJoinResult:
        """Delete only this attempt's token-matching principal."""
        return self._run("destroy", {
            "principal": self._principal,
            "ownership_token": self._ownership_token,
        }, _DESTROY_PROGRAM)


_T = TypeVar("_T")


class OneUseDomainJoinMaterial:
    """Own one generated join credential through use and proven destruction."""

    def __init__(
        self,
        realm: str,
        *,
        stage: Callable[[str], ControllerJoinResult],
        destroy: Callable[[], ControllerJoinResult],
    ) -> None:
        if not isinstance(realm, str) or not _SAFE_REALM.fullmatch(realm):
            raise ValueError("domain realm is invalid")
        self.realm = realm.upper()
        self._stage = stage
        self._destroy = destroy
        self._credential_value: str | None = None
        self._principal: str | None = None
        self._consumed = False
        self._destruction_pending = False

    def __repr__(self) -> str:
        state = (
            "cleanup-pending" if self._destruction_pending
            else "destroyed" if self._consumed
            else "unused"
        )
        return f"OneUseDomainJoinMaterial(realm={self.realm!r}, state={state})"

    @staticmethod
    def _generate() -> str:
        return "Synthetic-Join-" + secrets.token_urlsafe(24) + "-47!"

    def use(
        self, consumer: Callable[[Mapping[str, str]], _T],
    ) -> tuple[_T, ControllerJoinResult]:
        """Invoke one consumer, then require Controller-side destruction proof."""
        if self._consumed or self._credential_value is not None:
            raise ControllerJoinMaterialError(
                "domain join material is one-use")
        self._credential_value = self._generate()
        try:
            primary: BaseException | None = None
            value: _T | None = None
            try:
                # The destroy callback is ownership-bound. Mark cleanup pending
                # before staging so a lost stage acknowledgement is reconciled
                # by a safe, idempotent destruction attempt.
                self._destruction_pending = True
                staged = self._stage(self._credential_value)
                if (
                    staged.operation != "stage"
                    or not staged.principal.startswith(_PRINCIPAL_PREFIX)
                    or staged.destruction_proved
                ):
                    raise ControllerJoinMaterialError(
                        "Controller did not prove join-principal ownership")
                self._principal = staged.principal
                material = MappingProxyType({
                    "realm": self.realm,
                    "principal": staged.principal,
                    "credential": self._credential_value,
                    "operator": f"operator@{self.realm}",
                })
                value = consumer(material)
            except BaseException as error:
                primary = error
            proof: ControllerJoinResult | None = None
            cleanup: BaseException | None = None
            if self._destruction_pending:
                try:
                    proof = self._destroy()
                    if (
                        not proof.destruction_proved
                        or (
                            self._principal is not None
                            and proof.principal != self._principal
                        )
                    ):
                        raise ControllerJoinMaterialError(
                            "Controller did not prove join-principal destruction")
                    self._destruction_pending = False
                    self._principal = None
                except BaseException as error:
                    cleanup = error
            if primary is not None or cleanup is not None:
                details = []
                if primary is not None:
                    details.append(f"stage/consumer: {type(primary).__name__}")
                if cleanup is not None:
                    details.append(f"destruction: {type(cleanup).__name__}")
                raise ControllerJoinMaterialError(
                    "domain join material lifecycle failed; "
                    + "; ".join(details)) from None
            assert proof is not None
            return value, proof  # type: ignore[return-value]
        finally:
            self._credential_value = None
            self._consumed = True

    def retry_destruction(self) -> ControllerJoinResult:
        """Retry unresolved Controller-side cleanup until absence is proved."""
        if not self._destruction_pending:
            raise ControllerJoinMaterialError(
                "domain join destruction is not pending")
        proof = self._destroy()
        if (
            not proof.destruction_proved
            or (
                self._principal is not None
                and proof.principal != self._principal
            )
        ):
            raise ControllerJoinMaterialError(
                "Controller did not prove join-principal destruction")
        self._destruction_pending = False
        self._principal = None
        return proof
