"""Strict, bounded host protocol for a Windows sign-in diagnostic watcher.

The result is diagnostic context only.  Callers must never treat any result
code, including ``INTERACTIVE_LOGON_SUCCESS``, as identity acceptance.
"""

from __future__ import annotations

from enum import Enum
import json
from pathlib import Path
import re
import socket
import time
from typing import Callable, Mapping


SCHEMA_VERSION = 1
_NONCE = re.compile(r"[0-9a-f]{32}")
_UPN_LOCAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_UPN_REALM = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,188}[A-Za-z0-9])?")


class PostSubmitDiagnosticError(RuntimeError):
    """The diagnostic transport or protocol failed closed."""


class PostSubmitDiagnosticCode(Enum):
    """The complete, non-authoritative result vocabulary."""

    INTERACTIVE_LOGON_SUCCESS = "interactive-logon-success"
    BAD_CREDENTIAL = "bad-credential"
    ACCOUNT_DISABLED = "account-disabled"
    ACCOUNT_LOCKED = "account-locked"
    ACCOUNT_EXPIRED = "account-expired"
    PASSWORD_EXPIRED = "password-expired"
    LOGON_RESTRICTION = "logon-restriction"
    OTHER_REJECTION = "other-rejection"
    AUDIT_DISABLED = "audit-disabled"
    EVENT_LOG_RESET = "event-log-reset"
    EVENT_GAP = "event-gap"
    NO_CORRELATED_EVENT = "no-correlated-event"
    AMBIGUOUS = "ambiguous"
    WATCHER_ERROR = "watcher-error"


class PostSubmitDiagnosticCollection(Enum):
    """Fixed host collection failures, distinct from guest auth outcomes."""

    SUBMITTED_RECEIPT_UNAVAILABLE = "submitted-receipt-unavailable"
    RESULT_RECEIPT_UNAVAILABLE = "result-receipt-unavailable"
    CLEANUP_RECEIPT_UNAVAILABLE = "cleanup-receipt-unavailable"


class PostSubmitDiagnosticSession:
    """Own one exclusive COM1 socket from arming through the final result."""

    def __init__(
        self,
        connection: socket.socket,
        nonce: str,
        principal: str,
        *,
        timeout: float = 120.0,
        maximum_line: int = 1024,
        clock: Callable[[], float] = time.monotonic,
        pause: Callable[[float], None] = time.sleep,
        quiescence_delay: float = 0.25,
    ) -> None:
        if _NONCE.fullmatch(nonce) is None:
            raise PostSubmitDiagnosticError("diagnostic nonce is invalid")
        parts = principal.split("@")
        if (
            len(parts) != 2
            or _UPN_LOCAL.fullmatch(parts[0]) is None
            or _UPN_REALM.fullmatch(parts[1]) is None
            or "." not in parts[1]
        ):
            raise PostSubmitDiagnosticError("diagnostic principal is invalid")
        if not 0 < timeout <= 300:
            raise PostSubmitDiagnosticError("diagnostic timeout is invalid")
        if not 128 <= maximum_line <= 4096:
            raise PostSubmitDiagnosticError(
                "diagnostic serial line bound is invalid")
        self.connection = connection
        self.nonce = nonce
        self.principal = principal
        self.maximum_line = maximum_line
        self._clock = clock
        self._pause = pause
        self._quiescence_delay = quiescence_delay
        self._deadline = clock() + timeout
        self._state = "connected"
        self.closed = False

    @classmethod
    def connect(
        cls,
        socket_path: Path,
        nonce: str,
        principal: str,
        timeout: float = 120.0,
    ) -> "PostSubmitDiagnosticSession":
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            session = cls(
                connection, nonce, principal, timeout=timeout)
            session._set_operation_timeout()
            connection.connect(str(Path(socket_path)))
            return session
        except PostSubmitDiagnosticError:
            connection.close()
            raise
        except BaseException:
            connection.close()
            raise PostSubmitDiagnosticError(
                "diagnostic serial connection failed") from None

    def _set_operation_timeout(self) -> None:
        remaining = self._deadline - self._clock()
        if remaining <= 0:
            raise PostSubmitDiagnosticError(
                "diagnostic serial deadline expired")
        self.connection.settimeout(remaining)

    def _send(self, command: str, *, include_principal: bool = False) -> None:
        if self.closed:
            raise PostSubmitDiagnosticError("diagnostic serial is closed")
        record = {
            "schema_version": SCHEMA_VERSION,
            "command": command,
            "nonce": self.nonce,
        }
        if include_principal:
            record["principal"] = self.principal
        encoded = (
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        if len(encoded) > self.maximum_line:
            raise PostSubmitDiagnosticError(
                "diagnostic serial request exceeds bound")
        self._set_operation_timeout()
        try:
            self.connection.sendall(encoded)
        except (OSError, TimeoutError):
            raise PostSubmitDiagnosticError(
                "diagnostic serial request failed") from None

    def _read(self) -> Mapping[str, object]:
        if self.closed:
            raise PostSubmitDiagnosticError("diagnostic serial is closed")
        data = bytearray()
        try:
            while len(data) <= self.maximum_line:
                self._set_operation_timeout()
                octet = self.connection.recv(1)
                if not octet:
                    raise PostSubmitDiagnosticError(
                        "diagnostic serial closed before record")
                if octet == b"\n":
                    break
                if octet == b"\r":
                    raise PostSubmitDiagnosticError(
                        "diagnostic serial record contains CR")
                data.extend(octet)
            else:
                raise PostSubmitDiagnosticError(
                    "diagnostic serial record exceeds bound")
        except PostSubmitDiagnosticError:
            raise
        except (OSError, TimeoutError):
            raise PostSubmitDiagnosticError(
                "diagnostic serial receive failed") from None
        try:
            record = json.loads(data.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise PostSubmitDiagnosticError(
                "diagnostic serial record is not canonical JSON") from None
        if not isinstance(record, dict):
            raise PostSubmitDiagnosticError(
                "diagnostic serial record is not an object")
        canonical = json.dumps(
            record, sort_keys=True, separators=(",", ":")).encode("ascii")
        if canonical != bytes(data):
            raise PostSubmitDiagnosticError(
                "diagnostic serial record is not canonical JSON")
        return record

    def arm(self) -> None:
        if self._state != "connected":
            raise PostSubmitDiagnosticError(
                "diagnostic session cannot be armed")
        # The startup watcher predates this host connection. A wait=off QEMU
        # socket chardev cannot replay guest output produced during that gap,
        # so the nonce-bound host command initiates the handshake.
        self._send("arm", include_principal=True)
        record = self._read()
        expected = {
            "schema_version": SCHEMA_VERSION,
            "event": "armed",
            "nonce": self.nonce,
        }
        if record != expected:
            raise PostSubmitDiagnosticError(
                "diagnostic armed receipt is invalid")
        self._state = "armed"

    def _accept_result_record(
        self, record: Mapping[str, object],
    ) -> PostSubmitDiagnosticCode:
        if set(record) != {
            "schema_version", "event", "nonce", "code", "cleanup_complete",
        }:
            raise PostSubmitDiagnosticError(
                "diagnostic result fields are invalid")
        if (
            type(record["schema_version"]) is not int
            or record["schema_version"] != SCHEMA_VERSION
            or record["event"] != "result"
            or record["nonce"] != self.nonce
            or type(record["code"]) is not str
            or record["cleanup_complete"] is not True
        ):
            raise PostSubmitDiagnosticError(
                "diagnostic result is invalid")
        try:
            code = PostSubmitDiagnosticCode(record["code"])
        except ValueError:
            raise PostSubmitDiagnosticError(
                "diagnostic result code is invalid") from None
        self._state = "finished"
        self._pause(self._quiescence_delay)
        return code

    def submitted(self) -> PostSubmitDiagnosticCode | None:
        if self._state != "armed":
            raise PostSubmitDiagnosticError(
                "diagnostic submission is out of order")
        self._send("submitted")
        record = self._read()
        expected = {
            "schema_version": SCHEMA_VERSION,
            "event": "submitted",
            "nonce": self.nonce,
        }
        if record == expected:
            self._state = "submitted"
            return None
        if record.get("event") == "result":
            return self._accept_result_record(record)
        else:
            raise PostSubmitDiagnosticError(
                "diagnostic submitted receipt is invalid")

    def result(self) -> PostSubmitDiagnosticCode:
        if self._state != "submitted":
            raise PostSubmitDiagnosticError(
                "diagnostic result is out of order")
        return self._accept_result_record(self._read())

    def cancel(self) -> None:
        if self._state not in {"armed", "submitted"}:
            raise PostSubmitDiagnosticError(
                "diagnostic cancellation is out of order")
        self._send("cancel")
        record = self._read()
        expected = {
            "schema_version": SCHEMA_VERSION,
            "event": "cancelled",
            "nonce": self.nonce,
            "cleanup_complete": True,
        }
        if record != expected:
            raise PostSubmitDiagnosticError(
                "diagnostic cancellation receipt is invalid")
        self._state = "finished"
        self._pause(self._quiescence_delay)

    def close(self) -> None:
        if not self.closed:
            self.connection.close()
            self.closed = True

    def __enter__(self) -> "PostSubmitDiagnosticSession":
        if self.closed:
            raise PostSubmitDiagnosticError("diagnostic serial is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        try:
            if self._state in {"armed", "submitted"}:
                self.cancel()
        finally:
            self.close()
