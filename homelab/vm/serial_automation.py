#!/usr/bin/env python3
"""Bounded serial-console verification without recording credentials."""

from __future__ import annotations

import re
import selectors
import time
import uuid
from dataclasses import dataclass
from typing import BinaryIO, Callable

PASS_LINE = (
    "RESULT PASS: safe to proceed to the separately authorized attachment step"
)
ANSI = re.compile(
    rb"(?:\x1b\[[0-?]*[ -/]*[@-~]|"
    rb"\x1b\](?:[^\x07\x1b]|\x1b(?!\\))*(?:\x07|\x1b\\))"
)


class SerialAutomationError(RuntimeError):
    """The console did not prove the expected result within its bounds."""


@dataclass(frozen=True)
class SerialResult:
    helper_passed: bool
    helper_returncode: int
    powered_off: bool
    events: tuple[str, ...]


def normalized(data: bytes) -> str:
    """Remove terminal decoration while preserving line boundaries."""
    data = ANSI.sub(b"", data).replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data.decode("utf-8", "replace")


class SerialAutomation:
    """Drive one disposable controller login and its installed preflight."""

    def __init__(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
        password: bytes | None,
        *,
        timeout: float = 90.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if password is not None and (
                not password or b"\n" in password or b"\r" in password):
            raise ValueError("simulation password must be one non-empty line")
        self.reader = reader
        self.writer = writer
        self.password = password
        self.timeout = timeout
        self.clock = clock
        self.buffer = b""
        self.events: list[str] = []
        self.token = uuid.uuid4().hex

    def _send(self, value: bytes, event: str) -> None:
        self.writer.write(value + b"\n")
        self.writer.flush()
        self.events.append(event)

    def _wait(self, pattern: bytes, label: str) -> re.Match[bytes]:
        deadline = self.clock() + self.timeout
        matcher = re.compile(pattern, re.MULTILINE)
        selector = selectors.DefaultSelector()
        selector.register(self.reader, selectors.EVENT_READ)
        try:
            while self.clock() < deadline:
                clean = ANSI.sub(b"", self.buffer)
                match = matcher.search(clean)
                if match:
                    self.buffer = clean[match.end():]
                    self.events.append(label)
                    return match
                remaining = max(0.0, deadline - self.clock())
                if not selector.select(min(0.25, remaining)):
                    continue
                read = getattr(self.reader, "read1", self.reader.read)
                chunk = read(4096)
                if not chunk:
                    raise SerialAutomationError(
                        f"serial closed while waiting for {label}")
                self.buffer = (self.buffer + chunk)[-131072:]
        finally:
            selector.close()
        raise SerialAutomationError(f"timed out waiting for {label}")

    def run(self) -> SerialResult:
        if self.password is None:
            self._wait(
                rb"(?:^|\n)[^\n]*local-rescue[^\n]*\$\s+$",
                "simulation-autologin-shell",
            )
        else:
            self._wait(rb"(?:^|\n)bootstrap-dc login:\s*$", "login-prompt")
            self._send(b"local-rescue", "username-sent")
            self._wait(rb"(?:^|\n)Password:\s*$", "login-password-prompt")
            self._send(self.password, "login-password-sent")
            self._wait(rb"(?:^|\n)[^\n]*\$\s+$", "shell-prompt")

        prompt = f"__TELOS_SUDO_{self.token}__".encode()
        begin = f"__TELOS_BEGIN_{self.token}__".encode()
        result = f"__TELOS_RC_{self.token}=".encode()
        sudo = b"sudo -n" if self.password is None else (
            b"sudo -S -p '" + prompt + b"'")
        command = (
            b"printf '\\n" + begin + b"\\n'; "
            + sudo + b" /usr/local/sbin/homelab-network-attach-preflight; "
            + b"rc=$?; printf '\\n" + result + b"%s\\n' \"$rc\""
        )
        self._send(command, "preflight-command-sent")
        self._wait(
            rb"(?:^|\n)" + re.escape(begin) + rb"\s*(?:\n|$)",
            "preflight-begin-observed",
        )
        if self.password is not None:
            self._wait(re.escape(prompt), "sudo-password-prompt")
            self._send(self.password, "sudo-password-sent")
        self._wait(
            rb"(?:^|\n)" + re.escape(PASS_LINE.encode()) + rb"\s*(?:\n|$)",
            "exact-pass-observed",
        )
        match = self._wait(
            rb"(?:^|\n)" + re.escape(result) + rb"([0-9]+)\s*(?:\n|$)",
            "return-code-observed",
        )
        returncode = int(match.group(1))
        if returncode != 0:
            raise SerialAutomationError(
                f"preflight printed PASS but returned {returncode}")

        self._wait(rb"(?:^|\n)[^\n]*\$\s+$", "post-check-shell-prompt")
        poweroff = f"__TELOS_POWEROFF_{self.token}__".encode()
        self._send(
            b"printf '\\n" + poweroff
            + b"\\n'; sudo -n /usr/bin/systemctl poweroff",
            "poweroff-command-sent",
        )
        self._wait(
            rb"(?:^|\n)" + re.escape(poweroff) + rb"\s*(?:\n|$)",
            "poweroff-begin-observed",
        )
        self._wait(
            rb"(?:Reached target System Power Off|reboot: Power down)",
            "poweroff-observed",
        )
        return SerialResult(True, returncode, True, tuple(self.events))
