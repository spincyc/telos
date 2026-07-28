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

    def establish_disposable_controller_session(self) -> None:
        """Start systemd and authenticate one attempt-local Controller shell."""
        if self.password is None:
            raise SerialAutomationError(
                "Controller session credential is unavailable")
        marker = f"__TELOS_CONTROLLER_INIT_{self.token}__".encode()
        self._wait(rb"(?:^|\n)[^\n]*#\s*$", "disposable-init-shell")
        self._send(
            b"/usr/bin/mount -o remount,rw / && "
            b"/usr/bin/findmnt -no OPTIONS / | /usr/bin/grep -qw rw && "
            b"/usr/bin/printf '\\n" + marker + b"\\n'",
            "controller-root-remount-command-sent",
        )
        self._wait(
            rb"(?:^|\n)" + re.escape(marker) + rb"\s*(?:\n|$)",
            "controller-root-remount-confirmed",
        )
        self._wait(rb"(?:^|\n)[^\n]*#\s*$", "controller-init-shell-ready")
        self._send(
            b"/usr/bin/passwd local-rescue",
            "controller-passwd-command-sent",
        )
        self._wait(rb"New password:\s*$", "controller-new-password-prompt")
        self._send(self.password, "controller-new-password-sent")
        self._wait(
            rb"Retype new password:\s*$",
            "controller-password-confirm-prompt",
        )
        self._send(self.password, "controller-password-confirm-sent")
        self._wait(
            rb"(?:^|\n)passwd: password updated successfully\s*(?:\n|$)",
            "controller-password-updated",
        )
        self._wait(
            rb"(?:^|\n)[^\n]*#\s*$", "controller-post-passwd-init-shell")
        self._send(
            b"exec /usr/lib/systemd/systemd",
            "controller-systemd-exec-sent",
        )
        self._wait(
            rb"(?:^|\n)bootstrap-dc login:\s*$",
            "controller-login-prompt",
        )
        self._send(b"local-rescue", "controller-username-sent")
        self._wait(
            rb"(?:^|\n)Password:\s*$",
            "controller-login-password-prompt",
        )
        self._send(self.password, "controller-login-password-sent")
        self._wait(
            rb"(?:^|\n)[^\n]*local-rescue[^\n]*\$\s*$",
            "controller-shell-ready",
        )
        services = f"__TELOS_CONTROLLER_SERVICES_{self.token}=".encode()
        self._send(
            b"__telos_rc=1; "
            b"for __telos_try in $(seq 1 90); do "
            b"if /usr/bin/systemctl is-active --quiet "
            b"samba.service; then "
            b"__telos_rc=0; break; fi; /usr/bin/sleep 1; done; "
            b"printf '\\n" + services + b"%s\\n' \"$__telos_rc\"",
            "controller-service-readiness-command-sent",
        )
        match = self._wait(
            rb"(?:^|\n)" + re.escape(services) + rb"([0-9]+)\s*(?:\n|$)",
            "controller-service-readiness-observed",
        )
        if int(match.group(1)) != 0:
            raise SerialAutomationError(
                "Controller services did not become ready")

    def release_password(self) -> None:
        """Drop the retained attempt-local Controller credential."""
        self.password = None

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
