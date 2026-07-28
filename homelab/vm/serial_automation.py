#!/usr/bin/env python3
"""Bounded serial-console verification without recording credentials."""

from __future__ import annotations

import re
import selectors
import shlex
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

    def converge_disposable_controller(
        self, guest_command: str, *, timeout: float = 900.0,
    ) -> None:
        """Run the fixed private convergence payload and prove its release."""
        if (
            self.password is None
            or not isinstance(guest_command, str)
            or not guest_command
            or "\n" in guest_command
        ):
            raise SerialAutomationError(
                "Controller convergence command is invalid")
        original_timeout = self.timeout
        self.timeout = timeout
        token = uuid.uuid4().hex.encode("ascii")
        sudo_prompt = b"__TELOS_CONVERGE_SUDO_" + token + b"__"
        begin = b"__TELOS_CONVERGENCE_BEGIN_" + token + b"__"
        result = b"__TELOS_CONVERGENCE_RC_" + token + b"="
        release_prompt = b"__TELOS_RELEASE_SUDO_" + token + b"__"
        released = b"__TELOS_CONVERGENCE_RELEASED_" + token + b"="
        try:
            self._send(b"", "controller-convergence-shell-requested")
            self._wait(
                rb"(?:^|\n)[^\n]*\$\s*$",
                "controller-convergence-shell-ready",
            )
            self._send(
                b"printf '\\n" + begin + b"\\n'; "
                b"sudo -k -S -p '" + sudo_prompt
                + b"' /usr/bin/bash -c "
                + shlex.quote(guest_command).encode("ascii")
                + b" ; __telos_rc=$?; printf '\\n" + result
                + b"%s\\n' \"$__telos_rc\"",
                "controller-convergence-command-sent",
            )
            self._wait(
                rb"(?:^|\n)" + re.escape(begin) + rb"\s*(?:\n|$)",
                "controller-convergence-begin-observed",
            )
            self._wait(
                rb"(?:^|\n)" + re.escape(sudo_prompt) + rb"\s*$",
                "controller-convergence-sudo-prompt",
            )
            self._send(
                self.password, "controller-convergence-sudo-password-sent")
            passed = False
            last_stage = "begin"
            while True:
                outcome = self._wait(
                    rb"(?:^|\n)(?:"
                    rb"TELOS FACTORY STEP ([a-z0-9-]+)|"
                    rb"(TELOS FACTORY CONTROLLER PASS)|"
                    + re.escape(result) + rb"([0-9]+))\s*\n",
                    "controller-convergence-outcome-observed",
                )
                if outcome.group(1) is not None:
                    last_stage = outcome.group(1).decode("ascii")
                    self.events.append(
                        "controller-convergence-stage-" + last_stage)
                    continue
                if outcome.group(2) is not None:
                    passed = True
                    continue
                returncode = int(outcome.group(3))
                if returncode != 0:
                    raise SerialAutomationError(
                        "Controller convergence returned "
                        f"{returncode} after {last_stage}")
                if not passed:
                    raise SerialAutomationError(
                        "Controller convergence returned without PASS")
                break
            self._send(b"", "controller-convergence-prompt-requested")
            self._wait(
                rb"(?:^|\n)[^\n]*\$\s*$",
                "controller-convergence-post-shell-ready",
            )
            self._send(
                b"sudo -k -S -p '" + release_prompt
                + b"' /usr/bin/umount /run/telos-factory; "
                b"__telos_rc=$?; printf '\\n" + released
                + b"%s\\n' \"$__telos_rc\"",
                "controller-convergence-release-command-sent",
            )
            self._wait(
                rb"(?:^|\n)" + re.escape(release_prompt) + rb"\s*$",
                "controller-convergence-release-sudo-prompt",
            )
            self._send(
                self.password, "controller-convergence-release-password-sent")
            match = self._wait(
                rb"(?:^|\n)" + re.escape(released)
                + rb"([0-9]+)\s*(?:\n|$)",
                "controller-convergence-release-observed",
            )
            if int(match.group(1)) != 0:
                raise SerialAutomationError(
                    "Controller convergence media release failed")
            self._wait_controller_ad()
        finally:
            self.timeout = original_timeout

    def install_offline_controller_dependencies(
        self, *, timeout: float = 1200.0,
    ) -> None:
        """Verify and install the attached signed seed, then release it."""
        if self.password is None:
            raise SerialAutomationError(
                "Controller session credential is unavailable")
        original_timeout = self.timeout
        self.timeout = timeout
        token = uuid.uuid4().hex.encode("ascii")
        sudo_prompt = b"__TELOS_SEED_SUDO_" + token + b"__"
        verified = b"__TELOS_SEED_VERIFIED_" + token + b"__"
        installed = b"__TELOS_SEED_INSTALLED_" + token + b"__"
        packages = b"__TELOS_SEED_PACKAGES_" + token + b"__"
        imported = b"__TELOS_SEED_IMPORT_" + token + b"__"
        result = b"__TELOS_SEED_RC_" + token + b"="
        released = b"__TELOS_SEED_RELEASED_" + token + b"="
        command = (
            b"set +e; __telos_rc=0; __telos_mounted=0; "
            b"install -d -m 0700 /run/telos-seed; "
            b"mount -o ro -L TELOS_SEED /run/telos-seed; "
            b"__telos_step=$?; "
            b"if [ \"$__telos_step\" -eq 0 ]; then __telos_mounted=1; "
            b"else __telos_rc=$__telos_step; fi; "
            b"if [ \"$__telos_rc\" -eq 0 ]; then "
            b"/run/telos-seed/verify-seed /run/telos-seed; "
            b"__telos_step=$?; "
            b"if [ \"$__telos_step\" -eq 0 ]; then printf '\\n"
            + verified + b"\\n'; else __telos_rc=$__telos_step; fi; fi; "
            b"if [ \"$__telos_rc\" -eq 0 ]; then "
            b"/run/telos-seed/install-controller-deps /run/telos-seed; "
            b"__telos_step=$?; "
            b"if [ \"$__telos_step\" -eq 0 ]; then printf '\\n"
            + installed + b"\\n'; else __telos_rc=$__telos_step; fi; fi; "
            b"if [ \"$__telos_rc\" -eq 0 ]; then "
            b"pacman -Qq python-dnspython samba python >/dev/null; "
            b"__telos_step=$?; "
            b"if [ \"$__telos_step\" -eq 0 ]; then printf '\\n"
            + packages + b"\\n'; else __telos_rc=$__telos_step; fi; fi; "
            b"if [ \"$__telos_rc\" -eq 0 ]; then "
            b"python3 -c 'import dns, dns.resolver'; "
            b"__telos_step=$?; "
            b"if [ \"$__telos_step\" -eq 0 ]; then printf '\\n"
            + imported + b"\\n'; else __telos_rc=$__telos_step; fi; fi; "
            b"__telos_release_rc=0; "
            b"if [ \"$__telos_mounted\" -eq 1 ]; then "
            b"umount /run/telos-seed || __telos_release_rc=$?; fi; "
            b"printf '\\n" + released + b"%s\\n' \"$__telos_release_rc\"; "
            b"if [ \"$__telos_rc\" -eq 0 ] && "
            b"[ \"$__telos_release_rc\" -ne 0 ]; then "
            b"__telos_rc=$__telos_release_rc; fi; "
            b"exit \"$__telos_rc\""
        )
        try:
            self._send(b"", "controller-seed-shell-requested")
            self._wait(
                rb"(?:^|\n)[^\n]*\$\s*$",
                "controller-seed-shell-ready",
            )
            self._send(
                b"sudo -k -S -p '" + sudo_prompt
                + b"' /usr/bin/bash -c "
                + shlex.quote(command.decode("ascii")).encode("ascii")
                + b" ; __telos_rc=$?; printf '\\n" + result
                + b"%s\\n' \"$__telos_rc\"",
                "controller-seed-install-command-sent",
            )
            self._wait(
                re.escape(sudo_prompt) + rb"\s*$",
                "controller-seed-sudo-prompt",
            )
            self._send(
                self.password, "controller-seed-sudo-password-sent")
            seen: set[str] = set()
            returncode: int | None = None
            release_code: int | None = None
            outcome = re.compile(
                rb"(?:^|\n)(?:"
                + re.escape(verified) + rb"()|"
                + re.escape(installed) + rb"()|"
                + re.escape(packages) + rb"()|"
                + re.escape(imported) + rb"()|"
                + re.escape(released) + rb"([0-9]+)|"
                + re.escape(result) + rb"([0-9]+))\s*\n"
            )
            while returncode is None:
                match = self._wait(
                    outcome.pattern, "controller-seed-outcome-observed")
                if match.group(1) is not None:
                    seen.add("verified")
                    self.events.append("controller-seed-receipt-verified")
                elif match.group(2) is not None:
                    seen.add("installed")
                    self.events.append(
                        "controller-seed-dependencies-installed")
                elif match.group(3) is not None:
                    seen.add("packages")
                    self.events.append("controller-seed-packages-proven")
                elif match.group(4) is not None:
                    seen.add("imported")
                    self.events.append("controller-seed-import-proven")
                elif match.group(5) is not None:
                    release_code = int(match.group(5))
                    self.events.append("controller-seed-release-observed")
                else:
                    returncode = int(match.group(6))
                    self.events.append(
                        "controller-seed-install-result-observed")
            if release_code is None:
                raise SerialAutomationError(
                    "Controller seed media release was not observed")
            if release_code != 0:
                raise SerialAutomationError(
                    "Controller seed media release failed")
            if returncode != 0:
                raise SerialAutomationError(
                    f"Controller seed installation returned {returncode}")
            required = {"verified", "installed", "packages", "imported"}
            if seen != required:
                raise SerialAutomationError(
                    "Controller seed success proof is incomplete")
            self._send(b"", "controller-seed-post-shell-requested")
            self._wait(
                rb"(?:^|\n)[^\n]*\$\s+$",
                "controller-seed-post-shell-ready",
            )
        finally:
            self.timeout = original_timeout

    def _wait_controller_ad(self) -> None:
        """Require the exact AD service and database on the disposable disk."""
        services = f"__TELOS_CONTROLLER_SERVICES_{self.token}=".encode()
        self._send(
            b"__telos_rc=3; "
            b"for __telos_try in $(seq 1 90); do "
            b"if /usr/bin/systemctl is-active --quiet samba.service; then "
            b"__telos_rc=0; break; fi; /usr/bin/sleep 1; done; "
            b"if [ \"$__telos_rc\" -ne 0 ]; then "
            b"if /usr/bin/systemctl is-failed --quiet samba.service; then "
            b"__telos_rc=2; "
            b"elif ! /usr/bin/systemctl list-unit-files samba.service "
            b"--no-legend 2>/dev/null | /usr/bin/grep -q '^samba.service'; "
            b"then __telos_rc=4; fi; "
            b"if [ -f /var/lib/samba/private/sam.ldb ]; then "
            b"__telos_rc=$((__telos_rc + 10)); fi; fi; "
            b"printf '\\n" + services + b"%s\\n' \"$__telos_rc\"",
            "controller-service-readiness-command-sent",
        )
        match = self._wait(
            rb"(?:^|\n)" + re.escape(services) + rb"([0-9]+)\s*(?:\n|$)",
            "controller-service-readiness-observed",
        )
        if int(match.group(1)) != 0:
            code = int(match.group(1))
            state = {
                2: "failed", 3: "inactive", 4: "missing",
                12: "failed", 13: "inactive", 14: "missing",
            }.get(code, "unknown")
            database = "present" if code >= 10 else "absent"
            raise SerialAutomationError(
                "Controller AD service did not become ready "
                f"(state={state}, database={database})")

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
