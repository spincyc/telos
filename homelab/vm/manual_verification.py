#!/usr/bin/env python3
"""Fail-closed serial-console evidence for a controller simulation."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

try:
    from .secure_artifacts import atomic_write_text
except ImportError:
    from secure_artifacts import atomic_write_text

PASS_LINE = "RESULT PASS: safe to proceed to the separately authorized attachment step"
HELPER = "/usr/local/sbin/homelab-network-attach-preflight"
_ANSI = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


class SerialVerificationGate:
    """Recognize the installed helper's exact success line on serial output."""

    def __init__(self) -> None:
        self._pending = b""
        self.passed = False

    def feed(self, chunk: bytes) -> None:
        cleaned = _ANSI.sub(b"", self._pending + chunk).replace(b"\r", b"\n")
        lines = cleaned.split(b"\n")
        self._pending = lines.pop()
        for line in lines:
            if line.decode("utf-8", "replace").strip() == PASS_LINE:
                self.passed = True

    def require_pass(self) -> None:
        if not self.passed:
            raise RuntimeError(
                "controller verification was not observed on its serial console; "
                f"run: sudo {HELPER}")

    def write_receipt(self, path: Path) -> None:
        self.require_pass()
        document = {
            "schema": 1,
            "kind": "controller-simulation-manual-verification",
            "helper": HELPER,
            "observed_line": PASS_LINE,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "transport": "qemu-serial-console",
        }
        atomic_write_text(
            path, json.dumps(document, indent=2, sort_keys=True) + "\n")
