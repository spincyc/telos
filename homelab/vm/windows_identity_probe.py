#!/usr/bin/env python3
"""Bounded, private screen observation for a prepared Windows identity guest."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import time
from typing import Callable

from .signal_cleanup import SignalGuard
from .windows_gui import read_ppm, useful_frame
from .windows_identity_run import NativeProcessBoundary


class WindowsIdentityProbeError(RuntimeError):
    """The bounded observation did not end with complete teardown."""


@dataclass(frozen=True)
class ProbeReceipt:
    """Secret-free facts about a completed observation."""

    screenshots: tuple[Path, ...]
    useful_screenshots: int
    teardown_complete: bool


def probe_screen(
    boundary: NativeProcessBoundary,
    *,
    duration: float = 30.0,
    interval: float = 5.0,
    clock: Callable[[], float] = time.monotonic,
    pause: Callable[[float], None] = time.sleep,
) -> ProbeReceipt:
    """Capture bounded private QMP frames and unconditionally tear down.

    The Controller is deliberately not started: a screen-only probe needs the
    isolated switch/gateway for the Windows NIC, but no directory services.
    Cleanup does not depend on a start method returning successfully because a
    start method can fail after acquiring a child or disposable resource.
    """
    if duration <= 0 or interval <= 0:
        raise ValueError("probe duration and interval must be positive")

    previous_umask = os.umask(0o077)
    screenshots: list[Path] = []
    useful = 0
    primary: BaseException | None = None
    cleanup_errors: list[str] = []
    try:
        with SignalGuard():
            boundary.start_switch()
            boundary.start_windows()
            boundary.authenticate_qmp()
            if boundary.qmp is None:
                raise WindowsIdentityProbeError(
                    "QMP authentication returned without a client")
            deadline = clock() + duration
            sequence = 0
            while clock() < deadline:
                sequence += 1
                frame = boundary.runtime / f"probe-{sequence:04d}.ppm"
                boundary.qmp.screenshot(frame)
                frame.chmod(0o600)
                screenshots.append(frame)
                if useful_frame(read_ppm(frame)):
                    useful += 1
                remaining = deadline - clock()
                if remaining > 0:
                    pause(min(interval, remaining))
    except BaseException as error:
        primary = error
    finally:
        for label, cleanup in (
            ("windows", boundary.stop_windows),
            ("controller", boundary.stop_controller),
            ("switch", boundary.stop_switch),
        ):
            try:
                cleanup()
            except BaseException as error:
                cleanup_errors.append(f"{label}: {type(error).__name__}")
        os.umask(previous_umask)

    if primary is not None or cleanup_errors:
        details = []
        if primary is not None:
            details.append(f"probe: {type(primary).__name__}")
        details.extend(f"teardown {item}" for item in cleanup_errors)
        raise WindowsIdentityProbeError(
            "Windows identity screen probe failed; " + "; ".join(details)
        ) from primary
    if not screenshots or useful == 0:
        raise WindowsIdentityProbeError(
            "Windows identity screen probe captured no useful frame")
    return ProbeReceipt(tuple(screenshots), useful, True)
