#!/usr/bin/env python3
"""Secret-free evidence capture for post-join Windows UI calibration."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import uuid
from dataclasses import dataclass

from .windows_gui import Image, QmpClient, useful_frame
from .windows_identity_reference import GuestProvenance


MAX_CALIBRATION_FRAME_BYTES = 16 * 1024 * 1024
CALIBRATION_SAMPLE_COUNT = 1
CALIBRATION_STATES = frozenset({"generic-prompt", "password-target"})
CALIBRATION_FRAME_NAME = "post-join-generic-prompt.ppm"
CALIBRATION_RECORD_NAME = "post-join-generic-prompt.json"


class WindowsPostJoinCalibrationError(RuntimeError):
    """A bounded, public-only calibration capture could not be retained."""


@dataclass(frozen=True)
class PostJoinCalibrationFrame:
    """One useful public frame held in memory until its state is proved."""

    content: bytes
    image: Image


def _parse_authenticated_ppm(content: bytes) -> Image:
    """Parse the bytes read through the inode-authenticated descriptor."""
    tokens: list[bytes] = []
    cursor = 0
    while len(tokens) < 4:
        while cursor < len(content) and content[cursor] in b" \t\r\n":
            cursor += 1
        if cursor < len(content) and content[cursor] == ord("#"):
            cursor = content.find(b"\n", cursor)
            if cursor < 0:
                break
            continue
        start = cursor
        while (
            cursor < len(content)
            and content[cursor] not in b" \t\r\n"
        ):
            cursor += 1
        tokens.append(content[start:cursor])
    if len(tokens) != 4 or tokens[0] != b"P6":
        raise WindowsPostJoinCalibrationError(
            "calibration frame is not binary PPM")
    try:
        width, height, maximum = map(int, tokens[1:4])
    except ValueError:
        malformed = True
    else:
        malformed = False
    if malformed:
        raise WindowsPostJoinCalibrationError(
            "calibration frame header is malformed") from None
    if width < 320 or height < 200 or maximum != 255:
        raise WindowsPostJoinCalibrationError(
            "calibration frame geometry is implausible")
    if cursor >= len(content) or content[cursor] not in b" \t\r\n":
        raise WindowsPostJoinCalibrationError(
            "calibration frame lacks its pixel separator")
    cursor += 2 if content[cursor:cursor + 2] == b"\r\n" else 1
    pixels = content[cursor:]
    if len(pixels) != width * height * 3:
        raise WindowsPostJoinCalibrationError(
            "calibration frame pixels are truncated")
    return Image(width, height, pixels)


def _exclusive_write(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    open_failed = False
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError:
        open_failed = True
    if open_failed:
        raise WindowsPostJoinCalibrationError(
            "calibration evidence destination is unavailable") from None
    write_failed = False
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError("short calibration evidence write")
            offset += written
        os.fsync(descriptor)
    except BaseException:
        write_failed = True
        try:
            path.unlink()
        except OSError:
            pass
    finally:
        os.close(descriptor)
    if write_failed:
        raise WindowsPostJoinCalibrationError(
            "calibration evidence write failed") from None


def sample_post_join_calibration(
    qmp: QmpClient,
    evidence_root: Path,
) -> PostJoinCalibrationFrame:
    """Capture one useful public frame without assigning it a UI state."""
    root = Path(evidence_root).absolute()
    if (
        root.is_symlink()
        or not root.is_dir()
        or stat.S_IMODE(root.stat().st_mode) != 0o700
    ):
        raise WindowsPostJoinCalibrationError(
            "calibration evidence root is not a private real directory")

    staging = root / f".post-join-sample-{uuid.uuid4().hex}.ppm"
    descriptor = os.open(
        staging,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    identity = os.fstat(descriptor)
    os.close(descriptor)
    unexpected_failure = False
    result: PostJoinCalibrationFrame | None = None
    try:
        for _sample in range(CALIBRATION_SAMPLE_COUNT):
            qmp.screenshot(staging)
            descriptor = os.open(
                staging, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                observed = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(observed.st_mode)
                    or (observed.st_dev, observed.st_ino)
                    != (identity.st_dev, identity.st_ino)
                ):
                    raise WindowsPostJoinCalibrationError(
                        "calibration staging identity changed")
                os.fchmod(descriptor, 0o600)
                content = os.read(
                    descriptor, MAX_CALIBRATION_FRAME_BYTES + 1)
                if len(content) > MAX_CALIBRATION_FRAME_BYTES:
                    raise WindowsPostJoinCalibrationError(
                        "calibration frame exceeds the public evidence cap")
                if os.read(descriptor, 1):
                    raise WindowsPostJoinCalibrationError(
                        "calibration frame exceeds the public evidence cap")
            finally:
                os.close(descriptor)

        image = _parse_authenticated_ppm(content)
        if not useful_frame(image):
            raise WindowsPostJoinCalibrationError(
                "calibration frame is not useful")
        result = PostJoinCalibrationFrame(content, image)
    except WindowsPostJoinCalibrationError:
        raise
    except BaseException:
        unexpected_failure = True
    finally:
        try:
            staging.unlink()
        except FileNotFoundError:
            pass
    if unexpected_failure or result is None:
        raise WindowsPostJoinCalibrationError(
            "post-join calibration capture failed") from None
    return result


def retain_post_join_calibration(
    frame: PostJoinCalibrationFrame,
    evidence_root: Path,
    guest: GuestProvenance,
    *,
    state: str,
    stability_samples: int = 1,
) -> tuple[Path, Path]:
    """Assign a proved stable public frame its forensic state atomically."""
    root = Path(evidence_root).absolute()
    if (
        root.is_symlink()
        or not root.is_dir()
        or stat.S_IMODE(root.stat().st_mode) != 0o700
    ):
        raise WindowsPostJoinCalibrationError(
            "calibration evidence root is not a private real directory")
    if state not in CALIBRATION_STATES:
        raise WindowsPostJoinCalibrationError(
            "calibration state is not allowlisted")
    if type(stability_samples) is not int or not 1 <= stability_samples <= 3:
        raise WindowsPostJoinCalibrationError(
            "calibration stability sample count is invalid")
    frame_name = f"post-join-{state}.ppm"
    record_name = f"post-join-{state}.json"
    frame_path = root / frame_name
    record_path = root / record_name
    if (
        frame_path.exists()
        or frame_path.is_symlink()
        or record_path.exists()
        or record_path.is_symlink()
    ):
        raise WindowsPostJoinCalibrationError(
            "calibration evidence already exists")
    content, image = frame.content, frame.image
    _exclusive_write(frame_path, content)
    try:
        record = {
            "schema": 1,
            "phase": (
                "post-join-reauthentication.calibration-required."
                f"{state}"
            ),
            "state": state,
            "purpose": "forensic-review-only",
            "reference_promotion_authorized": False,
            "secret_input_since_post_join_reboot": False,
            "frame": {
                "name": frame_name,
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "width": image.width,
                "height": image.height,
                "samples": CALIBRATION_SAMPLE_COUNT,
                "stability_samples": stability_samples,
            },
            "guest": {
                "release": guest.release,
                "language": guest.language,
                "architecture": guest.architecture,
                "installer_iso_sha256": guest.installer_iso_sha256,
                "source_disk_sha256": guest.source_disk_sha256,
            },
        }
        encoded = (
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        try:
            _exclusive_write(record_path, encoded)
        except BaseException:
            frame_path.unlink(missing_ok=True)
            raise
        directory = os.open(root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return frame_path, record_path
    except WindowsPostJoinCalibrationError:
        frame_path.unlink(missing_ok=True)
        record_path.unlink(missing_ok=True)
        raise
    except BaseException:
        frame_path.unlink(missing_ok=True)
        record_path.unlink(missing_ok=True)
    raise WindowsPostJoinCalibrationError(
        "post-join calibration capture failed") from None


def capture_post_join_calibration(
    qmp: QmpClient,
    evidence_root: Path,
    guest: GuestProvenance,
    *,
    state: str = "generic-prompt",
) -> tuple[Path, Path]:
    """Compatibility capture for callers that already proved the UI state."""
    return retain_post_join_calibration(
        sample_post_join_calibration(qmp, evidence_root),
        evidence_root,
        guest,
        state=state,
        stability_samples=1,
    )
