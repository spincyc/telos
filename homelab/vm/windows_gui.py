#!/usr/bin/env python3
"""Fail-closed Windows Setup driving through QMP screenshots and key events."""

from __future__ import annotations

import json
import math
import os
import socket
import struct
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator


class WindowsGuiError(RuntimeError):
    """The observed display did not prove the expected setup state."""


SAFE_KEYS = frozenset({
    "esc", "tab", "backtab", "backspace", "ret", "spc", "up", "down",
    "left", "right", "home", "end", "pgup", "pgdn",
})
SHIFTED = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6",
    "&": "7", "*": "8", "(": "9", ")": "0", "_": "minus",
    "+": "equal", "{": "bracket_left", "}": "bracket_right",
    "|": "backslash", ":": "semicolon", '"': "apostrophe",
    "<": "comma", ">": "dot", "?": "slash", "~": "grave_accent",
}
PLAIN = {
    " ": "spc", "-": "minus", "=": "equal", "[": "bracket_left",
    "]": "bracket_right", "\\": "backslash", ";": "semicolon",
    "'": "apostrophe", ",": "comma", ".": "dot", "/": "slash",
    "`": "grave_accent",
}


@dataclass(frozen=True)
class Image:
    width: int
    height: int
    pixels: bytes


@dataclass(frozen=True)
class Checkpoint:
    name: str
    reference: Path
    keys: tuple[str, ...]
    timeout: float = 90.0
    threshold: float = 6.0
    crop: tuple[int, int, int, int] | None = None
    expected_geometry: tuple[int, int] | None = None


def read_ppm(path: Path) -> Image:
    """Read the binary PPM emitted by QEMU's screendump command."""
    raw = path.read_bytes()
    tokens: list[bytes] = []
    cursor = 0
    while len(tokens) < 4:
        while cursor < len(raw) and raw[cursor] in b" \t\r\n":
            cursor += 1
        if cursor < len(raw) and raw[cursor] == ord("#"):
            cursor = raw.find(b"\n", cursor)
            if cursor < 0:
                break
            continue
        start = cursor
        while cursor < len(raw) and raw[cursor] not in b" \t\r\n":
            cursor += 1
        tokens.append(raw[start:cursor])
    if len(tokens) != 4 or tokens[0] != b"P6":
        raise WindowsGuiError(f"{path}: expected binary PPM")
    try:
        width, height, maximum = map(int, tokens[1:4])
    except ValueError as error:
        raise WindowsGuiError(f"{path}: malformed PPM header") from error
    if width < 320 or height < 200 or maximum != 255:
        raise WindowsGuiError(f"{path}: implausible PPM geometry")
    if cursor >= len(raw) or raw[cursor] not in b" \t\r\n":
        raise WindowsGuiError(f"{path}: missing PPM pixel separator")
    # Netpbm requires one whitespace separator. Pixel bytes may themselves be
    # whitespace, so consuming an arbitrary run here would corrupt the image.
    cursor += 2 if raw[cursor:cursor + 2] == b"\r\n" else 1
    pixels = raw[cursor:]
    if len(pixels) != width * height * 3:
        raise WindowsGuiError(f"{path}: truncated PPM pixels")
    return Image(width, height, pixels)


def image_distance(actual: Image, reference: Image) -> float:
    """Return mean absolute RGB distance; exact geometry is mandatory."""
    if (actual.width, actual.height) != (reference.width, reference.height):
        return float("inf")
    if not actual.pixels:
        return float("inf")
    return sum(abs(a - b) for a, b in zip(
        actual.pixels, reference.pixels, strict=True)) / len(actual.pixels)


def crop_image(image: Image, crop: tuple[int, int, int, int] | None) -> Image:
    """Select a stable x/y/width/height region, excluding clocks or spinners."""
    if crop is None:
        return image
    x, y, width, height = crop
    if (x < 0 or y < 0 or width < 16 or height < 16
            or x + width > image.width or y + height > image.height):
        raise WindowsGuiError("checkpoint crop is outside the screenshot")
    rows = []
    stride = image.width * 3
    for row in range(y, y + height):
        start = row * stride + x * 3
        rows.append(image.pixels[start:start + width * 3])
    return Image(width, height, b"".join(rows))


def useful_frame(image: Image) -> bool:
    """Reject blank/solid frames that can otherwise match during transitions."""
    samples = image.pixels[::max(3, len(image.pixels) // 4096)]
    return bool(samples) and max(samples) - min(samples) >= 24


class QmpClient:
    """Small synchronous QMP client with correlated responses."""

    def __init__(
            self,
            connection: socket.socket,
            *,
            event_limit: int = 256,
            response_limit: int = 256,
            clock: Callable[[], float] = time.monotonic,
            pause: Callable[[float], None] = time.sleep,
            key_interval: float = 0.10,
    ) -> None:
        if event_limit < 1 or response_limit < 1:
            raise ValueError("QMP queue limits must be positive")
        if (
            type(key_interval) not in (int, float)
            or not math.isfinite(key_interval)
            or key_interval < 0
        ):
            raise ValueError("QMP key interval must be nonnegative")
        self.connection = connection
        self.reader = connection.makefile("rb")
        self.sequence = 0
        self._events: deque[dict] = deque()
        self._responses: dict[object, dict] = {}
        self._event_limit = event_limit
        self._response_limit = response_limit
        self._clock = clock
        self._pause = pause
        self._key_interval = float(key_interval)

    @classmethod
    def connect(
            cls,
            path: Path,
            timeout: float = 5.0,
            *,
            expected_peer_pid: int,
    ) -> "QmpClient":
        if type(expected_peer_pid) is not int or expected_peer_pid <= 0:
            raise ValueError("QMP peer pid must be a positive integer")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(timeout)
            connection.connect(str(path))
            credentials = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED,
                struct.calcsize("3i"))
            peer_pid, peer_uid, peer_gid = struct.unpack("3i", credentials)
            expected = (expected_peer_pid, os.geteuid(), os.getegid())
            if (peer_pid, peer_uid, peer_gid) != expected:
                raise WindowsGuiError(
                    "QMP peer credentials do not match the spawned process")
            client = cls(connection)
            try:
                greeting = client._message()
                if "QMP" not in greeting:
                    raise WindowsGuiError("QMP greeting missing")
                client.execute("qmp_capabilities")
            except BaseException:
                client.close()
                raise
            return client
        except BaseException:
            if connection.fileno() >= 0:
                connection.close()
            raise

    def close(self) -> None:
        self.reader.close()
        self.connection.close()

    def _read_message(self) -> dict:
        line = self.reader.readline()
        if not line:
            raise WindowsGuiError("QMP connection closed")
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            raise WindowsGuiError("QMP returned malformed JSON") from error
        if not isinstance(message, dict):
            raise WindowsGuiError("QMP returned malformed message")
        return message

    def _queue_event(self, message: dict) -> None:
        if len(self._events) >= self._event_limit:
            raise WindowsGuiError("QMP event queue limit exceeded")
        self._events.append(message)

    def _queue_response(self, message: dict) -> None:
        identifier = message.get("id")
        if identifier in self._responses:
            raise WindowsGuiError("QMP returned duplicate response id")
        if len(self._responses) >= self._response_limit:
            raise WindowsGuiError("QMP response queue limit exceeded")
        self._responses[identifier] = message

    def _remaining_timeout(
            self, deadline: float, previous_timeout: float | None) -> float:
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise WindowsGuiError("QMP command timed out")
        if previous_timeout is not None:
            return min(previous_timeout, remaining)
        return remaining

    def _message(
            self,
            *,
            deadline: float | None = None,
            previous_timeout: float | None = None,
    ) -> dict:
        while True:
            if deadline is not None:
                self.connection.settimeout(
                    self._remaining_timeout(deadline, previous_timeout))
            message = self._read_message()
            if "event" in message:
                self._queue_event(message)
                continue
            return message

    def execute(
            self,
            command: str,
            arguments: dict | None = None,
            *,
            timeout: float | None = None,
    ) -> dict:
        if timeout is not None and (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise WindowsGuiError("QMP command timeout is invalid")
        self.sequence += 1
        identifier = f"windows-gui-{self.sequence}"
        request = {"execute": command, "id": identifier}
        if arguments:
            request["arguments"] = arguments
        deadline = None if timeout is None else self._clock() + timeout
        previous_timeout = self.connection.gettimeout()
        try:
            if deadline is not None:
                self.connection.settimeout(
                    self._remaining_timeout(deadline, previous_timeout))
            self.connection.sendall(
                json.dumps(request, separators=(",", ":")).encode()
                + b"\r\n")
            while True:
                response = self._responses.pop(identifier, None)
                if response is None:
                    response = self._message(
                        deadline=deadline,
                        previous_timeout=previous_timeout,
                    )
                if response.get("id") != identifier:
                    self._queue_response(response)
                    continue
                if "error" in response:
                    raise WindowsGuiError(
                        f"QMP {command} failed: {response['error']}")
                return response.get("return", {})
        except (socket.timeout, TimeoutError) as error:
            raise WindowsGuiError("QMP command timed out") from error
        finally:
            if deadline is not None:
                self.connection.settimeout(previous_timeout)

    def await_device_deleted(
            self, device_id: str, *, timeout: float = 5.0) -> dict:
        """Await DEVICE_DELETED for exactly *device_id*, retaining other QMP traffic."""
        if not isinstance(device_id, str) or not device_id:
            raise ValueError("QMP device id must be non-empty")
        if timeout <= 0:
            raise ValueError("QMP event timeout must be positive")

        for event in tuple(self._events):
            if (event.get("event") == "DEVICE_DELETED"
                    and event.get("data", {}).get("device") == device_id):
                self._events.remove(event)
                return event

        deadline = time.monotonic() + timeout
        previous_timeout = self.connection.gettimeout()
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WindowsGuiError(
                        f"timed out awaiting DEVICE_DELETED for {device_id}")
                self.connection.settimeout(remaining)
                try:
                    message = self._read_message()
                except (socket.timeout, TimeoutError) as error:
                    raise WindowsGuiError(
                        f"timed out awaiting DEVICE_DELETED for {device_id}"
                    ) from error
                if "event" in message:
                    if (message.get("event") == "DEVICE_DELETED"
                            and message.get("data", {}).get("device")
                            == device_id):
                        return message
                    self._queue_event(message)
                else:
                    self._queue_response(message)
        finally:
            self.connection.settimeout(previous_timeout)

    def screenshot(self, path: Path) -> None:
        self.execute("screendump", {"filename": str(path)})

    def key(self, name: str, *, timeout: float | None = None) -> None:
        if name not in SAFE_KEYS:
            raise WindowsGuiError(f"unsafe GUI key: {name}")
        self.execute("send-key", {
            "keys": [{"type": "qcode", "data": name}],
            "hold-time": 60,
        }, timeout=timeout)

    def chord(
            self, *names: str, timeout: float | None = None) -> None:
        if not names or any(not isinstance(name, str) or not name for name in names):
            raise WindowsGuiError("invalid GUI key chord")
        self.execute("send-key", {
            "keys": [{"type": "qcode", "data": name} for name in names],
            "hold-time": 60,
        }, timeout=timeout)

    def type_text(self, value: str, *, timeout: float | None = None) -> None:
        """Type bounded ASCII without placing its value in an error message."""
        if not isinstance(value, str) or not 1 <= len(value) <= 512:
            raise WindowsGuiError("GUI text length is invalid")
        encoded: list[tuple[str, ...]] = []
        for offset, character in enumerate(value):
            if "a" <= character <= "z" or "0" <= character <= "9":
                keys = (character,)
            elif "A" <= character <= "Z":
                keys = ("shift", character.lower())
            elif character in PLAIN:
                keys = (PLAIN[character],)
            elif character in SHIFTED:
                keys = ("shift", SHIFTED[character])
            else:
                raise WindowsGuiError(
                    f"GUI text has unsupported character at offset {offset}")
            encoded.append(keys)
        if timeout is not None and (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise WindowsGuiError("QMP text timeout is invalid")
        deadline = None if timeout is None else self._clock() + timeout
        for index, keys in enumerate(encoded):
            remaining = (
                None if deadline is None
                else self._remaining_timeout(deadline, None)
            )
            self.chord(*keys, timeout=remaining)
            if index + 1 < len(encoded) and self._key_interval:
                interval = self._key_interval
                if deadline is not None:
                    interval = min(
                        interval, self._remaining_timeout(deadline, None))
                self._pause(interval)


class WindowsSetupDriver:
    """Advance only after each expected Windows Setup screen is observed."""

    def __init__(
        self,
        qmp: QmpClient,
        evidence_root: Path,
        *,
        interval: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
        pause: Callable[[float], None] = time.sleep,
    ) -> None:
        if evidence_root.is_symlink():
            raise WindowsGuiError("evidence root must not be a symlink")
        root = evidence_root.resolve()
        if not root.is_dir():
            raise WindowsGuiError("evidence root must be an existing directory")
        self.qmp = qmp
        self.root = root
        self.interval = interval
        self.clock = clock
        self.pause = pause

    def _screens(self, name: str) -> Iterator[Path]:
        counter = 0
        while True:
            counter += 1
            yield self.root / f"{counter:04d}-{name}.ppm"

    def wait(self, checkpoint: Checkpoint) -> Path:
        reference = read_ppm(checkpoint.reference)
        deadline = self.clock() + checkpoint.timeout
        screens = self._screens(checkpoint.name)
        best = float("inf")
        while self.clock() < deadline:
            path = next(screens)
            self.qmp.screenshot(path)
            os.chmod(path, 0o600)
            actual = read_ppm(path)
            distance = image_distance(
                crop_image(actual, checkpoint.crop),
                crop_image(reference, checkpoint.crop),
            )
            best = min(best, distance)
            if useful_frame(actual) and distance <= checkpoint.threshold:
                return path
            path.unlink(missing_ok=True)
            self.pause(self.interval)
        raise WindowsGuiError(
            f"timed out at {checkpoint.name}; best image distance {best:.2f}")

    def run(self, plan: tuple[Checkpoint, ...]) -> tuple[str, ...]:
        if not plan:
            raise WindowsGuiError("empty Windows Setup plan")
        events: list[str] = []
        for checkpoint in plan:
            self.wait(checkpoint)
            events.append(f"observed:{checkpoint.name}")
            for key in checkpoint.keys:
                self.qmp.key(key)
                events.append(f"key:{key}")
                self.pause(0.15)
        return tuple(events)


def load_plan(path: Path, reference_root: Path) -> tuple[Checkpoint, ...]:
    """Load a non-secret, navigation-only plan from tracked JSON."""
    payload = json.loads(path.read_text())
    if payload.get("schema") != 1 or not isinstance(payload.get("steps"), list):
        raise WindowsGuiError("invalid Windows Setup plan")
    root = reference_root.resolve()
    plan: list[Checkpoint] = []
    names: set[str] = set()
    for record in payload["steps"]:
        if set(record) - {
                "name", "reference", "keys", "timeout", "threshold", "crop"}:
            raise WindowsGuiError("unknown Windows Setup plan field")
        name = record.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise WindowsGuiError("step names must be unique non-empty strings")
        names.add(name)
        reference = (root / record["reference"]).resolve()
        if root not in reference.parents:
            raise WindowsGuiError("reference escapes reference root")
        keys = tuple(record.get("keys", ()))
        if any(key not in SAFE_KEYS for key in keys):
            raise WindowsGuiError("plan contains text-capable or unknown key")
        timeout = float(record.get("timeout", 90))
        threshold = float(record.get("threshold", 6))
        raw_crop = record.get("crop")
        crop = None
        if raw_crop is not None:
            if (not isinstance(raw_crop, list) or len(raw_crop) != 4
                    or any(not isinstance(value, int) for value in raw_crop)):
                raise WindowsGuiError("crop must be four integers")
            crop = tuple(raw_crop)
        if not 1 <= timeout <= 900 or not 0 <= threshold <= 32:
            raise WindowsGuiError("plan bounds are invalid")
        plan.append(Checkpoint(name, reference, keys, timeout, threshold, crop))
    return tuple(plan)
