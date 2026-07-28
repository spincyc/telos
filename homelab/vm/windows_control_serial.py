#!/usr/bin/env python3
"""Bounded host transport for the read-only Windows control probes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import socket
from typing import Mapping

from .windows_control_iso import audit_payload, probe_launch_command


class WindowsControlSerialError(RuntimeError):
    """A control probe did not produce an admissible public observation."""


MAX_RECORD_BYTES = 16 * 1024
CHARDEV_ID = "telosidentity"
_TOP_LEVEL_KEYS = {
    "schema_version", "action", "result", "observed_at", "observation",
}
_OBSERVATION_KEYS = {
    "current-principal": {
        "principal": str,
        "authenticated": bool,
        "elevated": bool,
        "authentication_type": str,
    },
    "current-session-state": {
        "authenticated": bool,
        "identity_resolved": bool,
        "profile_loaded": bool,
        "local_profile": bool,
        "local_administrator": bool,
        "domain_administrator": bool,
    },
    "controller-readiness": {
        "samba_ad": bool,
        "dns": bool,
        "kerberos": bool,
        "time": bool,
        "synthetic_directory": bool,
    },
    "domain-state": {
        "part_of_domain": bool,
        "domain": str,
        "secure_channel": bool,
        "operator": str,
        "operator_local_administrator": bool,
    },
    "managed-identity-state": {
        "standard_identity_resolved": bool,
        "standard_profile_present": bool,
        "operator_identity_resolved": bool,
        "operator_profile_present": bool,
        "operator_local_administrator": bool,
        "operator_domain_administrator": bool,
        "directory_admin_identity_resolved": bool,
        "directory_admin_domain_administrator": bool,
        "operator_is_directory_admin": bool,
    },
    "cached-logon-policy": {
        "configured": bool,
        "cached_logon_count": (int, type(None)),
    },
    "dependency-reachability": {
        "update_source_reachable": bool,
        "optional_storage_reachable": bool,
        "optional_storage_authorization_denied": bool,
    },
    "service-reachability": {
        "domain": str,
        "dns": bool,
        "kerberos": bool,
        "ldap": bool,
        "smb": bool,
    },
    "update-policy": {
        "policy_present": bool,
        "automatic_updates_configured": bool,
    },
}


@dataclass(frozen=True)
class ControlProbe:
    """A fixed launch command and its expected serial response action."""

    action: str
    command: str


def _validate_socket_path(path: Path) -> Path:
    path = Path(path).absolute()
    encoded = str(path).encode()
    if b"," in encoded or any(byte < 0x20 for byte in encoded):
        raise WindowsControlSerialError(
            "serial socket path is not QEMU-safe")
    parent = path.parent
    if (parent.is_symlink() or not parent.is_dir()
            or parent.stat().st_mode & 0o077):
        raise WindowsControlSerialError(
            "serial socket parent must be a private real directory")
    if path.exists() or path.is_symlink():
        raise WindowsControlSerialError("serial socket path must be absent")
    # Linux sockaddr_un.sun_path has 108 bytes including the trailing NUL.
    if len(encoded) >= 108:
        raise WindowsControlSerialError("serial socket path is too long")
    return path


def attach_qemu_serial(command: list[str], socket_path: Path) -> list[str]:
    """Return an argv copy whose COM1 is a private host Unix socket.

    The socket is a QEMU server.  Nothing secret enters argv, and the original
    authorized command is left untouched for audit comparison.
    """
    path = _validate_socket_path(socket_path)
    result = list(command)
    positions = [
        index for index, value in enumerate(result[:-1]) if value == "-serial"
    ]
    if len(positions) != 1:
        raise WindowsControlSerialError(
            "QEMU command must declare exactly one serial device")
    if any(value == "-chardev" for value in result):
        raise WindowsControlSerialError(
            "QEMU command already declares a character device")
    result[positions[0] + 1] = f"chardev:{CHARDEV_ID}"
    result += [
        "-chardev",
        f"socket,id={CHARDEV_ID},path={path},server=on,wait=off",
    ]
    return result


def control_probe(action: str) -> ControlProbe:
    """Construct an exact allowlisted probe launch request."""
    manifest = audit_payload()
    if action not in manifest["actions"]:
        raise WindowsControlSerialError("control action is not allowlisted")
    return ControlProbe(action=action, command=probe_launch_command(action))


def _validate_timestamp(value: object) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise WindowsControlSerialError("probe timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise WindowsControlSerialError("probe timestamp is invalid") from error
    if parsed.microsecond:
        raise WindowsControlSerialError("probe timestamp is invalid")


def parse_probe_record(line: bytes, expected_action: str) -> dict[str, object]:
    """Parse one strict, secret-free JSONL record for an expected action."""
    if not line.endswith(b"\n") or b"\n" in line[:-1] or b"\r" in line[:-1]:
        raise WindowsControlSerialError(
            "probe response must be exactly one JSONL record")
    if len(line) > MAX_RECORD_BYTES:
        raise WindowsControlSerialError("probe response exceeds size limit")
    try:
        record = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WindowsControlSerialError("probe response is invalid JSON") from error
    if not isinstance(record, dict) or set(record) != _TOP_LEVEL_KEYS:
        raise WindowsControlSerialError("probe response schema is invalid")
    if (record["schema_version"] != 1 or record["result"] != "pass"
            or record["action"] != expected_action):
        raise WindowsControlSerialError("probe response identity is invalid")
    _validate_timestamp(record["observed_at"])
    schema = _OBSERVATION_KEYS.get(expected_action)
    observation = record["observation"]
    if schema is None or not isinstance(observation, dict):
        raise WindowsControlSerialError("probe observation schema is invalid")
    if set(observation) != set(schema):
        raise WindowsControlSerialError("probe observation schema is invalid")
    for key, expected_type in schema.items():
        value = observation[key]
        # bool is a subclass of int; an integer field must reject booleans.
        if (expected_type == (int, type(None)) and isinstance(value, bool)
                or not isinstance(value, expected_type)):
            raise WindowsControlSerialError(
                "probe observation schema is invalid")
    return record


def fault_reachability_fields(
    record: Mapping[str, object],
    check: str,
) -> dict[str, object]:
    """Map a validated dependency probe into one fault observation fragment.

    Login, profile, and rescue outcomes remain owned by their separate guest
    observations. This maps only facts established by the two fixed UDP role
    probes, and refuses record-shaped input that did not pass the strict
    parser.
    """
    if (set(record) != _TOP_LEVEL_KEYS
            or record.get("schema_version") != 1
            or record.get("action") != "dependency-reachability"
            or record.get("result") != "pass"):
        raise WindowsControlSerialError(
            "dependency probe record is not validated")
    observation = record.get("observation")
    schema = _OBSERVATION_KEYS["dependency-reachability"]
    if (not isinstance(observation, dict)
            or set(observation) != set(schema)
            or any(type(observation[key]) is not bool for key in schema)):
        raise WindowsControlSerialError(
            "dependency probe observation schema is invalid")
    mappings = {
        "update-source-offline": {
            "update_source_reachable": "update_source_reachable",
        },
        "optional-storage-offline": {
            "storage_reachable": "optional_storage_reachable",
        },
        "optional-storage-access-denied": {
            "storage_reachable": "optional_storage_reachable",
            "storage_access": "optional_storage_authorization_denied",
        },
        "combined-dependencies-offline": {
            "update_source_reachable": "update_source_reachable",
            "optional_storage_reachable": "optional_storage_reachable",
        },
        "windows-services-restored": {
            "optional_storage_reachable": "optional_storage_reachable",
        },
    }
    try:
        fields = mappings[check]
    except KeyError as error:
        raise WindowsControlSerialError(
            "fault check has no dependency reachability mapping") from error
    result: dict[str, object] = {}
    for target, source in fields.items():
        value: object = observation[source]
        if check == "optional-storage-access-denied":
            if observation["optional_storage_reachable"] is not True:
                raise WindowsControlSerialError(
                    "storage denial proof requires reachable storage")
            if target == "storage_access":
                if value is not True:
                    raise WindowsControlSerialError(
                        "storage denial proof is absent")
                value = "denied"
        result[target] = value
    return result


def receive_probe_record(
    socket_path: Path,
    expected_action: str,
    *,
    timeout: float = 10.0,
) -> dict[str, object]:
    """Connect to QEMU's private serial socket and receive one bounded line."""
    if timeout <= 0:
        raise WindowsControlSerialError("serial timeout must be positive")
    path = Path(socket_path).absolute()
    if path.is_symlink() or not path.exists():
        raise WindowsControlSerialError(
            "serial socket must be an existing non-symlink")
    data = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(timeout)
            stream.connect(str(path))
            while b"\n" not in data and len(data) <= MAX_RECORD_BYTES:
                chunk = stream.recv(min(4096, MAX_RECORD_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
    except (OSError, TimeoutError) as error:
        raise WindowsControlSerialError(
            "failed to receive control probe response") from error
    return parse_probe_record(bytes(data), expected_action)
