#!/usr/bin/env python3
"""Record and verify the operator-observed guest attachment preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path


SCHEMA = 1
LIFETIME = timedelta(minutes=15)
BOOT_ID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _now() -> datetime:
    return datetime.now(UTC)


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("receipt time has no timezone")
    return parsed.astimezone(UTC)


def _private_regular(path: Path) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError("receipt must be a regular file, not a symlink")
    stat = path.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ValueError("receipt must be owned by this user and mode 0600")


def _disk_identity(disk: Path, serial: str) -> dict[str, object]:
    if not disk.is_file() or disk.is_symlink():
        raise ValueError("VM disk must be a regular file, not a symlink")
    stat = disk.stat()
    return {
        "path": str(disk.resolve()),
        "serial": serial,
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _evidence(document: dict[str, object]) -> str:
    unsigned = {key: value for key, value in document.items()
                if key not in {"evidence", "authorized_utc"}}
    encoded = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:16]


def record(
    output: Path,
    disk: Path,
    serial: str,
    guest_boot_id: str,
    guest_source_commit: str,
    host_tool_commit: str,
    *,
    now: datetime | None = None,
) -> str:
    """Write stage-one evidence and return its confirmation token."""
    if not BOOT_ID.fullmatch(guest_boot_id):
        raise ValueError("guest boot ID must be a lowercase UUID")
    if not COMMIT.fullmatch(guest_source_commit):
        raise ValueError("guest source commit must be a full lowercase SHA-1")
    if not COMMIT.fullmatch(host_tool_commit):
        raise ValueError("host tool commit must be a full lowercase SHA-1")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing to replace an existing receipt")
    parent = output.parent
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError("receipt parent must be an existing directory")
    stamp = (now or _now()).astimezone(UTC)
    document: dict[str, object] = {
        "schema": SCHEMA,
        "created_utc": stamp.isoformat(),
        "expires_utc": (stamp + LIFETIME).isoformat(),
        "guest_preflight_boot_id": guest_boot_id,
        "guest_source_commit": guest_source_commit,
        "host_tool_commit": host_tool_commit,
        "disk": _disk_identity(disk, serial),
        "claim": (
            "operator-observed evidence from the final isolated boot; "
            "not guest attestation and not proof of the subsequent boot"
        ),
    }
    document["evidence"] = _evidence(document)
    descriptor = os.open(
        output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return str(document["evidence"])


def authorize(
    receipt: Path,
    confirmation: str,
    *,
    now: datetime | None = None,
) -> None:
    """Apply the distinct operator confirmation to stage-one evidence."""
    _private_regular(receipt)
    document = json.loads(receipt.read_text(encoding="utf-8"))
    if document.get("authorized_utc") is not None:
        raise ValueError("receipt is already authorized")
    expected = _evidence(document)
    if confirmation != f"ATTACH {expected}":
        raise ValueError(f"confirmation must be: ATTACH {expected}")
    stamp = (now or _now()).astimezone(UTC)
    if stamp > _time(str(document["expires_utc"])):
        raise ValueError("receipt expired before authorization")
    document["authorized_utc"] = stamp.isoformat()
    receipt.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    receipt.chmod(0o600)


def verify(
    receipt: Path,
    disk: Path,
    serial: str,
    expected_commit: str,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    """Verify fresh, authorized evidence against the disk and public source."""
    _private_regular(receipt)
    try:
        document = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read receipt: {error}") from error
    required = {
        "schema", "created_utc", "expires_utc", "authorized_utc",
        "guest_preflight_boot_id", "guest_source_commit", "host_tool_commit",
        "disk", "claim", "evidence",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise ValueError("receipt fields do not match schema")
    if document["schema"] != SCHEMA:
        raise ValueError("unsupported receipt schema")
    if document["evidence"] != _evidence(document):
        raise ValueError("receipt evidence token does not match")
    stamp = (now or _now()).astimezone(UTC)
    created = _time(str(document["created_utc"]))
    expires = _time(str(document["expires_utc"]))
    authorized = _time(str(document["authorized_utc"]))
    if expires - created != LIFETIME or not created <= authorized <= stamp <= expires:
        raise ValueError("receipt is stale or has invalid timestamps")
    if document["host_tool_commit"] != expected_commit:
        raise ValueError("host tool commit does not match current public HEAD")
    if document["disk"] != _disk_identity(disk, serial):
        raise ValueError("VM disk identity changed after preflight")
    return document


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    record_parser = commands.add_parser("record")
    record_parser.add_argument("--output", type=Path, required=True)
    record_parser.add_argument("--disk", type=Path, required=True)
    record_parser.add_argument("--serial", required=True)
    record_parser.add_argument("--guest-boot-id", required=True)
    record_parser.add_argument("--guest-source-commit", required=True)
    record_parser.add_argument("--host-tool-commit", required=True)
    authorize_parser = commands.add_parser("authorize")
    authorize_parser.add_argument("--receipt", type=Path, required=True)
    authorize_parser.add_argument("--confirm", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "record":
            token = record(
                arguments.output, arguments.disk, arguments.serial,
                arguments.guest_boot_id, arguments.guest_source_commit,
                arguments.host_tool_commit)
            print(f"Recorded operator-observed evidence: {arguments.output}")
            print("This is not cryptographic guest attestation.")
            print(f"Second gate: --confirm 'ATTACH {token}'")
        else:
            authorize(
                arguments.receipt, arguments.confirm)
            print("Authorized short-lived preflight receipt.")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
