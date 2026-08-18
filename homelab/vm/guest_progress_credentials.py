"""Per-run credential documents for the guest progress channel.

The shipped guest reporter reads exactly one document from a fixed private
path inside the guest (``/run/telos-progress/credentials.json``) holding
exactly ``{attempt, nonce, key_hex}``; when it is absent the reporter exits
0 silently.  This module mints that attempt-scoped credential on the host
and renders that document byte for byte.

It is deliberately **channel-independent**.  How the document reaches the
guest is an open owner decision -- a one-use hot-attached ISO, a labelled
factory ISO installed to ``/run``, a per-run private HTTP overlay on the
Controller, or serial-console injection -- and every candidate consumes one
of exactly two seams:

* ``ProgressCredential.document_bytes()`` for a channel that carries bytes
  (HTTP body, serial injection, an ISO builder that takes file contents);
* ``stage_credential_document()`` for a channel that needs a real private
  file on the host (an ISO or filesystem image builder that takes a
  directory), destroyed afterwards with ``destroy_credential_document()``.

``GUEST_DOCUMENT_PATH`` tells any such channel where the guest expects to
find it.  Nothing else about the channel is assumed, so bolting one on adds
a caller, not a change here.

The credential never reaches argv, an environment variable, a log, a
transcript, retained evidence, or Git: it is born in host memory, and the
only file it may ever occupy is a run-scoped private staging file the caller
destroys.  ``repr`` and ``str`` of a credential redact the key for exactly
that reason.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

try:
    from .guest_progress_protocol import ProtocolConfig
except ImportError:  # Direct execution from homelab/vm.
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from homelab.vm.guest_progress_protocol import ProtocolConfig


#: The reporter's own constants; the guest side of the seam.
GUEST_DOCUMENT_DIRECTORY = "/run/telos-progress"
DOCUMENT_NAME = "credentials.json"
GUEST_DOCUMENT_PATH = f"{GUEST_DOCUMENT_DIRECTORY}/{DOCUMENT_NAME}"
#: The reporter refuses a shorter key and a larger file.
KEY_BYTES = 32
MAX_DOCUMENT_BYTES = 4096
DOCUMENT_FIELDS = ("attempt", "key_hex", "nonce")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class GuestProgressCredentialError(ValueError):
    """Fail-closed credential minting, rendering, or staging error."""


@dataclass(frozen=True)
class ProgressCredential:
    """One attempt-scoped progress credential, held in host memory only.

    ``attempt`` and ``nonce`` are bounded public tokens; ``key`` is the
    shared MAC secret and is never rendered by ``repr``, never logged, and
    never placed in argv or evidence.
    """

    attempt: str
    nonce: str
    key: bytes

    def __post_init__(self) -> None:
        for name, value in (("attempt", self.attempt), ("nonce", self.nonce)):
            if type(value) is not str or _TOKEN.fullmatch(value) is None:
                raise GuestProgressCredentialError(
                    f"{name} is not a bounded public token")
        if type(self.key) is not bytes or len(self.key) < KEY_BYTES:
            raise GuestProgressCredentialError(
                f"progress key must be at least {KEY_BYTES} exact bytes")

    def __repr__(self) -> str:  # pragma: no cover - trivial redaction
        return (
            f"ProgressCredential(attempt={self.attempt!r}, "
            f"nonce={self.nonce!r}, key=<redacted {len(self.key)} bytes>)")

    __str__ = __repr__

    def document(self) -> dict[str, str]:
        """The exact object the guest reporter accepts: no more, no less."""
        return {
            "attempt": self.attempt,
            "nonce": self.nonce,
            "key_hex": self.key.hex(),
        }

    def document_bytes(self) -> bytes:
        """Render the document deterministically for any delivery channel."""
        raw = (json.dumps(
            self.document(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8") + b"\n")
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise GuestProgressCredentialError(
                "credential document exceeds the reporter's size bound")
        return raw

    def protocol_config(
        self, *, producer: str, phases: tuple[str, ...],
        statuses: tuple[str, ...], **options,
    ) -> ProtocolConfig:
        """Bind this credential's public identity into a receiver config."""
        return ProtocolConfig(
            attempt=self.attempt, producer=producer, nonce=self.nonce,
            phases=tuple(phases), statuses=tuple(statuses), **options)


def mint_credential(
    *, prefix: str = "factory", attempt: str | None = None,
) -> ProgressCredential:
    """Mint one per-run credential from the system CSPRNG.

    The attempt token is process- and run-unique so two concurrent runs can
    never authenticate against each other's receiver.
    """
    if attempt is None:
        if type(prefix) is not str or _TOKEN.fullmatch(prefix) is None:
            raise GuestProgressCredentialError(
                "attempt prefix is not a bounded public token")
        attempt = f"{prefix}-{os.getpid()}-{secrets.token_hex(4)}"
    return ProgressCredential(
        attempt=attempt,
        nonce=secrets.token_hex(16),
        key=secrets.token_bytes(KEY_BYTES),
    )


def _private_directory(directory) -> Path:
    path = Path(directory)
    if path.is_symlink() or not path.is_dir():
        raise GuestProgressCredentialError(
            "credential staging directory must be a real directory")
    if path.stat().st_mode & 0o077:
        raise GuestProgressCredentialError(
            "credential staging directory must be private")
    return path


def staging_root(parent, *, name: str = "credentials") -> Path:
    """Create one private run-scoped directory for staged documents."""
    root = Path(parent) / name
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    root.chmod(0o700)
    return root


def stage_credential_document(
    credential: ProgressCredential, directory, *, name: str = DOCUMENT_NAME,
) -> Path:
    """Write the document into an existing private directory, mode 0600.

    The file is created exclusively and never followed through a symlink, so
    an existing name is a fail-closed error rather than an overwrite.  This
    is the file-shaped half of the delivery seam; a byte-shaped channel uses
    ``ProgressCredential.document_bytes()`` and never touches the disk.
    """
    if type(credential) is not ProgressCredential:
        raise GuestProgressCredentialError(
            "credential must be an exact ProgressCredential")
    if type(name) is not str or "/" in name or name in ("", ".", ".."):
        raise GuestProgressCredentialError("credential file name is invalid")
    path = _private_directory(directory) / name
    payload = credential.document_bytes()
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise GuestProgressCredentialError(
                "credential document was not written completely")
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise GuestProgressCredentialError(
                "staged credential document is not a private regular file")
    except BaseException:
        os.close(descriptor)
        destroy_credential_document(path)
        raise
    os.close(descriptor)
    return path


def destroy_credential_document(path) -> list[str]:
    """Overwrite, unlink, and prove the absence of a staged document.

    Overwriting is best effort -- no filesystem promises that a rewritten
    block replaces the original -- so the proof that matters is absence,
    which is returned as a failure list rather than raised.
    """
    target = Path(path)
    failures: list[str] = []
    try:
        descriptor = os.open(
            target, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        descriptor = None
    except OSError as error:
        descriptor = None
        failures.append(f"credential document is not writable: {error}")
    if descriptor is not None:
        try:
            info = os.fstat(descriptor)
            if stat.S_ISREG(info.st_mode) and info.st_size:
                os.write(descriptor, b"\x00" * min(
                    info.st_size, MAX_DOCUMENT_BYTES))
        except OSError as error:
            failures.append(f"credential document overwrite failed: {error}")
        finally:
            os.close(descriptor)
    try:
        target.unlink()
    except FileNotFoundError:
        pass
    except OSError as error:
        failures.append(f"credential document removal failed: {error}")
    if target.exists() or target.is_symlink():
        failures.append(f"credential document was not removed: {target}")
    return failures
