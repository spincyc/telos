#!/usr/bin/env python3
"""Validation for public Windows identity GUI calibration references."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Sequence

from .windows_gui import Image, WindowsGuiError, crop_image, read_ppm, useful_frame


class WindowsIdentityReferenceError(RuntimeError):
    """A calibration reference or its provenance is not trustworthy."""


_SHA256 = re.compile(r"[0-9a-f]{64}")
_CAPTURE_NAME = re.compile(
    r"(?:run|attempt)-[0-9]{8}T[0-9]{6}Z-[0-9a-f]+")


@dataclass(frozen=True)
class GuestProvenance:
    """Guest identity to which a visual reference is cryptographically bound."""

    release: str
    language: str
    architecture: str
    installer_iso_sha256: str
    source_disk_sha256: str


@dataclass(frozen=True)
class ValidatedIdentityReference:
    """A hash-verified, pre-cropped public checkpoint reference."""

    state: str
    state_kind: str
    captured_after_private_input: bool
    contains_private_material: bool
    guest: GuestProvenance
    path: Path
    image: Image
    geometry: tuple[int, int]
    crop: tuple[int, int, int, int]
    source_frame_sha256: tuple[str, ...]


def _object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise WindowsIdentityReferenceError(f"invalid {label} fields")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise WindowsIdentityReferenceError(f"invalid {label} SHA-256")
    return value


def _dimensions(
    value: object,
    *,
    count: int,
    label: str,
) -> tuple[int, ...]:
    if (
        not isinstance(value, list)
        or len(value) != count
        or any(type(item) is not int or item < 0 for item in value)
    ):
        raise WindowsIdentityReferenceError(f"invalid {label}")
    return tuple(value)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_identity_reference(
    manifest_path: Path,
    *,
    expected_guest: GuestProvenance | None = None,
) -> ValidatedIdentityReference:
    """Load a checked, pre-cropped reference without trusting its manifest."""
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise WindowsIdentityReferenceError("reference manifest must be a file")
    try:
        document = json.loads(manifest_path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise WindowsIdentityReferenceError(
            "reference manifest is not valid JSON") from error
    if not isinstance(document, dict):
        raise WindowsIdentityReferenceError("invalid reference manifest fields")
    schema = document.get("schema")
    if schema == 1:
        root = _object(
            document,
            {
                "schema", "state", "credential_entered", "guest", "capture",
                "reference",
            },
            "reference manifest",
        )
        if root["credential_entered"] is not False:
            raise WindowsIdentityReferenceError(
                "calibration reference must precede credential entry")
        state_kind = "sign-in"
        captured_after_private_input = False
        contains_private_material = False
    elif schema == 2:
        root = _object(
            document,
            {
                "schema", "state", "state_kind",
                "captured_after_private_input", "contains_private_material",
                "guest", "capture", "reference",
            },
            "reference manifest",
        )
        state_kind = root["state_kind"]
        if state_kind not in {
            "desktop", "run-dialog", "security-options", "change-password"
        }:
            raise WindowsIdentityReferenceError(
                "invalid reference state kind")
        captured_after_private_input = root["captured_after_private_input"]
        contains_private_material = root["contains_private_material"]
        if captured_after_private_input is not True:
            raise WindowsIdentityReferenceError(
                "navigation reference must follow private sign-in")
        if contains_private_material is not False:
            raise WindowsIdentityReferenceError(
                "reference must not contain private material")
    else:
        raise WindowsIdentityReferenceError("unsupported reference schema")
    if not isinstance(root["state"], str) or not root["state"].strip():
        raise WindowsIdentityReferenceError("invalid reference state")

    guest = _object(
        root["guest"],
        {
            "release", "language", "architecture", "installer_iso_sha256",
            "source_disk_sha256",
        },
        "guest provenance",
    )
    for field in ("release", "language", "architecture"):
        if not isinstance(guest[field], str) or not guest[field]:
            raise WindowsIdentityReferenceError(
                f"invalid guest provenance {field}")
    guest_provenance = GuestProvenance(
        release=guest["release"],
        language=guest["language"],
        architecture=guest["architecture"],
        installer_iso_sha256=_sha256(
            guest["installer_iso_sha256"], "installer ISO"),
        source_disk_sha256=_sha256(
            guest["source_disk_sha256"], "source disk"),
    )
    if expected_guest is not None and (
        guest_provenance.release != expected_guest.release
        or guest_provenance.language != expected_guest.language
        or guest_provenance.architecture != expected_guest.architecture
        or guest_provenance.installer_iso_sha256
        != expected_guest.installer_iso_sha256
    ):
        # The reference GUI (sign-in/desktop/prompt frames) is determined by
        # the Windows VERSION -- the installer ISO -- not by a specific
        # install's random bytes, so the match requires the release, language,
        # architecture, and installer ISO digest to agree. It deliberately
        # does NOT require source_disk_sha256 to equal the runtime disk: that
        # field records which install the reference was CAPTURED from (kept as
        # provenance), but a fresh install of the same Windows version presents
        # a byte-identical GUI. The real guarantee stays the runtime frame
        # comparison against the sha256-verified reference image; pinning the
        # exact disk made references single-install and blocked a repeatable
        # acceptance on a freshly minted disk.
        raise WindowsIdentityReferenceError(
            "reference guest provenance does not match prepared guest")

    capture = _object(
        root["capture"],
        {
            "source_bundle", "attempt", "geometry", "crop",
            "stable_source_frame_sha256",
        },
        "capture provenance",
    )
    for field in ("source_bundle", "attempt"):
        if (
            not isinstance(capture[field], str)
            or _CAPTURE_NAME.fullmatch(capture[field]) is None
        ):
            raise WindowsIdentityReferenceError(
                f"invalid capture provenance {field}")
    geometry = _dimensions(capture["geometry"], count=2, label="capture geometry")
    crop = _dimensions(capture["crop"], count=4, label="capture crop")
    x, y, width, height = crop
    if (
        width < 16
        or height < 16
        or x + width > geometry[0]
        or y + height > geometry[1]
    ):
        raise WindowsIdentityReferenceError("capture crop is outside its geometry")
    source_hashes = capture["stable_source_frame_sha256"]
    if not isinstance(source_hashes, list) or len(source_hashes) < 3:
        raise WindowsIdentityReferenceError(
            "reference requires at least three stable source frames")
    stable_hashes = tuple(
        _sha256(value, "source frame") for value in source_hashes)
    if len(set(stable_hashes)) != 1:
        raise WindowsIdentityReferenceError("source frames are not byte-stable")

    reference = _object(
        root["reference"], {"file", "sha256"}, "reference provenance")
    filename = reference["file"]
    if (
        not isinstance(filename, str)
        or Path(filename).name != filename
        or filename in {"", ".", ".."}
    ):
        raise WindowsIdentityReferenceError("unsafe reference filename")
    expected_hash = _sha256(reference["sha256"], "reference")
    path = manifest_path.parent / filename
    if path.is_symlink() or not path.is_file():
        raise WindowsIdentityReferenceError("reference image must be a file")
    if _digest(path) != expected_hash:
        raise WindowsIdentityReferenceError("reference image hash mismatch")
    try:
        image = read_ppm(path)
    except (OSError, WindowsGuiError) as error:
        raise WindowsIdentityReferenceError(
            "reference image is not a valid PPM") from error
    if (image.width, image.height) != (width, height):
        raise WindowsIdentityReferenceError(
            "reference image does not match declared crop")
    if not useful_frame(image):
        raise WindowsIdentityReferenceError("reference image is not useful")
    return ValidatedIdentityReference(
        state=root["state"],
        state_kind=state_kind,
        captured_after_private_input=captured_after_private_input,
        contains_private_material=contains_private_material,
        guest=guest_provenance,
        path=path,
        image=image,
        geometry=(geometry[0], geometry[1]),
        crop=(x, y, width, height),
        source_frame_sha256=stable_hashes,
    )


def verify_reference_sources(
    reference: ValidatedIdentityReference,
    source_frames: Sequence[Path],
) -> None:
    """Prove named full-frame captures reproduce the tracked crop exactly."""
    if len(source_frames) != len(reference.source_frame_sha256):
        raise WindowsIdentityReferenceError("source frame count mismatch")
    for path, expected_hash in zip(
        source_frames, reference.source_frame_sha256, strict=True
    ):
        if path.is_symlink() or not path.is_file() or _digest(path) != expected_hash:
            raise WindowsIdentityReferenceError("source frame hash mismatch")
        try:
            image = read_ppm(path)
            cropped = crop_image(image, reference.crop)
        except (OSError, WindowsGuiError) as error:
            raise WindowsIdentityReferenceError(
                "source frame is not a valid full screenshot") from error
        if (image.width, image.height) != reference.geometry:
            raise WindowsIdentityReferenceError("source frame geometry mismatch")
        if cropped != reference.image:
            raise WindowsIdentityReferenceError(
                "source frame does not reproduce reference crop")
