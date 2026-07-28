#!/usr/bin/env python3
"""Trusted on-disk composition for one native Windows identity acceptance."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

from .controller_factory import FactorySpec
from .windows_identity_adapter import NativeWindowsAcceptanceAdapter
from .windows_identity_contract import qemu_identity_command
from .windows_identity_diagnostics import (
    CredentialOwnershipState,
    ProductionSecretScanner,
    RetainedInventory,
)
from .windows_identity_progressive import ProgressiveRotationPlan
from .windows_identity_reference import (
    GuestProvenance,
    WindowsIdentityReferenceError,
    load_identity_reference,
)
from .windows_identity_run import NativeProcessBoundary
from .windows_public_command import PublicPowerShellLaunchPlan


class WindowsIdentityFactoryError(RuntimeError):
    """Prepared state cannot safely define a production acceptance."""


REFERENCE_ROOT = (
    Path(__file__).parent
    / "windows_identity_references/windows-11-25h2-en-us-1280x800"
)
REFERENCE_NAMES = (
    "sign-in", "desktop", "security-options", "change-password")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while block := source.read(1024 * 1024):
                digest.update(block)
    except OSError as error:
        raise WindowsIdentityFactoryError(
            "prepared source disk cannot be authenticated") from error
    return digest.hexdigest()


def _actual_overlay_backing(overlay: Path) -> Path:
    try:
        result = subprocess.run(
            ["qemu-img", "info", "--output=json", str(overlay)],
            check=True, capture_output=True, text=True,
        )
        information = json.loads(result.stdout)
    except (
        OSError,
        subprocess.CalledProcessError,
        UnicodeError,
        json.JSONDecodeError,
    ) as error:
        raise WindowsIdentityFactoryError(
            "prepared overlay metadata is unavailable") from error
    backing = information.get("full-backing-filename")
    if (
        information.get("format") != "qcow2"
        or not isinstance(backing, str)
        or not backing
    ):
        raise WindowsIdentityFactoryError(
            "prepared overlay lacks an exact qcow2 backing file")
    return Path(backing).absolute()


def _authorization(boundary: NativeProcessBoundary) -> dict[str, object]:
    try:
        value = json.loads(
            (boundary.attempt / "authorization.json").read_text(
                encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise WindowsIdentityFactoryError(
            "prepared authorization is unavailable") from error
    if not isinstance(value, dict):
        raise WindowsIdentityFactoryError(
            "prepared authorization has an invalid schema")
    return value


def _source_bundle(
    boundary: NativeProcessBoundary, authorization: dict[str, object],
) -> Path:
    source = authorization.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("bundle"), str):
        raise WindowsIdentityFactoryError(
            "prepared authorization lacks its source bundle")
    bundle = Path(source["bundle"]).absolute()
    try:
        info = bundle.lstat()
    except OSError as error:
        raise WindowsIdentityFactoryError(
            "prepared source bundle is unavailable") from error
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise WindowsIdentityFactoryError(
            "prepared source bundle is not a private real directory")
    overlay = authorization.get("overlay")
    source_disk = source.get("disk")
    if (
        not isinstance(overlay, dict)
        or not isinstance(source_disk, dict)
        or not isinstance(source_disk.get("path"), str)
        or not isinstance(source_disk.get("sha256"), str)
        or _SHA256.fullmatch(source_disk["sha256"]) is None
    ):
        raise WindowsIdentityFactoryError(
            "prepared overlay is not bound to its source bundle")
    disk = Path(source_disk["path"]).absolute()
    try:
        disk_info = disk.lstat()
    except OSError as error:
        raise WindowsIdentityFactoryError(
            "prepared source disk is unavailable") from error
    if (
        disk.parent != bundle
        or disk.name != "windows.qcow2"
        or stat.S_ISLNK(disk_info.st_mode)
        or not stat.S_ISREG(disk_info.st_mode)
        or stat.S_IMODE(disk_info.st_mode) != 0o600
        or overlay.get("backing_path") != str(disk)
        or _sha256(disk) != source_disk["sha256"]
        or _actual_overlay_backing(
            boundary.attempt / "windows.qcow2") != disk
    ):
        raise WindowsIdentityFactoryError(
            "prepared source disk or overlay backing differs from authorization")
    return bundle


def _references(
    authorization: dict[str, object],
) -> tuple[GuestProvenance, dict[str, object]]:
    source = authorization.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("disk"), dict):
        raise WindowsIdentityFactoryError(
            "prepared guest provenance is unavailable")
    disk = source["disk"]
    try:
        guest = GuestProvenance(
            release="Windows 11 25H2",
            language="en-US",
            architecture="x86_64",
            installer_iso_sha256=(
                "768984706b909479417b2368438909440f2967ff05c6a9195ed2667254e465e3"
            ),
            source_disk_sha256=disk["sha256"],
        )
        loaded = {
            name: load_identity_reference(
                REFERENCE_ROOT / f"{name}.json", expected_guest=guest)
            for name in (*REFERENCE_NAMES, "run-dialog")
        }
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        WindowsIdentityReferenceError,
    ) as error:
        raise WindowsIdentityFactoryError(
            "trusted Windows references do not match the prepared guest"
        ) from error
    return guest, loaded


def _retained_inventory(root: Path) -> RetainedInventory:
    try:
        if root.is_symlink() or not root.is_dir():
            raise WindowsIdentityFactoryError(
                "source evidence is not a real directory")
        files = tuple(
            PurePosixPath(path.relative_to(root).as_posix())
            for path in sorted(root.rglob("*"))
            if path.is_file() and not path.is_symlink()
        )
        nonregular = tuple(
            path for path in root.rglob("*")
            if path.is_symlink() or not (path.is_file() or path.is_dir())
        )
        empty_directories = tuple(
            PurePosixPath(path.relative_to(root).as_posix())
            for path in sorted(root.rglob("*"))
            if path.is_dir() and not any(path.iterdir())
        )
    except OSError as error:
        raise WindowsIdentityFactoryError(
            "source evidence inventory is unavailable") from error
    if not files or nonregular:
        raise WindowsIdentityFactoryError(
            "source evidence inventory is incomplete")
    logs = tuple(
        path for path in files if path.suffix in {".log", ".jsonl"})
    artifacts = tuple(path for path in files if path not in logs)
    return RetainedInventory(
        root,
        tracked_artifacts=artifacts,
        logs=logs,
        directories=empty_directories,
    )


def _attempt_inventory(attempt: Path) -> RetainedInventory:
    """Inventory every retained output while excluding exact active VM media."""
    expected_files = {
        "windows.qcow2", "OVMF_VARS.fd", "authorization.json",
        "qemu-command.json", "control.iso",
    }
    allowed_directories = {
        "runtime", "rotation-evidence", "public-command-evidence",
        "post-join-reauthentication",
    }
    try:
        entries = {path.name: path for path in attempt.iterdir()}
        if not expected_files.issubset(entries):
            raise WindowsIdentityFactoryError(
                "attempt retained surfaces lack prepared artifacts")
        unexpected_top = set(entries) - expected_files - allowed_directories
        if unexpected_top:
            raise WindowsIdentityFactoryError(
                "attempt contains an unexpected retained surface")
        for name in expected_files:
            if entries[name].is_symlink() or not entries[name].is_file():
                raise WindowsIdentityFactoryError(
                    "prepared attempt artifact identity changed")
        for name in set(entries).intersection(allowed_directories):
            if entries[name].is_symlink() or not entries[name].is_dir():
                raise WindowsIdentityFactoryError(
                    "retained evidence surface identity changed")

        runtime = attempt / "runtime"
        if not runtime.is_dir():
            raise WindowsIdentityFactoryError(
                "acceptance runtime evidence is unavailable")
        runtime_entries = {path.name: path for path in runtime.iterdir()}
        if set(runtime_entries) != {
            "switch.jsonl", "windows-qemu.log", "controller"
        }:
            raise WindowsIdentityFactoryError(
                "acceptance runtime has unexpected retained paths")
        controller = runtime / "controller"
        if controller.is_symlink() or not controller.is_dir():
            raise WindowsIdentityFactoryError(
                "active Controller media root is invalid")
        if {path.name for path in controller.iterdir()} != {
            "controller.raw", "OVMF_VARS.fd", "guard"
        }:
            raise WindowsIdentityFactoryError(
                "active Controller media set is invalid")
        guard = controller / "guard"
        if guard.is_symlink() or not guard.is_dir() or {
            path.name for path in guard.iterdir()
        } != {"controller-overlay.qcow2", "OVMF_VARS.fd"}:
            raise WindowsIdentityFactoryError(
                "active Controller guard media set is invalid")

        for name in (
            "rotation-evidence", "public-command-evidence",
            "post-join-reauthentication",
        ):
            evidence = attempt / name
            if not evidence.is_dir():
                raise WindowsIdentityFactoryError(
                    f"{name} retained evidence is unavailable")
            expected_calibration_names = {
                "post-join-generic-prompt.ppm",
                "post-join-generic-prompt.json",
                "post-join-password-target.ppm",
                "post-join-password-target.json",
            }
            if any(
                path.is_symlink()
                or not path.is_file()
                or (
                    name == "post-join-reauthentication"
                    and path.name not in expected_calibration_names
                )
                or (
                    name != "post-join-reauthentication"
                    and path.suffix != ".ppm"
                )
                for path in evidence.iterdir()
            ):
                raise WindowsIdentityFactoryError(
                    f"{name} contains an unexpected retained path")

        files = tuple(
            PurePosixPath(path.relative_to(attempt).as_posix())
            for path in sorted(attempt.rglob("*"))
            if path.is_file() and not path.is_symlink()
        )
    except OSError as error:
        raise WindowsIdentityFactoryError(
            "attempt retained surfaces cannot be inventoried") from error
    active_media = tuple(PurePosixPath(path) for path in (
        "windows.qcow2",
        "OVMF_VARS.fd",
        "runtime/controller/controller.raw",
        "runtime/controller/OVMF_VARS.fd",
        "runtime/controller/guard/controller-overlay.qcow2",
        "runtime/controller/guard/OVMF_VARS.fd",
    ))
    logs = tuple(
        path for path in files if path.suffix in {".log", ".jsonl"})
    artifacts = tuple(
        path for path in files
        if path not in logs and path not in active_media
    )
    return RetainedInventory(
        attempt,
        tracked_artifacts=artifacts,
        logs=logs,
        active_media=active_media,
    )


def default_acceptance_factory(boundary: NativeProcessBoundary):
    """Construct the exact production configuration for a validated attempt."""
    # Imported lazily to keep the CLI dataclass as the public configuration
    # contract without introducing an import cycle at module load time.
    from .windows_identity_cli import AcceptanceConfiguration

    authorization = _authorization(boundary)
    for relative in (
        "runtime",
        "rotation-evidence",
        "public-command-evidence",
        "post-join-reauthentication",
        "acceptance-evidence.jsonl",
    ):
        path = boundary.attempt / relative
        if path.exists() or path.is_symlink():
            raise WindowsIdentityFactoryError(
                "prepared attempt contains stale acceptance state")
    bundle = _source_bundle(boundary, authorization)
    guest, references = _references(authorization)
    del guest
    publication = bundle / "publication.iso"
    try:
        publication_info = publication.lstat()
    except OSError as error:
        raise WindowsIdentityFactoryError(
            "private recovery publication is unavailable") from error
    if (
        stat.S_ISLNK(publication_info.st_mode)
        or not stat.S_ISREG(publication_info.st_mode)
        or stat.S_IMODE(publication_info.st_mode) != 0o600
    ):
        raise WindowsIdentityFactoryError(
            "private recovery publication has an unsafe identity")
    if boundary.authorized_command is None:
        raise WindowsIdentityFactoryError(
            "validated authorized QEMU command is unavailable")

    rotation = ProgressiveRotationPlan(
        sign_in_manifest=REFERENCE_ROOT / "sign-in.json",
        desktop_manifest=REFERENCE_ROOT / "desktop.json",
        security_options_manifest=REFERENCE_ROOT / "security-options.json",
        change_password_manifest=REFERENCE_ROOT / "change-password.json",
        expected_guest=references["sign-in"].guest,
        evidence_root=boundary.attempt / "rotation-evidence",
        change_password_keys=("down", "down", "down", "ret"),
    )
    command = PublicPowerShellLaunchPlan(
        desktop=references["desktop"],
        run_dialog=references["run-dialog"],
    )
    source_inventory = _retained_inventory(bundle / "evidence")

    def scan_secrets(known_secrets: tuple[str, ...]) -> dict[str, object]:
        if (
            boundary.qmp_root is None
            or boundary.serial_socket is None
            or boundary.port is None
            or boundary.processes.get("windows") is None
            or boundary.processes["windows"].poll() is not None
        ):
            raise WindowsIdentityFactoryError(
                "live Windows command is unavailable for diagnostics")
        runtime_command = qemu_identity_command(
            disk=boundary.attempt / "windows.qcow2",
            variables=boundary.attempt / "OVMF_VARS.fd",
            qmp_socket=boundary.qmp_root / "windows.qmp",
            serial_socket=boundary.serial_socket,
            switch_port=boundary.port,
            control_iso=boundary.attempt / "control.iso",
        )
        if (
            boundary._normalized_command(runtime_command)
            != boundary._normalized_command(boundary.authorized_command)
        ):
            raise WindowsIdentityFactoryError(
                "live Windows command differs from authorization")
        controller_console = boundary.controller_console
        if controller_console is None or controller_console.password is None:
            raise WindowsIdentityFactoryError(
                "Controller session credential is outside diagnostics scope")
        try:
            controller_secret = controller_console.password.decode("ascii")
        except UnicodeDecodeError as error:
            raise WindowsIdentityFactoryError(
                "Controller session credential encoding is invalid") from error
        scoped_secrets = known_secrets + (controller_secret,)
        return ProductionSecretScanner(
            retained=(
                source_inventory,
                _attempt_inventory(boundary.attempt),
            ),
            qemu_arguments=tuple(runtime_command),
            credential_ownership=CredentialOwnershipState(
                acceptance_scope_active=True,
                scoped_credentials=len(scoped_secrets),
                credentials_outside_scope=0,
                recovery_publication_exists=(
                    publication.exists() or publication.is_symlink()),
                recovered_credential_invalidated=True,
            ),
        )(scoped_secrets)

    adapter = NativeWindowsAcceptanceAdapter(
        boundary,
        boundary.attempt,
        realm=FactorySpec().realm,
        local_principal="telosadmin",
        scan_secrets=scan_secrets,
        rotation_plan=rotation,
        command_plan=command,
    )
    return AcceptanceConfiguration(
        rotation_plan=rotation,
        publication=publication,
        private_root=boundary.attempt,
        evidence=boundary.attempt / "acceptance-evidence.jsonl",
        realm=FactorySpec().realm,
        callbacks=adapter.callbacks(),
        stage_principals=adapter.stage_principals,
        destroy_principals=adapter.destroy_principals,
        stage_join_principal=adapter.stage_join_principal,
        destroy_join_principal=adapter.destroy_join_principal,
    )
