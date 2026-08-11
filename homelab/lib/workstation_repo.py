"""Acquire and verify the offline workstation pacman repository.

The isolated factory fabric resolves no internet mirror, so gate 7's
in-guest ``pacstrap`` must draw the workstation-install package closure from
the disposable Controller.  This module is the acquire-phase counterpart of
``homelab/seed/build.py``: on the ONLINE build host it resolves the full
dependency closure of the ``workstation-install`` profile
(``package_contract.PROFILE_OVERLAYS``) through the host's signed pacman
mirrors, refuses any archive without a detached signature, builds a pacman
repository database with ``repo-add``, and binds every byte in a receipt
mirroring the Controller seed receipt (``package_seed_closure``).

The offline phases (``factory_publication.stage`` and the
``homelab-factory-offline-check`` Make target) only re-verify the receipt;
they never download.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Sequence

try:
    from .package_contract import (
        PACKAGE_RE, PROFILE_OVERLAYS, load_registry, merge_contract)
except ImportError:  # Script-style import with homelab/lib on sys.path.
    from package_contract import (
        PACKAGE_RE, PROFILE_OVERLAYS, load_registry, merge_contract)


ROOT = Path(__file__).resolve().parents[2]
PROFILE = "workstation-install"
# The pacman repository name.  It is also the database file stem, the
# ``[section]`` name the rendered installer writes into the live pacman.conf,
# and the sole repository the guest can reach; keep the three in sync by
# importing this constant, never by retyping the string.
REPO_NAME = "telos-workstation"
DATABASE = f"{REPO_NAME}.db.tar.gz"
RECEIPT_NAME = "receipt.json"
DEFAULT_REPO = ROOT / "homelab/var/media/arch/workstation-repo"
DEFAULT_CONTRACT = ROOT / "homelab/package-contract.json"
# The download configuration is the Controller seed's: host mirrorlist with
# the build-host signature policy (SigLevel Required).
DEFAULT_PACMAN_CONFIG = ROOT / "homelab/seed/pacman.conf"

# Identity grammar mirroring package_seed_closure; the receipts must stay
# mutually reviewable.
ARCHITECTURES = ("any", "x86_64")
ARCHIVE_SUFFIX = ".pkg.tar.zst"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^(?:[0-9]+:)?[A-Za-z0-9._+~]+$")
RELEASE_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
PACKAGE_VERIFICATION = (
    "pacman repository signatures required by build-host policy")


class WorkstationRepoError(RuntimeError):
    """The workstation repository cannot be built or proven safe to serve."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve_contract_packages(contract: Path = DEFAULT_CONTRACT) -> tuple[str, ...]:
    """Resolve the checked-in workstation-install package roots."""
    return merge_contract(
        load_registry(Path(contract)), PROFILE_OVERLAYS[PROFILE]
    ).packages


def _package_identity(archive: str) -> tuple[str, str, str]:
    if not archive.endswith(ARCHIVE_SUFFIX):
        raise WorkstationRepoError(
            f"package archive has unexpected suffix: {archive}")
    identity = archive[: -len(ARCHIVE_SUFFIX)]
    pieces = identity.rsplit("-", 3)
    if len(pieces) != 4:
        raise WorkstationRepoError(
            f"package archive name lacks exact identity: {archive}")
    name, version, release, architecture = pieces
    if not PACKAGE_RE.fullmatch(name):
        raise WorkstationRepoError(
            f"package archive has invalid package name: {archive}")
    if not VERSION_RE.fullmatch(version):
        raise WorkstationRepoError(
            f"package archive has invalid version: {archive}")
    if not RELEASE_RE.fullmatch(release):
        raise WorkstationRepoError(
            f"package archive has invalid release: {archive}")
    if architecture not in ARCHITECTURES:
        raise WorkstationRepoError(
            f"package archive has invalid architecture: {archive}")
    return name, f"{version}-{release}", architecture


def _files(root: Path) -> list[Path]:
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise WorkstationRepoError(
                "workstation repository must not contain symlinks: "
                f"{path.relative_to(root).as_posix()}")
        if path.is_dir():
            raise WorkstationRepoError(
                "workstation repository must stay a flat directory: "
                f"{path.relative_to(root).as_posix()}")
        if not path.is_file():
            raise WorkstationRepoError(
                "workstation repository must not contain special files: "
                f"{path.relative_to(root).as_posix()}")
        files.append(path)
    return files


def build_receipt(
    root: Path,
    requested: Sequence[str],
    *,
    contract_sha256: str,
    created_utc: str | None = None,
) -> dict:
    """Inventory a flat staged repository into its binding receipt value."""
    files = [path for path in _files(Path(root)) if path.name != RECEIPT_NAME]
    packages = [path for path in files if path.name.endswith(ARCHIVE_SUFFIX)]
    if created_utc is None:
        created_utc = dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0).isoformat()
    return {
        "schema": 1,
        "created_utc": created_utc,
        "profile": PROFILE,
        "overlays": list(PROFILE_OVERLAYS[PROFILE]),
        "contract_sha256": contract_sha256,
        "requested_packages": list(requested),
        "repository_database": DATABASE,
        "package_files": [
            {"name": item.name, "bytes": item.stat().st_size,
             "sha256": sha256(item)}
            for item in packages
        ],
        "payload_files": [
            {"path": item.name, "bytes": item.stat().st_size,
             "sha256": sha256(item)}
            for item in files
        ],
        "package_verification": PACKAGE_VERIFICATION,
    }


def _exact_object(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise WorkstationRepoError(f"{context} must be an object")
    unknown = set(value) - fields
    missing = fields - set(value)
    if unknown:
        raise WorkstationRepoError(
            f"{context} has unknown field: {sorted(unknown)[0]}")
    if missing:
        raise WorkstationRepoError(
            f"{context} is missing field: {sorted(missing)[0]}")
    return value


def _string(value: Any, context: str) -> str:
    if type(value) is not str or not value:
        raise WorkstationRepoError(f"{context} must be a nonempty string")
    return value


def _byte_count(value: Any, context: str) -> int:
    if type(value) is not int or value < 0:
        raise WorkstationRepoError(
            f"{context} must be a non-negative integer")
    return value


def parse_receipt(value: Any) -> dict:
    """Validate an already-decoded repository receipt without defaults."""
    raw = _exact_object(value, {
        "schema", "created_utc", "profile", "overlays", "contract_sha256",
        "requested_packages", "repository_database", "package_files",
        "payload_files", "package_verification",
    }, "receipt")
    if type(raw["schema"]) is not int or raw["schema"] != 1:
        raise WorkstationRepoError("receipt.schema must equal 1")
    created = _string(raw["created_utc"], "receipt.created_utc")
    try:
        moment = dt.datetime.fromisoformat(created)
    except ValueError as error:
        raise WorkstationRepoError(
            "receipt.created_utc is not an exact timestamp") from error
    if moment.utcoffset() != dt.timedelta(0):
        raise WorkstationRepoError(
            "receipt.created_utc is not an exact UTC timestamp")
    if raw["profile"] != PROFILE:
        raise WorkstationRepoError(
            f"receipt.profile is not the {PROFILE} profile")
    if raw["overlays"] != list(PROFILE_OVERLAYS[PROFILE]):
        raise WorkstationRepoError(
            "receipt.overlays differ from the workstation-install profile")
    contract_digest = _string(raw["contract_sha256"], "receipt.contract_sha256")
    if not SHA256_RE.fullmatch(contract_digest):
        raise WorkstationRepoError(
            "receipt.contract_sha256 is not an exact digest")
    if raw["repository_database"] != DATABASE:
        raise WorkstationRepoError(
            "receipt.repository_database is not the workstation repository")
    if raw["package_verification"] != PACKAGE_VERIFICATION:
        raise WorkstationRepoError(
            "receipt.package_verification is not the signed policy")

    if type(raw["requested_packages"]) is not list or not raw["requested_packages"]:
        raise WorkstationRepoError(
            "receipt.requested_packages must be a nonempty array")
    requested: list[str] = []
    for index, item in enumerate(raw["requested_packages"]):
        package = _string(item, f"receipt.requested_packages[{index}]")
        if not PACKAGE_RE.fullmatch(package):
            raise WorkstationRepoError(
                f"receipt has invalid requested package: {package}")
        requested.append(package)
    if len(set(requested)) != len(requested):
        raise WorkstationRepoError("receipt.requested_packages has duplicates")

    if type(raw["payload_files"]) is not list or not raw["payload_files"]:
        raise WorkstationRepoError(
            "receipt.payload_files must be a nonempty array")
    payloads: dict[str, tuple[int, str]] = {}
    for index, item in enumerate(raw["payload_files"]):
        entry = _exact_object(
            item, {"path", "bytes", "sha256"},
            f"receipt.payload_files[{index}]")
        path = _string(entry["path"], f"receipt.payload_files[{index}].path")
        if "/" in path or path in {".", ".."} or any(
                ord(character) < 32 or ord(character) == 127
                for character in path):
            raise WorkstationRepoError(
                f"payload path is not a flat file name: {path}")
        size = _byte_count(
            entry["bytes"], f"receipt.payload_files[{index}].bytes")
        digest = _string(
            entry["sha256"], f"receipt.payload_files[{index}].sha256")
        if not SHA256_RE.fullmatch(digest):
            raise WorkstationRepoError(
                f"payload file has invalid digest: {path}")
        if path in payloads:
            raise WorkstationRepoError(f"duplicate payload file path: {path}")
        if path == RECEIPT_NAME:
            raise WorkstationRepoError(
                "receipt.payload_files must not include receipt.json")
        payloads[path] = (size, digest)
    if DATABASE not in payloads:
        raise WorkstationRepoError(
            "repository payload lacks the pacman database")
    if payloads[DATABASE][0] == 0:
        raise WorkstationRepoError("pacman repository database is empty")

    if type(raw["package_files"]) is not list or not raw["package_files"]:
        raise WorkstationRepoError(
            "receipt.package_files must be a nonempty array")
    packages: dict[str, str] = {}
    for index, item in enumerate(raw["package_files"]):
        entry = _exact_object(
            item, {"name", "bytes", "sha256"},
            f"receipt.package_files[{index}]")
        archive = _string(entry["name"], f"receipt.package_files[{index}].name")
        size = _byte_count(
            entry["bytes"], f"receipt.package_files[{index}].bytes")
        if size == 0:
            raise WorkstationRepoError(f"package archive is empty: {archive}")
        digest = _string(
            entry["sha256"], f"receipt.package_files[{index}].sha256")
        if not SHA256_RE.fullmatch(digest):
            raise WorkstationRepoError(
                f"package archive has invalid digest: {archive}")
        name, _version, _architecture = _package_identity(archive)
        if name in packages:
            raise WorkstationRepoError(
                f"duplicate repository package identity: {name}")
        payload = payloads.get(archive)
        if payload is None:
            raise WorkstationRepoError(
                f"package archive is absent from payload: {archive}")
        if payload != (size, digest):
            raise WorkstationRepoError(
                f"package archive differs from payload: {archive}")
        signature = payloads.get(archive + ".sig")
        if signature is None:
            raise WorkstationRepoError(
                f"package archive has no detached signature: {archive}")
        if signature[0] == 0:
            raise WorkstationRepoError(
                f"package signature is empty: {archive}")
        packages[name] = archive

    absent = sorted(set(requested) - set(packages))
    if absent:
        raise WorkstationRepoError(
            f"requested package is absent from the closure: {absent[0]}")
    return raw


def verify_repo(
    root: Path,
    *,
    contract_packages: Sequence[str] | None = None,
) -> dict:
    """Prove a cached repository byte-for-byte against its receipt.

    When *contract_packages* is supplied (the current checked-in
    workstation-install resolution), a receipt whose requested set drifted
    from the contract is refused: the factory must never exercise a package
    contract its offline repository cannot satisfy.
    """
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise WorkstationRepoError(
            f"workstation repository is missing: {root}")
    receipt_path = root / RECEIPT_NAME
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise WorkstationRepoError(
            f"workstation repository is unsealed (no receipt): {root}")
    try:
        receipt = parse_receipt(
            json.loads(receipt_path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WorkstationRepoError(
            f"workstation repository receipt is unreadable: {error}"
        ) from error
    if contract_packages is not None and (
            set(receipt["requested_packages"]) != set(contract_packages)):
        raise WorkstationRepoError(
            "workstation repository was acquired for a different package "
            "contract; re-run the acquire target")
    listed = {
        entry["path"]: (entry["bytes"], entry["sha256"])
        for entry in receipt["payload_files"]
    }
    actual = {
        path.name: path
        for path in _files(root)
        if path.name != RECEIPT_NAME
    }
    for name in sorted(set(listed) - set(actual)):
        raise WorkstationRepoError(f"receipt-listed file is missing: {name}")
    for name in sorted(set(actual) - set(listed)):
        raise WorkstationRepoError(f"unlisted file in repository: {name}")
    total = 0
    for name, path in sorted(actual.items()):
        size, digest = listed[name]
        if path.stat().st_size != size or sha256(path) != digest:
            raise WorkstationRepoError(
                f"repository file differs from its receipt: {name}")
        total += size
    return {
        "packages": len(receipt["package_files"]),
        "bytes": total,
        "database": DATABASE,
        "receipt_sha256": sha256(receipt_path),
    }


def command_plan(
    packages: Sequence[str], work: Path, pacman_config: Path,
) -> list[list[str]]:
    """The networked acquire phases, for review without downloading."""
    stage = Path(work) / "repo"
    database = Path(work) / "pacman-db"
    return [
        [
            "fakeroot", "pacman", "--config", str(pacman_config),
            "-Syw", "--noconfirm",
            "--dbpath", str(database), "--cachedir", str(stage),
            "--", *packages,
        ],
        [
            "repo-add", str(stage / DATABASE),
            f"{stage}/<downloaded>{ARCHIVE_SUFFIX}",
        ],
    ]


def _materialize_links(stage: Path) -> None:
    """Replace repo-add's convenience symlinks with their exact bytes.

    ``repo-add`` leaves ``<repo>.db`` and ``<repo>.files`` as symlinks to the
    ``.tar.gz`` archives.  Symlinks are not valid publication payloads (the
    release rules refuse them), and pacman fetches ``<repo>.db`` by that
    exact name, so each link becomes a regular file with identical content.
    """
    for path in sorted(stage.iterdir()):
        if not path.is_symlink():
            continue
        target = (path.parent / os.readlink(path)).resolve()
        if target.parent != stage.resolve() or not target.is_file():
            raise WorkstationRepoError(
                f"repository symlink escapes the staging directory: {path.name}")
        content = target.read_bytes()
        path.unlink()
        path.write_bytes(content)


def build(
    output: Path,
    *,
    contract: Path = DEFAULT_CONTRACT,
    pacman_config: Path = DEFAULT_PACMAN_CONFIG,
    runner: Callable[..., object] = subprocess.run,
) -> dict:
    """Acquire the signed closure and atomically publish the local cache.

    ONLINE acquire phase only.  Deterministic given a resolved package set:
    everything except ``created_utc`` is a pure function of the downloaded
    signed archives and the checked-in contract.
    """
    output = Path(output)
    if output.is_symlink():
        raise WorkstationRepoError(
            "workstation repository cache must not be a symlink")
    contract = Path(contract)
    packages = resolve_contract_packages(contract)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
            prefix=".workstation-repo-", dir=output.parent) as temporary:
        work = Path(temporary)
        stage = work / "repo"
        stage.mkdir()
        database = work / "pacman-db"
        (database / "local").mkdir(parents=True)
        runner(
            [
                "fakeroot", "pacman", "--config", str(pacman_config),
                "-Syw", "--noconfirm",
                "--dbpath", str(database), "--cachedir", str(stage),
                "--", *packages,
            ],
            check=True,
        )
        archives = sorted(stage.glob(f"*{ARCHIVE_SUFFIX}"))
        if not archives:
            raise WorkstationRepoError("pacman downloaded no package archives")
        names = set()
        for archive in archives:
            if not Path(f"{archive}.sig").is_file():
                raise WorkstationRepoError(
                    f"package has no detached signature: {archive.name}")
            name, _version, _architecture = _package_identity(archive.name)
            names.add(name)
        missing = sorted(set(packages) - names)
        if missing:
            raise WorkstationRepoError(
                f"requested package is absent from the closure: {missing[0]}")
        runner(
            ["repo-add", str(stage / DATABASE),
             *[str(item) for item in archives]],
            check=True,
        )
        if not (stage / DATABASE).exists():
            raise WorkstationRepoError(
                "repo-add did not produce the repository database")
        _materialize_links(stage)
        receipt = build_receipt(
            stage, packages, contract_sha256=sha256(contract))
        (stage / RECEIPT_NAME).write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        summary = verify_repo(stage, contract_packages=packages)
        replaced = None
        if output.exists():
            replaced = output.with_name(
                f".{output.name}.replaced.{os.getpid()}")
            os.replace(output, replaced)
        try:
            os.replace(stage, output)
        except OSError:
            if replaced is not None:
                os.replace(replaced, output)
            raise
        if replaced is not None:
            shutil.rmtree(replaced)
        return summary
