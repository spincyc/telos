"""Reconcile package contracts and roots against the signed seed receipt."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import re
from typing import Any

from .package_contract import MergedPackageContract, PACKAGE_RE
from .package_root_gate import PackageRootEvidence


ARCHITECTURES = ("any", "x86_64")
ARCHIVE_SUFFIX = ".pkg.tar.zst"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^(?:[0-9]+:)?[A-Za-z0-9._+~]+$")
RELEASE_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
PACKAGE_VERIFICATION = (
    "pacman repository signatures required by build-host policy")
REPOSITORY_DATABASE = "packages/telos.db.tar.gz"


class SeedClosureError(ValueError):
    """The seed receipt cannot prove the required package closure."""


@dataclass(frozen=True, order=True)
class SeedPackage:
    name: str
    version: str
    architecture: str
    archive: str
    sha256: str


@dataclass(frozen=True)
class SeedReceipt:
    source_commit: str
    source_sha256: str
    requested_packages: tuple[str, ...]
    packages: tuple[SeedPackage, ...]


@dataclass(frozen=True)
class SeedClosureEvidence:
    source_commit: str
    seed_packages: tuple[SeedPackage, ...]
    contract_packages: tuple[str, ...]
    accounted_installed: tuple[tuple[str, str], ...]


def _fail(message: str) -> SeedClosureError:
    return SeedClosureError(message)


def _exact_object(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise _fail(f"{context} must be an object")
    unknown = set(value) - fields
    missing = fields - set(value)
    if unknown:
        raise _fail(f"{context} has unknown field: {sorted(unknown)[0]}")
    if missing:
        raise _fail(f"{context} is missing field: {sorted(missing)[0]}")
    return value


def _string(value: Any, context: str) -> str:
    if type(value) is not str or not value:
        raise _fail(f"{context} must be a nonempty string")
    return value


def _byte_count(value: Any, context: str) -> int:
    if type(value) is not int or value < 0:
        raise _fail(f"{context} must be a non-negative integer")
    return value


def _created_utc(value: Any) -> None:
    text = _string(value, "receipt.created_utc")
    try:
        moment = dt.datetime.fromisoformat(text)
    except ValueError as error:
        raise _fail("receipt.created_utc is not an exact timestamp") from error
    if moment.utcoffset() != dt.timedelta(0):
        raise _fail("receipt.created_utc is not an exact UTC timestamp")


def _payload_path(value: Any, context: str) -> str:
    path = _string(value, context)
    parts = path.split("/")
    if ("" in parts or "." in parts or ".." in parts
            or any(ord(character) < 32 or ord(character) == 127
                   for character in path)):
        raise _fail(f"{context} is not a normalized relative path: {path}")
    return path


def _package_identity(archive: str) -> tuple[str, str, str]:
    if not archive.endswith(ARCHIVE_SUFFIX):
        raise _fail(f"package archive has unexpected suffix: {archive}")
    identity = archive[:-len(ARCHIVE_SUFFIX)]
    pieces = identity.rsplit("-", 3)
    if len(pieces) != 4:
        raise _fail(f"package archive name lacks exact identity: {archive}")
    name, version, release, architecture = pieces
    if not PACKAGE_RE.fullmatch(name):
        raise _fail(f"package archive has invalid package name: {archive}")
    if not VERSION_RE.fullmatch(version):
        raise _fail(f"package archive has invalid version: {archive}")
    if not RELEASE_RE.fullmatch(release):
        raise _fail(f"package archive has invalid release: {archive}")
    if architecture not in ARCHITECTURES:
        raise _fail(f"package archive has invalid architecture: {archive}")
    return name, f"{version}-{release}", architecture


def parse_seed_receipt(value: Any) -> SeedReceipt:
    """Validate an already-decoded seed receipt without applying defaults."""
    raw = _exact_object(value, {
        "schema", "created_utc", "source", "requested_packages",
        "package_files", "payload_files", "package_verification",
        "private_configuration_included",
    }, "receipt")
    if type(raw["schema"]) is not int or raw["schema"] != 1:
        raise _fail("receipt.schema must equal 1")
    _created_utc(raw["created_utc"])
    if raw["package_verification"] != PACKAGE_VERIFICATION:
        raise _fail("receipt.package_verification is not the signed policy")
    if raw["private_configuration_included"] is not False:
        raise _fail("receipt.private_configuration_included must be false")

    source = _exact_object(
        raw["source"], {"commit", "archive", "sha256", "tracked_files_only"},
        "receipt.source")
    commit = _string(source["commit"], "receipt.source.commit")
    if not COMMIT_RE.fullmatch(commit):
        raise _fail("receipt.source.commit is not an exact commit")
    source_sha256 = _string(source["sha256"], "receipt.source.sha256")
    if not SHA256_RE.fullmatch(source_sha256):
        raise _fail("receipt.source.sha256 is not an exact digest")
    if source["archive"] != "source/telos.tar.gz":
        raise _fail("receipt.source.archive is not the tracked source archive")
    if source["tracked_files_only"] is not True:
        raise _fail("receipt.source.tracked_files_only must be true")

    if type(raw["requested_packages"]) is not list or not raw["requested_packages"]:
        raise _fail("receipt.requested_packages must be a nonempty array")
    requested: list[str] = []
    for index, item in enumerate(raw["requested_packages"]):
        package = _string(item, f"receipt.requested_packages[{index}]")
        if not PACKAGE_RE.fullmatch(package):
            raise _fail(f"receipt has invalid requested package: {package}")
        requested.append(package)
    if len(set(requested)) != len(requested):
        raise _fail("receipt.requested_packages has duplicates")

    if type(raw["payload_files"]) is not list or not raw["payload_files"]:
        raise _fail("receipt.payload_files must be a nonempty array")
    payloads: dict[str, tuple[int, str]] = {}
    for index, item in enumerate(raw["payload_files"]):
        entry = _exact_object(
            item, {"path", "bytes", "sha256"},
            f"receipt.payload_files[{index}]")
        path = _payload_path(entry["path"], f"receipt.payload_files[{index}].path")
        size = _byte_count(entry["bytes"], f"receipt.payload_files[{index}].bytes")
        digest = _string(
            entry["sha256"], f"receipt.payload_files[{index}].sha256")
        if not SHA256_RE.fullmatch(digest):
            raise _fail(f"payload file has invalid digest: {path}")
        if path in payloads:
            raise _fail(f"duplicate payload file path: {path}")
        if path == "receipt.json" or path.rsplit("/", 1)[-1] == "receipt.json":
            raise _fail("receipt.payload_files must not include receipt.json")
        payloads[path] = (size, digest)
    if REPOSITORY_DATABASE not in payloads:
        raise _fail("seed payload lacks the package repository database")

    if type(raw["package_files"]) is not list or not raw["package_files"]:
        raise _fail("receipt.package_files must be a nonempty array")
    packages: dict[str, SeedPackage] = {}
    for index, item in enumerate(raw["package_files"]):
        entry = _exact_object(
            item, {"name", "bytes", "sha256"},
            f"receipt.package_files[{index}]")
        archive = _string(entry["name"], f"receipt.package_files[{index}].name")
        if "/" in archive:
            raise _fail(f"package archive name is not a file name: {archive}")
        size = _byte_count(entry["bytes"], f"receipt.package_files[{index}].bytes")
        if size == 0:
            raise _fail(f"package archive is empty: {archive}")
        digest = _string(
            entry["sha256"], f"receipt.package_files[{index}].sha256")
        if not SHA256_RE.fullmatch(digest):
            raise _fail(f"package archive has invalid digest: {archive}")
        name, version, architecture = _package_identity(archive)
        if name in packages:
            raise _fail(f"duplicate seed package identity: {name}")
        payload = payloads.get(f"packages/{archive}")
        if payload is None:
            raise _fail(f"package archive is absent from payload: {archive}")
        if payload != (size, digest):
            raise _fail(f"package archive differs from payload: {archive}")
        signature = payloads.get(f"packages/{archive}.sig")
        if signature is None:
            raise _fail(f"package archive has no detached signature: {archive}")
        if signature[0] == 0:
            raise _fail(f"package signature is empty: {archive}")
        packages[name] = SeedPackage(
            name=name,
            version=version,
            architecture=architecture,
            archive=archive,
            sha256=digest,
        )

    absent = sorted(set(requested) - set(packages))
    if absent:
        raise _fail(f"requested package is absent from the closure: {absent[0]}")
    return SeedReceipt(
        source_commit=commit,
        source_sha256=source_sha256,
        requested_packages=tuple(requested),
        packages=tuple(sorted(packages.values())),
    )


def reconcile_seed_closure(
    receipt: SeedReceipt,
    contract: MergedPackageContract,
    evidence: PackageRootEvidence,
) -> SeedClosureEvidence:
    """Prove the contract and audited root are accounted for by the seed."""
    if type(receipt) is not SeedReceipt:
        raise _fail("receipt must be a parsed seed receipt")
    if type(contract) is not MergedPackageContract:
        raise _fail("contract must be a merged package contract")
    if type(evidence) is not PackageRootEvidence:
        raise _fail("evidence must be package root evidence")
    if evidence.required_packages != contract.packages:
        raise _fail("root evidence was audited against a different contract")
    closure = {package.name: package for package in receipt.packages}
    missing = sorted(set(contract.packages) - set(closure))
    if missing:
        raise _fail(
            f"required package is absent from the seed closure: {missing[0]}")
    accounted: list[tuple[str, str]] = []
    for installed in evidence.installed_packages:
        seed = closure.get(installed.name)
        if seed is None:
            raise _fail(
                f"installed package is absent from the seed closure: "
                f"{installed.name}")
        if seed.version != installed.version:
            raise _fail(
                f"installed package differs from the seed closure: "
                f"{installed.name} {installed.version} != {seed.version}")
        accounted.append((installed.name, installed.version))
    return SeedClosureEvidence(
        source_commit=receipt.source_commit,
        seed_packages=receipt.packages,
        contract_packages=contract.packages,
        accounted_installed=tuple(accounted),
    )
