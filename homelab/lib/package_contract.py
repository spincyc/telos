"""Strict package and executable ownership contracts for homelab images."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import re
from types import MappingProxyType
from typing import Any


PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9@._+-]*$")
OVERLAY_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
# Declared units carry an explicit suffix. systemd resolves a bare name to
# `.service`, so the contract records the resolved name and never the shorthand.
UNIT_RE = re.compile(r"^[a-z0-9][a-z0-9@._-]*\.(?:service|timer|socket)$")
EXPECTED_OVERLAYS = (
    "installer-live",
    "controller-network",
    "controller-domain",
    "controller-factory",
    "identity-client",
    "automatic-updates",
    "workstation",
    "services",
    "image-build-host",
)
PROFILE_OVERLAYS = MappingProxyType({
    "installer-live": ("installer-live",),
    "controller-seed": (
        "controller-network",
        "controller-domain",
        "controller-factory",
        "identity-client",
        "services",
        "image-build-host",
    ),
    "workstation-install": (
        "identity-client",
        "automatic-updates",
        "workstation",
    ),
})


class PackageContractError(ValueError):
    """The package contract is malformed or cannot be merged."""


@dataclass(frozen=True, order=True)
class BinaryOwnership:
    path: str
    owner: str


@dataclass(frozen=True)
class PackageLayer:
    packages: tuple[str, ...]
    binaries: tuple[BinaryOwnership, ...]
    services: tuple[str, ...] = ()


@dataclass(frozen=True)
class PackageRegistry:
    schema_version: int
    common: PackageLayer
    overlays: dict[str, PackageLayer]


@dataclass(frozen=True)
class MergedPackageContract:
    overlays: tuple[str, ...]
    packages: tuple[str, ...]
    binaries: tuple[BinaryOwnership, ...]
    services: tuple[str, ...] = ()


def _exact_object(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise PackageContractError(f"{context} must be an object")
    unknown = set(value) - fields
    missing = fields - set(value)
    if unknown:
        raise PackageContractError(
            f"{context} has unknown field: {sorted(unknown)[0]}")
    if missing:
        raise PackageContractError(
            f"{context} is missing field: {sorted(missing)[0]}")
    return value


def _string(value: Any, context: str) -> str:
    if type(value) is not str or not value:
        raise PackageContractError(f"{context} must be a nonempty string")
    return value


def _layer(value: Any, context: str) -> PackageLayer:
    raw = _exact_object(value, {"packages", "binaries", "services"}, context)
    if type(raw["packages"]) is not list:
        raise PackageContractError(f"{context}.packages must be an array")
    packages = tuple(
        _string(item, f"{context}.packages[{index}]")
        for index, item in enumerate(raw["packages"])
    )
    for package in packages:
        if not PACKAGE_RE.fullmatch(package):
            raise PackageContractError(
                f"{context} has invalid package name: {package}")
    if len(set(packages)) != len(packages):
        raise PackageContractError(f"{context} has duplicate packages")

    if type(raw["binaries"]) is not list:
        raise PackageContractError(f"{context}.binaries must be an array")
    binaries: list[BinaryOwnership] = []
    for index, item in enumerate(raw["binaries"]):
        binary = _exact_object(
            item, {"path", "owner"}, f"{context}.binaries[{index}]")
        path = _string(binary["path"], f"{context}.binaries[{index}].path")
        owner = _string(binary["owner"], f"{context}.binaries[{index}].owner")
        normalized = str(PurePosixPath(path))
        if (not path.startswith("/") or path == "/" or normalized != path
                or "//" in path or ".." in PurePosixPath(path).parts
                or any(ord(character) < 32 or ord(character) == 127
                       for character in path)):
            raise PackageContractError(
                f"{context} has non-normalized absolute binary path: {path}")
        if not PACKAGE_RE.fullmatch(owner):
            raise PackageContractError(
                f"{context} has invalid binary owner: {owner}")
        binaries.append(BinaryOwnership(path=path, owner=owner))
    if len({item.path for item in binaries}) != len(binaries):
        raise PackageContractError(f"{context} has duplicate binary paths")

    if type(raw["services"]) is not list:
        raise PackageContractError(f"{context}.services must be an array")
    services = tuple(
        _string(item, f"{context}.services[{index}]")
        for index, item in enumerate(raw["services"])
    )
    for service in services:
        if not UNIT_RE.fullmatch(service):
            raise PackageContractError(
                f"{context} has invalid service unit: {service}")
    if len(set(services)) != len(services):
        raise PackageContractError(f"{context} has duplicate services")
    return PackageLayer(
        packages=tuple(sorted(packages)),
        binaries=tuple(sorted(binaries)),
        services=tuple(sorted(services)),
    )


def parse_registry(value: Any) -> PackageRegistry:
    """Validate an already-decoded registry without applying defaults."""
    raw = _exact_object(
        value, {"schema_version", "common", "overlays"}, "registry")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise PackageContractError("registry.schema_version must equal 1")
    common = _layer(raw["common"], "registry.common")
    if type(raw["overlays"]) is not dict:
        raise PackageContractError("registry.overlays must be an object")
    if set(raw["overlays"]) != set(EXPECTED_OVERLAYS):
        unknown = set(raw["overlays"]) - set(EXPECTED_OVERLAYS)
        missing = set(EXPECTED_OVERLAYS) - set(raw["overlays"])
        detail = (
            f"unknown overlay: {sorted(unknown)[0]}" if unknown
            else f"missing overlay: {sorted(missing)[0]}"
        )
        raise PackageContractError(f"registry.overlays has {detail}")
    overlays = {
        name: _layer(raw["overlays"][name], f"registry.overlays.{name}")
        for name in EXPECTED_OVERLAYS
    }

    for name, layer in overlays.items():
        for package in layer.packages:
            if package in common.packages:
                raise PackageContractError(
                    f"package {package} collides between common and {name}")
        for binary in layer.binaries:
            if binary.path in {item.path for item in common.binaries}:
                raise PackageContractError(
                    f"binary {binary.path} collides between common and {name}")
        for service in layer.services:
            if service in common.services:
                raise PackageContractError(
                    f"service {service} collides between common and {name}")
        merged_packages = set(common.packages) | set(layer.packages)
        for binary in (*common.binaries, *layer.binaries):
            if binary.owner not in merged_packages:
                raise PackageContractError(
                    f"{name} binary owner is absent from the merged package "
                    f"set: {binary.owner}")
    return PackageRegistry(1, common, overlays)


def load_registry(path: Path) -> PackageRegistry:
    def exact_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PackageContractError(
                    f"package registry has duplicate object key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=exact_pairs,
        )
    except (
        OSError, UnicodeError, json.JSONDecodeError, PackageContractError,
    ) as error:
        raise PackageContractError(f"cannot read package registry: {error}") from error
    return parse_registry(value)


def merge_contract(
    registry: PackageRegistry, selected_overlays: list[str] | tuple[str, ...]
) -> MergedPackageContract:
    """Merge common with an explicit overlay selection deterministically."""
    if type(selected_overlays) not in (list, tuple):
        raise PackageContractError("overlay selection must be an array")
    selected = tuple(
        _string(name, f"overlay selection[{index}]")
        for index, name in enumerate(selected_overlays)
    )
    if len(set(selected)) != len(selected):
        raise PackageContractError("overlay selection has duplicates")
    unknown = set(selected) - set(registry.overlays)
    if unknown:
        raise PackageContractError(f"unknown overlay: {sorted(unknown)[0]}")
    canonical = tuple(name for name in EXPECTED_OVERLAYS if name in selected)
    layers = (registry.common, *(registry.overlays[name] for name in canonical))
    packages = tuple(sorted({
        package for layer in layers for package in layer.packages
    }))
    binaries_by_path: dict[str, BinaryOwnership] = {}
    for layer in layers:
        for binary in layer.binaries:
            previous = binaries_by_path.setdefault(binary.path, binary)
            if previous.owner != binary.owner:
                raise PackageContractError(
                    f"binary {binary.path} has conflicting owners: "
                    f"{previous.owner} and {binary.owner}")
    absent = sorted({
        binary.owner for binary in binaries_by_path.values()
    } - set(packages))
    if absent:
        raise PackageContractError(
            f"binary owner is absent from merged package set: {absent[0]}")
    return MergedPackageContract(
        overlays=canonical,
        packages=packages,
        binaries=tuple(sorted(binaries_by_path.values())),
        services=tuple(sorted({
            service for layer in layers for service in layer.services
        })),
    )
