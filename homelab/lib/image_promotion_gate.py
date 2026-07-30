"""One static promotion gate for every completed Arch-derived image root."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from .package_contract import (
    PROFILE_OVERLAYS,
    PackageContractError,
    load_registry,
    merge_contract,
)
from .package_root_gate import (
    PackageRootEvidence,
    PackageRootGateError,
    audit_package_root,
)
from .package_seed_closure import (
    SeedClosureError,
    SeedClosureEvidence,
    parse_seed_receipt,
    reconcile_seed_closure,
)


RECEIPT_LIMIT = 16 * 1024 * 1024


class ImagePromotionGateError(RuntimeError):
    """The candidate image cannot supply complete promotion evidence."""


@dataclass(frozen=True)
class ImagePromotionEvidence:
    profile: str
    overlays: tuple[str, ...]
    root: PackageRootEvidence
    closure: SeedClosureEvidence

    declared_services: tuple[str, ...] = ()

    def to_document(self) -> dict[str, Any]:
        """Render one machine-readable, secret-free evidence document.

        `declared_services` records what the merged contract requires, not what
        was observed: proving a unit is enabled and running needs the separate
        boot gate.
        """
        return {
            "schema": 1,
            "kind": "image-promotion-static-evidence",
            "profile": self.profile,
            "overlays": list(self.overlays),
            "declared_services": list(self.declared_services),
            "services_verified": False,
            "root": self.root.root,
            "seed_source_commit": self.closure.source_commit,
            "contract_packages": list(self.closure.contract_packages),
            "accounted_installed": [
                {"name": name, "version": version}
                for name, version in self.closure.accounted_installed
            ],
            "binaries": [
                {
                    "path": binary.path,
                    "owner": binary.owner,
                    "resolved_path": binary.resolved_path,
                }
                for binary in self.root.binaries
            ],
        }


def _fail(stage: str, error: Exception) -> ImagePromotionGateError:
    return ImagePromotionGateError(f"{stage}: {error}")


def _read_receipt(path: Path) -> Any:
    def exact_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SeedClosureError(
                    f"seed receipt has duplicate object key: {key}")
            result[key] = value
        return result

    try:
        raw = path.read_bytes()
        if len(raw) > RECEIPT_LIMIT:
            raise SeedClosureError("seed receipt is too large")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=exact_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SeedClosureError(f"cannot read seed receipt: {error}") from error


def gate_candidate_image(
    profile: str,
    registry_path: Path,
    root: Path,
    receipt_path: Path,
) -> ImagePromotionEvidence:
    """Prove one candidate root satisfies its profile contract and seed."""
    overlays = PROFILE_OVERLAYS.get(profile)
    if overlays is None:
        raise ImagePromotionGateError(f"unknown image profile: {profile}")
    try:
        contract = merge_contract(load_registry(registry_path), overlays)
    except PackageContractError as error:
        raise _fail("contract", error) from error
    try:
        root_evidence = audit_package_root(root, contract)
    except PackageRootGateError as error:
        raise _fail("root-audit", error) from error
    try:
        receipt = parse_seed_receipt(_read_receipt(receipt_path))
        closure = reconcile_seed_closure(receipt, contract, root_evidence)
    except SeedClosureError as error:
        raise _fail("seed-closure", error) from error
    return ImagePromotionEvidence(
        profile=profile,
        overlays=contract.overlays,
        root=root_evidence,
        closure=closure,
        declared_services=contract.services,
    )
