"""Prove one candidate image root against its role contract and signed seed."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .image_promotion_gate import ImagePromotionGateError, gate_candidate_image
from .package_contract import PROFILE_OVERLAYS


HOMELAB_ROOT = Path(__file__).resolve().parents[1]
# The tracked contract, and only the tracked contract. A promotion gate that
# accepted a caller-supplied registry could be satisfied by supplying a
# permissive one, which would make every promotion it signs off meaningless.
# This is not a default that can be overridden; there is no flag for it.
REGISTRY = HOMELAB_ROOT / "package-contract.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True,
                        choices=sorted(PROFILE_OVERLAYS))
    parser.add_argument("--root", type=Path, required=True,
                        help="candidate image root to audit read-only")
    parser.add_argument("--receipt", type=Path, required=True,
                        help="signed seed receipt that built the candidate")
    parser.add_argument("--evidence", type=Path,
                        help="write the evidence document here instead of stdout")
    args = parser.parse_args(argv)

    try:
        evidence = gate_candidate_image(
            args.profile, REGISTRY, args.root.resolve(), args.receipt)
    except ImagePromotionGateError as error:
        print(f"image promotion gate: {error}", file=sys.stderr)
        return 1
    document = json.dumps(evidence.to_document(), sort_keys=True)
    if args.evidence is None:
        print(document)
        return 0
    try:
        args.evidence.write_text(document + "\n", encoding="utf-8")
    except OSError as error:
        print(f"image promotion gate: cannot write evidence: {error}",
              file=sys.stderr)
        return 1
    print(f"promotion evidence: {args.evidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
