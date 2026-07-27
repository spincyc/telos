#!/usr/bin/env python3
"""Verify a staged Windows WinPE payload without modifying it."""

from __future__ import annotations

import argparse
from pathlib import Path

from common import verify_release


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("release_dir", type=Path)
    args = parser.parse_args()
    errors = verify_release(args.release_dir.resolve())
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print(f"PASS: {args.release_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
