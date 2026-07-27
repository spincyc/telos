#!/usr/bin/env python3
"""Build a secret-free, offline Controller seed ISO from public Telos."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PACKAGES = Path(__file__).with_name("packages.txt")
PACMAN_CONFIG = Path(__file__).with_name("pacman.conf")
DEFAULT_OUTPUT = ROOT / "homelab/var/seed/telos-controller-seed.iso"
FORBIDDEN_SOURCE_PARTS = {
    "private", "secret", "secrets", ".env", "id_rsa", "id_ed25519",
}
FORBIDDEN_TEXT_MARKERS = (
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
)
PUBLIC_TEST_FIXTURE_ALLOWLIST = {
    "homelab/seed/build.py",
    "homelab/tests/test_image.py",
    "homelab/tests/test_manifest.py",
    "homelab/tests/test_seed_build.py",
    "homelab/tests/test_seed_security.py",
}


def package_names(path: Path) -> list[str]:
    names = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        value = raw.split("#", 1)[0].strip()
        if value:
            names.append(value)
    if not names or len(names) != len(set(names)):
        raise ValueError("package list must be nonempty and contain no duplicates")
    return names


def command_plan(packages: list[str], stage: Path, output: Path) -> list[list[str]]:
    cache = stage / "packages"
    database = stage / ".pacman-db"
    return [
        [
            "fakeroot", "pacman", "--config", str(PACMAN_CONFIG),
            "-Syw", "--noconfirm",
            "--dbpath", str(database), "--cachedir", str(cache),
            "--", *packages,
        ],
        [
            "repo-add", str(cache / "telos.db.tar.gz"),
            *[str(item) for item in sorted(cache.glob("*.pkg.tar.zst"))],
        ],
        [
            "xorriso", "-as", "mkisofs", "-volid", "TELOS_SEED", "-r", "-J",
            "-o", str(output), str(stage),
        ],
    ]


def run(args: list[str], *, stdout=None) -> None:
    subprocess.run(args, cwd=ROOT, check=True, stdout=stdout)


def git_text(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, text=True
    ).strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_public_source() -> None:
    tracked = git_text("ls-tree", "-r", "--name-only", "HEAD").splitlines()
    rejected = []
    for path in tracked:
        lowered = path.lower()
        components = set(Path(lowered).parts)
        if (
            lowered.startswith("homelab/instance/")
            or lowered.startswith("telos-private/")
            or components.intersection(FORBIDDEN_SOURCE_PARTS)
            or lowered.endswith((".pem", ".p12", ".pfx"))
        ):
            rejected.append(path)
    if rejected:
        raise ValueError(f"refusing private-looking tracked path: {rejected[0]}")
    grep = subprocess.run(
        [
            "git", "grep", "-Il",
            *[value for marker in FORBIDDEN_TEXT_MARKERS for value in ("-e", marker.decode())],
            "HEAD",
        ],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, check=False,
    )
    if grep.returncode not in (0, 1):
        raise RuntimeError("could not scan committed source for private-key material")
    marker_paths = {
        line.removeprefix("HEAD:")
        for line in grep.stdout.splitlines()
        if line.removeprefix("HEAD:") not in PUBLIC_TEST_FIXTURE_ALLOWLIST
    }
    if marker_paths:
        raise ValueError(
            f"refusing private-key material in tracked path: "
            f"{sorted(marker_paths)[0]}"
        )


def source_snapshot(destination: Path) -> dict[str, object]:
    validate_public_source()
    commit = git_text("rev-parse", "HEAD")
    destination.parent.mkdir(parents=True)
    with destination.open("wb") as stream:
        run(["git", "archive", "--format=tar.gz", "--prefix=telos/", commit], stdout=stream)
    return {
        "commit": commit,
        "archive": destination.relative_to(destination.parents[1]).as_posix(),
        "sha256": sha256(destination),
        "tracked_files_only": True,
    }


def write_receipt(stage: Path, packages: list[str], source: dict[str, object]) -> None:
    package_files = sorted((stage / "packages").glob("*.pkg.tar.zst"))
    payload_files = sorted(
        item for item in stage.rglob("*") if item.is_file() and item.name != "receipt.json"
    )
    receipt = {
        "schema": 1,
        "created_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "source": source,
        "requested_packages": packages,
        "package_files": [
            {"name": item.name, "bytes": item.stat().st_size, "sha256": sha256(item)}
            for item in package_files
        ],
        "payload_files": [
            {
                "path": item.relative_to(stage).as_posix(),
                "bytes": item.stat().st_size,
                "sha256": sha256(item),
            }
            for item in payload_files
        ],
        "package_verification": "pacman repository signatures required by build-host policy",
        "private_configuration_included": False,
    }
    (stage / "receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def build(output: Path, package_file: Path) -> None:
    packages = package_names(package_file)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".seed-", dir=output.parent) as temporary:
        work = Path(temporary)
        stage = work / "root"
        cache = stage / "packages"
        cache.mkdir(parents=True)
        database = work / "pacman-db"
        (database / "local").mkdir(parents=True)
        shutil.copy2(Path(__file__).with_name("install-controller-deps"), stage)
        shutil.copy2(Path(__file__).with_name("install-controller"), stage)
        shutil.copy2(Path(__file__).with_name("verify-seed"), stage)
        shutil.copy2(package_file, stage / "packages.txt")
        shutil.copy2(PACMAN_CONFIG, stage / "pacman.conf")

        run([
            "fakeroot", "pacman", "--config", str(PACMAN_CONFIG),
            "-Syw", "--noconfirm",
            "--dbpath", str(database), "--cachedir", str(cache),
            "--", *packages,
        ])
        package_archives = sorted(cache.glob("*.pkg.tar.zst"))
        if not package_archives:
            raise RuntimeError("pacman downloaded no package archives")
        unsigned = [
            item.name for item in package_archives
            if not Path(f"{item}.sig").is_file()
        ]
        if unsigned:
            raise RuntimeError(f"package has no detached signature: {unsigned[0]}")
        run([
            "repo-add", str(cache / "telos.db.tar.gz"),
            *[str(item) for item in package_archives],
        ])
        source = source_snapshot(stage / "source/telos.tar.gz")
        write_receipt(stage, packages, source)

        partial = work / "telos-controller-seed.iso"
        run([
            "xorriso", "-as", "mkisofs", "-volid", "TELOS_SEED", "-r", "-J",
            "-o", str(partial), str(stage),
        ])
        os.replace(partial, output)
    print(f"built {output}")
    print(f"sha256 {sha256(output)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, default=DEFAULT_PACKAGES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--plan", action="store_true",
        help="print the networked build phases without downloading or writing",
    )
    args = parser.parse_args(argv)
    try:
        packages = package_names(args.packages)
        if args.plan:
            for command in command_plan(packages, Path("<temporary-stage>"), args.output):
                print(" ".join(command))
            return 0
        build(args.output.resolve(), args.packages.resolve())
    except (ValueError, OSError, subprocess.CalledProcessError, RuntimeError) as error:
        print(f"seed build failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
