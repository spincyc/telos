"""Build and offline-verify the pinned Samba SRV serialization compatibility fix.

Only libndr-nbt is deployed. The official package remains installed; the guest
must check base_package_version/base_library_sha256 before enabling the scoped
service override. No DNS backend, directory database or client identity changes.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESOURCES = ROOT / "media" / "samba-dns"
DEFAULT_CACHE = ROOT / "var" / "media" / "samba-dns"
DEFAULT_PACKAGES = ROOT / "var" / "media" / "arch" / "workstation-repo"
LIBRARY = "libndr-nbt.so.0"
RESOURCE_FILES = ("pins.json", "base-abi.json", "build.sh", "srv-target-no-compression.patch",
                  "roundtrip.py", "synthetic-srv-compressed.bin", "synthetic-srv-uncompressed.bin")
RECEIPT_KEYS = {"schema", "library_sha256", "base_library_sha256", "base_package",
                "base_package_version", "soname", "source", "resources", "abi", "build", "validation"}
VALIDATION = {"patched_unit_tests": 5, "original_unit_regression_fails": True,
              "original_cares_status": 8, "patched_cares_status": 0,
              "cares_version": "1.34.8", "inbound_compressed_accepted": True,
              "inbound_uncompressed_accepted": True, "exact_output_bytes": True,
              "reproducible_builds": 2}


class SambaDnsError(RuntimeError):
    """The library or its pinned provenance is not verified."""


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise SambaDnsError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise SambaDnsError(f"{path.name} must contain an object")
    return value


def _run(command, *, cwd=None, log=None, expected=0) -> str:
    result = subprocess.run([str(value) for value in command], cwd=cwd,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, env={**os.environ, "LC_ALL": "C"})
    if log is not None:
        log.write_text(result.stdout)
    if result.returncode != expected:
        raise SambaDnsError(f"{Path(str(command[0])).name} exited {result.returncode}: {result.stdout[-2500:]}")
    return result.stdout


def _regular(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SambaDnsError(f"missing {path.name}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SambaDnsError(f"{path.name} must be a regular file with one hard link")


def _elf(path: Path) -> dict:
    """Inspect bytes without loading the candidate into this process."""
    dynamic = _run(["readelf", "--wide", "--dynamic", path])
    segments = _run(["readelf", "--wide", "--program-headers", path])
    header = _run(["readelf", "--file-header", path])
    def values(tag):
        return re.findall(r"\(" + tag + r"\).*?\[([^]]+)\]", dynamic)
    def symbols(option):
        lines = _run(["nm", "-D", "--format=posix", option, path]).splitlines()
        return sorted(" ".join(line.split()[:2]) for line in lines if line.strip())
    stack = next((line for line in segments.splitlines() if "GNU_STACK" in line), "")
    return {"soname": values("SONAME"), "needed": sorted(values("NEEDED")),
            "runpath": values("RUNPATH"), "rpath": values("RPATH"),
            "defined": symbols("--defined-only"), "undefined": symbols("--undefined-only"),
            "elf64_x86_64": "ELF64" in header and "Advanced Micro Devices X86-64" in header,
            "relro": "GNU_RELRO" in segments, "bind_now": "BIND_NOW" in dynamic,
            "nonexec_stack": bool(stack) and not re.search(r"\sRWE\s", stack)}


def _resources() -> dict:
    return {name: _sha(RESOURCES / name) for name in RESOURCE_FILES}


def _check_abi(actual: dict) -> None:
    baseline = _json(RESOURCES / "base-abi.json")
    if actual != baseline:
        differences = sorted(key for key in baseline if actual.get(key) != baseline[key])
        raise SambaDnsError("ELF differs from pinned base ABI/hardening: " + ", ".join(differences))


def verify(cache: Path) -> dict:
    """Offline byte, provenance, ABI and hardening verification; never acquire."""
    cache = Path(cache)
    if cache.is_symlink():
        raise SambaDnsError("cache directory must not be a symlink")
    for name in (LIBRARY, "receipt.json"):
        _regular(cache / name)
    receipt = _json(cache / "receipt.json")
    pins = _json(RESOURCES / "pins.json")
    expected = {"schema": 1, "base_package": "smbclient", "base_package_version": pins["base_package_version"],
                "base_library_sha256": pins["base_library_sha256"], "soname": LIBRARY,
                "source": pins["source"], "resources": _resources(), "validation": VALIDATION}
    if set(receipt) != RECEIPT_KEYS or any(receipt.get(key) != value for key, value in expected.items()):
        raise SambaDnsError("receipt provenance or validation differs from the pinned recipe")
    digest = _sha(cache / LIBRARY)
    if receipt.get("library_sha256") != digest:
        raise SambaDnsError("library SHA-256 differs from receipt")
    if digest == pins["base_library_sha256"]:
        raise SambaDnsError("unmodified base library cannot provide the SRV fix")
    build = receipt.get("build")
    if (not isinstance(build, dict) or build.get("library_sha256s") != [digest, digest]
            or build.get("source_date_epoch") != pins["source_date_epoch"]
            or not isinstance(build.get("host_packages"), str) or not build["host_packages"]
            or not isinstance(build.get("compiler"), str) or not build["compiler"]):
        raise SambaDnsError("receipt has no matching reproducible build evidence")
    actual = _elf(cache / LIBRARY)
    _check_abi(actual)
    if receipt.get("abi") != actual:
        raise SambaDnsError("ELF metadata differs from receipt")
    return receipt


def stage(cache: Path, dest: Path) -> dict:
    """Copy exactly the verified library and receipt, publishing them together."""
    receipt = verify(cache)
    dest = Path(dest)
    if dest.exists() or dest.is_symlink():
        if verify(dest) != receipt:
            raise SambaDnsError("staging destination contains a different verified artifact")
        return receipt
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".samba-dns-stage-", dir=dest.parent) as temporary:
        prepared = Path(temporary) / "artifact"
        prepared.mkdir()
        for name in (LIBRARY, "receipt.json"):
            shutil.copyfile(Path(cache) / name, prepared / name)
            (prepared / name).chmod(0o644)
        if verify(prepared) != receipt:
            raise SambaDnsError("cache changed while staging")
        prepared.rename(dest)
    return receipt


def _acquire(record: dict, inputs: Path, packages: Path) -> Path:
    path = inputs / record["filename"]
    if not path.exists():
        existing = packages / record["filename"]
        if existing.is_file():
            shutil.copyfile(existing, path)
        else:
            partial = path.with_name(path.name + ".part")
            _run(["curl", "--fail", "--location", "--silent", "--show-error", "--retry", "2",
                  "--connect-timeout", "30", "--max-time", "1800",
                  "--output", partial, record["url"]])
            partial.rename(path)
    _regular(path)
    if _sha(path) != record["sha256"]:
        raise SambaDnsError(f"pinned input hash mismatch: {path.name}")
    return path


def _signature(command: list, fingerprint: str, log: Path) -> None:
    status = _run(command, log=log)
    valid = re.findall(r"\[GNUPG:\] VALIDSIG ([0-9A-F]+) ", status)
    if valid != [fingerprint]:
        raise SambaDnsError("signature does not match pinned signing fingerprint")


def _sandbox(work: Path, command: list, *, cwd: Path, env: dict | None = None) -> list:
    args = ["bwrap", "--ro-bind", "/", "/", "--tmpfs", "/tmp", "--bind", work, work,
            "--unshare-net", "--unshare-pid", "--die-with-parent", "--clearenv",
            "--proc", "/proc", "--dev", "/dev", "--chdir", cwd]
    variables = {"PATH": f"{work}/deps/usr/bin/vendor_perl:{work}/deps/usr/bin:/usr/bin",
                 "PERL5LIB": f"{work}/deps/usr/share/perl5/vendor_perl",
                 "TMPDIR": f"{work}/tmp", "XDG_CACHE_HOME": f"{work}/cache",
                 "PYTHONHASHSEED": "1", "LC_ALL": "C", **(env or {})}
    for key, value in variables.items():
        args.extend(["--setenv", key, value])
    return args + command


def _roundtrip(work: Path, library: Path, reference: Path, expected: int) -> dict:
    result = json.loads(_run(_sandbox(work, ["python3", RESOURCES / "roundtrip.py", library,
                     reference / "usr/lib/libcares.so.2.19.7"], cwd=work,
                     env={"LD_LIBRARY_PATH": f"{reference}/usr/lib:{reference}/usr/lib/samba"})))
    digest = _sha(RESOURCES / ("synthetic-srv-uncompressed.bin" if expected == 0 else "synthetic-srv-compressed.bin"))
    if (result.get("c_ares_version") != "1.34.8" or len(result.get("results", [])) != 2
            or any(row != {"input": kind, "ndr_pull": 0, "ndr_push": 0,
                           "emitted_length": 76 if expected == 0 else 64,
                           "emitted_sha256": digest, "matches_expected": expected == 0,
                           "ares_status": expected}
                   for kind, row in zip(("compressed", "uncompressed"), result["results"]))):
        raise SambaDnsError("NDR/c-ares round-trip regression failed")
    return result


def build(cache: Path = DEFAULT_CACHE, *, packages: Path = DEFAULT_PACKAGES) -> dict:
    """Acquire signed pins, build twice in isolation, prove ABI and stage locally."""
    cache, packages = Path(cache).absolute(), Path(packages).absolute()
    cache.mkdir(parents=True, exist_ok=True)
    if cache.is_symlink():
        raise SambaDnsError("cache directory must not be a symlink")
    inputs, evidence = cache / "inputs", cache / "evidence"
    inputs.mkdir(exist_ok=True)
    evidence.mkdir(exist_ok=True)
    pins = _json(RESOURCES / "pins.json")
    source = {key: _acquire(pins["source"][key], inputs, packages) for key in ("archive", "signature", "key")}
    package_files = {}
    for record in pins["packages"]:
        package = _acquire(record, inputs, packages)
        signature = _acquire({"filename": record["filename"] + ".sig", "url": record["url"] + ".sig",
                              "sha256": record["signature_sha256"]}, inputs, packages)
        _signature(["gpgv", "--status-fd", "1", "--keyring", "/etc/pacman.d/gnupg/pubring.gpg", signature, package],
                   record["signing_fingerprint"], evidence / (record["name"] + "-signature.log"))
        package_files[record["name"]] = package
    with tempfile.TemporaryDirectory(prefix=".samba-dns-build-", dir=cache.parent) as temporary:
        work = Path(temporary)
        for name in ("gnupg", "deps", "reference", "tmp", "cache"):
            (work / name).mkdir(mode=0o700)
        _run(["gpg", "--homedir", work / "gnupg", "--batch", "--import", source["key"]])
        tarfile = work / "samba.tar"
        with gzip.open(source["archive"], "rb") as compressed, tarfile.open("wb") as plain:
            shutil.copyfileobj(compressed, plain)
        _signature(["gpg", "--homedir", work / "gnupg", "--batch", "--status-fd", "1", "--verify",
                    source["signature"], tarfile], pins["source"]["signing_fingerprint"], evidence / "source-signature.log")
        for name, package in package_files.items():
            destination = work / ("deps" if name in {"perl-parse-yapp", "rpcsvc-proto"} else "reference")
            _run(["tar", "-xf", package, "-C", destination, "usr"])
        reference = work / "reference"
        original = reference / "usr/lib/libndr-nbt.so.0.0.1"
        if _sha(original) != pins["base_library_sha256"] or _sha(reference / "usr/lib/libcares.so.2.19.7") != pins["cares_library_sha256"]:
            raise SambaDnsError("package library does not match pinned base/parser")
        _check_abi(_elf(original))
        before = _roundtrip(work, original, reference, 8)
        hashes = []
        for iteration in (1, 2):
            root = work / f"build-{iteration}"
            root.mkdir()
            _run(["tar", "-xf", tarfile, "-C", root])
            source_dir = root / "samba-4.24.5"
            _run(["patch", "--batch", "--fuzz=0", "-p1", "-i", RESOURCES / "srv-target-no-compression.patch"], cwd=source_dir)
            _run(_sandbox(work, ["sh", RESOURCES / "build.sh", source_dir], cwd=source_dir),
                 log=evidence / f"build-{iteration}.log")
            executable = source_dir / "bin/default/librpc/test_ndr_dns_nbt"
            build_libs = f"{source_dir}/bin/shared:{source_dir}/bin/shared/private"
            tests = _run(_sandbox(work, [executable], cwd=source_dir, env={"LD_LIBRARY_PATH": build_libs}),
                         log=evidence / f"tests-{iteration}.log")
            if tests.count("success: test_") != 5 or "failure:" in tests:
                raise SambaDnsError("Samba DNS unit tests did not all pass")
            old_tests = _run(_sandbox(work, [executable], cwd=source_dir,
                             env={"LD_LIBRARY_PATH": f"{reference}/usr/lib:{reference}/usr/lib/samba:{build_libs}"}),
                             expected=1, log=evidence / f"original-tests-{iteration}.log")
            if old_tests.count("failure:") != 1 or "failure: test_ndr_dns_srv_target_no_compression" not in old_tests:
                raise SambaDnsError("regression test did not isolate the original SRV failure")
            artifact = work / f"library-{iteration}.so"
            shutil.copyfile(source_dir / "bin/default/librpc/libndr-nbt.so", artifact)
            _run(["strip", "--strip-unneeded", artifact])
            _check_abi(_elf(artifact))
            after = _roundtrip(work, artifact, reference, 0)
            hashes.append(_sha(artifact))
        if hashes[0] != hashes[1]:
            raise SambaDnsError("two clean builds produced different library bytes")
        receipt = {"schema": 1, "library_sha256": hashes[0], "base_package": "smbclient",
                   "base_package_version": pins["base_package_version"], "base_library_sha256": pins["base_library_sha256"],
                   "soname": LIBRARY, "source": pins["source"], "resources": _resources(), "abi": _elf(artifact),
                   "validation": VALIDATION, "build": {"library_sha256s": hashes,
                       "source_date_epoch": pins["source_date_epoch"], "compiler": _run(["gcc", "--version"]).splitlines()[0],
                       "host_packages": _run(["pacman", "-Q"]), "cflags_recipe": "build.sh"}}
        prepared = work / "artifact"
        prepared.mkdir()
        shutil.copyfile(artifact, prepared / LIBRARY)
        (prepared / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        verify(prepared)
        (evidence / "roundtrip.json").write_text(json.dumps({"original": before, "patched": after}, indent=2) + "\n")
        for name in (LIBRARY, "receipt.json"):
            os.replace(prepared / name, cache / name)
    return verify(cache)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
        if name == "build":
            command.add_argument("--packages", type=Path, default=DEFAULT_PACKAGES)
    args = parser.parse_args(argv)
    receipt = build(args.cache, packages=args.packages) if args.command == "build" else verify(args.cache)
    print(json.dumps({"cache": str(args.cache), "library_sha256": receipt["library_sha256"],
                      "base_package_version": receipt["base_package_version"], "verified": True}, sort_keys=True))
    return 0
