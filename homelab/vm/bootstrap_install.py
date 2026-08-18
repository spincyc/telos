#!/usr/bin/env python3
"""Install the canonical Controller image from the operator's own terminal.

Until now the only way to turn ``build/homelab/vm/bootstrap-dc`` into an
installed Controller was a long manual console session: boot the Arch ISO,
press ``e`` at the boot entry, append ``console=ttyS0,115200n8``, mount the
``TELOS_SEED`` volume, run ``/run/telos-seed/install-controller``, type the
erasure phrase, then type a new console password twice. Every live factory
activity depends on that image, so the whole project waited on someone
getting a twenty-step console session exactly right.

The serial protocol that answers those prompts already existed --
``controller_factory_install.FactoryInstallSerial`` -- but only ever ran
against a *disposable* raw disk for the acceptance matrix, and had no
production caller at all. This module points that same protocol and the same
direct-kernel-boot argv at the canonical qcow2, so the manual session becomes
one command plus the password the operator has to choose anyway.

Two properties are load-bearing and are why this is a separate module rather
than a flag on the disposable path.

*ADR 0058* (``homelab/decisions/0058-pty-driven-acceptance-testing.md``) says
"**No unattended installation code path exists.** The installer is interactive
and only interactive," and that the harness answers the prompts "the way a
person would, **including the final confirmation**". An external driver
answering prompts is therefore the prescribed mechanism; a skip-the-prompt
path inside ``homelab/seed/install-controller`` is what is forbidden. To keep
the property the ADR actually cares about -- that a *person* answered -- this
module never composes the erasure phrase. It relays, byte for byte, what the
operator passed as ``--confirm``, and the phrase appears nowhere in this file,
so there is no literal here that could be sent without a person having typed
it. A wrong phrase is refused by the installer in the guest, not silently
corrected here.

*The credential* is read with ``getpass`` at the controlling terminal through
``bootstrap_dc._typed_secret``, whose docstring states this repository's rule
for exactly this value: "Deliberately not a file, an environment variable, a
Make variable or an argv element." Without a terminal this fails closed.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

try:
    from . import bootstrap_dc
    from .controller_factory_install import (
        FactoryInstallSerial,
        _run_qemu,
        arch_volume_label,
        direct_kernel_install_command,
        extract_arch_boot_files,
        isolated_qemu_prefix,
    )
    from .controller_image import ControllerImageError, probe
    from .simulation_evidence import private_file
    from .simulation_overlay import LOCK_NAME, canonical_disk_users
except ImportError:  # Direct execution from homelab/vm.
    import bootstrap_dc
    from controller_factory_install import (
        FactoryInstallSerial,
        _run_qemu,
        arch_volume_label,
        direct_kernel_install_command,
        extract_arch_boot_files,
        isolated_qemu_prefix,
    )
    from controller_image import ControllerImageError, probe
    from simulation_evidence import private_file
    from simulation_overlay import LOCK_NAME, canonical_disk_users

DISK_SERIAL = bootstrap_dc.DISK_SERIAL
NAME = bootstrap_dc.NAME

#: Private evidence written beside ``manifest.json``.
RECEIPT_NAME = "install-receipt.json"
DIAGNOSTIC_NAME = "install-console.log"

#: The installer's own last line. Matched by ``FactoryInstallSerial`` and
#: recorded only when the protocol reports the event that proves it matched.
COMPLETION_LINE = (
    "Controller installation complete. Remove both ISOs and reboot.")
COMPLETION_EVENT = "installation-complete"

#: A pacstrap of the seed closure onto a fresh disk, plus a bootloader and an
#: interactive password exchange. Generous, because the failure mode of a
#: bound that is too tight is a half-installed disk.
INSTALL_TIMEOUT = 5400.0

#: The manifest fields this driver refuses to install against a mismatch on.
EXPECTED_FORMAT = "qcow2"


class InstallRefused(RuntimeError):
    """A fail-closed guard stopped the installation before QEMU was started."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def fresh_image_fingerprint(size: str) -> tuple[int, str]:
    """Size and digest of a *newly created* qcow2 of the declared size.

    ``qemu-img create -f qcow2`` is deterministic: two images of the same
    declared size are byte-identical, so a canonical disk that still matches
    this fingerprint provably holds nothing at all. Deriving the reference
    from the local ``qemu-img`` rather than hard-coding 197,888 bytes keeps
    the guard honest across qemu versions -- and a fingerprint that stops
    matching is a refusal, never a silent pass.
    """
    with tempfile.TemporaryDirectory(prefix="telos-fresh-image-") as name:
        reference = Path(name) / "reference.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-f", EXPECTED_FORMAT, str(reference), size],
            check=True, capture_output=True)
        return reference.stat().st_size, _sha256(reference)


def seed_receipt_sha256(seed_iso: Path) -> str:
    """Digest of ``receipt.json`` as it exists inside the seed medium.

    The ISO digest proves which medium was attached; the receipt digest ties
    it to the package closure and source archive ``verify-seed`` checks in the
    guest, so the receipt records both rather than making a reader take the
    ISO digest on faith.
    """
    with tempfile.TemporaryDirectory(prefix="telos-seed-receipt-") as name:
        extracted = Path(name) / "receipt.json"
        subprocess.run(
            ["xorriso", "-osirrox", "on", "-indev", str(seed_iso),
             "-extract", "/receipt.json", str(extracted)],
            check=True, capture_output=True)
        if not extracted.is_file():
            raise InstallRefused(
                f"the seed medium carries no receipt.json: {seed_iso}")
        return _sha256(extracted)


def _validated_confirmation(confirm: str | None) -> bytes:
    """Shape-check what the operator typed; never decide *what* it should be.

    Only the guest knows the phrase, and only a person can supply it. This
    refuses what cannot be relayed over a serial line at all -- an empty
    value, more than one line, control characters -- and leaves the actual
    comparison to ``install-controller``, which is where ADR 0058 puts it.
    """
    if not confirm:
        raise InstallRefused(
            "an applied installation requires the erasure confirmation the "
            "installer asks for, typed by you and passed as CONFIRM=; this "
            "driver only relays it and never composes it")
    if "\n" in confirm or "\r" in confirm:
        raise InstallRefused("the erasure confirmation must be one line")
    if any(ord(character) < 32 or ord(character) == 127
           for character in confirm):
        raise InstallRefused(
            "the erasure confirmation must not contain control characters")
    return confirm.encode("utf-8")


def preflight(
    state: Path, arch_iso: Path, seed_iso: Path,
) -> dict[str, object]:
    """Every refusal that must happen before a destructive boot is possible.

    Ordered cheapest-first and fail-closed throughout. The two that matter
    most are the identity guard (the manifest must declare this exact disk
    serial) and the freshness guard (the image must still be byte-identical
    to a newly created one). Together they mean this command cannot be aimed
    at a *working* Controller: a converged disk has written clusters and
    fails the freshness check long before QEMU is started.
    """
    if os.geteuid() == 0:
        raise InstallRefused(
            "the canonical installation refuses to run as root; run it as the "
            "user that owns the state directory")
    if not bootstrap_dc._safe_state_path(state):
        raise InstallRefused(f"state path includes a symlink: {state}")
    files = bootstrap_dc.paths(state)
    missing = [str(files[key]) for key in ("disk", "vars", "manifest")
               if not _regular_file(files[key])]
    if missing:
        raise InstallRefused(
            "the canonical state is not there; run make "
            "homelab-bootstrap-vm-create APPLY=1 first. Missing: "
            + ", ".join(missing))
    if not bootstrap_dc._private_state(files):
        raise InstallRefused(
            "state permissions must be 0700 with 0600 files")
    for tool in ("qemu-system-x86_64", "qemu-img", "xorriso"):
        if not shutil.which(tool):
            raise InstallRefused(f"{tool} is not installed")
    for medium, label in ((arch_iso, "Arch ISO"), (seed_iso, "seed ISO")):
        if not _regular_file(medium):
            raise InstallRefused(
                f"the {label} must be a regular, non-symlink file: {medium}")

    try:
        manifest = json.loads(files["manifest"].read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise InstallRefused(f"cannot read {files['manifest']}: {error}") from error
    disk = manifest.get("disk") if isinstance(manifest, dict) else None
    if not isinstance(disk, dict):
        raise InstallRefused(
            f"{files['manifest']} does not describe a disk")
    if disk.get("serial") != DISK_SERIAL:
        raise InstallRefused(
            f"{files['manifest']} declares disk serial {disk.get('serial')!r}; "
            f"this driver installs only {DISK_SERIAL}")
    if disk.get("format") != EXPECTED_FORMAT:
        raise InstallRefused(
            f"{files['manifest']} declares a {disk.get('format')!r} disk; "
            f"this driver installs only {EXPECTED_FORMAT}")
    size = disk.get("size")
    if not isinstance(size, str) or not size:
        raise InstallRefused(
            f"{files['manifest']} does not declare a disk size")

    users = canonical_disk_users(files["disk"]) + canonical_disk_users(
        files["vars"])
    if users:
        raise InstallRefused(
            "the canonical state is open by: " + ", ".join(users))

    disk_bytes = files["disk"].stat().st_size
    disk_digest = _sha256(files["disk"])
    fresh_bytes, fresh_digest = fresh_image_fingerprint(size)
    if (disk_bytes, disk_digest) != (fresh_bytes, fresh_digest):
        try:
            found = probe(files["disk"]).summary()
        except ControllerImageError as error:
            found = f"could not be inspected ({error})"
        raise InstallRefused(
            f"{files['disk']} is no longer a freshly created {size} image "
            f"({disk_bytes} bytes, sha256 {disk_digest}; a new one is "
            f"{fresh_bytes} bytes, sha256 {fresh_digest}). It {found}. "
            "This command erases only a provably empty image; destroy and "
            "recreate the state deliberately if that is really what you want")

    return {
        "files": files,
        "manifest": manifest,
        "size": size,
        "disk_bytes": disk_bytes,
        "disk_sha256": disk_digest,
        "fresh_bytes": fresh_bytes,
        "fresh_sha256": fresh_digest,
        "arch_iso_sha256": _sha256(arch_iso),
        "seed_iso_sha256": _sha256(seed_iso),
        "seed_receipt_sha256": seed_receipt_sha256(seed_iso),
    }


def install_command(
    files: dict[str, Path],
    workspace: Path,
    arch_iso: Path,
    seed_iso: Path,
    arch_label: str,
) -> list[str]:
    """The canonical direct-kernel-boot argv, with its serial asserted once."""
    pair = bootstrap_dc.ovmf_pair()
    if pair is None:
        raise InstallRefused("OVMF firmware was not found")
    command = direct_kernel_install_command(
        isolated_qemu_prefix(
            pair[0], files["vars"].resolve(), name=f"{NAME}-install"),
        disk=files["disk"].resolve(),
        disk_format=EXPECTED_FORMAT,
        kernel=workspace / "vmlinuz-linux",
        initramfs=workspace / "initramfs-linux.img",
        arch_label=arch_label,
        arch_iso=arch_iso.resolve(),
        seed_iso=seed_iso.resolve(),
    )
    # One disk, one serial. The installer picks its target by serial and
    # refuses anything but exactly one match, so a second device carrying the
    # same serial would make the guest's own safety check meaningless.
    serials = sum(part.count(f"serial={DISK_SERIAL}") for part in command)
    if serials != 1:
        raise InstallRefused(
            f"the launch argv names serial={DISK_SERIAL} {serials} times; "
            "exactly one device may carry it")
    if "-netdev" in command or "-nic" not in command:
        raise InstallRefused(
            "the installation launch must be isolated: -nic none and no netdev")
    return command


def _receipt(
    facts: dict[str, object],
    files: dict[str, Path],
    state: Path,
    arch_iso: Path,
    seed_iso: Path,
    command: list[str],
    events: tuple[str, ...],
    exit_status: int,
    after: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": 1,
        "kind": "controller-canonical-install-receipt",
        "installed_utc": datetime.now(UTC).isoformat(),
        "name": NAME,
        "state": str(state),
        "disk": {
            "path": str(files["disk"]),
            "format": EXPECTED_FORMAT,
            "serial": DISK_SERIAL,
            "declared_size": facts["size"],
            "bytes_before": facts["disk_bytes"],
            "sha256_before": facts["disk_sha256"],
            "bytes_after": after["bytes"],
            "sha256_after": after["sha256"],
            "image_state_after": after["image_state"],
        },
        "media": {
            "arch_iso": {
                "path": str(arch_iso),
                "sha256": facts["arch_iso_sha256"],
            },
            "seed_iso": {
                "path": str(seed_iso),
                "sha256": facts["seed_iso_sha256"],
                "receipt_sha256": facts["seed_receipt_sha256"],
            },
        },
        "firmware": {
            "variables": str(files["vars"]),
            "variables_sha256_after": _sha256(files["vars"]),
        },
        "qemu": {"argv": list(command), "exit_status": exit_status},
        "console": {
            "events": list(events),
            "completion_line_observed":
                COMPLETION_LINE if COMPLETION_EVENT in events else None,
            "diagnostic": str(state / DIAGNOSTIC_NAME),
        },
        "confirmation": (
            "the erasure phrase was typed by the operator and relayed to the "
            "guest verbatim; this driver never composes it"),
        "credential": (
            "the local-rescue console password was typed at the operator's "
            "terminal and is deliberately not recorded here, in the console "
            "capture, in argv, in the environment, or in any answer file"),
    }


def _summary(
    state: Path,
    files: dict[str, Path],
    facts: dict[str, object],
    arch_iso: Path,
    seed_iso: Path,
    command: list[str],
) -> None:
    print(f"{NAME}: canonical Controller installation")
    print(f"state: {state}")
    print(f"disk: {files['disk']} ({EXPECTED_FORMAT}, {facts['size']}, "
          f"serial {DISK_SERIAL})")
    print(f"freshness: byte-identical to a newly created {facts['size']} "
          f"{EXPECTED_FORMAT} image ({facts['disk_bytes']} bytes, sha256 "
          f"{facts['disk_sha256']}); this erases nothing that exists")
    print(f"arch iso: {arch_iso} (sha256 {facts['arch_iso_sha256']})")
    print(f"seed iso: {seed_iso} (sha256 {facts['seed_iso_sha256']}, "
          f"receipt sha256 {facts['seed_receipt_sha256']})")
    print("network: none; the guest is booted with -nic none and no netdev")
    print("confirmation: relayed verbatim from CONFIRM=; this driver holds no "
          "copy of the phrase and cannot answer for you")
    print("credential: typed at this terminal, never argv, environment, file, "
          "or transcript")
    print(f"receipt: {state / RECEIPT_NAME} (0600)")
    print(f"console capture: {state / DIAGNOSTIC_NAME} (0600, secret bytes "
          "replaced before anything reaches disk)")
    print(" ".join(str(part) for part in command))


def install(
    state: Path,
    arch_iso: Path,
    seed_iso: Path,
    *,
    apply: bool,
    confirm: str | None = None,
    timeout: float = INSTALL_TIMEOUT,
) -> int:
    """Plan, or drive, one canonical Controller installation."""
    # Media are resolved, exactly as ``DisposableFactoryController`` resolves
    # them: ``homelab/var/media/arch/archlinux-x86_64.iso`` is a symlink to the
    # dated release by design, and what must be a regular file is what the
    # symlink points at. The state directory is deliberately NOT resolved --
    # ``_safe_state_path`` refuses a symlinked state outright.
    arch_iso = Path(arch_iso).resolve()
    seed_iso = Path(seed_iso).resolve()
    try:
        facts = preflight(state, arch_iso, seed_iso)
    except (InstallRefused, ControllerImageError, OSError,
            subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    files = facts["files"]

    # The confirmation is demanded before a single byte is extracted, so an
    # applied run that is going to be refused is refused immediately.
    confirmation = None
    if apply:
        try:
            confirmation = _validated_confirmation(confirm)
        except InstallRefused as error:
            print(f"error: {error}", file=sys.stderr)
            return 2

    workspace = Path(tempfile.mkdtemp(prefix="telos-bootstrap-install-"))
    password: bytearray | None = None
    try:
        os.chmod(workspace, 0o700)
        try:
            label = arch_volume_label(arch_iso)
            extract_arch_boot_files(
                arch_iso, workspace / "vmlinuz-linux",
                workspace / "initramfs-linux.img")
            for name in ("vmlinuz-linux", "initramfs-linux.img"):
                os.chmod(workspace / name, 0o600)
            command = install_command(
                files, workspace, arch_iso, seed_iso, label)
        except (InstallRefused, RuntimeError, OSError,
                subprocess.CalledProcessError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        _summary(state, files, facts, arch_iso, seed_iso, command)
        if not apply:
            print("dry run; nothing was started and nothing was written")
            return 0

        try:
            # ``_typed_secret`` refuses outright without a controlling
            # terminal. The mutable copy is what the protocol writes and what
            # is zeroed below; the immutable value getpass returned cannot be
            # overwritten from Python, which is the honest limit of this.
            password = bytearray(bootstrap_dc._typed_secret(
                f"New console password for {bootstrap_dc.CONSOLE_ACCOUNT}: ",
                confirm=f"Retype the console password for "
                        f"{bootstrap_dc.CONSOLE_ACCOUNT}: "))
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2

        lock_path = state / LOCK_NAME
        with lock_path.open("a+b") as lock_stream:
            try:
                fcntl.flock(
                    lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                print(f"error: {NAME} is open elsewhere; its lock is held",
                      file=sys.stderr)
                return 2
            try:
                os.chmod(lock_path, 0o600)
                protocol = FactoryInstallSerial(
                    subprocess.DEVNULL, subprocess.DEVNULL,  # type: ignore[arg-type]
                    password, confirmation=confirmation, timeout=timeout)
                print("installing; this drives the guest console and prints "
                      "nothing it reads", flush=True)
                result = _run_qemu(
                    command, protocol, timeout=timeout,
                    diagnostic_path=state / DIAGNOSTIC_NAME,
                    diagnostic_secrets=(bytes(password),))
            except Exception as error:
                print(f"error: installation did not complete: {error}",
                      file=sys.stderr)
                return 2
            finally:
                fcntl.flock(lock_stream.fileno(), fcntl.LOCK_UN)

        if not result.installed:
            print("error: the guest did not report a completed installation",
                  file=sys.stderr)
            return 2
        try:
            after = {
                "bytes": files["disk"].stat().st_size,
                "sha256": _sha256(files["disk"]),
                "image_state": probe(files["disk"]).record(),
            }
        except (ControllerImageError, OSError) as error:
            print(f"error: the installation finished but its result could not "
                  f"be inspected: {error}", file=sys.stderr)
            return 2
        receipt = _receipt(
            facts, files, state, arch_iso, seed_iso, command,
            result.events, 0, after)
        try:
            private_file(
                state / RECEIPT_NAME,
                (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode())
        except (RuntimeError, OSError) as error:
            print(f"error: the Controller is installed but its receipt could "
                  f"not be written: {error}", file=sys.stderr)
            return 2
        installed = after["image_state"]["installed"]
        print(f"installed {NAME}; disk sha256 {after['sha256']}")
        print(f"image now reports: {after['image_state']['reason']}")
        print(f"receipt: {state / RECEIPT_NAME}")
        if not installed:
            print("error: the guest reported success but the image does not "
                  "look installed", file=sys.stderr)
            return 2
        return 0
    finally:
        if password is not None:
            for index in range(len(password)):
                password[index] = 0
        with contextlib.suppress(OSError):
            shutil.rmtree(workspace, ignore_errors=True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Drive the interactive Controller installer against the canonical "
            "bootstrap-dc image"))
    result.add_argument("--state-dir", type=Path,
                        default=bootstrap_dc.DEFAULT_STATE)
    result.add_argument("--iso", type=Path, required=True,
                        help="the stock Arch installation ISO")
    result.add_argument("--seed-iso", type=Path, required=True,
                        help="the offline TELOS_SEED convergence medium")
    result.add_argument(
        "--confirm",
        help="the erasure phrase you typed, relayed to the guest verbatim")
    result.add_argument("--apply", action="store_true")
    result.add_argument("--timeout", type=float, default=INSTALL_TIMEOUT)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return install(
        args.state_dir, args.iso, args.seed_iso,
        apply=args.apply, confirm=args.confirm, timeout=args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
