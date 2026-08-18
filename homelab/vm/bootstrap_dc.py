#!/usr/bin/env python3
"""Plan and operate the temporary, stateful bootstrap-dc QEMU guest."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import getpass
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

try:
    from .controller_factory import FactoryBundle, FactorySpec
    from .controller_image import ControllerImageError
    from .controller_image import assert_installed as assert_installed_image
    from .controller_image import probe as probe_controller_image
    from .network import DEFAULT_PORT, socket_network_args
    from .preflight_receipt import verify as verify_preflight_receipt
    from .serial_automation import SerialAutomation, SerialAutomationError
    from .simulation_overlay import (
        DESTROY_CONFIRMATION_PREFIX,
        LOCK_NAME,
        PERSISTENT_DISK_NAME,
        PERSISTENT_MARKER_NAME,
        PERSISTENT_VARS_NAME,
        PersistentControllerInstance,
        assert_installed_controller_image,
    )
except ImportError:  # Direct execution from homelab/.
    from controller_factory import FactoryBundle, FactorySpec
    from controller_image import ControllerImageError
    from controller_image import assert_installed as assert_installed_image
    from controller_image import probe as probe_controller_image
    from network import DEFAULT_PORT, socket_network_args
    from preflight_receipt import verify as verify_preflight_receipt
    from serial_automation import SerialAutomation, SerialAutomationError
    from simulation_overlay import (
        DESTROY_CONFIRMATION_PREFIX,
        LOCK_NAME,
        PERSISTENT_DISK_NAME,
        PERSISTENT_MARKER_NAME,
        PERSISTENT_VARS_NAME,
        PersistentControllerInstance,
        assert_installed_controller_image,
    )


NAME = "bootstrap-dc"
VCPUS = 4
MEMORY_MIB = 8192
DISK_SIZE = "80G"
DISK_SERIAL = "TELOS-BOOTSTRAP-DC1"
DEFAULT_STATE = Path("build/homelab/vm/bootstrap-dc")
#: Persistent instances live under their own root, never under DEFAULT_STATE.
#: ``simulation_overlay.assert_persistent_state_separate`` refuses the canonical
#: acceptance state whatever root and instance a caller names, so this default
#: is a convenience and not the safety property.
DEFAULT_PERSISTENT_ROOT = Path("build/homelab/vm/persistent-dc")
#: A persistent instance listens on its own loopback segment. Sharing the
#: acceptance port would let a forgotten persistent guest hold 127.0.0.1:12961
#: and make an acceptance run fail to bind; separate ports keep the two
#: simulations from touching each other at all. One persistent instance may be
#: up at a time, and a second one fails loudly on bind rather than silently
#: joining the first one's segment.
PERSISTENT_SOCKET_PORT = DEFAULT_PORT + 10
#: The synthetic MAC the isolated loopback segment gives a controller guest. Named
#: rather than repeated so the convergence peer is told the same address the
#: guest actually uses.
SOCKET_MAC = "52:54:00:11:11:11"
#: The console account ``homelab/seed/install-controller`` creates on the
#: canonical Controller image. Its password is typed by the operator during that
#: offline install and is not known to this harness, which is exactly why a
#: persistent instance needs no ESP rewrite: it logs in normally.
CONSOLE_ACCOUNT = "local-rescue"
#: Bounds for the persistent convergence console. The payload bound covers a full
#: offline Samba provisioning run; the console bound covers a login, one root
#: command, or a shutdown.
PERSISTENT_CONVERGE_TIMEOUT = 2700.0
PERSISTENT_CONSOLE_TIMEOUT = 300.0
#: Bound on the in-guest durable-account staging program. It creates three
#: directory users, replaces two group gidNumbers, re-reads every attribute it
#: wrote and makes three share roots; minutes, not the convergence's tens of
#: minutes. Bounded like every other console wait, never open-ended.
PERSISTENT_ACCOUNTS_TIMEOUT = 600.0
#: QEMU binds its loopback listener during startup, so the gateway peer may lose
#: the first connect attempts. A refused connect consumes nothing, so retrying is
#: safe; the bound keeps a genuinely dead guest from hanging the run.
GATEWAY_ATTACH_ATTEMPTS = 40
GATEWAY_ATTACH_DELAY = 0.25
#: Re-enable the built-in domain administrator after convergence, then prove it.
#:
#: The factory payload's last act is ``samba-tool user disable Administrator``,
#: which is right for a disposable guest: its synthetic credential is discarded
#: at teardown, so no live account may survive holding it. A *persistent*
#: directory is the opposite case. The operator typed this password, and leaving
#: the only built-in administrator disabled would leave a directory that cannot
#: create an account, join a machine, or rotate a credential — unadministrable
#: and unrecoverable. The enable is tolerant (an already-enabled account is
#: convergence, not failure) and the *proof* is fail-closed, mirroring the
#: payload's own ``administrator-disabled-proof`` step.
ADMINISTRATOR_ENABLE = (
    "/usr/bin/samba-tool user enable Administrator >/dev/null 2>&1 || true; "
    "__telos_uac=$(/usr/bin/samba-tool user show Administrator "
    "--attributes=userAccountControl | "
    "/usr/bin/sed -n 's/^userAccountControl: //p'); "
    "case \"$__telos_uac\" in ''|*[!0-9]*) exit 3;; esac; "
    "test $((__telos_uac & 2)) -eq 0"
)
#: Read the durable domain SID. Three sources are consulted and the first
#: canonical SID any of them prints is taken, because the exact wording of these
#: tools' output is not a contract; the host still validates the shape and fails
#: closed on no match rather than recording a guess.
DOMAIN_SID_COMMAND = (
    "{ /usr/bin/net getdomainsid; /usr/bin/net getlocalsid; "
    "/usr/bin/wbinfo -D \"$(/usr/bin/wbinfo --own-domain)\"; } 2>/dev/null | "
    "/usr/bin/grep -oE 'S-1-5-21(-[0-9]{1,10}){3}' | /usr/bin/head -1"
)
REPOSITORY = Path(__file__).resolve().parents[2]
SYS_CLASS_NET = Path("/sys/class/net")
_NET_NAME = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")
OVMF_PAIRS = (
    (
        Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd"),
        Path("/usr/share/edk2/x64/OVMF_VARS.4m.fd"),
    ),
    (
        Path("/usr/share/edk2-ovmf/x64/OVMF_CODE.fd"),
        Path("/usr/share/edk2-ovmf/x64/OVMF_VARS.fd"),
    ),
)


def _controller_principals():
    """Import the principal-staging module in BOTH of this file's run modes.

    ``bootstrap_dc.py`` is executed as a script by every Make recipe, so its
    package-relative imports fall back to top-level ones. That fallback cannot
    reach ``controller_principals``: that module imports ``.serial_automation``
    relatively and only ever loads as part of the package. Adding the
    repository root to ``sys.path`` and importing it by its package name works
    identically either way, and it is deferred into a call so the disposable
    acceptance verbs -- and every existing import of this module -- pay nothing
    for a durable-only dependency.
    """
    try:
        from . import controller_principals
    except ImportError:
        if str(REPOSITORY) not in sys.path:
            sys.path.insert(0, str(REPOSITORY))
        from homelab.vm import controller_principals
    return controller_principals


def ovmf_pair() -> tuple[Path, Path] | None:
    return next(((code, vars_) for code, vars_ in OVMF_PAIRS
                 if code.is_file() and vars_.is_file()), None)


def paths(state: Path) -> dict[str, Path]:
    return {
        "state": state,
        "disk": state / "bootstrap-dc.qcow2",
        "vars": state / "OVMF_VARS.fd",
        "manifest": state / "manifest.json",
    }


def persistent_paths(state: Path) -> dict[str, Path]:
    """File layout of a persistent instance: disjoint names from ``paths``."""
    return {
        "state": state,
        "disk": state / PERSISTENT_DISK_NAME,
        "vars": state / PERSISTENT_VARS_NAME,
        "marker": state / PERSISTENT_MARKER_NAME,
    }


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_state_path(state: Path) -> bool:
    """Refuse state paths whose existing components include a symlink."""
    candidate = state.absolute()
    for component in (candidate, *candidate.parents):
        if component.exists() and component.is_symlink():
            return False
    return True


def load_network_config(path: Path) -> dict[str, str]:
    """Load a private config for a host-created tap already on a bridge."""
    if not _regular_file(path):
        raise ValueError("network config must be a regular file, not a symlink")
    stat = path.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ValueError(
            "network config must be owned by this user and no broader than 0600")
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read network config: {error}") from error
    expected = {"schema", "mode", "tap", "bridge", "uplink", "mac"}
    if not isinstance(raw, dict) or set(raw) != expected:
        raise ValueError(
            "network config requires only schema, mode, tap, bridge, uplink, "
            "and mac")
    if raw["schema"] != 2 or raw["mode"] != "precreated-tap":
        raise ValueError("network config must select schema 2 precreated-tap")
    for key in ("tap", "bridge", "uplink"):
        if not isinstance(raw[key], str) or not _NET_NAME.fullmatch(raw[key]):
            raise ValueError(f"invalid {key} interface name")
    if (not isinstance(raw["mac"], str)
            or not re.fullmatch(
                r"52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}",
                raw["mac"].lower())):
        raise ValueError("MAC must use the synthetic 52:54:00 prefix")
    return {key: str(value) for key, value in raw.items() if key != "schema"}


def tap_network_args(config: dict[str, str], *, verify_host: bool) -> list[str]:
    """Attach only a named, pre-created tap with verified bridge membership."""
    tap = config["tap"]
    bridge = config["bridge"]
    uplink = config["uplink"]
    if verify_host:
        tap_path = SYS_CLASS_NET / tap
        bridge_path = SYS_CLASS_NET / bridge
        uplink_path = SYS_CLASS_NET / uplink
        membership = tap_path / "master"
        if not all(path.is_dir()
                   for path in (tap_path, bridge_path, uplink_path)):
            raise ValueError(
                "configured tap, bridge, and uplink must already exist")
        if not (bridge_path / "bridge").is_dir():
            raise ValueError(f"{bridge} is not a Linux bridge")
        if (not membership.is_symlink()
                or membership.resolve() != bridge_path.resolve()):
            raise ValueError(f"{tap} is not attached to configured bridge {bridge}")
        tun_flags = tap_path / "tun_flags"
        if not tun_flags.is_file():
            raise ValueError(f"{tap} is not a TAP interface")
        try:
            flags = int(tun_flags.read_text().strip(), 0)
        except (OSError, ValueError) as error:
            raise ValueError(f"cannot read {tap} TAP flags") from error
        if flags & 0x000f != 0x0002:
            raise ValueError(f"{tap} is not a TAP interface")
        owner = tap_path / "owner"
        try:
            tap_owner = int(owner.read_text().strip())
        except (OSError, ValueError) as error:
            raise ValueError(f"cannot read {tap} owner") from error
        if tap_owner != os.getuid():
            raise ValueError(
                f"{tap} owner {tap_owner} does not match invoking user "
                f"{os.getuid()}")
        for name, path in (
            (tap, tap_path), (bridge, bridge_path), (uplink, uplink_path)
        ):
            try:
                link_flags = int((path / "flags").read_text().strip(), 0)
            except (OSError, ValueError) as error:
                raise ValueError(f"cannot read {name} link flags") from error
            if not link_flags & 0x1:
                raise ValueError(f"{name} is not UP")
        uplink_master = uplink_path / "master"
        if (not uplink_master.is_symlink()
                or uplink_master.resolve() != bridge_path.resolve()):
            raise ValueError(
                f"{uplink} is not attached to configured bridge {bridge}")
        if not (uplink_path / "device").exists():
            raise ValueError(
                f"{uplink} is not an identifiable physical interface")
    return [
        "-nodefaults",
        "-netdev",
        f"tap,id=bootstrap,ifname={tap},script=no,downscript=no",
        "-device",
        f"virtio-net-pci,netdev=bootstrap,mac={config['mac'].lower()}",
    ]


def _private_state(files: dict[str, Path]) -> bool:
    if files["state"].stat().st_mode & 0o077:
        return False
    return all(not (files[key].stat().st_mode & 0o077)
               for key in ("disk", "vars", "manifest"))


def qemu_command(
    state: Path,
    iso: Path | None,
    seed_iso: Path | None = None,
    network_config: dict[str, str] | None = None,
    verify_host_network: bool = False,
    *,
    files: dict[str, Path] | None = None,
    socket_port: int = DEFAULT_PORT,
    name: str = NAME,
) -> list[str]:
    # ``files``, ``socket_port`` and ``name`` let a persistent instance reuse
    # this command shape without renaming its disk to the acceptance name,
    # without sharing the acceptance loopback segment, and while staying
    # distinguishable in ``ps``. Omitting them keeps the acceptance layout, so
    # every existing caller is byte-for-byte unchanged.
    files = paths(state) if files is None else files
    pair = ovmf_pair()
    code = pair[0] if pair else Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd")
    command = [
        "qemu-system-x86_64",
        "-name", name,
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-smp", str(VCPUS),
        "-m", str(MEMORY_MIB),
        "-display", "none",
        "-serial", "mon:stdio",
        "-boot", "strict=on,menu=off",
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={files['vars']}",
        "-drive", (
            f"if=none,id=osdisk,format=qcow2,cache=none,"
            f"file={files['disk']}"
        ),
        "-device", (
            f"virtio-blk-pci,drive=osdisk,serial={DISK_SERIAL},"
            f"bootindex={2 if iso else 1}"
        ),
    ]
    if network_config is None:
        command += socket_network_args(
            role="listen", mac=SOCKET_MAC, port=socket_port)
    else:
        command += tap_network_args(
            network_config, verify_host=verify_host_network)
    if iso:
        command += [
            "-device", "virtio-scsi-pci,id=mediabus",
            "-drive",
            f"if=none,id=installmedia,media=cdrom,readonly=on,"
            f"file={iso.resolve()}",
            "-device",
            "scsi-cd,bus=mediabus.0,drive=installmedia,bootindex=1",
        ]
    if seed_iso:
        if not iso:
            command += ["-device", "virtio-scsi-pci,id=mediabus"]
        command += [
            "-drive",
            f"if=none,id=seedmedia,media=cdrom,readonly=on,"
            f"file={seed_iso.resolve()}",
            "-device", "scsi-cd,bus=mediabus.0,drive=seedmedia,bootindex=3",
        ]
    return command


def create(state: Path, apply: bool) -> int:
    files = paths(state)
    pair = ovmf_pair()
    problems = []
    if not shutil.which("qemu-img"):
        problems.append("qemu-img is not installed")
    if not pair:
        problems.append("OVMF firmware was not found")
    if not _safe_state_path(state):
        problems.append(f"state path includes a symlink: {state}")
    if state.exists():
        problems.append(f"state already exists at {state}")
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2
    print(f"create {files['disk']} ({DISK_SIZE}, qcow2)")
    print(f"copy writable firmware variables to {files['vars']}")
    if not apply:
        print("dry run; repeat with --apply")
        return 0
    state.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{state.name}.", dir=state.parent))
    try:
        staging.chmod(0o700)
        staging_files = paths(staging)
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2",
             str(staging_files["disk"]), DISK_SIZE],
            check=True,
        )
        shutil.copyfile(pair[1], staging_files["vars"])
        manifest = {
            "schema": 1,
            "created_utc": datetime.now(UTC).isoformat(),
            "name": NAME,
            "vcpus": VCPUS,
            "memory_mib": MEMORY_MIB,
            "disk": {
                "format": "qcow2",
                "size": DISK_SIZE,
                "serial": DISK_SERIAL,
            },
            "firmware": {
                "code": str(pair[0]),
                "variables_source": str(pair[1]),
                "variables_sha256": _sha256(pair[1]),
            },
            "network": {
                "mode": "qemu-socket-loopback",
                "physical_attachment": "blocked-pending-network-gate",
            },
        }
        staging_files["manifest"].write_text(
            json.dumps(manifest, indent=2) + "\n")
        for key in ("disk", "vars", "manifest"):
            staging_files[key].chmod(0o600)
        staging.rename(state)
    except BaseException:
        shutil.rmtree(staging)
        raise
    print(f"created {NAME}; no VM was started")
    return 0


#: Written beside ``manifest.json`` by ``bootstrap_install``. Named here so
#: ``status`` can report an installation this factory actually performed
#: instead of inferring one, and so the name has a single owner.
INSTALL_RECEIPT_NAME = "install-receipt.json"


def _installation_report(files: dict[str, Path]) -> tuple[bool | None, str]:
    """Whether the canonical image holds an installed Controller, and why.

    ``None`` means "could not be determined", which is reported as unknown
    rather than swallowed: this is a status query, and the one thing it must
    not do is call an image ready when nobody has checked.
    """
    try:
        state = probe_controller_image(files["disk"])
    except ControllerImageError as error:
        return None, f"unknown; the image could not be inspected ({error})"
    if not state.installed:
        return False, f"not installed; {state.reason}"
    receipt = files["state"] / INSTALL_RECEIPT_NAME
    if not _regular_file(receipt):
        return True, (
            f"installed ({state.reason}), but not by this factory: there is "
            f"no {INSTALL_RECEIPT_NAME} beside the manifest")
    try:
        recorded = json.loads(receipt.read_text())
        when = recorded["installed_utc"]
        digest = recorded["disk"]["sha256_after"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        return True, (
            f"installed ({state.reason}); its receipt is unreadable ({error})")
    current = _sha256(files["disk"])
    drift = "" if current == digest else (
        f"; the disk has changed since (now {current})")
    return True, f"installed by this factory {when}, disk sha256 {digest}{drift}"


def status(state: Path) -> int:
    files = paths(state)
    safe = _safe_state_path(state)
    regular = safe and all(
        _regular_file(files[key]) for key in ("disk", "vars", "manifest"))
    private = regular and _private_state(files)
    installed, installation = (
        _installation_report(files) if private else (None, "unknown"))
    # "Ready" used to mean only that three files exist with the right modes,
    # which a never-installed 197,888-byte image satisfies -- and every
    # consumer inherited the blind spot. Readiness now requires a proven
    # installation, and every other outcome exits nonzero and says which one
    # it is.
    if not private:
        headline = "absent or incomplete"
    elif installed is True:
        headline = "ready"
    elif installed is False:
        headline = "created but not installed"
    else:
        headline = "present; installation state unknown"
    print(f"{NAME}: {headline}")
    print(f"state: {state}")
    if private:
        print(f"installation: {installation}")
    print("network: isolated (QEMU socket segment on host loopback)")
    print("convergence: deferred until the physical-network gate is approved")
    return 0 if installed is True else 1


def run(
    state: Path,
    iso: Path | None,
    apply: bool,
    seed_iso: Path | None = None,
    network_config_path: Path | None = None,
    network_receipt_path: Path | None = None,
    confirm: str | None = None,
) -> int:
    files = paths(state)
    if not _safe_state_path(state):
        print(f"error: state path includes a symlink: {state}", file=sys.stderr)
        return 2
    if state.is_dir() and all(
            _regular_file(files[key]) for key in ("disk", "vars", "manifest")
    ) and not _private_state(files):
        print("error: state permissions must be 0700 with 0600 files",
              file=sys.stderr)
        return 2
    missing = [str(files[key]) for key in ("disk", "vars", "manifest")
               if not _regular_file(files[key])]
    if not shutil.which("qemu-system-x86_64"):
        missing.append("qemu-system-x86_64")
    if iso and not iso.is_file():
        missing.append(str(iso))
    if seed_iso and not seed_iso.is_file():
        missing.append(str(seed_iso))
    if missing:
        print("error: missing: " + ", ".join(missing), file=sys.stderr)
        return 2
    network_config = None
    if network_receipt_path is not None and network_config_path is None:
        print("error: --network-receipt requires --network-config",
              file=sys.stderr)
        return 2
    if network_config_path is not None:
        if os.geteuid() == 0:
            print("error: physical-network attachment refuses root",
                  file=sys.stderr)
            return 2
        if iso is not None or seed_iso is not None:
            print("error: physical-network attachment is disk-only; "
                  "installer media are forbidden", file=sys.stderr)
            return 2
        if apply and confirm != "attach-bootstrap-dc":
            print("error: attachment requires "
                  "--confirm attach-bootstrap-dc", file=sys.stderr)
            return 2
        if apply and network_receipt_path is None:
            print("error: physical-network attachment requires a fresh "
                  "--network-receipt", file=sys.stderr)
            return 2
        if apply:
            try:
                expected_commit = subprocess.run(
                    ["git", "-C", str(REPOSITORY), "rev-parse", "HEAD"],
                    check=True, capture_output=True, text=True,
                ).stdout.strip()
                verify_preflight_receipt(
                    network_receipt_path, files["disk"], DISK_SERIAL,
                    expected_commit)
            except (OSError, ValueError, subprocess.CalledProcessError) as error:
                print(f"error: network preflight receipt: {error}",
                      file=sys.stderr)
                return 2
        try:
            network_config = load_network_config(network_config_path)
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
    try:
        command = qemu_command(
            state, iso, seed_iso, network_config,
            verify_host_network=apply and network_config is not None)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(" ".join(str(part) for part in command))
    if network_config is not None:
        print(
            "network: pre-created tap "
            f"{network_config['tap']} on bridge {network_config['bridge']}")
        if not apply:
            print("authorization: dry-run only; applied launch also requires "
                  "a fresh authorized preflight receipt")
    if not apply:
        print("dry run; repeat with --apply")
        return 0
    return subprocess.run(command, check=False).returncode


def destroy(state: Path, confirm: str | None) -> int:
    if confirm != NAME:
        print(f"refusing: pass --confirm {NAME}", file=sys.stderr)
        return 2
    if not _safe_state_path(state):
        print(f"refusing: state path includes a symlink: {state}",
              file=sys.stderr)
        return 2
    files = paths(state)
    if not state.exists():
        print(f"{NAME}: already absent")
        return 0
    # ``ControllerOverlay`` leaves its advisory lock file behind by design, so
    # any simulation run against this image used to make destruction refuse
    # forever. Expect the name -- as the persistent instance's own destroy
    # already does -- but never confuse a stale file for a free disk: take the
    # lock before erasing anything, or a run in flight would have its disk
    # removed underneath it. Every other unexpected entry still fails closed,
    # and a symlink is still refused.
    lock_path = state / LOCK_NAME
    expected = set(files.values()) | {lock_path}
    unexpected = [
        entry for entry in state.iterdir()
        if entry not in expected or entry.is_symlink()
    ]
    if unexpected:
        print("refusing: state directory contains unexpected files:", file=sys.stderr)
        for entry in unexpected:
            print(f"  {entry}", file=sys.stderr)
        return 2
    lock_stream = None
    if lock_path.is_file():
        lock_stream = lock_path.open("a")
        try:
            fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            lock_stream.close()
            print(f"refusing: {NAME} is open elsewhere; its lock is held. Stop "
                  "the run using it and retry.", file=sys.stderr)
            return 2
    try:
        for key in ("disk", "vars", "manifest"):
            files[key].unlink(missing_ok=True)
        lock_path.unlink(missing_ok=True)
    finally:
        if lock_stream is not None:
            fcntl.flock(lock_stream.fileno(), fcntl.LOCK_UN)
            lock_stream.close()
    state.rmdir()
    print(f"destroyed temporary state at {state}")
    return 0


def _persistent_state(root: Path, instance: str) -> Path:
    """Resolve one instance directory, refusing a name that could traverse."""
    if not PersistentControllerInstance.valid_instance_name(instance):
        raise ValueError(
            "instance must be 1-32 lowercase letters, digits, or hyphens and "
            "must not start or end with a hyphen")
    return Path(root) / instance


def _persistent_directory_summary(
    target: PersistentControllerInstance, existing: bool,
) -> str:
    """One honest line about whether this instance holds a real directory.

    Tolerant on purpose: a marker this reader cannot understand must not turn a
    bring-up or a status query into a failure, so an unreadable record is
    reported as unknown. Every path that *acts* on the marker still reads it
    through the fail-closed ``read_marker``.
    """
    if not existing:
        return "none yet; this instance has not been created"
    try:
        recorded = target.convergence()
    except (ValueError, RuntimeError) as error:
        return f"unknown; the convergence record is unreadable ({error})"
    if recorded is None:
        return (
            "not provisioned; this instance holds an installed Controller with "
            "no domain. Run persistent-converge to provision one")
    return (
        f"converged {recorded['converged_utc']}; realm {recorded.get('realm')}; "
        f"domain SID {recorded.get('domain_sid')}")


def _persistent_running(target: PersistentControllerInstance) -> bool | None:
    """Whether the instance lock is held; ``None`` when it cannot be probed."""
    if not target.lock_path.is_file():
        return False
    try:
        with target.lock_path.open("a+b") as stream:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    except OSError:
        return None
    return False


def persistent_up(
    root: Path,
    instance: str,
    apply: bool,
    *,
    canonical_state: Path = DEFAULT_STATE,
    seed_iso: Path | None = None,
) -> int:
    """Create when absent, then boot one persistent controller instance.

    Persistence is requested here and nowhere else: no runner infers it, and the
    disposable acceptance path never reaches this function. The instance's own
    disk is booted in place and is not hash-fenced, which is exactly why the
    acceptance canonical is refused before anything is printed or created.
    """
    try:
        state = _persistent_state(root, instance)
        target = PersistentControllerInstance(state, instance=instance)
        canonical = paths(canonical_state)
        target.assert_separate(canonical["disk"])
    except (ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    files = persistent_paths(state)
    existing = target.exists()
    try:
        # A read-only convergence/seed CD is the only extra medium this mode
        # accepts: installer media would reinstall over the directory this mode
        # exists to keep.
        command = qemu_command(
            state, None, seed_iso, files=files,
            socket_port=PERSISTENT_SOCKET_PORT,
            name=f"persistent-dc-{instance}")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"persistent controller instance: {instance}")
    print(f"state: {state}")
    print("mode: persistent; this disk is the durable directory and is not "
          "hash-fenced")
    if existing:
        print("bring-up: reuse the retained directory state")
    else:
        print(f"bring-up: seed {files['disk']} from {canonical['disk']}")
    # A bring-up must never imply a directory that is not there. An instance
    # seeded straight from the canonical image is an installed Controller with
    # no domain at all, and persistent-converge is the step that provisions one.
    print("directory: " + _persistent_directory_summary(target, existing))
    print(f"acceptance canonical: {canonical['state']} is read-only here and "
          "is never a persistent target")
    print(" ".join(str(part) for part in command))
    if not apply:
        print("dry run; repeat with --apply")
        return 0

    problems = [f"{tool} is not installed" for tool in
                ("qemu-system-x86_64", "qemu-img") if not shutil.which(tool)]
    if seed_iso is not None and not seed_iso.is_file():
        problems.append(f"{seed_iso} is missing")
    if not existing:
        problems += [str(canonical[key]) + " is missing"
                     for key in ("disk", "vars")
                     if not _regular_file(canonical[key])]
        # Seeding from a never-installed canonical produces an 80 GiB blank
        # instance that boots to a UEFI dead end and a marker recording the
        # hash of an empty image -- with a success-shaped exit. Refuse before
        # anything is created or locked, and say what to do about it.
        if not problems:
            try:
                assert_installed_controller_image(
                    canonical["disk"],
                    subject=f"the canonical image {canonical['disk']}")
            except ControllerImageError as error:
                problems.append(str(error))
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2
    try:
        if not existing:
            marker = target.create(canonical["disk"], canonical["vars"])
            print(f"seeded {instance} from "
                  f"{marker['seeded_from']['disk_sha256']}")
        target.prepare()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    try:
        returncode = subprocess.run(command, check=False).returncode
    except BaseException:
        # Release the lock on interruption, but never let a teardown error hide
        # why the run stopped.
        with contextlib.suppress(BaseException):
            target.close()
        raise
    # The guest QEMU has just exited but may still be visible in /proc for an
    # instant, so retry the release exactly as DisposableBootDisk.close does
    # rather than failing a good run on a teardown race.
    for attempt in range(6):
        try:
            target.close()
            break
        except (RuntimeError, OSError) as error:
            if attempt == 5:
                print(f"error: {error}", file=sys.stderr)
                return 2
            time.sleep(0.1)
    print(f"{instance}: guest exited; directory state retained at {state}")
    return returncode


class _AnnouncedEvents(list):
    """A serial event log that also reports progress to the operator.

    ``SerialAutomation`` records progress by appending to ``events`` and offers
    no callback, and a persistent convergence is a long wait behind a silent
    pipe. Substituting this list reports each stage as it happens without
    touching ``serial_automation.py``, which every acceptance gate shares.
    """

    def __init__(self, on_event: Callable[[str], None] | None = None) -> None:
        super().__init__()
        self.on_event = on_event

    def append(self, event: object) -> None:
        super().append(event)
        print(f"  {event}", flush=True)
        if self.on_event is not None:
            self.on_event(str(event))


def _controlling_terminal() -> bool:
    """True when this process can read a credential from its own terminal."""
    try:
        with open("/dev/tty", "rb"):
            return True
    except OSError:
        return False


def _typed_secret(prompt: str, *, confirm: str | None = None) -> bytes:
    """Read one operator credential from the controlling terminal only.

    Deliberately not a file, an environment variable, a Make variable or an
    argv element. These are *real* credentials — the console password the
    offline installer asked the operator to type, and the domain Administrator
    password the directory will keep for good — and this repository's rule for
    exactly those values is that they are typed directly and never land
    anywhere they could be read again. Without a terminal this fails closed
    rather than silently accepting an echoed or stored value.
    """
    if not _controlling_terminal():
        raise ValueError(
            "persistent convergence reads its credentials from a controlling "
            "terminal and from nowhere else: not a file, argv, an environment "
            "variable, or a Make variable")
    value = getpass.getpass(prompt)
    if confirm is not None and getpass.getpass(confirm) != value:
        raise ValueError("the two credential entries did not match")
    if not value or len(value) > 512:
        raise ValueError("a credential must be one non-empty line")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("a credential must not contain control characters")
    return value.encode("utf-8")


def _console_root(
    console: SerialAutomation,
    command: str,
    label: str,
    *,
    value: bytes | None = None,
) -> bytes | None:
    """Run one bounded root command over an authenticated console.

    Modelled on the identity lane's controller helper: only fixed switches and
    one quoted literal cross the wire, the credential answers sudo's own
    private prompt, and a nonzero result is a distinctly named failure instead
    of a silent continuation. With ``value`` the command's single-line output is
    returned, proven against that pattern before the return code is read.
    """
    if console.password is None:
        raise SerialAutomationError(
            f"persistent controller credential is unavailable: {label}")
    if not command or "\n" in command:
        raise SerialAutomationError(
            f"persistent controller command is invalid: {label}")
    token = os.urandom(16).hex().encode("ascii")
    prompt = b"__TELOS_PERSISTENT_SUDO_" + token + b"__"
    emitted = b"__TELOS_PERSISTENT_VALUE_" + token + b"="
    result = b"__TELOS_PERSISTENT_RC_" + token + b"="
    payload = command
    if value is not None:
        payload = (
            f"__telos_value=$({command}); "
            f"printf '\\n{emitted.decode('ascii')}%s\\n' \"$__telos_value\"")
    console._send(b"", label + "-shell-requested")
    console._wait(rb"(?:^|\n)[^\n]*\$\s*$", label + "-shell-ready")
    console._send(
        b"sudo -k -S -p '" + prompt + b"' /usr/bin/bash -c "
        + shlex.quote(payload).encode("ascii")
        + b"; __telos_rc=$?; printf '\\n" + result
        + b"%s\\n' \"$__telos_rc\"",
        label + "-command-sent")
    console._wait(
        rb"(?:^|[\r\n])" + re.escape(prompt) + rb"\s*$", label + "-sudo-prompt")
    console._send(console.password, label + "-password-sent")
    observed = None
    if value is not None:
        match = console._wait(
            rb"(?:^|\n)" + re.escape(emitted) + rb"(" + value + rb")\s*(?:\n|$)",
            label + "-value")
        observed = match.group(1)
    match = console._wait(
        rb"(?:^|\n)" + re.escape(result) + rb"([0-9]+)\s*(?:\n|$)",
        label + "-result")
    if int(match.group(1)) != 0:
        raise SerialAutomationError(
            f"persistent controller command failed: {label}")
    return observed


def _console_poweroff(
    console: SerialAutomation, password: bytes, label: str,
) -> None:
    """Power the guest off through the same authenticated console.

    ``sudo -n`` cannot be used because every command on this path passes ``-k``
    and so deliberately leaves no cached credential behind. The credential
    answers sudo's own private prompt, which sudo only prints once it has
    disabled echo on the tty, and every wait is bounded by the console's own
    timeout.
    """
    token = os.urandom(16).hex().encode("ascii")
    prompt = b"__TELOS_PERSISTENT_POWEROFF_" + token + b"__"
    console._send(b"", label + "-shell-requested")
    console._wait(rb"(?:^|\n)[^\n]*\$\s*$", label + "-shell-ready")
    console._send(
        b"sudo -k -S -p '" + prompt + b"' /usr/bin/systemctl poweroff",
        label + "-command-sent")
    console._wait(
        rb"(?:^|[\r\n])" + re.escape(prompt) + rb"\s*$", label + "-sudo-prompt")
    console._send(password, label + "-password-sent")
    console._wait(
        rb"(?:Reached target System Power Off|reboot: Power down)",
        label + "-observed")


def _extra_read_only_medium(
    medium: Path, *, drive_id: str, bootindex: int,
) -> list[str]:
    """Attach one more read-only data CD to the bus ``qemu_command`` created.

    Additive on purpose: ``qemu_command`` keeps emitting byte-identical argv for
    every existing caller, and no acceptance path reaches this function.
    """
    return [
        "-drive",
        f"if=none,id={drive_id},media=cdrom,readonly=on,"
        f"file={medium.resolve()}",
        "-device",
        f"scsi-cd,bus=mediabus.0,drive={drive_id},bootindex={bootindex}",
    ]


def _attach_simulated_gateway(
    port: int, log: Path, *, guest: subprocess.Popen[bytes] | None = None,
) -> subprocess.Popen[bytes]:
    """Attach the userspace peer the convergence measures its clock against.

    Not optional: the factory payload fails closed unless it can measure NTP
    against 198.51.100.10, which exists only inside this simulator. It is the
    same program the acceptance simulation uses, in its ``--connect`` role, so
    nothing on the host is created, changed, or bound outside loopback.
    """
    program = Path(__file__).with_name("simulated_gateway.py")
    argv = [
        sys.executable, str(program), "--connect", "--port", str(port),
        "--controller-mac", SOCKET_MAC,
    ]
    descriptor = os.open(
        log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        stream = os.fdopen(descriptor, "wb")
    except BaseException:
        os.close(descriptor)
        raise
    with stream:
        for _attempt in range(GATEWAY_ATTACH_ATTEMPTS):
            # A guest that has already exited will never bind the segment, so
            # stop immediately rather than spending the whole retry budget.
            if guest is not None and guest.poll() is not None:
                raise RuntimeError(
                    "the persistent controller guest exited before its "
                    f"loopback segment was attached (status {guest.poll()})")
            child = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=stream,
                stderr=subprocess.STDOUT)
            time.sleep(GATEWAY_ATTACH_DELAY)
            if child.poll() is None:
                return child
    raise RuntimeError(
        "the simulated gateway peer could not attach to the persistent "
        f"instance's loopback segment on 127.0.0.1:{port}")


#: The payload announces this stage immediately before the play that creates
#: the directory (``controller_factory.py``: ``TELOS FACTORY STEP ansible``).
#: Recording on the *start* of the stage rather than its completion is the
#: conservative choice: a failure inside the play can leave a provisioned
#: directory, and the record exists to stop a later run from believing
#: otherwise.
PROVISIONING_STAGE_EVENT = "controller-convergence-stage-ansible"


def _provisioning_recorder(
    target: PersistentControllerInstance,
) -> Callable[[str], None]:
    """Persist "this run reached provisioning" the moment the guest says so."""
    def record(event: str) -> None:
        if event != PROVISIONING_STAGE_EVENT:
            return
        try:
            target.record_provisioning_attempt()
        except (RuntimeError, OSError) as error:
            # Never kill a live provisioning run over a host-side note, but
            # never hide it either: without this record a later attempt would
            # ask for an Administrator password it cannot apply.
            print(f"  warning: could not record the provisioning attempt "
                  f"({error}); if this run fails, do NOT let a retry set a "
                  f"new Administrator password", file=sys.stderr, flush=True)
    return record


def _drive_persistent_convergence(
    process: subprocess.Popen[bytes],
    password: bytes,
    nonce: str,
    spec: FactorySpec,
    *,
    install_seed: bool,
    timeout: float,
    on_event: Callable[[str], None] | None = None,
) -> dict:
    """Log in normally, converge the durable disk, and prove what it now holds.

    Every step here runs against the instance's *own* loader entry: no ESP was
    rewritten, there is no init shell, and the only way in is the console
    account the offline installer created. ``converge_disposable_controller`` is
    reused verbatim because it is the proven protocol — it tracks the payload's
    named stages, requires ``TELOS FACTORY CONTROLLER PASS``, proves the
    convergence media were released, and proves ``samba.service`` live with a
    real ``sam.ldb`` before returning. Its *name* is a wart here; renaming it
    would touch a module every acceptance gate shares, so this comment carries
    the meaning instead.
    """
    if process.stdout is None or process.stdin is None:
        raise RuntimeError(
            "persistent controller serial pipes were not created")
    console = SerialAutomation(
        process.stdout, process.stdin, password,
        timeout=PERSISTENT_CONSOLE_TIMEOUT)
    console.events = _AnnouncedEvents(on_event)
    console._wait(
        rb"(?:^|\n)" + re.escape(NAME.encode("ascii")) + rb" login:\s*$",
        "persistent-login-prompt")
    console._send(CONSOLE_ACCOUNT.encode("ascii"), "persistent-username-sent")
    console._wait(rb"(?:^|\n)Password:\s*$", "persistent-login-password-prompt")
    console._send(password, "persistent-login-password-sent")
    console._wait(rb"(?:^|\n)[^\n]*\$\s*$", "persistent-shell-ready")
    if install_seed:
        console.install_offline_controller_dependencies()
    console.converge_disposable_controller(
        FactoryBundle.guest_command(nonce), timeout=timeout)
    _console_root(
        console, ADMINISTRATOR_ENABLE, "persistent-administrator-enable")
    sid = _console_root(
        console, DOMAIN_SID_COMMAND, "persistent-domain-sid",
        value=rb"S-1-5-21(?:-[0-9]{1,10}){3}")
    record = {
        "converged_utc": datetime.now(UTC).isoformat(),
        "realm": spec.realm,
        "netbios": spec.netbios,
        "dns_domain": spec.domain,
        "domain_sid": None if sid is None else sid.decode("ascii"),
        "administrator": (
            "enabled; its password was typed by the operator and is not "
            "stored by this harness"),
        "console_credential": (
            f"{CONSOLE_ACCOUNT}, as set by the offline installer; this "
            "convergence neither changed it nor recorded it"),
        "esp": "unmodified; the instance boots its own loader default",
    }
    _console_poweroff(console, password, "persistent-poweroff")
    return record


def persistent_converge(
    root: Path,
    instance: str,
    apply: bool,
    *,
    canonical_state: Path = DEFAULT_STATE,
    seed_iso: Path | None = None,
    reconverge: bool = False,
    timeout: float = PERSISTENT_CONVERGE_TIMEOUT,
) -> int:
    """Provision Active Directory into one persistent instance, in place.

    This is the step that turns an instance seeded from the canonical image
    (an installed Controller with no directory at all) into a directory server
    whose domain survives being shut down and brought up again. It is separate
    from ``persistent-up`` on purpose: it is long-running, it needs credentials
    typed at a terminal, it builds and destroys a secret-bearing medium, and it
    attaches a simulated peer — none of which belong in a bring-up that must
    stay fast and idempotent.

    Three properties matter more than the mechanism:

    * *the durable ESP is never rewritten.* No ``init=/bin/bash`` entry and no
      loader default is touched, because the login uses the console account the
      offline installer already created.
    * *no harness-generated credential reaches durable state.* Both credentials
      are typed by the operator, held in memory, and never written to a file,
      argv, transcript, or the marker.
    * *the acceptance path cannot be reached.* Every refusal
      ``persistent-up`` runs, runs here first and before anything is printed.
    """
    try:
        state = _persistent_state(root, instance)
        target = PersistentControllerInstance(state, instance=instance)
        canonical = paths(canonical_state)
        target.assert_separate(canonical["disk"])
    except (ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    files = persistent_paths(state)
    existing = target.exists()
    recorded = None
    attempted = None
    if existing:
        try:
            recorded = target.convergence()
            attempted = target.provisioning_attempted()
        except (ValueError, RuntimeError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
    # The domain Administrator password can only ever be *set* by the run that
    # provisions the directory; the role skips provisioning once ``sam.ldb``
    # exists. Prompting is therefore keyed on whether any run has reached the
    # provisioning stage, not on whether one has finished -- otherwise a
    # failure in the window between those two facts makes every retry ask for,
    # confirm, and silently discard a credential that cannot take effect.
    prompts_for_administrator = recorded is None and attempted is None
    spec = FactorySpec()
    try:
        command = qemu_command(
            state, None, None, files=files,
            socket_port=PERSISTENT_SOCKET_PORT,
            name=f"persistent-dc-{instance}")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"persistent controller instance: {instance}")
    print(f"state: {state}")
    print("mode: persistent convergence; the durable disk is provisioned in "
          "place and its ESP is never rewritten")
    if not existing:
        print(f"bring-up: seed {files['disk']} from {canonical['disk']}")
    elif recorded:
        print(f"already converged: {recorded['converged_utc']} "
              f"({recorded.get('realm')}, SID {recorded.get('domain_sid')})")
    else:
        print("bring-up: reuse the retained, not-yet-converged directory state")
    print(f"directory identity: {spec.realm} at {spec.address}/{spec.prefix}")
    print(f"console: this asks at your terminal for the {CONSOLE_ACCOUNT} "
          "password the offline installer told you to type; it is held in "
          "memory only and is neither changed nor recorded")
    if prompts_for_administrator:
        print("domain Administrator: provisioned with a password you type "
              "here, then left enabled so the directory stays administrable")
    elif recorded is not None:
        print("domain Administrator: already provisioned; its password is the "
              "one typed then and is NOT asked for or changed here")
    else:
        print(f"domain Administrator: an earlier attempt reached the "
              f"provisioning stage ({attempted['attempted_utc']}) without "
              "finishing, so the directory may already hold a password you "
              "typed then. This will not ask for a new one")
    print("convergence medium: a per-run TELOS_FACTORY CD built into a private "
          "mode-0700 directory, attached read-only, and destroyed afterwards")
    if seed_iso is not None:
        print(f"seed medium: {seed_iso} (read-only, optional)")
    print("fabric: a simulated gateway peer on "
          f"127.0.0.1:{PERSISTENT_SOCKET_PORT}; the payload measures NTP "
          f"against {spec.ntp_upstream}, which exists only there")
    print(f"acceptance canonical: {canonical['state']} is read-only here and "
          "is never a persistent target")
    print(" ".join(str(part) for part in command))
    if not apply:
        print("dry run; repeat with --apply")
        return 0

    problems = [f"{tool} is not installed" for tool in
                ("qemu-system-x86_64", "qemu-img", "xorriso")
                if not shutil.which(tool)]
    if recorded and not reconverge:
        problems.append(
            f"{instance} is already converged; pass --reconverge to run the "
            "convergent play again. A reconvergence does NOT change the domain "
            "Administrator password, because provisioning is skipped once a "
            "directory exists")
    if recorded is None and attempted is not None and not reconverge:
        problems.append(
            f"{instance} has an unfinished convergence that already reached "
            f"the directory-provisioning stage ({attempted['attempted_utc']}). "
            "If it provisioned, the domain Administrator password is the one "
            "you typed then and cannot be changed by converging again, so "
            "this refuses rather than asking you for a new one it would "
            "discard. Pass --reconverge to continue with the existing "
            "credential, or destroy and recreate the instance for a directory "
            "with a password you choose now")
    if seed_iso is not None and not _regular_file(seed_iso):
        problems.append(f"{seed_iso} is missing")
    if not existing:
        problems += [str(canonical[key]) + " is missing"
                     for key in ("disk", "vars")
                     if not _regular_file(canonical[key])]
        if not problems:
            try:
                assert_installed_controller_image(
                    canonical["disk"],
                    subject=f"the canonical image {canonical['disk']}")
            except ControllerImageError as error:
                problems.append(str(error))
    # Every refusal above happens before the first prompt, deliberately: an
    # operator must never type an unrecoverable secret into a run that cannot
    # possibly succeed.
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2

    console_password = b""
    administrator = None
    try:
        console_password = _typed_secret(
            f"{CONSOLE_ACCOUNT} console password: ")
        if prompts_for_administrator:
            administrator = _typed_secret(
                "new domain Administrator password: ",
                confirm="retype domain Administrator password: ")
    except (ValueError, EOFError, KeyboardInterrupt) as error:
        print(f"error: {error or type(error).__name__}", file=sys.stderr)
        return 2

    try:
        if not existing:
            marker = target.create(canonical["disk"], canonical["vars"])
            print(f"seeded {instance} from "
                  f"{marker['seeded_from']['disk_sha256']}")
        target.prepare()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    run_root = Path(tempfile.mkdtemp(prefix="telos-persistent-converge-"))
    run_root.chmod(0o700)
    nonce = secrets.token_hex(32)
    bundle = FactoryBundle(
        REPOSITORY, run_root / "controller-convergence.iso",
        authorization_nonce=nonce, spec=spec,
        password=None if administrator is None
        else administrator.decode("utf-8"))
    guest: subprocess.Popen[bytes] | None = None
    gateway: subprocess.Popen[bytes] | None = None
    record: dict | None = None
    failure: BaseException | None = None
    try:
        bundle.build()
        # The convergence CD goes through the ``seed_iso`` argument, which is
        # what creates the media bus; an optional dependency seed is then
        # appended to that same bus without changing ``qemu_command``.
        launch = qemu_command(
            state, None, bundle.output, files=files,
            socket_port=PERSISTENT_SOCKET_PORT,
            name=f"persistent-dc-{instance}")
        if seed_iso is not None:
            launch += _extra_read_only_medium(
                seed_iso, drive_id="persistentseedmedia", bootindex=4)
        print(" ".join(str(part) for part in launch))
        guest = subprocess.Popen(
            launch, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=0)
        gateway = _attach_simulated_gateway(
            PERSISTENT_SOCKET_PORT, run_root / "gateway.log", guest=guest)
        record = _drive_persistent_convergence(
            guest, console_password, nonce, spec,
            install_seed=seed_iso is not None, timeout=timeout,
            on_event=_provisioning_recorder(target))
    except BaseException as error:
        failure = error
    finally:
        # The credentials exist only here. Python cannot wipe an immutable
        # bytes object, so the best available step is to drop every reference,
        # including the bundle's in-memory copy, as the factory lanes do.
        bundle.password = ""
        console_password = b""
        administrator = None
        for child in (guest, gateway):
            if child is None or child.poll() is not None:
                continue
            child.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                child.wait(timeout=20)
            if child.poll() is None:
                child.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    child.wait(timeout=10)
        bundle.output.unlink(missing_ok=True)
        # The guest QEMU may still be visible in /proc for an instant, so retry
        # the release exactly as persistent_up does rather than failing a good
        # run on a teardown race.
        for attempt in range(6):
            try:
                target.close()
                break
            except (RuntimeError, OSError) as error:
                if attempt == 5:
                    if failure is None:
                        failure = error
                    break
                time.sleep(0.1)
        shutil.rmtree(run_root, ignore_errors=True)
    if failure is not None or record is None:
        print(f"error: persistent convergence failed: "
              f"{failure or 'no convergence was proved'}", file=sys.stderr)
        return 2
    try:
        target.record_convergence(record)
    except (RuntimeError, OSError) as error:
        # The directory is converged and the disk holds it; only the host-side
        # record failed. Say so distinctly rather than reporting a clean pass.
        print(f"error: the directory converged but its record could not be "
              f"written: {error}", file=sys.stderr)
        return 2
    print(f"{instance}: converged {record['realm']}; domain SID "
          f"{record['domain_sid']}; directory state retained at {state}")
    return 0


def _accounts_recorder(
    target: PersistentControllerInstance,
) -> Callable[[], None]:
    """Persist "this run reached the directory" before it writes anything."""
    def record() -> None:
        try:
            target.record_directory_accounts_attempt()
        except (RuntimeError, OSError) as error:
            # Never kill a live staging run over a host-side note, and never
            # hide it either: without this record a later run would be told the
            # directory holds none of these accounts when it may hold some.
            print(f"  warning: could not record the staging attempt ({error}); "
                  f"if this run fails, list the directory's accounts before "
                  f"staging again", file=sys.stderr, flush=True)
    return record


def _drive_persistent_accounts(
    process: subprocess.Popen[bytes],
    password: bytes,
    values: dict[str, str],
    *,
    roster: dict[str, str],
    roster_source: str,
    timeout: float,
    on_stage: Callable[[], None] | None = None,
    on_event: Callable[[str], None] | None = None,
):
    """Log in normally, prove the directory is live, then stage the roster.

    The whole exchange runs against the instance's *own* loader entry: no ESP
    is rewritten, there is no init shell, and the only way in is the console
    account the offline installer created. ``ControllerPrincipalSerial`` then
    does the actual staging, unchanged and for the same reason
    ``persistent_converge`` reuses ``converge_disposable_controller``: it is
    the proven protocol. It suppresses terminal echo and *proves* it before a
    credential is written, carries the credentials over the guest shell's own
    stdin rather than argv, answers sudo's private prompt from the console
    account, and fails closed on a nonzero result.
    """
    principals = _controller_principals()
    if process.stdout is None or process.stdin is None:
        raise RuntimeError(
            "persistent controller serial pipes were not created")
    console = SerialAutomation(
        process.stdout, process.stdin, password,
        timeout=PERSISTENT_CONSOLE_TIMEOUT)
    console.events = _AnnouncedEvents(on_event)
    console._wait(
        rb"(?:^|\n)" + re.escape(NAME.encode("ascii")) + rb" login:\s*$",
        "persistent-accounts-login-prompt")
    console._send(
        CONSOLE_ACCOUNT.encode("ascii"), "persistent-accounts-username-sent")
    console._wait(
        rb"(?:^|\n)Password:\s*$", "persistent-accounts-login-password-prompt")
    console._send(password, "persistent-accounts-login-password-sent")
    console._wait(rb"(?:^|\n)[^\n]*\$\s*$", "persistent-accounts-shell-ready")
    # Prove the directory is actually serving before anything is typed into it.
    # The host-side marker says a convergence finished; this says samba.service
    # is live with a real sam.ldb on THIS boot. Without it, a guest that came
    # up without its directory would take every credential and only then fail
    # inside the guest program, with the accounts nowhere and the operator's
    # passwords already spent.
    console._wait_controller_ad()
    if on_stage is not None:
        on_stage()
    serial = principals.ControllerPrincipalSerial(
        process.stdout, process.stdin, timeout=timeout,
        password=password, roster=roster, roster_source=roster_source)
    # The same shared-console substitution the Windows and Arch identity lanes
    # make: the protocol runs over the session that is already authenticated,
    # instead of opening a second one that would have to log in again.
    serial.console = console
    original = console.timeout
    console.timeout = timeout
    try:
        result = serial.stage(values)
    finally:
        console.timeout = original
    _console_poweroff(console, password, "persistent-accounts-poweroff")
    return result


def _persistent_accounts_summary(
    target: PersistentControllerInstance, existing: bool,
) -> str:
    """One honest line about this instance's durable account roster."""
    if not existing:
        return "none; this instance has not been created"
    try:
        staged = target.directory_accounts()
        attempted = target.directory_accounts_attempted()
    except (ValueError, RuntimeError) as error:
        return f"unknown; the record is unreadable ({error})"
    if staged is not None:
        roles = ", ".join(
            str(account.get("contract_role"))
            for account in staged["accounts"])
        return (f"staged {staged['staged_utc']}; roster fingerprint "
                f"{staged.get('roster_fingerprint')}; contract roles {roles}")
    if attempted is not None:
        return (
            f"UNFINISHED: a staging run reached the directory at "
            f"{attempted['attempted_utc']} and never proved it finished. Some "
            "of those accounts may exist; list them on the instance before "
            "staging again")
    return ("none staged; run persistent-accounts to stage the owner's "
            "durable roster into this directory")


def persistent_accounts(
    root: Path,
    instance: str,
    apply: bool,
    *,
    canonical_state: Path = DEFAULT_STATE,
    overlay_path: Path | None = None,
    restage: bool = False,
    timeout: float = PERSISTENT_ACCOUNTS_TIMEOUT,
) -> int:
    """Stage the owner's DURABLE account roster over the serial console.

    The gap this closes. ``make homelab-bootstrap-controller`` provisions the
    same durable accounts over host-side Ansible, but that reaches a Controller
    the control host can SSH to, and a *simulated* persistent instance is not
    one: ``persistent_up`` gives it a single QEMU socket netdev to the
    userspace gateway, which ``network.py`` documents as supplying no NAT and
    no route to the host LAN and which ``simulated_gateway.py`` says never
    forwards general traffic. The serial console is the only channel that
    reaches this directory at all, so this verb drives it.

    Four properties matter more than the mechanism:

    * *the synthetic roster is refused.* ``durable_directory_roster`` is
      ``identity_roster(require_overlay=True)``, so a missing or unreadable
      private overlay is a named refusal and never a directory full of
      permanent ``student``/``operator`` SIDs reported as a success.
    * *the privilege separation is not this verb's to widen.* The Domain
      Admins membership is derived, in the guest program, from
      ``DIRECTORY_ADMIN_ROLES``; ``daily_administrator`` is absent from it, so
      the owner's everyday elevated account gets a passworded workstation sudo
      and never a Domain Admins membership (ADR 0055; gate 8's
      ``domain-admin-separate``).
    * *no credential reaches durable state.* Every password is typed at the
      operator's terminal, held in memory, echo-suppressed on the wire and
      carried on the guest shell's stdin. None reaches argv, an environment
      variable, a Make variable, a file, the marker, or a retained transcript.
    * *the acceptance path cannot be reached.* Every refusal ``persistent_up``
      makes runs here first and before anything is printed.
    """
    principals = _controller_principals()
    try:
        state = _persistent_state(root, instance)
        target = PersistentControllerInstance(state, instance=instance)
        canonical = paths(canonical_state)
        target.assert_separate(canonical["disk"])
    except (ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    files = persistent_paths(state)
    if not target.exists():
        print(f"error: there is no persistent controller instance {instance} "
              f"at {state}; create one with persistent-up and give it a "
              f"directory with persistent-converge first", file=sys.stderr)
        return 2
    try:
        recorded = target.convergence()
        staged = target.directory_accounts()
        attempted = target.directory_accounts_attempted()
    except (ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if recorded is None:
        print(f"error: {instance} holds an installed Controller with no "
              f"recorded directory, so there is nothing to stage accounts "
              f"into. Run persistent-converge first", file=sys.stderr)
        return 2
    # Resolved before ANYTHING is printed, and fail-closed on both the dry run
    # and the applied one: an operator must learn that their private overlay is
    # missing from a plan, not from a refusal after they have typed four
    # credentials.
    try:
        roster = principals.durable_directory_roster(overlay_path)
        plan = principals.directory_account_plan(
            list(principals.DIRECTORY_ROLES), roster=roster)
        fingerprint = principals.identity_roster_fingerprint(roster)
        source = principals.identity_roster_source(overlay_path)
    except (principals.IdentityRosterError, principals.DirectoryPlanError,
            OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    try:
        command = qemu_command(
            state, None, None, files=files,
            socket_port=PERSISTENT_SOCKET_PORT,
            name=f"persistent-dc-{instance}")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"persistent controller instance: {instance}")
    print(f"state: {state}")
    print("mode: durable directory accounts; the owner's real roster is "
          "staged into the directory this instance already holds")
    print(f"directory: converged {recorded['converged_utc']}; realm "
          f"{recorded.get('realm')}; domain SID {recorded.get('domain_sid')}")
    print(f"roster source: {source}")
    print(f"roster fingerprint: {fingerprint}")
    if staged is not None:
        print(f"already staged: {staged['staged_utc']} (roster fingerprint "
              f"{staged.get('roster_fingerprint')})")
    elif attempted is not None:
        print("unfinished staging: an earlier run reached the directory at "
              f"{attempted['attempted_utc']} without proving it finished")
    print("accounts, by contract role. Real account names are instance data "
          "(ADR 0046): they are never printed here, never recorded in the "
          "instance marker, and appear only in the prompts at your own "
          "terminal, so you know whose password you are setting:")
    for entry in plan:
        print(f"  {entry['contract_role']}: directory role {entry['role']}, "
              f"uidNumber {entry['uidNumber']}, gidNumber "
              f"{entry['gidNumber']}")
    print("privilege separation: only "
          + ", ".join(principals.DIRECTORY_ADMIN_ROLES)
          + f" joins {principals.POSIX_ADMIN_GROUP}. daily_administrator is "
          "the workstation's passworded-sudo administrator and is never a "
          "Domain Admins member (ADR 0055; gate 8 domain-admin-separate)")
    print(f"console: this asks at your terminal for the {CONSOLE_ACCOUNT} "
          "password the offline installer told you to type, then one password "
          "per contract role. All are held in memory only, echo-suppressed on "
          "the wire, and never written to a file, argv, an environment "
          "variable, a Make variable, the instance marker, or this transcript")
    print("fabric: a simulated gateway peer on "
          f"127.0.0.1:{PERSISTENT_SOCKET_PORT}. This instance has no NAT and "
          "no route to the host LAN, which is why the roster is staged over "
          "the serial console instead of by host-side Ansible")
    print(f"acceptance canonical: {canonical['state']} is read-only here and "
          "is never a persistent target")
    print(" ".join(str(part) for part in command))
    if not apply:
        print("dry run; repeat with --apply")
        return 0

    problems = [f"{tool} is not installed" for tool in
                ("qemu-system-x86_64", "qemu-img") if not shutil.which(tool)]
    if staged is not None and not restage:
        problems.append(
            f"{instance} already holds a staged durable roster "
            f"({staged['staged_utc']}). Staging CREATES accounts and stops on "
            "the first one the directory already has, so this refuses rather "
            "than asking you for credentials it would discard. Pass --restage "
            "only to add a roster this directory does not have yet")
    if staged is None and attempted is not None and not restage:
        problems.append(
            f"{instance} has an unfinished staging run that already reached "
            f"the directory ({attempted['attempted_utc']}). Some of those "
            "accounts may exist with the credentials typed then, and staging "
            "again would stop on the first of them. List the directory's "
            "accounts on the instance, then pass --restage")
    if not problems:
        # The last refusal before the first prompt. An instance whose disk was
        # never installed cannot boot to a login, and an operator must never
        # type an unrecoverable credential into a run that cannot succeed.
        try:
            assert_installed_image(
                files["disk"],
                subject=f"the persistent instance disk {files['disk']}",
                remedy=(
                    "Recreate the instance from an installed canonical image "
                    "with persistent-up, then converge it."))
        except ControllerImageError as error:
            problems.append(str(error))
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2

    console_password = b""
    values: dict[str, str] = {}
    try:
        console_password = _typed_secret(
            f"{CONSOLE_ACCOUNT} console password: ")
        for entry in plan:
            typed = _typed_secret(
                f"new directory password for {entry['contract_role']} "
                f"({entry['name']}): ",
                confirm=f"retype password for {entry['contract_role']}: ")
            # Python cannot wipe an immutable object, and the guest program
            # reads a JSON document, so the value has to become a ``str``
            # somewhere. It becomes one here, once, and every reference is
            # dropped in the ``finally`` below.
            values[entry["name"]] = typed.decode("utf-8")
            typed = b""
    except (ValueError, EOFError, KeyboardInterrupt) as error:
        values.clear()
        print(f"error: {error or type(error).__name__}", file=sys.stderr)
        return 2
    if len(set(values.values())) != len(values):
        # Refused here rather than inside ``stage`` so it costs no boot: the
        # staged principals must be distinguishable by credential, and two
        # identical passwords usually mean a mistyped prompt.
        values.clear()
        print("error: each contract role needs its own password; two of the "
              "credentials you typed are identical", file=sys.stderr)
        return 2

    try:
        target.prepare()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        values.clear()
        print(f"error: {error}", file=sys.stderr)
        return 2

    run_root = Path(tempfile.mkdtemp(prefix="telos-persistent-accounts-"))
    run_root.chmod(0o700)
    guest: subprocess.Popen[bytes] | None = None
    gateway: subprocess.Popen[bytes] | None = None
    result = None
    failure: BaseException | None = None
    try:
        print(" ".join(str(part) for part in command))
        guest = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=0)
        gateway = _attach_simulated_gateway(
            PERSISTENT_SOCKET_PORT, run_root / "gateway.log", guest=guest)
        result = _drive_persistent_accounts(
            guest, console_password, values,
            roster=roster, roster_source=source, timeout=timeout,
            on_stage=_accounts_recorder(target))
    except BaseException as error:
        failure = error
    finally:
        # The credentials exist only here. Python cannot wipe an immutable str
        # or bytes, so the best available step is to drop every reference the
        # moment the console no longer needs one, exactly as the convergence
        # path does.
        console_password = b""
        values.clear()
        for child in (guest, gateway):
            if child is None or child.poll() is not None:
                continue
            child.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                child.wait(timeout=20)
            if child.poll() is None:
                child.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    child.wait(timeout=10)
        for attempt in range(6):
            try:
                target.close()
                break
            except (RuntimeError, OSError) as error:
                if attempt == 5:
                    if failure is None:
                        failure = error
                    break
                time.sleep(0.1)
        shutil.rmtree(run_root, ignore_errors=True)
    if failure is not None or result is None:
        print(f"error: staging the durable account roster failed: "
              f"{failure or 'no staging was proved'}", file=sys.stderr)
        print(f"the directory may now hold some of these accounts. "
              f"persistent-status reports the unfinished attempt; list the "
              f"accounts on {instance} before staging again", file=sys.stderr)
        return 2
    record = {
        "staged_utc": datetime.now(UTC).isoformat(),
        "roster_fingerprint": fingerprint,
        "roster_source": source,
        "accounts": [
            {
                "contract_role": entry["contract_role"],
                "role": entry["role"],
                "uidNumber": entry["uidNumber"],
                "gidNumber": entry["gidNumber"],
            }
            for entry in plan
        ],
        "domain_admin_roles": list(principals.DIRECTORY_ADMIN_ROLES),
        "credentials": (
            "one per contract role, typed by the operator at their terminal; "
            "held in memory, echo-suppressed on the wire, and never written "
            "to a file, argv, an environment variable, this marker, or a "
            "transcript"),
    }
    try:
        target.record_directory_accounts(record)
    except (RuntimeError, OSError) as error:
        # The accounts exist in the directory; only the host-side record
        # failed. Say so distinctly rather than reporting a clean pass.
        print(f"error: the durable roster was staged but its record could not "
              f"be written: {error}", file=sys.stderr)
        return 2
    print(f"{instance}: staged {len(plan)} durable directory accounts")
    for entry in plan:
        print(f"  {entry['contract_role']}: directory role {entry['role']}, "
              f"uidNumber {entry['uidNumber']}")
    print(f"directory state retained at {state}")
    return 0


def persistent_status(root: Path, instance: str) -> int:
    try:
        state = _persistent_state(root, instance)
        target = PersistentControllerInstance(state, instance=instance)
        target.assert_separate()
        marker = target.read_marker() if target.exists() else None
    except (ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    running = _persistent_running(target)
    print(f"persistent controller instance {instance}: "
          f"{'ready' if marker else 'absent or incomplete'}")
    print(f"state: {state}")
    if marker:
        print(f"created: {marker['created_utc']}")
        print(f"seeded from: {marker['seeded_from']['disk']} "
              f"({marker['seeded_from']['disk_sha256']})")
    print("directory: " + _persistent_directory_summary(
        target, marker is not None))
    print("directory accounts: " + _persistent_accounts_summary(
        target, marker is not None))
    print("running: " + {True: "yes", False: "no", None: "unknown"}[running])
    print("hash fence: none by design; the disk is the durable directory state")
    return 0 if marker else 1


def persistent_destroy(root: Path, instance: str, confirm: str | None) -> int:
    try:
        state = _persistent_state(root, instance)
        target = PersistentControllerInstance(state, instance=instance)
        target.assert_separate()
    except (ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    # Demand the confirmation before reporting anything about the instance, as
    # the disposable destroy does. ``PersistentControllerInstance.destroy``
    # checks it again against the marker's own name, which is the authority.
    expected = f"{DESTROY_CONFIRMATION_PREFIX} {instance}"
    if confirm != expected:
        print(f"error: refusing to erase a directory server; pass the exact "
              f"confirmation: {expected}", file=sys.stderr)
        return 2
    if not state.exists():
        print(f"persistent controller instance {instance}: already absent")
        return 0
    try:
        removed = target.destroy(confirm)
    except (RuntimeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"destroyed persistent controller instance {instance} at {removed}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Safe lifecycle for the isolated bootstrap-dc guest")
    result.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    commands = result.add_subparsers(dest="command")
    create_parser = commands.add_parser("create")
    create_parser.add_argument("--apply", action="store_true")
    commands.add_parser("status")
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--iso", type=Path)
    run_parser.add_argument(
        "--seed-iso",
        type=Path,
        help="attach a second read-only data CD after the installer and disk",
    )
    run_parser.add_argument("--apply", action="store_true")
    run_parser.add_argument(
        "--network-config",
        type=Path,
        help="private 0600 JSON selecting a pre-created bridged tap",
    )
    run_parser.add_argument(
        "--network-receipt",
        type=Path,
        help="private 0600 short-lived guest preflight receipt",
    )
    run_parser.add_argument(
        "--confirm",
        help="required acknowledgement for physical-network attachment",
    )
    destroy_parser = commands.add_parser("destroy")
    destroy_parser.add_argument("--confirm")
    # Persistent instances are a separate, explicitly named verb set. No
    # existing subcommand can reach them and none of them can reach the
    # disposable acceptance state.
    for name in (
        "persistent-up", "persistent-converge", "persistent-accounts",
        "persistent-status", "persistent-destroy",
    ):
        persistent_parser = commands.add_parser(name)
        persistent_parser.add_argument(
            "--instance", required=True,
            help="stable instance name; one directory server per name")
        persistent_parser.add_argument(
            "--persistent-root", type=Path, default=DEFAULT_PERSISTENT_ROOT,
            help="root holding persistent instances; never the acceptance state")
        if name in ("persistent-up", "persistent-converge"):
            persistent_parser.add_argument("--apply", action="store_true")
            persistent_parser.add_argument(
                "--seed-iso", type=Path,
                help="read-only convergence/seed CD for a first bring-up")
        if name == "persistent-converge":
            persistent_parser.add_argument(
                "--reconverge", action="store_true",
                help="run the convergent play again on an already converged "
                     "instance; the Administrator password is not changed")
            persistent_parser.add_argument(
                "--timeout", type=float, default=PERSISTENT_CONVERGE_TIMEOUT,
                help="bound on the in-guest convergence payload, in seconds")
        if name == "persistent-accounts":
            # No --seed-iso and no installer media: this verb boots the
            # instance's own disk and nothing else.
            persistent_parser.add_argument("--apply", action="store_true")
            persistent_parser.add_argument(
                "--identity-overlay", type=Path, default=None,
                help="resolve the durable roster against this private overlay "
                     "instead of homelab/instance/identity/principals.json; "
                     "reads NAMES, never a credential")
            persistent_parser.add_argument(
                "--restage", action="store_true",
                help="stage again after an unfinished or completed run; it "
                     "does NOT reset the password of an account the directory "
                     "already holds")
            persistent_parser.add_argument(
                "--timeout", type=float, default=PERSISTENT_ACCOUNTS_TIMEOUT,
                help="bound on the in-guest staging program, in seconds")
        if name == "persistent-destroy":
            persistent_parser.add_argument(
                "--confirm",
                help="required exact acknowledgement: 'DESTROY <instance>'")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    command = args.command or "status"
    if command == "create":
        return create(args.state_dir, args.apply)
    if command == "run":
        return run(
            args.state_dir, args.iso, args.apply, args.seed_iso,
            args.network_config, args.network_receipt, args.confirm)
    if command == "destroy":
        return destroy(args.state_dir, args.confirm)
    if command == "persistent-up":
        return persistent_up(
            args.persistent_root, args.instance, args.apply,
            canonical_state=args.state_dir, seed_iso=args.seed_iso)
    if command == "persistent-converge":
        return persistent_converge(
            args.persistent_root, args.instance, args.apply,
            canonical_state=args.state_dir, seed_iso=args.seed_iso,
            reconverge=args.reconverge, timeout=args.timeout)
    if command == "persistent-accounts":
        return persistent_accounts(
            args.persistent_root, args.instance, args.apply,
            canonical_state=args.state_dir,
            overlay_path=args.identity_overlay,
            restage=args.restage, timeout=args.timeout)
    if command == "persistent-status":
        return persistent_status(args.persistent_root, args.instance)
    if command == "persistent-destroy":
        return persistent_destroy(
            args.persistent_root, args.instance, args.confirm)
    return status(args.state_dir)


if __name__ == "__main__":
    raise SystemExit(main())
