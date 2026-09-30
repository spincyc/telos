#!/usr/bin/env python3
"""Prepare one durable Windows join attempt over a kept workstation's disk.

TASK-28, step 8 of ``homelab/DURABLE-WORKSTATION-FLOW.md``.  This is gate 6's
``windows_identity_prepare.prepare`` for a kept workstation ``W`` whose next
stage is ``windows-join``, with the attempt shaped so that gate 6's own
``NativeProcessBoundary._validate`` accepts it unchanged:

* the overlay is backed by ``W/workstation.qcow2`` -- the dual-boot disk, on
  which Windows sits behind systemd-boot's five-second Windows default -- and
  the firmware variables are ``W``'s own (the ``arch-install`` fold authored
  them), so the boot order the Arch installer wrote is the one that boots;
* the attempt lives under ``homelab/var/factory/durable-windows-joins/<W>/``,
  never inside ``W``, whose ``destroy`` refuses unexpected entries;
* the control disc is gate 6's audited payload with its probe rendered for
  the BOUND realm.  The tracked probe pins the synthetic realm in exactly two
  lines (``$ControllerDomain``/``$ControllerFqdn``), and its
  ``interactive-operator`` probe builds the operator's UPN from the first, so
  the tracked bytes can never prove a durable sign-in.  Only those two lines
  change, in a private staging copy that ``build_control_iso`` audits the way
  it audits the tracked one;
* the post-join operator sign-in reference is gate 6's tracked capture with
  its *state* relabelled for the bound realm.  The adapter admits a reference
  only for the principal's own realm (``_domain_sign_in_states``), and the
  tracked one names the synthetic realm; its pixels are the tracked ones,
  byte for byte and hash-checked.

The rendered probe and the relabelled manifest carry the realm, which is
instance data: both live only in the private attempt, never in a tracked
file, a plan line or a result record.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Mapping

from .durable_workstation import DurableBinding
from .simulation_evidence import private_file
from .windows_control_iso import (
    ASSET_ROOT, EXPECTED_FILES, MANIFEST, SCRIPT, audit_payload,
    build_control_iso)
from .windows_identity_contract import qemu_identity_command
from .windows_identity_factory import REFERENCE_ROOT
from .windows_identity_prepare import CONTROL_ISO_NAME, DISK_NAME, VARS_NAME
from .windows_identity_reference import load_identity_reference
from .workstation_instance import WorkstationInstance


#: The ledger stage this attempt serves (``workstation_instance.FLOW_STAGES``).
STAGE = "windows-join"
#: Durable attempts live apart from gate 6's ``<bundle>/identity`` attempts so
#: no disposable tool that globs those picks up an overlay of a kept disk.
DEFAULT_RUNS = Path("homelab/var/factory/durable-windows-joins")
#: The two tracked probe lines that pin the synthetic realm.
CONTROLLER_DOMAIN_LINE = "$ControllerDomain = 'ad.factory.test'"
CONTROLLER_FQDN_LINE = "$ControllerFqdn = 'bootstrap-dc.ad.factory.test'"
DURABLE_REFERENCES = "durable-references"
OPERATOR_SIGN_IN = "post-join-operator-sign-in"
_SIGN_IN_STATE = re.compile(
    r"focused password field for domain account "
    r"(?P<account>[a-z][a-z0-9-]{0,62})@(?P<realm>[A-Z0-9.-]{1,253})")
_DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DNS_NAME = re.compile(rf"{_DNS_LABEL}(?:\.{_DNS_LABEL})+")
_KERBEROS_REALM = re.compile(r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
                             r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+")


class DurableWindowsPrepareError(RuntimeError):
    """The kept workstation cannot be prepared for its Windows join."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_private(path: Path, label: str, *, mode: int = 0o600) -> None:
    if path.is_symlink() or not path.is_file():
        raise DurableWindowsPrepareError(
            f"{label} must be a regular non-symlink file: {path}")
    if path.stat().st_mode & 0o777 & ~mode:
        raise DurableWindowsPrepareError(
            f"{label} must be private (mode {mode:04o}): {path}")


# -- the control disc, rendered for the bound realm -----------------------------
def render_durable_probe(
    source: str, *, dns_domain: str, controller_fqdn: str,
) -> str:
    """The tracked probe with its two synthetic-realm lines replaced.

    Each tracked line must occur exactly once, and each replacement value is
    a lower-case DNS name, so nothing but those two string literals can
    change.  Refusals never quote a value.
    """
    for label, value in (("DNS domain", dns_domain),
                         ("bootstrap Controller FQDN", controller_fqdn)):
        if not isinstance(value, str) or not _DNS_NAME.fullmatch(value):
            raise DurableWindowsPrepareError(
                f"the bound {label} is not a lower-case DNS name; its value "
                "is not printed")
    if not controller_fqdn.endswith("." + dns_domain):
        raise DurableWindowsPrepareError(
            "the bound bootstrap Controller is not inside the bound DNS "
            "domain; values are not printed")
    rendered = source
    for line, replacement in (
            (CONTROLLER_DOMAIN_LINE, f"$ControllerDomain = '{dns_domain}'"),
            (CONTROLLER_FQDN_LINE, f"$ControllerFqdn = '{controller_fqdn}'")):
        if rendered.count(line) != 1:
            raise DurableWindowsPrepareError(
                f"the tracked probe no longer carries {line!r} exactly once; "
                "refusing to guess where it pins the realm")
        rendered = rendered.replace(line, replacement)
    return rendered


def stage_durable_control_assets(
    destination: Path, *, dns_domain: str, controller_fqdn: str,
    asset_root: Path = ASSET_ROOT,
) -> Path:
    """A private copy of gate 6's control payload with the realm rendered."""
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    source = (Path(asset_root) / SCRIPT.name).read_text(encoding="ascii")
    (destination / SCRIPT.name).write_text(render_durable_probe(
        source, dns_domain=dns_domain, controller_fqdn=controller_fqdn),
        encoding="ascii")
    shutil.copyfile(Path(asset_root) / MANIFEST.name, destination / MANIFEST.name)
    for name in EXPECTED_FILES:
        (destination / name).chmod(0o444)
    # The same audit gate 6 applies to its tracked payload: exactly the two
    # files, no mutating primitive, every action implemented.
    audit_payload(destination)
    return destination


def build_durable_control_iso(
    output: Path, *, dns_domain: str, controller_fqdn: str,
    roster: Mapping[str, str] | None = None,
    runner: Callable = subprocess.run,
) -> Path:
    """Gate 6's ``build_control_iso`` over the realm-rendered payload."""
    output = Path(output)
    with tempfile.TemporaryDirectory(
            prefix=".durable-control-", dir=output.parent) as temporary:
        assets = stage_durable_control_assets(
            Path(temporary) / "payload", dns_domain=dns_domain,
            controller_fqdn=controller_fqdn)
        return build_control_iso(
            output, asset_root=assets, runner=runner, roster=roster)


# -- the operator sign-in reference, relabelled for the bound realm --------------
def relabel_operator_sign_in(
    destination: Path, *, kerberos_realm: str,
    reference_root: Path = REFERENCE_ROOT,
) -> Path:
    """Write the tracked operator sign-in reference for *kerberos_realm*.

    Only the manifest's ``state`` changes, and only after ``@``: the captured
    account, the guest and capture provenance and the image are the tracked
    ones, and the image is copied and re-verified against the tracked hash
    by ``load_identity_reference``.
    """
    if not isinstance(kerberos_realm, str) or not _KERBEROS_REALM.fullmatch(
            kerberos_realm):
        raise DurableWindowsPrepareError(
            "the bound Kerberos realm is not an upper-case DNS name; its "
            "value is not printed")
    source = Path(reference_root) / f"{OPERATOR_SIGN_IN}.json"
    tracked = load_identity_reference(source)
    document = json.loads(source.read_text(encoding="utf-8"))
    match = _SIGN_IN_STATE.fullmatch(str(document.get("state")))
    if tracked.state_kind != "sign-in" or match is None:
        raise DurableWindowsPrepareError(
            "the tracked post-join operator sign-in reference no longer names "
            "a domain account's focused password field")
    document["state"] = (
        f"focused password field for domain account "
        f"{match.group('account')}@{kerberos_realm}")
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    image = destination / document["reference"]["file"]
    shutil.copyfile(tracked.path, image)
    image.chmod(0o600)
    manifest = destination / f"{OPERATOR_SIGN_IN}.json"
    private_file(manifest, (json.dumps(document, indent=2) + "\n").encode())
    relabelled = load_identity_reference(manifest)
    if (relabelled.image != tracked.image or relabelled.crop != tracked.crop
            or relabelled.guest != tracked.guest):
        raise DurableWindowsPrepareError(
            "the relabelled operator sign-in reference is not the tracked "
            "capture")
    return manifest


# -- the kept workstation ------------------------------------------------------
def _image_info(path: Path) -> dict:
    """``qemu-img info``: it takes qemu's read lock, so a live writer fails it."""
    completed = subprocess.run(
        ["qemu-img", "info", "--output=json", str(path)],
        check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)


def _create_overlay(backing: Path, overlay: Path) -> None:
    subprocess.run([
        "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2",
        "-b", str(Path(backing).resolve()), str(overlay),
    ], check=True, capture_output=True)


def inspect_workstation(
    workstation: WorkstationInstance, marker: dict, *,
    image_info: Callable[[Path], dict] = _image_info,
) -> dict:
    """``W``'s disk, variables and publication, proven at the ledger head."""
    refusal = workstation.pending_fold_refusal(marker)
    if refusal is not None:
        raise DurableWindowsPrepareError(refusal)
    head = marker["ledger"][-1]
    _regular_private(workstation.disk, "the kept workstation's disk")
    _regular_private(
        workstation.vars, "the kept workstation's firmware variables "
        "(a dual-boot disk boots through the entries the Arch installer "
        "authored in them)")
    _regular_private(workstation.publication,
                     "the kept workstation's custody publication")
    info = image_info(workstation.disk)
    if (info.get("format") != "qcow2" or info.get("dirty-flag")
            or info.get("backing-filename")
            or info.get("full-backing-filename")):
        raise DurableWindowsPrepareError(
            "the kept workstation's disk is not a clean standalone qcow2")
    disk_sha256 = _sha256(workstation.disk)
    vars_sha256 = _sha256(workstation.vars)
    if disk_sha256 != head["disk_sha256"]:
        raise DurableWindowsPrepareError(
            "the kept workstation's disk no longer hashes to its ledger head; "
            "it changed outside a fold")
    if vars_sha256 != head.get("vars_sha256"):
        raise DurableWindowsPrepareError(
            "the kept workstation's firmware variables no longer match its "
            "ledger head; they changed outside a fold")
    return {
        "workstation": str(workstation.state),
        "disk": {
            "path": str(workstation.disk.resolve()),
            "sha256": disk_sha256,
            "virtual_size": info.get("virtual-size"),
            "dirty": False,
        },
        "firmware": {
            "path": str(workstation.vars.resolve()),
            "sha256": vars_sha256,
        },
        "ledger_head": {
            "stage": head["stage"],
            "disk_sha256": head["disk_sha256"],
            "vars_sha256": head.get("vars_sha256"),
        },
    }


def prepare(
    workstation: WorkstationInstance,
    marker: dict,
    binding: DurableBinding,
    *,
    controller_state: Path,
    run_root: Path = DEFAULT_RUNS,
    switch_port: int = 31415,
    image_info: Callable[[Path], dict] = _image_info,
    create_overlay: Callable[[Path, Path], None] = _create_overlay,
    control_iso_builder: Callable[..., Path] = build_durable_control_iso,
    source: dict | None = None,
) -> Path:
    """One private attempt directory that gate 6's boundary validates as is.

    Nothing is written into ``W``.  On any failure the attempt is removed.
    *source* is ``inspect_workstation``'s answer when the caller already has
    it under ``W``'s lock, so a 20-30 GB disk is not hashed twice.
    """
    if source is None:
        source = inspect_workstation(workstation, marker, image_info=image_info)
    root = Path(run_root).absolute()
    root.mkdir(parents=True, exist_ok=True)
    runs = root / workstation.state.name
    if runs.is_symlink():
        raise DurableWindowsPrepareError(
            f"durable attempt root must not be a symlink: {runs}")
    runs.mkdir(mode=0o700, exist_ok=True)
    runs.chmod(0o700)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    attempt = runs / f"attempt-{stamp}-{secrets.token_hex(6)}"
    attempt.mkdir(mode=0o700)
    attempt.chmod(0o700)
    try:
        overlay = attempt / DISK_NAME
        variables = attempt / VARS_NAME
        control_iso = attempt / CONTROL_ISO_NAME
        qmp = attempt / "windows.qmp"
        shutil.copyfile(workstation.vars, variables)
        variables.chmod(0o600)
        create_overlay(workstation.disk, overlay)
        overlay.chmod(0o600)
        control_iso_builder(
            control_iso, dns_domain=binding.dns_domain,
            controller_fqdn=binding.controller_fqdn)
        reference = relabel_operator_sign_in(
            attempt / DURABLE_REFERENCES,
            kerberos_realm=binding.kerberos_realm)
        with tempfile.TemporaryDirectory(
                prefix="telos-win-durable-authorized-") as template_name:
            template_root = Path(template_name)
            template_root.chmod(0o700)
            serial = template_root / "windows.serial"
            command = qemu_identity_command(
                disk=overlay, variables=variables, qmp_socket=qmp,
                serial_socket=serial, switch_port=switch_port,
                control_iso=control_iso)
            authorized_serial_path = str(serial.resolve())
        command_digest = hashlib.sha256(
            json.dumps(command, separators=(",", ":")).encode()).hexdigest()
        # Gate 6's authorization, key for key where its boundary reads one,
        # plus a ``durable`` record the durable runner holds the run to.
        plan = {
            "schema": 1,
            "status": "prepared",
            "external_access": False,
            "source": source,
            "controller_state": str(Path(controller_state).resolve()),
            "overlay": {
                "path": str(overlay.resolve()),
                "backing_path": source["disk"]["path"],
                "format": "qcow2",
            },
            "firmware_copy": {
                "path": str(variables.resolve()),
                "source_sha256": source["firmware"]["sha256"],
            },
            "qmp_socket": str(qmp.resolve()),
            "serial_transport": {
                "kind": "private-unix-socket-jsonl",
                "authorized_path": authorized_serial_path,
                "contains_secrets": False,
            },
            "qemu_argv_sha256": command_digest,
            "control_media": {
                "path": str(control_iso.resolve()),
                "sha256": _sha256(control_iso),
                "read_only": True,
                "contains_secrets": False,
            },
            "installation_media_attached": False,
            "pxe_boot_enabled": False,
            # Gate 6's live-proven submission: neither calibration nor the
            # reviewed one-Tab activation.
            "post_join_submit_focus_calibration": {"enabled": False, "tabs": 0},
            "post_join_submit_focus_activation": {
                "enabled": False, "reference": None, "sha256": None},
            "durable": {
                "stage": STAGE,
                "workstation": workstation.state.name,
                "bound_instance": binding.instance,
                "ledger_head": source["ledger_head"],
                "control_probe": "rendered for the bound realm",
                "operator_sign_in_reference": {
                    "path": str(reference.relative_to(attempt)),
                    "sha256": _sha256(reference),
                },
            },
        }
        private_file(
            attempt / "authorization.json",
            (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode())
        private_file(
            attempt / "qemu-command.json",
            (json.dumps({"schema": 1, "argv": command}, indent=2)
             + "\n").encode())
        return attempt
    except BaseException:
        shutil.rmtree(attempt, ignore_errors=True)
        raise
