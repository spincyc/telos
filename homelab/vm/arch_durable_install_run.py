#!/usr/bin/env python3
"""Install Arch onto a kept workstation's disk, with the domain join deferred.

TASK-28, step 6 of ``homelab/DURABLE-WORKSTATION-FLOW.md``.  A kept
workstation ``W`` (``workstation_instance``) that has adopted a gate-5 Windows
disk gets its Arch half here, as its ``arch-install`` stage:

* the bundle is gate 7's own (``arch_install_prepare.prepare``) built with
  ``--durable-identity``: its installer bakes the PERMANENT realm of the
  persistent instance ``W`` is bound to, pins that instance's bootstrap
  Controller in ``sssd.conf`` and, because the realm is durable, defers the
  install-time join (``TELOS ARCH JOIN DEFERRED``) and seals the boot-time one;
* the "persistent Windows disk" the bundle overlays is ``W/workstation.qcow2``
  itself, so everything the install writes lands in an overlay backed by
  ``W``'s disk and nowhere else;
* the Controller is gate 7's DISPOSABLE canonical image serving the PXE
  release and the signed workstation repository from its publication, and
  nothing more: no directory is provisioned, no join account is staged, no
  join medium is built or attached, and the persistent Controller is not
  started -- the join is stage ``arch-join`` (step 7);
* on success the overlay is folded into ``W`` together with the firmware
  variables the installer authored; on any failure it is discarded and ``W``
  is untouched.  Evidence is retained either way.

Gate 7 (``arch_install_run``) is composed, never edited, so the disposable
gates stay byte-identical: its bundle verification, disk hot-attach,
installer drive and lifecycle validation are called as they are.  Its ``run``
cannot be reused whole -- it provisions a synthetic domain and carries one-use
join media around the install -- so ``DurableArchInstall.boot_and_install`` is
its apply path with those two steps removed, and with the Controller launched
the way gate 5 launches it (and gate 7 did before the join existed,
``a179368``): ``factory_runner.activate_publication`` over the plain PXE
gateway, which also drains the Controller console for the whole run.

The dry run (the default) binds the instance, resolves the realm, checks
``W`` and prints the plan; it writes nothing and names the bound instance
only -- never the realm or the domain SID.  ``--apply`` holds ``W``'s lock for
the whole run.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path
from typing import Mapping

if not __package__:  # Direct execution by the Make recipe (PEP 366).
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "homelab.vm"

from . import arch_install_prepare  # noqa: E402
from .arch_install_prepare import (  # noqa: E402
    DEFAULT_RELEASES, DISK_SERIAL, INSTALLER_NAME, OVERLAY_NAME, VARS_NAME,
    VERIFY_NAME, require_netbios_hostname)
from .arch_install_run import (  # noqa: E402
    FAIL_MARKER, MAX_DURATION, _bundle, _connect_qmp,
    _destroy_runtime_publication, _qmp_socket_path, _switch_port,
    _validate_lifecycle, acceptance_measurements, drive_installer,
    hot_attach_disk)
from .automated_controller import DisposableBootDisk  # noqa: E402
from .bootstrap_dc import (  # noqa: E402
    DEFAULT_PERSISTENT_ROOT, DEFAULT_STATE, paths)
from .durable_workstation import (  # noqa: E402
    SID_MATCH, SID_REPAIR, SRV_FIRST, DurableBinding, DurableBindingError,
    check_live_directory, durable_binding, require_durable_realm_agreement,
    require_workstation_dc_agreement)
from .factory_publication import stage as stage_publication  # noqa: E402
from .factory_runner import (  # noqa: E402
    DEFAULT_SEED_ISO, GATEWAY_MAC, PUBLICATION_LABEL, activate_publication,
    declared_chardevs, gateway_command, qemu_commands, switch_command,
    wait_for_switch_port)
from .signal_cleanup import (  # noqa: E402
    RunInterrupted, SignalGuard, terminate_children)
from .simulated_topology import audit_live_process  # noqa: E402
from .simulation_evidence import redact, retain_redacted_logs  # noqa: E402
from .simulation_overlay import sha256  # noqa: E402
from .workstation_instance import (  # noqa: E402
    DEFAULT_ROOT, WorkstationInstance, workstation_state)

from homelab.workstations.arch_second import (  # noqa: E402
    JOIN_DEFERRED_MARKER, JOIN_MEDIA_CONSUMED_MARKER, JOIN_VERIFIED_MARKER,
    SAFE_HOSTNAME, InstallContractError, InstallerRealm, InstallerRealmError,
    ad_server_value)


#: The ledger stage this runner folds (``workstation_instance.FLOW_STAGES``).
STAGE = "arch-install"
#: Durable bundles live apart from gate 7's ``arch-installs`` so no disposable
#: tool that globs those picks up an overlay backed by a kept disk.
DEFAULT_RUNS = Path("homelab/var/factory/durable-arch-installs")
#: Gate 7's install drive took about 4.5 minutes live with a 1800-second
#: budget; the Makefile's 120-second FACTORY_DURATION default would spend the
#: whole Controller publication and then time out mid-install.
MIN_APPLY_DURATION = 600
#: A conservative bound on what the Arch install adds to the disk.  The overlay
#: holds it once, and the fold's standalone copy holds the kept disk plus it.
ARCH_GROWTH_BYTES = 16 * 1024 ** 3
#: The authorized realm record gate 7's prepare writes, key for key.
REALM_FIELDS = (
    "dns_domain", "kerberos_realm", "netbios_name", "controller_fqdn",
    "durable")
RETAINED_LOGS = ("controller-publication.log", "workstation-serial.log")
RESULT_NAME = "result.json"


class DurableInstallError(RuntimeError):
    """A durable Arch install cannot proceed, or did not do what it must."""


# -- the bundle's realm -------------------------------------------------------
def authorized_realm(authorized: Mapping[str, object]) -> InstallerRealm:
    """The realm a bundle's authorization records, validated, or a refusal.

    The same record shape gate 7's ``require_realm_agreement`` reads, parsed
    here because that function refuses every durable bundle outright.  Values
    are never put into a message: a durable realm is instance data.
    """
    record = authorized.get("realm")
    if not isinstance(record, Mapping):
        raise DurableInstallError(
            "the bundle's authorization declares no realm; prepare it again")
    if set(record) != set(REALM_FIELDS) or any(
            record.get(name) is None for name in REALM_FIELDS):
        raise DurableInstallError(
            f"the bundle's authorized realm is not the recorded shape "
            f"({', '.join(REALM_FIELDS)}); it declares {sorted(record)}")
    try:
        return InstallerRealm(
            dns_domain=record["dns_domain"],
            kerberos_realm=record["kerberos_realm"],
            workgroup=record["netbios_name"],
            controller_fqdn=record["controller_fqdn"],
            durable=record["durable"],
            source="the bundle's authorization.json",
        )
    except InstallerRealmError as error:
        raise DurableInstallError(
            "the bundle's authorized realm is invalid; its values are not "
            "printed") from error


def require_durable_bundle_realm(
    authorized: Mapping[str, object], installer_script: str,
    binding: DurableBinding,
) -> InstallerRealm:
    """Refuse a bundle that is not a durable build for *binding*'s directory.

    ``durable_workstation.require_durable_realm_agreement`` replaces gate 7's
    outright durable refusal: the recorded realm must be permanent and be the
    bound instance's, its fallback controller the instance's recorded DC.
    The installer's own bytes are then held to the record the way gate 7
    holds them -- the ``ad_server`` line, which for a durable render asks
    SRV first and names that controller as its fallback (TASK-42) -- and to
    two facts only a durable build has: the deferred install-time join, and
    the roster fingerprint the persistent instance staged its accounts under.
    A bundle prepared before SRV-first discovery is refused here: its
    ``ad_server`` names the controller alone.
    """
    realm = authorized_realm(authorized)
    require_durable_realm_agreement(realm, binding)
    required = (
        (f"\nad_server = {ad_server_value(realm)}\n",
         "does not ask SRV first with the authorized domain controller as "
         "its fallback in sssd.conf; it predates SRV-first discovery or its "
         "authorization and its rendered bytes describe different realms"),
        (f'\necho "{JOIN_DEFERRED_MARKER}"\n',
         "does not defer the install-time join; a durable disk may not be "
         "joined while the disposable Controller serves the install"),
        (f"\nROSTER_FINGERPRINT='{binding.roster_fingerprint}'\n",
         f"was not rendered from the roster persistent instance "
         f"{binding.instance} staged; the disk's accounts and the "
         f"directory's would disagree"),
    )
    for line, reason in required:
        if line not in installer_script:
            raise DurableInstallError(f"the bundle's installer script {reason}")
    return realm


# -- the transcript -------------------------------------------------------------
def validate_durable_lifecycle(serial: str, disk_serial: str = DISK_SERIAL) -> None:
    """Gate 7's lifecycle check with the deferral standing for the join.

    A durable install never joins, so either install-time join marker is a
    refusal, and ``TELOS ARCH JOIN DEFERRED`` is required instead.  Everything
    else -- the required markers, one PXE firmware boot, a disk attached only
    after archiso is live, attach < join < complete -- is gate 7's own
    ``_validate_lifecycle``, called on a copy of the transcript in which the
    deferral stands where gate 7's two join markers stand.  Nothing is restated,
    so a check gate 7 gains applies here too.
    """
    present = [
        marker for marker in (JOIN_MEDIA_CONSUMED_MARKER, JOIN_VERIFIED_MARKER)
        if marker in serial]
    if present:
        raise DurableInstallError(
            "the install transcript carries install-time join markers ("
            + ", ".join(present) + "): a durable install never joins; the "
            "join belongs to stage arch-join")
    if FAIL_MARKER in serial:
        raise DurableInstallError("Arch installer reported failure")
    if JOIN_DEFERRED_MARKER not in serial:
        raise DurableInstallError(
            f"the install transcript never printed {JOIN_DEFERRED_MARKER}: "
            f"the installer that ran is not a durable render")
    stand_in = f"{JOIN_MEDIA_CONSUMED_MARKER}\n{JOIN_VERIFIED_MARKER}"
    try:
        _validate_lifecycle(
            serial.replace(JOIN_DEFERRED_MARKER, stand_in), disk_serial)
    except RuntimeError as error:
        raise DurableInstallError(
            f"{error} (gate 7's lifecycle check, with {JOIN_DEFERRED_MARKER} "
            f"standing where its two join markers stand)") from error


# -- evidence -----------------------------------------------------------------
def _write_result(evidence: Path, result: Mapping[str, object]) -> None:
    output = evidence / RESULT_NAME
    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(output, 0o600)


def _amend_result(evidence: Path, **fields: object) -> None:
    """Add the fold's outcome to a retained ``result.json``, if there is one."""
    output = evidence / RESULT_NAME
    if output.is_symlink() or not output.is_file():
        return
    result = json.loads(output.read_text(encoding="utf-8"))
    result.update(fields)
    _write_result(evidence, result)


def _join_drain_threads(timeout: float = 2.0) -> None:
    """Let ``activate_publication``'s console drain finish before redaction.

    The drain appends to the Controller log by path; once the Controller has
    been reaped it reads to end of file and stops.  Joined so its last chunk
    cannot land after ``retain_redacted_logs`` replaced the log.
    """
    for thread in threading.enumerate():
        if thread.name == "controller-serial-drain" and thread.is_alive():
            thread.join(timeout)


# -- process seams (replaced by the unit tests) ---------------------------------
def _launch(argv: list[str], **options) -> subprocess.Popen[bytes]:
    return subprocess.Popen(argv, **options)


def _listen(port: int) -> socket.socket:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(3)
    return listener


def _build_publication_iso(publication: Path, output: Path) -> None:
    subprocess.run([
        "xorriso", "-as", "mkisofs", "-quiet", "-iso-level", "3",
        "-V", PUBLICATION_LABEL, "-o", str(output), str(publication),
    ], check=True, capture_output=True)
    output.chmod(0o600)


# -- the install --------------------------------------------------------------
class DurableArchInstall:
    """One durable Arch install into one prepared bundle.  Folds nothing.

    ``execute`` verifies the bundle, boots, drives and validates, and always
    leaves ``evidence/result.json``; ``run`` owns the kept workstation, its
    lock and the fold.
    """

    def __init__(
        self, workstation: WorkstationInstance, binding: DurableBinding, *,
        controller_state: Path, releases: Path, seed_iso: Path,
        duration: float,
    ) -> None:
        self.workstation = workstation
        self.binding = binding
        self.controller_state = Path(controller_state)
        self.releases = Path(releases)
        self.seed_iso = Path(seed_iso)
        self.duration = float(duration)

    def verified_bundle(self, bundle: Path) -> tuple[dict, list[str]]:
        """Gate 7's bundle proof: argv digest, overlay, backing disk, inputs."""
        return _bundle(bundle)

    def check_bundle(self, bundle: Path) -> tuple[dict, list[str], str]:
        authorization, command = self.verified_bundle(bundle)
        authorized = authorization["authorization"]
        installer_script = (bundle / INSTALLER_NAME).read_text(encoding="utf-8")
        require_durable_bundle_realm(authorized, installer_script, self.binding)
        return authorized, command, installer_script

    def execute(self, bundle: Path) -> dict:
        bundle = Path(bundle).resolve()
        authorized, command, installer_script = self.check_bundle(bundle)
        evidence = bundle / "evidence"
        if evidence.exists():
            raise DurableInstallError("bundle already has execution evidence")
        evidence.mkdir(mode=0o700)
        result: dict = {
            "schema": 1, "status": "fail", "phase": "starting",
            "stage": STAGE,
            "workstation": self.workstation.state.name,
            "bound_instance": self.binding.instance,
            "hostname": authorized.get("hostname"),
            # Facts of this run, not outcomes: nothing here ever joins.
            "join_deferred": True,
            "join_media": None,
            "controller_role": "pxe-publication-only",
        }
        try:
            serial = self.boot_and_install(
                bundle, authorized, command,
                installer_script=installer_script, evidence=evidence,
                result=result)
            validate_durable_lifecycle(serial, authorized["disk_serial"])
            result.update({
                "status": "observed",
                "phase": "arch-installed-join-deferred",
                "pxe_firmware_boots": 1,
                "windows_preserved": True,
                "release_version": authorized.get("release_version"),
                "measurements": acceptance_measurements(
                    canonical_unchanged=True,
                    # Both guests passed audit_live_process.
                    loopback_only_audited=True,
                    arch_installed=True),
            })
            return result
        except BaseException as error:
            result["error_type"] = type(error).__name__
            result["error"] = redact(
                str(error).encode("utf-8", errors="replace")).decode(
                    "utf-8", errors="replace")
            context = error.__context__
            if context is not None:
                result["error_context_type"] = type(context).__name__
                result["error_context"] = redact(
                    str(context).encode("utf-8", errors="replace")).decode(
                        "utf-8", errors="replace")
            raise
        finally:
            _write_result(evidence, result)

    def boot_and_install(
        self, bundle: Path, authorized: Mapping, command: list[str], *,
        installer_script: str, evidence: Path, result: dict,
    ) -> str:
        """Gate 7's apply path without the domain or the join media.

        Returns the workstation's serial transcript once the installer
        finished, every non-workstation process is still healthy and the
        canonical Controller identity is re-proved.  Every child is reaped and
        the logs are redacted in place whatever happens.
        """
        disk_serial = authorized["disk_serial"]
        qmp_socket = _qmp_socket_path(command)
        port = _switch_port(command)
        verify_script = (bundle / VERIFY_NAME).read_text(encoding="utf-8")
        canonical = paths(self.controller_state)
        processes: dict[str, subprocess.Popen[bytes]] = {}
        owned_qmp_root: Path | None = None
        publication_iso = evidence / "publication.iso"
        # Everything created after the listener is inside the cleanup below.
        listener = _listen(port)
        try:
            if qmp_socket.parent != bundle:
                qmp_socket.parent.mkdir(mode=0o700, exist_ok=False)
                owned_qmp_root = qmp_socket.parent
            elif qmp_socket.exists():
                raise DurableInstallError(
                    "bundle QMP socket path is already occupied")
            with DisposableBootDisk(
                    canonical["disk"], canonical["vars"],
                    run_root=evidence / "controller") as overlay:
                receipt = stage_publication(
                    self.releases, evidence / "publication",
                    seed_iso=self.seed_iso, target="arch-workstation")
                if (receipt["version"] != authorized["release_version"]
                        or receipt["selected_manifest_sha256"]
                        != authorized["release_manifest_sha256"]):
                    raise DurableInstallError(
                        "published Arch release differs from the authorized "
                        "release")
                _build_publication_iso(evidence / "publication", publication_iso)
                controller_command = qemu_commands(
                    overlay.disk, overlay.vars,
                    bundle / OVERLAY_NAME, bundle / VARS_NAME,
                    port, None, publication_iso)["controller"]
                processes["switch"] = _launch(
                    switch_command(
                        listener.fileno(), evidence / "switch.jsonl",
                        accept_timeout=360, idle_timeout=self.duration + 60),
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT, pass_fds=(listener.fileno(),))
                listener.close()
                # The plain PXE gateway: the Controller's DNS and the synthetic
                # realm's search suffix exist for gate 7's install-time join,
                # which a durable install does not make.
                processes["gateway"] = _launch(
                    gateway_command(port), stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                wait_for_switch_port(
                    evidence / "switch.jsonl", "gateway", GATEWAY_MAC)
                processes["controller"] = _launch(
                    controller_command, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                audit_live_process(
                    processes["controller"].pid, "controller",
                    allowed_chardevs=declared_chardevs(controller_command),
                    disposable_disk=overlay.disk, disposable_vars=overlay.vars,
                    forbidden_paths=(canonical["disk"], canonical["vars"]))
                activate_publication(
                    processes["controller"],
                    evidence / "controller-publication.log")
                result["phase"] = "arch-publication-ready"
                processes["workstation"] = _launch(
                    command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
                audit_live_process(
                    processes["workstation"].pid, "client",
                    allowed_nic_models=("e1000e",))
                result["phase"] = "arch-install-driving"
                qmp = _connect_qmp(
                    qmp_socket, expected_peer_pid=processes["workstation"].pid)
                try:
                    serial = drive_installer(
                        processes["workstation"],
                        evidence / "workstation-serial.log",
                        verify_script=verify_script,
                        installer_script=installer_script,
                        serial=disk_serial,
                        attach=lambda: hot_attach_disk(qmp, disk_serial),
                        # No join media exists, so nothing is consumed.
                        consume_media=None,
                        timeout=self.duration)
                finally:
                    qmp.close()
                failed = [
                    role for role, process in processes.items()
                    if role != "workstation"
                    and process.poll() not in (None, 0)]
                if failed:
                    raise DurableInstallError(
                        "Arch lifecycle process failed: " + ", ".join(failed))
                overlay.overlay.verify_canonical()
                return serial
        finally:
            listener.close()
            failures = terminate_children(
                processes.values(), terminate_timeout=8, kill_timeout=3)
            _join_drain_threads()
            if owned_qmp_root is not None:
                qmp_socket.unlink(missing_ok=True)
                try:
                    owned_qmp_root.rmdir()
                except OSError:
                    failures.append("QMP runtime root was not removed")
            result["retained_logs"] = retain_redacted_logs(
                evidence, RETAINED_LOGS)
            publication_failure = _destroy_runtime_publication(publication_iso)
            if publication_failure:
                failures.append(publication_failure)
            result["runtime_publication_destroyed"] = publication_failure is None
            if failures:
                result["cleanup_failures"] = failures


# -- the kept workstation -----------------------------------------------------
def open_workstation(root: Path, name: str) -> WorkstationInstance:
    return WorkstationInstance(workstation_state(root, name), name=name)


def require_arch_install_next(workstation: WorkstationInstance) -> dict:
    """``W``'s validated marker, when ``arch-install`` is its next fold."""
    marker = workstation.read_marker()
    name = marker["workstation"]
    refusal = workstation.pending_fold_refusal(marker)
    if refusal is not None:
        raise DurableInstallError(refusal)
    following = workstation.next_stage(marker)
    if following != STAGE:
        raise DurableInstallError(
            f"the next stage for kept workstation {name} is {following!r}, "
            f"not {STAGE!r}")
    return marker


def require_workstation_binding(
    marker: dict, binding: DurableBinding,
) -> str | None:
    """Refuse a binding that is not the instance ``W`` was adopted against.

    Compared, never printed.  ``W`` recorded the instance's SID when it was
    adopted; a record the instance later completed (``REPAIR_SID``) still
    names the same directory, so ``check_live_directory``'s repair case is
    accepted as well as an exact match.

    Then ``W``'s Arch side, once installed, must be able to reach the
    instance's recorded DC (TASK-42): a disk that asks SRV first is accepted
    under any DC name and the returned note says so; a disk that names its
    controller alone is refused when that is no longer the instance's DC.
    """
    recorded = marker["binding"]
    name = marker["workstation"]
    if recorded["persistent_instance"] != binding.instance:
        raise DurableInstallError(
            f"kept workstation {name} is bound to persistent instance "
            f"{recorded['persistent_instance']}, not {binding.instance}")
    if recorded["realm"] != binding.kerberos_realm:
        raise DurableInstallError(
            f"kept workstation {name} recorded a realm that persistent "
            f"instance {binding.instance} no longer declares; values are not "
            f"printed")
    try:
        verdict = check_live_directory(recorded["domain_sid"], binding.domain_sid)
    except DurableBindingError as error:
        raise DurableInstallError(
            f"kept workstation {name} recorded a domain SID that is not "
            f"persistent instance {binding.instance}'s directory; values are "
            f"not printed") from error
    if verdict not in (SID_MATCH, SID_REPAIR):
        raise DurableInstallError("unexpected domain SID verdict")
    try:
        return require_workstation_dc_agreement(marker, binding)
    except DurableBindingError as error:
        raise DurableInstallError(str(error)) from error


def require_ledger_head(
    workstation: WorkstationInstance, marker: dict, bundle: Path,
) -> None:
    """Refuse, before anything boots, a bundle not built on ``W``'s head.

    Prepare hashed the disk it overlays; that hash must be the ledger head's,
    or ``fold`` would refuse the result after a whole install.
    """
    authorization = json.loads(
        (bundle / "authorization.json").read_text(encoding="utf-8"))
    backing = authorization["authorization"]["backing_windows_disk"]
    head = marker["ledger"][-1]
    if not os.path.samefile(backing["path"], workstation.disk):
        raise DurableInstallError(
            "the prepared overlay is not backed by the kept workstation's disk")
    if backing["sha256"] != head["disk_sha256"]:
        raise DurableInstallError(
            "the kept workstation's disk no longer hashes to its ledger head; "
            "it changed outside a fold")
    current_vars = (
        sha256(workstation.vars)
        if workstation.vars.is_file() and not workstation.vars.is_symlink()
        else None)
    if current_vars != head.get("vars_sha256"):
        raise DurableInstallError(
            "the kept workstation's firmware variables no longer match its "
            "ledger head; they changed outside a fold")


def _existing_ancestor(path: Path) -> Path:
    for candidate in (Path(path).absolute(), *Path(path).absolute().parents):
        if candidate.is_dir():
            return candidate
    return Path("/")


def space_needs(workstation: WorkstationInstance, run_root: Path) -> list[dict]:
    """A conservative per-filesystem free-space estimate for one run.

    The overlay grows by the Arch install under *run_root*; the fold writes a
    standalone copy of the kept disk plus that growth beside ``W``.  ``fold``
    re-checks with qemu-img's own estimate, but only after the install.
    """
    allocated = workstation.disk.stat().st_blocks * 512
    needs: dict[int, dict] = {}
    for directory, amount in (
            (workstation.state, allocated + ARCH_GROWTH_BYTES),
            (_existing_ancestor(run_root), ARCH_GROWTH_BYTES)):
        device = directory.stat().st_dev
        entry = needs.setdefault(device, {"path": directory, "needed": 0})
        entry["needed"] += amount
    for entry in needs.values():
        entry["free"] = shutil.disk_usage(entry["path"]).free
    return list(needs.values())


def prepare_arguments(
    args: argparse.Namespace, workstation: WorkstationInstance,
    binding: DurableBinding,
) -> argparse.Namespace:
    """Gate 7's prepare, asked for a durable bundle over ``W``'s own disk.

    Parsed by prepare's own parser so every option this runner does not set
    keeps gate 7's default.  The controller is the binding's: the instance's
    recorded DC (TASK-42), which ``sssd.conf`` names as the fallback after
    SRV discovery; it is parsed in-process and never reaches a process argv.
    """
    argv = [
        "--windows-disk", str(workstation.disk),
        "--releases", str(args.releases),
        "--run-root", str(args.run_root),
        "--hostname", args.hostname,
        "--durable-identity",
        "--controller-fqdn", binding.controller_fqdn,
    ]
    if args.directory_identity is not None:
        argv += ["--identity-document", str(args.directory_identity)]
    return arch_install_prepare.parser().parse_args(argv)


def resolve_bundle_realm(
    prepare_args: argparse.Namespace, binding: DurableBinding,
) -> InstallerRealm:
    """The bundle's permanent realm, its controller the bound instance's DC.

    The recorded DC is vouched for here and only here: the binding read it
    from the instance's own convergence record (``dc_hostname``), so a
    workstation minted after ADR 0081's restore may name the restored DC,
    which ADR 0065 never froze.  Nothing else widens what prepare accepts.
    """
    try:
        return arch_install_prepare.resolve_realm(
            prepare_args,
            recorded_dc_fqdn=f"{binding.dc_hostname}.{binding.dns_domain}")
    except InstallContractError as error:
        raise DurableInstallError(
            f"the permanent realm could not be resolved from the directory "
            f"identity ({type(error).__name__}); values are not printed"
        ) from error


def prepare_bundle(
    prepare_args: argparse.Namespace, realm: InstallerRealm,
) -> Path:
    return arch_install_prepare.prepare(prepare_args, realm)


def _discard_overlay(overlay: Path) -> bool:
    """Remove the overlay: stale after a fold, worthless after a failure."""
    try:
        overlay.unlink(missing_ok=True)
    except OSError:
        return False
    return True


def _gib(value: int) -> str:
    return f"{value / 1024 ** 3:.1f} GiB"


def print_plan(
    args: argparse.Namespace, workstation: WorkstationInstance, marker: dict,
    binding: DurableBinding, space: list[dict],
) -> None:
    stages = ", ".join(entry["stage"] for entry in marker["ledger"])
    print("Boundary: loopback-only switch; no host or UniFi changes")
    print(f"Kept workstation: {workstation.state.name} at {workstation.state}; "
          f"stages done: {stages}; next stage {STAGE}")
    print(f"Bound instance: {binding.instance}. The kept workstation's marker "
          f"names it, and the bundle's permanent realm, bootstrap Controller "
          f"and roster are checked against it; values are compared, never "
          f"printed")
    print(f"Controller: the DISPOSABLE canonical image at "
          f"{paths(args.controller_state)['state']} publishes the PXE release "
          f"and the signed workstation repository only; no directory is "
          f"provisioned and the persistent Controller is not started")
    print(f"Disk: a fresh overlay backed by {workstation.disk}; the Windows "
          f"partitions are preserved")
    print(f"Arch hostname: {args.hostname}")
    print(f"Domain join: none. The install-time join is deferred "
          f"({JOIN_DEFERRED_MARKER}); no join media and no join account. The "
          f"disk's sealed boot-time join runs once, in stage arch-join")
    print(f"On success: the overlay and the installer-authored firmware "
          f"variables are folded into {workstation.state.name} as stage "
          f"{STAGE}; the overlay is then removed")
    print(f"On failure: the overlay is removed and "
          f"{workstation.state.name} is unchanged; evidence stays under "
          f"{args.run_root}")
    for entry in space:
        verdict = "" if entry["free"] >= entry["needed"] else " (INSUFFICIENT)"
        print(f"Free space: {entry['path']} needs about "
              f"{_gib(entry['needed'])}, has {_gib(entry['free'])}{verdict}")
    note = ""
    if args.duration < MIN_APPLY_DURATION:
        note = (f" (below the {MIN_APPLY_DURATION}-second minimum --apply "
                f"accepts; set FACTORY_DURATION=1800)")
    print(f"Maximum runtime: {args.duration:g} seconds{note}")


def run(args: argparse.Namespace) -> int:
    if not 60 <= args.duration <= MAX_DURATION:
        raise DurableInstallError(
            f"duration must be between 60 and {MAX_DURATION} seconds")
    if not SAFE_HOSTNAME.fullmatch(args.hostname):
        raise DurableInstallError(
            "the Arch hostname must be lowercase letters, digits and hyphens, "
            "starting with a letter")
    require_netbios_hostname(args.hostname)
    workstation = open_workstation(args.root, args.workstation)
    marker = require_arch_install_next(workstation)
    binding = durable_binding(
        args.persistent_root, args.persistent_dc,
        canonical_state=args.controller_state,
        identity_path=args.directory_identity)
    require_workstation_binding(marker, binding)
    prepare_args = prepare_arguments(args, workstation, binding)
    realm = resolve_bundle_realm(prepare_args, binding)
    # Checked before the plan's first line, like gate 7's realm agreement, so
    # the dry run reports a refusal too.
    require_durable_realm_agreement(realm, binding)
    space = space_needs(workstation, args.run_root)
    print_plan(args, workstation, marker, binding, space)
    if not args.apply:
        print("dry run; repeat with --apply")
        return 0
    if args.duration < MIN_APPLY_DURATION:
        raise DurableInstallError(
            f"--apply needs a duration of at least {MIN_APPLY_DURATION} "
            f"seconds; gate 7 uses 1800")
    short = [entry for entry in space if entry["free"] < entry["needed"]]
    if short:
        raise DurableInstallError(
            "not enough free space for the overlay and the fold: "
            + "; ".join(f"{entry['path']} needs about {_gib(entry['needed'])}"
                        for entry in short))
    with SignalGuard(), workstation:
        # Re-read under the lock: another run may have folded meanwhile.
        marker = require_arch_install_next(workstation)
        require_workstation_binding(marker, binding)
        bundle = prepare_bundle(prepare_args, realm)
        print(f"Bundle: {bundle}")
        overlay = bundle / OVERLAY_NAME
        evidence = bundle / "evidence"
        entry: dict | None = None
        try:
            require_ledger_head(workstation, marker, bundle)
            DurableArchInstall(
                workstation, binding,
                controller_state=args.controller_state,
                releases=args.releases, seed_iso=args.seed_iso,
                duration=args.duration,
            ).execute(bundle)
            # Recorded before the fold: a fold that then fails leaves the
            # stage unfolded, and the record only counts once it is.
            workstation.record_arch_dc_discovery(
                SRV_FIRST, realm.controller_fqdn)
            entry = workstation.fold(
                overlay, STAGE, firmware_vars=bundle / VARS_NAME,
                source=str(bundle))
        finally:
            discarded = _discard_overlay(overlay)
            _amend_result(
                evidence,
                folded=entry is not None,
                fold=None if entry is None else {
                    key: entry.get(key)
                    for key in ("stage", "utc", "disk_sha256", "vars_sha256")},
                overlay_discarded=discarded)
    print(f"Folded stage {STAGE} into {workstation.state.name}; ledger head "
          f"{entry['disk_sha256']}")
    print(f"Evidence: {evidence}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Install Arch onto a kept workstation, join deferred "
                    "(TASK-28 step 6); a dry run unless --apply")
    result.add_argument("--workstation", required=True,
                        help="the kept workstation's stable name")
    result.add_argument(
        "--root", type=Path, default=DEFAULT_ROOT,
        help="root holding kept workstations (DURABLE_WORKSTATION_ROOT)")
    result.add_argument("--persistent-dc", required=True,
                        help="the persistent instance the workstation is "
                             "bound to")
    result.add_argument("--persistent-root", type=Path,
                        default=DEFAULT_PERSISTENT_ROOT)
    result.add_argument(
        "--directory-identity", type=Path, default=None,
        help="the permanent directory identity document (ADR 0065); "
             "defaults to the private overlay's")
    result.add_argument(
        "--hostname", required=True,
        help="the Arch host name baked onto the disk; at most 15 characters "
             "(NetBIOS), because stage arch-join derives the machine account "
             "from it")
    result.add_argument(
        "--controller-state", type=Path, default=DEFAULT_STATE,
        help="the canonical DISPOSABLE Controller image that publishes PXE")
    result.add_argument("--releases", type=Path, default=DEFAULT_RELEASES)
    result.add_argument("--seed-iso", type=Path, default=DEFAULT_SEED_ISO)
    result.add_argument("--run-root", type=Path, default=DEFAULT_RUNS)
    result.add_argument("--duration", type=float, default=1800)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(args)
    except RunInterrupted as error:
        print(f"error: {error}", file=sys.stderr)
        return error.exit_code
    except (RuntimeError, OSError, ValueError,
            subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
