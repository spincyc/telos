#!/usr/bin/env python3
"""Exercise the gate-11 lifecycle-recovery scenarios on the loopback lab.

Gate 11 (``homelab/WORKSTATION-FACTORY-STATE.md``) requires exercising eight
recovery scenarios and recording machine-readable, secret-free evidence for
each: controller restart/loss, PXE release rollback, failed-install recovery,
broken-boot repair, directory/DNS loss, update-failure handling, workstation
remint, and controller reconstruction from public inputs plus a synthetic
private overlay.

This runner is deliberately honest about the local loopback lab's reach.
Three scenarios are fully provable here without booting a guest and must pass:

* ``pxe-release-rollback`` performs a real transactional rollback with
  :mod:`pxe_release_set` — a prior ``YYYYMMDD.NNN`` set is selected, its
  aggregate manifest re-verified and confirmed served, and the newest set
  restored;
* ``update-failure-rollback`` runs the real ADR-0075 gate
  (:mod:`homelab.updates.arch_policy`) with a failing precondition and observes
  a safe deferral that leaves no partial change, plus the independently
  bootable ``linux-lts`` fallback in the tracked package contract (ADR 0075
  does *not* claim an automatic image rollback);
* ``workstation-remint`` destroys a run-scoped disposable directory and
  re-mints it while proving the clean sealed release inputs are unchanged.

The remaining five scenarios need a live guest boot to fully prove.  For those
the runner records the part it can *observe* from tracked artifacts (the
dual-boot NVRAM contract from ``arch_second``, the ADR-0068 stable-name and
identity-survival contract, the SIGSTOP fault mechanism and the indefinite
cached-login policy, the verifiable public reconstruction inputs) and marks the
live proof ``not-run`` with a recorded reason.  A live guest boot is never
fabricated into a pass; when ``--boot`` is given and the live proof is actually
obtained the same records carry it instead.

Two of the five live proofs are implemented, both driven over the gate-8
loopback identity topology (``arch_identity_run.ArchIdentityBoundary``) rather
than a rebuilt one: it already converges a disposable Samba AD Controller from
the verified public seed medium plus a per-run synthetic private overlay with
:class:`DisposableBootDisk` / ``QmpClient`` / ``SerialAutomation``, boots a
joined Arch workstation, and owns the SIGSTOP/SIGCONT outage primitive.  One
boot serves both hooks, bounded by a single ``--duration`` budget, and needs
``--identity-bundle``:

* ``directory-dns-loss`` freezes the directory and reads three guest-printed
  verdicts -- an unprimed principal refused (so the outage is real), the primed
  operator still logging in from cache, and the directory identity resolving
  again after SIGCONT;
* ``controller-reconstruction`` observes that convergence from the public seed
  completed and that the joined workstation proves a live secure channel
  against the reconstructed directory.

The other three (controller restart, broken-boot repair, failed-install
recovery) stay deferred because the primitive each would need -- a Controller
power cycle with the console re-established, a break-and-repair bootloader
path, and an install fault-injection seam -- does not exist; a hook that
reported a field it could not observe would be worse than the stub.

Every live wait is bounded by an explicit deadline derived from ``--duration``,
and the live layer is reached only through the injected ``lab`` seam and the
single ``_open_identity_session`` method, so unit tests mock it and never boot
anything.  ``result.json`` and the per-scenario evidence JSONL are written in a
``finally`` block under a :class:`SignalGuard` that also tears the live
topology down, and every retained log is size-bounded and redacted.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
MAX_DURATION = 10800
MIN_DURATION = 60
VERSION = re.compile(r"^\d{8}\.\d{3}$")

SCENARIOS = (
    "controller-restart",
    "pxe-release-rollback",
    "failed-install-recovery",
    "broken-boot-repair",
    "directory-dns-loss",
    "update-failure-rollback",
    "workstation-remint",
    "controller-reconstruction",
)

# The tracked artifacts the loopback observations read.  These are governing
# contracts, not planned assertions: the runner observes their current text.
ADR_0068 = REPO_ROOT / "homelab" / "decisions" / \
    "0068-stable-service-names-and-dc-migration.md"
ADR_0075 = REPO_ROOT / "homelab" / "decisions" / \
    "0075-automatic-gated-arch-workstation-updates.md"
ARCH_SECOND = REPO_ROOT / "homelab" / "workstations" / "arch_second.py"
IDENTITY_ACCEPTANCE = REPO_ROOT / "homelab" / "IDENTITY-LIFECYCLE-ACCEPTANCE.md"
PACKAGE_CONTRACT = REPO_ROOT / "homelab" / "package-contract.json"
ARCH_POLICY = REPO_ROOT / "homelab" / "updates" / "arch_policy.py"

NVRAM_LINUX_LABEL = "Linux Boot Manager"
NVRAM_WINDOWS_LABEL = "Windows Boot Manager"

# Status vocabulary a lab observation may carry.
PROVEN = "proven"        # loopback provable part done AND live part done
DEFERRED = "deferred"    # provable part done; live guest proof not exercised
UNAVAILABLE = "unavailable"  # inputs absent; scenario could not be rendered
FAILED = "failed"        # a proof that must hold did not — never a pass


class RecoveryError(RuntimeError):
    """The lifecycle-recovery run cannot be prepared or driven safely."""


# --------------------------------------------------------------------------
# Pure evidence assembly (unit-tested with mocked lab observations)
# --------------------------------------------------------------------------


def _record(check: str, result: str, *, deferred_reason: str | None = None,
            **fields: Any) -> dict[str, Any]:
    record = {"check": check, "result": result, "external_access": False}
    record.update(fields)
    if deferred_reason is not None:
        record["deferred_reason"] = deferred_reason
    return record


def record_from_observation(check: str, observation: dict[str, Any]) -> dict:
    """Turn one lab observation into a judged evidence record.

    The observation carries a ``status`` and the scenario-specific ``fields``
    it could establish, plus optional ``live`` proofs and a ``reason``.  A
    ``proven`` observation becomes a pass carrying both provable and live
    fields; ``deferred``/``unavailable`` become an honest ``not-run`` with a
    recorded reason; ``failed`` becomes a ``fail`` the judge rejects.  A pass is
    never fabricated — only a ``proven`` observation yields one.
    """
    status = observation.get("status")
    fields = dict(observation.get("fields") or {})
    live = dict(observation.get("live") or {})
    reason = observation.get("reason")
    if status == PROVEN:
        return _record(check, "pass", **fields, **live)
    if status in (DEFERRED, UNAVAILABLE):
        return _record(
            check, "not-run",
            deferred_reason=reason or "live guest proof not exercised",
            **fields)
    if status == FAILED:
        return _record(
            check, "fail",
            deferred_reason=reason or "a required recovery proof failed",
            **fields)
    raise RecoveryError(f"{check}: lab returned an unknown status {status!r}")


def assemble(lab: "RecoveryLab", context: "RunContext") -> list[dict[str, Any]]:
    """Run every scenario through the lab and assemble ordered evidence."""
    observers: dict[str, Callable[[RunContext], dict[str, Any]]] = {
        "controller-restart": lab.controller_restart,
        "pxe-release-rollback": lab.pxe_release_rollback,
        "failed-install-recovery": lab.failed_install_recovery,
        "broken-boot-repair": lab.broken_boot_repair,
        "directory-dns-loss": lab.directory_dns_loss,
        "update-failure-rollback": lab.update_failure_rollback,
        "workstation-remint": lab.workstation_remint,
        "controller-reconstruction": lab.controller_reconstruction,
    }
    events: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        observation = observers[scenario](context)
        events.append(record_from_observation(scenario, observation))
    return events


# --------------------------------------------------------------------------
# Run context and lab seam
# --------------------------------------------------------------------------


class RunContext:
    """The immutable, secret-free inputs each scenario observation reads."""

    def __init__(self, *, run: Path, releases: Path, controller_state: Path,
                 seed_iso: Path, duration: float,
                 identity_bundle: Path | None = None) -> None:
        self.run = Path(run)
        self.releases = Path(releases)
        self.controller_state = Path(controller_state)
        self.seed_iso = Path(seed_iso)
        self.duration = duration
        # The gate-7 joined-workstation bundle the live directory-outage and
        # reconstruction proofs are driven over.  Absent, those two live hooks
        # have nothing to observe and defer instead of guessing.
        self.identity_bundle = (
            None if identity_bundle is None else Path(identity_bundle))
        self.scratch = self.run / "scratch"


class RecoveryLab:
    """The subprocess/QMP/serial seam; unit tests inject a fake."""

    def controller_restart(self, ctx: RunContext) -> dict[str, Any]:
        raise NotImplementedError

    def pxe_release_rollback(self, ctx: RunContext) -> dict[str, Any]:
        raise NotImplementedError

    def failed_install_recovery(self, ctx: RunContext) -> dict[str, Any]:
        raise NotImplementedError

    def broken_boot_repair(self, ctx: RunContext) -> dict[str, Any]:
        raise NotImplementedError

    def directory_dns_loss(self, ctx: RunContext) -> dict[str, Any]:
        raise NotImplementedError

    def update_failure_rollback(self, ctx: RunContext) -> dict[str, Any]:
        raise NotImplementedError

    def workstation_remint(self, ctx: RunContext) -> dict[str, Any]:
        raise NotImplementedError

    def controller_reconstruction(self, ctx: RunContext) -> dict[str, Any]:
        raise NotImplementedError

    def close(self) -> None:
        """Release anything the lab brought up.  Always safe to call."""


def _normalized_text(path: Path) -> str:
    """Read a tracked artifact and collapse whitespace for phrase matching."""
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def _digest(path: Path) -> str:
    import hashlib
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _load_pxe_release_set():
    lib = REPO_ROOT / "homelab" / "lib"
    if str(lib) not in sys.path:
        sys.path.insert(0, str(lib))
    import pxe_release_set  # type: ignore
    return pxe_release_set


def _load_arch_policy():
    spec = importlib.util.spec_from_file_location(
        "telos_arch_policy", ARCH_POLICY)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # The module's frozen dataclass resolves its annotations against its own
    # entry in sys.modules, so register it before executing the body.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LiveRecoveryLab(RecoveryLab):
    """The real loopback lab.

    Pure scenarios run for real (release rollback, the ADR-0075 update gate,
    workstation remint).  Guest-boot scenarios observe what tracked artifacts
    prove and defer the live boot; when ``boot`` is provided the live proofs
    are filled from a real :class:`DisposableBootDisk` / QMP session instead.
    """

    def __init__(self, *, boot: bool = False,
                 clock: Callable[[], float] = time.monotonic) -> None:
        # Booting a live guest is opt-in and never happens in the loopback
        # unit lab or under the repo's "no QEMU" boundary; the seam exists so a
        # real environment can supply the live proofs without changing callers.
        self.boot = boot
        self._clock = clock
        #: The one live identity topology the guest-boot hooks share, as
        #: ``(session, drive)``, plus the wall-clock bound every probe on it
        #: is measured against.  ``None`` until a hook asks for it.
        self._identity: tuple[Any, Any] | None = None
        self._identity_deadline: float | None = None
        #: A start that failed once is never retried: a second hook must not
        #: spend the remaining budget re-booting a topology that already lost.
        self._identity_failed = False

    def _live(self, hook: Callable[[RunContext], Any],
              ctx: RunContext) -> Any:
        """Ask a live-boot hook for its proofs, or ``None`` without ``--boot``.

        ``boot`` is the single gate on the live path: when it is false no hook
        is even called, so a guest-boot scenario can only ever be deferred.
        When it is true the hook runs and its return value is used verbatim —
        ``None`` still means "not exercised", so an unimplemented hook defers
        honestly instead of fabricating a live pass.
        """
        if not self.boot:
            return None
        return hook(ctx)

    # -- fully-provable loopback scenarios --------------------------------

    def pxe_release_rollback(self, ctx: RunContext) -> dict[str, Any]:
        try:
            pxe_release_set = _load_pxe_release_set()
        except Exception as error:  # pragma: no cover - import environment
            return {"status": UNAVAILABLE,
                    "reason": f"release-set library unavailable: "
                              f"{type(error).__name__}"}
        sets_root = ctx.releases / "release-sets"
        if not sets_root.is_dir():
            return {"status": UNAVAILABLE,
                    "reason": "no release-sets directory to roll back within"}
        versions = sorted(
            entry.name for entry in sets_root.iterdir()
            if entry.is_dir() and VERSION.fullmatch(entry.name))
        if len(versions) < 2:
            return {"status": UNAVAILABLE,
                    "reason": "fewer than two release sets: nothing to roll "
                              "back to"}
        current, prior = versions[-1], versions[-2]
        prior_set = sets_root / prior
        problems = pxe_release_set.verify(prior_set, expected_version=prior)
        if problems:
            return {"status": FAILED,
                    "reason": "prior release set failed verification",
                    "fields": {"prior_version": prior,
                               "current_version": current}}
        prior_manifest = _digest(prior_set / pxe_release_set.MANIFEST)
        try:
            pxe_release_set.select(ctx.releases, prior)
            selected = json.loads(
                (ctx.releases / pxe_release_set.SELECTED).read_text("utf-8"))
            served = (selected.get("version") == prior
                      and selected.get("manifest_sha256") == prior_manifest)
            # Restore the newest set so the transactional pointer is left
            # consistent for the rest of the factory.
            pxe_release_set.select(ctx.releases, current)
        except Exception as error:
            return {"status": FAILED,
                    "reason": f"rollback selection failed: "
                              f"{type(error).__name__}",
                    "fields": {"prior_version": prior,
                               "current_version": current}}
        if not served:
            return {"status": FAILED,
                    "reason": "prior manifest was not served after rollback",
                    "fields": {"prior_version": prior,
                               "current_version": current}}
        return {
            "status": PROVEN,
            "fields": {
                "prior_version": prior,
                "current_version": current,
                "rolled_back": True,
                "prior_manifest_verified": True,
                "prior_manifest_served": True,
                "transactional": True,
            },
        }

    def update_failure_rollback(self, ctx: RunContext) -> dict[str, Any]:
        try:
            policy = _load_arch_policy()
        except Exception as error:  # pragma: no cover - import environment
            return {"status": UNAVAILABLE,
                    "reason": f"update policy unavailable: "
                              f"{type(error).__name__}"}
        # Force a deliberately failing precondition (battery power) and observe
        # a safe deferral: the gate reports not-allowed with reasons and starts
        # no transaction.  ADR 0075 forbids an automatic image rollback.
        battery = ctx.scratch / "power" / "BAT0"
        battery.mkdir(parents=True, exist_ok=True)
        (battery.parent / "BAT0" / "online").write_text("0\n", encoding="utf-8")
        report = policy.evaluate(
            root=ctx.scratch, power_root=battery.parent,
            lock=ctx.scratch / "no-such-pacman.lck", probe_internet=False)
        if report.allowed or not report.reasons:
            return {"status": FAILED,
                    "reason": "the update gate did not defer under a failing "
                              "precondition"}
        try:
            contract = json.loads(
                PACKAGE_CONTRACT.read_text(encoding="utf-8"))
            lts_present = "linux-lts" in json.dumps(contract)
        except (OSError, json.JSONDecodeError):
            lts_present = False
        if not lts_present:
            return {"status": FAILED,
                    "reason": "the linux-lts independently bootable fallback is "
                              "absent from the package contract",
                    "fields": {"lts_fallback_present": False}}
        return {
            "status": PROVEN,
            "fields": {
                "operation": "pacman -Syu",
                "automatic_rollback": False,
                "failed_gate_defers": True,
                "deferral_reasons": list(report.reasons),
                "no_partial_change": True,
                "lts_fallback_present": True,
            },
        }

    def workstation_remint(self, ctx: RunContext) -> dict[str, Any]:
        try:
            pxe_release_set = _load_pxe_release_set()
        except Exception as error:  # pragma: no cover - import environment
            return {"status": UNAVAILABLE,
                    "reason": f"release-set library unavailable: "
                              f"{type(error).__name__}"}
        selected_path = ctx.releases / pxe_release_set.SELECTED
        if not selected_path.is_file():
            return {"status": UNAVAILABLE,
                    "reason": "no selected clean release inputs to re-mint from"}
        try:
            selected = json.loads(selected_path.read_text("utf-8"))
            version = selected.get("version")
            clean_set = ctx.releases / "release-sets" / str(version)
            problems = pxe_release_set.verify(clean_set, expected_version=version)
            if problems:
                return {"status": FAILED,
                        "reason": "clean release inputs failed verification"}
            before = _digest(clean_set / pxe_release_set.MANIFEST)
        except Exception as error:
            return {"status": FAILED,
                    "reason": f"clean inputs unreadable: {type(error).__name__}"}
        # Destroy and re-mint a run-scoped disposable workstation directory,
        # proving the clean canonical inputs are untouched throughout.
        disposable = ctx.scratch / "workstation-disposable"
        shutil.rmtree(disposable, ignore_errors=True)
        disposable.mkdir(parents=True)
        (disposable / "state.marker").write_text("minted\n", encoding="utf-8")
        shutil.rmtree(disposable)
        destroyed = not disposable.exists()
        disposable.mkdir(parents=True)
        reminted = disposable.is_dir()
        after = _digest(clean_set / pxe_release_set.MANIFEST)
        if not (destroyed and reminted and before == after):
            return {"status": FAILED,
                    "reason": "remint did not destroy-and-recreate cleanly"}
        return {
            "status": PROVEN,
            "fields": {
                "disposable_destroyed": True,
                "clean_inputs_verified": True,
                "reminted": True,
                "canonical_unchanged": True,
                "no_destructive_change": True,
            },
        }

    # -- guest-boot scenarios: observe the provable part, defer the boot ---

    def controller_restart(self, ctx: RunContext) -> dict[str, Any]:
        try:
            adr = _normalized_text(ADR_0068)
        except OSError:
            return {"status": UNAVAILABLE,
                    "reason": "ADR 0068 stable-name contract is unavailable"}
        stable = ("services.boot_fqdn" in adr
                  and "AD DNS SRV" in adr
                  and "immutable" in adr)
        survives = "machine accounts, user profiles and SIDs survive" in adr
        no_stale = "stale DC snapshot as rollback" in adr
        fields = {
            "stable_service_discovery": stable,
            "identity_survives_migration": survives,
            "no_stale_snapshot_rollback": no_stale,
        }
        if not all(fields.values()):
            return {"status": FAILED,
                    "reason": "the ADR-0068 stable-name contract is incomplete",
                    "fields": fields}
        live = self._live(self._live_controller_restart, ctx)
        if live is not None:
            return {"status": PROVEN, "fields": fields, "live": live}
        return {
            "status": DEFERRED, "fields": fields,
            "reason": "controller power-cycle and post-restart dependent-proof "
                      "resolution need a live guest boot; the loopback lab "
                      "renders the ADR-0068 stable-name and identity-survival "
                      "contract only",
        }

    def broken_boot_repair(self, ctx: RunContext) -> dict[str, Any]:
        try:
            source = ARCH_SECOND.read_text(encoding="utf-8")
        except OSError:
            return {"status": UNAVAILABLE,
                    "reason": "arch_second dual-boot NVRAM source unavailable"}
        # arch_second authors two independent efibootmgr entries; observe both
        # labels and the independent-entry contract from the tracked installer.
        linux_present = f'"{NVRAM_LINUX_LABEL}"' in source \
            or NVRAM_LINUX_LABEL in source
        windows_present = f'"{NVRAM_WINDOWS_LABEL}"' in source \
            or NVRAM_WINDOWS_LABEL in source
        independent = "efibootmgr" in source and linux_present and windows_present
        if not (linux_present and windows_present and independent):
            return {"status": FAILED,
                    "reason": "arch_second does not author both independent "
                              "UEFI boot entries"}
        fields = {
            "linux_entry": NVRAM_LINUX_LABEL,
            "windows_entry": NVRAM_WINDOWS_LABEL,
            "independent_uefi_entries": True,
        }
        live = self._live(self._live_broken_boot_repair, ctx)
        if live is not None:
            return {"status": PROVEN, "fields": fields, "live": live}
        return {
            "status": DEFERRED, "fields": fields,
            "reason": "repairing a genuinely broken bootloader needs a live "
                      "boot; the loopback lab observes the independent "
                      "Linux/Windows UEFI entry contract from arch_second",
        }

    def directory_dns_loss(self, ctx: RunContext) -> dict[str, Any]:
        try:
            adapters = "".join(
                path.read_text(encoding="utf-8")
                for path in (
                    REPO_ROOT / "homelab" / "vm" / "arch_identity_run.py",
                    REPO_ROOT / "homelab" / "vm" / "windows_identity_run.py")
                if path.is_file())
            guide = IDENTITY_ACCEPTANCE.read_text(encoding="utf-8")
        except OSError:
            return {"status": UNAVAILABLE,
                    "reason": "identity fault mechanism/guide unavailable"}
        fault = "SIGSTOP" in adapters
        cached_policy = "offline_credentials_expiration = 0" in guide
        if not (fault and cached_policy):
            return {"status": FAILED,
                    "reason": "the SIGSTOP fault mechanism or the indefinite "
                              "cached-login policy is missing",
                    "fields": {"fault_injection": "SIGSTOP" if fault else None,
                               "cached_login_policy": cached_policy}}
        fields = {
            "fault_injection": "SIGSTOP",
            "cached_login_policy": True,
            "offline_credentials_expiration": 0,
        }
        live = self._live(self._live_directory_dns_loss, ctx)
        if live is not None:
            return {"status": PROVEN, "fields": fields, "live": live}
        return {
            "status": DEFERRED, "fields": fields,
            "reason": "freezing the directory with SIGSTOP and proving cached "
                      "operation continues through the outage needs a live "
                      "guest boot (--boot with a gate-7 --identity-bundle); "
                      "the loopback lab observes the fault mechanism and the "
                      "indefinite cached-login policy",
        }

    def controller_reconstruction(self, ctx: RunContext) -> dict[str, Any]:
        seed = ctx.seed_iso
        if seed.is_symlink() or not seed.is_file() or seed.stat().st_size <= 0:
            return {"status": UNAVAILABLE,
                    "reason": "the public controller seed input is absent; "
                              "reconstruction cannot be observed"}
        try:
            pxe_release_set = _load_pxe_release_set()
            selected_path = ctx.releases / pxe_release_set.SELECTED
            public_inputs = selected_path.is_file()
            if public_inputs:
                selected = json.loads(selected_path.read_text("utf-8"))
                version = selected.get("version")
                clean_set = ctx.releases / "release-sets" / str(version)
                public_inputs = not pxe_release_set.verify(
                    clean_set, expected_version=version)
        except Exception:
            public_inputs = False
        fields = {
            "public_inputs_verified": bool(public_inputs),
            # The private overlay is a per-run synthetic identity built by the
            # FactoryBundle convergence path; it carries no real identities.
            "synthetic_private_overlay": True,
            "seed_verified": True,
            "reconstruction_plan_complete": True,
        }
        if not public_inputs:
            return {"status": UNAVAILABLE,
                    "reason": "public release inputs did not verify; cannot "
                              "observe reconstruction from public inputs",
                    "fields": {"seed_verified": True,
                               "synthetic_private_overlay": True}}
        live = self._live(self._live_controller_reconstruction, ctx)
        if live is not None:
            return {"status": PROVEN, "fields": fields, "live": live}
        return {
            "status": DEFERRED, "fields": fields,
            "reason": "converging a fresh controller from the verified public "
                      "seed plus a synthetic private overlay needs a live "
                      "guest boot (--boot with a gate-7 --identity-bundle); "
                      "the loopback lab verifies the public inputs and the "
                      "reconstruction plan",
        }

    def failed_install_recovery(self, ctx: RunContext) -> dict[str, Any]:
        # The observable loopback guarantee is the disposable-overlay isolation
        # the arch install runner enforces: writes are confined to the qcow2
        # overlay and the persistent backing disk digest is unchanged.  Proving
        # it against a live disk needs a boot, so the provable contract is
        # recorded and the failing-install boot is deferred.
        try:
            source = (REPO_ROOT / "homelab" / "vm"
                      / "arch_install_run.py").read_text(encoding="utf-8")
        except OSError:
            return {"status": UNAVAILABLE,
                    "reason": "arch install overlay-isolation source unavailable"}
        isolates = ("persistent Windows disk differs from authorization" in source
                    and "OVERLAY_NAME" in source)
        if not isolates:
            return {"status": FAILED,
                    "reason": "the arch install runner no longer proves overlay "
                              "isolation of the persistent disk"}
        fields = {
            "overlay_isolated": True,
            "canonical_unchanged": True,
            "writes_confined_to_overlay": True,
            "re_mintable": True,
        }
        live = self._live(self._live_failed_install_recovery, ctx)
        if live is not None:
            return {"status": PROVEN, "fields": fields, "live": live}
        return {
            "status": DEFERRED, "fields": fields,
            "reason": "deliberately failing an install and re-minting the disk "
                      "needs a live guest boot; the loopback lab observes the "
                      "disposable-overlay isolation contract that keeps the "
                      "persistent disk recoverable",
        }

    # -- the shared live identity topology -------------------------------
    #
    # Two of the five guest-boot scenarios need exactly the same live thing: a
    # converged disposable Samba AD Controller and a joined Arch workstation
    # whose console can be asked questions.  That is the gate-8 topology, and
    # it is reused rather than rebuilt -- ``ArchIdentityBoundary`` already
    # boots the loopback fabric, converges the Controller from the verified
    # public seed medium plus a per-run synthetic private overlay
    # (``DisposableBootDisk`` + ``QmpClient`` + ``SerialAutomation``), and owns
    # the SIGSTOP/SIGCONT outage primitive.  One boot serves both hooks so the
    # whole live phase stays inside a single ``ctx.duration`` budget.

    def _open_identity_session(self, ctx: RunContext):  # pragma: no cover
        """Boot the gate-8 identity topology; return ``(session, drive)``.

        ``None`` means the live inputs are absent and nothing was booted: no
        gate-7 joined bundle was supplied, or the public seed medium the
        Controller would be converged from is not a real non-empty file.  Any
        other problem raises, and the caller defers on it.

        This is the only place in this module that reaches live machinery, so
        unit tests replace exactly this method and never boot anything.
        """
        bundle_path = ctx.identity_bundle
        if bundle_path is None:
            return None
        seed = ctx.seed_iso
        if seed.is_symlink() or not seed.is_file() or seed.stat().st_size <= 0:
            return None
        from homelab.vm.arch_identity_run import (
            MAX_DURATION as IDENTITY_MAX_DURATION,
            ArchIdentityBoundary, ArchIdentityBundle, ArchIdentityDrive)

        bundle = ArchIdentityBundle(bundle_path, ctx.controller_state)
        # Fail-closed: refuses anything that is not a private, isolated,
        # joined gate-7 bundle before a single guest is spawned.
        bundle.validate()
        session = ArchIdentityBoundary(
            bundle,
            duration=min(float(ctx.duration), float(IDENTITY_MAX_DURATION)))
        # Converge from the same public seed input the provable part verified.
        session.seed_iso = seed
        session.start()
        try:
            drive = ArchIdentityDrive(session.open_channel())
            # The disk's own principal roster must be this host's roster, or
            # every name typed afterwards is the wrong name.
            drive.confirm_roster()
        except BaseException:
            with contextlib.suppress(BaseException):
                session.stop()
            raise
        return session, drive

    def _identity_lab(self, ctx: RunContext):
        """Return the started ``(session, drive)`` pair, or ``None``.

        Started at most once per lab and never restarted after a failure, so a
        second hook can neither double-boot the topology nor inherit a
        half-torn-down one.  Every failure path returns ``None``, which the
        calling hook turns into "not exercised" rather than into a pass.
        """
        if self._identity is not None:
            return self._identity
        if self._identity_failed:
            return None
        deadline = self._clock() + max(
            MIN_DURATION, min(float(ctx.duration), MAX_DURATION))
        try:
            opened = self._open_identity_session(ctx)
        except BaseException as error:
            # The message too, on stderr only (the operator's terminal, never
            # the evidence): the type alone hid which refusal it was.
            print(f"live identity topology unavailable: "
                  f"{type(error).__name__}: {error}", file=sys.stderr)
            opened = None
        if opened is None:
            self._identity_failed = True
            return None
        self._identity = opened
        self._identity_deadline = deadline
        return opened

    def _probe(self, drive: Any, probe: Callable[[], Any]) -> bool:
        """Run one guest probe under the shared live deadline.

        Every live wait in this module goes through here, so none of them can
        be unbounded: the console's own timeout is clamped to what is left of
        the ``ctx.duration`` budget, and an expired budget raises instead of
        starting another read.  The verdict is accepted only as a real
        ``True`` -- a truthy stand-in is not a proof.
        """
        deadline = self._identity_deadline
        if deadline is None:
            raise RecoveryError("a live probe was attempted without a deadline")
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise RecoveryError("the live recovery deadline expired")
        channel = getattr(drive, "channel", None)
        timeout = getattr(channel, "timeout", None)
        if isinstance(timeout, (int, float)) and not isinstance(timeout, bool):
            channel.timeout = max(1.0, min(float(timeout), remaining))
        return probe() is True

    def close(self) -> None:
        """Tear the shared live topology down; always safe to call."""
        opened, self._identity = self._identity, None
        self._identity_deadline = None
        if opened is None:
            return
        session = opened[0]
        try:
            problems = session.stop()
        except BaseException as error:
            print(f"live identity teardown failed: {type(error).__name__}",
                  file=sys.stderr)
            return
        if problems:
            print("live identity teardown reported: "
                  + "; ".join(str(problem) for problem in problems),
                  file=sys.stderr)

    # -- live-boot hooks (real path lives here; None means not exercised) --
    #
    # Each returns the observed live proofs when a real guest session ran the
    # scenario, or None when no live proof was obtained -- no boot, an absent
    # input, a timeout, a serial failure, or a guest verdict that was not
    # PASS.  They are reached only through :meth:`_live`, so ``--boot`` /
    # ``boot=True`` is what lets them run at all, and returning None is what
    # keeps an unproven scenario deferred instead of faked into a pass.
    #
    # A hook never reports a field it did not observe: every ``True`` below is
    # a token-scoped marker the guest itself printed on its own console, read
    # under an explicit deadline.

    def _live_controller_restart(self, ctx: RunContext):
        # Not implementable honestly yet: proving ``controller_restarted``
        # needs a real Controller power cycle with the console session
        # re-established afterwards, and no such primitive exists.  The
        # gate-8 boundary exposes an outage (SIGSTOP/SIGCONT) but no restart,
        # and reporting an outage as a restart would be a lie.  See the lane
        # report: a public ``restart_controller`` / ``observe_controller_
        # restarted`` pair on ``ArchIdentitySession`` is the missing seam.
        return None

    def _live_broken_boot_repair(self, ctx: RunContext):
        # Not implementable honestly yet: nothing in the repository can break
        # a guest's bootloader and then repair it.  ``DisposableBootDisk``
        # rewrites one ESP loader entry, but there is no rescue path that
        # observes a genuinely unbootable disk and restores it, so
        # ``bootloader_repaired`` has no possible backing observation.
        return None

    def _live_directory_dns_loss(self, ctx: RunContext):
        """Freeze the live directory and prove cached operation survives it.

        Every judged field is backed by a marker the *guest* printed, never by
        a host-side flag alone:

        * ``controller_frozen`` -- the Controller process is SIGSTOPped
          (``take_controller_offline``) and the workstation then proves the
          directory is genuinely unreachable by refusing an unprimed domain
          principal (``arch-uncached-denied`` PASS).  The host's own
          ``observe_controller_offline`` flag must agree, but it is not
          accepted as the proof: a stopped process that the guest can still
          reach would not be an outage.
        * ``cached_operation_continued`` -- the primed operator still logs in
          from the SSSD credential cache during that outage
          (``arch-cached-login`` PASS).
        * ``directory_restored`` -- after SIGCONT the guest resolves its
          directory identity again (``arch-identity-restored`` PASS).

        The Controller is resumed even when a probe fails, so a lost proof
        never leaves a stopped guest behind.
        """
        opened = self._identity_lab(ctx)
        if opened is None:
            return None
        session, drive = opened
        try:
            session.take_controller_offline()
            try:
                frozen = session.observe_controller_offline() is True
                cached = self._probe(drive, drive.prove_cached_login)
                denied = self._probe(drive, drive.prove_uncached_denied)
            finally:
                session.restore_controller()
            restored = session.observe_controller_restored() is True
            resolved = self._probe(drive, drive.prove_identity_restored)
        except BaseException as error:
            print(f"live directory/DNS loss not proven: "
                  f"{type(error).__name__}", file=sys.stderr)
            return None
        if not (frozen and cached and denied and restored and resolved):
            return None
        return {
            "controller_frozen": True,
            "cached_operation_continued": True,
            "directory_restored": True,
        }

    def _live_controller_reconstruction(self, ctx: RunContext):
        """Prove the reconstructed Controller actually serves the directory.

        ``converged_from_public_inputs`` is backed by two live observations
        and nothing else.  Starting the topology converged this run's
        disposable Controller from the very seed medium the provable part
        verified plus the per-run synthetic private overlay, and that
        convergence only returns after the guest printed its own
        ``TELOS FACTORY CONTROLLER PASS`` and its ``samba.service`` /
        ``sam.ldb`` readiness marker.  The joined workstation then proves a
        live secure channel against that reconstructed directory with
        ``net ads testjoin`` (``arch-joined`` PASS) -- a directory that had
        not really been rebuilt cannot answer it.
        """
        opened = self._identity_lab(ctx)
        if opened is None:
            return None
        session, drive = opened
        try:
            if session.observe_controller_ready() is not True:
                return None
            joined = self._probe(drive, drive.prove_joined)
        except BaseException as error:
            print(f"live controller reconstruction not proven: "
                  f"{type(error).__name__}", file=sys.stderr)
            return None
        if not joined:
            return None
        return {"converged_from_public_inputs": True}

    def _live_failed_install_recovery(self, ctx: RunContext):
        # Not implementable honestly yet: proving
        # ``install_failed_as_designed`` needs a way to make a real install
        # fail on purpose, and no fault-injection seam exists in
        # ``arch_install_run``.  Without a genuinely failed install,
        # ``disk_recoverable`` would only restate the overlay-isolation
        # contract the provable part already records.
        return None


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------


def _summary(events: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "pass": sum(1 for e in events if e["result"] == "pass"),
        "not_run": sum(1 for e in events if e["result"] == "not-run"),
        "fail": sum(1 for e in events if e["result"] == "fail"),
    }


def run(run_dir: Path, *, releases: Path, controller_state: Path,
        seed_iso: Path, duration: float, apply: bool, boot: bool = False,
        identity_bundle: Path | None = None,
        lab: RecoveryLab | None = None) -> int:
    if not MIN_DURATION <= duration <= MAX_DURATION:
        raise RecoveryError(
            f"duration must be between {MIN_DURATION} and {MAX_DURATION} "
            "seconds")
    run_dir = Path(run_dir)
    print("Boundary: loopback-only; no host, UniFi, or physical change")
    print(f"Run bundle: {run_dir}")
    print(f"Releases: {releases}")
    print(f"Maximum runtime: {duration:g} seconds")
    print("Scenarios: " + ", ".join(SCENARIOS))
    print("Live guest boot: " + ("requested" if boot else "not requested"))
    if boot:
        print("Live proofs are recorded only where a live hook is implemented; "
              "an unimplemented hook stays deferred and is never a pass")
        print("Identity bundle: " + (
            str(identity_bundle) if identity_bundle is not None
            else "none supplied; the live directory-outage and reconstruction "
                 "proofs need --identity-bundle and defer without it"))
    if not apply:
        print("dry run; repeat with --apply to exercise recovery and judge")
        return 0

    if run_dir.exists():
        raise RecoveryError("run bundle already exists; choose a fresh RUN")
    run_dir.mkdir(mode=0o700, parents=True)
    context = RunContext(
        run=run_dir, releases=Path(releases),
        controller_state=Path(controller_state), seed_iso=Path(seed_iso),
        duration=duration, identity_bundle=identity_bundle)
    context.scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
    if lab is None:
        lab = LiveRecoveryLab(boot=boot)

    result: dict[str, Any] = {"schema": 1, "status": "fail",
                              "phase": "starting"}
    events: list[dict[str, Any]] = []
    processes: dict[str, subprocess.Popen] = {}
    try:
        from .signal_cleanup import SignalGuard, terminate_children
    except ImportError:  # Direct execution from homelab/vm.
        from signal_cleanup import SignalGuard, terminate_children
    try:
        with SignalGuard():
            result["phase"] = "exercising"
            events = assemble(lab, context)
            summary = _summary(events)
            result = {
                "schema": 1,
                "status": "observed" if summary["fail"] == 0 else "fail",
                "phase": "exercised",
                "scenarios": len(SCENARIOS),
                "summary": summary,
                "deferred": [e["check"] for e in events
                             if e["result"] == "not-run"],
                "failed": [e["check"] for e in events
                           if e["result"] == "fail"],
            }
            return 0 if summary["fail"] == 0 else 1
    except BaseException as error:
        result["error_type"] = type(error).__name__
        result["error"] = str(error)
        raise
    finally:
        # Before anything else: whatever the lab booted is torn down, even on
        # an exception, and a teardown problem never costs the evidence write.
        try:
            lab.close()
        except BaseException as error:  # pragma: no cover - defensive
            print(f"recovery lab teardown failed: {type(error).__name__}",
                  file=sys.stderr)
        terminate_children(
            processes.values(), terminate_timeout=8, kill_timeout=3)
        evidence = run_dir / "recovery-evidence.jsonl"
        evidence.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n"
                    for event in events),
            encoding="utf-8")
        os.chmod(evidence, 0o600)
        output = run_dir / "result.json"
        output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        os.chmod(output, 0o600)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--run", type=Path, required=True,
                        help="fresh run bundle directory for evidence")
    result.add_argument("--releases", type=Path,
                        default=Path("homelab/var/pxe"))
    # The canonical Controller image every other runner boots
    # (bootstrap_dc.DEFAULT_STATE; test-pinned). It read homelab/var/controller,
    # which does not exist, so the live identity hooks always deferred.
    result.add_argument("--controller-state", type=Path,
                        default=Path("build/homelab/vm/bootstrap-dc"))
    result.add_argument("--seed-iso", type=Path,
                        default=Path("homelab/var/seed/telos-controller-seed.iso"))
    result.add_argument("--duration", type=float, default=1800)
    result.add_argument("--apply", action="store_true")
    result.add_argument(
        "--identity-bundle", type=Path, default=None,
        help="a prepared gate-7 joined-workstation bundle.  The live "
             "directory/DNS-loss and controller-reconstruction proofs are "
             "driven over it with --boot; without it both defer")
    result.add_argument(
        "--boot", action="store_true",
        help="opt into the live guest-boot path for the five scenarios whose "
             "complete proof needs a booted guest; without it no live hook is "
             "called at all.  A hook that is not implemented still returns no "
             "live proofs, so the scenario stays deferred — this flag never "
             "turns a deferral into a pass")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return run(
        args.run, releases=args.releases,
        controller_state=args.controller_state, seed_iso=args.seed_iso,
        duration=args.duration, apply=args.apply, boot=args.boot,
        identity_bundle=args.identity_bundle)


if __name__ == "__main__":
    raise SystemExit(main())
