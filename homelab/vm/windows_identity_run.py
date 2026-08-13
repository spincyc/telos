#!/usr/bin/env python3
"""Ordered, fail-closed lifecycle for native Windows identity acceptance."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Mapping
from types import MappingProxyType
from pathlib import Path

from .automated_controller import DisposableBootDisk
from .bootstrap_dc import paths
from .controller_factory import FactoryBundle
from .factory_runner import (
    DEFAULT_SEED_ISO,
    GATEWAY_MAC,
    MACS,
    SwitchEvidenceCursor,
    _switch_events_after,
    capture_switch_evidence_cursor,
    gateway_command,
    switch_command,
    wait_for_plain_dhcp_transaction,
    wait_for_switch_disconnect,
    wait_for_switch_port,
)
from .signal_cleanup import RunInterrupted, terminate_children
from .serial_automation import SerialAutomation, SerialAutomationError
from .simulated_topology import audit_live_process, controller_command
from .windows_gui import QmpClient
from .windows_identity_contract import qemu_identity_command
from .windows_identity_prepare import CONTROL_ISO_NAME
from .windows_identity_recovery import RecoveredLocalCredential
from .windows_identity_dependency import DEPENDENCIES
from .windows_postsubmit_diagnostic import (
    PostSubmitDiagnosticCleanup,
    PostSubmitDiagnosticCode,
    PostSubmitDiagnosticCollection,
)
from .controller_auth_diagnostic import (
    ControllerAuthArmSubphase,
    ControllerAuthCollection,
    ControllerAuthReceiveObservation,
    ControllerAuthResult,
)

IDENTITY_CONTROLLER_MAC = bytes.fromhex(MACS["controller"].replace(":", ""))
WINDOWS_OS_READINESS_TIMEOUT = 300.0


@dataclass(frozen=True)
class IdentityFailureDiagnostic:
    """Allowlisted, secret-free identity failure coordinates."""

    check: str
    operation: str
    error_type: str
    post_submit_diagnostic: str | None = None
    post_submit_collection: str | None = None
    post_submit_cleanup: str | None = None
    controller_auth: ControllerAuthResult | None = None
    controller_auth_arm_subphase: ControllerAuthArmSubphase | None = None
    controller_auth_receive_observation: (
        ControllerAuthReceiveObservation | None) = None

    _STATIC_PROBE_PAIRS = frozenset({
        ("controller-ready", "controller-readiness"),
        ("windows-joined", "domain-state"),
        ("windows-standard-online", "managed-identity-state"),
        ("windows-daily-admin", "managed-identity-state"),
        ("domain-admin-separate", "managed-identity-state"),
        ("windows-rebooted-joined", "domain-state"),
        ("windows-rebooted-joined", "interactive-operator"),
        ("windows-cached-policy", "cached-logon-policy"),
        ("windows-cached-policy", "managed-identity-state"),
        ("controller-offline", "service-reachability"),
        ("controller-restored", "service-reachability"),
        ("windows-secure-channel-restored", "domain-state"),
        ("windows-update-policy", "update-policy"),
        ("update-source-offline", "dependency-reachability"),
        ("optional-storage-offline", "dependency-reachability"),
        ("optional-storage-access-denied", "dependency-reachability"),
        ("ad-dns-offline", "service-reachability"),
        ("combined-dependencies-offline", "dependency-reachability"),
        ("windows-services-restored", "service-reachability"),
        ("windows-services-restored", "domain-state"),
        ("windows-services-restored", "dependency-reachability"),
    })
    _STATIC_PROBES = frozenset(
        (check, f"static-probe.{action}{suffix}")
        for check, action in _STATIC_PROBE_PAIRS
        for suffix in (
            "", ".preflight", ".lease", ".connect", ".launch", ".launcher-receive",
            ".launcher-parse", ".start-receive", ".start-parse",
            ".outcome-receive", ".outcome-parse", ".guest", ".validate",
        )
    )
    _CONTROLLER_CONVERGENCE_STAGES = frozenset({
        "network",
        "time-sync",
        "time-sync-response",
        "time-sync-clock",
        "payload-stage",
        "package-preflight",
        "package-missing-samba",
        "package-missing-krb5",
        "package-missing-ntp",
        "package-missing-python-cryptography",
        "package-missing-python-dnspython",
        "package-missing-python-markdown",
        "package-missing-openresolv",
        "package-missing-bind",
        "ansible",
        "services",
        "auth-audit",
        "auth-audit-preflight",
        "auth-audit-sink-create",
        "auth-audit-config-write",
        "auth-audit-config-verify",
        "auth-audit-restart",
        "auth-audit-sink-verify",
        "verify",
        *(f"verify-{index:02d}" for index in range(1, 11)),
        "administrator-disable",
        "administrator-disabled-proof",
    })
    _ERROR_TYPES = frozenset({
        "ControllerJoinMaterialError",
        "ControllerJoinReturnCode",
        "ControllerPrincipalError",
        "EvidencePublicationError",
        "FaultPhaseError",
        "OSError",
        "SerialAutomationError",
        "TimeoutError",
        "WindowsControlSerialError",
        "WindowsCredentialActionError",
        "WindowsGuestProbeError",
        "WindowsIdentityAdapterError",
        "WindowsIdentityDiagnosticError",
        "WindowsIdentityFactoryError",
        "WindowsIdentityGuiError",
        "WindowsIdentityObservationError",
        "WindowsIdentityOrchestratorError",
        "WindowsJoinIsoError",
        "WindowsLocalReauthenticationError",
        "WindowsPublicCommandError",
    })
    # The 24 required acceptance checks, in contract order. A failure at any
    # check between windows-daily-admin and the final aggregate used to
    # collapse to scoped-acceptance.acceptance/UnexpectedError (attempt 47);
    # acceptance_check() names WHICH check and its phase instead.
    _ACCEPTANCE_CHECKS = frozenset({
        "controller-ready", "windows-joined", "windows-standard-online",
        "windows-daily-admin", "domain-admin-separate",
        "windows-rebooted-joined", "windows-cached-policy",
        "controller-offline", "windows-cached-login",
        "windows-cached-admin-login", "windows-uncached-denied",
        "windows-local-rescue", "controller-restored",
        "windows-secure-channel-restored", "windows-update-policy",
        "gateway-offline", "update-source-offline",
        "optional-storage-offline", "optional-storage-access-denied",
        "ad-dns-offline", "combined-dependencies-offline",
        "windows-services-restored", "windows-diagnostics-sanitized",
        "windows-identity-acceptance",
    })
    _ACCEPTANCE_PHASES = frozenset({
        "observe", "static-probe", "credential-action",
        "fault-transition", "aggregate",
    })
    # Exact (check, guest credential action) pairs, mirroring the adapter's
    # check-to-action map including the combined-dependencies split.
    _CREDENTIAL_ACTION_PAIRS = frozenset({
        ("windows-standard-online", "connected-domain-login"),
        ("windows-daily-admin", "operator-local-administrators-check"),
        ("windows-cached-login", "cached-domain-login"),
        ("windows-cached-admin-login", "cached-domain-login"),
        ("windows-uncached-denied", "uncached-domain-user-denied"),
        ("windows-local-rescue", "local-rescue-login"),
        ("gateway-offline", "connected-domain-login"),
        ("update-source-offline", "connected-domain-login"),
        ("optional-storage-offline", "connected-domain-login"),
        ("optional-storage-access-denied", "connected-domain-login"),
        ("ad-dns-offline", "cached-domain-login"),
        ("combined-dependencies-offline", "cached-domain-login"),
        ("combined-dependencies-offline", "local-rescue-login"),
    })

    @classmethod
    def credential_action(
        cls, check: str, action: str, phase: str, error_type: str,
    ) -> "IdentityFailureDiagnostic":
        """Bind a typed guest credential-action failure to its check.

        Attempt 36 (20260811T132018Z) failed inside the first live
        connected-domain-login and rendered NOTHING: the credential-action
        machinery carried no diagnostic, so the run reported only its
        wrapper exception type and taught the next run nothing -- the same
        gap guest_boot closed for boot raises.
        """
        if (
            (check, action) not in cls._CREDENTIAL_ACTION_PAIRS
            or phase not in {"serial-connect", "media", "execute"}
        ):
            return cls("unknown-check", "unknown-operation", "UnexpectedError")
        if error_type not in cls._ERROR_TYPES:
            error_type = "UnexpectedError"
        return cls(
            check, f"credential-action.{action}.{phase}", error_type)

    @classmethod
    def scoped_acceptance(
        cls, phase: str, error_type: str,
    ) -> "IdentityFailureDiagnostic":
        """Last-resort coordinate for a diagnostic-less acceptance failure.

        run_scoped_acceptance forwarded diagnostic=None whenever the inner
        failure carried none, and the progressive sanitizer then discarded
        the message too, so attempt 36 rendered a completely bare
        `WindowsIdentityRunError`. Under the no-bare-coordinates convention
        even an untyped failure names which side of the scope broke and the
        exact inner exception type.
        """
        if phase not in {"acceptance", "principal-destruction"}:
            return cls("unknown-check", "unknown-operation", "UnexpectedError")
        if error_type not in cls._ERROR_TYPES:
            error_type = "UnexpectedError"
        return cls(
            "windows-identity-acceptance",
            f"scoped-acceptance.{phase}",
            error_type,
        )

    @classmethod
    def acceptance_check(
        cls, check: str, phase: str, error_type: str,
    ) -> "IdentityFailureDiagnostic":
        """Name WHICH acceptance check raised, and in which phase.

        Attempt 47 failed somewhere in the fault phases (checks 8-24) and
        rendered scoped-acceptance.acceptance/UnexpectedError -- the check
        identity and the real exception type were both swallowed by the
        FaultPhaseError re-wrap. This binds the failure to its exact check.
        """
        if check not in cls._ACCEPTANCE_CHECKS or phase not in (
                cls._ACCEPTANCE_PHASES):
            return cls("unknown-check", "unknown-operation", "UnexpectedError")
        if error_type not in cls._ERROR_TYPES:
            error_type = "UnexpectedError"
        return cls(check, f"acceptance.{phase}", error_type)

    @classmethod
    def join_material(
        cls, operation: str, phase: str, error_type: str,
    ) -> "IdentityFailureDiagnostic":
        """Bind a typed Controller join failure to its acceptance check."""
        candidate = f"join-material.{operation}.{phase}"
        if (
            operation not in {"stage", "destroy"}
            or phase not in {
                "shell-prompt-request", "shell-prompt", "command-send",
                "secret-input-ready", "secret-input-send",
                "sudo-password-prompt", "sudo-password-send", "return-code",
            }
        ):
            return cls("unknown-check", "unknown-operation", "UnexpectedError")
        if error_type not in cls._ERROR_TYPES:
            error_type = "UnexpectedError"
        return cls("windows-joined", candidate, error_type)

    @classmethod
    def guest_boot(
        cls, phase: str, error_type: str, *, retried: bool = False,
    ) -> "IdentityFailureDiagnostic":
        """Bind a bounded Windows boot failure to its acceptance check.

        Exhausting the boot retry used to raise with no diagnostic at all, so
        an eleven-minute run reported only its exception type and taught the
        next run nothing.

        The operation carries the signal. Exhausted readiness has no
        underlying typed exception, and `WindowsIdentityRunError` is
        deliberately absent from the allowlist so a generic run error cannot
        pass as a typed one, so it renders as `UnexpectedError` while the
        operation still says exactly where the boot stopped.
        """
        if phase not in {"os-readiness", "switch-disconnect-proof"}:
            return cls("unknown-check", "unknown-operation", "UnexpectedError")
        if error_type not in cls._ERROR_TYPES:
            error_type = "UnexpectedError"
        suffix = ".after-retry" if retried else ""
        # The check is the one being pursued, as join_material does; the
        # operation says where it stopped.
        return cls("windows-joined", f"guest-boot.{phase}{suffix}", error_type)

    @classmethod
    def controller_convergence(
        cls, phase: str, error_type: str,
    ) -> "IdentityFailureDiagnostic":
        """Bind a Controller factory failure to its last public phase."""
        if phase not in cls._CONTROLLER_CONVERGENCE_STAGES:
            return cls("unknown-check", "unknown-operation", "UnexpectedError")
        if error_type not in cls._ERROR_TYPES:
            error_type = "UnexpectedError"
        return cls(
            "controller-ready",
            f"controller-convergence.{phase}",
            error_type,
        )

    @classmethod
    def join_guest(
        cls, phase: str, error_type: str,
        post_submit_diagnostic: str | None = None,
        post_submit_collection: str | None = None,
        post_submit_cleanup: str | None = None,
        controller_auth: ControllerAuthResult | None = None,
        controller_auth_arm_subphase: ControllerAuthArmSubphase | None = None,
        controller_auth_receive_observation: (
            ControllerAuthReceiveObservation | None) = None,
    ) -> "IdentityFailureDiagnostic":
        candidate = f"join-guest.{phase}"
        if phase not in {
            "serial-connect", "prepare", "attach", "launch",
            "elevation-receive", "elevation-parse", "marker-receive",
            "media-destroy", "release", "result-receive", "result-parse",
            "result-ack", "accepted-receive", "accepted-parse",
            "result", "reboot-reauth",
            "reboot-probe", "cleanup",
            # One coordinate per expected post-reboot proof field, so a
            # proof mismatch names its first failing field instead of a
            # bare `result` (attempt 34, 20260811T123220Z).
            "result-mismatch-schema-version",
            "result-mismatch-boot-completed",
            "result-mismatch-domain-joined", "result-mismatch-domain",
            "result-mismatch-operator",
            "result-mismatch-operator-local-administrator",
            "result-mismatch-key-set",
            "result-guest-add-computer",
            "result-guest-join-authorization",
            "result-guest-join-authentication",
            "result-guest-join-domain-discovery",
            "result-guest-join-account-conflict",
            "result-guest-join-unclassified",
            "result-guest-operator-resolution",
            "result-guest-operator-mutation",
            "result-guest-operator-verification",
            "marker-guest-diagnostic-source",
            "result-guest-policy-mutation",
            "result-guest-policy-readback",
            "result-guest-policy-verification",
            "result-guest-reboot-ack",
        } and phase not in {
            f"reboot-reauth-{operation}"
            for operation in (
                "wake", "calibration-capture", "calibration-required",
                "select-local-account", "type-public-username",
                "prove-password-target", "submit-focus-calibration",
                "controller-auth-arm", "diagnostic-arm",
                "diagnostic-arm-preflight", "diagnostic-arm-connect",
                "diagnostic-arm-launch", "diagnostic-arm-receive",
                "diagnostic-arm-parse", "diagnostic-arm-guest",
                "diagnostic-cleanup", "type-secret",
                "submit", "desktop",
                "desktop-near-reference",
                "desktop-sign-in-persisted",
                "desktop-sign-in-near-reference",
            )
        }:
            return cls("unknown-check", "unknown-operation", "UnexpectedError")
        if error_type not in cls._ERROR_TYPES:
            error_type = "UnexpectedError"
        return cls(
            "windows-joined", candidate, error_type,
            post_submit_diagnostic,
            post_submit_collection,
            post_submit_cleanup,
            controller_auth,
            controller_auth_arm_subphase,
            controller_auth_receive_observation,
        )

    @classmethod
    def static_probe(
        cls,
        check: str,
        action: str,
        error: BaseException,
        *,
        phase: str | None = None,
        normalized_error_type: str | None = None,
    ) -> "IdentityFailureDiagnostic":
        suffix = "" if phase is None else f".{phase}"
        operation = f"static-probe.{action}{suffix}"
        if (check, operation) not in cls._STATIC_PROBES:
            check = "unknown-check"
            operation = "unknown-operation"
        error_type = (
            type(error).__name__
            if normalized_error_type is None
            else normalized_error_type
        )
        if error_type not in cls._ERROR_TYPES:
            error_type = "UnexpectedError"
        return cls(check, operation, error_type)

    @classmethod
    def adapter_static_probe(
        cls, action: str, phase: str, error: BaseException,
    ) -> "IdentityFailureDiagnostic":
        checks = sorted(
            check for check, candidate in cls._STATIC_PROBE_PAIRS
            if candidate == action
        )
        check = checks[0] if checks else "unknown-check"
        return cls.static_probe(check, action, error, phase=phase)

    @classmethod
    def rebind_static_probe(
        cls,
        check: str,
        action: str,
        diagnostic: "IdentityFailureDiagnostic",
    ) -> "IdentityFailureDiagnostic | None":
        prefix = f"static-probe.{action}."
        if not diagnostic.operation.startswith(prefix):
            return None
        phase = diagnostic.operation.removeprefix(prefix)
        if phase not in {
            "preflight", "lease", "connect", "launch",
            "launcher-receive", "launcher-parse",
            "start-receive", "start-parse",
            "outcome-receive", "outcome-parse", "guest", "validate",
        }:
            return None
        operation = f"static-probe.{action}.{phase}"
        if (check, operation) not in cls._STATIC_PROBES:
            return None
        return cls(check, operation, diagnostic.error_type)

    def __post_init__(self) -> None:
        if (
            self.post_submit_diagnostic is not None
            and (
                type(self.post_submit_diagnostic) is not str
                or self.post_submit_diagnostic not in {
                    code.value for code in PostSubmitDiagnosticCode
                }
                or self.operation not in {
                    "join-guest.reboot-reauth-desktop",
                    "join-guest.reboot-reauth-diagnostic-cleanup",
                    "join-guest.reboot-reauth-desktop-near-reference",
                    "join-guest.reboot-reauth-desktop-sign-in-persisted",
                    "join-guest.reboot-reauth-desktop-sign-in-near-reference",
                }
                or self.error_type
                != "WindowsLocalReauthenticationError"
            )
        ):
            raise ValueError("post-submit diagnostic is invalid")
        if (
            self.post_submit_collection is not None
            and (
                type(self.post_submit_collection) is not str
                or self.post_submit_collection not in {
                    code.value for code in PostSubmitDiagnosticCollection
                }
                or self.operation not in {
                    "join-guest.reboot-reauth-desktop",
                    "join-guest.reboot-reauth-diagnostic-cleanup",
                    "join-guest.reboot-reauth-desktop-near-reference",
                    "join-guest.reboot-reauth-desktop-sign-in-persisted",
                    "join-guest.reboot-reauth-desktop-sign-in-near-reference",
                }
                or self.error_type
                != "WindowsLocalReauthenticationError"
            )
        ):
            raise ValueError("post-submit collection is invalid")
        if (
            self.post_submit_cleanup is not None
            and (
                type(self.post_submit_cleanup) is not str
                or self.post_submit_cleanup not in {
                    code.value for code in PostSubmitDiagnosticCleanup
                }
                or self.operation not in {
                    "join-guest.reboot-reauth-desktop",
                    "join-guest.reboot-reauth-diagnostic-cleanup",
                    "join-guest.reboot-reauth-desktop-near-reference",
                    "join-guest.reboot-reauth-desktop-sign-in-persisted",
                    "join-guest.reboot-reauth-desktop-sign-in-near-reference",
                }
                or self.error_type
                != "WindowsLocalReauthenticationError"
            )
        ):
            raise ValueError("post-submit cleanup is invalid")
        if (
            self.controller_auth is not None
            and (
                type(self.controller_auth) is not ControllerAuthResult
                or self.operation not in {
                    "join-guest.reboot-reauth-controller-auth-arm",
                    "join-guest.reboot-reauth-diagnostic-cleanup",
                    "join-guest.reboot-reauth-desktop",
                    "join-guest.reboot-reauth-desktop-near-reference",
                    "join-guest.reboot-reauth-desktop-sign-in-persisted",
                    "join-guest.reboot-reauth-desktop-sign-in-near-reference",
                }
                or self.error_type
                != "WindowsLocalReauthenticationError"
            )
        ):
            raise ValueError("Controller auth diagnostic is invalid")
        if (
            self.controller_auth_arm_subphase is not None
            and (
                type(self.controller_auth_arm_subphase)
                is not ControllerAuthArmSubphase
                or (
                    self.operation
                    != "join-guest.reboot-reauth-controller-auth-arm"
                    # A proved-cleanup arm failure lets the GUI continue and
                    # fail later; the subphase then explains the unavailable
                    # receipt at whichever reauthentication coordinate the
                    # attempt actually reached.
                    and not (
                        self.controller_auth is not None
                        and self.controller_auth.collection
                        is ControllerAuthCollection.RECEIPT_UNAVAILABLE
                    )
                )
                or self.error_type
                != "WindowsLocalReauthenticationError"
            )
        ):
            raise ValueError("Controller auth arm subphase is invalid")
        if (
            self.controller_auth_receive_observation is not None
            and (
                type(self.controller_auth_receive_observation)
                is not ControllerAuthReceiveObservation
                or self.controller_auth_arm_subphase
                is not ControllerAuthArmSubphase.RECEIVE
            )
        ):
            raise ValueError(
                "Controller auth receive observation is invalid")
        if (
            self.controller_auth_arm_subphase
            is ControllerAuthArmSubphase.RECEIVE
            and self.controller_auth_receive_observation is None
        ):
            raise ValueError(
                "Controller auth receive observation is missing")
        if (
            (self.check, self.operation) not in self._STATIC_PROBES
            and not (
                self.check == "windows-joined"
                and self.operation.startswith("join-material.")
                and len(self.operation.split(".")) == 3
                and self.operation.split(".")[1] in {"stage", "destroy"}
                and self.operation.split(".")[2] in {
                    "shell-prompt-request", "shell-prompt", "command-send",
                    "secret-input-ready", "secret-input-send",
                    "sudo-password-prompt", "sudo-password-send",
                    "return-code",
                }
            )
            and not (
                self.check == "windows-joined"
                and self.operation.startswith("join-guest.")
                and self.operation.removeprefix("join-guest.") in {
                    "serial-connect", "prepare", "attach", "launch", "marker-receive",
                    "elevation-receive", "elevation-parse",
                    "media-destroy", "release", "result-receive",
                    "result-parse", "result-ack", "accepted-receive",
                    "accepted-parse", "result", "reboot-reauth",
                    "reboot-probe", "cleanup",
                    "result-mismatch-schema-version",
                    "result-mismatch-boot-completed",
                    "result-mismatch-domain-joined",
                    "result-mismatch-domain",
                    "result-mismatch-operator",
                    "result-mismatch-operator-local-administrator",
                    "result-mismatch-key-set",
                    "result-guest-add-computer",
                    "result-guest-join-authorization",
                    "result-guest-join-authentication",
                    "result-guest-join-domain-discovery",
                    "result-guest-join-account-conflict",
                    "result-guest-join-unclassified",
                    "result-guest-operator-resolution",
                    "result-guest-operator-mutation",
                    "result-guest-operator-verification",
                    "marker-guest-diagnostic-source",
                    "result-guest-policy-mutation",
                    "result-guest-policy-readback",
                    "result-guest-policy-verification",
                    "result-guest-reboot-ack",
                } | {
                    f"reboot-reauth-{operation}"
                    for operation in (
                        "wake", "calibration-capture",
                        "calibration-required", "select-local-account",
                        "type-public-username", "prove-password-target",
                        "controller-auth-arm", "diagnostic-arm", "type-secret",
                        "diagnostic-arm-preflight", "diagnostic-arm-connect",
                        "diagnostic-arm-launch", "diagnostic-arm-receive",
                        "diagnostic-arm-parse", "diagnostic-arm-guest",
                        "diagnostic-cleanup",
                        "submit", "desktop",
                        "desktop-near-reference",
                        "desktop-sign-in-persisted",
                        "desktop-sign-in-near-reference",
                    )
                }
            )
            and not (
                self.check == "windows-joined"
                and self.operation.startswith("guest-boot.")
                and self.operation.removeprefix("guest-boot.").removesuffix(
                    ".after-retry"
                ) in {"os-readiness", "switch-disconnect-proof"}
            )
            and not (
                self.check == "controller-ready"
                and self.operation.startswith("controller-convergence.")
                and self.operation.removeprefix(
                    "controller-convergence."
                ) in self._CONTROLLER_CONVERGENCE_STAGES
            )
            and not (
                self.operation.startswith("credential-action.")
                and len(self.operation.split(".")) == 3
                and (
                    self.check, self.operation.split(".")[1],
                ) in self._CREDENTIAL_ACTION_PAIRS
                and self.operation.split(".")[2] in {
                    "serial-connect", "media", "execute",
                }
            )
            and not (
                self.check == "windows-identity-acceptance"
                and self.operation in {
                    "scoped-acceptance.acceptance",
                    "scoped-acceptance.principal-destruction",
                }
            )
            and not (
                self.check in self._ACCEPTANCE_CHECKS
                and self.operation.startswith("acceptance.")
                and self.operation.removeprefix("acceptance.")
                in self._ACCEPTANCE_PHASES
            )
            and (self.check, self.operation)
            != ("unknown-check", "unknown-operation")
        ):
            raise ValueError("identity failure coordinates are invalid")
        if (
            self.error_type not in self._ERROR_TYPES
            and self.error_type != "UnexpectedError"
        ):
            raise ValueError("identity failure type is invalid")

    def render(self) -> str:
        rendered = (
            f"check={self.check}; operation={self.operation}; "
            f"error={self.error_type}"
        )
        if self.post_submit_diagnostic is not None:
            rendered += (
                "; post-submit-diagnostic="
                f"{self.post_submit_diagnostic}"
            )
        if self.post_submit_collection is not None:
            rendered += (
                "; post-submit-collection="
                f"{self.post_submit_collection}"
            )
        if self.post_submit_cleanup is not None:
            rendered += (
                "; post-submit-cleanup="
                f"{self.post_submit_cleanup}"
            )
        if self.controller_auth is not None:
            if self.controller_auth.code is not None:
                rendered += (
                    f"; controller-auth={self.controller_auth.code.value}")
            if self.controller_auth.collection is not None:
                rendered += (
                    "; controller-auth-collection="
                    f"{self.controller_auth.collection.value}")
            if self.controller_auth.cleanup is not None:
                rendered += (
                    "; controller-auth-cleanup="
                    f"{self.controller_auth.cleanup.value}")
            if self.controller_auth.host_error is not None:
                rendered += (
                    "; controller-auth-host-error="
                    f"{self.controller_auth.host_error}")
            if self.controller_auth.receipt_origin is not None:
                rendered += (
                    "; controller-auth-receipt-origin="
                    f"{self.controller_auth.receipt_origin.value}")
        if self.controller_auth_arm_subphase is not None:
            rendered += (
                "; controller-auth-arm-subphase="
                f"{self.controller_auth_arm_subphase.value}")
        if self.controller_auth_receive_observation is not None:
            rendered += (
                "; controller-auth-receive-observation="
                f"{self.controller_auth_receive_observation.value}")
        return rendered


class WindowsIdentityRunError(RuntimeError):
    """The native identity lifecycle did not reach a safe terminal state."""

    def __init__(
        self,
        message: str,
        *,
        diagnostic: IdentityFailureDiagnostic | None = None,
    ) -> None:
        super().__init__(message)
        self.diagnostic = diagnostic


class WindowsLocalReauthenticationError(WindowsIdentityRunError):
    """Secret-free, allowlisted coordinate for post-join GUI failures."""

    _OPERATIONS = frozenset({
        "wake",
        "calibration-capture",
        "calibration-required",
        "select-local-account",
        "type-public-username",
        "prove-password-target",
        "submit-focus-calibration",
        "controller-auth-arm",
        "diagnostic-arm",
        "diagnostic-arm-preflight",
        "diagnostic-arm-connect",
        "diagnostic-arm-launch",
        "diagnostic-arm-receive",
        "diagnostic-arm-parse",
        "diagnostic-arm-guest",
        "diagnostic-cleanup",
        "type-secret",
        "submit",
        "desktop",
        "desktop-near-reference",
        "desktop-sign-in-persisted",
        "desktop-sign-in-near-reference",
    })

    def __init__(
        self,
        operation: str,
        *,
        post_submit_diagnostic: PostSubmitDiagnosticCode | None = None,
        post_submit_collection: PostSubmitDiagnosticCollection | None = None,
        post_submit_cleanup: PostSubmitDiagnosticCleanup | None = None,
        controller_auth_result: ControllerAuthResult | None = None,
        controller_auth_arm_subphase: ControllerAuthArmSubphase | None = None,
        controller_auth_receive_observation: (
            ControllerAuthReceiveObservation | None) = None,
    ) -> None:
        if operation not in self._OPERATIONS:
            operation = "prove-password-target"
        if (
            post_submit_diagnostic is not None
            and (
                type(post_submit_diagnostic) is not PostSubmitDiagnosticCode
                or operation not in {
                    "desktop", "desktop-near-reference",
                    "diagnostic-cleanup",
                    "desktop-sign-in-persisted",
                    "desktop-sign-in-near-reference",
                }
            )
        ):
            post_submit_diagnostic = None
        self.reauth_operation = operation
        self.post_submit_diagnostic = post_submit_diagnostic
        if (
            post_submit_collection is not None
            and (
                type(post_submit_collection)
                is not PostSubmitDiagnosticCollection
                or operation not in {
                    "desktop", "desktop-near-reference",
                    "diagnostic-cleanup",
                    "desktop-sign-in-persisted",
                    "desktop-sign-in-near-reference",
                }
            )
        ):
            post_submit_collection = None
        self.post_submit_collection = post_submit_collection
        if (
            post_submit_cleanup is not None
            and (
                type(post_submit_cleanup) is not PostSubmitDiagnosticCleanup
                or operation not in {
                    "desktop", "desktop-near-reference",
                    "diagnostic-cleanup",
                    "desktop-sign-in-persisted",
                    "desktop-sign-in-near-reference",
                }
            )
        ):
            post_submit_cleanup = None
        self.post_submit_cleanup = post_submit_cleanup
        if (
            controller_auth_result is not None
            and (
                type(controller_auth_result) is not ControllerAuthResult
                or operation not in {
                    "controller-auth-arm",
                    "diagnostic-arm",
                    "diagnostic-arm-preflight",
                    "diagnostic-arm-connect",
                    "diagnostic-arm-launch",
                    "diagnostic-arm-receive",
                    "diagnostic-arm-parse",
                    "diagnostic-arm-guest",
                    "diagnostic-cleanup",
                    "type-secret",
                    "submit",
                    "desktop", "desktop-near-reference",
                    "desktop-sign-in-persisted",
                    "desktop-sign-in-near-reference",
                }
            )
        ):
            controller_auth_result = None
        self.controller_auth_result = controller_auth_result
        if (
            controller_auth_arm_subphase is not None
            and (
                type(controller_auth_arm_subphase)
                is not ControllerAuthArmSubphase
                or (
                    operation != "controller-auth-arm"
                    # A proved-cleanup arm failure lets the GUI continue
                    # without a watcher; the later failure then carries an
                    # unavailable receipt whose only explanation is the arm
                    # subphase recorded here. Dropping it rendered attempt
                    # eight as a bare unattributed receipt.
                    and not (
                        self.controller_auth_result is not None
                        and self.controller_auth_result.collection
                        is ControllerAuthCollection.RECEIPT_UNAVAILABLE
                    )
                )
            )
        ):
            controller_auth_arm_subphase = None
        self.controller_auth_arm_subphase = controller_auth_arm_subphase
        if (
            controller_auth_receive_observation is not None
            and (
                type(controller_auth_receive_observation)
                is not ControllerAuthReceiveObservation
                or controller_auth_arm_subphase
                is not ControllerAuthArmSubphase.RECEIVE
            )
        ):
            controller_auth_receive_observation = None
        if (
            controller_auth_arm_subphase
            is ControllerAuthArmSubphase.RECEIVE
            and controller_auth_receive_observation is None
        ):
            controller_auth_arm_subphase = None
            self.controller_auth_arm_subphase = None
        self.controller_auth_receive_observation = (
            controller_auth_receive_observation)
        super().__init__(
            f"post-join local reauthentication failed at {operation}")


@dataclass(repr=False)
class IdentityOperations:
    """Secret-owning operations supplied by the native runner adapter."""

    start_switch: Callable[[], None]
    start_controller: Callable[[], None]
    start_windows: Callable[[], None]
    authenticate_qmp: Callable[[], None]
    rotate_local_credential: Callable[[], None]
    destroy_private_publication: Callable[[], None]
    stage_controller_principals: Callable[[], None]
    run_acceptance_phases: Callable[[], None]
    destroy_controller_principals: Callable[[], None]
    stop_windows: Callable[[], None]
    stop_controller: Callable[[], None]
    stop_switch: Callable[[], None]

    def __repr__(self) -> str:
        return "IdentityOperations(<private callbacks>)"


@dataclass
class IdentityReceipt:
    """Secret-free lifecycle facts retained by the caller."""

    phases: list[str] = field(default_factory=list)
    local_credential_rotated: bool = False
    private_publication_destroyed: bool = False
    controller_principals_staged: bool = False
    controller_principals_destroyed: bool = False
    acceptance_complete: bool = False
    teardown_complete: bool = False


class NativeProcessBoundary:
    """Own the isolated switch, disposable Controller, Windows VM, and QMP."""

    def __init__(self, attempt: Path, controller_state: Path) -> None:
        self.attempt = Path(attempt).absolute()
        self.controller_state = Path(controller_state).absolute()
        self.runtime = self.attempt / "runtime"
        self.processes: dict[str, subprocess.Popen[bytes]] = {}
        self.controller_overlay: DisposableBootDisk | None = None
        self.qmp: QmpClient | None = None
        self.qmp_root: Path | None = None
        self.serial_socket: Path | None = None
        self.port: int | None = None
        self.authorized_command: list[str] | None = None
        self.control_iso_identity: tuple[int, int] | None = None
        self.control_iso_fd: int | None = None
        self.control_iso_sha256: str | None = None
        self.gateway_switch_generation: int | None = None
        self.windows_switch_generation: int | None = None
        self.suspended_processes: set[str] = set()
        self.dependency_endpoints: dict[str, tuple[str, int]] = {}
        self.controller_console: SerialAutomation | None = None
        self.controller_factory_bundle: FactoryBundle | None = None
        self.controller_qmp: QmpClient | None = None
        self.controller_qmp_root: Path | None = None
        self.controller_factory_fd: int | None = None
        self.attempt_claim: object | None = None
        self.ownership_close_failed = False

    @staticmethod
    def _normalized_command(command: list[str]) -> list[str]:
        normalized = []
        for value in command:
            if value.startswith("unix:") and value.endswith(
                    ",server=on,wait=off"):
                normalized.append("unix:<PRIVATE-QMP>,server=on,wait=off")
            elif re.fullmatch(
                    r"socket,id=telosidentity,path=[^,]+,"
                    r"server=on,wait=off", value):
                normalized.append(
                    "socket,id=telosidentity,path=<PRIVATE-SERIAL>,"
                    "server=on,wait=off")
            elif re.fullmatch(
                    r"socket,id=factory,connect=127\.0\.0\.1:"
                    r"[1-9][0-9]{0,4}", value):
                normalized.append(
                    "socket,id=factory,connect=127.0.0.1:<PORT>")
            else:
                normalized.append(value)
        return normalized

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _sha256_fd(descriptor: int) -> str:
        digest = hashlib.sha256()
        offset = 0
        while True:
            block = os.pread(descriptor, 1024 * 1024, offset)
            if not block:
                return digest.hexdigest()
            digest.update(block)
            offset += len(block)

    @staticmethod
    def _process_holds_inode(
        pid: int, *, device: int, inode: int,
    ) -> bool:
        for entry in Path(f"/proc/{pid}/fd").iterdir():
            try:
                opened = entry.stat()
            except FileNotFoundError:
                continue
            if opened.st_dev == device and opened.st_ino == inode:
                return True
        return False

    def _wait_for_process_inode(
        self,
        process: subprocess.Popen[bytes],
        *,
        device: int,
        inode: int,
        artifact: str = "authorized control ISO",
        timeout: float = 10.0,
    ) -> None:
        deadline = time.monotonic() + timeout
        while True:
            if process.poll() is not None:
                raise WindowsIdentityRunError(
                    f"Windows exited before opening the {artifact}")
            if self._process_holds_inode(
                    process.pid, device=device, inode=inode):
                return
            if time.monotonic() >= deadline:
                raise WindowsIdentityRunError(
                    f"Windows did not open the {artifact} in time")
            time.sleep(0.05)

    @classmethod
    def _open_boot_artifact(
        cls, path: Path,
    ) -> tuple[int, tuple[int, int, int, int, str]]:
        try:
            descriptor = os.open(
                path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as error:
            raise WindowsIdentityRunError(
                f"boot artifact open failed: {path.name}") from error
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise WindowsIdentityRunError(
                    f"boot artifact is not regular: {path.name}")
            identity = (
                opened.st_dev, opened.st_ino, opened.st_size,
                opened.st_blocks, cls._sha256_fd(descriptor),
            )
            current = path.stat(follow_symlinks=False)
            if (
                current.st_dev != opened.st_dev
                or current.st_ino != opened.st_ino
                or not stat.S_ISREG(current.st_mode)
            ):
                raise WindowsIdentityRunError(
                    f"boot artifact identity changed: {path.name}")
            return descriptor, identity
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _prove_boot_artifact_path(
        path: Path, expected: tuple[int, int, int, int, str],
    ) -> None:
        observed = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(observed.st_mode)
            or (observed.st_dev, observed.st_ino) != expected[:2]
        ):
            raise WindowsIdentityRunError(
                f"boot artifact identity changed: {path.name}")

    @staticmethod
    def _destroy_owned_inode(fd: int, expected_path: Path) -> None:
        owned = os.fstat(fd)
        matches = []
        for entry in expected_path.parent.iterdir():
            try:
                info = entry.lstat()
            except FileNotFoundError:
                continue
            if info.st_dev == owned.st_dev and info.st_ino == owned.st_ino:
                matches.append(entry)
        if len(matches) != 1 or not stat.S_ISREG(matches[0].lstat().st_mode):
            raise WindowsIdentityRunError(
                "Controller convergence media ownership is ambiguous")
        matches[0].unlink()
        if any(
            entry.lstat().st_dev == owned.st_dev
            and entry.lstat().st_ino == owned.st_ino
            for entry in expected_path.parent.iterdir()
        ):
            raise WindowsIdentityRunError(
                "Controller convergence media destruction failed")

    def _validate(self) -> None:
        terminal = self.attempt / "terminal-teardown.json"
        if terminal.exists() or terminal.is_symlink():
            raise WindowsIdentityRunError(
                "identity attempt was already consumed")
        consumed = self.attempt / "attempt-consumed.json"
        if consumed.exists() or consumed.is_symlink():
            if (
                self.attempt_claim is None
                or not self.attempt_claim.verify(self.attempt)
            ):
                raise WindowsIdentityRunError(
                    "identity attempt was already consumed")
        if (self.attempt.is_symlink() or not self.attempt.is_dir()
                or self.attempt.stat().st_mode & 0o077):
            raise WindowsIdentityRunError(
                "identity attempt must be a private real directory")
        for name in (
                "windows.qcow2", "OVMF_VARS.fd", "authorization.json",
                "qemu-command.json"):
            item = self.attempt / name
            if item.is_symlink() or not item.is_file():
                raise WindowsIdentityRunError(
                    f"identity attempt lacks regular {name}")
            if item.stat().st_mode & 0o077:
                raise WindowsIdentityRunError(f"{name} must be mode 0600")
        control_iso = self.attempt / CONTROL_ISO_NAME
        if control_iso.is_symlink() or not control_iso.is_file():
            raise WindowsIdentityRunError(
                "identity attempt lacks regular control.iso")
        if stat.S_IMODE(control_iso.stat().st_mode) != 0o444:
            raise WindowsIdentityRunError("control.iso must be mode 0444")
        control_info = control_iso.stat()
        if self.control_iso_fd is not None:
            os.close(self.control_iso_fd)
        try:
            control_fd = os.open(
                control_iso,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as error:
            raise WindowsIdentityRunError(
                "control ISO ownership open failed") from error
        opened_control = os.fstat(control_fd)
        if (
            opened_control.st_dev != control_info.st_dev
            or opened_control.st_ino != control_info.st_ino
        ):
            os.close(control_fd)
            raise WindowsIdentityRunError(
                "control ISO identity changed during authorization")
        self.control_iso_fd = control_fd
        self.control_iso_identity = (
            opened_control.st_dev, opened_control.st_ino)
        try:
            authorization = json.loads(
                (self.attempt / "authorization.json").read_text(
                    encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise WindowsIdentityRunError(
                "identity authorization is unreadable") from error
        expected = {
            "status": "prepared",
            "external_access": False,
            "installation_media_attached": False,
            "pxe_boot_enabled": False,
        }
        if any(authorization.get(key) != value
               for key, value in expected.items()):
            raise WindowsIdentityRunError(
                "identity authorization does not preserve native isolation")
        try:
            command_document = json.loads(
                (self.attempt / "qemu-command.json").read_text(
                    encoding="utf-8"))
            command = command_document["argv"]
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
            raise WindowsIdentityRunError(
                "authorized QEMU command is unreadable") from error
        if (not isinstance(command_document, dict)
                or set(command_document) != {"schema", "argv"}
                or command_document["schema"] != 1
                or not isinstance(command, list)
                or any(not isinstance(value, str) for value in command)):
            raise WindowsIdentityRunError(
                "authorized QEMU command has an invalid schema")
        command_digest = hashlib.sha256(
            json.dumps(command, separators=(",", ":")).encode()).hexdigest()
        if authorization.get("qemu_argv_sha256") != command_digest:
            raise WindowsIdentityRunError(
                "authorized QEMU command digest does not match")
        self.authorized_command = command
        if authorization.get("controller_state") != str(
                self.controller_state.resolve()):
            raise WindowsIdentityRunError(
                "identity authorization names a different Controller state")
        overlay = authorization.get("overlay")
        firmware = authorization.get("firmware_copy")
        control_media = authorization.get("control_media")
        serial_transport = authorization.get("serial_transport")
        serial_arguments = [
            value for value in command
            if re.fullmatch(
                r"socket,id=telosidentity,path=[^,]+,"
                r"server=on,wait=off", value)
        ]
        if (
            not isinstance(overlay, dict)
            or overlay.get("path") != str(
                (self.attempt / "windows.qcow2").resolve())
            or overlay.get("format") != "qcow2"
            or not isinstance(firmware, dict)
            or firmware.get("path") != str(
                (self.attempt / "OVMF_VARS.fd").resolve())
        ):
            raise WindowsIdentityRunError(
                "identity authorization paths do not match the attempt")
        if (
            not isinstance(control_media, dict)
            or set(control_media) != {
                "path", "sha256", "read_only", "contains_secrets"}
            or control_media.get("path") != str(control_iso.resolve())
            or control_media.get("read_only") is not True
            or control_media.get("contains_secrets") is not False
            or control_media.get("sha256") != self._sha256_fd(control_fd)
        ):
            raise WindowsIdentityRunError(
                "control ISO differs from the authorized static artifact")
        self.control_iso_sha256 = control_media["sha256"]
        if (
            not isinstance(serial_transport, dict)
            or set(serial_transport) != {
                "kind", "authorized_path", "contains_secrets"}
            or serial_transport.get("kind") != "private-unix-socket-jsonl"
            or serial_transport.get("contains_secrets") is not False
            or len(serial_arguments) != 1
            or serial_transport.get("authorized_path")
            != serial_arguments[0].split(",path=", 1)[1].split(",", 1)[0]
        ):
            raise WindowsIdentityRunError(
                "serial transport differs from the authorized boundary")
        controller = paths(self.controller_state)
        if (self.controller_state.is_symlink()
                or not self.controller_state.is_dir()
                or self.controller_state.stat().st_mode & 0o077):
            raise WindowsIdentityRunError(
                "Controller state must be a private real directory")
        for key in ("disk", "vars"):
            item = controller[key]
            if item.is_symlink() or not item.is_file():
                raise WindowsIdentityRunError(
                    f"Controller {key} must be a regular file")
            if item.stat().st_mode & 0o077:
                raise WindowsIdentityRunError(
                    f"Controller {key} must be mode 0600")

    def start_switch(self) -> None:
        self._validate()
        if self.runtime.exists():
            raise WindowsIdentityRunError(
                "identity runtime already exists")
        self.runtime.mkdir(mode=0o700)
        listener = socket.socket()
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(3)
            self.port = int(listener.getsockname()[1])
            command = switch_command(
                listener.fileno(), self.runtime / "switch.jsonl",
                accept_timeout=1200, idle_timeout=3600,
                identity_mode=True)
            for role, spec in DEPENDENCIES.items():
                command.extend([
                    "--port",
                    f"{role}={bytes(spec['mac']).hex(':')}",
                ])
            self.processes["switch"] = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                pass_fds=(listener.fileno(),),
            )
        except BaseException:
            self._stop("switch")
            raise
        finally:
            listener.close()
        try:
            assert self.port is not None
            self.processes["gateway"] = subprocess.Popen(
                gateway_command(
                    self.port,
                    controller_mac=IDENTITY_CONTROLLER_MAC.hex(":"),
                    identity_mode=True,
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
            )
            self.gateway_switch_generation = wait_for_switch_port(
                self.runtime / "switch.jsonl", "gateway", GATEWAY_MAC)
        except BaseException:
            self._stop("gateway", "switch")
            raise

    def _start_dependency(self, role: str) -> None:
        """Attach one separately owned service to its pinned isolated L2 port."""
        if role in self.processes or role in self.dependency_endpoints:
            raise WindowsIdentityRunError(
                f"{role} dependency runtime already exists")
        if self.port is None:
            raise WindowsIdentityRunError("switch must start before dependency")
        spec = DEPENDENCIES[role]
        process = subprocess.Popen(
            [
                sys.executable,
                "-m", "homelab.vm.windows_identity_dependency",
                "--role", role,
                "--switch-port", str(self.port),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        self.processes[role] = process
        self.dependency_endpoints[role] = (
            str(spec["ip"]), int(spec["port"]))
        try:
            wait_for_switch_port(
                self.runtime / "switch.jsonl", role,
                bytes(DEPENDENCIES[role]["mac"]).hex(":"))
            if process.poll() is not None:
                raise WindowsIdentityRunError(
                    f"{role} dependency exited during readiness")
        except BaseException:
            try:
                self._stop(role)
            finally:
                self.dependency_endpoints.pop(role, None)
            raise

    def start_controller(self) -> None:
        if self.port is None:
            raise WindowsIdentityRunError("switch must start before Controller")
        canonical = paths(self.controller_state)
        try:
            self.controller_overlay = DisposableBootDisk(
                canonical["disk"], canonical["vars"],
                run_root=self.runtime / "controller").prepare()
            command = controller_command(
                self.controller_state,
                self.controller_overlay.disk,
                self.controller_overlay.vars,
                self.port,
                disk_format="raw",
            )
            self.controller_qmp_root = Path(tempfile.mkdtemp(
                prefix="telos-controller-qmp-"))
            self.controller_qmp_root.chmod(0o700)
            controller_qmp_path = self.controller_qmp_root / "controller.qmp"
            command.extend([
                "-qmp",
                f"unix:{controller_qmp_path},server=on,wait=off",
                "-device", "virtio-scsi-pci,id=identityfactorybus",
            ])
            nonce = secrets.token_hex(32)
            media_root = self.runtime / "controller-media"
            media_root.mkdir(mode=0o700)
            factory_bundle = FactoryBundle(
                Path(__file__).resolve().parents[2],
                media_root / "controller-convergence.iso",
                authorization_nonce=nonce,
            )
            self.controller_factory_bundle = factory_bundle
            process = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
            self.processes["controller"] = process
            audit_live_process(
                process.pid, "controller",
                disposable_disk=self.controller_overlay.disk,
                disposable_vars=self.controller_overlay.vars,
                forbidden_paths=(canonical["disk"], canonical["vars"]),
                qmp_socket=controller_qmp_path,
            )
            if process.stdout is None or process.stdin is None:
                raise WindowsIdentityRunError(
                    "Controller serial console is unavailable")
            password = (
                "Synthetic-Controller-" + secrets.token_urlsafe(24) + "-47!"
            ).encode("ascii")
            console = SerialAutomation(
                process.stdout, process.stdin, password, timeout=120.0)
            try:
                console.establish_disposable_controller_session()
            except SerialAutomationError as error:
                console.release_password()
                raise WindowsIdentityRunError(
                    "Controller session initialization failed") from error
            self.controller_console = console
            wait_for_switch_port(
                self.runtime / "switch.jsonl", "controller",
                IDENTITY_CONTROLLER_MAC.hex(":"))
            deadline = time.monotonic() + 30.0
            while True:
                try:
                    self.controller_qmp = QmpClient.connect(
                        controller_qmp_path, timeout=5.0,
                        expected_peer_pid=process.pid)
                    break
                except (OSError, RuntimeError):
                    if time.monotonic() >= deadline:
                        raise WindowsIdentityRunError(
                            "Controller QMP authentication failed")
                    time.sleep(0.1)
            seed_iso = (
                Path(__file__).resolve().parents[2] / DEFAULT_SEED_ISO)
            if (
                seed_iso.is_symlink()
                or not seed_iso.is_file()
                or seed_iso.stat().st_mode & 0o022
            ):
                raise WindowsIdentityRunError(
                    "Controller seed media has an unsafe identity")
            seed_fd = os.open(
                seed_iso, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                seed_stat = os.fstat(seed_fd)
                if (
                    not stat.S_ISREG(seed_stat.st_mode)
                    or seed_stat.st_mode & 0o022
                ):
                    raise WindowsIdentityRunError(
                        "opened Controller seed media is unsafe")
                assert self.controller_qmp is not None
                self.controller_qmp.execute("blockdev-add", {
                    "node-name": "identityseedfile",
                    "driver": "file",
                    "filename": str(seed_iso),
                })
                self.controller_qmp.execute("blockdev-add", {
                    "node-name": "identityseednode",
                    "driver": "raw",
                    "read-only": True,
                    "file": "identityseedfile",
                })
                if not self._process_holds_inode(
                    process.pid,
                    device=seed_stat.st_dev,
                    inode=seed_stat.st_ino,
                ):
                    raise WindowsIdentityRunError(
                        "Controller seed media identity differs from audit")
                self.controller_qmp.execute("device_add", {
                    "driver": "scsi-cd",
                    "id": "identityseedcd",
                    "drive": "identityseednode",
                    "bus": "identityfactorybus.0",
                })
                console.install_offline_controller_dependencies()
                self.controller_qmp.execute(
                    "device_del", {"id": "identityseedcd"})
                self.controller_qmp.await_device_deleted(
                    "identityseedcd", timeout=30.0)
                self.controller_qmp.execute(
                    "blockdev-del", {"node-name": "identityseednode"})
                self.controller_qmp.execute(
                    "blockdev-del", {"node-name": "identityseedfile"})
                if self._process_holds_inode(
                    process.pid,
                    device=seed_stat.st_dev,
                    inode=seed_stat.st_ino,
                ):
                    raise WindowsIdentityRunError(
                        "Controller retained seed media")
            finally:
                os.close(seed_fd)
            factory_bundle.build()
            media_fd = os.open(
                factory_bundle.output,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            self.controller_factory_fd = media_fd
            media_stat = os.fstat(media_fd)
            assert self.controller_qmp is not None
            self.controller_qmp.execute("blockdev-add", {
                    "node-name": "identityfactoryfile",
                    "driver": "file",
                    "filename": str(factory_bundle.output.resolve()),
            })
            self.controller_qmp.execute("blockdev-add", {
                    "node-name": "identityfactorynode",
                    "driver": "raw",
                    "read-only": True,
                    "file": "identityfactoryfile",
            })
            if not self._process_holds_inode(
                process.pid,
                device=media_stat.st_dev,
                inode=media_stat.st_ino,
            ):
                raise WindowsIdentityRunError(
                    "Controller convergence media identity differs from audit")
            self.controller_qmp.execute("device_add", {
                    "driver": "scsi-cd",
                    "id": "identityfactorycd",
                    "drive": "identityfactorynode",
                    "bus": "identityfactorybus.0",
            })
            self._converge_controller(
                console, FactoryBundle.guest_command(nonce))
            self.controller_qmp.execute(
                "device_del", {"id": "identityfactorycd"})
            self.controller_qmp.await_device_deleted(
                "identityfactorycd", timeout=30.0)
            self.controller_qmp.execute(
                "blockdev-del", {"node-name": "identityfactorynode"})
            self.controller_qmp.execute(
                "blockdev-del", {"node-name": "identityfactoryfile"})
            if self._process_holds_inode(
                process.pid,
                device=media_stat.st_dev,
                inode=media_stat.st_ino,
            ):
                raise WindowsIdentityRunError(
                    "Controller retained convergence media")
            self._destroy_owned_inode(media_fd, factory_bundle.output)
            os.close(media_fd)
            self.controller_factory_fd = None
            factory_bundle.password = ""
            self.controller_factory_bundle = None
            media_root.rmdir()
        except BaseException:
            self.stop_controller()
            raise

    @staticmethod
    def _converge_controller(
        console: SerialAutomation, guest_command: str,
    ) -> None:
        """Converge while retaining only the last allowlisted public phase."""
        diagnostic: IdentityFailureDiagnostic | None = None
        try:
            console.converge_disposable_controller(guest_command)
        except SerialAutomationError:
            prefix = "controller-convergence-stage-"
            phase = next(
                (
                    event.removeprefix(prefix)
                    for event in reversed(console.events)
                    if event.startswith(prefix)
                ),
                "",
            )
            diagnostic = IdentityFailureDiagnostic.controller_convergence(
                phase, "SerialAutomationError")
        if diagnostic is not None:
            raise WindowsIdentityRunError(
                "Controller convergence failed",
                diagnostic=diagnostic,
            ) from None

    def start_windows(self) -> None:
        if self.port is None:
            raise WindowsIdentityRunError("switch must start before Windows")
        if self.qmp_root is not None:
            raise WindowsIdentityRunError(
                "Windows QMP runtime is already allocated")
        overlay = self.attempt / "windows.qcow2"
        firmware = self.attempt / "OVMF_VARS.fd"
        overlay_fd, pristine = self._open_boot_artifact(overlay)
        try:
            firmware_fd, firmware_identity = self._open_boot_artifact(
                firmware)
        except BaseException:
            os.close(overlay_fd)
            raise
        firmware_before = firmware_identity[4]
        try:
            for boot_attempt in (1, 2):
                evidence = self.runtime / "switch.jsonl"
                cursor = capture_switch_evidence_cursor(evidence)
                self.windows_switch_generation = None
                self._allocate_windows_qmp_runtime()
                command = self._authorized_windows_command()
                process = self._spawn_windows_process(
                    command, append_log=boot_attempt == 2,
                    boot_artifacts=(
                        ("authorized Windows overlay", pristine[:2]),
                        ("authorized OVMF variables", firmware_identity[:2]),
                    ))
                try:
                    self._wait_for_windows_os_readiness(cursor, process)
                except RuntimeError:
                    boot_diagnostic = self._collect_boot_failure_diagnostic(
                        process, pristine)
                    self._stop("windows")
                    boot_diagnostic["overlay_pristine_after_reap"] = (
                        self._overlay_is_pristine(
                            overlay_fd, overlay, pristine))
                    self._prove_boot_artifact_path(
                        firmware, firmware_identity)
                    disconnect_error: BaseException | None = None
                    if self.windows_switch_generation is not None:
                        try:
                            wait_for_switch_disconnect(
                                evidence, "workstation", MACS["client"],
                                self.windows_switch_generation, after=cursor)
                        except BaseException as error:
                            disconnect_error = error
                    boot_diagnostic["switch_disconnect_proven"] = (
                        self.windows_switch_generation is None
                        or disconnect_error is None
                    )
                    retry_eligible = (
                        boot_attempt == 1
                        and disconnect_error is None
                        and self._boot_retry_is_eligible(
                            boot_diagnostic)
                    )
                    self._record_windows_boot_retry(
                        boot_attempt,
                        boot_diagnostic,
                        firmware_before,
                        firmware_fd,
                        firmware_identity,
                        retry_eligible=retry_eligible,
                    )
                    if disconnect_error is not None:
                        raise WindowsIdentityRunError(
                            "Windows switch disconnect proof failed",
                            diagnostic=IdentityFailureDiagnostic.guest_boot(
                                "switch-disconnect-proof",
                                type(disconnect_error).__name__,
                                retried=boot_attempt == 2,
                            ),
                        ) from disconnect_error
                    if not retry_eligible:
                        raise WindowsIdentityRunError(
                            "Windows OS readiness failed after bounded retry",
                            diagnostic=IdentityFailureDiagnostic.guest_boot(
                                "os-readiness",
                                "WindowsIdentityRunError",
                                retried=boot_attempt == 2,
                            ),
                        ) from None
                    self._reopen_control_iso_for_retry(process)
                    self._cleanup_qmp_root()
                    continue
                break
            os.close(self.control_iso_fd)
            self.control_iso_fd = None
            self._start_dependency("update-source")
            self._start_dependency("optional-storage")
        except BaseException as start_error:
            try:
                self.stop_windows()
            except BaseException:
                raise WindowsIdentityRunError(
                    "Windows startup failed and teardown also failed"
                ) from start_error
            raise
        finally:
            os.close(firmware_fd)
            os.close(overlay_fd)

    def _allocate_windows_qmp_runtime(self) -> None:
        if self.qmp_root is not None:
            raise WindowsIdentityRunError(
                "Windows QMP runtime is already allocated")
        self.qmp_root = Path(tempfile.mkdtemp(
            prefix="telos-win-id-qmp-"))
        self.qmp_root.chmod(0o700)
        self.serial_socket = self.qmp_root / "windows.serial"

    def _authorized_windows_command(self) -> list[str]:
        assert self.qmp_root is not None
        assert self.serial_socket is not None
        try:
            command = qemu_identity_command(
                disk=self.attempt / "windows.qcow2",
                variables=self.attempt / "OVMF_VARS.fd",
                qmp_socket=self.qmp_root / "windows.qmp",
                serial_socket=self.serial_socket,
                switch_port=self.port,
                control_iso=self.attempt / CONTROL_ISO_NAME,
            )
        except BaseException:
            self._cleanup_qmp_root()
            raise
        if (
            self.authorized_command is None
            or self._normalized_command(command)
            != self._normalized_command(self.authorized_command)
        ):
            self._cleanup_qmp_root()
            raise WindowsIdentityRunError(
                "runtime QEMU command differs from the authorized template")
        return command

    def _spawn_windows_process(
        self,
        command: list[str],
        *,
        append_log: bool,
        boot_artifacts: tuple[
            tuple[str, tuple[int, int]], ...,
        ] = (),
    ) -> subprocess.Popen[bytes]:
        qemu_log = self.runtime / "windows-qemu.log"
        with qemu_log.open("ab" if append_log else "xb") as output:
            qemu_log.chmod(0o600)
            process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.STDOUT)
        self.processes["windows"] = process
        chardevs = (
            (command[command.index("-chardev") + 1],)
            if "-chardev" in command else ()
        )
        audit_live_process(
            process.pid, "client", allowed_nic_models=("e1000e",),
            allowed_chardevs=chardevs)
        if self.control_iso_identity is None:
            raise WindowsIdentityRunError(
                "authorized control ISO ownership is unavailable")
        self._wait_for_process_inode(
            process,
            device=self.control_iso_identity[0],
            inode=self.control_iso_identity[1],
        )
        for artifact, identity in boot_artifacts:
            self._wait_for_process_inode(
                process,
                device=identity[0],
                inode=identity[1],
                artifact=artifact,
            )
        return process

    def reboot_and_await_readiness(self) -> None:
        """Hard-reset the running guest and wait until it has rebooted.

        The fault-restore step reboots Windows so the machine secure channel,
        which Netlogon dropped during the controller outage, re-establishes on
        boot. The operator probe runs UAC-filtered (non-elevated) and cannot
        actively reset the channel, and a plain Test-ComputerSecureChannel
        query does not re-establish it; a reboot restores it unconditionally.
        `system_reset` keeps the same QEMU process, so the guest drops its
        switch connection and reconnects -- the existing OS-readiness signal
        (a fresh switch port plus a DHCP transaction) is the boot-completion
        proof, exactly as at first boot.
        """
        process = self.processes.get("windows")
        if self.qmp is None or process is None:
            raise WindowsIdentityRunError(
                "guest reboot requires a running Windows QEMU and QMP session")
        evidence = self.runtime / "switch.jsonl"
        cursor = capture_switch_evidence_cursor(evidence)
        self.windows_switch_generation = None
        self.qmp.execute("system_reset")
        self._wait_for_windows_os_readiness(cursor, process)

    def _wait_for_windows_os_readiness(
        self, cursor: SwitchEvidenceCursor,
        process: "subprocess.Popen[bytes] | None" = None,
    ) -> None:
        evidence = self.runtime / "switch.jsonl"
        deadline = time.monotonic() + WINDOWS_OS_READINESS_TIMEOUT
        abort = self._windows_boot_abort_reason(evidence, cursor, process)
        self.windows_switch_generation = wait_for_switch_port(
            evidence, "workstation", MACS["client"],
            timeout=max(0.0, deadline - time.monotonic()), after=cursor,
            abort=abort)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Windows OS readiness deadline expired")
        wait_for_plain_dhcp_transaction(
            evidence, "workstation", MACS["client"], timeout=remaining,
            after=cursor, generation=self.windows_switch_generation,
            gateway_generation=self.gateway_switch_generation, abort=abort)

    @staticmethod
    def _windows_boot_abort_reason(
        evidence: Path,
        cursor: SwitchEvidenceCursor,
        process: "subprocess.Popen[bytes] | None",
    ):
        """Detect a boot that can no longer succeed instead of waiting it out.

        A guest whose QEMU has exited, or whose switch connection was
        abandoned before authentication, will never produce the port and DHCP
        events the readiness wait is polling for; attempt 4 spent its full
        two-boot 600-second budget on exactly that. Both signals are terminal
        for the current boot only — the caller's retry policy is unchanged.
        """
        last_scan = [float("-inf")]

        def reason() -> str | None:
            if process is not None and process.poll() is not None:
                return (
                    "Windows guest exited during boot with code "
                    f"{process.returncode}")
            now = time.monotonic()
            if now - last_scan[0] < 1.0:
                return None
            last_scan[0] = now
            try:
                events = _switch_events_after(evidence, cursor)
            except FileNotFoundError:
                return None
            for event in events:
                if event.get("event") == (
                        "peer-abandoned-before-authentication"):
                    return (
                        "Windows guest abandoned the switch before "
                        "authentication")
            return None

        return reason

    @staticmethod
    def _prove_pristine_overlay(
        descriptor: int,
        overlay: Path,
        expected: tuple[int, int, int, int, str],
    ) -> None:
        info = os.fstat(descriptor)
        observed = (
            info.st_dev, info.st_ino, info.st_size, info.st_blocks,
            NativeProcessBoundary._sha256_fd(descriptor),
        )
        if observed != expected:
            raise WindowsIdentityRunError(
                "Windows overlay changed before OS readiness")
        NativeProcessBoundary._prove_boot_artifact_path(overlay, expected)

    @staticmethod
    def _overlay_is_pristine(
        descriptor: int,
        overlay: Path,
        expected: tuple[int, int, int, int, str],
    ) -> bool:
        try:
            NativeProcessBoundary._prove_pristine_overlay(
                descriptor, overlay, expected)
        except (OSError, WindowsIdentityRunError):
            return False
        return True

    def _connect_boot_diagnostic_qmp(
        self, process: subprocess.Popen[bytes],
    ) -> QmpClient:
        assert self.qmp_root is not None
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise WindowsIdentityRunError(
                    "Windows exited before boot diagnostics")
            try:
                return QmpClient.connect(
                    self.qmp_root / "windows.qmp", timeout=1.0,
                    expected_peer_pid=process.pid)
            except OSError:
                time.sleep(0.05)
        raise WindowsIdentityRunError(
            "Windows boot diagnostics were unavailable")

    def _collect_boot_failure_diagnostic(
        self,
        process: subprocess.Popen[bytes],
        expected: tuple[int, int, int, int, str],
    ) -> dict[str, int | str | bool]:
        qmp = self._connect_boot_diagnostic_qmp(process)
        try:
            records = qmp.execute("query-blockstats")
        finally:
            qmp.close()
        if not isinstance(records, list):
            raise WindowsIdentityRunError(
                "Windows boot block statistics are invalid")
        selected = [
            record for record in records
            if isinstance(record, dict) and record.get("device") == "osdisk"
        ]
        if len(selected) != 1 or not isinstance(
                selected[0].get("stats"), dict):
            raise WindowsIdentityRunError(
                "Windows OS disk statistics are unavailable")
        statistics = selected[0]["stats"]
        counters = (
            statistics.get("rd_bytes"),
            statistics.get("rd_operations"),
            statistics.get("wr_bytes"),
            statistics.get("wr_operations"),
        )
        if any(type(value) is not int or value < 0 for value in counters):
            raise WindowsIdentityRunError(
                "Windows boot block statistics are invalid")
        if counters[2:] != (0, 0):
            reason = "osdisk-written-without-os-readiness"
        elif counters[:2] == (0, 0):
            reason = "firmware-did-not-read-osdisk"
        else:
            reason = "osdisk-read-without-os-readiness"
        return {
            "reason": reason,
            "qmp_rd_bytes": counters[0],
            "qmp_rd_operations": counters[1],
            "qmp_wr_bytes": counters[2],
            "qmp_wr_operations": counters[3],
            "overlay_blocks": expected[3],
        }

    def _boot_retry_is_eligible(
        self,
        diagnostic: Mapping[str, int | str | bool],
    ) -> bool:
        if (
            diagnostic.get("qmp_wr_bytes") != 0
            or diagnostic.get("qmp_wr_operations") != 0
            or diagnostic.get("overlay_pristine_after_reap") is not True
        ):
            return False
        return True

    def _reopen_control_iso_for_retry(
        self, reaped_process: subprocess.Popen[bytes],
    ) -> None:
        if (
            self.control_iso_fd is None
            or self.control_iso_identity is None
            or self.control_iso_sha256 is None
        ):
            raise WindowsIdentityRunError(
                "control ISO ownership was lost before boot retry")
        if reaped_process.poll() is None:
            raise WindowsIdentityRunError(
                "Windows was not reaped before control ISO reopen")
        os.close(self.control_iso_fd)
        self.control_iso_fd = None
        try:
            descriptor = os.open(
                self.attempt / CONTROL_ISO_NAME,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError as error:
            raise WindowsIdentityRunError(
                "control ISO reopen failed before boot retry") from error
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev,
                opened.st_ino,
            ) != self.control_iso_identity:
                raise WindowsIdentityRunError(
                    "control ISO identity changed before boot retry")
            if self._sha256_fd(descriptor) != self.control_iso_sha256:
                raise WindowsIdentityRunError(
                    "control ISO hash changed before boot retry")
        except BaseException:
            os.close(descriptor)
            raise
        self.control_iso_fd = descriptor

    def _record_windows_boot_retry(
        self,
        boot_attempt: int,
        diagnostic: Mapping[str, int | str | bool],
        firmware_before: str,
        firmware_fd: int | None = None,
        firmware_identity: tuple[int, int, int, int, str] | None = None,
        *,
        retry_eligible: bool,
    ) -> None:
        if boot_attempt not in (1, 2):
            raise WindowsIdentityRunError(
                "Windows boot attempt diagnostic index is invalid")
        if firmware_fd is None or firmware_identity is None:
            firmware_after = self._sha256(
                self.attempt / "OVMF_VARS.fd")
        else:
            self._prove_boot_artifact_path(
                self.attempt / "OVMF_VARS.fd", firmware_identity)
            firmware_after = self._sha256_fd(firmware_fd)
        output = self.runtime / (
            f"windows-boot-attempt-{boot_attempt}.json")
        document = json.dumps({
            "schema_version": 1,
            "event": "windows-boot-readiness-timeout",
            "boot_attempt": boot_attempt,
            **diagnostic,
            "firmware_sha256_before": firmware_before,
            "firmware_sha256_after": firmware_after,
            "firmware_mutation_retained": True,
            "retry_eligible": retry_eligible,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        flags = (
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            | os.O_NOFOLLOW
        )
        try:
            descriptor = os.open(output, flags, 0o600)
        except OSError as error:
            raise WindowsIdentityRunError(
                "Windows boot diagnostic creation failed") from error
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(document):
                written = os.write(descriptor, document[offset:])
                if written <= 0:
                    raise OSError("Windows boot diagnostic write stalled")
                offset += written
            os.fsync(descriptor)
        except BaseException as error:
            raise WindowsIdentityRunError(
                "Windows boot diagnostic write failed") from error
        finally:
            os.close(descriptor)
        try:
            directory = os.open(
                self.runtime,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError as error:
            raise WindowsIdentityRunError(
                "Windows boot diagnostic directory open failed") from error
        try:
            os.fsync(directory)
        except OSError as error:
            raise WindowsIdentityRunError(
                "Windows boot diagnostic directory sync failed") from error
        finally:
            os.close(directory)

    def authenticate_qmp(self) -> None:
        if "windows" not in self.processes:
            raise WindowsIdentityRunError("Windows must start before QMP")
        deadline = time.monotonic() + 30
        error: OSError | None = None
        while time.monotonic() < deadline:
            if self.processes["windows"].poll() is not None:
                raise WindowsIdentityRunError(
                    "Windows exited before QMP authentication")
            try:
                if self.qmp_root is None:
                    raise WindowsIdentityRunError(
                        "Windows QMP runtime is unavailable")
                self.qmp = QmpClient.connect(
                    self.qmp_root / "windows.qmp", timeout=2,
                    expected_peer_pid=self.processes["windows"].pid)
                setattr(
                    self.qmp, "qemu_pid",
                    self.processes["windows"].pid)
                return
            except OSError as caught:
                error = caught
                time.sleep(0.1)
        raise WindowsIdentityRunError(
            "timed out authenticating Windows QMP") from error

    def _stop(self, *roles: str) -> None:
        resume_failures = []
        for role in roles:
            if role not in self.suspended_processes:
                continue
            process = self.processes.get(role)
            if process is not None and process.poll() is not None:
                # A dead child cannot remain suspended. Drop only the stale
                # availability state and continue through normal reap/removal.
                self.suspended_processes.remove(role)
                continue
            try:
                self._set_process_available(role, True)
            except BaseException as error:
                resume_failures.append(
                    f"{role} resume before teardown: {type(error).__name__}")
        selected = [
            (role, self.processes[role]) for role in roles
            if role in self.processes
        ]
        children = [process for _, process in selected]
        failures = terminate_children(children)
        teardown_failures = resume_failures + failures
        for role, process in selected:
            if process.poll() is None:
                teardown_failures.append(
                    f"{role} process remained live after teardown")
            else:
                self.processes.pop(role, None)
                self.suspended_processes.discard(role)
        if teardown_failures:
            raise WindowsIdentityRunError("; ".join(teardown_failures))

    def _set_process_available(self, role: str, available: bool) -> None:
        """Suspend or resume one separately owned dependency process.

        SIGSTOP/SIGCONT provide a host-enforced, reversible outage without
        changing the isolated switch, guest disks, or dependency state.  A
        dependency must have its own live process: aliases would make the
        individual and combined fault phases indistinguishable.
        """
        if not isinstance(available, bool):
            raise WindowsIdentityRunError(
                f"{role} dependency availability must be boolean")
        process = self.processes.get(role)
        if process is None:
            raise WindowsIdentityRunError(
                f"{role} dependency has no separately owned process")
        if process.poll() is not None:
            raise WindowsIdentityRunError(
                f"{role} dependency process is not live")
        is_suspended = role in self.suspended_processes
        if available == (not is_suspended):
            raise WindowsIdentityRunError(
                f"{role} dependency is already "
                f"{'available' if available else 'offline'}")
        os.kill(process.pid, signal.SIGCONT if available else signal.SIGSTOP)
        if available:
            self.suspended_processes.remove(role)
        else:
            self.suspended_processes.add(role)

    def set_controller_available(self, available: bool) -> None:
        self._set_process_available("controller", available)

    def set_gateway_available(self, available: bool) -> None:
        self._set_process_available("gateway", available)

    def set_update_source_available(self, available: bool) -> None:
        self._set_process_available("update-source", available)

    def set_optional_storage_available(self, available: bool) -> None:
        self._set_process_available("optional-storage", available)

    def _cleanup_qmp_root(self) -> None:
        if self.qmp_root is None:
            return
        if (self.qmp_root.is_symlink() or not self.qmp_root.is_dir()
                or self.qmp_root.stat().st_mode & 0o077):
            raise WindowsIdentityRunError(
                "private QMP runtime identity changed")
        entries = list(self.qmp_root.iterdir())
        for entry in entries:
            metadata = entry.lstat()
            if entry.name not in {"windows.qmp", "windows.serial"} or not stat.S_ISSOCK(
                    metadata.st_mode):
                raise WindowsIdentityRunError(
                    "private QMP runtime contains an unexpected entry")
            entry.unlink()
        self.qmp_root.rmdir()
        self.qmp_root = None
        self.serial_socket = None

    def stop_windows(self) -> None:
        failures = []
        windows = self.processes.get("windows")
        if self.control_iso_fd is not None:
            descriptor = self.control_iso_fd
            self.control_iso_fd = None
            try:
                os.close(descriptor)
            except OSError as error:
                failures.append(
                    f"control ISO ownership: {type(error).__name__}")
        if {
            "optional-storage", "update-source"
        }.intersection(self.processes):
            try:
                self._stop("optional-storage", "update-source")
            except BaseException as error:
                failures.append(
                    f"dependency processes: {type(error).__name__}")
        if not {
            "optional-storage", "update-source"
        }.intersection(self.processes):
            self.dependency_endpoints.clear()
        if self.qmp is not None:
            try:
                self.qmp.close()
            except BaseException as error:
                failures.append(f"QMP close: {type(error).__name__}")
            else:
                self.qmp = None
        try:
            self._stop("windows")
        except BaseException as error:
            failures.append(f"Windows process: {type(error).__name__}")
        if (
            windows is not None
            and "windows" not in self.processes
            and self.control_iso_identity is not None
        ):
            try:
                retained = self._process_holds_inode(
                    windows.pid,
                    device=self.control_iso_identity[0],
                    inode=self.control_iso_identity[1],
                )
            except FileNotFoundError:
                retained = False
            if retained:
                failures.append("Windows retained control ISO inode")
        if self.qmp is None and "windows" not in self.processes:
            try:
                self._cleanup_qmp_root()
            except BaseException as error:
                failures.append(f"QMP runtime: {type(error).__name__}")
        if failures:
            raise WindowsIdentityRunError("; ".join(failures))

    def stop_controller(self) -> None:
        failures = []
        if self.controller_console is not None:
            try:
                self.controller_console.release_password()
            except BaseException as error:
                failures.append(
                    f"Controller console credential release: "
                    f"{type(error).__name__}")
            else:
                self.controller_console = None
        if self.controller_qmp is not None:
            try:
                self.controller_qmp.close()
            except BaseException as error:
                failures.append(
                    f"Controller QMP close: {type(error).__name__}")
            else:
                self.controller_qmp = None
        try:
            self._stop("controller")
        except BaseException as error:
            failures.append(f"Controller process: {type(error).__name__}")
        if "controller" not in self.processes and self.controller_factory_bundle is not None:
            try:
                if self.controller_factory_fd is not None:
                    descriptor = self.controller_factory_fd
                    self.controller_factory_fd = None
                    try:
                        self._destroy_owned_inode(
                            descriptor,
                            self.controller_factory_bundle.output,
                        )
                    finally:
                        os.close(descriptor)
                else:
                    self.controller_factory_bundle.close()
            except BaseException as error:
                failures.append(
                    f"Controller convergence media: {type(error).__name__}")
            else:
                self.controller_factory_bundle.password = ""
                self.controller_factory_bundle = None
        media_root = self.runtime / "controller-media"
        if (
            "controller" not in self.processes
            and self.controller_factory_fd is None
            and media_root.exists()
        ):
            try:
                if any(media_root.iterdir()):
                    raise WindowsIdentityRunError(
                        "Controller convergence media cleanup is unresolved")
                media_root.rmdir()
            except BaseException as error:
                failures.append(
                    f"Controller media runtime: {type(error).__name__}")
        if self.controller_overlay is not None:
            try:
                self.controller_overlay.close()
            except BaseException as error:
                failures.append(f"Controller overlay: {type(error).__name__}")
            else:
                self.controller_overlay = None
        if (
            "controller" not in self.processes
            and self.controller_qmp is None
            and self.controller_qmp_root is not None
        ):
            try:
                for entry in tuple(self.controller_qmp_root.iterdir()):
                    if entry.name != "controller.qmp" or not stat.S_ISSOCK(
                        entry.lstat().st_mode
                    ):
                        raise WindowsIdentityRunError(
                            "unexpected Controller QMP runtime entry")
                    entry.unlink()
                self.controller_qmp_root.rmdir()
            except BaseException as error:
                failures.append(
                    f"Controller QMP runtime: {type(error).__name__}")
            else:
                self.controller_qmp_root = None
        if failures:
            raise WindowsIdentityRunError("; ".join(failures))

    def stop_switch(self) -> None:
        roles = [
            role for role in (
                "optional-storage", "update-source", "gateway", "switch")
            if role in self.processes
        ]
        if roles:
            self._stop(*roles)
        if not {
            "optional-storage", "update-source"
        }.intersection(self.processes):
            self.dependency_endpoints.clear()

    def claim_attempt(self) -> None:
        """Publish and retain this boundary's exclusive claim capability."""
        if self.attempt_claim is not None:
            raise WindowsIdentityRunError(
                "identity attempt claim ownership is invalid")
        from .windows_identity_attempt import claim
        try:
            self.attempt_claim = claim(self.attempt)
        except BaseException as error:
            from .windows_identity_attempt import _ClaimPublicationError
            if isinstance(error, _ClaimPublicationError):
                self.attempt_claim = error.claim
            raise

    def terminalize_attempt(
        self, *, outcome: str, teardown: Mapping[str, bool],
    ) -> None:
        """Publish terminal state while the original claim inode stays open."""
        if self.attempt_claim is None:
            raise WindowsIdentityRunError(
                "identity attempt claim ownership is unavailable")
        from .windows_identity_attempt import terminalize
        try:
            terminalize(
                self.attempt,
                claim=self.attempt_claim,
                outcome=outcome,
                teardown=teardown,
            )
        finally:
            self.attempt_claim.close()
            self.attempt_claim = None

    def release_prestart_ownership(self) -> None:
        """Release validation-only ownership when Windows never started."""
        if "windows" in self.processes or self.control_iso_fd is None:
            return
        descriptor = self.control_iso_fd
        self.control_iso_fd = None
        try:
            os.close(descriptor)
        except OSError:
            self.ownership_close_failed = True

    def audit_teardown(self) -> dict[str, bool]:
        """Return fixed, secret-free facts derived after teardown attempts."""
        runtime_sockets = (
            tuple(self.runtime.rglob("*.qmp"))
            + tuple(self.runtime.rglob("*.serial"))
        ) if self.runtime.exists() else ()
        return {
            "processes_reaped": not self.processes
            and not self.suspended_processes,
            "qmp_closed": self.qmp is None and self.controller_qmp is None
            and self.qmp_root is None and self.controller_qmp_root is None,
            "runtime_quiescent": not runtime_sockets,
            "owned_media_closed": self.control_iso_fd is None
            and not self.ownership_close_failed
            and self.controller_console is None
            and self.controller_factory_fd is None
            and self.controller_factory_bundle is None
            and self.controller_overlay is None,
            "dependencies_released": not self.dependency_endpoints,
        }


class PrivateIdentityMaterial:
    """Own recovered and generated credentials without exposing their values."""

    def __init__(
        self,
        publication: Path,
        private_parent: Path,
        *,
        rotate_guest: Callable[[str, str], None],
        stage_principals: Callable[[dict[str, str]], None],
        destroy_principals: Callable[[tuple[str, ...]], None],
    ) -> None:
        self.recovery = RecoveredLocalCredential(
            publication, private_parent)
        self.rotate_guest = rotate_guest
        self.stage_guest_principals = stage_principals
        self.destroy_guest_principals = destroy_principals
        self._recovery_context: RecoveredLocalCredential | None = None
        self._old_local: str | None = None
        self._new_local: str | None = None
        self._principals: dict[str, str] = {}

    @staticmethod
    def _credential() -> str:
        # Keep interactive Windows credentials independent of input-locale
        # punctuation while retaining 128 bits of entropy and three password
        # complexity categories.
        return "T7a" + secrets.token_hex(16)

    def rotate_local_credential(self) -> None:
        if self._recovery_context is not None:
            raise WindowsIdentityRunError(
                "local credential recovery is already active")
        self._recovery_context = self.recovery
        self._old_local = self._recovery_context.__enter__()
        self._new_local = self._credential()
        try:
            self.rotate_guest(self._old_local, self._new_local)
        except BaseException:
            self.close()
            raise

    def generate_replacement_credential(self) -> str:
        """Generate and retain one replacement for a progressive rotation."""
        if self._new_local is not None:
            raise WindowsIdentityRunError(
                "replacement credential is already owned")
        self._new_local = self._credential()
        return self._new_local

    def run_scoped_acceptance(
        self,
        replacement: str,
        acceptance: Callable[[str, Mapping[str, str]], None],
    ) -> None:
        """Keep all credentials memory-owned through one acceptance callback.

        The callback receives a read-only principal mapping at runtime.  On a
        successful acceptance and principal teardown, every retained
        credential reference owned by this object is released.
        """
        if replacement is not self._new_local:
            raise WindowsIdentityRunError(
                "acceptance replacement is not the owned credential")
        if self._old_local is not None or self._recovery_context is not None:
            raise WindowsIdentityRunError(
                "recovered credential remains active during acceptance")
        self.stage_controller_principals()
        primary: BaseException | None = None
        cleanup: BaseException | None = None
        try:
            acceptance(
                self._new_local,
                MappingProxyType(self._principals),
            )
        except BaseException as error:
            primary = error
        try:
            self.destroy_controller_principals()
        except BaseException as error:
            cleanup = error
        if cleanup is None:
            self._new_local = None
        if primary is not None or cleanup is not None:
            details = []
            if primary is not None:
                details.append(f"acceptance: {type(primary).__name__}")
            if cleanup is not None:
                details.append(
                    f"principal destruction: {type(cleanup).__name__}")
            source = primary if primary is not None else cleanup
            candidate = getattr(source, "diagnostic", None)
            diagnostic = (
                candidate
                if isinstance(candidate, IdentityFailureDiagnostic)
                else None
            )
            if diagnostic is None:
                # Walk the cause/context chain: a wrapper (e.g.
                # FaultPhaseError) may not itself carry the diagnostic while
                # an inner acceptance-check failure does.
                seen = set()
                walker: BaseException | None = source
                while walker is not None and id(walker) not in seen:
                    seen.add(id(walker))
                    inner = getattr(walker, "diagnostic", None)
                    if isinstance(inner, IdentityFailureDiagnostic):
                        diagnostic = inner
                        break
                    walker = walker.__cause__ or walker.__context__
            if diagnostic is None:
                # No-bare-coordinates convention: attempt 36 rendered only
                # the wrapper type because this producer forwarded
                # diagnostic=None and the progressive sanitizer discards
                # messages. Even an untyped failure names its scope side
                # and inner exception type.
                diagnostic = IdentityFailureDiagnostic.scoped_acceptance(
                    "acceptance"
                    if primary is not None
                    else "principal-destruction",
                    type(source).__name__,
                )
            message = "scoped identity acceptance failed; " + "; ".join(details)
            if diagnostic is not None:
                message += "; " + diagnostic.render()
            raise WindowsIdentityRunError(
                message, diagnostic=diagnostic,
            ) from None

    def destroy_private_publication(self) -> None:
        if (self._recovery_context is None or self._old_local is None
                or self._new_local is None):
            raise WindowsIdentityRunError(
                "guest rotation must precede publication destruction")
        self._recovery_context.destroy_publication()
        self._old_local = None
        self._new_local = None
        self._recovery_context.__exit__(None, None, None)
        self._recovery_context = None

    def stage_controller_principals(self) -> None:
        if self._old_local is not None or self._recovery_context is not None:
            raise WindowsIdentityRunError(
                "recovered credential must be destroyed before staging")
        if self._principals:
            raise WindowsIdentityRunError(
                "Controller principals are already staged")
        self._principals = {
            name: self._credential()
            for name in ("student", "operator", "directory-admin")
        }
        try:
            self.stage_guest_principals(self._principals)
        except BaseException as stage_error:
            try:
                self.destroy_guest_principals(tuple(self._principals))
            except BaseException as destroy_error:
                raise WindowsIdentityRunError(
                    "Controller principal staging and rollback both failed: "
                    f"{type(stage_error).__name__}; "
                    f"{type(destroy_error).__name__}") from stage_error
            self._principals.clear()
            raise

    def destroy_controller_principals(self) -> None:
        names = tuple(self._principals)
        if not names:
            raise WindowsIdentityRunError(
                "Controller principals were not staged")
        self.destroy_guest_principals(names)
        self._principals.clear()

    def close(self, *, controller_destroyed: bool = False) -> None:
        self._old_local = None
        self._new_local = None
        if self._principals and not controller_destroyed:
            raise WindowsIdentityRunError(
                "Controller principal cleanup remains unresolved")
        self._principals.clear()
        if self._recovery_context is not None:
            self._recovery_context.__exit__(None, None, None)
            self._recovery_context = None


def run_lifecycle(operations: IdentityOperations) -> IdentityReceipt:
    """Run identity proof in the only ordering that may consume credentials."""
    receipt = IdentityReceipt()
    started: list[str] = []
    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []
    try:
        started.append("switch")
        operations.start_switch()
        receipt.phases.append("switch-started")
        started.append("controller")
        operations.start_controller()
        receipt.phases.append("controller-started")
        started.append("windows")
        operations.start_windows()
        receipt.phases.append("windows-started")
        operations.authenticate_qmp()
        receipt.phases.append("qmp-authenticated")
        operations.rotate_local_credential()
        receipt.local_credential_rotated = True
        receipt.phases.append("local-credential-rotated")
        operations.destroy_private_publication()
        receipt.private_publication_destroyed = True
        receipt.phases.append("private-publication-destroyed")
        operations.stage_controller_principals()
        receipt.controller_principals_staged = True
        receipt.phases.append("controller-principals-staged")
        operations.run_acceptance_phases()
        receipt.acceptance_complete = True
        receipt.phases.append("acceptance-complete")
    except BaseException as error:
        primary_error = error
    finally:
        if receipt.controller_principals_staged:
            try:
                operations.destroy_controller_principals()
                receipt.controller_principals_destroyed = True
                receipt.phases.append("controller-principals-destroyed")
            except BaseException as error:
                cleanup_errors.append(
                    f"controller principal destruction: {type(error).__name__}")
        for role, stop in (
            ("windows", operations.stop_windows),
            ("controller", operations.stop_controller),
            ("switch", operations.stop_switch),
        ):
            if role not in started:
                continue
            try:
                stop()
                receipt.phases.append(f"{role}-stopped")
            except BaseException as error:
                cleanup_errors.append(f"{role} teardown: {type(error).__name__}")
        receipt.teardown_complete = not cleanup_errors
    if primary_error is not None or cleanup_errors:
        if isinstance(primary_error, RunInterrupted) and not cleanup_errors:
            raise primary_error
        details = []
        if primary_error is not None:
            details.append(f"lifecycle: {type(primary_error).__name__}")
        details.extend(cleanup_errors)
        diagnostic = (
            primary_error.diagnostic
            if (
                isinstance(primary_error, WindowsIdentityRunError)
                and isinstance(
                    primary_error.diagnostic, IdentityFailureDiagnostic)
            )
            else None
        )
        if diagnostic is not None:
            details.append(diagnostic.render())
        raise WindowsIdentityRunError(
            "native identity lifecycle failed; " + "; ".join(details),
            diagnostic=diagnostic,
        ) from None
    required = (
        receipt.local_credential_rotated,
        receipt.private_publication_destroyed,
        receipt.controller_principals_staged,
        receipt.controller_principals_destroyed,
        receipt.acceptance_complete,
        receipt.teardown_complete,
    )
    if not all(required):
        raise WindowsIdentityRunError(
            "native identity lifecycle ended without complete destruction proof")
    return receipt
