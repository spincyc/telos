"""Bind a durable workstation run to one persistent Controller instance.

TASK-28, step 1 (``homelab/DURABLE-WORKSTATION-FLOW.md``).  Every durable step
-- the probe, the joins, the keep-verify -- starts from one binding: the
instance marker (``simulation_overlay.PersistentControllerInstance``), the
owner's permanent directory identity (``directory_identity``) and the durable
account record with its roster fingerprint (``controller_principals``).  The
binding is pure: it reads those three and refuses when they disagree with each
other or with the per-run loopback fabric.  It boots nothing.

Three refusals carry the weight:

* *realm.*  The marker's recorded realm, DNS domain and NetBIOS name must be
  the ones the overlay declares, and a workstation bundle must carry the same
  realm and pin the bootstrap FQDN -- the persistent instance IS the bootstrap
  Controller.  A mismatch joins a machine to a domain that does not exist.
* *fabric.*  The per-run gateway accepts the Controller only from one fixed
  address (``simulated_gateway.CONTROLLER_IP``) and the Windows install
  contract hard-codes it.  Parameterising the fabric is deferred, so an
  instance declaring any other address, prefix or gateway is refused.  The
  values are compared, never printed: they are instance data (ADR 0046).
* *SID.*  ``check_live_directory`` accepts the live directory only when its
  SID is the recorded one.  The single tolerated difference is a recorded
  value that is a strict prefix of the live one: the serial split-read defect
  fixed in ``05eec6e`` truncated the last sub-authority of an early
  convergence record.  That case is reported as repairable and is repaired
  only when asked; anything else is a different directory.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

# Package-relative only, like ``controller_join_material``: the one script that
# reaches this module, ``persistent_controller_session.py``, imports it as part
# of the package in both of its run modes.
from .bootstrap_dc import DEFAULT_STATE, NAME, _controller_principals, paths
from .directory_identity import (
    DirectoryIdentityError,
    directory_identity_source,
    durable_directory_identity,
)
from .directory_password_policy import (
    SAMBA_DEFAULT,
    DirectoryPasswordPolicy,
    policy_from_record,
)
from .simulated_gateway import CONTROLLER_IP, GATEWAY_IP, NETMASK
from .simulation_overlay import DOMAIN_SID, PersistentControllerInstance


#: The per-run fabric's fixed Controller addressing, read from the gateway
#: that enforces it rather than restated.
FABRIC_CONTROLLER_ADDRESS = CONTROLLER_IP
FABRIC_GATEWAY_ADDRESS = GATEWAY_IP
FABRIC_PREFIX = ipaddress.IPv4Network(f"0.0.0.0/{NETMASK}").prefixlen

#: ``check_live_directory`` outcomes.
SID_MATCH = "match"
SID_REPAIR = "repair"


class DurableBindingError(RuntimeError):
    """A durable run cannot be bound to this persistent instance."""


@dataclass(frozen=True, repr=False)
class DurableBinding:
    """One persistent instance, proven to agree with its declarations.

    ``domain_sid`` is the value the marker RECORDS, which may be the truncated
    one ``check_live_directory`` knows how to repair.  ``password_policy`` is
    the instance's recorded directory password policy, or Samba's default when
    it records none; every host-side check of a typed password uses it.
    ``repr`` names only the instance so a binding that reaches a log cannot
    carry the realm with it.
    """

    instance: str
    state: Path
    dns_domain: str
    kerberos_realm: str
    netbios_name: str
    controller_fqdn: str
    permanent_dc_fqdn: str
    domain_sid: str
    roster_fingerprint: str
    identity_source: str
    password_policy: DirectoryPasswordPolicy = SAMBA_DEFAULT

    def __repr__(self) -> str:
        return f"DurableBinding(instance={self.instance!r})"


def require_fabric_agreement(identity: object, source: str) -> None:
    """Refuse an identity whose Controller addressing is not the fabric's."""
    try:
        declared = (
            ("network.address",
             ipaddress.IPv4Address(getattr(identity, "address")),
             FABRIC_CONTROLLER_ADDRESS),
            ("network.prefix", getattr(identity, "prefix"), FABRIC_PREFIX),
            ("network.gateway",
             ipaddress.IPv4Address(getattr(identity, "gateway")),
             FABRIC_GATEWAY_ADDRESS),
        )
    except (AttributeError, ValueError) as error:
        raise DurableBindingError(
            f"{source} declares no usable Controller addressing") from error
    mismatched = [key for key, value, fabric in declared if value != fabric]
    if mismatched:
        raise DurableBindingError(
            f"{', '.join(mismatched)} in {source} differ from the per-run "
            f"loopback fabric's fixed Controller addressing. The simulated "
            f"gateway accepts the Controller only from that address and the "
            f"Windows install contract hard-codes it; parameterising the "
            f"fabric is deferred, so this instance cannot be bound. Neither "
            f"value is printed")


def _current_roster_fingerprint(overlay_path: Path | None) -> str:
    principals = _controller_principals()
    try:
        roster = principals.durable_directory_roster(overlay_path)
        return principals.identity_roster_fingerprint(roster.roster)
    except (principals.IdentityRosterError, OSError, ValueError) as error:
        raise DurableBindingError(str(error)) from error


def durable_binding(
    root: Path,
    instance: str,
    *,
    canonical_state: Path = DEFAULT_STATE,
    identity_path: Path | None = None,
    overlay_path: Path | None = None,
    roster_fingerprint: str | None = None,
) -> DurableBinding:
    """Bind to ``root/instance`` or refuse, before anything is booted.

    *roster_fingerprint* exists for the reason ``durable_directory_roster``
    takes a path: a test must be able to bind without resolving whatever
    private roster the developer's machine carries.  Omitted, it is computed
    from the durable roster (``overlay_path``), which refuses the synthetic
    acceptance names outright.
    """
    if not PersistentControllerInstance.valid_instance_name(instance):
        raise DurableBindingError(
            "instance must be 1-32 lowercase letters, digits, or hyphens and "
            "must not start or end with a hyphen")
    state = Path(root) / instance
    target = PersistentControllerInstance(state, instance=instance)
    try:
        target.assert_separate(paths(canonical_state)["disk"])
        if not target.exists():
            raise DurableBindingError(
                f"there is no persistent controller instance {instance} at "
                f"{target.state}")
        recorded = target.convergence()
        staged = target.directory_accounts()
        password_policy = policy_from_record(
            target.directory_password_policy(), instance)
    except DurableBindingError:
        raise
    except (RuntimeError, ValueError, OSError) as error:
        raise DurableBindingError(str(error)) from error
    if recorded is None or recorded.get("domain_sid") is None:
        raise DurableBindingError(
            f"{instance} records no converged directory with a domain SID; "
            f"converge it with homelab-factory-persistent-converge first")
    if staged is None:
        raise DurableBindingError(
            f"{instance} records no staged durable account roster; stage it "
            f"with homelab-factory-persistent-accounts first")
    try:
        identity = durable_directory_identity(identity_path)
    except (DirectoryIdentityError, OSError, ValueError) as error:
        raise DurableBindingError(str(error)) from error
    source = directory_identity_source(identity.source)
    disagreeing = [
        key for key, declared in (
            ("realm", identity.kerberos_realm),
            ("dns_domain", identity.dns_domain),
            ("netbios", identity.netbios_name),
        ) if recorded.get(key) != declared
    ]
    if disagreeing:
        raise DurableBindingError(
            f"{instance}'s convergence record disagrees with {source} on "
            f"{', '.join(disagreeing)}: the instance holds a directory the "
            f"overlay does not declare. Values are not printed")
    if identity.hostname != NAME:
        raise DurableBindingError(
            f"{source} names a bootstrap controller whose host name is not "
            f"{NAME!r}; the persistent console protocol matches on it")
    require_fabric_agreement(identity, source)
    current = (roster_fingerprint if roster_fingerprint is not None
               else _current_roster_fingerprint(overlay_path))
    if staged.get("roster_fingerprint") != current:
        raise DurableBindingError(
            f"{instance}'s staged roster fingerprint is not the durable "
            f"roster's current one: the directory holds accounts the private "
            f"roster no longer declares")
    return DurableBinding(
        instance=instance,
        state=target.state,
        dns_domain=identity.dns_domain,
        kerberos_realm=identity.kerberos_realm,
        netbios_name=identity.netbios_name,
        controller_fqdn=identity.bootstrap_dc_fqdn,
        permanent_dc_fqdn=identity.permanent_dc_fqdn,
        domain_sid=recorded["domain_sid"],
        roster_fingerprint=current,
        identity_source=source,
        password_policy=password_policy,
    )


def require_durable_realm_agreement(
    bundle_realm: object, binding: DurableBinding,
) -> None:
    """Refuse a bundle realm that is not this binding's permanent realm.

    *bundle_realm* is ``workstations/arch_second.InstallerRealm`` or anything
    with its fields.  Its ``controller_fqdn`` must be the bootstrap FQDN: the
    persistent instance this flow boots is the bootstrap Controller, and a
    bundle pinning the permanent FQDN would pin a Controller that does not
    exist yet.
    """
    if getattr(bundle_realm, "durable", None) is not True:
        raise DurableBindingError(
            "the bundle was not built against the permanent realm")
    mismatched = [
        label for label, field, expected in (
            ("DNS domain", "dns_domain", binding.dns_domain),
            ("Kerberos realm", "kerberos_realm", binding.kerberos_realm),
            ("NetBIOS name", "workgroup", binding.netbios_name),
            ("domain controller (must be the bootstrap FQDN)",
             "controller_fqdn", binding.controller_fqdn),
        ) if getattr(bundle_realm, field, None) != expected
    ]
    if mismatched:
        raise DurableBindingError(
            f"the bundle's realm disagrees with persistent instance "
            f"{binding.instance} on {', '.join(mismatched)}")


def check_live_directory(recorded: str, live: str) -> str:
    """``SID_MATCH``, ``SID_REPAIR``, or a refusal naming neither value."""
    for label, value in (("recorded", recorded), ("live", live)):
        if not isinstance(value, str) or not DOMAIN_SID.fullmatch(value):
            raise DurableBindingError(
                f"the {label} domain SID is not a canonical domain SID")
    if live == recorded:
        return SID_MATCH
    if live.startswith(recorded) and live[len(recorded):].isdigit():
        return SID_REPAIR
    raise DurableBindingError(
        "the live directory's domain SID is neither the recorded one nor a "
        "completion of a truncated record: this is a different directory")


def repaired_convergence(
    record: dict, live: str, *, now: str | None = None,
) -> dict:
    """The convergence record with a truncated SID completed from the live one."""
    if check_live_directory(record.get("domain_sid"), live) != SID_REPAIR:
        raise DurableBindingError("the recorded domain SID needs no repair")
    repaired = dict(record)
    repaired["domain_sid"] = live
    repaired["domain_sid_repaired"] = {
        "repaired_utc": now or datetime.now(UTC).isoformat(),
        "reason": (
            "the recorded value was a strict prefix of the SID the live "
            "directory reported; the serial split-read defect fixed in "
            "05eec6e truncated it at convergence"),
    }
    return repaired
