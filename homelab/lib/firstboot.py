"""First-boot activation: the checks that must pass before DHCP starts.

ADR 0009 requires Controller network services to activate automatically on the
first boot after installation, and to **fail closed**: if the transition
conditions cannot be verified, DHCP stays stopped and the machine says why.

That matters more than it sounds. ADR 0010 has the operator carry a powered-off
Controller from the network it was provisioned on to the network it will serve.
If the machine is plugged into the wrong segment, or the intended NIC was swapped,
or another DHCP server is already answering there, then starting dnsmasq puts a
second DHCP authority on somebody else's network -- the exact thing ADR 0008
forbids at every stage.

So this module is a list of conditions, each of which can fail on its own, with a
message naming what to do about it. The probes are injected so the logic is
testable without a network.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Callable, Protocol

STABLE_NAME = "lan0"


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str
    remedy: str = ""


@dataclass(frozen=True)
class Activation:
    checks: list[Check]

    @property
    def may_start(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def failures(self) -> list[Check]:
        return [check for check in self.checks if not check.passed]


class Probes(Protocol):
    def interface_exists(self, name: str) -> bool: ...
    def permanent_mac(self, name: str) -> str: ...
    def has_carrier(self, name: str) -> bool: ...
    def addresses(self, name: str) -> list[str]: ...
    def dhcp_server_responds(self, name: str, timeout: float) -> bool: ...


def evaluate(probes: Probes, *, expected_mac: str, expected_address: str,
             interface: str = STABLE_NAME, dhcp_probe_seconds: float = 6.0) -> Activation:
    """Run every condition. Order matters: later checks assume earlier ones."""
    checks: list[Check] = []

    if not probes.interface_exists(interface):
        return Activation([Check(
            "interface-exists", False,
            f"{interface} does not exist on this machine",
            f"The managed interface is pinned to {expected_mac} by a systemd .link "
            f"file. If the network card was replaced, the machine must be "
            f"re-provisioned or the manifest amended deliberately.")])
    checks.append(Check("interface-exists", True, f"{interface} is present"))

    actual_mac = (probes.permanent_mac(interface) or "").lower()
    expected = (expected_mac or "").lower()
    if actual_mac != expected:
        checks.append(Check(
            "interface-identity", False,
            f"{interface} has MAC {actual_mac or 'unknown'}, expected {expected}",
            "This is not the interface this Controller was installed against. "
            "Starting DHCP here could serve a network this machine does not own."))
    else:
        checks.append(Check("interface-identity", True, f"{interface} is {actual_mac}"))

    if not probes.has_carrier(interface):
        checks.append(Check(
            "carrier", False,
            f"{interface} has no link",
            "Connect the managed interface to its switch. This is the most common "
            "cause of a fail-closed first boot after relocating the machine."))
    else:
        checks.append(Check("carrier", True, f"{interface} has link"))

    configured = probes.addresses(interface)
    if expected_address not in configured:
        checks.append(Check(
            "service-address", False,
            f"{expected_address} is not configured on {interface} "
            f"(found: {', '.join(configured) or 'none'})",
            "The static address configuration did not apply. Check the network "
            "unit before starting any service."))
    else:
        checks.append(Check("service-address", True, f"{expected_address} is configured"))

    # The check that cannot be skipped. Everything above is about this machine;
    # this one is about the network it has been plugged into.
    if probes.dhcp_server_responds(interface, dhcp_probe_seconds):
        checks.append(Check(
            "sole-dhcp-authority", False,
            f"another DHCP server answered on {interface}",
            "ADR 0008 forbids two DHCP authorities on one segment. This Controller "
            "will not start DHCP. Either this is the wrong network, or the existing "
            "server must be retired first."))
    else:
        checks.append(Check(
            "sole-dhcp-authority", True,
            f"no other DHCP server answered on {interface}"))

    return Activation(checks)


def report(activation: Activation, *, interface: str = STABLE_NAME) -> list[str]:
    """What gets written to the console and the journal."""
    rule = "=" * 72
    lines = [rule]
    lines.append("CONTROLLER NETWORK SERVICES --- FIRST BOOT" if activation.may_start
                 else "CONTROLLER NETWORK SERVICES NOT STARTED")
    lines.append(rule)
    lines.append("")
    for check in activation.checks:
        mark = "ok  " if check.passed else "FAIL"
        lines.append(f"  [{mark}] {check.name:<22} {check.detail}")
    lines.append("")

    if activation.may_start:
        lines.append("  All conditions met. Starting dnsmasq and nginx together.")
        lines.append("  This Controller is now the sole DHCP authority on this segment.")
    else:
        lines.append("  DHCP and DNS have NOT been started, deliberately (ADR 0009).")
        lines.append("")
        for check in activation.failures:
            lines.append(f"  {check.name}:")
            for line in check.remedy.split(". "):
                if line.strip():
                    lines.append(f"    {line.strip().rstrip('.')}.")
            lines.append("")
        lines.append("  Fix the above, then:  systemctl restart homelab-first-boot")
    lines.append(rule)
    return lines


# --------------------------------------------------------------------------
# The real machine
# --------------------------------------------------------------------------


class SystemProbes:
    """Reads the running machine. Never used by a unit test."""

    def __init__(self, run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> None:
        self.run = run

    def _read(self, path: str) -> str:
        try:
            with open(path) as handle:
                return handle.read().strip()
        except OSError:
            return ""

    def interface_exists(self, name: str) -> bool:
        return bool(self._read(f"/sys/class/net/{name}/address"))

    def permanent_mac(self, name: str) -> str:
        return self._read(f"/sys/class/net/{name}/address").lower()

    def has_carrier(self, name: str) -> bool:
        return self._read(f"/sys/class/net/{name}/carrier") == "1"

    def addresses(self, name: str) -> list[str]:
        result = self.run(["ip", "-4", "-brief", "addr", "show", name],
                          capture_output=True, text=True)
        found = []
        for field in (result.stdout or "").split()[2:]:
            found.append(field.split("/")[0])
        return found

    def dhcp_server_responds(self, name: str, timeout: float) -> bool:
        """Ask for a lease and see whether anything offers one.

        `dhcpcd --test` performs a DISCOVER without configuring the interface,
        so it answers exactly the question that matters -- is somebody else
        already the DHCP authority here -- without changing anything.

        A probe that errors is treated as **a server responding**, because
        failing closed is the whole point of this check. Being unable to prove
        the segment is clear is not the same as proving it is.
        """
        try:
            result = self.run(["dhcpcd", "--test", "--timeout", str(int(timeout)), name],
                              capture_output=True, text=True, timeout=timeout + 5)
        except (OSError, subprocess.TimeoutExpired):
            return True
        return result.returncode == 0
