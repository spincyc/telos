"""Ordered, fail-closed fault phases for Windows identity acceptance."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol


class FaultPhaseError(RuntimeError):
    """A dependency fault phase did not reach a restored terminal state."""


class RuntimeFaultBoundary(Protocol):
    """Native boundary required by the ordered fault driver."""

    def set_controller_available(self, available: bool) -> None: ...
    def set_gateway_available(self, available: bool) -> None: ...
    def set_update_source_available(self, available: bool) -> None: ...
    def set_optional_storage_available(self, available: bool) -> None: ...


@dataclass(frozen=True)
class FaultPhaseOperations:
    """Callbacks that inject dependency state and collect guest evidence."""

    set_controller_available: Callable[[bool], None]
    set_gateway_available: Callable[[bool], None]
    set_update_source_available: Callable[[bool], None]
    set_optional_storage_available: Callable[[bool], None]
    observe: Callable[[str], None]


@dataclass
class FaultPhaseReceipt:
    """Secret-free record of completed fault transitions and observations."""

    phases: list[str] = field(default_factory=list)
    all_dependencies_restored: bool = False


def native_fault_operations(
    boundary: RuntimeFaultBoundary,
    observe: Callable[[str], None],
) -> FaultPhaseOperations:
    """Bind the ordered driver to a real native process boundary."""
    return FaultPhaseOperations(
        set_controller_available=boundary.set_controller_available,
        set_gateway_available=boundary.set_gateway_available,
        set_update_source_available=boundary.set_update_source_available,
        set_optional_storage_available=boundary.set_optional_storage_available,
        observe=observe,
    )


_SETTERS = {
    "controller": "set_controller_available",
    "gateway": "set_gateway_available",
    "update-source": "set_update_source_available",
    "optional-storage": "set_optional_storage_available",
}


class _Driver:
    def __init__(self, operations: FaultPhaseOperations) -> None:
        self.operations = operations
        self.receipt = FaultPhaseReceipt()
        self.offline: list[str] = []
        self.uncertain_restoration: str | None = None

    def _setter(self, dependency: str) -> Callable[[bool], None]:
        return getattr(self.operations, _SETTERS[dependency])

    def disable(self, dependency: str) -> None:
        if dependency in self.offline:
            raise FaultPhaseError(f"{dependency} is already offline")
        self._setter(dependency)(False)
        self.offline.append(dependency)
        self.receipt.phases.append(f"{dependency}-disabled")

    def restore(self, dependency: str) -> None:
        if not self.offline or self.offline[-1] != dependency:
            raise FaultPhaseError(
                f"{dependency} restoration violates reverse fault order")
        try:
            self._setter(dependency)(True)
        except BaseException:
            self.uncertain_restoration = dependency
            raise
        self.offline.pop()
        self.receipt.phases.append(f"{dependency}-restored")

    def observe(self, check: str) -> None:
        self.operations.observe(check)
        self.receipt.phases.append(check)

    def cleanup(self) -> list[str]:
        failures: list[str] = []
        while self.offline:
            dependency = self.offline[-1]
            if self.uncertain_restoration == dependency:
                failures.append(
                    f"{dependency} restoration state is uncertain")
                break
            try:
                self.restore(dependency)
            except BaseException as error:
                failures.append(
                    f"{dependency} restoration: {type(error).__name__}")
                # Do not retry an arbitrary state-changing callback. Retain
                # the dependency in ``offline`` so the receipt cannot claim a
                # restored terminal state.
                break
        return failures


def run_fault_phases(
    operations: FaultPhaseOperations,
) -> FaultPhaseReceipt:
    """Inject required outages, prove them, and restore in safe order.

    A failed transition or observation prevents every subsequent acceptance
    phase. Dependencies already taken offline are restored in reverse order
    before the failure is reported.
    """
    driver = _Driver(operations)
    primary: BaseException | None = None
    cleanup_failures: list[str] = []
    try:
        driver.disable("controller")
        for check in (
            "controller-offline",
            "windows-cached-login",
            "windows-cached-admin-login",
            "windows-uncached-denied",
            "windows-local-rescue",
        ):
            driver.observe(check)
        driver.restore("controller")
        driver.observe("controller-restored")
        driver.observe("windows-secure-channel-restored")

        driver.disable("gateway")
        driver.observe("gateway-offline")
        driver.restore("gateway")

        driver.disable("update-source")
        driver.observe("update-source-offline")
        driver.restore("update-source")

        driver.disable("optional-storage")
        driver.observe("optional-storage-offline")
        driver.restore("optional-storage")

        driver.disable("controller")
        driver.observe("ad-dns-offline")
        driver.disable("gateway")
        driver.disable("update-source")
        driver.disable("optional-storage")
        driver.observe("combined-dependencies-offline")
        driver.restore("optional-storage")
        driver.restore("update-source")
        driver.restore("gateway")
        driver.restore("controller")
        driver.observe("windows-services-restored")
    except BaseException as error:
        primary = error
    finally:
        cleanup_failures = driver.cleanup()

    driver.receipt.all_dependencies_restored = not driver.offline
    if primary is not None or cleanup_failures:
        details = []
        if primary is not None:
            details.append(f"phase: {type(primary).__name__}")
        details.extend(cleanup_failures)
        raise FaultPhaseError(
            "Windows identity fault phases failed; " + "; ".join(details)
        ) from primary
    if not driver.receipt.all_dependencies_restored:
        raise FaultPhaseError(
            "Windows identity fault phases ended with dependencies offline")
    return driver.receipt
