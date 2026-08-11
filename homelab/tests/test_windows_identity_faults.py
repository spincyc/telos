import unittest

from homelab.vm.windows_identity_faults import (
    FaultPhaseError,
    FaultPhaseOperations,
    run_fault_phases,
)


class Recorder:
    def __init__(self, failure=None, restore_failure=None):
        self.events = []
        self.failure = failure
        self.restore_failure = restore_failure

    def setter(self, dependency):
        def set_available(available):
            event = (
                f"restore:{dependency}" if available
                else f"disable:{dependency}"
            )
            self.events.append(event)
            if available and self.restore_failure == dependency:
                raise RuntimeError("restore failed")
        return set_available

    def observe(self, check):
        self.events.append(f"observe:{check}")
        if self.failure == check:
            raise RuntimeError("observation failed")

    def operations(self):
        return FaultPhaseOperations(
            set_controller_available=self.setter("controller"),
            set_gateway_available=self.setter("gateway"),
            set_update_source_available=self.setter("update-source"),
            set_optional_storage_available=self.setter("optional-storage"),
            observe=self.observe,
        )


class WindowsIdentityFaultTests(unittest.TestCase):
    def test_required_faults_have_one_order_and_reverse_restoration(self):
        recorder = Recorder()
        receipt = run_fault_phases(recorder.operations())
        self.assertEqual([
            "disable:controller",
            "observe:controller-offline",
            "observe:windows-cached-login",
            "observe:windows-cached-admin-login",
            "observe:windows-uncached-denied",
            "observe:windows-local-rescue",
            "restore:controller",
            "observe:controller-restored",
            "observe:windows-secure-channel-restored",
            "disable:gateway",
            "observe:gateway-offline",
            "restore:gateway",
            "disable:update-source",
            "observe:update-source-offline",
            "restore:update-source",
            "disable:optional-storage",
            "observe:optional-storage-offline",
            "restore:optional-storage",
            "observe:optional-storage-access-denied",
            "disable:controller",
            "observe:ad-dns-offline",
            "disable:gateway",
            "disable:update-source",
            "disable:optional-storage",
            "observe:combined-dependencies-offline",
            "restore:optional-storage",
            "restore:update-source",
            "restore:gateway",
            "restore:controller",
            "observe:windows-services-restored",
        ], recorder.events)
        self.assertTrue(receipt.all_dependencies_restored)

    def test_failed_observation_aborts_later_phases_and_restores(self):
        recorder = Recorder(failure="update-source-offline")
        with self.assertRaisesRegex(FaultPhaseError, "phase: RuntimeError"):
            run_fault_phases(recorder.operations())
        self.assertEqual(
            "restore:update-source", recorder.events[-1])
        self.assertNotIn("disable:optional-storage", recorder.events)
        self.assertNotIn(
            "observe:combined-dependencies-offline", recorder.events)

    def test_faultphase_error_preserves_the_originating_diagnostic(self):
        """Attempt 47: a fault-phase failure collapsed to a generic
        coordinate. FaultPhaseError now carries the originating error's
        diagnostic so the acceptance layer names the fault-phase check."""
        sentinel = object()

        class DiagnosedError(RuntimeError):
            diagnostic = sentinel

        recorder = Recorder()
        original_observe = recorder.observe

        def observe(check):
            original_observe(check)
            if check == "controller-offline":
                raise DiagnosedError("controller-offline observation failed")

        recorder.observe = observe
        with self.assertRaises(FaultPhaseError) as caught:
            run_fault_phases(recorder.operations())
        self.assertIs(sentinel, caught.exception.diagnostic)
        # A failure with no diagnostic leaves the attribute None, not absent.
        plain = Recorder(failure="gateway-offline")
        with self.assertRaises(FaultPhaseError) as caught:
            run_fault_phases(plain.operations())
        self.assertIsNone(caught.exception.diagnostic)

    def test_combined_failure_restores_every_dependency_in_reverse_order(self):
        recorder = Recorder(failure="combined-dependencies-offline")
        with self.assertRaises(FaultPhaseError):
            run_fault_phases(recorder.operations())
        self.assertEqual([
            "restore:optional-storage",
            "restore:update-source",
            "restore:gateway",
            "restore:controller",
        ], recorder.events[-4:])
        self.assertNotIn("observe:windows-services-restored", recorder.events)

    def test_cleanup_failure_is_reported_and_never_claims_success(self):
        recorder = Recorder(
            failure="combined-dependencies-offline",
            restore_failure="optional-storage",
        )
        with self.assertRaisesRegex(
                FaultPhaseError,
                "optional-storage restoration state is uncertain"):
            run_fault_phases(recorder.operations())
        self.assertEqual("restore:optional-storage", recorder.events[-1])
        self.assertNotIn("restore:update-source", recorder.events[-1:])

    def test_normal_restoration_failure_is_not_retried_blindly(self):
        recorder = Recorder(restore_failure="gateway")
        with self.assertRaisesRegex(
                FaultPhaseError, "restoration state is uncertain"):
            run_fault_phases(recorder.operations())
        self.assertEqual(1, recorder.events.count("restore:gateway"))
        self.assertNotIn("disable:update-source", recorder.events)


if __name__ == "__main__":
    unittest.main()
