"""Contract tests for the bounded concurrent factory skeleton."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm import factory_runner
from homelab.vm.qemu_boundary import audit_disposable_controller


class FactoryRunnerTests(unittest.TestCase):
    def test_commands_use_one_loopback_switch_and_disposable_paths(self):
        with mock.patch.object(
                factory_runner, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch(
                    "homelab.vm.simulated_topology.ovmf_pair",
                    return_value=(Path("/code"), Path("/vars"))):
            plans = factory_runner.qemu_commands(
                Path("/run/controller.qcow2"),
                Path("/run/controller-vars.fd"),
                Path("/run/workstation.qcow2"),
                Path("/run/workstation-vars.fd"),
                31415,
                None,
            )
        self.assertEqual(set(plans), {"controller", "workstation"})
        for command in plans.values():
            text = " ".join(command)
            self.assertIn("connect=127.0.0.1:31415", text)
            self.assertNotIn("tap,", text)
            self.assertNotIn("bridge,", text)
            self.assertNotIn("user,", text)
        self.assertIn(
            "/run/controller.qcow2", " ".join(plans["controller"]))
        self.assertIn(
            "format=raw", " ".join(plans["controller"]))
        self.assertIn(
            "/run/workstation.qcow2", " ".join(plans["workstation"]))

    def test_switch_has_exact_pinned_factory_ports(self):
        command = factory_runner.switch_command(9, Path("/run/evidence"))
        text = " ".join(command)
        self.assertIn("--listener-fd 9", text)
        self.assertIn("controller=52:54:00:31:11:12", text)
        self.assertIn("workstation=52:54:00:31:12:12", text)
        self.assertNotIn("0.0.0.0", text)

    def test_controller_command_passes_strict_standalone_raw_audit(self):
        disk = Path("/run/disposable/controller.raw")
        variables = Path("/run/disposable/OVMF_VARS.fd")
        with mock.patch.object(
                factory_runner, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch(
                    "homelab.vm.simulated_topology.ovmf_pair",
                    return_value=(Path("/code"), Path("/vars"))):
            command = factory_runner.qemu_commands(
                disk, variables,
                Path("/run/workstation.qcow2"),
                Path("/run/workstation-vars.fd"),
                31415, None)["controller"]
        audit_disposable_controller(
            command,
            disk=disk,
            vars_file=variables,
            forbidden_paths=(
                Path("/canonical/controller.qcow2"),
                Path("/canonical/OVMF_VARS.fd"),
            ),
        )

    def test_plan_is_default_and_starts_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            (state / "bootstrap-dc.qcow2").write_bytes(b"disk")
            (state / "OVMF_VARS.fd").write_bytes(b"vars")
            with mock.patch.object(
                    factory_runner, "ovmf_pair",
                    return_value=(Path("/code"), Path("/vars"))), \
                    mock.patch.object(
                        factory_runner.shutil, "which",
                        return_value="/usr/bin/tool"), \
                    mock.patch.object(
                        factory_runner.subprocess, "Popen") as start:
                self.assertEqual(
                    factory_runner.run(state, apply=False, duration=1), 0)
                start.assert_not_called()

    def test_duration_is_bounded(self):
        with mock.patch.object(factory_runner, "_problems", return_value=[]):
            self.assertEqual(
                factory_runner.run(Path("/state"), apply=False, duration=0), 2)
            self.assertEqual(
                factory_runner.run(
                    Path("/state"), apply=False, duration=3601), 2)

    def test_source_sets_disposable_factory_state_private(self):
        source = Path(factory_runner.__file__).read_text()
        self.assertGreaterEqual(source.count(".chmod(0o600)"), 2)


if __name__ == "__main__":
    unittest.main()
