import re
import unittest
from pathlib import Path


MAKEFILE = (Path(__file__).parents[2] / "Makefile").read_text()


def target(name: str) -> str:
    match = re.search(
        rf"^{re.escape(name)}:.*?(?=^[A-Za-z0-9_.-]+:|\Z)",
        MAKEFILE,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing Make target: {name}")
    return match.group(0)


class SimulationMakeTests(unittest.TestCase):
    def test_surface_is_phony(self):
        phony = MAKEFILE.split(".PHONY:", 1)[1].split(
            ".DELETE_ON_ERROR:", 1)[0]
        for name in (
            "homelab-sim-plan",
            "homelab-sim-run",
            "homelab-sim-check",
            "homelab-sim-repeat",
            "homelab-sim-deps",
            "homelab-sim-auto-plan",
            "homelab-sim-auto-run",
            "homelab-sim-auto-repeat",
        ):
            self.assertIn(name, phony)
            self.assertIn(f"{name}:", MAKEFILE)

    def test_plan_needs_no_iso_and_cannot_apply(self):
        body = target("homelab-sim-plan")
        self.assertNotIn("--arch-iso", body)
        self.assertNotIn("--apply", body)

    def test_live_targets_require_apply(self):
        for name in ("homelab-sim-run", "homelab-sim-repeat"):
            body = target(name)
            self.assertIn("if [ '$(APPLY)' != 1 ]", body)
            self.assertNotIn("--arch-iso", body)
            self.assertIn("--apply", body)

    def test_repeat_rejects_invalid_cycle_count(self):
        for name in ("homelab-sim-repeat", "homelab-sim-auto-repeat"):
            body = target(name)
            self.assertIn("SIM_CYCLES must be a positive integer", body)
            self.assertIn("*[!0-9]*|0)", body)

    def test_surface_has_no_physical_network_inputs(self):
        combined = "\n".join(target(name) for name in (
            "homelab-sim-plan",
            "homelab-sim-run",
            "homelab-sim-check",
            "homelab-sim-repeat",
            "homelab-sim-deps",
            "homelab-sim-auto-plan",
            "homelab-sim-auto-run",
            "homelab-sim-auto-repeat",
        ))
        for forbidden in (
            "NETWORK_CONFIG",
            "homelab-host-network",
            "homelab-bootstrap-network",
            "sudo",
        ):
            self.assertNotIn(forbidden, combined)

    def test_automated_surface_is_explicit_and_apply_gated(self):
        plan = target("homelab-sim-auto-plan")
        self.assertIn("--automated", plan)
        self.assertNotIn("--apply", plan)
        for name in ("homelab-sim-auto-run", "homelab-sim-auto-repeat"):
            body = target(name)
            self.assertIn("if [ '$(APPLY)' != 1 ]", body)
            self.assertIn("--automated", body)
            self.assertIn("--apply", body)
            self.assertNotIn("homelab-sim-run", body)

    def test_make_surface_never_accepts_credentials(self):
        combined = "\n".join(target(name) for name in (
            "homelab-sim-auto-plan",
            "homelab-sim-auto-run",
            "homelab-sim-auto-repeat",
        )).lower()
        for forbidden in ("password", "credential", "secret", "answer"):
            self.assertNotRegex(
                combined, rf"\$\([^)]*{forbidden}[^)]*\)")

    def test_dependency_check_is_read_only_and_complete(self):
        body = target("homelab-sim-deps")
        for tool in (
            "$(PYTHON)", "qemu-system-x86_64", "qemu-img", "sfdisk", "mcopy",
        ):
            self.assertIn(tool, body)
        for forbidden in ("pacman", "sudo", "install-dependencies"):
            self.assertNotIn(forbidden, body)

    def test_check_covers_all_homelab_acceptance_suites(self):
        body = target("homelab-sim-check")
        self.assertIn(
            "unittest discover -s homelab/tests -t . -v", body)
        self.assertIn("PYTHONPATH=.", body)
        self.assertNotIn("-p 'test_sim*.py'", body)


if __name__ == "__main__":
    unittest.main()
