import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "arch_policy", ROOT / "updates" / "arch_policy.py")
policy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = policy
SPEC.loader.exec_module(policy)


class TestArchUpdatePolicy(unittest.TestCase):
    def test_battery_defers_without_failing_hard(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "BAT0").mkdir()
            (root / "BAT0" / "online").write_text("0\n")
            with patch.object(policy.shutil, "disk_usage",
                              return_value=type("Usage", (), {"free": 20 * 1024**3})()):
                report = policy.evaluate(root=root, power_root=root,
                                         lock=root / "lock", probe_internet=False)
        self.assertFalse(report.allowed)
        self.assertIn("battery power", report.reasons)

    def test_all_local_gates_can_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(policy.shutil, "disk_usage",
                              return_value=type("Usage", (), {"free": 20 * 1024**3})()):
                report = policy.evaluate(root=root, power_root=root,
                                         lock=root / "lock", probe_internet=False)
        self.assertTrue(report.allowed)

    def test_active_pacman_and_low_space_both_report(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            lock = root / "lock"
            lock.touch()
            with patch.object(policy.shutil, "disk_usage",
                              return_value=type("Usage", (), {"free": 1})()):
                report = policy.evaluate(root=root, power_root=root,
                                         lock=lock, probe_internet=False)
        self.assertEqual(len(report.reasons), 2)


class TestArchUpdateDeployment(unittest.TestCase):
    def test_role_copies_canonical_scripts(self):
        for name in ("arch_policy.py", "arch-update"):
            canonical = (ROOT / "updates" / name).read_text()
            deployed = (ROOT / "ansible" / "roles" / "arch_updates" /
                        "files" / name).read_text()
            self.assertEqual(deployed, canonical)

    def test_timer_is_daily_randomized_and_persistent(self):
        timer = (ROOT / "ansible" / "roles" / "arch_updates" / "files" /
                 "homelab-arch-update.timer").read_text()
        self.assertIn("OnCalendar=*-*-* 03:00", timer)
        self.assertIn("RandomizedDelaySec=3h", timer)
        self.assertIn("Persistent=true", timer)
