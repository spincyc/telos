import copy
import unittest
from pathlib import Path

from lib.workstation_profile import (
    WorkstationProfileError,
    load_profile,
    require_valid_profile,
    validate_profile,
)


PROFILE = (
    Path(__file__).parents[1]
    / "workstations"
    / "profiles"
    / "phase1-windows-primary.json"
)


class WorkstationProfileTests(unittest.TestCase):
    def setUp(self):
        self.profile = load_profile(PROFILE)

    def test_tracked_phase1_profile_is_valid(self):
        self.assertEqual([], validate_profile(self.profile))

    def test_boot_contract_is_bounded(self):
        mutations = (
            ("firmware", "boot_mode", "bios"),
            ("firmware", "partition_table", "mbr"),
            ("firmware", "secure_boot", True),
            ("operating_systems", "windows", {"release": "10"}),
            ("boot_menu", "timeout_seconds", 10),
        )
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                changed = copy.deepcopy(self.profile)
                changed[section][key] = value
                self.assertTrue(validate_profile(changed))

    def test_phase1_rejects_every_encryption_or_key_enrollment_switch(self):
        for setting in ("bitlocker", "luks", "tpm_enrollment", "recovery_keys"):
            with self.subTest(setting=setting):
                changed = copy.deepcopy(self.profile)
                changed["phase1_security"][setting] = True
                self.assertIn(setting, " ".join(validate_profile(changed)))

    def test_windows_must_be_the_only_default(self):
        changed = copy.deepcopy(self.profile)
        changed["operating_systems"]["windows"]["default_boot"] = False
        changed["operating_systems"]["arch_linux"]["default_boot"] = True
        errors = validate_profile(changed)
        self.assertEqual(2, len(errors))

    def test_future_security_work_is_explicitly_deferred(self):
        changed = copy.deepcopy(self.profile)
        changed["future_migrations"] = []
        errors = validate_profile(changed)
        self.assertEqual(3, len(errors))
        self.assertTrue(all("future_migrations" in error for error in errors))

    def test_require_valid_reports_all_errors(self):
        changed = copy.deepcopy(self.profile)
        changed["firmware"]["secure_boot"] = True
        changed["phase1_security"]["luks"] = True
        with self.assertRaises(WorkstationProfileError) as caught:
            require_valid_profile(changed)
        message = str(caught.exception)
        self.assertIn("secure_boot", message)
        self.assertIn("luks", message)


if __name__ == "__main__":
    unittest.main()
