import json
from pathlib import Path
import unittest

from workstations.layout import (
    GIB,
    LayoutError,
    build_record,
    load_profile,
    plan_layout,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = ROOT / "workstations/profiles/default-layout.json"
WORKSTATION_PROFILE = (
    ROOT / "workstations/profiles/phase1-windows-primary.json"
)


class WorkstationLayoutTests(unittest.TestCase):
    def test_default_profile_has_required_partition_shapes(self):
        profile = load_profile(DEFAULT_PROFILE)
        plan = plan_layout(512 * GIB, profile)

        sizes = {item.type: item.size_mib for item in plan.partitions}
        self.assertEqual(sizes["esp"], 1024)
        self.assertEqual(sizes["msr"], 16)
        self.assertEqual(sizes["windows-recovery"], 2048)
        self.assertEqual(
            sizes["basic-data"] + sizes["linux-root"],
            plan.disk_mib - 1024 - 16 - 2048 - 2,
        )
        surplus = (
            sizes["basic-data"] + sizes["linux-root"] - 224 * 1024
        )
        self.assertEqual(
            sizes["basic-data"], 160 * 1024 + surplus * 75 // 100
        )
        self.assertEqual(plan.unallocated_mib, 0)

    def test_rejects_disk_that_cannot_meet_both_minima(self):
        with self.assertRaisesRegex(LayoutError, "too small"):
            plan_layout(227 * GIB)

    def test_ratio_override_is_bounded_and_must_preserve_minima(self):
        plan = plan_layout(1024 * GIB, {"mode": "ratio", "windows_percent": 60})
        windows, arch = plan.partitions[2:4]
        self.assertEqual(windows.size_mib + arch.size_mib, 1024 * 1024 - 3090)
        self.assertGreater(windows.size_mib, arch.size_mib)

        with self.assertRaisesRegex(LayoutError, "50..90"):
            plan_layout(1024 * GIB, {"mode": "ratio", "windows_percent": 95})

    def test_fixed_override_leaves_explicit_unallocated_capacity(self):
        plan = plan_layout(
            512 * GIB,
            {
                "mode": "fixed",
                "windows_gib": 300,
                "arch_gib": 100,
                "leftover": "unallocated",
            },
        )
        self.assertEqual(plan.partitions[2].size_mib, 300 * 1024)
        self.assertEqual(plan.partitions[3].size_mib, 100 * 1024)
        self.assertEqual(plan.unallocated_mib, 512 * 1024 - 3090 - 400 * 1024)

    def test_fixed_override_rejects_minimum_and_capacity_failures(self):
        with self.assertRaisesRegex(LayoutError, "smaller than 160"):
            plan_layout(
                512 * GIB,
                {
                    "mode": "fixed",
                    "windows_gib": 159,
                    "arch_gib": 100,
                    "leftover": "unallocated",
                },
            )
        with self.assertRaisesRegex(LayoutError, "exceed"):
            plan_layout(
                512 * GIB,
                {
                    "mode": "fixed",
                    "windows_gib": 400,
                    "arch_gib": 200,
                    "leftover": "unallocated",
                },
            )

    def test_fixed_override_requires_an_explicit_leftover_decision(self):
        with self.assertRaisesRegex(LayoutError, "leftover"):
            plan_layout(
                512 * GIB,
                {"mode": "fixed", "windows_gib": 300, "arch_gib": 100},
            )

    def test_combined_record_binds_layout_boot_and_security_profiles(self):
        record = build_record(
            512 * GIB, DEFAULT_PROFILE, WORKSTATION_PROFILE
        )
        self.assertEqual(record["workstation_profile_id"], "phase1-windows-primary")
        self.assertEqual(record["layout"]["windows_percent"], 75)
        self.assertFalse(record["boot_contract"]["firmware"]["secure_boot"])
        self.assertFalse(record["phase1_security"]["bitlocker"])
        self.assertRegex(
            record["sources"]["layout_profile"]["sha256"], r"^[0-9a-f]{64}$"
        )

    def test_schema_and_profile_are_parseable_json(self):
        schema = json.loads(
            (ROOT / "workstations/layout.schema.json").read_text(encoding="utf-8")
        )
        profile = load_profile(DEFAULT_PROFILE)
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(profile["windows_percent"], 75)


if __name__ == "__main__":
    unittest.main()
