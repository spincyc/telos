"""Adversarial phase-one dual-boot disk and firmware contract tests.

These tests deliberately use planner records as stand-ins for the evidence that
will later be collected from disposable QEMU workstations.
"""

import json
from pathlib import Path
import unittest

from workstations.layout import (
    GIB,
    MIB,
    GPT_MARGIN_MIB,
    LayoutError,
    build_record,
    plan_layout,
)


ROOT = Path(__file__).resolve().parents[1]
LAYOUT = ROOT / "workstations/profiles/default-layout.json"
WORKSTATION = ROOT / "workstations/profiles/phase1-windows-primary.json"


class DualBootDiskAcceptanceTests(unittest.TestCase):
    def test_exact_minimum_disk_is_accepted_without_hidden_overcommit(self):
        fixed_mib = 1024 + 16 + 2048 + GPT_MARGIN_MIB
        disk_mib = fixed_mib + (160 + 64) * 1024

        plan = plan_layout(disk_mib * MIB)

        self.assertEqual(0, plan.unallocated_mib)
        self.assertEqual(
            disk_mib - GPT_MARGIN_MIB,
            sum(partition.size_mib for partition in plan.partitions),
        )
        self.assertEqual(160 * 1024, plan.partitions[2].size_mib)
        self.assertEqual(64 * 1024, plan.partitions[3].size_mib)

    def test_sub_mib_tail_is_never_claimed_by_the_plan(self):
        plan = plan_layout(512 * GIB + MIB - 1)

        self.assertEqual(512 * 1024, plan.disk_mib)
        self.assertLessEqual(
            (plan.allocated_mib + plan.unallocated_mib + GPT_MARGIN_MIB) * MIB,
            512 * GIB + MIB - 1,
        )

    def test_ratio_extremes_still_preserve_both_absolute_minima(self):
        for percentage in (50, 75, 90):
            with self.subTest(windows_percent=percentage):
                plan = plan_layout(
                    2 * 1024 * GIB,
                    {"mode": "ratio", "windows_percent": percentage},
                )
                windows, arch = plan.partitions[2:4]
                self.assertGreaterEqual(windows.size_mib, 160 * 1024)
                self.assertGreaterEqual(arch.size_mib, 64 * 1024)
                self.assertEqual(
                    plan.disk_mib - GPT_MARGIN_MIB,
                    plan.allocated_mib + plan.unallocated_mib,
                )

    def test_non_integer_and_boolean_capacity_inputs_are_rejected(self):
        bad_configs = (
            {"mode": "ratio", "windows_percent": True},
            {"mode": "ratio", "windows_percent": 75.0},
            {
                "mode": "fixed",
                "windows_gib": True,
                "arch_gib": 64,
                "leftover": "unallocated",
            },
            {
                "mode": "fixed",
                "windows_gib": 160,
                "arch_gib": 64.0,
                "leftover": "unallocated",
            },
        )
        for config in bad_configs:
            with self.subTest(config=config), self.assertRaises(LayoutError):
                plan_layout(512 * GIB, config)

    def test_fixed_layout_cannot_silently_consume_leftover_space(self):
        with self.assertRaisesRegex(LayoutError, "leftover"):
            plan_layout(
                512 * GIB,
                {"mode": "fixed", "windows_gib": 300, "arch_gib": 100},
            )
        with self.assertRaisesRegex(LayoutError, "unallocated"):
            plan_layout(
                512 * GIB,
                {
                    "mode": "fixed",
                    "windows_gib": 300,
                    "arch_gib": 100,
                    "leftover": "windows",
                },
            )

    def test_mock_qemu_record_requires_windows_first_policy(self):
        record = build_record(512 * GIB, LAYOUT, WORKSTATION)
        contract = record["boot_contract"]

        self.assertEqual("uefi", contract["firmware"]["boot_mode"])
        self.assertEqual("gpt", contract["firmware"]["partition_table"])
        self.assertTrue(
            contract["operating_systems"]["windows"]["default_boot"]
        )
        self.assertFalse(
            contract["operating_systems"]["arch_linux"]["default_boot"]
        )
        self.assertEqual(
            ["esp", "msr", "basic-data", "linux-root", "windows-recovery"],
            [partition["type"] for partition in record["layout"]["partitions"]],
        )

    def test_mock_qemu_record_preserves_one_shared_efi_partition(self):
        record = build_record(512 * GIB, LAYOUT, WORKSTATION)
        partitions = record["layout"]["partitions"]
        esps = [partition for partition in partitions if partition["type"] == "esp"]

        self.assertEqual(1, len(esps))
        self.assertEqual(1, esps[0]["number"])
        self.assertEqual(1024, esps[0]["size_mib"])
        self.assertEqual(len(partitions), len({p["number"] for p in partitions}))

    def test_phase_one_mock_has_no_disk_encryption_or_tpm_enrollment(self):
        record = build_record(512 * GIB, LAYOUT, WORKSTATION)
        security = record["phase1_security"]

        self.assertEqual(
            {
                "bitlocker": False,
                "luks": False,
                "tpm_enrollment": False,
                "recovery_keys": False,
            },
            security,
        )
        serialized = json.dumps(record).lower()
        self.assertNotIn('"bitlocker": true', serialized)
        self.assertNotIn('"luks": true', serialized)

    def test_profile_hashes_make_mock_evidence_tamper_evident(self):
        record = build_record(512 * GIB, LAYOUT, WORKSTATION)

        for source in record["sources"].values():
            self.assertRegex(source["sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertNotEqual(
            record["sources"]["layout_profile"]["sha256"],
            record["sources"]["workstation_profile"]["sha256"],
        )


if __name__ == "__main__":
    unittest.main()
