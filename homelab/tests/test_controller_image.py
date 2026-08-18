"""What a read-only look at a Controller image may and may not conclude."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vm"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import controller_image  # noqa: E402
import fake_image_tools  # noqa: E402


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.disk = self.root / "bootstrap-dc.qcow2"

    def probe(self, tool=None):
        with mock.patch.object(
                controller_image.subprocess, "run",
                side_effect=tool or fake_image_tools.image_tool):
            return controller_image.probe(self.disk)

    def test_an_unallocated_image_is_not_installed_and_costs_one_map(self):
        fake_image_tools.blank_image(self.disk)
        calls = []

        def record(argv, **kwargs):
            calls.append(list(argv))
            return fake_image_tools.image_tool(argv, **kwargs)

        state = self.probe(record)
        self.assertFalse(state.installed)
        self.assertIn("entirely unallocated", state.reason)
        self.assertEqual(state.allocated_bytes, 0)
        # The cheap answer settles it: nothing is extracted and no partition
        # table is read for an image that has never been written.
        self.assertEqual(
            [argv[1] for argv in calls if argv[0] == "qemu-img"],
            ["info", "map"])
        self.assertNotIn("sfdisk", [argv[0] for argv in calls])

    def test_a_gpt_with_one_esp_is_installed(self):
        fake_image_tools.installed_image(self.disk)
        state = self.probe()
        self.assertTrue(state.installed)
        self.assertEqual(state.esp_partitions, 1)
        self.assertEqual(state.partitions, 2)
        self.assertEqual(
            state.allocated_bytes, fake_image_tools.WRITTEN_BYTES)
        self.assertEqual(state.virtual_bytes, fake_image_tools.VIRTUAL_BYTES)
        self.assertIn("installed", state.summary())
        self.assertEqual(state.record()["installed"], True)

    def test_written_bytes_without_a_partition_table_are_not_an_installation(self):
        fake_image_tools.installed_image(self.disk)

        def no_table(argv, **kwargs):
            if argv[0] == "sfdisk":
                return subprocess.CompletedProcess(argv, 1, "", "")
            return fake_image_tools.image_tool(argv, **kwargs)

        state = self.probe(no_table)
        self.assertFalse(state.installed)
        self.assertIn("no readable partition table", state.reason)

    def test_a_second_esp_is_refused_rather_than_taken_as_the_first(self):
        fake_image_tools.installed_image(self.disk)

        def two_esps(argv, **kwargs):
            result = fake_image_tools.image_tool(argv, **kwargs)
            if argv[0] != "sfdisk":
                return result
            table = json.loads(result.stdout)
            table["partitiontable"]["partitions"][1]["type"] = (
                fake_image_tools.EFI_SYSTEM_GUID)
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(table), "")

        state = self.probe(two_esps)
        self.assertFalse(state.installed)
        self.assertIn("2 EFI system partitions", state.reason)

    def test_geometry_that_does_not_fit_the_image_is_refused(self):
        fake_image_tools.installed_image(self.disk)

        def oversized(argv, **kwargs):
            result = fake_image_tools.image_tool(argv, **kwargs)
            if argv[0] != "sfdisk":
                return result
            table = json.loads(result.stdout)
            table["partitiontable"]["partitions"][0]["size"] = 1 << 40
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(table), "")

        state = self.probe(oversized)
        self.assertFalse(state.installed)
        self.assertIn("geometry", state.reason)

    def test_a_dos_label_is_not_the_gpt_the_installer_writes(self):
        fake_image_tools.installed_image(self.disk)

        def protective_mbr(argv, **kwargs):
            result = fake_image_tools.image_tool(argv, **kwargs)
            if argv[0] != "sfdisk":
                return result
            return subprocess.CompletedProcess(argv, 0, json.dumps({
                "partitiontable": {
                    "label": "dos", "sectorsize": 512,
                    "partitions": [{"node": "x1", "start": 1, "size": 2047,
                                    "type": "ee"}],
                }}), "")

        state = self.probe(protective_mbr)
        self.assertFalse(state.installed)
        self.assertIn("not the GPT", state.reason)

    def test_an_uninspectable_image_raises_rather_than_reporting_a_verdict(self):
        fake_image_tools.installed_image(self.disk)

        def unreadable(argv, **_kwargs):
            return subprocess.CompletedProcess(argv, 0, "not json", "")

        with self.assertRaises(controller_image.ControllerImageError):
            self.probe(unreadable)

    def test_a_missing_tool_is_a_named_refusal_not_a_traceback(self):
        fake_image_tools.installed_image(self.disk)

        def absent(argv, **_kwargs):
            raise FileNotFoundError(argv[0])

        with self.assertRaisesRegex(
                controller_image.ControllerImageError, "qemu-img is required"):
            self.probe(absent)

    def test_a_symlinked_image_is_refused(self):
        real = self.root / "real.qcow2"
        fake_image_tools.installed_image(real)
        self.disk.symlink_to(real)
        with self.assertRaisesRegex(
                controller_image.ControllerImageError, "regular"):
            self.probe()

    def test_assert_installed_names_the_subject_and_the_way_out(self):
        fake_image_tools.blank_image(self.disk)
        with mock.patch.object(
                controller_image.subprocess, "run",
                side_effect=fake_image_tools.image_tool):
            with self.assertRaises(
                    controller_image.ControllerImageError) as raised:
                controller_image.assert_installed(
                    self.disk, subject="the canonical image",
                    remedy="Install it first.")
            message = str(raised.exception)
            self.assertIn("the canonical image", message)
            self.assertIn("Install it first.", message)
            # And it returns the state on the happy path.
            fake_image_tools.installed_image(self.disk)
            state = controller_image.assert_installed(
                self.disk, subject="the canonical image", remedy="")
            self.assertTrue(state.installed)


class RealToolTests(unittest.TestCase):
    """One end-to-end pass against the actual tools, when they are present.

    The fake models the tools; this proves the model is right. Skipped rather
    than failed where qemu-img or sfdisk is unavailable, because the unit
    suite must run on a host with neither.
    """

    def setUp(self):
        import shutil
        for tool in ("qemu-img", "sfdisk"):
            if not shutil.which(tool):
                self.skipTest(f"{tool} is not installed")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_a_fresh_qcow2_reads_as_not_installed(self):
        disk = self.root / "fresh.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", str(disk), "80G"],
            check=True, capture_output=True)
        state = controller_image.probe(disk)
        self.assertFalse(state.installed)
        self.assertEqual(state.allocated_bytes, 0)
        self.assertEqual(state.virtual_bytes, 80 * (1 << 30))

    def test_a_partitioned_image_reads_as_installed(self):
        raw = self.root / "raw.img"
        with raw.open("wb") as stream:
            stream.truncate(8 * (1 << 30))
        subprocess.run(
            ["sfdisk", "--wipe", "always", str(raw)],
            input='label: gpt\nsize=1GiB, type=U, name="EFI System"\n'
                  'type=L, name="Arch Linux"\n',
            text=True, check=True, capture_output=True)
        disk = self.root / "installed.qcow2"
        subprocess.run(
            ["qemu-img", "convert", "-f", "raw", "-O", "qcow2",
             str(raw), str(disk)],
            check=True, capture_output=True)
        state = controller_image.probe(disk)
        self.assertTrue(state.installed, state.reason)
        self.assertEqual(state.esp_partitions, 1)
        self.assertEqual(state.partitions, 2)


if __name__ == "__main__":
    unittest.main()
