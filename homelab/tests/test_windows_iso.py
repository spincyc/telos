import hashlib
import tempfile
import unittest
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import windows_iso  # noqa: E402


FILES = "\n".join(
    ["Path = " + path.lstrip("/") for path in
    [
        "/bootmgr",
        "/Boot/BCD",
        "/boot/boot.sdi",
        "/efi/boot/bootx64.efi",
        "/efi/microsoft/boot/cdboot.efi",
        "/sources/boot.wim",
        "/sources/install.wim",
    ]]
)


class FakeTools:
    def __init__(self, listing=FILES, info="Name: Windows 11 Pro\n"):
        self.listing = listing
        self.info = info
        self.commands = []

    def __call__(self, command):
        self.commands.append(command)
        if command[0] == "wimlib-imagex":
            return self.info
        if command[0] == "7z" and command[1] == "e":
            output = next(value[2:] for value in command if value.startswith("-o"))
            Path(output, "install.wim").write_bytes(b"fixture install image")
            return ""
        return self.listing


class WindowsIsoTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.iso = Path(self.temporary.name) / "windows.iso"
        self.iso.write_bytes(b"synthetic iso")
        self.digest = hashlib.sha256(self.iso.read_bytes()).hexdigest()

    def test_verifies_checksum_boot_chain_and_exact_pro_edition(self):
        tools = FakeTools()
        receipt = windows_iso.verify(self.iso, self.digest.upper(), run=tools)
        self.assertEqual("Windows 11 Pro", receipt["edition"])
        self.assertEqual("/sources/install.wim", receipt["install_image"])
        self.assertEqual("7z", tools.commands[0][0])
        self.assertIn("-tUdf", tools.commands[0])
        self.assertIn("-tUdf", tools.commands[-2])
        self.assertEqual("wimlib-imagex", tools.commands[-1][0])

    def test_checksum_mismatch_stops_before_external_tools(self):
        tools = FakeTools()
        with self.assertRaisesRegex(windows_iso.VerificationError, "mismatch"):
            windows_iso.verify(self.iso, "0" * 64, run=tools)
        self.assertEqual([], tools.commands)

    def test_expected_checksum_has_strict_shape(self):
        with self.assertRaisesRegex(windows_iso.VerificationError, "64 hexadecimal"):
            windows_iso.verify(self.iso, "sha256:1234", run=FakeTools())

    def test_missing_uefi_boot_file_is_rejected(self):
        listing = FILES.replace("Path = efi/boot/bootx64.efi\n", "")
        with self.assertRaisesRegex(windows_iso.VerificationError, "bootx64.efi"):
            windows_iso.verify(self.iso, self.digest, run=FakeTools(listing=listing))

    def test_requires_exactly_one_install_image(self):
        listing = FILES + "\nPath = sources/install.esd"
        with self.assertRaisesRegex(windows_iso.VerificationError, "exactly one"):
            windows_iso.verify(self.iso, self.digest, run=FakeTools(listing=listing))

    def test_pro_n_does_not_satisfy_pro_requirement(self):
        with self.assertRaisesRegex(windows_iso.VerificationError, "exact edition"):
            windows_iso.verify(
                self.iso,
                self.digest,
                run=FakeTools(info="Name: Windows 11 Pro N\n"),
            )

    def test_iso_paths_are_matched_case_insensitively(self):
        receipt = windows_iso.verify(
            self.iso, self.digest, run=FakeTools(listing=FILES.upper())
        )
        self.assertEqual("/SOURCES/INSTALL.WIM", receipt["install_image"])

    def test_xorriso_shell_quoted_paths_are_accepted(self):
        listing = FILES
        receipt = windows_iso.verify(
            self.iso, self.digest, run=FakeTools(listing=listing)
        )
        self.assertEqual("/sources/install.wim", receipt["install_image"])


if __name__ == "__main__":
    unittest.main()
