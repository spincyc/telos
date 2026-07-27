import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "pxe" / "windows"


class WindowsPxeFlowContractTests(unittest.TestCase):
    def setUp(self):
        self.boot = (WINDOWS / "boot.ipxe").read_text(encoding="utf-8")
        self.flow = (WINDOWS / "FLOW.md").read_text(encoding="utf-8")

    def test_wimboot_payload_is_small_and_ordered(self):
        commands = [
            line.strip()
            for line in self.boot.splitlines()
            if line.startswith(("kernel ", "initrd "))
        ]
        self.assertEqual(
            [
                "kernel ${release-root}/wimboot",
                "initrd ${release-root}/bootmgr bootmgr",
                "initrd ${release-root}/boot/BCD BCD",
                "initrd ${release-root}/boot/boot.sdi boot.sdi",
                "initrd ${release-root}/sources/boot.wim boot.wim",
            ],
            commands,
        )
        self.assertNotRegex(self.boot.casefold(), r"install\.(wim|esd)")

    def test_install_image_is_read_from_restricted_smb_source(self):
        folded = self.flow.casefold()
        words = " ".join(folded.split())
        self.assertIn(r"\\bootstrap-dc\windows-<release>", folded)
        self.assertIn("read-only", folded)
        self.assertIn("install-only", folded)
        self.assertIn(r"w:\setup.exe /installfrom w:\sources\install.wim", folded)
        self.assertIn("exact byte count", folded)
        self.assertIn("controller hashes every source artifact", words)
        self.assertNotIn("certutil -hashfile", folded)

    def test_no_answer_file_or_hidden_edition_selection(self):
        folded = self.flow.casefold()
        words = " ".join(folded.split())
        for forbidden in ("autounattend.xml", "unattend.xml", "ei.cfg"):
            self.assertIn(forbidden, folded)
        self.assertIn("must not introduce", folded)
        self.assertIn("select exactly **windows 11 pro**", folded)
        self.assertIn("visible edition name is the authorization gate", words)

    def test_password_is_prompted_not_embedded(self):
        command = next(
            line.strip()
            for line in self.flow.splitlines()
            if line.strip().casefold().startswith("net use ")
        )
        self.assertIn(r" * /user:telos\pxe-install", command.casefold())
        self.assertNotRegex(command, r"/password:|/pass:|:[^\\\s]+\s*$")

    def test_hardware_contract_covers_windows_requirements(self):
        folded = self.flow.casefold()
        for required in (
            "uefi network boot",
            "tpm 2.0",
            "secure-boot-capable",
            "nvme or sata/ahci",
            "e1000e",
        ):
            self.assertIn(required, folded)

    def test_acceptance_excludes_iso_shortcut(self):
        self.assertIn(
            "direct iso attachment", self.flow.casefold()
        )
        self.assertIn(
            "does not satisfy\npxe acceptance", self.flow.casefold()
        )


if __name__ == "__main__":
    unittest.main()
