"""Static safety contract for the offline bootstrap Controller installer.

The real installation necessarily needs root and a disposable block device.
These tests keep the ordinary suite harmless while pinning the properties that
must not quietly disappear from the shell entry point.
"""

from pathlib import Path
import subprocess
import unittest


INSTALLER = Path(__file__).parents[1] / "seed" / "install-controller"
BUILDER = INSTALLER.with_name("build.py")


class SeedInstallerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INSTALLER.read_text(encoding="utf-8")

    def test_is_valid_posix_shell(self) -> None:
        subprocess.run(["sh", "-n", str(INSTALLER)], check=True)

    def test_requires_root_and_contains_no_dry_run_bypass(self) -> None:
        self.assertRegex(self.source, r'id\s+-u')
        self.assertNotRegex(self.source, r'--(?:dry-run|yes|non-interactive)')

    def test_discovers_one_disk_by_exact_serial(self) -> None:
        self.assertIn("lsblk -dnpo NAME,SERIAL,TYPE", self.source)
        self.assertIn("TELOS-BOOTSTRAP-DC1", self.source)
        self.assertNotRegex(self.source, r'grep\s+.*TELOS-BOOTSTRAP-DC1')
        self.assertRegex(
            self.source,
            r'\[\s*"\$serial"\s*=\s*"\$expected_serial"\s*\]',
        )
        self.assertRegex(self.source, r'\[\s*"\$matches"\s*-eq\s*1\s*\]')

    def test_requires_the_full_erase_phrase(self) -> None:
        self.assertIn("expected_serial=TELOS-BOOTSTRAP-DC1", self.source)
        self.assertIn("Type ERASE %s to continue", self.source)
        self.assertRegex(
            self.source,
            r'\[\s*"\$confirmation"\s*=\s*"ERASE \$expected_serial"\s*\]',
        )

    def test_writes_a_uefi_gpt_root_layout(self) -> None:
        self.assertIn("sfdisk --wipe always", self.source)
        self.assertRegex(self.source, r'(?m)^label:\s*gpt$')
        self.assertRegex(self.source, r'(?m)^size=1GiB,\s*type=U,')
        self.assertRegex(self.source, r'(?m)^type=L,')
        self.assertRegex(self.source, r'mkfs\.fat')
        self.assertRegex(self.source, r'mkfs\.ext4')

    def test_installs_only_from_seed_packages(self) -> None:
        self.assertRegex(self.source, r'pacstrap[^\n]*\s-U(?:\s|$)')
        self.assertNotRegex(self.source, r'\bpacstrap\b[^\n]*\s-[^\n]*\bS')
        self.assertNotRegex(self.source, r'\bpacman\s+(?:-[^\n ]*)?S(?:y|u|yu)?\b')

    def test_configures_systemd_boot_and_serial_console(self) -> None:
        self.assertIn("bootctl", self.source)
        self.assertIn("console=ttyS0", self.source)
        self.assertIn("serial-getty@ttyS0.service", self.source)

    def test_sets_fixed_bootstrap_identity(self) -> None:
        self.assertRegex(
            self.source,
            r'(?:printf|echo)[^\n]*bootstrap-dc[^\n]*>\s*'
            r'(?:"?\$[^ ]+"?)?/etc/hostname',
        )
        self.assertIn("passwd local-rescue", self.source)
        self.assertRegex(
            self.source,
            r'passwd\s+(?:(?:-[dl]|--lock)\s+root|root\s+(?:-[dl]|--lock))',
        )

    def test_disables_ssh_password_and_root_login(self) -> None:
        self.assertRegex(self.source, r'PasswordAuthentication\s+no')
        self.assertRegex(self.source, r'PermitRootLogin\s+no')

    def test_builder_places_installer_on_seed(self) -> None:
        builder = BUILDER.read_text(encoding="utf-8")
        self.assertRegex(
            builder,
            r'(?:copy2|install)[^\n]*install-controller',
        )


if __name__ == "__main__":
    unittest.main()
