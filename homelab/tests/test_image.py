"""Tests for staging the provisioning image.

The image is a public artifact: it is published with its checksum and readable
by anyone who can fetch it, and it is handed a disk to erase. Two properties
therefore matter more than anything else here, and both are tested rather than
intended -- that nothing secret is baked into it, and that the installer inside
it is the same program the acceptance harness drives.

The build itself needs root and is not run from a test. Everything up to the
build is.
"""

import importlib.machinery
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_loader = importlib.machinery.SourceFileLoader("homelab_image",
                                               str(ROOT / "bin/homelab-image"))
_spec = importlib.util.spec_from_loader("homelab_image", _loader)
image = importlib.util.module_from_spec(_spec)
_loader.exec_module(image)

PUBLIC_KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExample"
              "ExampleExampleExam observer@example\n")

PRIVATE_KEY = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
               "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAA\n"
               "-----END OPENSSH PRIVATE KEY-----\n")


class StagingCase(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="homelab-image-test-"))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.overlay = self.work / "overlay"
        self.overlay.mkdir()

    def stage(self):
        image.stage(self.work, overlay=self.overlay)
        return self.work / "profile"

    def with_key(self, text=PUBLIC_KEY):
        (self.overlay / "authorized_keys").write_text(text)


class TestTheInstallerIsInTheImage(StagingCase):
    def test_the_program_is_at_the_path_the_unit_names(self):
        build = self.stage()
        unit = (build / "airootfs/etc/systemd/system/homelab-installer.service"
                ).read_text()
        self.assertIn("/usr/local/bin/homelab-install", unit)
        self.assertTrue(
            (build / "airootfs/usr/local/bin/homelab-install").is_file())

    def test_it_is_byte_identical_to_the_one_the_tests_drive(self):
        # An image containing a *copy* of the installer that has been adjusted
        # to fit the image is an image running a program nothing tested.
        build = self.stage()
        staged = build / "airootfs/usr/local/bin/homelab-install"
        self.assertEqual(staged.read_bytes(),
                         (ROOT / "bin/homelab-install").read_bytes())

    def test_every_module_it_imports_is_present(self):
        build = self.stage()
        library = build / "airootfs/usr/local/lib/homelab"
        for module in image.INSTALLER_MODULES:
            with self.subTest(module=module):
                self.assertTrue((library / module).is_file())

    def test_the_modules_are_findable_at_runtime(self):
        build = self.stage()
        environment = (build / "airootfs/etc/environment").read_text()
        self.assertIn("PYTHONPATH=/usr/local/lib/homelab", environment)

    def test_a_missing_module_stops_the_build(self):
        original = image.INSTALLER_MODULES
        image.INSTALLER_MODULES = original + ("does-not-exist.py",)
        self.addCleanup(setattr, image, "INSTALLER_MODULES", original)
        with self.assertRaises(image.StagingError):
            self.stage()


class TestNothingSecretIsBakedIn(StagingCase):
    def test_a_private_key_in_the_overlay_is_refused(self):
        self.with_key(PRIVATE_KEY)
        with self.assertRaises(image.StagingError) as caught:
            self.stage()
        self.assertIn("private key", str(caught.exception))

    def test_an_empty_key_file_is_refused(self):
        # Silently shipping an empty authorized_keys would look like SSH access
        # was configured when nothing can log in.
        self.with_key("   \n")
        with self.assertRaises(image.StagingError):
            self.stage()

    def test_the_audit_finds_a_secret_planted_after_staging(self):
        build = self.stage()
        (build / "airootfs/root/planted").parent.mkdir(parents=True, exist_ok=True)
        (build / "airootfs/root/planted").write_text(PRIVATE_KEY)
        problems = image.audit(build)
        self.assertTrue(any("private key" in problem for problem in problems))

    def test_a_clean_tree_audits_clean(self):
        self.assertEqual(image.audit(self.stage()), [])


class TestSshIsEnabledOnlyWithAKey(StagingCase):
    def wants(self, build):
        directory = build / "airootfs/etc/systemd/system/multi-user.target.wants"
        return {path.name for path in directory.iterdir()}

    def test_without_a_key_there_is_no_sshd(self):
        # A listening sshd with no authorized key is attack surface that nothing
        # can log in through, on an image whose root account has no password.
        self.assertNotIn("sshd.service", self.wants(self.stage()))

    def test_with_a_key_sshd_is_enabled(self):
        self.with_key()
        self.assertIn("sshd.service", self.wants(self.stage()))

    def test_the_installer_is_always_enabled(self):
        self.assertIn("homelab-installer.service", self.wants(self.stage()))

    def test_password_authentication_is_off(self):
        build = self.stage()
        configuration = (build / "airootfs/etc/ssh/sshd_config.d/10-homelab.conf"
                         ).read_text()
        self.assertIn("PasswordAuthentication no", configuration)
        self.assertIn("PermitRootLogin prohibit-password", configuration)


class TestDeclaredPathsExist(StagingCase):
    def test_no_permission_entry_names_a_missing_file(self):
        # mkarchiso fails on a file_permissions entry it cannot find, after
        # doing all the expensive work. Catching it here costs nothing.
        self.assertEqual(image.audit(self.stage()), [])

    def test_the_authorized_keys_entry_is_dropped_when_there_is_no_key(self):
        build = self.stage()
        profiledef = (build / "profiledef.sh").read_text()
        self.assertNotIn("/root/.ssh/authorized_keys", profiledef)

    def test_the_authorized_keys_entry_survives_when_there_is_one(self):
        self.with_key()
        build = self.stage()
        profiledef = (build / "profiledef.sh").read_text()
        self.assertIn("/root/.ssh/authorized_keys", profiledef)
        self.assertEqual(image.audit(build), [])


class TestProvenance(StagingCase):
    def test_the_image_records_which_commit_it_came_from(self):
        build = self.stage()
        stamp = (build / "airootfs/etc/homelab-image-version").read_text().strip()
        self.assertTrue(stamp)
        # Every failure report from this thing arrives by hand, so an image
        # that cannot say what it is cannot be correlated with one.
        self.assertRegex(stamp, r"^(unknown|[0-9a-f]{7,})(\+dirty)?$")


class TestProfileIsBootable(StagingCase):
    """Properties of the tracked profile itself, not of staging."""

    def test_it_is_uefi_only(self):
        # ADR 0019. Shipping a BIOS path would only create a way to reach a
        # refusal slowly.
        profiledef = (ROOT / "archiso/profiledef.sh").read_text()
        self.assertIn("uefi-x64", profiledef)
        self.assertNotIn("bios.syslinux", profiledef)

    def test_it_builds_netboot_artifacts(self):
        profiledef = (ROOT / "archiso/profiledef.sh").read_text()
        self.assertIn("buildmodes=('netboot')", profiledef)

    def test_the_initramfs_can_fetch_its_root_over_http(self):
        configuration = (
            ROOT / "archiso/airootfs/etc/mkinitcpio.conf.d/archiso.conf"
        ).read_text()
        hooks = configuration.split("HOOKS=(", 1)[1].split(")", 1)[0].split()
        for hook in image.REQUIRED_INITRAMFS_HOOKS:
            with self.subTest(hook=hook):
                self.assertIn(hook, hooks)
        self.assertLess(
            hooks.index("archiso_pxe_common"),
            hooks.index("archiso_pxe_http"),
        )
        for hook in image.FORBIDDEN_INITRAMFS_HOOKS:
            with self.subTest(hook=hook):
                self.assertNotIn(hook, hooks)

        packages = (ROOT / "archiso/packages.x86_64").read_text().splitlines()
        self.assertNotIn("syslinux", packages)

    def test_the_audit_refuses_an_initramfs_without_http_pxe(self):
        build = self.stage()
        configuration = (
            build / "airootfs/etc/mkinitcpio.conf.d/archiso.conf"
        )
        configuration.write_text(
            configuration.read_text().replace(" archiso_pxe_http", "")
        )
        self.assertTrue(any(
            "archiso_pxe_http" in problem for problem in image.audit(build)
        ))

    def test_the_audit_refuses_memdisk_without_syslinux(self):
        build = self.stage()
        configuration = (
            build / "airootfs/etc/mkinitcpio.conf.d/archiso.conf"
        )
        configuration.write_text(
            configuration.read_text().replace(" kms archiso", " kms memdisk archiso")
        )
        self.assertTrue(any(
            "memdisk" in problem for problem in image.audit(build)
        ))

    def test_pacman_conf_is_present(self):
        # mkarchiso reads the file profiledef.sh names; without it the build
        # fails immediately and unhelpfully.
        profiledef = (ROOT / "archiso/profiledef.sh").read_text()
        self.assertIn('pacman_conf="pacman.conf"', profiledef)
        self.assertTrue((ROOT / "archiso/pacman.conf").is_file())

    def test_the_network_comes_up_by_dhcp(self):
        # The provisioning environment gets its address from the Controller it
        # is booting from; the installer unit waits for it.
        profile = ROOT / "archiso/airootfs"
        network = (
            profile / "etc/systemd/network/20-ethernet.network"
        ).read_text()
        self.assertIn("DHCP=yes", network)
        unit = (
            profile / "etc/systemd/system/homelab-installer.service"
        ).read_text()
        self.assertIn("systemd-networkd-wait-online.service", unit)
        for relative in image.REQUIRED_NETWORKD_LINKS:
            with self.subTest(link=relative):
                self.assertTrue((profile / relative).is_symlink())

    def test_the_installer_is_on_the_serial_console(self):
        # ADR 0056: the acceptance matrix attaches to ttyS0.
        unit = (ROOT / "archiso/airootfs/etc/systemd/system/"
                       "homelab-installer.service").read_text()
        self.assertIn("TTYPath=/dev/ttyS0", unit)

    def test_every_package_can_be_traced_to_a_reason(self):
        # The package list is grouped under comments explaining why each group
        # is there. A group with no comment is a package nobody justified.
        text = (ROOT / "archiso/packages.x86_64").read_text()
        groups = [block for block in text.split("\n\n") if block.strip()]
        for group in groups[1:]:                      # the first block is the header
            with self.subTest(group=group.splitlines()[0]):
                self.assertTrue(group.lstrip().startswith("#"),
                                "package group has no stated reason")


if __name__ == "__main__":
    unittest.main()
