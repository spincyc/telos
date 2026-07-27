import tempfile
import unittest
from pathlib import Path

from homelab.vm.qemu_boundary import audit_disposable_controller


class QemuBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.disk = root / "controller.raw"
        self.vars = root / "OVMF_VARS.fd"
        self.canonical_disk = root / "canonical.qcow2"
        self.canonical_vars = root / "canonical-vars.fd"
        self.argv = [
            "qemu-system-x86_64", "-nodefaults",
            "-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF_CODE.fd",
            "-drive", f"if=pflash,format=raw,file={self.vars.resolve()}",
            "-drive", f"if=virtio,format=raw,cache=none,file={self.disk.resolve()}",
            "-netdev", "socket,id=simnet,connect=127.0.0.1:12971",
            "-device", "virtio-net-pci,netdev=simnet,mac=52:54:00:31:11:12",
        ]

    def audit(self, argv=None):
        audit_disposable_controller(
            argv or self.argv, disk=self.disk, vars_file=self.vars,
            forbidden_paths=(self.canonical_disk, self.canonical_vars))

    def test_accepts_standalone_disposable_boundary(self):
        self.audit()

    def test_rejects_canonical_path_anywhere(self):
        for canonical in (self.canonical_disk, self.canonical_vars):
            with self.subTest(canonical=canonical):
                with self.assertRaisesRegex(ValueError, "canonical"):
                    self.audit(self.argv + ["-name", str(canonical.resolve())])

    def test_rejects_overlay_or_wrong_disk_format(self):
        changed = [
            item.replace("if=virtio,format=raw", "if=virtio,format=qcow2")
            for item in self.argv
        ]
        with self.assertRaisesRegex(ValueError, "standalone raw"):
            self.audit(changed)

    def test_rejects_extra_writable_drive(self):
        with self.assertRaisesRegex(ValueError, "another writable drive"):
            self.audit(self.argv + [
                "-drive", "if=virtio,format=raw,file=/tmp/extra.raw"])

    def test_rejects_non_loopback_or_extra_network(self):
        for addition in (
            ["-netdev", "user,id=escape"],
            ["-virtfs", "local,path=/tmp,mount_tag=host"],
            ["-netdev", "socket,id=escape,connect=10.1.1.1:12971"],
        ):
            with self.subTest(addition=addition):
                with self.assertRaises(ValueError):
                    self.audit(self.argv + addition)

    def test_rejects_canonical_paths_as_disposable_arguments(self):
        with self.assertRaisesRegex(ValueError, "overlap"):
            audit_disposable_controller(
                self.argv, disk=self.canonical_disk, vars_file=self.vars,
                forbidden_paths=(self.canonical_disk, self.canonical_vars))


if __name__ == "__main__":
    unittest.main()
