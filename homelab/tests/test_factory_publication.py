"""Contracts for selected release-set publication into the isolated factory."""

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.lib import pxe_release_set, windows_install_source
from homelab.vm import factory_publication


class FactoryPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.releases = self.root / "pxe"
        self.version = "20260727.001"
        self.release_set = self.releases / "release-sets" / self.version
        self.release_set.mkdir(parents=True)
        self.aggregate_bytes = b'{"schema":1,"selected":"exact bytes"}\n'
        aggregate = self.release_set / pxe_release_set.MANIFEST
        aggregate.write_bytes(self.aggregate_bytes)
        for target in pxe_release_set.TARGETS:
            leaf = self.release_set / "targets" / target / self.version
            leaf.mkdir(parents=True)
            (leaf / "boot.ipxe").write_text(f"#!ipxe\n# {target}\n")
        (self.release_set / "targets" / "windows" / self.version
         / "release.json").write_text(json.dumps({
             "source_iso_sha256": "a" * 64,
         }))
        selected = {
            "schema": 1,
            "version": self.version,
            "manifest_sha256": hashlib.sha256(
                self.aggregate_bytes).hexdigest(),
        }
        self.releases.mkdir(exist_ok=True)
        (self.releases / pxe_release_set.SELECTED).write_text(
            json.dumps(selected))
        self.ipxe = self.root / "ipxe.efi"
        self.ipxe.write_bytes(b"verified first stage")
        self.seed = self.root / "seed.iso"
        self.seed.write_bytes(b"verified seed")

    def stage(self, destination, **kwargs):
        def repair(_seed, repair_root):
            repair_root.mkdir()
            package = repair_root / "tftp-hpa-5.2-11-x86_64.pkg.tar.zst"
            package.write_bytes(b"signed package")
            signature = package.with_name(package.name + ".sig")
            signature.write_bytes(b"detached signature")
            return {
                "seed_iso_sha256": "1" * 64,
                "seed_receipt_sha256": "2" * 64,
                "package": {"name": package.name, "size": package.stat().st_size,
                            "sha256": factory_publication.digest(package)},
                "signature": {"name": signature.name,
                              "size": signature.stat().st_size,
                              "sha256": factory_publication.digest(signature)},
                "install": "pacman --noconfirm -U (local archive only, if absent)",
            }
        with mock.patch.object(
                factory_publication, "extract_tftp_repair",
                side_effect=repair):
            return factory_publication.stage(
                self.releases, destination, seed_iso=self.seed,
                ipxe_binary=self.ipxe, **kwargs)

    def extract_receipt(self, payload_files):
        receipt = json.dumps({"payload_files": payload_files}).encode()
        content = {
            "/receipt.json": receipt,
            "/packages/tftp-hpa-5.2-11-x86_64.pkg.tar.zst": b"package",
            "/packages/tftp-hpa-5.2-11-x86_64.pkg.tar.zst.sig": b"signature",
        }

        def extract(command, **_kwargs):
            logical = command[command.index("-extract") + 1]
            Path(command[-1]).write_bytes(content[logical])
            return subprocess.CompletedProcess(command, 0)

        with mock.patch.object(
                factory_publication.subprocess, "run",
                side_effect=extract), \
                mock.patch.object(
                    factory_publication.shutil, "which",
                    return_value="/usr/bin/xorriso"):
            return factory_publication.extract_tftp_repair(
                self.seed, self.root / "repair-extracted")

    @mock.patch.object(pxe_release_set, "verify", return_value=[])
    def test_stages_exact_selected_manifest_and_served_bytes(self, _verify):
        destination = self.root / "publication"
        receipt = self.stage(destination)
        self.assertEqual(
            (destination / pxe_release_set.MANIFEST).read_bytes(),
            self.aggregate_bytes,
        )
        bootstrap = destination / receipt["bootstrap"]
        self.assertIn(
            f"/arch-workstation/{self.version}/boot.ipxe",
            bootstrap.read_text(),
        )
        for name, record in receipt["artifacts"].items():
            artifact = destination / name
            self.assertEqual(record["size"], artifact.stat().st_size)
            self.assertEqual(record["sha256"],
                             factory_publication.digest(artifact))
        sums = (destination / "SHA256SUMS").read_text()
        self.assertIn("release-set.json", sums)
        self.assertIn("www/boot/boot.ipxe", sums)
        self.assertIn("tftp/ipxe.efi", sums)
        self.assertIn("controller/factory-nginx.conf", sums)
        self.assertIn("repair/tftp-hpa-5.2-11-x86_64.pkg.tar.zst", sums)
        publisher = (destination / "publish").read_text()
        self.assertIn("sha256sum --check --strict SHA256SUMS", publisher)
        self.assertIn("cp -a -- www/. /srv/http/homelab/", publisher)
        self.assertIn("TELOS PXE SERVICES READY", publisher)
        self.assertIn("telos-factory-tftp.service", publisher)
        self.assertIn("factory-access.log", publisher)
        self.assertIn("TELOS PXE READINESS FAIL timeout", publisher)
        self.assertIn("systemctl --no-pager --full status", publisher)
        self.assertIn(
            "/etc/systemd/system/NetworkManager.service", publisher)
        self.assertIn(
            "controller/telos-factory-tftp.service", publisher)
        self.assertIn(
            "ExecStart=/usr/bin/nginx -c /etc/homelab/factory-nginx.conf "
            "-g 'daemon off;'",
            publisher,
        )
        self.assertNotIn(
            "ExecStart=/usr/bin/nginx -c /etc/homelab/factory-nginx.conf\n",
            publisher,
        )
        self.assertIn("install -m 0644 tftp/ipxe.efi", publisher)
        self.assertIn("command -v \"$binary\"", publisher)
        self.assertIn("pacman --noconfirm -U", publisher)
        self.assertIn("chmod -R a+rX /srv/http/homelab", publisher)
        self.assertIn("actual == expected", publisher)
        self.assertIn(
            "http://10.1.31.2/arch-workstation/20260727.001/boot.ipxe",
            publisher,
        )
        self.assertEqual(
            receipt["offline_repair"]["seed_iso_sha256"], "1" * 64)
        subprocess.run(
            ["bash", "-n", str(destination / "publish")],
            check=True, capture_output=True)

    @mock.patch.object(pxe_release_set, "verify", return_value=[])
    def test_private_windows_inputs_are_explicit_complete_and_checksummed(
        self, _verify,
    ):
        private = self.root / "run-abc123"
        private.mkdir(mode=0o700)
        for name in factory_publication.PRIVATE_WINDOWS_FILES:
            (private / name).write_text(f"private {name}\n")
        destination = self.root / "publication"
        receipt = self.stage(
            destination, target="windows", private_windows_inputs=private)
        self.assertEqual(receipt["private_windows_run"], "run-abc123")
        bootstrap = destination / receipt["bootstrap"]
        self.assertIn(
            "http://10.1.31.2/private/run-abc123/boot.ipxe",
            bootstrap.read_text())
        sums = (destination / "SHA256SUMS").read_text()
        for name in factory_publication.PRIVATE_WINDOWS_FILES:
            self.assertIn(f"www/private/run-abc123/{name}", sums)
        # The immutable selected release remains byte-for-byte unchanged.
        self.assertEqual(
            (self.release_set / "targets" / "windows" / self.version
             / "boot.ipxe").read_text(),
            "#!ipxe\n# windows\n")

    @mock.patch.object(pxe_release_set, "verify", return_value=[])
    def test_private_windows_inputs_fail_closed_on_missing_or_extra_files(
        self, _verify,
    ):
        private = self.root / "run-abc123"
        private.mkdir()
        (private / "boot.ipxe").write_text("#!ipxe\n")
        with self.assertRaisesRegex(
                factory_publication.PublicationError, "incomplete"):
            self.stage(
                self.root / "publication", target="windows",
                private_windows_inputs=private)

    @mock.patch.object(pxe_release_set, "verify", return_value=[])
    @mock.patch.object(windows_install_source, "verify_cache")
    def test_verified_complete_windows_source_is_private_read_only_smb(
        self, verify_cache, _verify,
    ):
        verify_cache.return_value = {
            "bytes": 1234, "file_count": 2,
            "source_iso_sha256": "a" * 64,
        }
        private = self.root / "run-abc123"
        private.mkdir()
        for name in factory_publication.PRIVATE_WINDOWS_FILES:
            (private / name).write_text(f"private {name}\n")
        source = self.root / "windows-source"
        source.mkdir()
        (source / "receipt.json").write_text('{"schema":1}\n')
        (source / "setup.exe").write_bytes(b"setup")
        destination = self.root / "publication"
        receipt = self.stage(
            destination, target="windows", private_windows_inputs=private,
            windows_source=source)
        verify_cache.assert_called_once_with(source, "a" * 64)
        self.assertEqual(
            receipt["windows_install_source"]["file_count"], 2)
        self.assertTrue((destination / "windows-source/setup.exe").is_file())
        publisher = (destination / "publish").read_text()
        for expected in (
            "bind interfaces only = yes",
            "read only = yes",
            "guest ok = no",
            "valid users = pxe-install",
            "smbpasswd -s -a pxe-install",
            "systemctl enable smb.service",
            "systemctl is-active --quiet smb.service",
            "Requires=telos-factory-http.service "
            "telos-factory-tftp.service smb.service",
        ):
            self.assertIn(expected, publisher)
        self.assertNotIn("private install-password.txt", publisher)
        subprocess.run(
            ["bash", "-n", str(destination / "publish")],
            check=True, capture_output=True)

    @mock.patch.object(pxe_release_set, "verify", return_value=[])
    def test_mismatched_selected_manifest_fails_before_copy(self, _verify):
        selected = self.releases / pxe_release_set.SELECTED
        value = json.loads(selected.read_text())
        value["manifest_sha256"] = "0" * 64
        selected.write_text(json.dumps(value))
        destination = self.root / "publication"
        with self.assertRaisesRegex(
                factory_publication.PublicationError, "does not match"):
            self.stage(destination)
        self.assertFalse(destination.exists())

    @mock.patch.object(
        pxe_release_set, "verify", return_value=["arch-workstation: altered"])
    def test_invalid_release_set_fails_before_copy(self, _verify):
        destination = self.root / "publication"
        with self.assertRaisesRegex(
                factory_publication.PublicationError, "altered"):
            self.stage(destination)
        self.assertFalse(destination.exists())

    @mock.patch.object(pxe_release_set, "verify", return_value=[])
    def test_existing_destination_is_never_replaced(self, _verify):
        destination = self.root / "publication"
        destination.mkdir()
        marker = destination / "owned"
        marker.write_text("preserve")
        with self.assertRaisesRegex(
                factory_publication.PublicationError, "already exists"):
            self.stage(destination)
        self.assertEqual(marker.read_text(), "preserve")

    @mock.patch.object(pxe_release_set, "verify", return_value=[])
    def test_missing_or_empty_ipxe_fails_before_publication(self, _verify):
        self.ipxe.write_bytes(b"")
        destination = self.root / "publication"
        with self.assertRaisesRegex(
                factory_publication.PublicationError, "ipxe.efi"):
            self.stage(destination)
        self.assertFalse(destination.exists())

    def test_extracts_one_receipt_bound_signed_tftp_archive(self):
        package = b"package"
        signature = b"signature"
        records = [
            {"path": "packages/tftp-hpa-5.2-11-x86_64.pkg.tar.zst",
             "bytes": len(package),
             "sha256": hashlib.sha256(package).hexdigest()},
            {"path": "packages/tftp-hpa-5.2-11-x86_64.pkg.tar.zst.sig",
             "bytes": len(signature),
             "sha256": hashlib.sha256(signature).hexdigest()},
        ]
        repair = self.extract_receipt(records)
        self.assertEqual(repair["package"]["name"],
                         "tftp-hpa-5.2-11-x86_64.pkg.tar.zst")
        self.assertRegex(repair["seed_iso_sha256"], r"^[0-9a-f]{64}$")

    def test_tftp_repair_requires_exactly_one_archive_and_signature(self):
        package = b"package"
        record = {
            "path": "packages/tftp-hpa-5.2-11-x86_64.pkg.tar.zst",
            "bytes": len(package),
            "sha256": hashlib.sha256(package).hexdigest(),
        }
        with self.assertRaisesRegex(
                factory_publication.PublicationError, "signature"):
            self.extract_receipt([record])
        other = dict(record)
        other["path"] = "packages/tftp-hpa-5.2-12-x86_64.pkg.tar.zst"
        with self.assertRaisesRegex(
                factory_publication.PublicationError, "exactly one"):
            self.extract_receipt([record, other])


if __name__ == "__main__":
    unittest.main()
