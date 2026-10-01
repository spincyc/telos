"""The raw disk a Samba backup crosses in and out of a persistent instance.

ADR 0081.  The header format has one definition, and both sides of it are
exercised here: the host's writer and reader directly, and the guest's
commands under ``bash`` against an ordinary file standing in for the
virtio-blk device, with a stand-in ``samba-tool``.  Nothing boots, nothing is
elevated, and everything lives in a temporary directory.
"""

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from homelab.vm import samba_backup_disk as disk
from homelab.vm.samba_backup_disk import BackupDiskError, Header

TOKEN = "0123456789abcdef0123456789abcdef"
OTHER_TOKEN = "fedcba9876543210fedcba9876543210"
PAYLOAD = bytes(range(256)) * 1200 + b"tail"
GUEST_TOOLS = (
    "/usr/bin/bash", "/usr/bin/dd", "/usr/bin/truncate", "/usr/bin/sha256sum",
    "/usr/bin/shred", "/usr/bin/head", "/usr/bin/tr", "/usr/bin/mktemp",
    "/usr/bin/find", "/usr/bin/install", "/usr/bin/stat", "/usr/bin/printf",
    "/usr/bin/mv", "/usr/bin/rm",
)
#: A stand-in ``samba-tool``: ``domain backup offline`` writes $FAKE_PAYLOAD
#: as the one tarball; ``domain backup restore`` lays out private/sam.ldb and
#: etc/smb.conf in its target; $FAKE_FAIL makes either fail.
FAKE_SAMBA_TOOL = """#!/bin/sh
[ -n "$FAKE_FAIL" ] && { echo "ERROR: fake failure" >&2; exit 1; }
case "$3" in
offline)
    dir=${4#--targetdir=}
    [ -n "$FAKE_NO_TARBALL" ] && exit 0
    cp "$FAKE_PAYLOAD" "$dir/samba-backup-ad.example-2026-09-30.tar.bz2"
    echo "Creating backup file $dir/samba-backup-ad.example.tar.bz2" ;;
restore)
    file=${4#--backup-file=}
    name=${5#--newservername=}
    target=${6#--targetdir=}
    [ -e "$target" ] && [ -n "$(ls -A "$target")" ] && {
        echo "Target directory is not empty" >&2; exit 1; }
    mkdir -p "$target/private" "$target/etc"
    cp "$file" "$target/private/sam.ldb"
    printf '[global]\\n\\tnetbios name = %s\\n' "$name" > "$target/etc/smb.conf"
    echo "Backup file successfully restored to $target" ;;
*) exit 2 ;;
esac
"""


class HeaderTests(unittest.TestCase):
    def test_a_header_round_trips_and_is_exactly_one_block(self):
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        block = disk.encode_header(len(PAYLOAD), digest, TOKEN)
        self.assertEqual(len(block), disk.HEADER_SIZE)
        self.assertTrue(block.startswith(b"TELOS-SAMBA-BACKUP-V1\nlength="))
        self.assertEqual(
            disk.decode_header(block, capacity=1 << 20),
            Header(len(PAYLOAD), digest, TOKEN))

    def test_every_malformed_header_is_refused(self):
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        good = disk.header_text(len(PAYLOAD), digest, TOKEN).encode()

        def pad(text: bytes) -> bytes:
            return text + b"\0" * (disk.HEADER_SIZE - len(text))

        variants = {
            "short block": good,
            "no magic": pad(good.replace(b"TELOS-SAMBA-BACKUP-V1", b"OTHER")),
            "wrong version": pad(good.replace(b"-V1", b"-V2")),
            "extra line": pad(good + b"note=x\n"),
            "bytes after the end": pad(good)[:-1] + b"x",
            "zero length": pad(good.replace(
                f"length={len(PAYLOAD)}".encode(), b"length=0")),
            "leading zero": pad(good.replace(
                f"length={len(PAYLOAD)}".encode(), b"length=0300")),
            "too long for the disk": pad(good.replace(
                f"length={len(PAYLOAD)}".encode(), b"length=99999999")),
            "upper-case digest": pad(good.replace(
                digest.encode(), digest.upper().encode())),
            "short token": pad(good.replace(TOKEN.encode(), b"0123")),
            "reordered": pad(good.replace(b"length=", b"lenght=")),
            "not text": pad(b"\xff" + good),
        }
        for name, block in variants.items():
            with self.subTest(variant=name):
                with self.assertRaises(BackupDiskError):
                    disk.decode_header(block, capacity=1 << 20)

    def test_the_encoder_refuses_what_the_decoder_would(self):
        digest = "a" * 64
        for args in ((0, digest, TOKEN), (True, digest, TOKEN),
                     (1, "A" * 64, TOKEN), (1, digest, "x" * 32),
                     (1, digest[:-1], TOKEN)):
            with self.subTest(args=args):
                with self.assertRaises(BackupDiskError):
                    disk.encode_header(*args)


class DiskFileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_a_blank_disk_is_new_private_sparse_and_whole_blocks(self):
        path = disk.create_blank(self.root / "out.raw", 1 << 20)
        self.assertEqual(path.stat().st_size, 1 << 20)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.read_bytes(), b"\0" * (1 << 20))
        with self.assertRaises(FileExistsError):
            disk.create_blank(path, 1 << 20)
        for size in (disk.HEADER_SIZE, (1 << 20) + 1):
            with self.subTest(size=size):
                with self.assertRaises(BackupDiskError):
                    disk.create_blank(self.root / f"{size}.raw", size)

    def test_an_image_round_trips_through_the_reader(self):
        path = self.root / "in.raw"
        header = disk.write_image(path, PAYLOAD, TOKEN)
        self.assertEqual(path.stat().st_size % disk.INPUT_ALIGNMENT, 0)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        payload, read = disk.read_payload(path, token=TOKEN)
        self.assertEqual(payload, PAYLOAD)
        self.assertEqual(read, header)

    def test_corruption_another_runs_token_and_truncation_are_refused(self):
        path = self.root / "in.raw"
        disk.write_image(path, PAYLOAD, TOKEN)
        with self.assertRaisesRegex(BackupDiskError, "another run"):
            disk.read_payload(path, token=OTHER_TOKEN)
        data = bytearray(path.read_bytes())
        data[disk.HEADER_SIZE + 1000] ^= 0xFF
        path.write_bytes(bytes(data))
        with self.assertRaisesRegex(BackupDiskError, "does not match"):
            disk.read_payload(path, token=TOKEN)
        path.write_bytes(bytes(data[:disk.HEADER_SIZE + 10]))
        with self.assertRaises(BackupDiskError):
            disk.read_payload(path, token=TOKEN)
        blank = disk.create_blank(self.root / "blank.raw", 1 << 20)
        with self.assertRaisesRegex(BackupDiskError, "no Telos"):
            disk.read_payload(blank, token=TOKEN)
        link = self.root / "link.raw"
        link.symlink_to(blank)
        with self.assertRaises(BackupDiskError):
            disk.read_payload(link, token=TOKEN)

    def test_shredding_overwrites_what_was_written_then_unlinks(self):
        path = disk.create_blank(self.root / "out.raw", 1 << 20)
        with path.open("r+b") as stream:
            stream.write(disk.encode_header(
                len(PAYLOAD), hashlib.sha256(PAYLOAD).hexdigest(), TOKEN))
            stream.write(PAYLOAD)
        witness = self.root / "witness"
        os.link(path, witness)
        disk.shred_disk(path)
        self.assertFalse(path.exists())
        after = witness.read_bytes()
        self.assertEqual(len(after), 1 << 20)
        self.assertNotIn(PAYLOAD[:4096], after)
        self.assertNotIn(b"TELOS-SAMBA-BACKUP", after)


class GuestCommandTests(unittest.TestCase):
    """The guest's own commands, run under bash against a plain file."""

    def setUp(self):
        for tool in GUEST_TOOLS:
            if not Path(tool).exists():
                self.skipTest(f"{tool} is not installed")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.tool = self.root / "samba-tool"
        self.tool.write_text(FAKE_SAMBA_TOOL)
        self.tool.chmod(0o700)
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        self.payload = self.root / "payload.tar.bz2"
        self.payload.write_bytes(PAYLOAD)
        self.env = {"PATH": "/usr/bin:/bin",
                    "FAKE_PAYLOAD": str(self.payload)}

    def guest(self, command: str, **env: str) -> tuple[str, str]:
        """Run *command* the way ``_console_root`` captures a value."""
        self.assertNotIn("\n", command)
        result = subprocess.run(
            ["/usr/bin/bash", "-c",
             f"__telos_value=$({command}); "
             "printf '%s' \"$__telos_value\""],
            capture_output=True, text=True, env={**self.env, **env},
            check=True)
        return result.stdout, result.stderr

    def backup(self, device: Path, capacity: int = 4 << 20, **env):
        command = disk.backup_command(
            str(device), TOKEN, capacity=capacity, samba_tool=str(self.tool),
            tmp_root=str(self.tmp), require_block_device=False)
        return self.guest(command, **env)

    def test_the_guest_writes_what_the_host_reads_and_keeps_no_copy(self):
        device = disk.create_blank(self.root / "out.raw", 4 << 20)
        proof, log = self.backup(device)
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        self.assertEqual(proof, f"{digest}:{len(PAYLOAD)}")
        self.assertTrue(re.fullmatch(disk.BACKUP_PROOF, proof.encode()))
        self.assertIn("Creating backup file", log)
        payload, header = disk.read_payload(device, token=TOKEN)
        self.assertEqual(payload, PAYLOAD)
        self.assertEqual(f"{header.sha256}:{header.length}", proof)
        # The guest's temporary directory, and the tarball in it, are gone.
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_each_guest_failure_names_its_step_and_cleans_up(self):
        for env, capacity, step in (
                ({"FAKE_FAIL": "1"}, 4 << 20, "samba-tool"),
                ({"FAKE_NO_TARBALL": "1"}, 4 << 20, "tarball"),
                ({}, 64 << 10, "capacity")):
            with self.subTest(step=step):
                device = self.root / f"{step}.raw"
                disk.create_blank(device, capacity)
                proof, _ = self.backup(device, capacity, **env)
                self.assertEqual(proof, f"FAIL:{step}")
                self.assertTrue(re.fullmatch(disk.BACKUP_PROOF,
                                             proof.encode()))
                self.assertEqual(list(self.tmp.iterdir()), [])
                with self.assertRaises(BackupDiskError):
                    disk.read_payload(device, token=TOKEN)

    def test_the_real_command_requires_the_block_device(self):
        command = disk.backup_command(
            disk.device_path("TELOS-BACKUP-OUT"), TOKEN)
        self.assertIn("test -b /dev/disk/by-id/virtio-TELOS-BACKUP-OUT",
                      command)
        self.assertIn("/usr/bin/samba-tool domain backup offline", command)
        self.assertIn(TOKEN, command)
        proof, _ = self.guest(command.replace(
            "/dev/disk/by-id/virtio-TELOS-BACKUP-OUT",
            str(self.root / "not-a-device")))
        self.assertEqual(proof, "FAIL:device")

    def restore(self, image: Path, header: Header, name="dr-2609301200",
                **env):
        self.state = self.root / "var-lib-samba"
        self.conf = self.root / "etc" / "samba" / "smb.conf"
        command = disk.restore_command(
            str(image), header, name, samba_tool=str(self.tool),
            state_root=str(self.state), smb_conf=str(self.conf),
            tmp_root=str(self.tmp), require_block_device=False)
        self.assertNotIn(PAYLOAD[:16].hex(), command)
        return self.guest(command, **env)

    def test_a_restore_reads_the_disk_proves_it_and_lays_out_samba(self):
        image = self.root / "in.raw"
        header = disk.write_image(image, PAYLOAD, TOKEN)
        (self.root / "var-lib-samba" / "private").mkdir(parents=True)
        proof, log = self.restore(image, header)
        self.assertEqual(proof, "RESTORED")
        self.assertIn("successfully restored", log)
        self.assertEqual(
            (self.state / "private" / "sam.ldb").read_bytes(), PAYLOAD)
        self.assertIn("netbios name = dr-2609301200", self.conf.read_text())
        self.assertEqual(self.conf.stat().st_mode & 0o777, 0o644)
        # The package's own (empty) tree was set aside, not merged into.
        self.assertTrue((self.root / "var-lib-samba.pre-restore"
                         / "private").is_dir())
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_a_restore_refuses_a_foreign_corrupt_or_occupied_disk(self):
        image = self.root / "in.raw"
        header = disk.write_image(image, PAYLOAD, TOKEN)
        cases = {
            "header": Header(header.length, header.sha256, OTHER_TOKEN),
            "checksum": Header(header.length, "0" * 64, TOKEN),
        }
        for step, claimed in cases.items():
            with self.subTest(step=step):
                if step == "checksum":
                    # The disk's own header must agree, so corrupt the data.
                    data = bytearray(image.read_bytes())
                    data[disk.HEADER_SIZE + 5] ^= 0xFF
                    image.write_bytes(bytes(data))
                    claimed = header
                proof, _ = self.restore(image, claimed)
                self.assertEqual(proof, f"FAIL:{step}")
                self.assertFalse((self.root / "var-lib-samba").exists())
        image = self.root / "clean.raw"
        header = disk.write_image(image, PAYLOAD, TOKEN)
        conf = self.root / "etc" / "samba" / "smb.conf"
        conf.parent.mkdir(parents=True)
        conf.write_text("[global]\n")
        proof, _ = self.restore(image, header)
        self.assertEqual(proof, "FAIL:precondition")
        conf.unlink()
        (self.root / "var-lib-samba" / "private").mkdir(parents=True)
        (self.root / "var-lib-samba" / "private" / "sam.ldb").write_bytes(b"x")
        proof, _ = self.restore(image, header)
        self.assertEqual(proof, "FAIL:precondition")
        self.assertEqual(
            (self.root / "var-lib-samba" / "private" / "sam.ldb").read_bytes(),
            b"x")

    def test_a_restore_takes_only_a_name_the_domain_never_held(self):
        header = Header(10, "a" * 64, TOKEN)
        for name in ("", "BOOTSTRAP-DC", "1dc", "dc-", "a" * 16, "dc_1",
                     "dc;rm"):
            with self.subTest(name=name):
                with self.assertRaises(BackupDiskError):
                    disk.restore_command("/dev/x", header, name)
        command = disk.restore_command(
            disk.device_path("TELOS-BACKUP-IN"), header, "dr-2609301200")
        self.assertIn(
            "/usr/bin/samba-tool domain backup restore "
            '--backup-file="$d/backup.tar.bz2" --newservername=dr-2609301200 '
            "--targetdir=/var/lib/samba", command)
        self.assertIn("/usr/bin/install -D -m 0644 /var/lib/samba/etc/smb.conf "
                      "/etc/samba/smb.conf", command)
        self.assertNotIn("\n", command)


if __name__ == "__main__":
    unittest.main()
