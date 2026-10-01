"""The OVMF variable-store reader and its boot-path-cache drop.

Every store is synthetic and built byte by byte (``ovmf_store_fixture``);
nothing reads ``build/``, ``homelab/var/`` or ``homelab/instance/``.
"""

import os
import stat
import struct
import tempfile
import unittest
import uuid
from pathlib import Path

from homelab.tests.ovmf_store_fixture import (
    HDDP_PATH, efi_variable, hddp_variable, load_option_bytes, store,
    variable_store)
from homelab.vm import ovmf_vars

GLOBAL = ovmf_vars.EFI_GLOBAL_VARIABLE
HDDP = (ovmf_vars.HDDP_VENDOR, ovmf_vars.HDDP_NAME)


def mixed_store(*, authenticated: bool = True) -> bytes:
    """Every way a copy can look like the cache without being a live one."""
    def variable(name, vendor, data, **options):
        return efi_variable(name, vendor, data, authenticated=authenticated,
                            **options)

    return variable_store([
        variable("Boot0000", GLOBAL, load_option_bytes("Linux Boot Manager")),
        # An older cache the firmware already deleted, in both deleted states.
        variable("HDDP", ovmf_vars.HDDP_VENDOR, b"old", state=0x3D),
        variable("HDDP", ovmf_vars.HDDP_VENDOR, b"older", state=0x3C),
        # A copy caught mid-update, then the live one.
        hddp_variable(state=ovmf_vars.VAR_ADDED_IN_TRANSITION,
                      authenticated=authenticated),
        hddp_variable(authenticated=authenticated),
        # The same name under another vendor, and a longer name: not the cache.
        variable("HDDP", GLOBAL, b"not the cache"),
        variable("HDDPX", ovmf_vars.HDDP_VENDOR, b"not the cache either"),
        variable("BootOrder", GLOBAL, b"\x00\x00"),
    ], authenticated=authenticated)


def changed(left: bytes, right: bytes) -> list[int]:
    return [index for index in range(len(left)) if left[index] != right[index]]


class WithoutHddpTests(unittest.TestCase):
    def test_only_the_live_cache_copies_are_deleted(self):
        for authenticated in (True, False):
            with self.subTest(authenticated=authenticated):
                data = mixed_store(authenticated=authenticated)
                states = ovmf_vars.hddp_states(data)
                self.assertEqual(len(states), 2)
                cleaned, dropped = ovmf_vars.without_hddp(data)
                self.assertEqual(dropped, 2)
                self.assertEqual(len(cleaned), len(data))
                # Only those two state bytes change, each to its deleted form.
                self.assertEqual(changed(data, cleaned), states)
                self.assertEqual(
                    sorted(cleaned[at] for at in states), [0x3C, 0x3D])
                before = ovmf_vars.firmware_variables(data)
                after = ovmf_vars.firmware_variables(cleaned)
                self.assertEqual(before.pop(HDDP), HDDP_PATH)
                self.assertNotIn(HDDP, after)
                self.assertEqual(after, before)
                self.assertEqual(after[(GLOBAL, "HDDP")], b"not the cache")
                self.assertEqual(ovmf_vars.hddp_states(cleaned), [])

    def test_a_lone_copy_in_transition_is_deleted_too(self):
        data = variable_store([hddp_variable(
            state=ovmf_vars.VAR_ADDED_IN_TRANSITION)])
        self.assertIn(HDDP, ovmf_vars.firmware_variables(data))
        cleaned, dropped = ovmf_vars.without_hddp(data)
        self.assertEqual(dropped, 1)
        self.assertEqual(ovmf_vars.firmware_variables(cleaned), {})

    def test_it_is_idempotent_and_a_clean_store_is_returned_as_is(self):
        once, first = ovmf_vars.without_hddp(mixed_store())
        twice, second = ovmf_vars.without_hddp(once)
        self.assertEqual((first, second), (2, 0))
        self.assertEqual(twice, once)
        clean = store("no cache")
        self.assertEqual(ovmf_vars.without_hddp(clean), (clean, 0))

    def test_what_is_not_a_store_is_refused(self):
        good = store("refusals", hddp=True)
        store_at = struct.unpack_from(
            "<H", good, ovmf_vars.FV_HEADER_LENGTH_OFFSET)[0]
        foreign = bytearray(good)
        foreign[store_at:store_at + 16] = uuid.uuid4().bytes_le
        unformatted = bytearray(good)
        unformatted[store_at + 20] = 0xFF
        runaway = bytearray(good)
        # The first variable's data size, inflated past the store's end.
        struct.pack_into("<I", runaway, store_at + 28 + 40, 1 << 20)
        for label, data, message in (
                ("text", b"installer-authored vars\n" * 8, "firmware volume"),
                ("truncated", good[:40], "firmware volume"),
                ("foreign store", bytes(foreign), "not an EDK2"),
                ("unformatted", bytes(unformatted), "not formatted"),
                ("runaway", bytes(runaway), "past the store")):
            with self.subTest(label), self.assertRaisesRegex(
                    ovmf_vars.FirmwareVariablesError, message):
                ovmf_vars.without_hddp(data)


class CopyWithoutHddpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.source = self.tmp / "retained-OVMF_VARS.fd"
        self.data = store("retained", hddp=True)
        self.source.write_bytes(self.data)
        self.source.chmod(0o640)

    def test_the_copy_is_private_and_the_source_is_only_read(self):
        target = self.tmp / "boot-OVMF_VARS.fd"
        target.write_bytes(b"stale copy, longer than nothing")
        target.chmod(0o644)
        self.assertEqual(ovmf_vars.copy_without_hddp(self.source, target), 1)
        self.assertEqual(target.read_bytes(),
                         ovmf_vars.without_hddp(self.data)[0])
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(self.source.read_bytes(), self.data)
        self.assertEqual(stat.S_IMODE(self.source.stat().st_mode), 0o640)

    def test_a_refused_store_writes_nothing(self):
        self.source.write_bytes(b"not a store")
        target = self.tmp / "boot-OVMF_VARS.fd"
        with self.assertRaises(ovmf_vars.FirmwareVariablesError):
            ovmf_vars.copy_without_hddp(self.source, target)
        self.assertFalse(target.exists())

    def test_a_symlinked_target_is_refused(self):
        elsewhere = self.tmp / "elsewhere.fd"
        elsewhere.write_bytes(b"untouched")
        target = self.tmp / "boot-OVMF_VARS.fd"
        os.symlink(elsewhere, target)
        with self.assertRaises(OSError):
            ovmf_vars.copy_without_hddp(self.source, target)
        self.assertEqual(elsewhere.read_bytes(), b"untouched")


if __name__ == "__main__":
    unittest.main()
