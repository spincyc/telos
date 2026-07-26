"""Tests for the installation manifest.

The important property is negative and enforced in code: a manifest cannot be
built containing anything that looks like a credential. It is written to a file
readable by anyone who can unlock the root, and it is the obvious thing for a
future operator to paste into a bug report, so the guard has to be structural.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import manifest  # noqa: E402
from hardware import Disk, Firmware, Interface  # noqa: E402
from manifest import ManifestError  # noqa: E402
from netplan import build_plan  # noqa: E402

FIRMWARE = Firmware(uefi=True, secure_boot="disabled", tpm2=True)
DISK = Disk("/dev/nvme0n1", "Samsung SSD 9100 PRO 4TB", "S7YANJ0Y405056D",
            4000787030016, False, False, "nvme")
NIC = Interface("eno1", "60:cf:84:77:c6:6f", True, 10000, False)
PLAN = build_plan({
    "managed_ipv4_cidr": "10.0.7.0/24",
    "controller_ipv4_address": "10.0.7.2",
    "dhcp_pool_start": "10.0.7.100",
    "dhcp_pool_end": "10.0.7.200",
})


def build(**overrides):
    arguments = dict(
        installer_version="0.1.0", installed_at="2026-07-26T09:00:00Z",
        profile="controller", hostname="polycarp", development_proof=True,
        firmware=FIRMWARE, target_disk=DISK, managed_interface=NIC,
        network_plan=PLAN,
        partitions=[{"number": 1, "role": "esp", "size_bytes": 2 * 2**30},
                    {"number": 2, "role": "luks2", "size_bytes": 0}],
        verified_artifacts={"archiso.iso": "abc123"},
    )
    arguments.update(overrides)
    return manifest.build(**arguments)


class TestContents(unittest.TestCase):
    def test_records_identity_and_provenance(self):
        document = build()
        self.assertEqual(document["schema"], manifest.SCHEMA_VERSION)
        self.assertEqual(document["hostname"], "polycarp")
        self.assertEqual(document["fqdn"], "polycarp.home.arpa")
        self.assertEqual(document["installer_version"], "0.1.0")

    def test_records_the_development_proof_label(self):
        # ADR 0043: a recorded project state, not a remembered one.
        self.assertIs(build(development_proof=True)["development_proof"], True)
        self.assertIs(build(development_proof=False)["development_proof"], False)

    def test_records_the_disk_by_serial(self):
        self.assertEqual(build()["target_disk"]["serial"], "S7YANJ0Y405056D")

    def test_records_the_permanent_mac_as_the_interface_identity(self):
        # ADR 0050.
        interface = build()["managed_interface"]
        self.assertEqual(interface["permanent_mac"], "60:cf:84:77:c6:6f")
        self.assertEqual(interface["stable_name"], "lan0")

    def test_records_entered_and_derived_network_values(self):
        # ADR 0045 requires both, not just what was typed.
        network = build()["network"]
        self.assertEqual(network["entered"]["controller_ipv4_address"], "10.0.7.2")
        self.assertEqual(network["derived"]["netmask"], "255.255.255.0")
        self.assertEqual(network["derived"]["dns_server"], "10.0.7.2")
        self.assertIsNone(network["default_router"])

    def test_records_observed_firmware_state(self):
        firmware = build()["firmware_observed"]
        self.assertTrue(firmware["uefi"])
        self.assertEqual(firmware["secure_boot"], "disabled")

    def test_a_workstation_manifest_omits_controller_fields(self):
        document = build(profile="workstation", managed_interface=None, network_plan=None)
        self.assertNotIn("managed_interface", document)
        self.assertNotIn("network", document)


class TestNoSecrets(unittest.TestCase):
    def test_a_credential_shaped_key_is_refused(self):
        for key in ("passphrase", "luks_passphrase", "recovery_key", "api_token",
                    "private_key", "smb_password", "secret_value"):
            with self.subTest(key=key):
                with self.assertRaises(ManifestError):
                    manifest.assert_non_secret({"extra": {key: "x"}})

    def test_key_material_is_refused_whatever_the_field_is_called(self):
        with self.assertRaisesRegex(ManifestError, "key material"):
            manifest.assert_non_secret(
                {"notes": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA"})

    def test_a_password_hash_is_refused(self):
        with self.assertRaises(ManifestError):
            manifest.assert_non_secret({"root": "$6$rounds=5000$abc$def"})

    def test_nested_and_listed_values_are_checked(self):
        with self.assertRaises(ManifestError):
            manifest.assert_non_secret({"hosts": [{"auth": {"token": "abc"}}]})

    def test_a_fingerprint_is_allowed(self):
        # Recording an identity is the whole point; recording the material is not.
        manifest.assert_non_secret(
            {"secure_boot_certificate_fingerprint": "SHA256:0a1b2c"})

    def test_the_real_manifest_passes(self):
        manifest.assert_non_secret(build())

    def test_build_refuses_rather_than_writing(self):
        # The guard runs inside build(), so a bad field cannot reach a file.
        with self.assertRaises(ManifestError):
            build(verified_artifacts={"signing_passphrase": "hunter2"})


class TestSerialisation(unittest.TestCase):
    def test_render_is_stable(self):
        self.assertEqual(manifest.render(build()), manifest.render(build()))

    def test_render_is_valid_json(self):
        self.assertEqual(json.loads(manifest.render(build()))["hostname"], "polycarp")

    def test_console_block_round_trips(self):
        # ADR 0060: the harness captures the manifest from the console, so the
        # markers are a contract rather than decoration.
        noise_before = "[3/9] set up the LUKS2 container\n"
        noise_after = "\n[4/9] create the Btrfs subvolumes\n"
        stream = noise_before + "\n".join(manifest.console_block(build())) + noise_after
        recovered = manifest.extract_from_console(stream)
        self.assertEqual(recovered["hostname"], "polycarp")
        self.assertEqual(recovered["target_disk"]["serial"], "S7YANJ0Y405056D")

    def test_missing_manifest_in_output_is_an_error(self):
        with self.assertRaises(ManifestError):
            manifest.extract_from_console("[1/9] probing hardware\n")


if __name__ == "__main__":
    unittest.main()
