"""Tests for the host- and UniFi-independent simulated topology."""

import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vm import simulated_topology
from vm.manual_verification import SerialVerificationGate


class SimulatedTopologyTests(unittest.TestCase):
    def test_serial_relay_opens_gate_across_chunks(self):
        class ShortReads(io.BytesIO):
            def read(self, _size=-1):
                return super().read(7)

        process = mock.Mock()
        process.stdout = ShortReads(
            b"RESULT PASS: safe to proceed to the separately "
            b"authorized attachment step\r\n")
        process.wait.return_value = 0
        output = io.BytesIO()
        gate = SerialVerificationGate()
        self.assertEqual(
            simulated_topology.relay_controller_serial(
                process, gate, output), 0)
        self.assertTrue(gate.passed)
        self.assertIn(b"RESULT PASS", output.getvalue())

    def test_serial_relay_does_not_accept_near_miss(self):
        process = mock.Mock()
        process.stdout = io.BytesIO(b"RESULT PASS: almost\n")
        process.wait.return_value = 0
        gate = SerialVerificationGate()
        simulated_topology.relay_controller_serial(
            process, gate, io.BytesIO())
        with self.assertRaisesRegex(RuntimeError, "not observed"):
            gate.require_pass()

    def test_has_two_separate_loopback_segments(self):
        with mock.patch.object(
                simulated_topology, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))):
            plans = simulated_topology.commands(
                Path("/controller"), Path("/arch.iso"), Path("/runtime"))
        gateway = " ".join(plans["gateway"])
        controller = " ".join(plans["controller"])
        client = " ".join(plans["client"])
        self.assertIn("listen=127.0.0.1:12971", gateway)
        self.assertIn("listen=127.0.0.1:12972", gateway)
        self.assertIn("connect=127.0.0.1:12971", controller)
        self.assertIn("connect=127.0.0.1:12972", client)

    def test_controller_disk_is_snapshot_only(self):
        with mock.patch.object(
                simulated_topology, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))):
            plans = simulated_topology.commands(
                Path("/controller"), Path("/arch.iso"), Path("/runtime"))
        text = " ".join(plans["controller"])
        self.assertIn("format=qcow2,snapshot=on", text)
        self.assertNotIn("tap,", text)
        self.assertNotIn("user,", text)
        self.assertNotIn("bridge,", text)

    def test_rejects_non_loopback_or_host_backend(self):
        for backend in (
            "socket,id=x,listen=0.0.0.0:12971",
            "tap,id=x,ifname=tap0",
            "user,id=x",
            "socket,id=x,connect=127.0.0.1:70000",
        ):
            with self.subTest(backend=backend):
                plan = [
                    "qemu-system-x86_64", "-nodefaults", "-netdev", backend,
                    "-device", "virtio-net-pci,netdev=x",
                ]
                with self.assertRaises(ValueError):
                    simulated_topology.audit_qemu_argv("controller", plan)

    def test_rejects_extra_nics_shares_and_agents(self):
        valid = [
            "qemu-system-x86_64", "-nodefaults",
            "-netdev", "socket,id=x,connect=127.0.0.1:12971",
            "-device", "virtio-net-pci,netdev=x",
        ]
        additions = (
            ["-netdev", "socket,id=y,connect=127.0.0.1:12972",
             "-device", "virtio-net-pci,netdev=y"],
            ["-virtfs", "local,path=/tmp,mount_tag=host"],
            ["-fsdev", "local,id=share,path=/tmp"],
            ["-device", "virtserialport,name=org.qemu.guest_agent.0"],
            ["-device", "e1000,netdev=rogue"],
            ["-nic", "user"],
            ["-chardev", "socket,id=agent,path=/tmp/agent"],
        )
        for addition in additions:
            with self.subTest(addition=addition):
                with self.assertRaises(ValueError):
                    simulated_topology.audit_qemu_argv(
                        "controller", valid + addition)

    def test_allows_only_one_exact_authorized_private_chardev(self):
        valid = [
            "qemu-system-x86_64", "-nodefaults",
            "-netdev", "socket,id=x,connect=127.0.0.1:12971",
            "-device", "e1000e,netdev=x",
        ]
        serial = (
            "socket,id=telosidentity,path=/private/windows.serial,"
            "server=on,wait=off")
        command = valid + ["-chardev", serial, "-serial",
                           "chardev:telosidentity"]
        simulated_topology.audit_qemu_argv(
            "client", command, allowed_nic_models=("e1000e",),
            allowed_chardevs=(serial,))
        for candidate in (
            command + ["-chardev", serial],
            valid + ["-chardev", serial.replace(
                "/private/", "/different/")],
        ):
            with self.subTest(candidate=candidate), self.assertRaises(
                    ValueError):
                simulated_topology.audit_qemu_argv(
                    "client", candidate, allowed_nic_models=("e1000e",),
                    allowed_chardevs=(serial,))

    def test_live_proc_cmdline_is_reaudited(self):
        argv = [
            "/usr/bin/qemu-system-x86_64", "-nodefaults",
            "-netdev", "socket,id=x,connect=127.0.0.1:12971",
            "-device", "virtio-net-pci,netdev=x",
        ]
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)
            (proc / "123").mkdir()
            (proc / "123" / "cmdline").write_bytes(
                b"\0".join(item.encode() for item in argv) + b"\0")
            simulated_topology.audit_live_process(
                123, "controller", proc_root=proc)
            (proc / "123" / "cmdline").write_bytes(
                b"\0".join(item.encode() for item in argv + [
                    "-nic", "user"]) + b"\0")
            with self.assertRaises(ValueError):
                simulated_topology.audit_live_process(
                    123, "controller", proc_root=proc)

    def test_default_is_dry_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / "controller"
            state.mkdir()
            (state / "bootstrap-dc.qcow2").write_text("disk")
            (state / "OVMF_VARS.fd").write_text("vars")
            iso = root / "arch.iso"
            iso.write_text("iso")
            with mock.patch.object(
                    simulated_topology, "ovmf_pair",
                    return_value=(Path("/code"), Path("/vars"))), \
                    mock.patch.object(
                        simulated_topology.shutil, "which",
                        return_value="/usr/bin/qemu-system-x86_64"), \
                    mock.patch.object(
                        simulated_topology.subprocess, "Popen") as popen:
                self.assertEqual(
                    simulated_topology.run(state, apply=False), 0)
                popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
