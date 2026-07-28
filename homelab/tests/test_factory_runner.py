"""Contract tests for the bounded concurrent factory skeleton."""

import subprocess
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm import factory_runner
from homelab.vm.qemu_boundary import audit_disposable_controller


class FactoryRunnerTests(unittest.TestCase):
    def test_switch_port_readiness_requires_one_exact_json_object(self):
        with tempfile.TemporaryDirectory() as name:
            evidence = Path(name) / "switch.jsonl"
            evidence.write_text(
                '{"event":"switch-ready","ports":['
                '{"port":"gateway","mac":"52:54:00:31:11:01"}]}\n'
                '{"event":"port-connected","port":"controller",'
                '"mac":"52:54:00:31:11:01","generation":1,'
                '"transaction":"201851"}\n'
                '{"event":"port-connected","port":"other",'
                '"mac":"52:54:00:31:11:01","generation":1}\n'
                '{"event":"other","port":"gateway",'
                '"mac":"52:54:00:31:11:01","generation":1}\n'
                '{"event":"port-connected","port":"gateway",'
                '"mac":"52:54:00:31:11:99","generation":1}\n'
                '{"event":"port-connected","port":"gateway"\n')
            with self.assertRaisesRegex(RuntimeError, "pinned switch port"):
                factory_runner.wait_for_switch_port(
                    evidence, "gateway", factory_runner.GATEWAY_MAC,
                    timeout=0.01)
            with evidence.open("a") as output:
                output.write(
                    '{"event":"port-connected","port":"gateway",'
                    '"mac":"52:54:00:31:11:01","generation":true}\n')
            with self.assertRaisesRegex(RuntimeError, "pinned switch port"):
                factory_runner.wait_for_switch_port(
                    evidence, "gateway", factory_runner.GATEWAY_MAC,
                    timeout=0.01)
            with evidence.open("a") as output:
                output.write(
                    '{"event":"port-connected","port":"gateway",'
                    '"mac":"52:54:00:31:11:01","generation":1}\n')
            factory_runner.wait_for_switch_port(
                evidence, "gateway", factory_runner.GATEWAY_MAC,
                timeout=0.01)

    def test_plain_dhcp_readiness_rejects_mixed_spoofed_and_pxe_records(self):
        expected = "52:54:00:31:12:12"

        def event(kind, transaction, **extra):
            source = (
                expected if kind in {"DISCOVER", "REQUEST"}
                else factory_runner.GATEWAY_MAC
            )
            peer = (
                "workstation" if kind in {"DISCOVER", "REQUEST"}
                else "gateway"
            )
            record = {
                "event": "dhcp", "kind": kind, "transaction": transaction,
                "source_mac": source, "client_mac": expected, "peer": peer,
            }
            if kind in {"OFFER", "ACK"}:
                record.update({
                    "delivered_to": "workstation",
                    "offered_ip": "10.1.31.11",
                })
            if kind == "REQUEST":
                record["requested_ip"] = "10.1.31.11"
            record.update(extra)
            return json.dumps(record)

        invalid_cases = (
            [
                event("DISCOVER", "00000001"), event("OFFER", "00000002"),
                event("REQUEST", "00000001"), event("ACK", "00000002"),
            ],
            [
                event("DISCOVER", "00000001",
                      source_mac="52:54:00:31:12:99"),
                event("OFFER", "00000001"), event("REQUEST", "00000001"),
                event("ACK", "00000001"),
            ],
            [
                event("DISCOVER", "00000001"), event("OFFER", "00000001"),
                event("REQUEST", "00000001"), event("ACK", "00000001",
                                               boot_file="ipxe.efi"),
            ],
            [
                '{"event":"dhcp","kind":"DISCOVER"',
                event("OFFER", "00000001"), event("REQUEST", "00000001"),
                event("ACK", "00000001"),
            ],
            [
                event("OFFER", "00000001"), event("DISCOVER", "00000001"),
                event("REQUEST", "00000001"), event("ACK", "00000001"),
            ],
            [
                event("DISCOVER", "00000001"), event("OFFER", "00000001"),
                event("OFFER", "00000001"), event("REQUEST", "00000001"),
                event("ACK", "00000001"),
            ],
            [
                event("DISCOVER", "00000001"),
                event("OFFER", "00000001", delivered_to="controller"),
                event("REQUEST", "00000001"), event("ACK", "00000001"),
            ],
            [
                event("DISCOVER", "00000001", architecture=7),
                event("OFFER", "00000001"), event("REQUEST", "00000001"),
                event("ACK", "00000001"),
            ],
            [
                event("DISCOVER", "00000001"),
                event("OFFER", "00000001",
                      client_mac="52:54:00:31:12:99"),
                event("REQUEST", "00000001"), event("ACK", "00000001"),
            ],
            [
                event("DISCOVER", "00000001"), event("OFFER", "00000001"),
                event("REQUEST", "00000001"), event("NAK", "00000001"),
                event("ACK", "00000001"),
            ],
        )
        for records in invalid_cases:
            with self.subTest(records=records):
                with tempfile.TemporaryDirectory() as name:
                    evidence = Path(name) / "switch.jsonl"
                    evidence.write_text("\n".join(records) + "\n")
                    with self.assertRaisesRegex(RuntimeError, "DHCP readiness"):
                        factory_runner.wait_for_plain_dhcp_transaction(
                            evidence, "workstation", expected, timeout=0.01)

        with tempfile.TemporaryDirectory() as name:
            evidence = Path(name) / "switch.jsonl"
            evidence.write_text("\n".join(
                event(kind, "deadbeef") for kind in
                ("DISCOVER", "OFFER", "REQUEST", "ACK")) + "\n")
            factory_runner.wait_for_plain_dhcp_transaction(
                evidence, "workstation", expected, timeout=0.01)

    def test_readiness_is_scoped_to_cursor_and_connection_generation(self):
        expected = "52:54:00:31:12:12"

        def transaction(generation, transaction_id="deadbeef"):
            common = (
                f'"event":"dhcp","transaction":"{transaction_id}",'
                f'"client_mac":"{expected}"'
            )
            return [
                "{" + common + ',"kind":"DISCOVER","peer":"workstation",'
                f'"source_mac":"{expected}","peer_generation":{generation}}}',
                "{" + common + ',"kind":"OFFER","peer":"gateway",'
                f'"source_mac":"{factory_runner.GATEWAY_MAC}",'
                '"offered_ip":"10.1.31.11","delivered_to":"workstation",'
                f'"peer_generation":1,"delivered_to_generation":{generation}}}',
                "{" + common + ',"kind":"REQUEST","peer":"workstation",'
                f'"source_mac":"{expected}","requested_ip":"10.1.31.11",'
                f'"peer_generation":{generation}}}',
                "{" + common + ',"kind":"ACK","peer":"gateway",'
                f'"source_mac":"{factory_runner.GATEWAY_MAC}",'
                '"offered_ip":"10.1.31.11","delivered_to":"workstation",'
                f'"peer_generation":1,"delivered_to_generation":{generation}}}',
            ]

        with tempfile.TemporaryDirectory() as name:
            evidence = Path(name) / "switch.jsonl"
            evidence.write_text("\n".join(transaction(1)) + "\n")
            cursor = factory_runner.capture_switch_evidence_cursor(evidence)
            with self.assertRaisesRegex(RuntimeError, "DHCP readiness"):
                factory_runner.wait_for_plain_dhcp_transaction(
                    evidence, "workstation", expected, timeout=0.01,
                    after=cursor, generation=2, gateway_generation=1)
            with evidence.open("a") as output:
                output.write("\n".join(transaction(1)) + "\n")
            with self.assertRaisesRegex(RuntimeError, "DHCP readiness"):
                factory_runner.wait_for_plain_dhcp_transaction(
                    evidence, "workstation", expected, timeout=0.01,
                    after=cursor, generation=2, gateway_generation=1)
            with evidence.open("a") as output:
                output.write("\n".join(transaction(2, "cafebabe")) + "\n")
            factory_runner.wait_for_plain_dhcp_transaction(
                evidence, "workstation", expected, timeout=0.01,
                after=cursor, generation=2, gateway_generation=1)

    def test_dhcp_readiness_rejects_boolean_connection_generations(self):
        expected = "52:54:00:31:12:12"
        base = [
            {
                "event": "dhcp", "kind": "DISCOVER",
                "transaction": "deadbeef", "client_mac": expected,
                "peer": "workstation", "source_mac": expected,
                "peer_generation": 1,
            },
            {
                "event": "dhcp", "kind": "OFFER",
                "transaction": "deadbeef", "client_mac": expected,
                "peer": "gateway",
                "source_mac": factory_runner.GATEWAY_MAC,
                "offered_ip": "10.1.31.11", "delivered_to": "workstation",
                "peer_generation": 1, "delivered_to_generation": 1,
            },
            {
                "event": "dhcp", "kind": "REQUEST",
                "transaction": "deadbeef", "client_mac": expected,
                "peer": "workstation", "source_mac": expected,
                "requested_ip": "10.1.31.11", "peer_generation": 1,
            },
            {
                "event": "dhcp", "kind": "ACK",
                "transaction": "deadbeef", "client_mac": expected,
                "peer": "gateway",
                "source_mac": factory_runner.GATEWAY_MAC,
                "offered_ip": "10.1.31.11", "delivered_to": "workstation",
                "peer_generation": 1, "delivered_to_generation": 1,
            },
        ]
        for record_index, field in (
            (0, "peer_generation"),
            (1, "peer_generation"),
            (1, "delivered_to_generation"),
        ):
            with self.subTest(record_index=record_index, field=field):
                records = [dict(record) for record in base]
                records[record_index][field] = True
                with tempfile.TemporaryDirectory() as name:
                    evidence = Path(name) / "switch.jsonl"
                    evidence.write_text(
                        "".join(json.dumps(record) + "\n"
                                for record in records))
                    with self.assertRaisesRegex(
                            RuntimeError, "DHCP readiness"):
                        factory_runner.wait_for_plain_dhcp_transaction(
                            evidence, "workstation", expected, timeout=0.01,
                            generation=1, gateway_generation=1)

    def test_readiness_rejects_invalid_expected_generations(self):
        evidence = Path("unused-switch-evidence.jsonl")
        invalid = (True, False, 0, -1, "1", 1.0)
        for generation in invalid:
            with self.subTest(api="dhcp-workstation", generation=generation):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    factory_runner.wait_for_plain_dhcp_transaction(
                        evidence, "workstation", "52:54:00:31:12:12",
                        timeout=0.01, generation=generation)
            with self.subTest(api="dhcp-gateway", generation=generation):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    factory_runner.wait_for_plain_dhcp_transaction(
                        evidence, "workstation", "52:54:00:31:12:12",
                        timeout=0.01, gateway_generation=generation)
            with self.subTest(api="disconnect", generation=generation):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    factory_runner.wait_for_switch_disconnect(
                        evidence, "workstation", "52:54:00:31:12:12",
                        generation, timeout=0.01)
        with self.assertRaisesRegex(ValueError, "positive integer"):
            factory_runner.wait_for_switch_disconnect(
                evidence, "workstation", "52:54:00:31:12:12",
                None, timeout=0.01)

    def test_switch_cursor_rejects_replacement_and_ignores_partial_suffix(self):
        with tempfile.TemporaryDirectory() as name:
            evidence = Path(name) / "switch.jsonl"
            evidence.write_text('{"event":"switch-ready"}\n')
            cursor = factory_runner.capture_switch_evidence_cursor(evidence)
            evidence.write_text("")
            with self.assertRaisesRegex(RuntimeError, "truncated"):
                factory_runner.wait_for_switch_port(
                    evidence, "gateway", factory_runner.GATEWAY_MAC,
                    timeout=0.01, after=cursor)
            evidence.unlink()
            evidence.write_text('{"event":"switch-ready"}\n')
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                factory_runner.wait_for_switch_port(
                    evidence, "gateway", factory_runner.GATEWAY_MAC,
                    timeout=0.01, after=cursor)

        with tempfile.TemporaryDirectory() as name:
            evidence = Path(name) / "switch.jsonl"
            evidence.write_text('{"event":"switch-ready"}\n')
            cursor = factory_runner.capture_switch_evidence_cursor(evidence)
            record = (
                '{"event":"port-connected","port":"gateway",'
                f'"mac":"{factory_runner.GATEWAY_MAC}","generation":1}}')
            with evidence.open("a") as output:
                output.write(record)
            with self.assertRaisesRegex(RuntimeError, "pinned switch port"):
                factory_runner.wait_for_switch_port(
                    evidence, "gateway", factory_runner.GATEWAY_MAC,
                    timeout=0.01, after=cursor)
            with evidence.open("a") as output:
                output.write("\n")
            self.assertEqual(factory_runner.wait_for_switch_port(
                evidence, "gateway", factory_runner.GATEWAY_MAC,
                timeout=0.01, after=cursor), 1)

    def test_failure_evidence_is_private_bounded_and_redacted(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            runtime = root / "runtime"
            runtime.mkdir()
            (runtime / "controller-publication.log").write_bytes(
                b"x" * (factory_runner.EVIDENCE_LIMIT + 10)
                + b"\npassword=exposed\n")
            destination = factory_runner.retain_failure_evidence(
                runtime, root / "evidence", RuntimeError("token=exposed"))
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            log = destination / "controller-publication.log"
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            self.assertLessEqual(log.stat().st_size,
                                 factory_runner.EVIDENCE_LIMIT)
            self.assertNotIn(b"exposed", log.read_bytes())
            result = destination / "result.json"
            self.assertEqual(result.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("exposed", result.read_text())

    def test_success_evidence_is_retained_without_an_error(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            runtime = root / "runtime"
            runtime.mkdir()
            (runtime / "workstation-serial.log").write_text("archiso login: ")
            destination = factory_runner.retain_evidence(
                runtime, root / "evidence", status="pass")
            result = json.loads((destination / "result.json").read_text())
            self.assertEqual(result["status"], "pass")
            self.assertNotIn("error", result)

    def test_publication_and_service_readiness_timeouts_are_distinct(self):
        read_fd, write_fd = __import__("os").pipe()
        reader = __import__("os").fdopen(read_fd, "rb", buffering=0)

        class Process:
            stdin = __import__("io").BytesIO()
            stdout = reader

            @staticmethod
            def poll():
                return None

        def emit():
            __import__("os").write(
                write_fd, b"#\nTELOS PXE PUBLICATION PASS\n")

        thread = threading.Thread(target=emit)
        thread.start()
        with tempfile.TemporaryDirectory() as temp_name:
            with self.assertRaisesRegex(RuntimeError, "services.*ready"):
                factory_runner.activate_publication(
                    Process(), Path(temp_name) / "serial.log", timeout=0.1)
        thread.join()
        __import__("os").close(write_fd)
        reader.close()

    def test_initial_prompt_is_not_mistaken_for_bootstrap_return(self):
        os = __import__("os")
        read_fd, write_fd = os.pipe()
        reader = os.fdopen(read_fd, "rb", buffering=0)

        class Process:
            stdin = __import__("io").BytesIO()
            stdout = reader

            @staticmethod
            def poll():
                return None

        def emit():
            os.write(write_fd, b"[root@controller /]#")
            __import__("time").sleep(0.02)
            os.write(write_fd, b"\nTELOS PXE SERVICES READY\n")

        thread = threading.Thread(target=emit)
        thread.start()
        with tempfile.TemporaryDirectory() as temp_name:
            factory_runner.activate_publication(
                Process(), Path(temp_name) / "serial.log", timeout=0.5)
        thread.join()
        os.close(write_fd)
        reader.close()

    def test_intermediate_output_does_not_rematch_initial_prompt(self):
        os = __import__("os")
        read_fd, write_fd = os.pipe()
        reader = os.fdopen(read_fd, "rb", buffering=0)

        class Process:
            stdin = __import__("io").BytesIO()
            stdout = reader

            @staticmethod
            def poll():
                return None

        def emit():
            os.write(write_fd, b"[root@controller /]#")
            __import__("time").sleep(0.02)
            os.write(write_fd, b"\nbootstrap starting\n")
            __import__("time").sleep(0.02)
            os.write(write_fd, b"TELOS PXE SERVICES READY\n")

        thread = threading.Thread(target=emit)
        thread.start()
        with tempfile.TemporaryDirectory() as temp_name:
            factory_runner.activate_publication(
                Process(), Path(temp_name) / "serial.log", timeout=0.5)
        thread.join()
        os.close(write_fd)
        reader.close()

    def test_package_progress_hash_is_not_a_shell_prompt(self):
        self.assertFalse(factory_runner._at_root_prompt(
            b"(1/1) checking package integrity [############"))
        self.assertTrue(factory_runner._at_root_prompt(
            b"\x1b[?2004h[root@archlinux /]# "))

    def test_direct_script_help_resolves_local_imports(self):
        result = subprocess.run(
            [
                "python3", str(Path(factory_runner.__file__).resolve()),
                "--help",
            ],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--releases", result.stdout)

    def test_commands_use_one_loopback_switch_and_disposable_paths(self):
        with mock.patch.object(
                factory_runner, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch(
                    "homelab.vm.simulated_topology.ovmf_pair",
                    return_value=(Path("/code"), Path("/vars"))):
            plans = factory_runner.qemu_commands(
                Path("/run/controller.qcow2"),
                Path("/run/controller-vars.fd"),
                Path("/run/workstation.qcow2"),
                Path("/run/workstation-vars.fd"),
                31415,
                None,
            )
        self.assertEqual(set(plans), {"controller", "workstation"})
        for command in plans.values():
            text = " ".join(command)
            self.assertIn("connect=127.0.0.1:31415", text)
            self.assertNotIn("tap,", text)
            self.assertNotIn("bridge,", text)
            self.assertNotIn("user,", text)
        self.assertIn(
            "/run/controller.qcow2", " ".join(plans["controller"]))
        self.assertIn(
            "format=raw", " ".join(plans["controller"]))
        self.assertIn(
            "/run/workstation.qcow2", " ".join(plans["workstation"]))

    def test_switch_has_exact_pinned_factory_ports(self):
        command = factory_runner.switch_command(9, Path("/run/evidence"))
        text = " ".join(command)
        self.assertIn("--listener-fd 9", text)
        self.assertIn("gateway=52:54:00:31:11:01", text)
        self.assertIn("controller=52:54:00:31:11:12", text)
        self.assertIn("workstation=52:54:00:31:12:12", text)
        self.assertNotIn("0.0.0.0", text)

    def test_switch_timeouts_can_cover_controller_publication(self):
        command = factory_runner.switch_command(
            9, Path("/run/evidence"),
            accept_timeout=360, idle_timeout=240)
        text = " ".join(command)
        self.assertIn("--accept-timeout 360", text)
        self.assertIn("--idle-timeout 240", text)

    def test_gateway_is_explicit_loopback_switch_peer(self):
        command = factory_runner.gateway_command(31415)
        self.assertIn("--connect", command)
        self.assertIn("31415", command)
        self.assertNotIn("0.0.0.0", " ".join(command))
        identity_command = factory_runner.gateway_command(
            31415, controller_mac=factory_runner.MACS["controller"],
            identity_mode=True)
        self.assertEqual(
            identity_command[-3:],
            ["--controller-mac", "52:54:00:31:11:12", "--identity-mode"],
        )
        identity_switch = factory_runner.switch_command(
            9, Path("/run/evidence"), identity_mode=True)
        self.assertEqual(identity_switch[-1], "--identity-mode")
        self.assertNotIn(
            "--identity-mode",
            factory_runner.switch_command(9, Path("/run/evidence")))
        self.assertNotIn(
            "--identity-mode", factory_runner.gateway_command(31415))

    def test_handoff_requires_dhcp_bootstrap_and_installer_markers(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            switch = root / "switch.jsonl"
            switch.write_text("\n".join(
                f'{{\"kind\":\"{kind}\",\"peer\":\"gateway\"}}'
                for kind in ("DISCOVER", "OFFER", "REQUEST", "ACK")))
            controller = root / "controller.log"
            controller.write_text(
                'TELOS PXE SERVICES READY\n'
                'GET /boot/boot.ipxe HTTP/1.1\n'
                'GET /arch-workstation/20260727.001/boot.ipxe HTTP/1.1\n'
                'GET /arch-workstation/20260727.001/payload/arch/boot/'
                'x86_64/vmlinuz-linux HTTP/1.1\n'
                'GET /arch-workstation/20260727.001/payload/arch/boot/'
                'x86_64/initramfs-linux.img HTTP/1.1\n'
                'GET /arch-workstation/20260727.001/payload/arch/x86_64/'
                'airootfs.sfs HTTP/1.1\n')
            workstation = root / "workstation.log"
            workstation.write_text("archiso login: ")
            self.assertEqual(factory_runner.assess_handoff(
                switch, controller, workstation, "20260727.001"), [])
            workstation.write_text("firmware only")
            self.assertIn("no Arch or WinPE handoff was observed",
                          factory_runner.assess_handoff(
                              switch, controller, workstation,
                              "20260727.001"))

    def test_handoff_correlates_ipxe_client_urls_with_ready_probe(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            switch = root / "switch.jsonl"
            switch.write_text("\n".join(
                f'{{\"kind\":\"{kind}\",\"peer\":\"gateway\"}}'
                for kind in ("DISCOVER", "OFFER", "REQUEST", "ACK")))
            controller = root / "controller.log"
            controller.write_text("TELOS PXE SERVICES READY\n")
            workstation = root / "workstation.log"
            base = "http://10.1.31.2/arch-workstation/20260727.001/"
            workstation.write_text(
                "http://10.1.31.2/boot/boot.ipxe\n"
                + base + "boot.ipxe\n"
                + base + "payload/arch/boot/x86_64/vmlinuz-linux\n"
                + base + "payload/arch/boot/x86_64/initramfs-linux.img\n"
                + base + "payload/arch/x86_64/airootfs.sfs\n"
                + "archiso login: ")
            self.assertEqual(factory_runner.assess_handoff(
                switch, controller, workstation, "20260727.001"), [])

    def test_windows_handoff_requires_full_payload_and_wimboot_execution(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            switch = root / "switch.jsonl"
            switch.write_text("\n".join(
                f'{{\"kind\":\"{kind}\",\"peer\":\"gateway\"}}'
                for kind in ("DISCOVER", "OFFER", "REQUEST", "ACK")))
            controller = root / "controller.log"
            controller.write_text("TELOS PXE SERVICES READY\n")
            workstation = root / "workstation.log"
            base = "http://10.1.31.2/windows/20260727.001/"
            workstation.write_text(
                "http://10.1.31.2/boot/boot.ipxe\n"
                + "".join(base + name + "\n" for name in (
                    "boot.ipxe", "wimboot", "bootmgr", "boot/BCD",
                    "boot/boot.sdi", "sources/boot.wim",
                ))
                + "Windows Imaging Format bootloader\n"
                + "...found WIM file boot.wim\n")
            self.assertEqual(factory_runner.assess_handoff(
                switch, controller, workstation, "20260727.001", "windows"),
                [])
            workstation.write_text(workstation.read_text().replace(
                "...found WIM file boot.wim\n", ""))
            self.assertIn("no Arch or WinPE handoff was observed",
                          factory_runner.assess_handoff(
                              switch, controller, workstation,
                              "20260727.001", "windows"))

    def test_ipxe_preboot_marker_is_not_kernel_handoff(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            switch = root / "switch.jsonl"
            switch.write_text("\n".join(
                f'{{\"kind\":\"{kind}\",\"peer\":\"gateway\"}}'
                for kind in ("DISCOVER", "OFFER", "REQUEST", "ACK")))
            controller = root / "controller.log"
            controller.write_text("TELOS PXE SERVICES READY\n")
            workstation = root / "workstation.log"
            base = "http://10.1.31.2/arch-workstation/20260727.001/"
            workstation.write_text(
                "http://10.1.31.2/boot/boot.ipxe\n"
                + base + "boot.ipxe\n"
                + base + "payload/arch/boot/x86_64/vmlinuz-linux\n"
                + base + "payload/arch/boot/x86_64/initramfs-linux.img\n"
                + "TELOS IPXE PRE-BOOT: selected files loaded\n")
            problems = factory_runner.assess_handoff(
                switch, controller, workstation, "20260727.001")
            self.assertIn("no Arch or WinPE handoff was observed", problems)

    def test_kernel_and_archiso_hook_are_recorded_but_root_is_required(self):
        phases = factory_runner.arch_handoff_phases(
            "TELOS IPXE PRE-BOOT\n"
            "Run /init as init process\n"
            ":: running hook [archiso_pxe_common]\n")
        self.assertEqual(phases, {
            "ipxe_preboot": True,
            "kernel_init": True,
            "archiso_network_hook": True,
            "network_root_ready": False,
        })

    def test_controller_receives_publication_as_read_only_media(self):
        with mock.patch.object(
                factory_runner, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch(
                    "homelab.vm.simulated_topology.ovmf_pair",
                    return_value=(Path("/code"), Path("/vars"))):
            command = factory_runner.qemu_commands(
                Path("/run/controller.raw"),
                Path("/run/controller-vars.fd"),
                Path("/run/workstation.qcow2"),
                Path("/run/workstation-vars.fd"),
                31415, None, Path("/run/publication.iso"),
            )["controller"]
        text = " ".join(command)
        self.assertIn("media=cdrom,readonly=on", text)
        self.assertIn("file=/run/publication.iso", text)
        self.assertNotIn("file=/run/publication.iso,writable", text)

    def test_publication_bootstrap_is_guest_local_and_resumes_systemd(self):
        command = factory_runner.publication_bootstrap_command().decode()
        self.assertIn("mount -L TELOS_PXE_RELEASE", command)
        self.assertIn("/run/telos-pxe-release/publish", command)
        self.assertIn("exec /usr/lib/systemd/systemd", command)
        for forbidden in ("tap", "bridge", "curl", "ssh", "http://"):
            self.assertNotIn(forbidden, command)

    def test_controller_command_passes_strict_standalone_raw_audit(self):
        disk = Path("/run/disposable/controller.raw")
        variables = Path("/run/disposable/OVMF_VARS.fd")
        with mock.patch.object(
                factory_runner, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))), \
                mock.patch(
                    "homelab.vm.simulated_topology.ovmf_pair",
                    return_value=(Path("/code"), Path("/vars"))):
            command = factory_runner.qemu_commands(
                disk, variables,
                Path("/run/workstation.qcow2"),
                Path("/run/workstation-vars.fd"),
                31415, None)["controller"]
        audit_disposable_controller(
            command,
            disk=disk,
            vars_file=variables,
            forbidden_paths=(
                Path("/canonical/controller.qcow2"),
                Path("/canonical/OVMF_VARS.fd"),
            ),
        )

    def test_plan_is_default_and_starts_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            (state / "bootstrap-dc.qcow2").write_bytes(b"disk")
            (state / "OVMF_VARS.fd").write_bytes(b"vars")
            with mock.patch.object(
                    factory_runner, "ovmf_pair",
                    return_value=(Path("/code"), Path("/vars"))), \
                    mock.patch.object(
                        factory_runner.shutil, "which",
                        return_value="/usr/bin/tool"), \
                    mock.patch.object(
                        factory_runner.subprocess, "Popen") as start:
                self.assertEqual(
                    factory_runner.run(state, apply=False, duration=1), 0)
                start.assert_not_called()

    def test_duration_is_bounded(self):
        with mock.patch.object(factory_runner, "_problems", return_value=[]):
            self.assertEqual(
                factory_runner.run(Path("/state"), apply=False, duration=0), 2)
            self.assertEqual(
                factory_runner.run(
                    Path("/state"), apply=False, duration=3601), 2)

    def test_source_sets_disposable_factory_state_private(self):
        source = Path(factory_runner.__file__).read_text()
        self.assertGreaterEqual(source.count(".chmod(0o600)"), 2)


if __name__ == "__main__":
    unittest.main()
