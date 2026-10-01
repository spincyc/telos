"""The persistent Controller on the per-run fabric (TASK-28 steps 2 and 3).

No guest is ever launched: every process is a fake, and the instance is a
synthetic directory holding a tiny qcow2 made with ``qemu-img`` in a
temporary directory.  Nothing here reads ``build/``, ``homelab/var/`` or
``homelab/instance/``.
"""

import base64
import contextlib
import inspect
import io
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from homelab.vm import (
    bootstrap_dc,
    durable_workstation,
    factory_runner,
    persistent_controller_session as session_module,
    simulated_gateway,
    simulated_topology,
)
from homelab.vm.serial_automation import SerialAutomation, SerialAutomationError
from homelab.vm.simulation_overlay import (
    AcceptanceStateProtected, PersistentControllerInstance)
from homelab.tests.identity_overlay_pin import pinned_acceptance_state


def setUpModule():
    # HANDOFF section 5: no test stats the operator's build/ tree.  Every
    # persistent-instance separation check resolves the reserved acceptance
    # state, which defaults to the real build/homelab/vm/bootstrap-dc, so
    # every test here reserves private spellings of it instead.
    unittest.enterModuleContext(pinned_acceptance_state())

INSTANCE = "lab-dc1"
PORT = 40123
PASSWORD = b"console-secret-typed-9"
JOIN_CREDENTIAL = "Synthetic-Join-credential-47!"
DOMAIN = "ad.example.home.arpa"
REALM = DOMAIN.upper()
BOOTSTRAP = f"bootstrap-dc.{DOMAIN}"
SID = "S-1-5-21-1111111111-2222222222-3333333333"
TRUNCATED = "S-1-5-21-1111111111-2222222222-33"
FINGERPRINT = "0123456789abcdef"
REAL_POPEN = subprocess.Popen


class FakeGuest:
    """A QEMU process that never ran: records how it is stopped."""

    def __init__(self, argv, output=b""):
        self.argv = list(argv)
        self.pid = 424242
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(output)
        self.returncode = None
        self.signals = []

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("qemu", timeout)
        return self.returncode

    def terminate(self):
        self.signals.append("terminate")
        self.returncode = -15

    def kill(self):
        self.signals.append("kill")
        self.returncode = -9


def make_instance(root: Path, *, domain_sid=SID) -> Path:
    state = root / "persistent" / INSTANCE
    state.mkdir(parents=True)
    subprocess.run(
        ["qemu-img", "create", "-q", "-f", "qcow2",
         str(state / "persistent-dc.qcow2"), "1M"], check=True)
    (state / "OVMF_VARS.fd").write_bytes(b"synthetic variables")
    marker = {
        "schema": 1, "mode": "persistent", "instance": INSTANCE,
        "created_utc": "2026-01-01T00:00:00+00:00",
        "converged": {
            "converged_utc": "2026-01-01T00:00:00+00:00",
            "realm": REALM, "netbios": "EXAMPLEAD", "dns_domain": DOMAIN,
            "domain_sid": domain_sid,
        },
        "directory_accounts": {
            "staged_utc": "2026-01-01T00:00:00+00:00",
            "roster_fingerprint": FINGERPRINT,
            "accounts": [{"contract_role": "standard_user"}],
        },
    }
    (state / "persistent-instance.json").write_text(json.dumps(marker))
    for name in ("persistent-dc.qcow2", "OVMF_VARS.fd",
                 "persistent-instance.json"):
        (state / name).chmod(0o600)
    state.chmod(0o700)
    return state


class SessionFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = make_instance(self.root)
        self.canonical = self.root / "canonical"
        self.proc = self.root / "proc"
        self.target = PersistentControllerInstance(
            self.state, instance=INSTANCE)
        self.guests = []
        self.calls = []
        self.guest_output = b""
        self.live_argv = None
        self.login_hostnames = []
        patch = mock.patch.object(
            bootstrap_dc, "ovmf_pair",
            return_value=(Path("/code/OVMF_CODE.fd"), Path("/code/VARS.fd")))
        patch.start()
        self.addCleanup(patch.stop)

    def spawn(self, argv):
        guest = FakeGuest(argv, self.guest_output)
        (self.proc / str(guest.pid)).mkdir(parents=True, exist_ok=True)
        (self.proc / str(guest.pid) / "cmdline").write_bytes(
            b"\0".join(part.encode() for part in (self.live_argv or argv))
            + b"\0")
        self.guests.append(guest)
        self.calls.append("spawn")
        return guest

    def session(self, **options):
        values = {
            "port": PORT, "password": PASSWORD,
            "canonical_state": self.canonical, "spawn": self.spawn,
            "proc_root": self.proc,
        }
        values.update(options)
        return session_module.PersistentControllerSession(
            self.target, **values)

    def login(self, console, label, *, hostname=None):
        self.calls.append("login")
        self.login_hostnames.append(hostname)
        self.assertEqual(console.password, PASSWORD)
        # Pull the whole fake console through the retained tee.
        console.reader.read1(1 << 20)

    def poweroff(self, console, password, label):
        self.calls.append("poweroff")
        self.assertEqual(password, PASSWORD)
        self.guests[-1].returncode = 0

    @contextlib.contextmanager
    def console_fakes(self, *, login=None, poweroff=None):
        with mock.patch.object(
                session_module, "persistent_console_login",
                side_effect=login or self.login), \
             mock.patch.object(
                SerialAutomation, "_wait_controller_ad",
                lambda _self: self.calls.append("ad")), \
             mock.patch.object(
                session_module, "_console_poweroff",
                side_effect=poweroff or self.poweroff) as patched:
            yield patched

    def lock_held(self) -> bool:
        other = PersistentControllerInstance(self.state, instance=INSTANCE)
        return bootstrap_dc._persistent_running(other) is True


class SessionCommandTests(SessionFixture):
    def test_the_instance_boots_in_place_on_the_switch_with_its_own_mac(self):
        argv = self.session().command
        files = bootstrap_dc.persistent_paths(self.state)
        persistent_up = bootstrap_dc.qemu_command(
            self.state, None, None, files=files, socket_port=PORT,
            name=f"persistent-dc-{INSTANCE}")
        # The same machine every earlier boot of this directory had; only the
        # NIC now connects to the per-run switch instead of listening.
        self.assertEqual(argv[:-4], persistent_up[:-4])
        self.assertEqual(argv[-4:], [
            "-netdev", f"socket,id=bootstrap,connect=127.0.0.1:{PORT}",
            "-device",
            f"virtio-net-pci,netdev=bootstrap,mac={bootstrap_dc.SOCKET_MAC}",
        ])
        joined = " ".join(argv)
        self.assertIn(f"file={files['disk']}", joined)
        self.assertIn(f"file={files['vars']}", joined)
        for forbidden in ("-qmp", "-monitor", "cdrom", "scsi-cd", "snapshot",
                          "listen=", "-S", "-kernel", "-chardev"):
            self.assertNotIn(forbidden, argv if forbidden.startswith("-")
                             else joined)

    def test_the_audit_refuses_every_departure_from_that_shape(self):
        argv = self.session().command
        files = bootstrap_dc.persistent_paths(self.state)
        disk = next(item for item in argv if "id=osdisk" in item)
        nic = argv[-1]
        netdev = argv[-3]
        variants = {
            "qmp": argv + ["-qmp", "unix:/tmp/q.sock,server=on,wait=off"],
            "monitor": argv + ["-monitor", "stdio"],
            "paused": argv + ["-S"],
            "snapshot option": argv + ["-snapshot"],
            "kernel": argv + ["-kernel", "/boot/vmlinuz"],
            "cdrom": argv + ["-cdrom", "/tmp/x.iso"],
            "chardev": argv + ["-chardev", "socket,id=c,path=/tmp/c"],
            "listen": [netdev.replace("connect=", "listen=")
                       if item == netdev else item for item in argv],
            "wrong port": [netdev.replace(str(PORT), str(PORT + 1))
                           if item == netdev else item for item in argv],
            "other mac": [nic.replace(bootstrap_dc.SOCKET_MAC,
                                      "52:54:00:31:11:12")
                          if item == nic else item for item in argv],
            "snapshot disk": [disk + ",snapshot=on" if item == disk else item
                              for item in argv],
            "read-only disk": [disk + ",readonly=on" if item == disk else item
                               for item in argv],
            "other disk": [disk.replace(str(files["disk"]), "/tmp/other.qcow2")
                           if item == disk else item for item in argv],
            "medium": argv + [
                "-drive", "if=none,id=m,media=cdrom,readonly=on,file=/x.iso"],
            "second nic": argv + [
                "-device", "virtio-net-pci,netdev=bootstrap,mac=52:54:00:1:1:1"],
        }
        simulated_topology.audit_persistent_controller(
            argv, disk=files["disk"], vars_file=files["vars"], port=PORT,
            mac=bootstrap_dc.SOCKET_MAC)
        for name, variant in variants.items():
            with self.subTest(variant=name):
                with self.assertRaises(ValueError):
                    simulated_topology.audit_persistent_controller(
                        variant, disk=files["disk"], vars_file=files["vars"],
                        port=PORT, mac=bootstrap_dc.SOCKET_MAC)

    def test_the_acceptance_canonical_is_refused(self):
        files = bootstrap_dc.persistent_paths(self.state)
        argv = self.session().command
        with self.assertRaisesRegex(ValueError, "acceptance canonical"):
            simulated_topology.audit_persistent_controller(
                argv, disk=files["disk"], vars_file=files["vars"], port=PORT,
                mac=bootstrap_dc.SOCKET_MAC, forbidden_paths=(files["disk"],))
        # Named as the canonical state itself ...
        with self.assertRaises(AcceptanceStateProtected):
            self.session(canonical_state=self.state)
        # ... or holding the acceptance artefact, the instance never boots.
        (self.state / "bootstrap-dc.qcow2").write_bytes(b"canonical")
        with self.assertRaises(AcceptanceStateProtected):
            self.session()
        self.assertEqual(self.calls, [])

    def test_the_switch_carries_the_instance_mac_and_no_workstation(self):
        evidence = self.root / "switch.jsonl"
        argv = bootstrap_dc.persistent_switch_command(7, evidence)
        ports = [argv[index + 1] for index, item in enumerate(argv)
                 if item == "--port"]
        self.assertEqual(ports, [
            f"gateway={factory_runner.GATEWAY_MAC}",
            f"controller={bootstrap_dc.SOCKET_MAC}",
        ])
        self.assertIn("--identity-mode", argv)
        with_workstation = bootstrap_dc.persistent_switch_command(
            7, evidence, workstation_mac="52:54:00:31:12:12")
        self.assertIn("workstation=52:54:00:31:12:12", with_workstation)
        gateway = factory_runner.gateway_command(
            PORT, controller_mac=bootstrap_dc.SOCKET_MAC, identity_mode=True)
        self.assertIn(bootstrap_dc.SOCKET_MAC, gateway)
        for command in (argv, gateway, self.session().command):
            self.assertNotIn(PASSWORD.decode(), " ".join(command))


class SessionLifecycleTests(SessionFixture):
    def test_start_logs_in_and_stop_powers_off_before_any_terminate(self):
        session = self.session()
        with self.console_fakes():
            session.start()
            self.assertTrue(self.lock_held())
            self.assertTrue(session.facts["live_argv_audited"])
            session.stop()
        self.assertEqual(self.calls, ["spawn", "login", "ad", "poweroff"])
        self.assertEqual(self.guests[0].signals, [])
        self.assertEqual(session.facts["clean_poweroffs"], 1)
        self.assertFalse(session.facts["terminated_fallback"])
        self.assertTrue(session.facts["lock_released"])
        self.assertFalse(self.lock_held())

    def test_a_failed_poweroff_falls_back_to_terminate_and_records_it(self):
        def refuse(console, password, label):
            self.calls.append("poweroff")
            raise SerialAutomationError("timed out waiting for poweroff")

        session = self.session()
        with self.console_fakes(poweroff=refuse):
            session.start()
            session.stop()
        self.assertEqual(self.calls[-1], "poweroff")
        self.assertEqual(self.guests[0].signals, ["terminate"])
        self.assertTrue(session.facts["terminated_fallback"])
        self.assertFalse(self.lock_held())

    def test_a_refused_login_never_types_the_password_into_a_poweroff(self):
        def refused(console, label, **_kwargs):
            self.calls.append("login")
            raise SerialAutomationError("refused the local-rescue password")

        session = self.session()
        with self.console_fakes(login=refused) as poweroff:
            with self.assertRaisesRegex(SerialAutomationError, "refused"):
                session.start()
        poweroff.assert_not_called()
        self.assertEqual(self.guests[0].signals, ["terminate"])
        self.assertTrue(session.facts["terminated_fallback"])
        self.assertFalse(self.lock_held())

    def test_a_live_process_that_is_not_the_audited_command_is_stopped(self):
        session = self.session()
        self.live_argv = session.command + ["-qmp", "unix:/tmp/q,server=on"]
        with self.console_fakes() as poweroff:
            with self.assertRaises(
                    session_module.PersistentControllerSessionError):
                session.start()
        poweroff.assert_not_called()
        self.assertNotIn("login", self.calls)
        self.assertEqual(self.guests[0].signals, ["terminate"])
        self.assertFalse(self.lock_held())

    def test_relaunch_logs_in_again_and_close_drops_the_credential(self):
        session = self.session()
        with self.console_fakes():
            session.start()
            session.relaunch()
            session.close()
        self.assertEqual(self.calls, [
            "spawn", "login", "ad", "poweroff",
            "spawn", "login", "ad", "poweroff"])
        self.assertEqual(session.facts["launches"], 2)
        self.assertEqual(session.facts["logins"], 2)
        with self.assertRaisesRegex(
                session_module.PersistentControllerSessionError, "closed"):
            session.start()
        self.assertFalse(self.lock_held())

    def test_there_is_no_pause_and_no_signal_method(self):
        session = self.session()
        for name in sorted(session_module.FORBIDDEN_FAULT_HOOKS):
            with self.subTest(hook=name):
                self.assertFalse(hasattr(session, name))
                self.assertFalse(hasattr(
                    session_module.PersistentControllerSession, name))
                with self.assertRaisesRegex(AttributeError, "no pause"):
                    getattr(session, name)()
        source = inspect.getsource(session_module.PersistentControllerSession)
        for forbidden in ("SIGSTOP", "SIGCONT", "signal.", "os.kill"):
            self.assertNotIn(forbidden, source)

    def test_the_credential_never_reaches_the_retained_transcript(self):
        self.guest_output = (
            b"bootstrap-dc login: local-rescue\r\nPassword: " + PASSWORD
            + b"\r\n[local-rescue@bootstrap-dc ~]$ echoed "
            + JOIN_CREDENTIAL.encode() + b"\r\n")
        session = self.session()
        with self.console_fakes():
            session.start()
            session.stop()
        transcript = session.redacted_transcript([JOIN_CREDENTIAL])
        self.assertIsNotNone(transcript)
        self.assertNotIn(PASSWORD, transcript)
        self.assertNotIn(JOIN_CREDENTIAL.encode(), transcript)
        self.assertIn(b"bootstrap-dc login:", transcript)
        # A copy the redactor cannot see is withheld, never retained.
        session._transcript.extend(base64.b64encode(PASSWORD) + b"\n")
        self.assertIsNone(session.redacted_transcript())
        session.close()
        self.assertIsNone(session.redacted_transcript())


class ProbeTests(SessionFixture):
    def setUp(self):
        super().setUp()
        self.identity = self.root / "directory.json"
        self.identity.write_text(json.dumps({
            "schema_version": 1,
            "identity": {"dns_domain": DOMAIN, "kerberos_realm": REALM,
                         "netbios_name": "EXAMPLEAD"},
            "services": {"bootstrap_dc_fqdn": BOOTSTRAP,
                         "permanent_dc_fqdn": f"dc2.{DOMAIN}"},
            "network": {
                "address": str(simulated_gateway.CONTROLLER_IP),
                "prefix": durable_workstation.FABRIC_PREFIX,
                "gateway": str(simulated_gateway.GATEWAY_IP)},
        }))
        self.evidence = self.root / "evidence"
        self.live_sid = SID
        self.commands = []
        self.children = []
        self.prompts = []
        self.join_serials = []
        patch = mock.patch.object(
            durable_workstation, "_current_roster_fingerprint",
            return_value=FINGERPRINT)
        patch.start()
        self.addCleanup(patch.stop)

    def run_probe(self, apply=True, **options):
        values = {
            "canonical_state": self.canonical,
            "identity_path": self.identity,
            "evidence_root": self.evidence,
        }
        values.update(options)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = session_module.probe(
                self.state.parent, INSTANCE, apply, **values)
        return code, out.getvalue(), err.getvalue()

    # -- fakes for one applied probe --------------------------------------
    def popen(self, argv, **kwargs):
        argv = list(argv)
        if argv[0] == "qemu-system-x86_64":
            self.calls.append("spawn")
            guest = FakeGuest(argv, self.guest_output)
            self.guests.append(guest)
            return guest
        if argv[0] == sys.executable:
            self.calls.append("fabric")
            child = FakeGuest(argv)
            self.children.append(child)
            return child
        return REAL_POPEN(argv, **kwargs)

    def console_root(self, console, command, label, *, value=None):
        self.assertNotIn(PASSWORD.decode(), command)
        self.commands.append((label, command))
        answers = {
            "probe-realm": REALM.lower().encode(),
            "probe-domain-sid": self.live_sid.encode(),
            "probe-gateway": b"1",
            "probe-clock": str(int(time.time())).encode(),
        }
        return answers.get(label, b"1")

    def typed(self, prompt, **_kwargs):
        self.prompts.append(prompt)
        self.calls.append("prompt")
        return PASSWORD

    def join_module(self):
        test = self

        class Serial:
            def __init__(self, reader, writer, *, timeout):
                self.console = None
                self.destroyed = False
                test.join_serials.append(self)

            def stage(self, credential):
                test.calls.append("stage")
                return SimpleNamespace(
                    operation="stage", principal="tj-0123456789abcdef",
                    destruction_proved=False)

            def destroy(self):
                test.calls.append("destroy")
                self.destroyed = True
                return SimpleNamespace(
                    operation="destroy", principal="tj-0123456789abcdef",
                    destruction_proved=True)

        class Material:
            def __init__(self, realm, *, stage, destroy):
                self._stage, self._destroy = stage, destroy

            def use(self, consumer):
                staged = self._stage(JOIN_CREDENTIAL)
                return consumer({"principal": staged.principal}), \
                    self._destroy()

        return SimpleNamespace(
            ControllerJoinSerial=Serial, OneUseDomainJoinMaterial=Material,
            ControllerJoinMaterialError=RuntimeError)

    @contextlib.contextmanager
    def applied(self):
        patches = [
            mock.patch.object(subprocess, "Popen", side_effect=self.popen),
            mock.patch.object(
                session_module.shutil, "which", return_value="/usr/bin/x"),
            mock.patch.object(
                session_module, "ovmf_pair",
                return_value=(Path("/code/OVMF_CODE.fd"), Path("/v"))),
            mock.patch.object(session_module, "assert_installed"),
            mock.patch.object(
                session_module, "_typed_secret", side_effect=self.typed),
            mock.patch.object(session_module, "wait_for_switch_port"),
            mock.patch.object(
                session_module.PersistentControllerSession, "_audit_live",
                lambda session, pid: session.facts.update(
                    live_argv_audited=True)),
            mock.patch.object(
                session_module, "_console_root",
                side_effect=self.console_root),
            mock.patch.object(
                session_module, "_join_material",
                side_effect=self.join_module),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            stack.enter_context(self.console_fakes())
            yield

    def result(self):
        [run] = list((self.evidence / INSTANCE).iterdir())
        return run, json.loads((run / "result.json").read_text())

    # -- the probe --------------------------------------------------------
    def test_the_dry_run_prints_the_plan_and_starts_nothing(self):
        with mock.patch.object(
                subprocess, "Popen",
                side_effect=AssertionError("a dry run started a process")), \
             mock.patch.object(
                session_module, "_typed_secret",
                side_effect=AssertionError("a dry run asked for a password")):
            code, out, _ = self.run_probe(apply=False)
        self.assertEqual(code, 0, out)
        self.assertIn("dry run", out)
        self.assertIn("connect=127.0.0.1:<per-run port>", out)
        for value in (REALM, DOMAIN, SID, BOOTSTRAP,
                      str(simulated_gateway.CONTROLLER_IP)):
            self.assertNotIn(value, out)
        self.assertFalse(self.evidence.exists())

    def test_every_refusal_comes_before_the_password_prompt(self):
        holder = PersistentControllerInstance(self.state, instance=INSTANCE)
        holder.prepare()
        self.addCleanup(holder.close)
        with self.applied():
            code, _, err = self.run_probe()
        self.assertEqual(code, 2)
        self.assertIn("already running", err)
        self.assertEqual(self.prompts, [])
        self.assertEqual(self.calls, [])

    def test_a_restored_instance_is_probed_under_its_recorded_dc_name(self):
        """TASK-42: the console, the A and the SRV checks follow the record."""
        instance = PersistentControllerInstance(self.state, instance=INSTANCE)
        record = instance.convergence()
        record["dc_hostname"] = "dr-2609302105"
        instance.record_convergence(record)
        with self.applied():
            code, _, err = self.run_probe()
        self.assertEqual(code, 0, err)
        self.assertEqual(self.login_hostnames, ["dr-2609302105"])
        commands = dict(self.commands)
        fqdn = f"dr-2609302105.{DOMAIN}"
        self.assertIn(fqdn, commands["probe-a-record"])
        for label in ("probe-srv-ldap", "probe-srv-kerberos"):
            self.assertIn(f" {fqdn}.", commands[label])
        self.assertNotIn(BOOTSTRAP, " ".join(commands.values()))

    def test_a_passing_probe_repairs_a_truncated_sid_and_keeps_no_secret(self):
        instance = PersistentControllerInstance(self.state, instance=INSTANCE)
        record = instance.convergence()
        record["domain_sid"] = TRUNCATED
        instance.record_convergence(record)
        self.guest_output = (
            b"bootstrap-dc login: local-rescue\r\nPassword: " + PASSWORD
            + b"\r\n$ " + JOIN_CREDENTIAL.encode() + b"\r\n")
        with self.applied():
            code, out, err = self.run_probe(repair_sid=True)
        self.assertEqual(code, 0, err)
        # One prompt, before any process; fabric before the guest; the join
        # principal staged and destroyed before a clean poweroff.
        self.assertEqual(self.calls[:4], ["prompt", "fabric", "fabric", "spawn"])
        self.assertEqual(
            [call for call in self.calls
             if call in ("stage", "destroy", "poweroff")],
            ["stage", "destroy", "poweroff"])
        self.assertEqual(self.guests[0].signals, [])
        self.assertTrue(all("terminate" in child.signals
                            for child in self.children))
        self.assertEqual(instance.convergence()["domain_sid"], SID)
        run, result = self.result()
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["checks"]["domain_sid"], "repaired")
        self.assertTrue(all(result["checks"][key] is True
                            for key in session_module.REQUIRED_CHECKS))
        labels = [label for label, _ in self.commands]
        self.assertEqual(labels[:2], ["probe-realm", "probe-domain-sid"])
        srv = dict(self.commands)["probe-srv-ldap"]
        self.assertIn(f"_ldap._tcp.{DOMAIN}", srv)
        self.assertIn(str(simulated_gateway.CONTROLLER_IP), srv)
        retained = b"".join(path.read_bytes() for path in run.iterdir())
        for secret in (PASSWORD, JOIN_CREDENTIAL.encode()):
            self.assertNotIn(secret, retained)
        rendered = (run / "result.json").read_text()
        for value in (REALM, DOMAIN, SID, TRUNCATED, BOOTSTRAP,
                      str(simulated_gateway.CONTROLLER_IP)):
            self.assertNotIn(value, rendered)
        self.assertIn(b"[REDACTED]", (run / "console-transcript.log")
                      .read_bytes())
        self.assertIn("PASS", out)

    def test_a_truncated_sid_without_repair_fails_and_writes_nothing(self):
        instance = PersistentControllerInstance(self.state, instance=INSTANCE)
        record = instance.convergence()
        record["domain_sid"] = TRUNCATED
        instance.record_convergence(record)
        with self.applied():
            code, _, err = self.run_probe()
        self.assertEqual(code, 2)
        self.assertIn("REPAIR_SID=1", err)
        self.assertEqual(instance.convergence()["domain_sid"], TRUNCATED)
        _, result = self.result()
        self.assertEqual(result["checks"]["domain_sid"], "repair-needed")
        self.assertEqual(result["verdict"], "fail")

    def test_another_directory_is_refused_before_anything_is_written(self):
        self.live_sid = "S-1-5-21-4444444444-5555555555-6666666666"
        with self.applied():
            code, _, err = self.run_probe(repair_sid=True)
        self.assertEqual(code, 2)
        self.assertIn("different directory", err)
        self.assertNotIn("stage", self.calls)
        self.assertEqual(self.calls[-1], "poweroff")
        self.assertEqual(self.guests[0].signals, [])
        _, result = self.result()
        self.assertEqual(result["checks"]["domain_sid"], "mismatch")
        self.assertEqual(result["failure"]["step"], "directory")
        self.assertTrue(result["checks"]["clean_poweroff"])
        self.assertFalse(self.lock_held())


if __name__ == "__main__":
    unittest.main()
