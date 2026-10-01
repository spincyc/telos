"""Samba backup and restore of persistent directory instances (ADR 0081).

No guest is launched: QEMU, the fabric and the console are fakes, and the
"guest" side of the backup disk is written by the fake console exactly as
``samba_backup_disk``'s guest command would write it (that command itself is
exercised under bash in ``test_samba_backup_disk``).  Every instance, backup
set and evidence directory is temporary; nothing here reads ``build/``,
``homelab/var/`` or ``homelab/instance/``.
"""

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from homelab.tests.identity_overlay_pin import pinned_acceptance_state
from homelab.tests.test_persistent_controller_session import (
    DOMAIN, FINGERPRINT, INSTANCE, PASSWORD, PORT, REAL_POPEN, REALM, SID,
    FakeGuest, SessionFixture)
from homelab.vm import (
    bootstrap_dc,
    credential_custody as cc,
    durable_workstation,
    persistent_backup as runner,
    persistent_controller_session as session_module,
    samba_backup_disk as disk,
    simulated_gateway,
    simulated_topology,
)
from homelab.vm.serial_automation import SerialAutomation
from homelab.vm.simulation_overlay import (
    PersistentControllerInstance, PersistentInstanceInvalid)


def setUpModule():
    unittest.enterModuleContext(pinned_acceptance_state())


TOKEN = "0123456789abcdef0123456789abcdef"
TARBALL = b"BZh91AY&SY" + bytes(range(256)) * 300
PRINCIPALS = "17:" + hashlib.sha256(b"sorted principal SIDs").hexdigest()
DRILL = "lab-dc2"
ADMINISTRATOR = "Administrator0Stored9"
ACCOUNT = "Daily0Account1Stored"
NEW_CONSOLE = "Console0New1Created2"
PRIVATE = (PASSWORD.decode(), ADMINISTRATOR, ACCOUNT, NEW_CONSOLE)


def identity_document(realm=REALM, domain=DOMAIN):
    return {
        "schema_version": 1,
        "identity": {"dns_domain": domain, "kerberos_realm": realm,
                     "netbios_name": "EXAMPLEAD"},
        "services": {"bootstrap_dc_fqdn": f"bootstrap-dc.{domain}",
                     "permanent_dc_fqdn": f"dc2.{domain}"},
        "network": {
            "address": str(simulated_gateway.CONTROLLER_IP),
            "prefix": durable_workstation.FABRIC_PREFIX,
            "gateway": str(simulated_gateway.GATEWAY_IP)},
    }


class BackupFixture(SessionFixture):
    """One converged, staged instance, with the probe's fakes for a run."""

    def setUp(self):
        super().setUp()
        self.identity = self.root / "directory.json"
        self.identity.write_text(json.dumps(identity_document()))
        self.backups = self.root / "backups"
        self.evidence = self.root / "evidence"
        self.restore_evidence = self.root / "restore-evidence"
        self.canonical.mkdir()
        files = bootstrap_dc.paths(self.canonical)
        for key in ("disk", "vars"):
            files[key].write_bytes(b"canonical " + key.encode())
            files[key].chmod(0o600)
        target = PersistentControllerInstance(self.state, instance=INSTANCE)
        marker = target.read_marker()
        marker["directory_password_policy"] = {
            "min_length": 4, "complexity": False, "min_age_days": 0,
            "source": f"{INSTANCE}'s recorded directory policy",
            "recorded_utc": "2026-09-30T00:00:00+00:00", "run_id": "r1"}
        marker["directory_account_password_resets"] = [{
            "role": "standard_user", "utc": "2026-09-30T00:00:00+00:00",
            "must_change": False, "run_id": "r2"}]
        target._write_marker(marker)
        self.commands = []
        self.children = []
        self.prompts = []
        self.created = []
        self.payload = TARBALL
        self.write_proof = None
        self.live_sid = SID
        self.live_realm = REALM
        self.live_principals = PRINCIPALS
        self.restore_proof = b"RESTORED"
        self.console_password = PASSWORD
        self.guest_output = (
            b"bootstrap-dc login: local-rescue\r\nPassword: " + PASSWORD
            + b"\r\n$ ")
        patch = mock.patch.object(
            durable_workstation, "_current_roster_fingerprint",
            return_value=FINGERPRINT)
        patch.start()
        self.addCleanup(patch.stop)

    # -- fakes ---------------------------------------------------------------
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

    def login(self, console, label):
        self.calls.append("login")
        self.assertEqual(console.password, self.console_password)
        console.reader.read1(1 << 20)

    def poweroff(self, console, password, label):
        self.calls.append("poweroff")
        self.assertEqual(password, self.console_password)
        self.guests[-1].returncode = 0

    def backup_disk(self) -> Path:
        drive = next(part for part in self.guests[-1].argv
                     if "id=backupdisk" in part)
        return Path(drive.rpartition("file=")[2])

    def guest_writes(self):
        """What the guest's backup command writes, on the run's own disk."""
        digest = hashlib.sha256(self.payload).hexdigest()
        with self.backup_disk().open("r+b") as stream:
            stream.write(disk.encode_header(len(self.payload), digest, TOKEN))
            stream.write(self.payload)
        return (self.write_proof
                or f"{digest}:{len(self.payload)}".encode())

    def console_root(self, console, command, label, *, value=None):
        for secret in PRIVATE:
            self.assertNotIn(secret, command)
        self.commands.append((label, command))
        self.calls.append(label)
        if label == "backup-write":
            return self.guest_writes()
        answers = {
            "backup-realm": REALM.lower().encode(),
            "backup-domain-sid": SID.encode(),
            "backup-dc-name": b"BOOTSTRAP-DC",
            "backup-principals": PRINCIPALS.encode(),
            "restore-run": self.restore_proof,
            "restore-realm": self.live_realm.encode(),
            "restore-domain-sid": self.live_sid.encode(),
            "restore-principals": self.live_principals.encode(),
        }
        return answers.get(label)

    def typed(self, prompt, **_kwargs):
        self.prompts.append(prompt)
        self.calls.append("prompt")
        return PASSWORD

    def create(self, target, canonical, backup_set):
        """A freshly created instance: an installed image, no directory."""
        self.calls.append("create")
        self.created.append(target.instance)
        state = target.state
        state.mkdir(mode=0o700)
        subprocess.run(
            ["qemu-img", "create", "-q", "-f", "qcow2",
             str(state / "persistent-dc.qcow2"), "1M"], check=True)
        (state / "OVMF_VARS.fd").write_bytes(b"synthetic variables")
        marker = {
            "schema": 1, "mode": "persistent", "instance": target.instance,
            "created_utc": "2026-09-30T12:00:00+00:00",
            "seeded_from": {"disk": str(canonical["disk"]),
                            "disk_sha256": "c" * 64, "vars_sha256": "d" * 64},
        }
        if backup_set.custody == cc.AGENT:
            marker.update(credential_custody=cc.AGENT, throwaway=True)
        (state / "persistent-instance.json").write_text(json.dumps(marker))
        for name in ("persistent-dc.qcow2", "OVMF_VARS.fd",
                     "persistent-instance.json"):
            (state / name).chmod(0o600)
        if backup_set.custody == cc.AGENT:
            cc.instance_store(target).create({"console": NEW_CONSOLE})
        return marker

    @contextlib.contextmanager
    def applied(self):
        patches = [
            mock.patch.object(subprocess, "Popen", side_effect=self.popen),
            mock.patch.object(runner.shutil, "which",
                              return_value="/usr/bin/x"),
            mock.patch.object(
                runner, "ovmf_pair",
                return_value=(Path("/code/OVMF_CODE.fd"), Path("/v"))),
            mock.patch.object(runner, "assert_installed"),
            mock.patch.object(runner, "assert_installed_controller_image"),
            mock.patch.object(runner, "_typed_secret", side_effect=self.typed),
            mock.patch.object(runner, "wait_for_switch_port"),
            mock.patch.object(session_module, "wait_for_switch_port"),
            mock.patch.object(
                session_module.PersistentControllerSession, "_audit_live",
                lambda session, pid: session.facts.update(
                    live_argv_audited=True)),
            mock.patch.object(runner, "_console_root",
                              side_effect=self.console_root),
            mock.patch.object(runner, "new_token", return_value=TOKEN),
            mock.patch.object(runner, "_create_instance",
                              side_effect=self.create),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            stack.enter_context(self.console_fakes(
                login=self.login, poweroff=self.poweroff))
            yield

    @contextlib.contextmanager
    def inert(self):
        """A run that must start nothing and ask for nothing."""
        with mock.patch.object(
                subprocess, "Popen",
                side_effect=AssertionError("a process was started")), \
             mock.patch.object(
                runner, "_typed_secret",
                side_effect=AssertionError("a password was asked for")), \
             mock.patch.object(
                runner, "_create_instance",
                side_effect=AssertionError("an instance was created")), \
             mock.patch.object(
                runner, "assert_installed_controller_image"):
            yield

    # -- runs --------------------------------------------------------------
    def run_backup(self, apply=True):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = runner.backup(
                self.state.parent, INSTANCE, apply,
                canonical_state=self.canonical, identity_path=self.identity,
                backup_root=self.backups, evidence_root=self.evidence)
        return code, out.getvalue(), err.getvalue()

    def run_restore(self, backup_set, apply=True, instance=DRILL,
                    confirm=None, dc_name=None, identity=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = runner.restore(
                self.state.parent, instance, backup_set, apply,
                confirm=(f"RESTORE {instance}" if confirm is None
                         else confirm),
                dc_name=dc_name, canonical_state=self.canonical,
                identity_path=identity or self.identity,
                evidence_root=self.restore_evidence)
        return code, out.getvalue(), err.getvalue()

    def take_backup(self) -> Path:
        with self.applied():
            code, out, err = self.run_backup()
        self.assertEqual(code, 0, err)
        [backup_set] = [path for path in (self.backups / INSTANCE).iterdir()]
        self.guests.clear()
        self.calls.clear()
        self.commands.clear()
        return backup_set

    def result(self, root: Path, instance: str = INSTANCE):
        [run] = [path for path in (root / instance).iterdir()
                 if not path.name.startswith(".")]
        return run, json.loads((run / "result.json").read_text())

    def make_agent(self):
        """Turn the fixture's instance into a throwaway agent-custody one."""
        target = PersistentControllerInstance(self.state, instance=INSTANCE)
        marker = target.read_marker()
        marker.update(credential_custody=cc.AGENT, throwaway=True)
        target._write_marker(marker)
        cc.instance_store(target).create({
            "console": PASSWORD.decode(), "administrator": ADMINISTRATOR,
            "accounts": {"standard_user": {"current": ACCOUNT}}})
        return target


class BackupDiskAuditTests(SessionFixture):
    """The one extra device, admitted only in backup and restore mode."""

    def setUp(self):
        super().setUp()
        self.disk = self.root / "sets" / "out.raw"
        self.files = bootstrap_dc.persistent_paths(self.state)

    def audit(self, argv, **backup):
        simulated_topology.audit_persistent_controller(
            argv, disk=self.files["disk"], vars_file=self.files["vars"],
            port=PORT, mac=bootstrap_dc.SOCKET_MAC,
            forbidden_paths=(self.canonical / "bootstrap-dc.qcow2",),
            **backup)

    def command(self, mode):
        return session_module.session_command(
            self.target, PORT, canonical_state=self.canonical,
            backup_disk=self.disk, backup_mode=mode)

    def test_backup_mode_adds_one_raw_unbootable_disk_before_the_nic(self):
        plain = self.session().command
        argv = self.command(simulated_topology.BACKUP_OUTPUT)
        extra = simulated_topology.backup_disk_args(
            self.disk, simulated_topology.BACKUP_OUTPUT)
        # ``plain`` ends with -nodefaults and the NIC's -netdev/-device pair.
        self.assertEqual(argv, plain[:-5] + extra + plain[-5:])
        self.assertEqual(extra, [
            "-drive",
            f"if=none,id=backupdisk,format=raw,cache=none,file={self.disk}",
            "-device", "virtio-blk-pci,drive=backupdisk,serial=TELOS-BACKUP-OUT",
        ])
        self.assertNotIn("bootindex", extra[3])
        self.audit(argv, backup_disk=self.disk,
                   backup_mode=simulated_topology.BACKUP_OUTPUT)

    def test_restore_mode_is_read_only_and_has_no_network_at_all(self):
        plain = self.session().command
        argv = self.command(simulated_topology.BACKUP_INPUT)
        self.assertEqual(argv, plain[:-5] + simulated_topology.backup_disk_args(
            self.disk, simulated_topology.BACKUP_INPUT) + ["-nodefaults"])
        self.assertIn("readonly=on", argv[-4])
        self.assertIn("serial=TELOS-BACKUP-IN", argv[-2])
        for absent in ("-netdev", "virtio-net-pci"):
            self.assertFalse(any(absent in part for part in argv))
        self.audit(argv, backup_disk=self.disk,
                   backup_mode=simulated_topology.BACKUP_INPUT)
        with self.assertRaises(ValueError):
            # Restore mode refuses a NIC, even the instance's own.
            self.audit(self.command(simulated_topology.BACKUP_OUTPUT),
                       backup_disk=self.disk,
                       backup_mode=simulated_topology.BACKUP_INPUT)

    def test_the_disk_is_refused_outside_its_mode_and_in_any_other_shape(self):
        output = simulated_topology.BACKUP_OUTPUT
        argv = self.command(output)
        drive = next(part for part in argv if "id=backupdisk" in part)
        device = next(part for part in argv if "drive=backupdisk" in part)

        def swap(old, new):
            return [new if part == old else part for part in argv]

        # Without backup mode the extra disk is just another refused device.
        with self.assertRaises(ValueError):
            self.audit(argv)
        with self.assertRaises(ValueError):
            self.audit(self.session().command, backup_disk=self.disk,
                       backup_mode=output)
        variants = {
            "other path": swap(drive, drive.replace(
                str(self.disk), str(self.root / "other.raw"))),
            "the instance disk": swap(drive, drive.replace(
                str(self.disk), str(self.files["disk"]))),
            "qcow2": swap(drive, drive.replace("format=raw", "format=qcow2")),
            "read-only output": swap(drive, drive + ",readonly=on"),
            "snapshot": swap(drive, drive + ",snapshot=on"),
            "cdrom": swap(drive, drive + ",media=cdrom"),
            "bootable": swap(device, device + ",bootindex=0"),
            "other serial": swap(device, device.replace(
                "TELOS-BACKUP-OUT", "TELOS-BACKUP-IN")),
            "scsi": swap(device, device.replace(
                "virtio-blk-pci", "scsi-hd")),
            "second backup disk": argv[:-5] + simulated_topology.backup_disk_args(
                self.root / "two.raw", output) + argv[-5:],
            "defaults": [part for part in argv if part != "-nodefaults"],
            "canonical": swap(drive, drive.replace(
                str(self.disk), str(self.canonical / "bootstrap-dc.qcow2"))),
        }
        for name, variant in variants.items():
            with self.subTest(variant=name):
                with self.assertRaises(ValueError):
                    self.audit(variant, backup_disk=self.disk,
                               backup_mode=output)
        writable_input = self.command(simulated_topology.BACKUP_INPUT)
        writable_input = [part.replace(",readonly=on", "")
                          for part in writable_input]
        with self.assertRaises(ValueError):
            self.audit(writable_input, backup_disk=self.disk,
                       backup_mode=simulated_topology.BACKUP_INPUT)
        for mode in (None, "backup-sideways"):
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    self.audit(argv, backup_disk=self.disk, backup_mode=mode)

    def test_a_path_qemu_would_split_is_refused(self):
        for path in (Path("relative.raw"), self.root / "a,b.raw"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    simulated_topology.backup_disk_args(
                        path, simulated_topology.BACKUP_OUTPUT)


class BackupRunTests(BackupFixture):
    def test_the_dry_run_prints_the_plan_and_starts_nothing(self):
        with self.inert():
            code, out, err = self.run_backup(apply=False)
        self.assertEqual(code, 0, err)
        self.assertIn("dry run; repeat with APPLY=1", out)
        self.assertIn("samba-tool domain backup offline", out)
        self.assertIn("serial TELOS-BACKUP-OUT", out)
        self.assertIn("last backup: none recorded", out)
        self.assertIn("id=backupdisk", out)
        for value in (REALM, DOMAIN, SID):
            self.assertNotIn(value, out)
        self.assertFalse(self.backups.exists())
        self.assertFalse(self.evidence.exists())
        self.assertEqual(self.calls, [])

    def test_a_backup_is_verified_kept_privately_and_recorded(self):
        with self.applied():
            code, out, err = self.run_backup()
        self.assertEqual(code, 0, err)
        self.assertEqual(self.calls[:4], ["prompt", "fabric", "fabric",
                                          "spawn"])
        self.assertEqual(
            [call for call in self.calls if call.startswith("backup-")
             or call == "poweroff"],
            ["backup-realm", "backup-domain-sid", "backup-dc-name",
             "backup-dbcheck", "backup-principals", "backup-write",
             "poweroff"])
        self.assertEqual(self.guests[0].signals, [])
        argv = self.guests[0].argv
        self.assertIn("virtio-blk-pci,drive=backupdisk,serial=TELOS-BACKUP-OUT",
                      argv)
        self.assertNotIn(PASSWORD.decode(), " ".join(argv))
        write = dict(self.commands)["backup-write"]
        self.assertIn("domain backup offline", write)
        self.assertIn("/dev/disk/by-id/virtio-TELOS-BACKUP-OUT", write)
        # The set: private, complete, and nothing else left behind.
        sets = self.backups / INSTANCE
        [backup_set] = list(sets.iterdir())
        self.assertEqual(sets.stat().st_mode & 0o777, 0o700)
        self.assertEqual(backup_set.stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            sorted(path.name for path in backup_set.iterdir()),
            ["manifest.json", "persistent-instance.json",
             "samba-backup.tar.bz2"])
        for path in backup_set.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, path)
        self.assertEqual((backup_set / "samba-backup.tar.bz2").read_bytes(),
                         TARBALL)
        manifest = json.loads((backup_set / "manifest.json").read_text())
        digest = hashlib.sha256(TARBALL).hexdigest()
        self.assertEqual(manifest["tarball"], {
            "name": "samba-backup.tar.bz2", "bytes": len(TARBALL),
            "sha256": digest})
        self.assertEqual(manifest["directory"], {
            "realm": REALM, "dns_domain": DOMAIN, "netbios": "EXAMPLEAD",
            "domain_sid": SID, "dc_server_name": "BOOTSTRAP-DC",
            "principals": PRINCIPALS})
        self.assertEqual(manifest["custody"], {
            "credential_custody": "owner", "throwaway": False, "store": None})
        self.assertEqual(runner.load_backup_set(backup_set).tarball, TARBALL)
        # The run's raw disk was shredded, with its staging directory.
        self.assertFalse(any(path.name.startswith(".")
                             for path in sets.iterdir()))
        last = PersistentControllerInstance(
            self.state, instance=INSTANCE).last_backup()
        self.assertEqual((last["path"], last["sha256"]),
                         (str(backup_set), digest))
        # Evidence carries no credential and no directory value.
        run, result = self.result(self.evidence)
        self.assertEqual(result["verdict"], "pass")
        self.assertTrue(all(result["checks"][key] is True
                            for key in runner.BACKUP_CHECKS))
        self.assertEqual(result["tarball_sha256"], digest)
        retained = b"".join(path.read_bytes() for path in run.iterdir())
        self.assertNotIn(PASSWORD, retained)
        rendered = (run / "result.json").read_text()
        for value in (REALM, DOMAIN, SID, PRINCIPALS):
            self.assertNotIn(value, rendered)
        for value in (REALM, DOMAIN, SID):
            self.assertNotIn(value, out)
        self.assertIn("PASS", out)
        self.assertFalse(self.lock_held())

    def test_an_agent_custody_backup_keeps_the_store_and_asks_nothing(self):
        self.make_agent()
        with self.applied():
            code, _, err = self.run_backup()
        self.assertEqual(code, 0, err)
        self.assertNotIn("prompt", self.calls)
        [backup_set] = list((self.backups / INSTANCE).iterdir())
        manifest = json.loads((backup_set / "manifest.json").read_text())
        self.assertEqual(manifest["custody"]["credential_custody"], "agent")
        self.assertTrue(manifest["custody"]["throwaway"])
        store = backup_set / runner.CUSTODY_COPY_NAME
        self.assertEqual(store.stat().st_mode & 0o777, 0o600)
        self.assertEqual(manifest["custody"]["store"]["sha256"],
                         hashlib.sha256(store.read_bytes()).hexdigest())
        loaded = runner.load_backup_set(backup_set)
        self.assertEqual(loaded.custody_document["administrator"],
                         ADMINISTRATOR)
        run, _ = self.result(self.evidence)
        retained = b"".join(path.read_bytes() for path in run.iterdir())
        for secret in (PASSWORD.decode(), ADMINISTRATOR, ACCOUNT):
            self.assertNotIn(secret.encode(), retained)

    def test_a_guest_failure_keeps_nothing_and_records_nothing(self):
        self.write_proof = b"FAIL:samba-tool"
        with self.applied():
            code, out, err = self.run_backup()
        self.assertEqual(code, 2)
        self.assertIn("failed at samba-tool", err)
        self.assertEqual(list((self.backups / INSTANCE).iterdir()), [])
        self.assertIsNone(PersistentControllerInstance(
            self.state, instance=INSTANCE).last_backup())
        _, result = self.result(self.evidence)
        self.assertEqual(result["failure"]["step"], "backup")
        self.assertTrue(result["checks"]["clean_poweroff"])
        self.assertIn("FAIL", out)

    def test_a_disk_that_disagrees_with_the_guest_proof_is_refused(self):
        self.write_proof = (hashlib.sha256(b"other").hexdigest()
                            + f":{len(TARBALL)}").encode()
        with self.applied():
            code, _, err = self.run_backup()
        self.assertEqual(code, 2)
        self.assertIn("not the one the guest proved", err)
        self.assertEqual(list((self.backups / INSTANCE).iterdir()), [])
        _, result = self.result(self.evidence)
        self.assertFalse(result["checks"]["disk_verified"])
        self.assertIsNone(PersistentControllerInstance(
            self.state, instance=INSTANCE).last_backup())

    def test_another_directory_is_refused_before_anything_is_backed_up(self):
        with self.applied():
            original = self.console_root

            def other_sid(console, command, label, *, value=None):
                if label == "backup-domain-sid":
                    return b"S-1-5-21-4444444444-5555555555-6666666666"
                return original(console, command, label, value=value)

            with mock.patch.object(runner, "_console_root",
                                   side_effect=other_sid):
                code, _, err = self.run_backup()
        self.assertEqual(code, 2)
        self.assertNotIn("backup-write", self.calls)
        self.assertIn("domain SID is not the expected one", err)
        self.assertNotIn(SID, err)

    def test_a_running_instance_is_refused_before_the_prompt(self):
        target = PersistentControllerInstance(self.state, instance=INSTANCE)
        target.prepare()
        self.addCleanup(target.close)
        with self.applied():
            code, _, err = self.run_backup()
        self.assertEqual(code, 2)
        self.assertIn("power it off first", err)
        self.assertEqual(self.calls, [])


class RestoreRunTests(BackupFixture):
    def test_the_dry_run_verifies_the_set_and_starts_nothing(self):
        backup_set = self.take_backup()
        with self.inert():
            code, out, err = self.run_restore(backup_set, apply=False)
        self.assertEqual(code, 0, err)
        self.assertIn("restore drill into a separate instance", out)
        self.assertIn("DC name: DR-", out)
        self.assertIn("never from a disk image", out)
        self.assertIn(f"dry run; repeat with APPLY=1 CONFIRM='RESTORE {DRILL}'",
                      out)
        for value in (REALM, DOMAIN, SID):
            self.assertNotIn(value, out)
        self.assertFalse((self.state.parent / DRILL).exists())
        self.assertFalse(self.restore_evidence.exists())

    def test_an_existing_instance_is_refused_dry_or_applied(self):
        backup_set = self.take_backup()
        for apply in (False, True):
            with self.subTest(apply=apply), self.inert():
                code, _, err = self.run_restore(
                    backup_set, apply=apply, instance=INSTANCE)
                self.assertEqual(code, 2)
                self.assertIn("exists and is not destroyed", err)
                self.assertIn(f"CONFIRM='DESTROY {INSTANCE}'", err)

    def test_a_wrong_confirmation_creates_nothing_and_asks_nothing(self):
        backup_set = self.take_backup()
        for confirm in ("", f"RESTORE {INSTANCE}", "restore lab-dc2",
                        f"DESTROY {DRILL}"):
            with self.subTest(confirm=confirm), self.inert():
                code, _, err = self.run_restore(backup_set, confirm=confirm)
                self.assertEqual(code, 2)
                self.assertIn(f"exact confirmation: RESTORE {DRILL}", err)
        self.assertFalse((self.state.parent / DRILL).exists())

    def test_a_missing_or_corrupt_set_is_refused(self):
        backup_set = self.take_backup()

        def refused(path, message):
            with self.inert():
                code, _, err = self.run_restore(path)
            self.assertEqual(code, 2)
            self.assertIn(message, err)
            for value in (REALM, SID):
                self.assertNotIn(value, err)
            self.assertFalse((self.state.parent / DRILL).exists())

        refused(self.root / "nowhere", "there is no backup set")
        tarball = backup_set / "samba-backup.tar.bz2"
        good = tarball.read_bytes()
        tarball.write_bytes(good[:-1] + bytes([good[-1] ^ 1]))
        refused(backup_set, "the set is corrupt")
        tarball.write_bytes(good)
        marker = backup_set / "persistent-instance.json"
        original = marker.read_bytes()
        marker.write_bytes(original.replace(b'"EXAMPLEAD"', b'"OTHERAD"'))
        refused(backup_set, "marker copy does not match")
        marker.write_bytes(original)
        backup_set.chmod(0o755)
        refused(backup_set, "mode 0700")
        backup_set.chmod(0o700)
        tarball.chmod(0o644)
        refused(backup_set, "mode 0600")
        tarball.chmod(0o600)
        (backup_set / runner.CUSTODY_COPY_NAME).write_text("{}")
        (backup_set / runner.CUSTODY_COPY_NAME).chmod(0o600)
        refused(backup_set, "owner-custody backup holds a custody store")

    def test_a_realm_or_sid_mismatch_is_refused_before_anything_starts(self):
        backup_set = self.take_backup()
        manifest_path = backup_set / "manifest.json"
        original = json.loads(manifest_path.read_text())
        for key, value in (
                ("realm", "OTHER.EXAMPLE.HOME.ARPA"),
                ("domain_sid", "S-1-5-21-4444444444-5555555555-6666666666")):
            with self.subTest(key=key):
                manifest = json.loads(json.dumps(original))
                manifest["directory"][key] = value
                manifest_path.write_text(json.dumps(manifest))
                with self.inert():
                    code, _, err = self.run_restore(backup_set)
                self.assertEqual(code, 2)
                self.assertIn("disagree on", err)
                self.assertNotIn(value, err)
        manifest_path.write_text(json.dumps(original))
        other = self.root / "other-identity.json"
        other.write_text(json.dumps(identity_document(
            realm="OTHER.EXAMPLE.HOME.ARPA", domain="other.example.home.arpa")))
        with self.inert():
            code, _, err = self.run_restore(backup_set, identity=other)
        self.assertEqual(code, 2)
        self.assertIn("not the domain the overlay declares", err)

    def test_the_backed_up_dcs_own_name_is_refused(self):
        backup_set = self.take_backup()
        for name in ("bootstrap-dc", "BOOTSTRAP-DC", "Bad_Name", "1dc"):
            with self.subTest(name=name), self.inert():
                code, _, err = self.run_restore(
                    backup_set, apply=False, dc_name=name)
                self.assertEqual(code, 2)
                self.assertIn("RESTORE_DC_NAME", err)

    def test_a_drill_restores_proves_and_records_the_directory(self):
        backup_set = self.take_backup()
        with self.applied():
            code, out, err = self.run_restore(backup_set)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.calls[:3], ["prompt", "create", "spawn"])
        self.assertEqual(
            [call for call in self.calls
             if call.startswith("restore-") or call in ("ad", "poweroff")],
            ["restore-run", "restore-samba-start", "ad", "restore-realm",
             "restore-domain-sid", "restore-principals", "poweroff"])
        self.assertNotIn("fabric", self.calls)
        argv = self.guests[0].argv
        self.assertFalse(any("-netdev" == part for part in argv))
        self.assertIn("virtio-blk-pci,drive=backupdisk,serial=TELOS-BACKUP-IN",
                      argv)
        drive = next(part for part in argv if "id=backupdisk" in part)
        self.assertIn("readonly=on", drive)
        command = dict(self.commands)["restore-run"]
        self.assertIn("domain backup restore", command)
        self.assertIn("--targetdir=/var/lib/samba", command)
        self.assertRegex(command, r"--newservername=dr-[0-9]{10} ")
        # The input disk and its private directory are gone.
        self.assertFalse(Path(drive.rpartition("file=")[2]).exists())
        self.assertEqual(
            [path.name for path in (self.restore_evidence / DRILL).iterdir()
             if path.name.startswith(".")], [])
        restored = PersistentControllerInstance(
            self.state.parent / DRILL, instance=DRILL)
        source = PersistentControllerInstance(self.state, instance=INSTANCE)
        self.assertEqual(restored.convergence(), source.convergence())
        self.assertEqual(restored.directory_accounts(),
                         source.directory_accounts())
        self.assertEqual(restored.directory_password_policy(),
                         source.directory_password_policy())
        self.assertEqual(restored.directory_account_password_resets(),
                         source.directory_account_password_resets())
        record = restored.restored()
        self.assertEqual(record["replaced_dc_server_name"], "BOOTSTRAP-DC")
        self.assertRegex(record["dc_server_name"], r"^dr-[0-9]{10}$")
        self.assertEqual(record["source_instance"], INSTANCE)
        self.assertEqual(record["backup_sha256"],
                         hashlib.sha256(TARBALL).hexdigest())
        _, result = self.result(self.restore_evidence, DRILL)
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["checks"]["principals"], "match")
        self.assertEqual(result["network"], "none")
        rendered = json.dumps(result)
        for value in (REALM, DOMAIN, SID, PASSWORD.decode()):
            self.assertNotIn(value, rendered)
        for value in (REALM, SID):
            self.assertNotIn(value, out)
        # The source instance was not touched.
        self.assertIsNone(source.restored())
        # Samba's restore gave the DC a new name: no durable stage binds it.
        with self.assertRaisesRegex(durable_workstation.DurableBindingError,
                                    "restored from a Samba backup"):
            durable_workstation.durable_binding(
                self.state.parent, DRILL, canonical_state=self.canonical,
                identity_path=self.identity)
        self.assertFalse(self.lock_held())

    def test_disaster_recovery_into_the_lost_instances_own_name(self):
        backup_set = self.take_backup()
        code = bootstrap_dc.persistent_destroy(
            self.state.parent, INSTANCE, f"DESTROY {INSTANCE}")
        self.assertEqual(code, 0)
        with self.applied():
            code, out, err = self.run_restore(
                backup_set, instance=INSTANCE, dc_name="dr-recovery")
        self.assertEqual(code, 0, err)
        self.assertIn("disaster recovery into the lost instance's own name",
                      out)
        record = PersistentControllerInstance(
            self.state, instance=INSTANCE).restored()
        self.assertEqual(record["dc_server_name"], "dr-recovery")

    def test_a_different_live_directory_records_nothing(self):
        backup_set = self.take_backup()
        for attribute, value, message in (
                ("live_sid", "S-1-5-21-4444444444-5555555555-6666666666",
                 "domain SID is not the expected one"),
                ("live_principals", "16:" + "0" * 64,
                 "security principals are not the backup's"),
                ("restore_proof", b"FAIL:checksum",
                 "in-guest restore failed at checksum")):
            with self.subTest(attribute=attribute):
                saved = getattr(self, attribute)
                setattr(self, attribute, value)
                try:
                    with self.applied():
                        code, _, err = self.run_restore(backup_set)
                finally:
                    setattr(self, attribute, saved)
                self.assertEqual(code, 2)
                self.assertIn(message, err)
                self.assertIn("before restoring again", err)
                target = PersistentControllerInstance(
                    self.state.parent / DRILL, instance=DRILL)
                self.assertIsNone(target.convergence())
                self.assertIsNone(target.restored())
                self.assertEqual(self.guests[-1].signals, [])
                self.assertEqual(self.calls[-1], "poweroff")
                self.assertEqual(0, bootstrap_dc.persistent_destroy(
                    self.state.parent, DRILL, f"DESTROY {DRILL}"))

    def test_an_agent_custody_backup_restores_its_credentials(self):
        self.make_agent()
        backup_set = self.take_backup()
        loaded = runner.load_backup_set(backup_set)
        self.assertEqual(loaded.custody, cc.AGENT)
        self.console_password = NEW_CONSOLE.encode()
        self.guest_output = (
            b"bootstrap-dc login: local-rescue\r\nPassword: "
            + NEW_CONSOLE.encode() + b"\r\n$ ")
        with self.applied():
            code, out, err = self.run_restore(backup_set)
        self.assertEqual(code, 0, err)
        self.assertNotIn("prompt", self.calls)
        self.assertIn("credential custody: agent (throwaway)", out)
        target = PersistentControllerInstance(
            self.state.parent / DRILL, instance=DRILL)
        self.assertEqual(target.credential_custody(), cc.AGENT)
        store = cc.instance_store(target).read()
        # The new disk's console credential; the directory's own passwords.
        self.assertEqual(store["console"], NEW_CONSOLE)
        self.assertEqual(store["administrator"], ADMINISTRATOR)
        self.assertEqual(store["accounts"],
                         {"standard_user": {"current": ACCOUNT}})
        run, _ = self.result(self.restore_evidence, DRILL)
        retained = b"".join(path.read_bytes() for path in run.iterdir())
        for secret in PRIVATE:
            self.assertNotIn(secret.encode(), retained)

    def test_an_agent_set_without_its_store_is_refused(self):
        self.make_agent()
        backup_set = self.take_backup()
        (backup_set / runner.CUSTODY_COPY_NAME).unlink()
        with self.inert():
            code, _, err = self.run_restore(backup_set)
        self.assertEqual(code, 2)
        self.assertIn("no readable custody store", err)


class RestoreRecordTests(SessionFixture):
    """The marker records a restore writes, validated like their writers."""

    def restored(self, **changes):
        record = {
            "utc": "2026-09-30T12:00:00+00:00", "run_id": "r",
            "backup_path": "/sets/x", "backup_sha256": "a" * 64,
            "backup_created_utc": "2026-09-30T11:00:00+00:00",
            "source_instance": INSTANCE, "dc_server_name": "dr-1",
            "replaced_dc_server_name": "BOOTSTRAP-DC",
        }
        record.update(changes)
        return record

    def test_a_restore_fills_only_a_fresh_instance(self):
        records = {"converged": self.target.convergence()}
        with self.assertRaisesRegex(PersistentInstanceInvalid,
                                    "already records a directory"):
            self.target.record_restoration(records, self.restored())

    def test_unusable_restore_and_last_backup_records_are_refused(self):
        for changes in ({"dc_server_name": "BOOTSTRAP-DC"},
                        {"backup_sha256": "x"}, {"extra": "y"},
                        {"dc_server_name": "a b"}, {"utc": ""}):
            with self.subTest(changes=changes):
                with self.assertRaises(PersistentInstanceInvalid):
                    self.target._validated_restored(self.restored(**changes))
        for record in ({"utc": "u", "path": "p", "sha256": "a" * 64},
                       {"utc": "u", "path": "p", "sha256": "x", "run_id": "r"},
                       {"utc": "u", "path": "p", "sha256": "a" * 64,
                        "run_id": "r", "secret": "v"}):
            with self.subTest(record=record):
                with self.assertRaises(PersistentInstanceInvalid):
                    self.target.record_last_backup(record)
        self.assertIsNone(self.target.last_backup())
        self.target.record_last_backup(
            {"utc": "u", "path": "p", "sha256": "a" * 64, "run_id": "r"})
        self.assertEqual(self.target.last_backup()["path"], "p")

    def test_status_reports_the_last_backup(self):
        marker = self.target.read_marker()
        marker["seeded_from"] = {"disk": "/canonical", "disk_sha256": "c" * 64,
                                 "vars_sha256": "d" * 64}
        self.target._write_marker(marker)
        self.target.record_last_backup(
            {"utc": "2026-09-30T12:00:00+00:00", "path": "/sets/lab-dc1/r",
             "sha256": "a" * 64, "run_id": "r"})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bootstrap_dc.persistent_status(self.state.parent, INSTANCE)
        self.assertIn("samba backup: last 2026-09-30T12:00:00+00:00 at "
                      "/sets/lab-dc1/r", out.getvalue())


class CommandLineTests(unittest.TestCase):
    def test_both_verbs_parse_and_default_to_the_ignored_backup_root(self):
        args = runner.parser().parse_args(
            ["backup", "--instance", "x"])
        self.assertEqual(args.backup_root, Path("homelab/var/backups"))
        self.assertFalse(args.apply)
        args = runner.parser().parse_args(
            ["--state-dir", "/s", "restore", "--instance", "x", "--backup",
             "/b", "--confirm", "RESTORE x", "--restore-dc-name", "dr-1",
             "--apply"])
        self.assertEqual((args.backup, args.confirm, args.restore_dc_name),
                         (Path("/b"), "RESTORE x", "dr-1"))
        self.assertEqual(args.state_dir, Path("/s"))
        self.assertTrue(args.apply)

    def test_the_default_dc_name_is_a_new_netbios_name(self):
        from datetime import UTC, datetime
        name = runner.default_restore_dc_name(
            datetime(2026, 9, 30, 21, 5, tzinfo=UTC))
        self.assertEqual(name, "dr-2609302105")
        self.assertTrue(disk.NEW_SERVER_NAME.fullmatch(name))
        self.assertLessEqual(len(name), 15)


if __name__ == "__main__":
    unittest.main()
