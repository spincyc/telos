"""Contracts for the canonical Controller installation driver.

The two that matter most are not about mechanism. First, the operator types
the erasure confirmation and this driver only relays it, so ADR 0058's
property -- that a person answered the final confirmation -- survives
automation. Second, the console password is read at a terminal and reaches
argv, the receipt, the console capture and the environment nowhere at all.
"""

import contextlib
import io
import json
import re
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vm"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import bootstrap_dc  # noqa: E402
import bootstrap_install  # noqa: E402
import fake_image_tools  # noqa: E402
from controller_factory_install import (  # noqa: E402
    FactoryInstallResult,
    FactoryInstallSerial,
)
from serial_automation import SerialAutomationError  # noqa: E402

PASSWORD = "console-secret-typed"
#: What the operator types. Built here from parts so that even the test file
#: does not hand the driver a ready-made literal to copy.
CONFIRMATION = "ERASE " + bootstrap_dc.DISK_SERIAL
ARCH_LABEL = "ARCH_202608"


def fake_tools(argv, **kwargs):
    """``fake_image_tools`` plus the two xorriso reads the driver makes."""
    argv = [str(part) for part in argv]
    if argv[0] != "xorriso":
        return fake_image_tools.image_tool(argv, **kwargs)
    if "-pvd_info" in argv:
        return subprocess.CompletedProcess(
            argv, 0, f"  Volume id    : '{ARCH_LABEL}'\n", "")
    if "-extract" in argv:
        destination = Path(argv[-1])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"extracted " + argv[-2].encode())
        return subprocess.CompletedProcess(argv, 0, "", "")
    return subprocess.CompletedProcess(argv, 0, "", "")


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "bootstrap-dc"
        self.state.mkdir(mode=0o700)
        self.files = bootstrap_dc.paths(self.state)
        # A canonical image that is byte-identical to what the fake
        # ``qemu-img create`` produces, which is exactly the freshness the
        # driver requires before it will erase anything.
        fake_image_tools.blank_image(self.files["disk"])
        self.files["vars"].write_bytes(b"OVMF variables")
        self.files["manifest"].write_text(json.dumps({
            "schema": 1,
            "name": bootstrap_dc.NAME,
            "disk": {
                "format": "qcow2",
                "size": bootstrap_dc.DISK_SIZE,
                "serial": bootstrap_dc.DISK_SERIAL,
            },
        }))
        for key in ("disk", "vars", "manifest"):
            self.files[key].chmod(0o600)
        self.arch_iso = self.root / "arch.iso"
        self.arch_iso.write_bytes(b"arch installation medium")
        self.seed_iso = self.root / "seed.iso"
        self.seed_iso.write_bytes(b"telos seed medium")
        self.typed = []
        self.launches = []

    # -- harness ---------------------------------------------------------
    def _install_result(self):
        return FactoryInstallResult(True, True, (
            "archiso-login-prompt", "seed-receipt-verified",
            "disk-erasure-prompt", "disk-erasure-authorized",
            "console-password-prompt", "console-password-updated",
            "installation-complete", "poweroff-observed",
        ))

    def _run_qemu(self, command, protocol, **kwargs):
        self.launches.append({
            "command": list(command),
            "protocol": protocol,
            # Snapshot: the live buffer is zeroed before the call returns,
            # which ``test_the_password_buffer_is_zeroed_after_the_run``
            # asserts on the same object.
            "password_at_launch": bytes(protocol.password),
            "kwargs": dict(kwargs),
        })
        # A real installation leaves an installed image behind; model that, so
        # the driver's own post-install proof runs against something real.
        fake_image_tools.installed_image(
            self.files["disk"], b" installed by the driver")
        self.files["disk"].chmod(0o600)
        return self._install_result()

    def _getpass(self, prompt):
        self.typed.append(prompt)
        return PASSWORD

    @contextlib.contextmanager
    def harness(self, *, terminal=True, run_qemu=None, users=()):
        with contextlib.ExitStack() as stack:
            for patch in (
                mock.patch.object(
                    bootstrap_install.subprocess, "run",
                    side_effect=fake_tools),
                mock.patch.object(
                    bootstrap_install.shutil, "which",
                    side_effect=lambda tool: "/usr/bin/" + tool),
                mock.patch.object(
                    bootstrap_dc, "ovmf_pair",
                    return_value=(Path("/code.fd"), Path("/vars.fd"))),
                mock.patch.object(
                    bootstrap_install, "canonical_disk_users",
                    return_value=list(users)),
                mock.patch.object(
                    bootstrap_dc, "_controlling_terminal",
                    return_value=terminal),
                mock.patch.object(
                    bootstrap_dc.getpass, "getpass",
                    side_effect=self._getpass),
                mock.patch.object(
                    bootstrap_install, "_run_qemu",
                    side_effect=run_qemu or self._run_qemu),
            ):
                stack.enter_context(patch)
            yield

    def call(self, *argv, expect, **harness):
        out, err = io.StringIO(), io.StringIO()
        with self.harness(**harness), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = bootstrap_install.main([
                "--state-dir", str(self.state),
                "--iso", str(self.arch_iso),
                "--seed-iso", str(self.seed_iso),
                *argv,
            ])
        self.assertEqual(code, expect, err.getvalue() or out.getvalue())
        return out.getvalue(), err.getvalue()

    def receipt(self):
        return json.loads(
            (self.state / bootstrap_install.RECEIPT_NAME).read_text())

    # -- the dry run -----------------------------------------------------
    def test_the_dry_run_prints_the_boundary_and_changes_nothing(self):
        before = {path.name: path.read_bytes()
                  for path in self.state.iterdir()}
        out, _ = self.call(expect=0)
        after = {path.name: path.read_bytes()
                 for path in self.state.iterdir()}
        self.assertEqual(before, after)
        self.assertEqual(sorted(before), sorted(after))
        self.assertEqual(self.launches, [])
        self.assertEqual(self.typed, [])
        self.assertIn("dry run", out)
        # The boundary summary the other targets print.
        self.assertIn(str(self.files["disk"]), out)
        self.assertIn(bootstrap_dc.DISK_SERIAL, out)
        self.assertIn("byte-identical to a newly created", out)
        self.assertIn("network: none", out)
        self.assertIn("qemu-system-x86_64", out)
        self.assertIn(f"archisolabel={ARCH_LABEL}", out)
        self.assertIn("console=ttyS0,115200n8", out)

    def test_the_dry_run_needs_no_confirmation_and_no_terminal(self):
        self.call(expect=0, terminal=False)
        self.assertEqual(self.typed, [])

    # -- the launch argv --------------------------------------------------
    def test_the_argv_carries_exactly_one_canonical_serial_and_no_network(self):
        self.call("--confirm", CONFIRMATION, "--apply", expect=0)
        command = self.launches[0]["command"]
        joined = " ".join(command)
        self.assertEqual(
            sum(part.count(f"serial={bootstrap_dc.DISK_SERIAL}")
                for part in command), 1)
        self.assertIn("-nic", command)
        self.assertNotIn("-netdev", command)
        # The canonical qcow2 and the canonical firmware variables, not a
        # temporary raw disk.
        self.assertIn(f"format=qcow2,cache=none,file={self.files['disk']}",
                      joined)
        self.assertIn(f"if=pflash,format=raw,file={self.files['vars']}",
                      joined)
        # Direct kernel boot: no manual boot-menu edit is possible or needed.
        self.assertIn("-kernel", command)
        self.assertIn("-initrd", command)
        # Both media are read-only.
        self.assertEqual(joined.count("media=cdrom,readonly=on"), 2)

    def test_a_second_device_carrying_the_serial_is_refused(self):
        with self.harness():
            with self.assertRaisesRegex(
                    bootstrap_install.InstallRefused, "exactly one"):
                bootstrap_install.install_command(
                    self.files, self.root, self.arch_iso, self.seed_iso,
                    ARCH_LABEL + f" serial={bootstrap_dc.DISK_SERIAL}")

    # -- the confirmation is the operator's ------------------------------
    def test_an_applied_run_without_a_confirmation_refuses(self):
        _, err = self.call("--apply", expect=2)
        self.assertIn("requires the erasure confirmation", err)
        self.assertIn("only relays it", err)
        self.assertEqual(self.launches, [])
        self.assertEqual(self.typed, [])

    def test_whatever_the_operator_typed_is_what_the_guest_receives(self):
        typo = "ERASE TELOS-BOOTSTRAP-DC2"
        self.call("--confirm", typo, "--apply", expect=0)
        self.assertEqual(
            self.launches[0]["protocol"].confirmation, typo.encode())
        # The driver did not silently correct it: only the guest may judge.
        self.assertNotEqual(
            self.launches[0]["protocol"].confirmation, CONFIRMATION.encode())

    def test_the_driver_holds_no_copy_of_the_phrase_it_could_send(self):
        """ADR 0058: a *person* answers the confirmation.

        A literal here would be a code path that reaches a destructive
        operation without anyone having typed anything, which is precisely
        what the ADR forbids. The disposable acceptance path keeps its own
        default, because there the harness answering is the decision the ADR
        records.
        """
        source = Path(bootstrap_install.__file__).read_text()
        self.assertNotIn(bootstrap_dc.DISK_SERIAL, source)
        self.assertNotIn("ERASE", source)

    def test_a_multiline_or_control_confirmation_is_refused(self):
        for bad in ("", "one\ntwo", "with\ttab\x01"):
            with self.subTest(confirmation=bad):
                with self.assertRaises(bootstrap_install.InstallRefused):
                    bootstrap_install._validated_confirmation(bad)

    # -- the fail-closed guards ------------------------------------------
    def test_a_disk_that_is_no_longer_fresh_refuses(self):
        fake_image_tools.installed_image(
            self.files["disk"], b" a working Controller")
        self.files["disk"].chmod(0o600)
        _, err = self.call("--confirm", CONFIRMATION, "--apply", expect=2)
        self.assertIn("no longer a freshly created", err)
        # It says what it found, so the operator knows what they nearly wiped.
        self.assertIn("installed", err)
        self.assertIn("destroy and recreate the state deliberately", err)
        self.assertEqual(self.launches, [])
        self.assertEqual(self.typed, [])

    def test_a_manifest_naming_another_serial_refuses(self):
        manifest = json.loads(self.files["manifest"].read_text())
        manifest["disk"]["serial"] = "SOME-OTHER-DISK"
        self.files["manifest"].write_text(json.dumps(manifest))
        _, err = self.call("--confirm", CONFIRMATION, "--apply", expect=2)
        self.assertIn("declares disk serial", err)
        self.assertEqual(self.launches, [])

    def test_a_manifest_naming_another_format_refuses(self):
        manifest = json.loads(self.files["manifest"].read_text())
        manifest["disk"]["format"] = "raw"
        self.files["manifest"].write_text(json.dumps(manifest))
        _, err = self.call("--confirm", CONFIRMATION, "--apply", expect=2)
        self.assertIn("declares a 'raw' disk", err)

    def test_an_absent_state_refuses_and_names_the_create_target(self):
        for key in ("disk", "vars", "manifest"):
            self.files[key].unlink()
        _, err = self.call("--confirm", CONFIRMATION, "--apply", expect=2)
        self.assertIn("homelab-bootstrap-vm-create", err)
        self.assertEqual(self.launches, [])

    def test_a_world_readable_state_refuses(self):
        self.files["manifest"].chmod(0o644)
        _, err = self.call("--confirm", CONFIRMATION, "--apply", expect=2)
        self.assertIn("0700 with 0600", err)

    def test_a_state_reachable_through_a_symlink_refuses(self):
        link = self.root / "linked-state"
        link.symlink_to(self.state, target_is_directory=True)
        out, err = io.StringIO(), io.StringIO()
        with self.harness(), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = bootstrap_install.main([
                "--state-dir", str(link),
                "--iso", str(self.arch_iso),
                "--seed-iso", str(self.seed_iso),
            ])
        self.assertEqual(code, 2)
        self.assertIn("symlink", err.getvalue())

    def test_a_canonical_another_process_holds_open_refuses(self):
        _, err = self.call(
            "--confirm", CONFIRMATION, "--apply", expect=2,
            users=["qemu-system-x86_64 [4242]"])
        self.assertIn("open by", err)
        self.assertEqual(self.launches, [])

    def test_missing_media_refuse_before_anything_is_read(self):
        self.seed_iso.unlink()
        _, err = self.call("--confirm", CONFIRMATION, "--apply", expect=2)
        self.assertIn("seed ISO", err)

    # -- the credential ---------------------------------------------------
    def test_no_controlling_terminal_refuses_and_starts_nothing(self):
        _, err = self.call(
            "--confirm", CONFIRMATION, "--apply", expect=2, terminal=False)
        self.assertIn("controlling terminal", err)
        self.assertIn("not a file, argv", err)
        self.assertEqual(self.launches, [])

    def test_the_credential_is_typed_twice_and_never_leaves_memory(self):
        self.call("--confirm", CONFIRMATION, "--apply", expect=0)
        self.assertEqual(len(self.typed), 2)
        self.assertIn("New console password", self.typed[0])
        self.assertIn("Retype", self.typed[1])
        launch = self.launches[0]
        self.assertNotIn(PASSWORD, " ".join(launch["command"]))
        # It is handed to the console protocol and declared to the redactor,
        # and to nothing else.
        self.assertEqual(launch["password_at_launch"], PASSWORD.encode())
        self.assertIn(
            PASSWORD.encode(), launch["kwargs"]["diagnostic_secrets"])
        self.assertEqual(
            launch["kwargs"]["diagnostic_path"],
            self.state / bootstrap_install.DIAGNOSTIC_NAME)
        # Not in the receipt, and not in any file the run left behind.
        self.assertNotIn(PASSWORD, json.dumps(self.receipt()))
        for path in self.state.iterdir():
            self.assertNotIn(
                PASSWORD.encode(), path.read_bytes(), f"leaked into {path}")

    def test_the_password_buffer_is_zeroed_after_the_run(self):
        self.call("--confirm", CONFIRMATION, "--apply", expect=0)
        buffer = self.launches[0]["protocol"].password
        self.assertEqual(bytes(buffer), bytes(len(PASSWORD)))

    def test_mismatched_entries_refuse_before_the_guest_starts(self):
        entries = iter([PASSWORD, "something-else"])

        def typed(prompt):
            self.typed.append(prompt)
            return next(entries)

        out, err = io.StringIO(), io.StringIO()
        with self.harness(), mock.patch.object(
                bootstrap_dc.getpass, "getpass", side_effect=typed), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = bootstrap_install.main([
                "--state-dir", str(self.state),
                "--iso", str(self.arch_iso), "--seed-iso", str(self.seed_iso),
                "--confirm", CONFIRMATION, "--apply",
            ])
        self.assertEqual(code, 2)
        self.assertIn("did not match", err.getvalue())
        self.assertEqual(self.launches, [])

    # -- the receipt ------------------------------------------------------
    def test_the_receipt_records_the_run_and_is_private(self):
        self.call("--confirm", CONFIRMATION, "--apply", expect=0)
        path = self.state / bootstrap_install.RECEIPT_NAME
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        receipt = self.receipt()
        self.assertEqual(
            receipt["kind"], "controller-canonical-install-receipt")
        self.assertRegex(receipt["installed_utc"], r"^\d{4}-\d\d-\d\dT")
        disk = receipt["disk"]
        self.assertEqual(disk["serial"], bootstrap_dc.DISK_SERIAL)
        self.assertEqual(disk["format"], "qcow2")
        self.assertNotEqual(disk["sha256_before"], disk["sha256_after"])
        self.assertTrue(disk["image_state_after"]["installed"])
        media = receipt["media"]
        self.assertEqual(
            media["arch_iso"]["sha256"],
            bootstrap_install._sha256(self.arch_iso))
        self.assertEqual(
            media["seed_iso"]["sha256"],
            bootstrap_install._sha256(self.seed_iso))
        self.assertTrue(media["seed_iso"]["receipt_sha256"])
        # The whole argv, and the ordered secret-free console events.
        self.assertEqual(
            receipt["qemu"]["argv"], self.launches[0]["command"])
        self.assertEqual(
            receipt["console"]["events"], list(self._install_result().events))
        self.assertIn("disk-erasure-authorized", receipt["console"]["events"])
        self.assertIn("console-password-updated", receipt["console"]["events"])
        self.assertIn("installation-complete", receipt["console"]["events"])
        self.assertEqual(
            receipt["console"]["completion_line_observed"],
            bootstrap_install.COMPLETION_LINE)
        # And it says, in words, that the credential is deliberately absent.
        self.assertIn("deliberately not recorded", receipt["credential"])
        self.assertIn("relayed", receipt["confirmation"])

    def test_a_completion_line_that_was_not_observed_is_not_claimed(self):
        def without_completion(command, protocol, **kwargs):
            self._run_qemu(command, protocol, **kwargs)
            return FactoryInstallResult(True, True, ("poweroff-observed",))

        self.call(
            "--confirm", CONFIRMATION, "--apply", expect=0,
            run_qemu=without_completion)
        self.assertIsNone(
            self.receipt()["console"]["completion_line_observed"])

    def test_a_guest_that_did_not_install_writes_no_receipt(self):
        def failed(command, protocol, **kwargs):
            self.launches.append({
                "command": list(command), "protocol": protocol,
                "kwargs": dict(kwargs)})
            raise SerialAutomationError("timed out waiting for archiso login")

        _, err = self.call(
            "--confirm", CONFIRMATION, "--apply", expect=2, run_qemu=failed)
        self.assertIn("installation did not complete", err)
        self.assertFalse(
            (self.state / bootstrap_install.RECEIPT_NAME).exists())

    def test_a_guest_that_claims_success_on_a_blank_disk_is_not_believed(self):
        def lying(command, protocol, **kwargs):
            self.launches.append({
                "command": list(command), "protocol": protocol,
                "kwargs": dict(kwargs)})
            return self._install_result()

        _, err = self.call(
            "--confirm", CONFIRMATION, "--apply", expect=2, run_qemu=lying)
        self.assertIn("does not look installed", err)


class RelayProtocolTests(unittest.TestCase):
    """The serial exchange, driven against a scripted guest."""

    def drive(self, responder, *, confirmation):
        left, right = socket.socketpair()
        thread = threading.Thread(target=responder, args=(right,), daemon=True)
        thread.start()
        try:
            return FactoryInstallSerial(
                left.makefile("rb", buffering=0),
                left.makefile("wb", buffering=0),
                b"ephemeral-password",
                confirmation=confirmation,
                timeout=2,
            ).run()
        finally:
            left.close()
            right.close()
            thread.join(timeout=2)

    @staticmethod
    def _prologue(sock, stream, sent):
        sock.sendall(b"archiso login: ")
        sent.append(stream.readline())
        sock.sendall(b"root@archiso ~ # ")
        sent.append(stream.readline())
        token = sent[-1].split(b"__TELOS_SEED_", 1)[1].split(b"__", 1)[0]
        sock.sendall(
            b"seed receipt verified\n__TELOS_SEED_" + token + b"__\n# ")
        sent.append(stream.readline())
        sock.sendall(b"Type ERASE TELOS-BOOTSTRAP-DC1 to continue: ")
        sent.append(stream.readline())

    def test_the_operator_phrase_is_relayed_byte_for_byte(self):
        sent = []
        typed = b"ERASE TELOS-BOOTSTRAP-DC1"

        def responder(sock):
            stream = sock.makefile("rb", buffering=0)
            self._prologue(sock, stream, sent)
            sock.sendall(b"New password: ")
            sent.append(stream.readline())
            sock.sendall(b"Retype new password: ")
            sent.append(stream.readline())
            sock.sendall(
                b"passwd: password updated successfully\n"
                b"Controller installation complete. "
                b"Remove both ISOs and reboot.\n# ")
            sent.append(stream.readline())
            sock.sendall(b"Reached target System Power Off.\n")

        result = self.drive(responder, confirmation=typed)
        self.assertTrue(result.installed)
        self.assertEqual(sent[3], typed + b"\n")
        self.assertIn("disk-erasure-authorized", result.events)

    def test_a_refused_confirmation_stops_at_once_and_says_why(self):
        """A typo must not become a twenty-minute timeout."""
        sent = []

        def responder(sock):
            stream = sock.makefile("rb", buffering=0)
            self._prologue(sock, stream, sent)
            sock.sendall(b"install-controller: confirmation did not match\n")

        with self.assertRaisesRegex(
                SerialAutomationError, "confirmation did not match"):
            self.drive(responder, confirmation=b"ERASE WRONG-SERIAL")
        self.assertEqual(sent[3], b"ERASE WRONG-SERIAL\n")

    def test_a_blank_or_multiline_confirmation_is_rejected_at_construction(self):
        for bad in (b"", b"one\ntwo", b"one\rtwo"):
            with self.subTest(confirmation=bad):
                with self.assertRaisesRegex(ValueError, "confirmation"):
                    FactoryInstallSerial(
                        io.BytesIO(), io.BytesIO(), b"password",
                        confirmation=bad)


class ModuleShapeTests(unittest.TestCase):
    def test_the_driver_never_reads_a_credential_from_the_environment(self):
        source = Path(bootstrap_install.__file__).read_text()
        self.assertNotIn("os.environ", source)
        self.assertNotIn("getenv", source)

    def test_the_fresh_fingerprint_is_derived_not_hard_coded(self):
        source = Path(bootstrap_install.__file__).read_text()
        # 197,888 is what a fresh 80 GiB qcow2 happens to be today. Hard-coding
        # it would make the guard silently wrong on a qemu that changes it.
        self.assertNotIn("197888", source)
        self.assertTrue(
            re.search(r"qemu-img\", \"create\"", source),
            "the reference image is created by qemu-img at run time")


if __name__ == "__main__":
    unittest.main()
