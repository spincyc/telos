"""Credential custody (TASK-40): the store, generation, the marker, sources,
agent-custody creation and destroy.

Nothing here boots QEMU, runs sudo, or reads ``build/``, ``homelab/var/`` or
``homelab/instance/``: every instance, workstation and store lives in a
temporary directory, the canonical image is ``fake_image_tools``' model, the
init boot's guest is a scripted socket, and the one real-tool test builds a
tiny GPT disk with ``sfdisk`` and ``mtools`` to prove the one-run entry is
selected and then removed byte-for-byte.  Every credential is synthetic or
generated.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from homelab.tests import fake_image_tools
from homelab.tests.identity_overlay_pin import pinned_acceptance_state
from homelab.vm import agent_console_init as aci
from homelab.vm import automated_controller
from homelab.vm import bootstrap_dc
from homelab.vm import controller_principals
from homelab.vm import credential_custody as cc
from homelab.vm import simulation_overlay as so
from homelab.vm import workstation_instance as wi
from homelab.vm.windows_durable_join import typeable_problem


def setUpModule():
    unittest.enterModuleContext(pinned_acceptance_state())


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def write_instance(root: Path, name: str = "agent-dc", *,
                   custody: str | None = cc.AGENT, throwaway: bool = True,
                   console: str | None = "Console0Stored1Value",
                   extra: dict | None = None) -> so.PersistentControllerInstance:
    """A persistent instance on disk, its marker written directly."""
    state = Path(root) / name
    state.mkdir(mode=0o700, parents=True)
    for file_name, content in ((so.PERSISTENT_DISK_NAME, b"disk"),
                               (so.PERSISTENT_VARS_NAME, b"vars")):
        (state / file_name).write_bytes(content)
        (state / file_name).chmod(0o600)
    marker = {
        "schema": so.PERSISTENT_MARKER_SCHEMA, "mode": so.PERSISTENT_MODE,
        "instance": name, "created_utc": "2026-09-30T00:00:00+00:00",
        "disk": {"format": "qcow2", "name": so.PERSISTENT_DISK_NAME},
        "seeded_from": {"disk": "/canonical", "disk_sha256": "0" * 64,
                        "vars_sha256": "1" * 64},
    }
    if custody is not None:
        marker[cc.CUSTODY_KEY] = custody
        marker[cc.THROWAWAY_KEY] = throwaway
    marker.update(extra or {})
    (state / so.PERSISTENT_MARKER_NAME).write_text(json.dumps(marker))
    target = so.PersistentControllerInstance(state, instance=name)
    if custody == cc.AGENT and console is not None:
        cc.instance_store(target).create({"console": console})
    return target


class GenerationTests(unittest.TestCase):
    def test_values_are_long_three_class_typeable_and_meet_the_default(self):
        seen = set()
        for _ in range(200):
            value = cc.generate_password()
            seen.add(value)
            self.assertEqual(cc.GENERATED_LENGTH, len(value))
            self.assertTrue(any(c.isupper() for c in value))
            self.assertTrue(any(c.islower() for c in value))
            self.assertTrue(any(c.isdigit() for c in value))
            self.assertTrue(set(value) <= set(cc.ALPHABET))
            self.assertIsNone(typeable_problem(value))
            self.assertIsNone(controller_principals.directory_password_problem(
                value, "zqx-daily"))
        self.assertEqual(200, len(seen))

    def test_a_check_or_an_avoided_value_draws_again(self):
        draws = iter(["Aa1" + "x" * 21, "Bb2" + "y" * 21, "Cc3" + "z" * 21])

        class Draw:
            def choice(self, sequence):
                return next(self.chars)

            def shuffle(self, _sequence):
                return None

        draw = Draw()
        draw.chars = iter("".join(draws))
        with mock.patch.object(cc.secrets, "SystemRandom", return_value=draw):
            value = cc.generate_password(
                checks=(lambda v: "refused" if v.startswith("Bb2") else None,),
                avoid=("Aa1" + "x" * 21,))
        self.assertEqual("Cc3" + "z" * 21, value)

    def test_exhaustion_is_a_refusal_that_stores_nothing(self):
        with self.assertRaisesRegex(cc.CustodyError, "nothing was stored"):
            cc.generate_password(checks=(lambda _v: "never",))


class MarkerTests(unittest.TestCase):
    def test_absent_custody_is_the_owner_and_agent_needs_throwaway(self):
        self.assertEqual(cc.OWNER, cc.marker_custody({}))
        self.assertFalse(cc.marker_throwaway({}))
        cc.validate_marker({cc.CUSTODY_KEY: cc.AGENT, cc.THROWAWAY_KEY: True})
        for marker in ({cc.CUSTODY_KEY: cc.AGENT},
                       {cc.CUSTODY_KEY: cc.AGENT, cc.THROWAWAY_KEY: False},
                       {cc.CUSTODY_KEY: "someone"},
                       {cc.THROWAWAY_KEY: "yes"}):
            with self.subTest(marker=marker):
                with self.assertRaises(cc.CustodyError):
                    cc.validate_marker(marker)

    def test_creation_refuses_agent_custody_without_throwaway(self):
        with self.assertRaisesRegex(cc.CustodyError, "THROWAWAY=1"):
            cc.requested_custody("agent", False)
        with self.assertRaises(cc.CustodyError):
            cc.requested_custody("everyone", True)
        self.assertEqual((cc.OWNER, False), cc.requested_custody(None, False))
        self.assertEqual((cc.AGENT, True), cc.requested_custody("agent", True))

    def test_a_tampered_marker_is_refused_by_the_instance(self):
        with tempfile.TemporaryDirectory() as temp:
            target = write_instance(Path(temp), throwaway=False, console=None)
            with self.assertRaisesRegex(so.PersistentInstanceInvalid,
                                        "throwaway"):
                target.read_marker()


class StoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name) / "state"
        self.state.mkdir()
        self.store = cc.CustodyStore(
            self.state, scope=cc.SCOPE_INSTANCE, name="agent-dc")

    def test_the_store_is_private_and_holds_one_document(self):
        self.store.create({"console": "Console0Value1"})
        self.assertEqual(0o700, _mode(self.store.directory))
        self.assertEqual(0o600, _mode(self.store.path))
        self.assertEqual({cc.STORE_NAME},
                         {entry.name for entry in self.store.directory.iterdir()})
        document = self.store.read()
        self.assertEqual("Console0Value1", document["console"])
        self.assertEqual(("Console0Value1",), self.store.values())
        with self.assertRaises(cc.CustodyError):
            self.store.create({"console": "again"})

    def test_updates_are_atomic_and_leave_no_copy_behind(self):
        self.store.create({"console": "Console0Value1"})
        before = os.stat(self.store.path).st_ino
        self.store.update(lambda doc: doc.update(administrator="Admin0Value2"))
        self.assertNotEqual(before, os.stat(self.store.path).st_ino)
        self.assertEqual({cc.STORE_NAME},
                         {entry.name for entry in self.store.directory.iterdir()})
        self.assertEqual(0o600, _mode(self.store.path))
        self.assertEqual({"Console0Value1", "Admin0Value2"},
                         set(self.store.values()))

    def test_a_failed_write_keeps_the_old_document(self):
        self.store.create({"console": "Console0Value1"})
        with mock.patch.object(cc.os, "replace",
                               side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.store.update(
                    lambda doc: doc.update(administrator="Admin0Value2"))
        self.assertEqual("Console0Value1", self.store.read()["console"])
        self.assertNotIn("administrator", self.store.read())
        self.assertFalse((self.store.directory
                          / cc.STORE_STAGING_NAME).exists())
        # The interrupted write left a second link to the LIVE document; the
        # next write must unlink it, never shred the live inode through it.
        self.store.update(lambda doc: doc.update(administrator="Admin0Value2"))
        self.assertEqual("Admin0Value2", self.store.read()["administrator"])
        self.assertEqual({cc.STORE_NAME},
                         {entry.name for entry in self.store.directory.iterdir()})

    def test_a_mis_permissioned_or_symlinked_store_is_refused(self):
        self.store.create({"console": "Console0Value1"})
        self.store.path.chmod(0o644)
        with self.assertRaisesRegex(cc.CustodyError, "0600"):
            self.store.read()
        self.store.path.chmod(0o600)
        self.store.directory.chmod(0o755)
        with self.assertRaisesRegex(cc.CustodyError, "0700"):
            self.store.read()
        self.store.directory.chmod(0o700)
        other = cc.CustodyStore(self.state, scope=cc.SCOPE_INSTANCE,
                                name="another-dc")
        with self.assertRaisesRegex(cc.CustodyError, "does not belong"):
            other.read()
        elsewhere = self.state.parent / "elsewhere"
        elsewhere.mkdir()
        linked = cc.CustodyStore(elsewhere, scope=cc.SCOPE_INSTANCE,
                                 name="agent-dc")
        (elsewhere / cc.CUSTODY_DIR_NAME).symlink_to(self.store.directory)
        with self.assertRaisesRegex(cc.CustodyError, "real directory"):
            linked.read()

    def test_shred_overwrites_then_removes_and_refuses_strangers(self):
        self.store.create({"console": "Console0Value1"})
        (self.store.directory / "stranger").write_text("x")
        with self.assertRaisesRegex(cc.CustodyError, "unexpected"):
            self.store.shred()
        self.assertTrue(self.store.path.exists())
        (self.store.directory / "stranger").unlink()
        overwritten = []
        real = cc.shred_file

        def spy(path):
            overwritten.append(Path(path).name)
            real(path)
        with mock.patch.object(cc, "shred_file", side_effect=spy):
            self.store.shred()
        self.assertEqual([cc.STORE_NAME], overwritten)
        self.assertFalse(self.store.directory.exists())

    def test_the_account_lifecycle_pending_then_current(self):
        self.store.create({"console": "Console0Value1"})
        source = cc.AgentCredentialSource(self.store)
        temporary = source.staging_value("daily_administrator", temporary=True)
        self.assertEqual(temporary, source.staging_value(
            "daily_administrator", temporary=True))
        source.begin_pending("daily_administrator", "Pending0Value3",
                             kind=cc.PENDING_FIRST_LOGON)
        with self.assertRaisesRegex(cc.CustodyError, "pending"):
            source.live_current("daily_administrator")
        source.promote_pending("daily_administrator")
        entry = source.account("daily_administrator")
        self.assertEqual("Pending0Value3", entry["current"])
        self.assertIsNone(entry["temporary"])
        self.assertIsNone(entry["pending"])
        self.assertEqual(b"Pending0Value3",
                         source.live_current("daily_administrator"))
        source.begin_pending("daily_administrator", "Reset0Value4",
                             kind=cc.PENDING_RESET, must_change=True)
        source.promote_pending("daily_administrator")
        entry = source.account("daily_administrator")
        self.assertEqual("Reset0Value4", entry["temporary"])
        self.assertIsNone(entry["current"])

    def test_the_administrator_is_stored_once_and_never_replaced(self):
        self.store.create({"console": "Console0Value1"})
        source = cc.AgentCredentialSource(self.store)
        first = source.issue_administrator()
        self.assertEqual(first, self.store.read()["administrator"])
        self.assertEqual(first, source.issue_administrator())

    def test_break_glass_lives_in_the_workstation_store(self):
        self.store.create({"console": "Console0Value1"})
        wstate = self.state.parent / "w1"
        wstate.mkdir()
        wstore = cc.workstation_store(wstate, "w1")
        source = cc.AgentCredentialSource(self.store, wstore)
        value = source.begin_break_glass(cc.ARCH_LOCAL_RESCUE)
        self.assertEqual(0o700, _mode(wstore.directory))
        self.assertEqual(value, wstore.read()["break_glass"][
            cc.ARCH_LOCAL_RESCUE]["pending"])
        self.assertNotIn(value, self.store.values())
        self.assertIn(value, source.scan_values())
        source.promote_break_glass(cc.ARCH_LOCAL_RESCUE)
        self.assertEqual(value, wstore.read()["break_glass"][
            cc.ARCH_LOCAL_RESCUE]["current"])


class SourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_the_owner_source_calls_the_runners_prompt_exactly(self):
        target = write_instance(self.root, "owner-dc", custody=None)
        calls = []

        def prompt(*args, **kwargs):
            calls.append((args, kwargs))
            return b"typed"
        source = cc.credential_source(target, prompt=prompt)
        self.assertFalse(source.agent)
        self.assertEqual(b"typed", source.console("console password: "))
        source.ask("new: ", confirm="again: ")
        self.assertEqual([(("console password: ",), {}),
                          (("new: ",), {"confirm": "again: "})], calls)
        self.assertEqual((), source.scan_values())

    def test_an_owner_instance_never_has_a_store(self):
        target = write_instance(self.root, "owner-dc", custody=None)
        (target.state / cc.CUSTODY_DIR_NAME).mkdir(mode=0o700)
        with self.assertRaisesRegex(cc.CustodyError, "owner custody never"):
            cc.credential_source(target, prompt=self.fail)
        (target.state / cc.CUSTODY_DIR_NAME).rmdir()
        workstation = self.root / "w1"
        (workstation / cc.CUSTODY_DIR_NAME).mkdir(parents=True)
        with self.assertRaisesRegex(cc.CustodyError, "owner custody"):
            cc.credential_source(target, prompt=self.fail,
                                 workstation=(workstation, "w1"))

    def test_the_agent_source_never_prompts_and_needs_its_store(self):
        target = write_instance(self.root)
        source = cc.credential_source(target, prompt=self.fail)
        self.assertTrue(source.agent)
        self.assertEqual(b"Console0Stored1Value", source.console("ignored"))
        lost = write_instance(self.root, "lost-dc", console=None)
        with self.assertRaisesRegex(cc.CustodyError, "lost its custody"):
            cc.credential_source(lost, prompt=self.fail)

    def test_a_missing_instance_is_the_owners(self):
        target = so.PersistentControllerInstance(
            self.root / "absent", instance="absent")
        self.assertIsInstance(
            cc.credential_source(target, prompt=lambda *_a, **_k: b""),
            cc.OwnerCredentialSource)
        self.assertEqual((), cc.custody_scan_values(target))


class _Guard:
    """``ControllerOverlay`` for ``create``: hands out the canonical as is."""

    def __init__(self, disk, vars_file, *, run_root, proc_root=None):
        self.disk = Path(disk)
        self.vars = Path(vars_file)
        self.canonical_disk_sha256 = "a" * 64
        self.canonical_vars_sha256 = "b" * 64

    def prepare(self):
        return self

    def close(self):
        return None


def _convert(argv, **_kwargs):
    argv = [str(part) for part in argv]
    if argv[:2] == ["qemu-img", "convert"]:
        shutil.copyfile(argv[-2], argv[-1])
        return subprocess.CompletedProcess(argv, 0, "", "")
    return fake_image_tools.image_tool(argv)


class CreationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.canonical = self.root / "canonical"
        self.canonical.mkdir()
        self.disk = fake_image_tools.installed_image(
            self.canonical / "bootstrap-dc.qcow2", b" canonical")
        self.vars = self.canonical / "OVMF_VARS.fd"
        self.vars.write_bytes(b"canonical vars")
        for patch in (mock.patch.object(so, "ControllerOverlay", _Guard),
                      mock.patch.object(so.subprocess, "run",
                                        side_effect=_convert)):
            patch.start()
            self.addCleanup(patch.stop)

    def target(self, name="agent-dc"):
        return so.PersistentControllerInstance(
            self.root / "persistent" / name, instance=name)

    def test_an_owner_marker_is_exactly_what_it_was(self):
        marker = self.target("owner-dc").create(self.disk, self.vars)
        self.assertNotIn(cc.CUSTODY_KEY, marker)
        self.assertNotIn(cc.THROWAWAY_KEY, marker)
        self.assertFalse((self.root / "persistent" / "owner-dc"
                          / cc.CUSTODY_DIR_NAME).exists())

    def test_agent_custody_needs_throwaway_and_an_initializer(self):
        for options in ({"custody": cc.AGENT, "throwaway": False,
                         "initialize": lambda **_k: {}},
                        {"custody": cc.AGENT, "throwaway": True},
                        {"custody": cc.OWNER,
                         "initialize": lambda **_k: {}}):
            with self.subTest(options=options):
                with self.assertRaises(so.PersistentInstanceInvalid):
                    self.target().create(self.disk, self.vars, **options)
        self.assertFalse((self.root / "persistent").exists()
                         and any((self.root / "persistent").iterdir()))

    def test_the_initializer_runs_on_the_staged_copy_before_it_exists(self):
        seen = {}

        def initialize(*, disk, vars_file, staging):
            seen["exists"] = self.target().exists()
            seen["staged"] = Path(disk).parent == Path(staging)
            cc.CustodyStore(staging, scope=cc.SCOPE_INSTANCE,
                            name="agent-dc").create({"console": "Console0V1"})
            return {"utc": "now", "one_run_entry_removed": True}
        marker = self.target().create(
            self.disk, self.vars, custody=cc.AGENT, throwaway=True,
            initialize=initialize)
        self.assertEqual({"exists": False, "staged": True}, seen)
        self.assertEqual(cc.AGENT, marker[cc.CUSTODY_KEY])
        self.assertIs(True, marker[cc.THROWAWAY_KEY])
        self.assertEqual(cc.AGENT, self.target().credential_custody())
        self.assertTrue(self.target().throwaway())
        store = cc.instance_store(self.target())
        self.assertEqual("Console0V1", store.read()["console"])
        self.assertNotIn("Console0V1", json.dumps(self.target().read_marker()))
        self.assertEqual(
            self.disk.read_bytes(),
            (self.target().state / so.PERSISTENT_DISK_NAME).read_bytes())

    def test_a_failed_initializer_leaves_nothing_and_shreds_the_store(self):
        shredded = []
        real = cc.shred_file

        def spy(path):
            shredded.append(Path(path).name)
            real(path)

        def initialize(*, disk, vars_file, staging):
            cc.CustodyStore(staging, scope=cc.SCOPE_INSTANCE,
                            name="agent-dc").create({"console": "Console0V1"})
            raise aci.AgentConsoleInitError("the guest never logged in")
        with mock.patch.object(cc, "shred_file", side_effect=spy):
            with self.assertRaises(aci.AgentConsoleInitError):
                self.target().create(self.disk, self.vars, custody=cc.AGENT,
                                     throwaway=True, initialize=initialize)
        self.assertIn(cc.STORE_NAME, shredded)
        self.assertEqual([], list((self.root / "persistent").iterdir()))

    def test_destroy_shreds_the_store_before_the_disk(self):
        target = write_instance(self.root / "live")
        order = []
        real_shred = cc.CustodyStore.shred
        real_unlink = Path.unlink

        def shred(store):
            order.append("store")
            real_shred(store)

        def unlink(path, *args, **kwargs):
            order.append(path.name)
            return real_unlink(path, *args, **kwargs)
        with mock.patch.object(target, "prepare"), \
                mock.patch.object(target, "_unlock"), \
                mock.patch.object(cc.CustodyStore, "shred", shred), \
                mock.patch.object(Path, "unlink", unlink):
            target.destroy("DESTROY agent-dc")
        self.assertEqual("store", order[0])
        self.assertLess(order.index("store"),
                        order.index(so.PERSISTENT_DISK_NAME))
        self.assertFalse(target.state.exists())

    def test_destroy_refuses_a_stranger_in_the_store_and_deletes_nothing(self):
        target = write_instance(self.root / "live")
        (target.state / cc.CUSTODY_DIR_NAME / "stranger").write_text("x")
        with mock.patch.object(target, "prepare"), \
                mock.patch.object(target, "_unlock"):
            with self.assertRaises(so.PersistentInstanceInvalid):
                target.destroy("DESTROY agent-dc")
        self.assertTrue((target.state / so.PERSISTENT_DISK_NAME).exists())
        self.assertTrue(cc.instance_store(target).path.exists())


class PersistentUpCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.canonical = self.root / "canonical"
        self.canonical.mkdir()
        files = bootstrap_dc.paths(self.canonical)
        for key in ("disk", "vars", "manifest"):
            files[key].write_bytes(b"canonical " + key.encode())
            files[key].chmod(0o600)
        fake_image_tools.installed_image(files["disk"], b" canonical disk")
        self.persistent_root = self.root / "persistent"
        self.guests: list[list[str]] = []
        self.initialized: list[str] = []

    def dispatch(self, argv, **kwargs):
        if argv[0] in {"qemu-img", "sfdisk"}:
            return fake_image_tools.image_tool(argv, **kwargs)
        self.guests.append(list(argv))
        return subprocess.CompletedProcess(argv, 0)

    def fake_init_module(self):
        test = self

        class Module:
            REQUIRED_TOOLS = aci.REQUIRED_TOOLS

            @staticmethod
            def initializer(instance, *, forbidden=()):
                def initialize(*, disk, vars_file, staging):
                    test.initialized.append(instance)
                    test.forbidden = forbidden
                    cc.CustodyStore(
                        staging, scope=cc.SCOPE_INSTANCE, name=instance
                    ).create({"console": "Console0Generated1"})
                    return {"utc": "now", "one_run_entry_removed": True}
                return initialize
        return Module

    def call(self, *argv, expect):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(bootstrap_dc, "ovmf_pair",
                                  return_value=(Path("/code"), Path("/vars"))), \
                mock.patch.object(bootstrap_dc.shutil, "which",
                                  return_value="/usr/bin/x"), \
                mock.patch.object(bootstrap_dc.subprocess, "run",
                                  side_effect=self.dispatch), \
                mock.patch.object(bootstrap_dc, "_agent_console_init",
                                  self.fake_init_module), \
                mock.patch.object(bootstrap_dc.getpass, "getpass",
                                  side_effect=AssertionError("prompted")):
            result = bootstrap_dc.main(list(argv))
        self.assertEqual(expect, result, err.getvalue() or out.getvalue())
        return out.getvalue(), err.getvalue()

    def up(self, *extra, expect=0, name="agent-dc"):
        return self.call(
            "--state-dir", str(self.canonical), "persistent-up",
            "--instance", name, "--persistent-root", str(self.persistent_root),
            *extra, expect=expect)

    def test_agent_custody_without_throwaway_is_refused_before_anything(self):
        _, err = self.up("--custody", "agent", "--apply", expect=2)
        self.assertIn("THROWAWAY=1", err)
        self.assertFalse(self.persistent_root.exists())
        self.assertEqual([], self.guests)

    def test_the_plan_names_the_custody_and_creates_nothing(self):
        out, _ = self.up("--custody", "agent", "--throwaway")
        self.assertIn("credential custody: agent (throwaway", out)
        self.assertIn("not booted interactively", out)
        self.assertIn("dry run", out)
        self.assertFalse(self.persistent_root.exists())

    def test_agent_creation_initializes_custody_and_boots_nothing_else(self):
        out, _ = self.up("--custody", "agent", "--throwaway", "--apply")
        self.assertEqual(["agent-dc"], self.initialized)
        self.assertEqual([], self.guests)
        files = bootstrap_dc.paths(self.canonical)
        self.assertEqual((files["disk"], files["vars"]), self.forbidden)
        target = so.PersistentControllerInstance(
            self.persistent_root / "agent-dc", instance="agent-dc")
        self.assertEqual(cc.AGENT, target.credential_custody())
        self.assertNotIn("Console0Generated1", out)
        self.assertIn("homelab-factory-persistent-converge", out)
        status, _ = self.call(
            "persistent-status", "--instance", "agent-dc",
            "--persistent-root", str(self.persistent_root), expect=0)
        self.assertIn("credential custody: agent (throwaway", status)
        self.assertNotIn("Console0Generated1", status)
        # Custody is fixed at creation.
        _, err = self.up("--custody", "owner", "--apply", expect=2)
        self.assertIn("fixed at creation", err)
        # Destroy shreds the store first and reports it.
        out, _ = self.call(
            "persistent-destroy", "--instance", "agent-dc",
            "--persistent-root", str(self.persistent_root),
            "--confirm", "DESTROY agent-dc", expect=0)
        self.assertIn("shredded the credential custody store", out)
        self.assertFalse((self.persistent_root / "agent-dc").exists())

    def test_an_owner_instance_is_never_turned_into_an_agent_one(self):
        self.up("--apply", name="owner-dc")
        self.assertEqual(1, len(self.guests))
        _, err = self.up("--custody", "agent", "--throwaway", "--apply",
                         expect=2, name="owner-dc")
        self.assertIn("fixed at creation", err)
        self.assertFalse((self.persistent_root / "owner-dc"
                          / cc.CUSTODY_DIR_NAME).exists())


class _Responder:
    """A scripted init boot: init shell, passwd, systemd, login, poweroff."""

    def __init__(self, right: socket.socket) -> None:
        self.right = right
        self.observed: dict[str, bytes] = {}
        self.failures: list[str] = []

    def __call__(self) -> None:
        right = self.right
        stream = right.makefile("rb", buffering=0)
        try:
            right.sendall(b"[root@bootstrap-dc /]# ")
            remount = stream.readline()
            self.observed["remount"] = remount
            parts = remount.split(b"printf '%s%s\\n' '", 1)[1]
            first, second = parts.split(b"' '", 1)
            token = first + second.split(b"'", 1)[0]
            right.sendall(b"\r\n" + token + b"\r\n[root@bootstrap-dc /]# ")
            self.observed["passwd"] = stream.readline()
            right.sendall(b"New password: ")
            self.observed["new"] = stream.readline()
            right.sendall(b"\r\nRetype new password: ")
            self.observed["retype"] = stream.readline()
            right.sendall(b"\r\npasswd: password updated successfully\r\n"
                          b"[root@bootstrap-dc /]# ")
            self.observed["exec"] = stream.readline()
            right.sendall(b"\r\nbootstrap-dc login: ")
            self.observed["username"] = stream.readline()
            right.sendall(b"\r\nPassword: ")
            self.observed["login"] = stream.readline()
            right.sendall(b"\r\n[local-rescue@bootstrap-dc ~]$ ")
            self.observed["blank"] = stream.readline()
            right.sendall(b"\r\n[local-rescue@bootstrap-dc ~]$ ")
            command = stream.readline()
            self.observed["poweroff"] = command
            prompt = command.split(b"-p '", 1)[1].split(b"'", 1)[0]
            right.sendall(b"\r\n" + prompt + b"\r\n")
            self.observed["sudo"] = stream.readline()
            right.sendall(b"\r\nReached target System Power Off\r\n")
        except BaseException as error:  # surfaced, never swallowed
            self.failures.append(repr(error))


class ConsoleInitDriveTests(unittest.TestCase):
    def test_passwd_then_login_then_sudo_poweroff_with_one_value(self):
        left, right = socket.socketpair()
        responder = _Responder(right)
        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        password = b"Generated0Console1Value"
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                events = aci.drive_console_init(
                    left.makefile("rb", buffering=0),
                    left.makefile("wb", buffering=0), password, timeout=5.0,
                    events=bootstrap_dc._AnnouncedEvents())
        finally:
            left.close()
            right.close()
            thread.join(timeout=2)
        self.assertEqual([], responder.failures)
        observed = responder.observed
        self.assertEqual(b"/usr/bin/passwd local-rescue\n", observed["passwd"])
        for key in ("new", "retype", "login", "sudo"):
            self.assertEqual(password + b"\n", observed[key])
        self.assertEqual(b"local-rescue\n", observed["username"])
        self.assertIn(b"sudo -k -S", observed["poweroff"])
        self.assertIn(b"systemctl poweroff", observed["poweroff"])
        for key in ("remount", "passwd", "exec", "poweroff", "username"):
            self.assertNotIn(password, observed[key])
        self.assertIn("password-updated", events)
        self.assertIn("agent-custody-poweroff-observed", events)

    def test_the_init_half_is_automated_serials_own_sequence(self):
        source = Path(automated_controller.__file__).read_text()
        mine = Path(aci.__file__).read_text()
        for literal in (
                'b"/usr/bin/passwd local-rescue"',
                'b"exec /usr/lib/systemd/systemd"',
                'b"/usr/bin/mount -o remount,rw /; "',
                "rb\"(?:^|\\n)passwd: password updated successfully",
                f'"{aci.ONE_RUN_ENTRY}"'):
            with self.subTest(literal=literal):
                self.assertIn(literal, source)
                self.assertIn(literal, mine)


class InitCommandTests(unittest.TestCase):
    def test_the_boot_has_no_network_no_medium_and_no_canonical(self):
        raw, vars_file = Path("/staging/.custody-init.raw"), Path(
            "/staging/OVMF_VARS.fd")
        with mock.patch.object(aci, "ovmf_pair",
                               return_value=(Path("/code"), Path("/v"))):
            argv = aci.init_command(raw, vars_file, instance="agent-dc")
        aci.audit_init_command(argv, raw=raw, vars_file=vars_file,
                               forbidden=(Path("/canonical/disk.qcow2"),))
        self.assertEqual(["-nic", "none"], argv[-2:])
        joined = " ".join(argv)
        for forbidden in ("-netdev", "-qmp", "media=cdrom", "user,"):
            self.assertNotIn(forbidden, joined)
        for bad in (argv[:-2], argv + ["-netdev", "user,id=n"],
                    argv + ["-drive", "if=none,media=cdrom,file=/x.iso"]):
            with self.subTest(bad=bad[-2:]):
                with self.assertRaises(aci.AgentConsoleInitError):
                    aci.audit_init_command(bad, raw=raw, vars_file=vars_file)
        with self.assertRaises(aci.AgentConsoleInitError):
            aci.audit_init_command(argv, raw=raw, vars_file=vars_file,
                                   forbidden=(raw,))


@unittest.skipUnless(all(shutil.which(tool) for tool in (
    "sfdisk", "mcopy", "mdel", "mmd", "mkfs.fat")), "sfdisk/mtools missing")
class InitializerTests(unittest.TestCase):
    """The whole initializer on a real tiny GPT disk; QEMU is a fake process."""

    LOADER = b"timeout 3\ndefault arch.conf\n"
    ENTRY = b"title Arch\nlinux /vmlinuz\noptions root=UUID=x rw\n"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.staging = self.root / ".agent-dc.staging"
        self.staging.mkdir(mode=0o700)
        self.disk = self.staging / so.PERSISTENT_DISK_NAME
        self.vars = self.staging / so.PERSISTENT_VARS_NAME
        self.vars.write_bytes(b"vars")
        self._build_disk(self.disk)
        self.original = self.disk.read_bytes()
        self.spawned: list[list[str]] = []
        self.environ_at_spawn: dict | None = None
        self.driven: list[bytes] = []

    def _build_disk(self, disk: Path) -> None:
        with disk.open("wb") as stream:
            stream.truncate(8 * 1024 * 1024)
        subprocess.run(
            ["sfdisk", "--quiet", str(disk)], check=True, capture_output=True,
            input=(f"label: gpt\nstart=2048, size=8192, "
                   f"type={fake_image_tools.EFI_SYSTEM_GUID}\n").encode())
        esp = self.root / "esp.img"
        subprocess.run(["mkfs.fat", "-C", str(esp), "4096"], check=True,
                       capture_output=True)
        with disk.open("r+b") as stream:
            stream.seek(2048 * 512)
            stream.write(esp.read_bytes())
        image = f"{disk}@@{2048 * 512}"
        subprocess.run(["mmd", "-i", image, "::loader", "::loader/entries"],
                       check=True, capture_output=True)
        for name, content in (("loader.conf", self.LOADER),
                              ("arch.conf", self.ENTRY)):
            source = self.root / name
            source.write_bytes(content)
            target = ("::loader/loader.conf" if name == "loader.conf"
                      else f"::loader/entries/{name}")
            subprocess.run(["mcopy", "-i", image, str(source), target],
                           check=True, capture_output=True)

    def convert(self, argv, **kwargs):
        argv = [str(part) for part in argv]
        if argv[:2] == ["qemu-img", "convert"]:
            shutil.copyfile(argv[-2], argv[-1])
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        return self.real_run(argv, **kwargs)

    def spawn(self, argv):
        self.spawned.append(list(argv))
        self.environ_at_spawn = dict(os.environ)
        osdisk = next(value for value in argv if "id=osdisk" in value)
        raw = Path(osdisk.split("file=", 1)[1])
        esp = aci.StagedEsp(raw, self.root)
        self.selected = (esp.loader_bytes(), esp.entry_present())
        process = mock.Mock()
        process.stdout, process.stdin = io.BytesIO(), io.BytesIO()
        process.wait.return_value = 0
        process.poll.return_value = 0
        return process

    def drive(self, reader, writer, password, *, timeout, events):
        self.driven.append(password)
        return ("password-updated", "agent-custody-poweroff-observed")

    def initialize(self):
        self.real_run = subprocess.run
        initialize = aci.initializer(
            "agent-dc", forbidden=(Path("/canonical/bootstrap-dc.qcow2"),),
            spawn=self.spawn, drive=self.drive)
        with mock.patch.object(aci.subprocess, "run",
                               side_effect=self.convert), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            record = initialize(disk=self.disk, vars_file=self.vars,
                                staging=self.staging)
        return record, out.getvalue()

    def test_the_entry_is_selected_for_the_boot_and_gone_after_it(self):
        record, out = self.initialize()
        loader, present = self.selected
        self.assertIn(aci.ONE_RUN_ENTRY.encode(), loader)
        self.assertTrue(present)
        # After: outside the ESP the disk is byte-identical; inside it the
        # loader is the original and the one-run entry cannot be read.  (A
        # FAT deletion leaves a deleted directory slot, so the ESP's bytes
        # are compared by what the loader reads, as the code proves them.)
        after = self.disk.read_bytes()
        start, end = 2048 * 512, (2048 + 8192) * 512
        self.assertEqual(self.original[:start], after[:start])
        self.assertEqual(self.original[end:], after[end:])
        esp = aci.StagedEsp(self.disk, self.root)
        self.assertEqual(self.LOADER, esp.loader_bytes())
        self.assertFalse(esp.entry_present())
        self.assertTrue(esp.entry_present("arch.conf"))
        self.assertTrue(record["one_run_entry_removed"])
        store = cc.CustodyStore(self.staging, scope=cc.SCOPE_INSTANCE,
                                name="agent-dc")
        value = store.read()["console"]
        self.assertEqual([value.encode()], self.driven)
        # Never argv, never the environment, never stdout, never the record.
        self.assertNotIn(value, " ".join(self.spawned[0]))
        self.assertNotIn(value, "".join(self.environ_at_spawn.values()))
        self.assertNotIn(value, out)
        self.assertNotIn(value, json.dumps(record))
        self.assertEqual(["-nic", "none"], self.spawned[0][-2:])
        self.assertEqual(
            {so.PERSISTENT_DISK_NAME, so.PERSISTENT_VARS_NAME,
             cc.CUSTODY_DIR_NAME},
            {entry.name for entry in self.staging.iterdir()})

    def test_a_guest_that_never_powers_off_fails_and_leaves_no_raw_copy(self):
        def drive(*_args, **_kwargs):
            raise aci.SerialAutomationError("timed out waiting for login")
        self.drive = drive
        with self.assertRaises(aci.AgentConsoleInitError):
            self.initialize()
        self.assertFalse((self.staging / aci.RAW_NAME).exists())
        self.assertFalse((self.staging / aci.WORK_NAME).exists())
        # The staged qcow2 itself was never touched: the edit was on the raw.
        self.assertEqual(self.original, self.disk.read_bytes())


class WorkstationDestroyTests(unittest.TestCase):
    def test_the_custody_store_is_shredded_before_the_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "w1"
            state.mkdir()
            workstation = wi.WorkstationInstance(state, name="w1")
            marker = {"workstation": "w1",
                      "binding": {"persistent_instance": "agent-dc"},
                      "machine_accounts": []}
            store = workstation.custody_store(marker)
            store.create({})
            (state / wi.PUBLICATION_NAME).write_bytes(b"publication")
            order = []
            with mock.patch.object(workstation, "read_marker",
                                   return_value=marker), \
                    mock.patch.object(workstation, "acquire"), \
                    mock.patch.object(workstation, "release"), \
                    mock.patch.object(workstation, "_assert_not_open"), \
                    mock.patch.object(
                        cc.CustodyStore, "shred", autospec=True,
                        side_effect=lambda s: order.append("store")), \
                    mock.patch.object(
                        wi, "_shred",
                        side_effect=lambda p: order.append(p.name)):
                with self.assertRaises(OSError):
                    # The mocked shred leaves the store's directory behind,
                    # so the final rmdir fails; the order is what is proved.
                    workstation.destroy("DESTROY w1")
            self.assertEqual(["store", wi.PUBLICATION_NAME], order)


if __name__ == "__main__":
    unittest.main()
