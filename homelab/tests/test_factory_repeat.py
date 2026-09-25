"""Tests for the gate-12 repeat driver.

These fabricate whole phase bundles on disk, drive the aggregate assembly with
a fake lifecycle driver, and push the result through the REAL
``factory_verify.verify_run`` and ``compare_runs``.  Nothing here boots a
guest, spawns a process, touches the network, or needs privilege.

What they cannot cover is stated in ``factory_repeat``'s module docstring: the
``SubprocessLifecycle`` that drives the live Make targets has never run, and
gate 12 itself needs two live lifecycles no test can substitute for.
"""

import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parent
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "vm"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pxe_release  # noqa: E402
import pxe_release_set  # noqa: E402
import factory_repeat  # noqa: E402
import fake_image_tools  # noqa: E402
import factory_runner  # noqa: E402
import factory_verify  # noqa: E402


GATEWAY_MAC = "52:54:00:31:11:01"

SWITCH = "\n".join(
    json.dumps(event) for event in (
        {"event": "dhcp", "kind": "OFFER", "peer": "gateway",
         "source_mac": GATEWAY_MAC},
        {"event": "dhcp", "kind": "ACK", "peer": "gateway",
         "source_mac": GATEWAY_MAC},
    )
) + "\n"

WINDOWS_MEASUREMENTS = {
    "controller_disk_unchanged": True,
    "firmware_vars_unchanged": True,
    "external_connections_after_offline_gate": 0,
    "install_order": ["windows"],
    "guest_disks": [
        {"name": "windows.qcow2", "disposable": True, "run_scoped": True},
    ],
}
ARCH_MEASUREMENTS = {
    "controller_disk_unchanged": True,
    "firmware_vars_unchanged": True,
    "external_connections_after_offline_gate": 0,
    "install_order": ["arch-workstation"],
    "guest_disks": [
        {"name": "arch-workstation.qcow2", "disposable": True,
         "run_scoped": True},
    ],
}
DUALBOOT_MEASUREMENTS = {"default_boot": "windows"}

PRODUCED = {
    "host_network_changes": {
        "tap": 0, "bridge": 0, "route": 0, "vlan": 0,
        "forwarding": 0, "listener": 0, "unifi": 0,
    },
    "login": {
        "windows": {"online": True, "offline_cached": True},
        "arch": {"online": True, "offline_cached": True},
    },
    "optional_storage_absence_nonblocking": True,
    "artifact_scan": {"media": 0, "credentials": 0, "private": 0,
                      "oversized": 0},
}


def wired_producers(**overrides) -> factory_repeat.Producers:
    """Producers wired to fixed values, injected at the adapter seam.

    Deliberately NOT the sibling modules: the seam exists so this module's
    tests never depend on a sibling's internals or on its presence.
    """
    values = dict(PRODUCED)
    values.update(overrides)
    return factory_repeat.Producers(
        **{key: (None if values[key] is None else (lambda v=values[key]: v))
           for key in factory_repeat.PRODUCED_KEYS})


#: The per-phase bundle contents one fabricated lifecycle iteration produces,
#: mirroring the real retained bundles under ``homelab/var/factory``.
PHASE_FIXTURES = {
    "windows-install": {
        "evidence": {
            "result.json": json.dumps(
                {"schema": 1, "status": "observed",
                 "measurements": WINDOWS_MEASUREMENTS}).encode(),
            "controller-publication.log": b"TELOS PXE SERVICES READY\n",
            "workstation-serial.log": b"windows install complete\n",
            "switch.jsonl": SWITCH.encode(),
        },
        "trees": ("controller",),
    },
    "windows-identity": {
        "files": {"acceptance-evidence.jsonl": b'{"check": "windows-joined"}\n'},
    },
    "arch-install": {
        "evidence": {
            "result.json": json.dumps(
                {"schema": 1, "status": "observed",
                 "measurements": ARCH_MEASUREMENTS}).encode(),
            "controller-publication.log": b"TELOS PXE SERVICES READY\n",
            "workstation-serial.log": b"arch install complete\n",
            "switch.jsonl": SWITCH.encode(),
        },
        "trees": ("publication",),
    },
    "arch-identity": {
        "evidence": {
            "identity-lifecycle.jsonl": b'{"check": "arch-standard-online"}\n',
            "workstation-boot.json": b"{}\n",
            "workstation-firmware.log": b"",
            "workstation-serial.log": b"arch identity complete\n",
            "workstation-switch.jsonl": SWITCH.encode(),
            "workstation-stall-1.ppm": b"P6\n",
        },
    },
    "dualboot-acceptance": {
        "evidence": {
            "result.json": json.dumps(
                {"schema": 1, "status": "observed",
                 "measurements": DUALBOOT_MEASUREMENTS}).encode(),
            "boot1-serial.log": b"boot 1\n",
            "boot2-serial.log": b"boot 2\n",
            "dualboot-events.jsonl": b'{"check": "default-boot"}\n',
        },
        "trees": ("boot1-frames", "boot2-frames"),
    },
    "lifecycle-recovery": {
        "evidence": {
            "result.json": json.dumps(
                {"schema": 1, "status": "observed"}).encode(),
            "recovery-evidence.jsonl": b'{"check": "pxe-release-rollback"}\n',
        },
        "trees": ("scratch",),
        "root": True,
    },
}


class FakeLifecycle(factory_repeat.LifecycleDriver):
    """Materialises the fabricated bundles a real lifecycle would leave."""

    def __init__(self, *, fixtures=None, network=True):
        self.fixtures = PHASE_FIXTURES if fixtures is None else fixtures
        self.network = network
        self.destroyed: list[Path] = []
        self.prepared: list[list[str] | None] = []
        self.executed: list[list[str]] = []
        self.captures = 0

    def destroy(self, workdir):
        self.destroyed.append(Path(workdir))

    def capture_host_network(self):
        self.captures += 1
        return {"capture": self.captures} if self.network else None

    def run_phase(self, phase, *, workdir, bundles, duration):
        self.prepared.append(factory_repeat.prepare_command(phase, bundles))
        bundle = Path(workdir) / phase.name
        self.executed.append(
            factory_repeat.run_command(phase, bundle, duration=duration))
        fixture = self.fixtures.get(phase.name, {})
        evidence = bundle if fixture.get("root") else bundle / "evidence"
        for name, content in fixture.get("evidence", {}).items():
            evidence.mkdir(parents=True, exist_ok=True)
            (evidence / name).write_bytes(content)
        for name, content in fixture.get("files", {}).items():
            bundle.mkdir(parents=True, exist_ok=True)
            (bundle / name).write_bytes(content)
        for tree in fixture.get("trees", ()):
            (evidence / tree).mkdir(parents=True, exist_ok=True)
        return bundle


class TemporaryRootTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def release_set(self):
        """A real ``pxe_release_set`` release set, so check 16 can PASS."""
        seal = self.root / "seal.json"
        seal_value = {"schema": 1, "content": [
            {"name": "arch-iso", "sha256": "a" * 64},
            {"name": "windows-iso", "sha256": "b" * 64},
            {"name": "wimboot", "sha256": "c" * 64},
            {"name": "windows-install-source", "source_iso_sha256": "b" * 64,
             "receipt_sha256": "d" * 64, "bytes": 8_000_000_000,
             "file_count": 976},
        ]}
        seal.write_text(json.dumps(seal_value), encoding="utf-8")
        version = "20260810.001"

        def stage(build_root):
            leaves = {}
            for target in pxe_release_set.TARGETS:
                source = build_root / "sources" / target
                source.mkdir(parents=True)
                (source / "boot.ipxe").write_text("#!ipxe\n", encoding="utf-8")
                (source / "target.json").write_text(json.dumps({
                    "schema": 1, "id": target, "entrypoints": ["boot.ipxe"],
                }), encoding="utf-8")
                leaves[target] = pxe_release.stage(
                    source, build_root / "releases", version=version)
            return leaves

        return pxe_release_set.build(
            self.root / "releases", version, seal, seal_value, stage)

    def installed_controller_disk(self) -> Path:
        """A stand-in the real installed-image probe accepts.

        A sparse file over the size floor is no longer enough: the precondition
        reads the partition table through ``controller_image.probe``, precisely
        so that a partially written gigabyte cannot pass for an installation.
        So model the image tools the way the bootstrap suite does, and keep the
        patch alive for the rest of the test.
        """
        disk = fake_image_tools.installed_image(
            self.root / "bootstrap-dc.qcow2")
        patcher = mock.patch.object(
            factory_repeat.controller_image.subprocess, "run",
            side_effect=fake_image_tools.image_tool)
        patcher.start()
        self.addCleanup(patcher.stop)
        return disk

    def iteration(self, index=1, *, driver=None, producers=None, phases=None):
        """Run one fabricated iteration, returning its aggregate evidence."""
        driver = FakeLifecycle() if driver is None else driver
        producers = wired_producers() if producers is None else producers
        return factory_repeat.run_iteration(
            index, driver=driver, workdir=self.root / f"work-{index}",
            destination=self.root / f"aggregate-{index}",
            bind=lambda bundles, **kwargs: producers,
            phases=factory_repeat.PHASES if phases is None else phases)


# --------------------------------------------------------------------------
# Measurement assembly
# --------------------------------------------------------------------------


class MeasurementAssemblyTests(unittest.TestCase):
    def test_install_order_concatenates_across_both_phases(self):
        merged = factory_repeat.merge_phase_measurements([
            ("windows-install", WINDOWS_MEASUREMENTS),
            ("arch-install", ARCH_MEASUREMENTS),
        ])
        self.assertEqual(["windows", "arch-workstation"],
                         merged["install_order"])

    def test_concatenated_install_order_renders_check_11_pass(self):
        # The whole reason the aggregate exists: no phase bundle can render
        # anything but NOT-RUN here, because each records only its own half.
        merged = factory_repeat.merge_phase_measurements([
            ("windows-install", WINDOWS_MEASUREMENTS),
            ("arch-install", ARCH_MEASUREMENTS),
        ])
        self.assertEqual(
            "PASS",
            factory_verify._check_windows_before_arch(merged)["status"])
        for half in (WINDOWS_MEASUREMENTS, ARCH_MEASUREMENTS):
            self.assertEqual(
                "NOT-RUN",
                factory_verify._check_windows_before_arch(half)["status"])

    def test_reversed_install_order_still_fails_check_11(self):
        merged = factory_repeat.merge_phase_measurements([
            ("arch-install", ARCH_MEASUREMENTS),
            ("windows-install", WINDOWS_MEASUREMENTS),
        ])
        self.assertEqual(["arch-workstation", "windows"],
                         merged["install_order"])
        self.assertEqual(
            "FAIL",
            factory_verify._check_windows_before_arch(merged)["status"])

    def test_repeated_install_is_never_deduplicated(self):
        merged = factory_repeat.merge_phase_measurements([
            ("windows-install", WINDOWS_MEASUREMENTS),
            ("windows-reinstall", WINDOWS_MEASUREMENTS),
        ])
        self.assertEqual(["windows", "windows"], merged["install_order"])

    def test_guest_disk_inventories_union(self):
        merged = factory_repeat.merge_phase_measurements([
            ("windows-install", WINDOWS_MEASUREMENTS),
            ("arch-install", ARCH_MEASUREMENTS),
        ])
        self.assertEqual(
            ["windows.qcow2", "arch-workstation.qcow2"],
            [disk["name"] for disk in merged["guest_disks"]])

    def test_disagreeing_phases_fail_closed(self):
        with self.assertRaises(factory_repeat.RepeatError) as raised:
            factory_repeat.merge_phase_measurements([
                ("windows-install", {"default_boot": "windows"}),
                ("dualboot-acceptance", {"default_boot": "arch"}),
            ])
        self.assertIn("default_boot", str(raised.exception))

    def test_agreeing_phases_do_not_conflict(self):
        merged = factory_repeat.merge_phase_measurements([
            ("a", {"default_boot": "windows"}),
            ("b", {"default_boot": "windows"}),
        ])
        self.assertEqual("windows", merged["default_boot"])

    def test_unknown_phase_measurement_is_refused(self):
        with self.assertRaises(factory_repeat.RepeatError) as raised:
            factory_repeat.merge_phase_measurements(
                [("windows-install", {"secure_boot_enabled": True})])
        self.assertIn("secure_boot_enabled", str(raised.exception))

    def test_union_is_complete_and_exactly_the_pinned_keys(self):
        measurements = factory_repeat.assemble_measurements(
            [("windows-install", WINDOWS_MEASUREMENTS),
             ("arch-install", ARCH_MEASUREMENTS),
             ("dualboot-acceptance", DUALBOOT_MEASUREMENTS)],
            producers=wired_producers())
        self.assertEqual(set(factory_runner.MEASUREMENT_KEYS),
                         set(measurements))
        self.assertEqual([], factory_repeat.missing_measurements(measurements))
        self.assertEqual(10, len(measurements))

    def test_assembly_refuses_to_widen_past_the_pinned_keys(self):
        # measurement_block is the composer, so an unknown key can never reach
        # the retained evidence even if a producer or a phase drifts.
        with self.assertRaises(RuntimeError):
            factory_runner.measurement_block(
                **dict(WINDOWS_MEASUREMENTS, secure_boot_enabled=True))
        with self.assertRaises(factory_repeat.RepeatError):
            factory_repeat.assemble_measurements(
                [("phase", {"secure_boot_enabled": True})],
                producers=wired_producers())

    def test_an_unavailable_producer_leaves_the_field_absent(self):
        measurements = factory_repeat.assemble_measurements(
            [("windows-install", WINDOWS_MEASUREMENTS),
             ("arch-install", ARCH_MEASUREMENTS),
             ("dualboot-acceptance", DUALBOOT_MEASUREMENTS)],
            producers=wired_producers(login=None, artifact_scan=None))
        self.assertNotIn("login", measurements)
        self.assertEqual(["artifact_scan", "login"],
                         factory_repeat.missing_measurements(measurements))
        # Absent, never fabricated: the check stays NOT-RUN.
        self.assertEqual("NOT-RUN",
                         factory_verify._check_login(measurements)["status"])

    def test_a_producer_returning_none_leaves_the_field_absent(self):
        producers = factory_repeat.Producers(host_network_changes=lambda: None)
        measurements = factory_repeat.assemble_measurements([], producers=producers)
        self.assertEqual({}, measurements)

    def test_a_producer_contradicting_a_phase_fails_closed(self):
        with self.assertRaises(factory_repeat.RepeatError):
            factory_repeat.assemble_measurements(
                [("dualboot-acceptance",
                  {"optional_storage_absence_nonblocking": False})],
                producers=wired_producers())


class ProducerSeamTests(unittest.TestCase):
    """The seam must survive a sibling module that is not there at all."""

    def test_absent_module_yields_no_producer(self):
        self.assertIsNone(factory_repeat._optional_module(
            "definitely_not_a_module_in_this_tree"))

    def test_entry_point_table_covers_every_produced_key(self):
        self.assertEqual(set(factory_repeat.PRODUCED_KEYS),
                         set(factory_repeat.PRODUCER_ENTRY_POINTS))
        self.assertTrue(
            set(factory_repeat.PRODUCED_KEYS)
            <= set(factory_runner.MEASUREMENT_KEYS))

    def test_availability_is_reported_per_key(self):
        availability = factory_repeat.producer_availability()
        self.assertEqual(set(factory_repeat.PRODUCED_KEYS), set(availability))
        for value in availability.values():
            self.assertIsInstance(value, bool)

    def test_unbound_producers_report_availability(self):
        self.assertEqual(["login"], factory_repeat.Producers(
            login=lambda: PRODUCED["login"]).available())

    def test_identity_producers_stay_unbound_without_both_streams(self):
        producers = factory_repeat.bind_producers(
            windows_evidence=None, arch_evidence=None)
        self.assertIsNone(producers.login)
        self.assertIsNone(producers.optional_storage_absence_nonblocking)

    def test_host_network_producer_stays_unbound_without_both_captures(self):
        self.assertIsNone(
            factory_repeat.bind_producers(network_before={"a": 1}).host_network_changes)

    def test_a_tolerated_unproven_signal_becomes_an_absent_field(self):
        # The sibling raises UnprovenCategory to mean "not proven"; the adapter
        # turns that into an omitted field (NOT-RUN), never a fabricated zero.
        class Unproven(Exception):
            pass

        module = type(sys)("fake_producer_module")
        module.produce = lambda: (_ for _ in ()).throw(Unproven())
        module.Unproven = Unproven
        sys.modules["fake_producer_module"] = module
        self.addCleanup(sys.modules.pop, "fake_producer_module", None)
        factory_repeat.PRODUCER_ENTRY_POINTS["login"] = (
            "fake_producer_module", "produce")
        self.addCleanup(
            factory_repeat.PRODUCER_ENTRY_POINTS.__setitem__, "login",
            ("factory_measurements", "login_measurement"))
        producer = factory_repeat._producer(
            "login", lambda f: f(), tolerate="Unproven")
        self.assertIsNone(producer())


# --------------------------------------------------------------------------
# Evidence re-retention
# --------------------------------------------------------------------------


class EvidenceDispositionTests(unittest.TestCase):
    def test_the_two_tables_exactly_cover_allowed_evidence(self):
        # The driver never widens ALLOWED_EVIDENCE; it merges into the names
        # that whitelist already accepts.  Pinning the relationship here means
        # a future widening of either table breaks a test rather than silently
        # loosening the fail-closed surface.
        self.assertEqual(
            frozenset(factory_repeat.MERGED_EVIDENCE)
            | {factory_verify.RESULT, factory_verify.PXE_AUTHORITY_AUDIT},
            factory_verify.ALLOWED_EVIDENCE)
        self.assertFalse(
            frozenset(factory_repeat.MERGED_EVIDENCE)
            & factory_repeat.PHASE_LOCAL_EVIDENCE)

    def test_merged_names_are_the_allowed_ones(self):
        for name in factory_repeat.MERGED_EVIDENCE:
            self.assertEqual(factory_repeat.MERGE,
                             factory_repeat.evidence_disposition(name))

    def test_phase_local_names_are_retained(self):
        for name in ("result.json", "dualboot-events.jsonl",
                     "recovery-evidence.jsonl", "boot1-serial.log",
                     "boot2-serial.log", "identity-lifecycle.jsonl",
                     "workstation-stall-1.ppm",
                     "20260727T201057Z-controller.json",
                     "20260727T201057Z-serial-redacted.log"):
            self.assertEqual(factory_repeat.RETAIN,
                             factory_repeat.evidence_disposition(name), name)

    def test_an_unrecognised_artifact_is_refused(self):
        for name in ("secret.bin", "windows.qcow2", "boot1-serial.log.gz",
                     "workstation-stall-1.ppm.bak", "control.iso"):
            with self.subTest(name=name):
                with self.assertRaises(factory_repeat.RepeatError):
                    factory_repeat.evidence_disposition(name)

    def test_planning_refuses_an_unrecognised_artifact(self):
        with self.assertRaises(factory_repeat.RepeatError) as raised:
            factory_repeat.plan_retention(
                [("dualboot-acceptance", ["result.json", "smuggled.bin"], [])])
        self.assertIn("smuggled.bin", str(raised.exception))

    def test_planning_places_every_recognised_artifact(self):
        plan = factory_repeat.plan_retention([
            ("windows-install",
             ["controller-publication.log", "result.json", "switch.jsonl"],
             ["controller"]),
            ("arch-install",
             ["controller-publication.log", "switch.jsonl"], []),
        ])
        self.assertEqual(["windows-install", "arch-install"],
                         plan.merged["switch.jsonl"])
        self.assertEqual({"windows-install": ["result.json"]}, plan.retained)
        self.assertEqual({"windows-install": ["controller"]},
                         plan.subdirectories)


class RetentionTests(TemporaryRootTests):
    def bundle(self, name, files, subdirectories=()):
        directory = self.root / name
        directory.mkdir(parents=True)
        for filename, content in files.items():
            (directory / filename).write_bytes(content)
        for subdirectory in subdirectories:
            (directory / subdirectory).mkdir()
        return directory

    def test_merged_artifacts_concatenate_in_phase_order(self):
        first = self.bundle("a", {"workstation-serial.log": b"first\n",
                                  "result.json": b"{}\n"})
        second = self.bundle("b", {"workstation-serial.log": b"second\n"})
        destination = factory_repeat.retain_aggregate_evidence(
            self.root / "aggregate", [("a", first), ("b", second)],
            result={"schema": 1, "status": "observed"})
        self.assertEqual(
            b"first\nsecond\n",
            (destination / "workstation-serial.log").read_bytes())

    def test_phase_local_artifacts_land_under_phases(self):
        bundle = self.bundle("dual", {
            "result.json": b'{"status": "observed"}\n',
            "boot1-serial.log": b"boot 1\n",
            "dualboot-events.jsonl": b'{"check": "x"}\n',
        }, subdirectories=("boot1-frames",))
        destination = factory_repeat.retain_aggregate_evidence(
            self.root / "aggregate", [("dualboot", bundle)],
            result={"schema": 1, "status": "observed"})
        tree = destination / factory_repeat.PHASE_TREE / "dualboot"
        self.assertEqual(b"boot 1\n", (tree / "boot1-serial.log").read_bytes())
        self.assertEqual(b'{"status": "observed"}\n',
                         (tree / "result.json").read_bytes())
        # The aggregate's own result.json is its own, not the phase's.
        aggregate = json.loads(
            (destination / "result.json").read_text(encoding="utf-8"))
        self.assertEqual("observed", aggregate["status"])
        self.assertEqual(
            {"dualboot": ["boot1-frames"]},
            aggregate["phase_evidence"]["uncopied_working_trees"])

    def test_the_aggregate_directory_satisfies_check_2(self):
        # Measured today: a dual-boot or recovery bundle FAILs check 2 because
        # its own artifact names are not in ALLOWED_EVIDENCE.  Re-retention is
        # what makes the aggregate readable without widening that whitelist.
        bundle = self.bundle("dual", {
            "result.json": b'{"status": "observed"}\n',
            "boot1-serial.log": b"boot 1\n",
            "boot2-serial.log": b"boot 2\n",
            "dualboot-events.jsonl": b'{"check": "x"}\n',
        })
        direct = factory_verify.verify_run(bundle)
        self.assertEqual(
            "FAIL", direct["checks"]["evidence_contents_expected"]["status"])

        destination = factory_repeat.retain_aggregate_evidence(
            self.root / "aggregate", [("dualboot", bundle)],
            result={"schema": 1, "status": "observed"})
        receipt = factory_verify.verify_run(destination)
        self.assertEqual(
            "PASS", receipt["checks"]["evidence_contents_expected"]["status"])
        self.assertEqual([factory_repeat.PHASE_TREE],
                         receipt["evidence_subdirectories"])

    def test_an_unrecognised_phase_artifact_stops_the_whole_retention(self):
        bundle = self.bundle("dual", {"result.json": b"{}\n",
                                      "smuggled.bin": b"payload"})
        with self.assertRaises(factory_repeat.RepeatError):
            factory_repeat.retain_aggregate_evidence(
                self.root / "aggregate", [("dualboot", bundle)],
                result={"schema": 1, "status": "observed"})
        # Nothing was written: the plan is decided before any byte is copied.
        self.assertFalse((self.root / "aggregate").exists())

    def test_a_symlinked_phase_artifact_is_refused(self):
        bundle = self.bundle("dual", {"result.json": b"{}\n"})
        (bundle / "switch.jsonl").symlink_to(bundle / "result.json")
        with self.assertRaises(factory_repeat.RepeatError):
            factory_repeat.enumerate_bundle(bundle)

    def test_a_fifo_in_phase_evidence_is_refused(self):
        bundle = self.bundle("dual", {"result.json": b"{}\n"})
        os.mkfifo(bundle / "pipe")
        with self.assertRaises(factory_repeat.RepeatError):
            factory_repeat.enumerate_bundle(bundle)

    def test_a_merged_artifact_is_redacted_and_size_bounded(self):
        limit = factory_verify.EVIDENCE_LIMIT
        bundle = self.bundle("a", {
            "result.json": b"{}\n",
            "workstation-serial.log": b"x" * (limit + 10) + b"password: hunter2\n",
        })
        destination = factory_repeat.retain_aggregate_evidence(
            self.root / "aggregate", [("a", bundle)],
            result={"schema": 1, "status": "observed"})
        data = (destination / "workstation-serial.log").read_bytes()
        self.assertLessEqual(len(data), limit)
        self.assertNotIn(b"hunter2", data)
        receipt = factory_verify.verify_run(destination)
        self.assertEqual(
            "PASS", receipt["checks"]["evidence_within_size_limit"]["status"])
        self.assertEqual(
            "PASS",
            receipt["checks"]["no_secret_material_in_evidence"]["status"])

    def test_a_head_truncated_jsonl_drops_its_partial_record(self):
        limit = factory_verify.EVIDENCE_LIMIT
        filler = b'{"event": "pad", "value": "' + b"y" * limit + b'"}\n'
        bundle = self.bundle("a", {
            "result.json": b"{}\n",
            "switch.jsonl": filler + SWITCH.encode(),
        })
        destination = factory_repeat.retain_aggregate_evidence(
            self.root / "aggregate", [("a", bundle)],
            result={"schema": 1, "status": "observed"})
        data = (destination / "switch.jsonl").read_bytes()
        for line in data.splitlines():
            json.loads(line)

    def test_retained_files_are_private(self):
        bundle = self.bundle("dual", {"result.json": b"{}\n",
                                      "boot1-serial.log": b"boot 1\n",
                                      "switch.jsonl": SWITCH.encode()})
        destination = factory_repeat.retain_aggregate_evidence(
            self.root / "aggregate", [("dualboot", bundle)],
            result={"schema": 1, "status": "observed"})
        for path in sorted(destination.rglob("*")):
            mode = stat.S_IMODE(path.lstat().st_mode)
            self.assertEqual(0o700 if path.is_dir() else 0o600, mode, path)

    def test_an_existing_destination_is_refused(self):
        bundle = self.bundle("a", {"result.json": b"{}\n"})
        (self.root / "aggregate").mkdir()
        with self.assertRaises(factory_repeat.RepeatError):
            factory_repeat.retain_aggregate_evidence(
                self.root / "aggregate", [("a", bundle)],
                result={"schema": 1, "status": "observed"})


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------


class AggregateStatusTests(unittest.TestCase):
    COMPLETE = dict(WINDOWS_MEASUREMENTS, **PRODUCED,
                    install_order=["windows", "arch-workstation"],
                    default_boot="windows")

    def observations(self, *statuses):
        return [{"phase": f"p{index}", "status": status,
                 "status_required": True, "evidence": "evidence"}
                for index, status in enumerate(statuses)]

    def test_complete_union_and_passing_phases_claim_the_aggregate_vocabulary(self):
        self.assertEqual([], factory_repeat.missing_measurements(self.COMPLETE))
        self.assertEqual(
            "pass",
            factory_repeat.aggregate_status(
                self.observations("observed", "observed"), self.COMPLETE))

    def test_incomplete_union_stays_in_the_phase_vocabulary(self):
        partial = {k: v for k, v in self.COMPLETE.items() if k != "login"}
        self.assertEqual(
            "observed",
            factory_repeat.aggregate_status(
                self.observations("observed"), partial))

    def test_a_failed_phase_fails_the_aggregate(self):
        self.assertEqual(
            "fail",
            factory_repeat.aggregate_status(
                self.observations("observed", "fail"), self.COMPLETE))

    def test_a_missing_phase_status_fails_the_aggregate(self):
        self.assertEqual(
            "fail",
            factory_repeat.aggregate_status(
                self.observations("observed", None), self.COMPLETE))

    def test_a_phase_that_retains_no_result_is_not_required_to_have_one(self):
        observations = [{"phase": "arch-identity", "status": None,
                         "status_required": False, "evidence": "evidence"}]
        self.assertEqual(
            "pass",
            factory_repeat.aggregate_status(observations, self.COMPLETE))

    def test_the_aggregate_result_records_the_gap(self):
        partial = {k: v for k, v in self.COMPLETE.items() if k != "artifact_scan"}
        result = factory_repeat.aggregate_result(
            iteration=1, observations=self.observations("observed"),
            measurements=partial)
        self.assertEqual("observed", result["status"])
        self.assertEqual(["artifact_scan"], result["measurements_missing"])


class RepeatReceiptTests(unittest.TestCase):
    def receipt(self, verdict="PASS", not_run=()):
        return {"schema": 1, "kind": "factory-verify-run", "evidence": "run",
                "verdict": verdict, "checks": {},
                "needs_live_gate": list(not_run),
                "summary": {"pass": 16, "fail": 0, "not_run": len(not_run)}}

    def comparison(self, divergent=0):
        return {"equivalent": not divergent, "differences": [],
                "content_equivalent_count": 0, "divergent_count": divergent}

    def test_one_iteration_is_not_a_repeat(self):
        with self.assertRaises(factory_repeat.RepeatError):
            factory_repeat.repeat_receipt([self.receipt()], [])

    def test_two_passing_equivalent_runs_pass(self):
        document = factory_repeat.repeat_receipt(
            [self.receipt(), self.receipt()], [self.comparison()])
        self.assertEqual("PASS", document["verdict"])
        self.assertTrue(document["equivalent"])
        self.assertEqual(2, document["iterations"])

    def test_a_divergence_fails_even_when_both_runs_pass(self):
        document = factory_repeat.repeat_receipt(
            [self.receipt(), self.receipt()], [self.comparison(divergent=1)])
        self.assertEqual("FAIL", document["verdict"])
        self.assertFalse(document["equivalent"])

    def test_a_not_run_check_holds_the_verdict_at_not_run(self):
        document = factory_repeat.repeat_receipt(
            [self.receipt(verdict="NOT-RUN", not_run=("release_set_integrity",)),
             self.receipt()],
            [self.comparison()])
        self.assertEqual("NOT-RUN", document["verdict"])
        self.assertEqual(["release_set_integrity"], document["needs_live_gate"])

    def test_a_failing_run_fails(self):
        document = factory_repeat.repeat_receipt(
            [self.receipt(verdict="FAIL"), self.receipt()],
            [self.comparison()])
        self.assertEqual("FAIL", document["verdict"])


# --------------------------------------------------------------------------
# Preconditions
# --------------------------------------------------------------------------


def fresh_canonical_disk(root: Path) -> Path | None:
    """A never-installed 80G qcow2, exactly what homelab-bootstrap-vm-create makes.

    Never the checkout's own ``build/homelab/vm/bootstrap-dc`` image: on
    2026-09-24 the owner installed that image, and a test that ran
    ``factory_repeat.main(["--apply", ...])`` against it expecting a refusal
    instead started a real Windows install from inside the unit suite. A unit
    test's verdict must not depend on the state of the operator's lab, and no
    unit test may be one installed disk away from a live lifecycle.  ``None``
    when ``qemu-img`` is absent, so a caller can skip rather than probe bytes
    no partition-table reader understands.
    """
    qemu_img = shutil.which("qemu-img")
    if qemu_img is None:
        return None
    disk = root / "bootstrap-dc.qcow2"
    subprocess.run([qemu_img, "create", "-q", "-f", "qcow2", str(disk), "80G"],
                   check=True)
    return disk


class PreconditionTests(TemporaryRootTests):
    def test_a_fresh_canonical_image_is_refused(self):
        # What homelab-bootstrap-vm-create leaves behind: a 197,888-byte
        # never-installed qcow2, which every phase would otherwise boot.
        disk = fresh_canonical_disk(self.root)
        if disk is None:
            self.skipTest("qemu-img is required to create a real qcow2")
        problem = factory_repeat.controller_image_problem(disk)
        self.assertIsNotNone(problem)
        # The verdict comes from the partition-table probe, not a size floor,
        # and it names the remedy rather than leaving the operator to find it.
        self.assertIn("is not an installed Controller", problem)
        self.assertIn("homelab-bootstrap-vm-install", problem)

    def test_an_absent_image_is_refused(self):
        self.assertIn(
            "cannot be read",
            factory_repeat.controller_image_problem(self.root / "absent.qcow2"))

    def test_a_symlinked_image_is_refused(self):
        disk = self.installed_controller_disk()
        link = self.root / "link.qcow2"
        link.symlink_to(disk)
        self.assertIn("not a regular file",
                      factory_repeat.controller_image_problem(link))

    def test_an_installed_sized_image_is_accepted(self):
        self.assertIsNone(factory_repeat.controller_image_problem(
            self.installed_controller_disk()))

    def test_one_iteration_is_a_precondition_failure(self):
        problems = factory_repeat.preflight(
            iterations=1, controller_disk=self.installed_controller_disk())
        self.assertEqual(1, len(problems))
        self.assertIn("at least 2", problems[0])

    def test_a_missing_release_set_is_a_precondition_failure(self):
        problems = factory_repeat.preflight(
            controller_disk=self.installed_controller_disk(),
            releases=self.root / "no-releases")
        self.assertEqual(1, len(problems))
        self.assertIn("release set root is missing", problems[0])


class ApplyRefusalTests(TemporaryRootTests):
    def test_apply_refuses_while_the_canonical_image_is_empty(self):
        empty = self.root / "empty.qcow2"
        empty.write_bytes(b"x" * 197_888)
        errors = io.StringIO()
        stream = io.StringIO()
        driver = FakeLifecycle()
        real_stderr, sys.stderr = sys.stderr, errors
        try:
            status = factory_repeat.repeat(
                apply=True, controller_disk=empty, driver=driver,
                evidence_root=self.root / "evidence",
                work_root=self.root / "work", releases=self.release_set(),
                bind=lambda bundles, **kwargs: wired_producers(),
                stream=stream)
        finally:
            sys.stderr = real_stderr
        self.assertEqual(2, status)
        # Either refusal is correct here -- a blank image and one qemu-img
        # cannot read at all are both "not something a lifecycle can boot" --
        # so assert the refusal and the remedy, not one wording of the cause.
        printed = errors.getvalue()
        self.assertIn("refusing to run the lifecycle", printed)
        self.assertIn("homelab-bootstrap-vm-install", printed)
        # It refused before doing anything: no phase ran, nothing was destroyed.
        self.assertEqual([], driver.executed)
        self.assertEqual([], driver.destroyed)
        self.assertFalse((self.root / "evidence").exists())

    def test_the_default_cli_run_is_a_dry_run_that_touches_nothing(self):
        stream = io.StringIO()
        status = factory_repeat.repeat(
            evidence_root=self.root / "evidence", work_root=self.root / "work",
            releases=None, driver=FakeLifecycle(), stream=stream)
        self.assertEqual(0, status)
        self.assertIn("dry run", stream.getvalue())
        self.assertFalse((self.root / "evidence").exists())

    def test_the_dry_run_names_every_phase_and_every_refusal(self):
        stream = io.StringIO()
        factory_repeat.repeat(
            evidence_root=self.root / "evidence", work_root=self.root / "work",
            releases=None, controller_disk=self.root / "absent.qcow2",
            stream=stream)
        printed = stream.getvalue()
        for phase in factory_repeat.PHASES:
            self.assertIn(phase.name, printed)
        self.assertIn("refuses to apply", printed)

    def test_main_refuses_apply_against_a_fresh_canonical_image(self):
        # The CLI entry builds the REAL subprocess lifecycle, so the disk it is
        # handed must be one this test created; see fresh_canonical_disk.
        disk = fresh_canonical_disk(self.root)
        if disk is None:
            disk = self.root / "empty.qcow2"
            disk.write_bytes(b"x" * 197_888)
        errors = io.StringIO()
        real_stdout, real_stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = io.StringIO(), errors
        try:
            status = factory_repeat.main([
                "--apply",
                "--controller-disk", str(disk),
                "--evidence-root", str(self.root / "evidence"),
                "--work-root", str(self.root / "work"),
                "--releases", str(self.release_set()),
            ])
        finally:
            sys.stdout, sys.stderr = real_stdout, real_stderr
        self.assertEqual(2, status)
        self.assertIn("refusing to run the lifecycle", errors.getvalue())


# --------------------------------------------------------------------------
# The phase table and its commands
# --------------------------------------------------------------------------


class PhaseCommandTests(unittest.TestCase):
    def phase(self, name):
        return next(p for p in factory_repeat.PHASES if p.name == name)

    def test_windows_install_prepares_without_a_source(self):
        self.assertEqual(
            ["make", "--no-print-directory",
             "homelab-windows-install-prepare", "APPLY=1"],
            factory_repeat.prepare_command(self.phase("windows-install"), {}))

    def test_a_later_phase_consumes_an_earlier_bundle(self):
        command = factory_repeat.prepare_command(
            self.phase("arch-install"), {"windows-install": Path("/w/run-1")})
        self.assertIn("WINDOWS_RUN=/w/run-1", command)

    def test_a_source_suffix_names_a_file_inside_the_earlier_bundle(self):
        command = factory_repeat.prepare_command(
            self.phase("arch-identity"),
            {"arch-install": Path("/a/run-2"),
             "windows-identity": Path("/w/attempt-1")})
        self.assertIn("ARCH_RUN=/a/run-2", command)
        self.assertIn(
            "WINDOWS_IDENTITY_EVIDENCE=/w/attempt-1/acceptance-evidence.jsonl",
            command)

    def test_an_unrun_source_phase_fails_closed(self):
        with self.assertRaises(factory_repeat.RepeatError):
            factory_repeat.prepare_command(self.phase("arch-install"), {})

    def test_a_phase_without_a_prepare_target_mints_its_own_bundle(self):
        self.assertIsNone(factory_repeat.prepare_command(
            self.phase("lifecycle-recovery"), {}))

    def test_the_run_command_is_apply_gated_and_carries_the_bundle(self):
        command = factory_repeat.run_command(
            self.phase("arch-install"), Path("/a/run-2"), duration=900)
        self.assertEqual(
            ["make", "--no-print-directory", "homelab-arch-install-run",
             "APPLY=1", "ARCH_RUN=/a/run-2", "FACTORY_DURATION=900"], command)

    def test_windows_is_installed_before_arch_in_the_phase_order(self):
        names = [phase.name for phase in factory_repeat.PHASES]
        self.assertLess(names.index("windows-install"), names.index("arch-install"))

    def test_every_phase_names_a_distinct_bundle_variable(self):
        variables = [phase.variable for phase in factory_repeat.PHASES]
        self.assertEqual(len(variables), len(set(variables)))


# --------------------------------------------------------------------------
# End to end, through the real verifier and comparator
# --------------------------------------------------------------------------


class IterationTests(TemporaryRootTests):
    def test_one_iteration_renders_all_sixteen_checks(self):
        destination = self.iteration()
        receipt = factory_verify.verify_run(
            destination, release_set=self.release_set())
        self.assertEqual(len(factory_verify.CHECK_NAMES), len(receipt["checks"]))
        for name, check in receipt["checks"].items():
            self.assertEqual("PASS", check["status"], f"{name}: {check}")
        self.assertEqual("PASS", receipt["verdict"])
        self.assertEqual([], receipt["needs_live_gate"])
        # The aggregate vocabulary, not a phase's narrower claim.
        self.assertEqual({"status": "pass", "scope": "aggregate"},
                         receipt["run_status"])

    def test_the_iteration_destroys_disposable_state_first(self):
        driver = FakeLifecycle()
        self.iteration(driver=driver)
        self.assertEqual([self.root / "work-1"], driver.destroyed)
        # Destroyed first, then every phase in the declared order.
        self.assertEqual([phase.run_target for phase in factory_repeat.PHASES],
                         [command[2] for command in driver.executed])

    def test_the_iteration_captures_host_network_state_on_both_sides(self):
        driver = FakeLifecycle()
        self.iteration(driver=driver)
        self.assertEqual(2, driver.captures)

    def test_a_phase_bundle_alone_cannot_render_the_gate(self):
        # The premise of the whole driver, measured rather than asserted: the
        # richest single phase bundle still leaves half the checks NOT-RUN.
        driver = FakeLifecycle()
        self.iteration(driver=driver)
        phase = self.root / "work-1" / "windows-install" / "evidence"
        receipt = factory_verify.verify_run(phase, release_set=self.release_set())
        self.assertEqual("NOT-RUN", receipt["verdict"])
        self.assertGreater(receipt["summary"]["not_run"], 0)
        self.assertEqual(
            "NOT-RUN",
            receipt["checks"]["windows_installed_before_arch"]["status"])

    def test_an_unavailable_producer_leaves_its_check_not_run(self):
        destination = self.iteration(
            producers=wired_producers(artifact_scan=None))
        receipt = factory_verify.verify_run(
            destination, release_set=self.release_set())
        self.assertEqual("NOT-RUN", receipt["verdict"])
        self.assertEqual(
            "NOT-RUN",
            receipt["checks"]["no_forbidden_artifact_content"]["status"])
        self.assertEqual(0, receipt["summary"]["fail"])
        # And the aggregate honestly declines the aggregate vocabulary.
        self.assertEqual({"status": "observed", "scope": "phase"},
                         receipt["run_status"])

    def test_a_failing_phase_makes_the_aggregate_fail(self):
        fixtures = {name: dict(fixture)
                    for name, fixture in PHASE_FIXTURES.items()}
        broken = dict(fixtures["dualboot-acceptance"])
        broken["evidence"] = dict(broken["evidence"])
        broken["evidence"]["result.json"] = json.dumps(
            {"schema": 1, "status": "fail",
             "measurements": DUALBOOT_MEASUREMENTS}).encode()
        fixtures["dualboot-acceptance"] = broken
        destination = self.iteration(driver=FakeLifecycle(fixtures=fixtures))
        receipt = factory_verify.verify_run(destination)
        self.assertEqual("FAIL", receipt["checks"]["run_status_pass"]["status"])
        self.assertEqual("FAIL", receipt["verdict"])


class RepeatEndToEndTests(TemporaryRootTests):
    def repeat(self, *, driver=None, receipt=None, iterations=2,
               producers=None):
        stream = io.StringIO()
        errors = io.StringIO()
        real_stderr, sys.stderr = sys.stderr, errors
        try:
            status = factory_repeat.repeat(
                apply=True, iterations=iterations,
                controller_disk=self.installed_controller_disk(),
                evidence_root=self.root / "evidence",
                work_root=self.root / "work",
                releases=self.release_set(),
                receipt=receipt,
                driver=FakeLifecycle() if driver is None else driver,
                bind=lambda bundles, **kwargs: (
                    wired_producers() if producers is None else producers),
                stream=stream)
        finally:
            sys.stderr = real_stderr
        return status, stream.getvalue(), errors.getvalue()

    def test_two_iterations_pass_and_compare_equivalent(self):
        status, printed, errors = self.repeat()
        self.assertEqual(0, status)
        document = json.loads(printed)
        self.assertEqual("PASS", document["verdict"])
        self.assertTrue(document["equivalent"])
        self.assertEqual(2, document["iterations"])
        for run in document["runs"]:
            self.assertEqual("PASS", run["verdict"])
            self.assertEqual(16, run["summary"]["pass"])
        self.assertIn("PASS: factory-repeat", errors)

    def test_the_only_difference_between_iterations_is_content_equivalent(self):
        _, printed, _ = self.repeat()
        document = json.loads(printed)
        comparison = document["comparisons"][0]
        self.assertEqual("iteration-1", comparison["a"])
        self.assertEqual("iteration-2", comparison["b"])
        self.assertEqual(0, comparison["divergent_count"])
        self.assertGreater(comparison["content_equivalent_count"], 0)
        # The evidence directory name is exactly the expected-varying leaf.
        self.assertEqual(
            ["evidence"], [difference["path"]
                           for difference in comparison["differences"]])
        self.assertEqual("content-equivalent",
                         comparison["differences"][0]["classification"])

    def test_a_real_divergence_between_iterations_is_reported(self):
        class Drifting(FakeLifecycle):
            """The second iteration reverses the install order."""

            def __init__(self):
                super().__init__()
                self.iterations = 0

            def destroy(self, workdir):
                super().destroy(workdir)
                self.iterations += 1

            def run_phase(self, phase, *, workdir, bundles, duration):
                bundle = super().run_phase(
                    phase, workdir=workdir, bundles=bundles, duration=duration)
                if self.iterations > 1 and phase.name == "arch-install":
                    result = bundle / "evidence" / "result.json"
                    value = json.loads(result.read_text(encoding="utf-8"))
                    value["measurements"] = dict(
                        ARCH_MEASUREMENTS, install_order=["arch-workstation"])
                    value["status"] = "fail"
                    result.write_text(json.dumps(value), encoding="utf-8")
                return bundle

        status, printed, errors = self.repeat(driver=Drifting())
        self.assertEqual(1, status)
        document = json.loads(printed)
        self.assertEqual("FAIL", document["verdict"])
        self.assertFalse(document["equivalent"])
        divergent = [difference
                     for difference in document["comparisons"][0]["differences"]
                     if difference["classification"] == "divergent"]
        self.assertTrue(divergent)
        self.assertIn("verdict", {difference["path"] for difference in divergent})

    def test_the_receipt_file_is_private_and_matches_standard_output(self):
        receipt = self.root / "repeat-receipt.json"
        status, printed, errors = self.repeat(receipt=receipt)
        self.assertEqual(0, status)
        self.assertEqual(printed, receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            0o600, stat.S_IMODE(receipt.lstat().st_mode))
        self.assertIn("receipt written", errors)

    def test_a_single_iteration_is_refused_before_anything_runs(self):
        driver = FakeLifecycle()
        stream = io.StringIO()
        errors = io.StringIO()
        real_stderr, sys.stderr = sys.stderr, errors
        try:
            status = factory_repeat.repeat(
                apply=True, iterations=1, driver=driver,
                controller_disk=self.installed_controller_disk(),
                evidence_root=self.root / "evidence",
                work_root=self.root / "work", releases=self.release_set(),
                bind=lambda bundles, **kwargs: wired_producers(),
                stream=stream)
        finally:
            sys.stderr = real_stderr
        self.assertEqual(2, status)
        self.assertEqual([], driver.executed)
        self.assertIn("at least 2", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
