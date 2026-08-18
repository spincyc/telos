"""Fail-closed grading of a booted image's declared systemd services.

The transcripts here are synthetic: the judge is pure, so proving it needs no
guest, no root, and no QEMU. Every failure mode the live capture can produce --
a missing unit, a dead one, a truncated read, an echoed marker, a transcript
from another run or another role -- is exercised as its own case, because a
judge that passes on absent evidence is worse than no judge at all.
"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from homelab.lib.image_service_gate import (
    ImageServiceGateError,
    judge_capture,
    main,
    parse_capture,
    read_transcript,
)
from homelab.lib.package_contract import (
    EXPECTED_OVERLAYS,
    PROFILE_OVERLAYS,
    load_registry,
    merge_contract,
)


ROOT = Path(__file__).resolve().parents[1]
TRACKED_REGISTRY = ROOT / "package-contract.json"

PROFILE = "workstation-install"
TOKEN = "svc0a1b2c3d4"

RUNNING = {"enabled": "enabled", "active": "active",
           "type": "simple", "result": "success"}
COMPLETED_ONESHOT = {"enabled": "enabled", "active": "inactive",
                     "type": "oneshot", "result": "success"}


def empty_layer():
    """An empty layer in whatever shape the tracked registry defines.

    Derived rather than hardcoded: the layer schema grows (services, modules)
    and a hardcoded literal here would fail the next time it does, for a
    reason that has nothing to do with this judge.
    """
    template = json.loads(TRACKED_REGISTRY.read_text(encoding="utf-8"))
    return {key: [] for key in template["common"]}


def registry():
    """A synthetic registry whose workstation-install profile declares three
    units: one plain service from common, one from an overlay, one oneshot."""
    overlays = {name: empty_layer() for name in EXPECTED_OVERLAYS}
    overlays["identity-client"]["services"] = ["sssd.service"]
    overlays["workstation"]["services"] = ["telos-arch-join-once.service"]
    common = empty_layer()
    common["services"] = ["sshd.service"]
    return {"schema_version": 1, "common": common, "overlays": overlays}


def unit(name, **overrides):
    fields = dict(RUNNING)
    fields.update(overrides)
    return {"name": name, **fields}


def healthy_units():
    return [
        unit("sshd.service"),
        unit("sssd.service"),
        unit("telos-arch-join-once.service", **COMPLETED_ONESHOT),
    ]


def render(units, *, token=TOKEN, profile=PROFILE, count=None,
           external_access="false", verdict="PASS", schema="1",
           noise=True, prologue=(), epilogue=(), terminator="\r\n",
           final_terminator=None):
    """One synthetic ttyS0 capture, CRLF-terminated the way a serial console
    really terminates lines, with ambient kernel noise around the frame."""
    lines = list(prologue)
    if noise:
        lines.append("[    0.000000] Linux version 6.9.1-arch1-1")
        lines.append("[    3.412000] systemd[1]: Reached target multi-user.")
    lines.append(f"__TELOS_SERVICE_BEGIN_{token} schema={schema} "
                 f"profile={profile}")
    for item in units:
        lines.append(
            f"__TELOS_SERVICE_UNIT_{token} name={item['name']} "
            f"enabled={item['enabled']} active={item['active']} "
            f"type={item['type']} result={item['result']}")
    total = len(units) if count is None else count
    lines.append(f"__TELOS_SERVICE_END_{token} units={total} "
                 f"external_access={external_access} verdict={verdict}")
    lines.extend(epilogue)
    text = "".join(line + terminator for line in lines)
    if final_terminator is not None:
        text = text[:-len(terminator)] + final_terminator
    return text


class ServiceCaptureJudgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.registry_path = self.base / "package-contract.json"
        self.write_registry(registry())

    def tearDown(self):
        self.temporary.cleanup()

    def write_registry(self, value):
        self.registry_path.write_text(json.dumps(value), encoding="utf-8")

    def judge(self, text, *, profile=PROFILE, token=None):
        return judge_capture(
            profile, self.registry_path, text, token=token)

    def refuse(self, text, message, *, profile=PROFILE, token=None):
        with self.assertRaises(ImageServiceGateError) as raised:
            self.judge(text, profile=profile, token=token)
        self.assertIn(message, str(raised.exception))
        return str(raised.exception)

    # -- the passing shape ------------------------------------------------

    def test_every_declared_unit_enabled_and_active_passes(self):
        verdict = self.judge(render(healthy_units()))
        self.assertEqual(verdict["result"], "pass")
        self.assertEqual(verdict["schema_version"], 1)
        self.assertEqual(verdict["kind"], "image-declared-service-observation")
        self.assertEqual(verdict["profile"], PROFILE)
        self.assertEqual(
            verdict["overlays"],
            ["identity-client", "automatic-updates", "workstation"])
        self.assertEqual(verdict["checks"], 3)
        self.assertIs(verdict["external_access"], False)
        self.assertEqual(
            verdict["declared_services"],
            ["sshd.service", "sssd.service", "telos-arch-join-once.service"])
        self.assertEqual(
            verdict["running_services"], ["sshd.service", "sssd.service"])
        self.assertEqual(
            verdict["completed_oneshots"], ["telos-arch-join-once.service"])
        self.assertEqual(verdict["undeclared_enabled"], [])
        self.assertEqual(verdict["records"], 3)

    def test_a_completed_oneshot_is_not_treated_as_a_dead_unit(self):
        """A oneshot that ran and exited is inactive by design.

        Demanding active=active of everything would fail every real image:
        telos-arch-join-once, homelab-first-boot and
        systemd-networkd-wait-online are all oneshots.
        """
        verdict = self.judge(render(healthy_units()))
        self.assertIn(
            "telos-arch-join-once.service", verdict["completed_oneshots"])

    def test_verdict_carries_no_host_paths_hostnames_or_tokens(self):
        document = json.dumps(self.judge(render(healthy_units())))
        for leak in (str(self.base), str(self.registry_path), TOKEN, "/home/"):
            self.assertNotIn(leak, document)

    # -- declared units that are not proven --------------------------------

    def test_one_missing_unit_fails(self):
        units = [item for item in healthy_units()
                 if item["name"] != "sssd.service"]
        self.refuse(
            render(units),
            "declared unit is absent from the capture: sssd.service")

    def test_one_enabled_but_inactive_unit_fails(self):
        units = healthy_units()
        units[1] = unit("sssd.service", active="inactive")
        self.refuse(
            render(units),
            "declared unit is enabled but not running: sssd.service reports "
            "active=inactive type=simple result=success")

    def test_a_failed_unit_fails(self):
        units = healthy_units()
        units[0] = unit("sshd.service", active="failed", result="exit-code")
        self.refuse(
            render(units),
            "declared unit is enabled but not running: sshd.service")

    def test_a_oneshot_that_did_not_succeed_fails(self):
        units = healthy_units()
        units[2] = unit("telos-arch-join-once.service", active="inactive",
                        type="oneshot", result="exit-code")
        self.refuse(
            render(units),
            "declared unit is enabled but not running: "
            "telos-arch-join-once.service")

    def test_a_disabled_unit_fails(self):
        units = healthy_units()
        units[1] = unit("sssd.service", enabled="disabled")
        self.refuse(
            render(units), "declared unit is not enabled: sssd.service reports "
            "disabled")

    def test_runtime_only_enablement_fails(self):
        """enabled-runtime does not survive the next boot."""
        units = healthy_units()
        units[1] = unit("sssd.service", enabled="enabled-runtime")
        self.refuse(
            render(units), "declared unit is not enabled: sssd.service reports "
            "enabled-runtime")

    def test_a_unit_absent_from_the_image_fails(self):
        units = healthy_units()
        units[1] = unit("sssd.service", enabled="not-found", active="inactive")
        self.refuse(
            render(units),
            "declared unit is not installed in the image: sssd.service")

    def test_a_profile_that_declares_nothing_cannot_pass(self):
        value = registry()
        value["common"]["services"] = []
        value["overlays"]["identity-client"]["services"] = []
        value["overlays"]["workstation"]["services"] = []
        self.write_registry(value)
        self.refuse(render([]), "declares no services to verify")

    # -- drift: what the image runs that the contract never declared -------

    def test_an_undeclared_enabled_unit_is_named_and_makes_it_partial(self):
        units = healthy_units() + [
            unit("cronie.service"), unit("telnet.socket")]
        verdict = self.judge(render(units))
        self.assertEqual(verdict["result"], "partial")
        self.assertEqual(
            verdict["undeclared_enabled"], ["cronie.service", "telnet.socket"])
        # The declared half is still fully proven; drift is a finding, not a
        # reason to hide the units that did pass.
        self.assertEqual(verdict["checks"], 3)
        self.assertEqual(
            verdict["running_services"], ["sshd.service", "sssd.service"])

    def test_a_runtime_enabled_undeclared_unit_is_drift_too(self):
        units = healthy_units() + [
            unit("cronie.service", enabled="enabled-runtime")]
        verdict = self.judge(render(units))
        self.assertEqual(verdict["undeclared_enabled"], ["cronie.service"])

    def test_an_undeclared_disabled_unit_is_not_a_finding(self):
        units = healthy_units() + [
            unit("cronie.service", enabled="disabled", active="inactive")]
        verdict = self.judge(render(units))
        self.assertEqual(verdict["result"], "pass")
        self.assertEqual(verdict["undeclared_enabled"], [])

    # -- anchoring: the bug class this repository keeps hitting -------------

    def test_a_unit_name_that_only_contains_a_declared_name_proves_nothing(self):
        """The deliberate substring case.

        `telos-sshd.service` contains `sshd.service`, and the kernel log line
        below contains it too. An unanchored matcher would call `sshd.service`
        proven; an anchored one sees it was never reported at all.
        """
        units = [item for item in healthy_units()
                 if item["name"] != "sshd.service"]
        units.append(unit("telos-sshd.service"))
        text = render(
            units,
            epilogue=("[    9.220000] systemd[1]: Started sshd.service.",
                      "[    9.221000] audit: unit=sshd.service enabled=enabled "
                      "active=active"))
        self.refuse(
            text, "declared unit is absent from the capture: sshd.service")

    def test_a_marker_printed_by_the_shell_is_not_evidence(self):
        """A shell echoing the capture script prints the marker text itself."""
        echoed = (
            "  printf '__TELOS_SERVICE_UNIT_%s name=%s enabled=%s\\n' "
            "\"$token\" \"$name\" \"$state\"")
        self.refuse(
            render(healthy_units(), prologue=(echoed,)),
            "capture marker is not line-anchored")

    def test_a_marker_glued_onto_a_kernel_message_is_not_evidence(self):
        units = healthy_units()
        text = render(units)
        text = text.replace(
            f"__TELOS_SERVICE_UNIT_{TOKEN} name=sssd.service",
            f"[   12.5] systemd[1]: X __TELOS_SERVICE_UNIT_{TOKEN} "
            "name=sssd.service")
        self.refuse(text, "capture marker is not line-anchored")

    def test_a_transcript_cut_mid_line_fails(self):
        text = render(healthy_units())
        self.refuse(
            text[:len(text) - 12],
            "transcript is truncated: it does not end with a line terminator")

    def test_a_transcript_missing_its_final_terminator_fails(self):
        self.refuse(
            render(healthy_units(), final_terminator=""),
            "transcript is truncated: it does not end with a line terminator")

    def test_a_frame_that_never_ended_fails(self):
        text = render(healthy_units())
        text = text[:text.index(f"__TELOS_SERVICE_END_{TOKEN}")]
        self.refuse(
            text, "transcript is truncated: the capture frame never ended")

    def test_a_frame_whose_count_disagrees_with_its_records_fails(self):
        self.refuse(
            render(healthy_units(), count=9),
            "transcript is truncated: the frame declares 9 units and carries 3")

    def test_a_partial_read_that_shortens_a_count_fails(self):
        """The owner_uid=1-from-10001 shape, in the frame's own length."""
        units = healthy_units() + [unit(f"pad{index}.service")
                                   for index in range(9)]
        self.refuse(
            render(units, count=1),
            "the frame declares 1 units and carries 12")

    def test_a_partial_read_that_shortens_a_value_fails(self):
        text = render(healthy_units()).replace(
            "active=active type=simple", "active=activ type=simple", 1)
        self.refuse(text, "unknown active state for sshd.service: activ")

    def test_records_must_match_a_whole_line(self):
        text = render(healthy_units()).replace(
            "name=sssd.service enabled=enabled",
            "name=sssd.service  enabled=enabled", 1)
        self.refuse(text, "malformed capture record")

    def test_a_reordered_field_fails(self):
        text = render(healthy_units()).replace(
            "name=sssd.service enabled=enabled active=active",
            "enabled=enabled name=sssd.service active=active", 1)
        self.refuse(text, "UNIT record expects field 'name'")

    def test_a_missing_field_fails(self):
        text = render(healthy_units()).replace(
            " type=simple result=success", " result=success", 1)
        self.refuse(text, "UNIT record must carry exactly 5 fields, not 4")

    # -- framing and attribution -------------------------------------------

    def test_a_transcript_with_no_frame_fails(self):
        self.refuse(
            "[    0.000000] Linux version 6.9.1-arch1-1\r\n",
            "transcript carries no capture frame")

    def test_an_empty_transcript_fails(self):
        self.refuse("", "transcript is empty")

    def test_two_frames_fail(self):
        text = render(healthy_units())
        self.refuse(text + text, "more than one capture frame")

    def test_a_record_after_the_frame_end_fails(self):
        extra = (f"__TELOS_SERVICE_UNIT_{TOKEN} name=cronie.service "
                 "enabled=enabled active=active type=simple result=success")
        self.refuse(
            render(healthy_units(), epilogue=(extra,)),
            "capture record follows the frame end")

    def test_a_record_before_the_frame_start_fails(self):
        early = (f"__TELOS_SERVICE_UNIT_{TOKEN} name=cronie.service "
                 "enabled=enabled active=active type=simple result=success")
        self.refuse(
            render(healthy_units(), prologue=(early,)),
            "capture record precedes the frame start")

    def test_two_interleaved_capture_runs_fail(self):
        text = render(healthy_units()).replace(
            f"__TELOS_SERVICE_UNIT_{TOKEN} name=sssd.service",
            "__TELOS_SERVICE_UNIT_zzzz99887766 name=sssd.service", 1)
        self.refuse(text, "interleaves two capture tokens")

    def test_a_duplicated_unit_record_fails(self):
        units = healthy_units() + [unit("sshd.service")]
        self.refuse(render(units), "duplicate record for sshd.service")

    def test_a_transcript_from_another_role_fails(self):
        self.refuse(
            render(healthy_units(), profile="controller-seed"),
            "transcript was captured for profile controller-seed, "
            "not workstation-install")

    def test_a_transcript_from_another_run_fails(self):
        self.refuse(
            render(healthy_units()),
            "transcript carries another run's capture token",
            token="aaaa11112222")

    def test_the_expected_token_is_accepted(self):
        verdict = self.judge(render(healthy_units()), token=TOKEN)
        self.assertEqual(verdict["result"], "pass")

    def test_an_unusable_token_shape_fails(self):
        self.refuse(render(healthy_units(), token="short"),
                    "malformed capture record")

    def test_a_guest_side_failure_verdict_is_never_promoted(self):
        self.refuse(
            render(healthy_units(), verdict="FAIL"),
            "the guest capture itself reported FAIL")

    def test_a_capture_that_reached_the_network_fails(self):
        self.refuse(
            render(healthy_units(), external_access="true"),
            "capture does not prove external_access=false")

    def test_an_unknown_capture_schema_fails(self):
        self.refuse(
            render(healthy_units(), schema="2"),
            "unsupported capture schema: 2")

    def test_a_non_numeric_frame_count_fails(self):
        text = render(healthy_units()).replace("units=3", "units=three", 1)
        self.refuse(text, "non-numeric unit count")

    def test_an_invalid_unit_name_fails(self):
        units = healthy_units()
        units[0] = unit("sshd")
        self.refuse(render(units), "invalid unit name: sshd")

    def test_an_unknown_enablement_vocabulary_fails(self):
        units = healthy_units()
        units[0] = unit("sshd.service", enabled="probably")
        self.refuse(
            render(units), "unknown enabled state for sshd.service: probably")

    def test_lf_only_transcripts_are_read_too(self):
        verdict = self.judge(render(healthy_units(), terminator="\n"))
        self.assertEqual(verdict["result"], "pass")

    # -- contract and profile plumbing -------------------------------------

    def test_an_unknown_profile_fails(self):
        self.refuse(
            render(healthy_units(), profile="rogue"),
            "unknown image profile: rogue", profile="rogue")

    def test_a_broken_registry_is_attributed_to_the_contract(self):
        value = registry()
        del value["overlays"]["workstation"]
        self.write_registry(value)
        self.refuse(render(healthy_units()), "contract: ")

    def test_declared_services_come_from_the_tracked_contract(self):
        """No second copy of the list: the judge reads package-contract.json."""
        for profile, overlays in PROFILE_OVERLAYS.items():
            expected = merge_contract(
                load_registry(TRACKED_REGISTRY), overlays).services
            self.assertTrue(expected, profile)
            units = [unit(name) for name in expected]
            verdict = judge_capture(
                profile, TRACKED_REGISTRY,
                render(units, profile=profile))
            self.assertEqual(verdict["result"], "pass")
            self.assertEqual(verdict["declared_services"], list(expected))
            self.assertEqual(verdict["checks"], len(expected))

    def test_a_real_profile_unit_dropped_from_the_image_fails(self):
        overlays = PROFILE_OVERLAYS[PROFILE]
        declared = merge_contract(
            load_registry(TRACKED_REGISTRY), overlays).services
        units = [unit(name) for name in declared[1:]]
        with self.assertRaises(ImageServiceGateError) as raised:
            judge_capture(
                PROFILE, TRACKED_REGISTRY, render(units, profile=PROFILE))
        self.assertIn(
            f"declared unit is absent from the capture: {declared[0]}",
            str(raised.exception))


class TranscriptReadingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.path = self.base / "console.log"

    def tearDown(self):
        self.temporary.cleanup()

    def test_an_absent_transcript_fails(self):
        with self.assertRaises(ImageServiceGateError) as raised:
            read_transcript(self.path)
        message = str(raised.exception)
        self.assertIn("cannot read capture transcript", message)
        self.assertNotIn(str(self.base), message)

    def test_an_endless_transcript_is_refused_before_it_is_held(self):
        self.path.symlink_to("/dev/zero")
        with self.assertRaises(ImageServiceGateError) as raised:
            read_transcript(self.path)
        self.assertIn("capture transcript is too large", str(raised.exception))

    def test_an_undecodable_transcript_fails(self):
        self.path.write_bytes(b"\xff\xfe not utf-8\n")
        with self.assertRaises(ImageServiceGateError) as raised:
            read_transcript(self.path)
        self.assertIn("is not UTF-8", str(raised.exception))

    def test_a_readable_transcript_round_trips(self):
        text = render(healthy_units())
        self.path.write_text(text, encoding="utf-8")
        capture = parse_capture(read_transcript(self.path))
        self.assertEqual(capture.token, TOKEN)
        self.assertEqual(capture.profile, PROFILE)
        self.assertEqual(len(capture.units), 3)


class ServiceGateCommandTests(unittest.TestCase):
    """The command grades against the tracked contract and nothing else.

    There is deliberately no ``--registry`` flag: a gate that accepted a
    caller-supplied registry could be satisfied by supplying one that declares
    no services at all, which would make every verdict it signs meaningless.
    These cases therefore build their transcripts from the real
    ``homelab/package-contract.json``.
    """

    @classmethod
    def setUpClass(cls):
        cls.declared = merge_contract(
            load_registry(TRACKED_REGISTRY), PROFILE_OVERLAYS[PROFILE]).services

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.transcript = self.base / "console.log"

    def tearDown(self):
        self.temporary.cleanup()

    def tracked_units(self):
        return [unit(name) for name in self.declared]

    def run_main(self, *extra, units=None):
        self.transcript.write_text(
            render(self.tracked_units() if units is None else units),
            encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        argv = ["--profile", PROFILE, *extra, str(self.transcript)]
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_the_command_takes_no_registry_override(self):
        out, err = io.StringIO(), io.StringIO()
        with self.assertRaises(SystemExit), \
                redirect_stdout(out), redirect_stderr(err):
            main(["--profile", PROFILE, "--registry", "/tmp/permissive.json",
                  str(self.transcript)])
        self.assertIn("unrecognized arguments: --registry", err.getvalue())

    def test_a_pass_prints_one_sorted_json_verdict(self):
        code, out, err = self.run_main()
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        verdict = json.loads(out)
        self.assertEqual(verdict["result"], "pass")
        self.assertEqual(verdict["declared_services"], list(self.declared))
        self.assertEqual(out, json.dumps(verdict, sort_keys=True) + "\n")

    def test_a_failure_exits_non_zero_and_says_why(self):
        code, out, err = self.run_main(units=self.tracked_units()[1:])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(
            "image service gate: declared unit is absent from the capture: "
            f"{self.declared[0]}", err)

    def test_drift_is_named_on_stderr_and_still_exits_zero(self):
        code, out, err = self.run_main(
            units=self.tracked_units() + [unit("cronie.service")])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["result"], "partial")
        self.assertIn("image enables undeclared units: cronie.service", err)

    def test_the_verdict_can_be_retained_as_a_file(self):
        evidence = self.base / "service-evidence.json"
        code, out, err = self.run_main("--evidence", str(evidence))
        self.assertEqual(code, 0)
        self.assertIn("service verdict:", out)
        self.assertEqual(
            json.loads(evidence.read_text(encoding="utf-8"))["result"], "pass")

    def test_an_unreadable_transcript_exits_non_zero(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["--profile", PROFILE, str(self.transcript)])
        self.assertEqual(code, 1)
        self.assertIn("cannot read capture transcript", err.getvalue())


if __name__ == "__main__":
    unittest.main()
