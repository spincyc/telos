"""The Windows COM1 progress reporter: framing, corpus, and non-authority.

Windows has no virtio-serial driver in this factory, so the reporter can only
use COM1 -- one-way, and shared with human-readable console output.  These
tests are the corpus's third consumer.  They prove three separate things:

* the reporter's line framing survives an adversarial shared console;
* the PowerShell script renders the same canonical bytes the host and the Arch
  reporter render, driven by the script's own field order rather than by a
  hand-copy of it;
* the COM1 path cannot be recorded as authoritative or acknowledged.

The PowerShell script itself is unexecuted: no Windows guest and no PowerShell
runtime exist here.  What is proven is its text, its declared field order, and
the host parser driven with byte-exact fixtures that reproduce its output.
"""

import base64
import hashlib
import hmac
import inspect
import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from homelab.tests.guest_progress_corpus import load_corpus, load_schema, validate
from homelab.vm import factory_runner
from homelab.vm import guest_progress_protocol as protocol
from homelab.vm.guest_progress_com1 import (
    ACKNOWLEDGED,
    AUTHORITATIVE,
    CHANNEL,
    COM1_PHASES,
    COM1_PRODUCER,
    MARKER,
    MAX_EVENT_BYTES,
    MAX_LINE_BYTES,
    Com1Observation,
    Com1ProgressError,
    Com1ProgressReader,
    com1_config,
    com1_progress_record,
    decode_line,
    frame_line,
)
from homelab.vm.guest_progress_protocol import (
    AcceptedEvent,
    AuthenticationError,
    ProtocolConfig,
    ReceiverState,
    ack_for,
    canonical_json,
)
from homelab.vm.windows_progress_iso import (
    FORBIDDEN_POWERSHELL,
    REPORTED_PHASE,
    SCRIPT,
    TASK_NAME,
    VOLUME_LABEL,
    WindowsProgressIsoError,
    audit_payload,
    build_progress_iso,
    progress_task_argument,
    register_launch_command,
    validate_material,
)

BASE64URL_ALPHABET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_FIELD_ADD = re.compile(r"""\$fields\.Add\('"([a-z0-9_]+)":""")


def script_text():
    return SCRIPT.read_text(encoding="utf-8")


def script_field_order():
    """The JSON key order the shipped script actually emits.

    Read from the script rather than restated here, so reordering the script
    breaks the byte-identity assertion instead of passing silently.
    """
    keys = []
    for name in _FIELD_ADD.findall(script_text()):
        if not keys or keys[-1] != name:
            keys.append(name)
    return keys


def render_like_the_script(case, key, order):
    """Reproduce the script's rendering in Python, in the script's own order.

    Every value the script emits is a validated bounded token, a canonical
    UUID, a fixed timestamp shape, base64, or an integer, so the script
    performs no JSON escaping and neither does this model.
    """
    values = {
        "attempt": case["attempt"],
        "boot_id": case["boot_id"],
        "id": case["id"],
        "nonce": case["nonce"],
        "phase": case["phase"],
        "progress": case["progress"],
        "sequence": case["sequence"],
        "source": case["producer"],
        "specversion": "1.0",
        "status": case["status"],
        "time": case["time"],
        "type": case["event_type"],
    }
    fields = []
    for name in order:
        value = values[name]
        if name in ("nonce",) and value is None:
            continue
        if name == "progress" and value is None:
            continue
        if value is None:
            fields.append(f'"{name}":null')
        elif isinstance(value, int) and not isinstance(value, bool):
            fields.append(f'"{name}":{value}')
        else:
            fields.append(f'"{name}":"{value}"')
    unsigned = "{" + ",".join(fields) + "}"
    digest = hmac.new(
        key,
        b"telos-guest-progress-v1\x00" + unsigned.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    mac = base64.b64encode(digest).decode("ascii")
    fields.insert(3, '"mac":"' + mac + '"')
    return ("{" + ",".join(fields) + "}").encode("utf-8")


class CorpusCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = load_corpus()
        cls.schema = load_schema()
        cls.key = bytes.fromhex(cls.corpus["key_hex"])
        cls.windows = [
            case for case in cls.corpus["accept"]
            if case["producer"] == COM1_PRODUCER
        ]

    def config(self):
        return com1_config(
            attempt=self.corpus["attempt"], nonce=self.corpus["nonce"])

    def reader(self, *, deadline=1000.0):
        ticks = iter(float(value) for value in range(1, 10000))
        return Com1ProgressReader(
            self.config(), self.key, deadline=deadline,
            clock=lambda: next(ticks))


class FramingTests(CorpusCase):
    def test_a_well_formed_line_round_trips_to_the_same_payload(self):
        for case in self.windows:
            with self.subTest(case=case["name"]):
                payload = case["canonical"].encode("utf-8")
                line = frame_line(payload)
                self.assertTrue(line.startswith(MARKER + " "))
                self.assertEqual(decode_line(line), payload)

    def test_the_corpus_lines_are_exactly_what_frame_line_renders(self):
        by_name = {case["name"]: case for case in self.windows}
        for entry in self.corpus["com1"]["accept_lines"]:
            with self.subTest(case=entry["name"]):
                payload = by_name[entry["case"]]["canonical"].encode("utf-8")
                self.assertEqual(frame_line(payload), entry["line"])

    def test_arbitrary_console_text_never_parses_as_an_event(self):
        for entry in self.corpus["com1"]["skip_lines"]:
            with self.subTest(case=entry["name"]):
                self.assertIsNone(decode_line(entry["line"]))

    def test_a_marker_in_the_wrong_position_is_rejected(self):
        payload = self.windows[0]["canonical"].encode("utf-8")
        line = frame_line(payload)
        body = line.split(" ", 1)[1]
        for hostile in (
            "prefix " + line,
            " " + line,
            "TELOS-PROGRESS-V10 " + body,
            "XTELOS-PROGRESS-V1 " + body,
            "TELOS-PROGRESS-V1" + body,
            line + " trailing",
            line + " " + line,
            "TELOS-PROGRESS-V2 " + body,
            "telos-progress-v1 " + body,
        ):
            with self.subTest(line=hostile[:48]):
                self.assertIsNone(decode_line(hostile))

    def test_a_marker_inside_the_payload_is_not_a_frame_boundary(self):
        # Every marker character is in the base64url alphabet, so a payload
        # may legitimately contain the marker text. Framing is a fullmatch on
        # the whole line, never a search for the marker, so an embedded
        # occurrence is ordinary payload.
        self.assertLessEqual(set(MARKER), BASE64URL_ALPHABET)
        embedded = MARKER + "AAA"
        self.assertEqual(len(embedded) % 4, 0)
        self.assertIsInstance(decode_line(MARKER + " " + embedded), bytes)

    def test_a_marked_line_that_is_not_an_event_fails_closed(self):
        for entry in self.corpus["com1"]["fail_lines"]:
            with self.subTest(case=entry["name"]):
                reader = self.reader()
                with self.assertRaises(Com1ProgressError) as caught:
                    reader.feed((entry["line"] + "\n").encode("ascii"))
                self.assertEqual(
                    caught.exception.classification, entry["classification"])
                reader.close()

    def test_a_partial_read_never_half_matches(self):
        payload = self.windows[0]["canonical"].encode("utf-8")
        raw = (frame_line(payload) + "\n").encode("ascii")
        for split in (1, 8, 17, 18, 40, len(raw) - 2, len(raw) - 1):
            with self.subTest(split=split):
                reader = self.reader()
                self.assertEqual(reader.feed(raw[:split]), ())
                observations = reader.feed(raw[split:])
                self.assertEqual(len(observations), 1)
                self.assertEqual(observations[0].type, "sync")
                reader.close()

    def test_an_interleaved_line_fails_closed_rather_than_half_matching(self):
        payload = self.windows[0]["canonical"].encode("utf-8")
        line = frame_line(payload)
        # Console output cuts the progress line short at an LF.
        truncated = line[: len(line) // 2] + "\n"
        reader = self.reader()
        with self.assertRaises(Com1ProgressError) as caught:
            reader.feed(truncated.encode("ascii"))
        self.assertEqual(caught.exception.classification, "malformed")
        # And the reader stays failed rather than resuming mid-stream.
        with self.assertRaises(Com1ProgressError):
            reader.feed((line + "\n").encode("ascii"))
        reader.close()

    def test_console_text_interleaved_between_events_is_skipped(self):
        reader = self.reader()
        chunks = []
        for index, case in enumerate(self.windows):
            chunks.append(f"Windows Setup: step {index}\n")
            chunks.append(frame_line(case["canonical"].encode("utf-8")) + "\n")
            chunks.append('{"schema_version":1,"event":"noise"}\n')
        observations = reader.feed("".join(chunks).encode("ascii"))
        self.assertEqual(len(observations), len(self.windows))
        self.assertEqual(reader.skipped_lines, 2 * len(self.windows))
        self.assertIsNone(reader.failure)
        reader.close()

    def test_a_crlf_line_is_console_output_not_an_event(self):
        payload = self.windows[0]["canonical"].encode("utf-8")
        reader = self.reader()
        self.assertEqual(
            reader.feed((frame_line(payload) + "\r\n").encode("ascii")), ())
        self.assertEqual(reader.skipped_lines, 1)
        reader.close()

    def test_an_overlong_console_line_is_dropped_whole(self):
        payload = self.windows[0]["canonical"].encode("utf-8")
        line = frame_line(payload)
        reader = self.reader()
        # An overlong line that ends with a valid frame must not have its tail
        # promoted into an event.
        noise = ("x" * (MAX_LINE_BYTES + 16)) + line + "\n"
        self.assertEqual(reader.feed(noise.encode("ascii")), ())
        self.assertEqual(reader.discarded_lines, 1)
        # The next complete line is a genuine line start and still works.
        observations = reader.feed((line + "\n").encode("ascii"))
        self.assertEqual(len(observations), 1)
        reader.close()

    def test_a_non_ascii_console_line_is_skipped(self):
        reader = self.reader()
        self.assertEqual(reader.feed("naïve console line\n".encode("utf-8")), ())
        self.assertEqual(reader.skipped_lines, 1)
        reader.close()

    def test_frame_line_refuses_an_oversized_payload(self):
        with self.assertRaises(Com1ProgressError):
            frame_line(b"a" * (MAX_EVENT_BYTES + 1))
        with self.assertRaises(Com1ProgressError):
            frame_line(b"")


class ReaderStreamTests(CorpusCase):
    def test_the_windows_stream_is_accepted_in_order(self):
        reader = self.reader()
        for case in self.windows:
            observations = reader.feed(
                (frame_line(case["canonical"].encode("utf-8")) + "\n"
                 ).encode("ascii"))
            self.assertEqual(len(observations), 1)
            observation = observations[0]
            self.assertEqual(observation.type, case["event_type"])
            self.assertEqual(observation.phase, case["phase"])
            self.assertEqual(observation.status, case["status"])
            self.assertEqual(observation.sequence, case["sequence"])
            self.assertEqual(observation.progress, case["progress"])
            self.assertFalse(observation.duplicate)
        record = reader.record()
        self.assertEqual(record["events_accepted"], len(self.windows))
        self.assertEqual(record["last_phase"], REPORTED_PHASE)
        self.assertIsNone(record["classification"])
        reader.close()

    def test_an_echoed_line_is_reported_as_a_duplicate(self):
        reader = self.reader()
        line = frame_line(self.windows[0]["canonical"].encode("utf-8")) + "\n"
        first = reader.feed(line.encode("ascii"))
        again = reader.feed(line.encode("ascii"))
        self.assertFalse(first[0].duplicate)
        self.assertTrue(again[0].duplicate)
        self.assertEqual(reader.record()["events_accepted"], 1)
        reader.close()

    def test_a_dropped_line_leaves_a_sequence_gap_that_fails_closed(self):
        # An exact echo is a duplicate, but a console line that swallowed a
        # progress line leaves a gap, and a gap is never silently tolerated.
        reader = self.reader()
        reader.feed(
            (frame_line(self.windows[0]["canonical"].encode("utf-8")) + "\n"
             ).encode("ascii"))
        with self.assertRaises(Com1ProgressError) as caught:
            reader.feed(
                (frame_line(self.windows[2]["canonical"].encode("utf-8"))
                 + "\n").encode("ascii"))
        self.assertEqual(caught.exception.classification, "replayed")
        self.assertEqual(reader.record()["classification"], "replayed")
        reader.close()

    def test_a_stream_that_does_not_begin_with_sync_fails_closed(self):
        reader = self.reader()
        with self.assertRaises(Com1ProgressError) as caught:
            reader.feed(
                (frame_line(self.windows[1]["canonical"].encode("utf-8"))
                 + "\n").encode("ascii"))
        self.assertEqual(caught.exception.classification, "replayed")
        reader.close()

    def test_a_foreign_producer_event_fails_authentication(self):
        arch = [
            case for case in self.corpus["accept"]
            if case["producer"] == self.corpus["producers"]["arch"]
        ][0]
        reader = self.reader()
        with self.assertRaises(Com1ProgressError) as caught:
            reader.feed(
                (frame_line(arch["canonical"].encode("utf-8")) + "\n"
                 ).encode("ascii"))
        self.assertEqual(caught.exception.classification, "unauthenticated")
        reader.close()

    def test_closing_keeps_the_observation_it_already_made(self):
        # Teardown destroys the receiver key. The counts it already earned are
        # honest evidence and must survive; reporting "absent" would erase
        # events that really arrived.
        reader = self.reader()
        for case in self.windows[:3]:
            reader.feed(
                (frame_line(case["canonical"].encode("utf-8")) + "\n"
                 ).encode("ascii"))
        before = reader.record()
        reader.close()
        after = reader.record()
        self.assertEqual(after, before)
        self.assertEqual(after["events_accepted"], 3)
        self.assertIs(after["authoritative"], False)

    def test_a_closed_reader_reports_an_absent_stream(self):
        reader = self.reader()
        reader.close()
        record = reader.record()
        self.assertEqual(record["liveness"], "absent")
        with self.assertRaises(Com1ProgressError):
            reader.feed(b"anything\n")


class NonAuthorityTests(CorpusCase):
    def test_a_com1_observation_is_not_an_acknowledgeable_event(self):
        reader = self.reader()
        observation = reader.feed(
            (frame_line(self.windows[0]["canonical"].encode("utf-8")) + "\n"
             ).encode("ascii"))[0]
        self.assertIsInstance(observation, Com1Observation)
        self.assertNotIsInstance(observation, AcceptedEvent)
        with self.assertRaises(AuthenticationError):
            ack_for(observation, self.config(), self.key)
        reader.close()

    def test_the_reader_retains_no_acknowledgeable_event(self):
        reader = self.reader()
        reader.feed(
            (frame_line(self.windows[0]["canonical"].encode("utf-8")) + "\n"
             ).encode("ascii"))
        for value in vars(reader).values():
            self.assertNotIsInstance(value, AcceptedEvent)
        reader.close()

    def test_authoritative_is_a_property_no_constructor_can_set(self):
        with self.assertRaises(TypeError):
            Com1Observation(
                type="sync", phase=None, status="starting", sequence=0,
                boot_id="boot-1", progress=None, duplicate=False,
                authoritative=True)
        observation = Com1Observation(
            type="sync", phase=None, status="starting", sequence=0,
            boot_id="boot-1", progress=None, duplicate=False)
        self.assertFalse(observation.authoritative)
        self.assertFalse(observation.acknowledged)

    def test_the_record_takes_no_authority_argument(self):
        parameters = set(inspect.signature(com1_progress_record).parameters)
        self.assertNotIn("authoritative", parameters)
        self.assertNotIn("acknowledged", parameters)
        with self.assertRaises(TypeError):
            com1_progress_record(liveness="absent", authoritative=True)

    def test_every_record_declares_the_channel_diagnostic(self):
        self.assertIs(AUTHORITATIVE, False)
        self.assertIs(ACKNOWLEDGED, False)
        record = com1_progress_record(liveness="absent")
        self.assertIs(record["authoritative"], False)
        self.assertIs(record["acknowledged"], False)
        self.assertEqual(record["channel"], CHANNEL)
        self.assertEqual(record["producer"], COM1_PRODUCER)
        reader = self.reader()
        reader.feed(
            (frame_line(self.windows[0]["canonical"].encode("utf-8")) + "\n"
             ).encode("ascii"))
        self.assertIs(reader.record()["authoritative"], False)
        self.assertIs(reader.record()["acknowledged"], False)
        reader.close()

    def test_the_reader_refuses_a_non_com1_producer(self):
        arch = ProtocolConfig(
            attempt=self.corpus["attempt"],
            producer=factory_runner.PROGRESS_PRODUCER,
            nonce=self.corpus["nonce"],
            phases=factory_runner.PROGRESS_PHASES,
            statuses=factory_runner.PROGRESS_STATUSES,
        )
        with self.assertRaises(Com1ProgressError) as caught:
            Com1ProgressReader(arch, self.key, deadline=10.0)
        self.assertEqual(caught.exception.classification, "unauthenticated")

    def test_com1_events_cannot_be_smuggled_into_an_authoritative_receiver(self):
        # The protocol binds `source` to the configured producer, so the COM1
        # producer is refused by any authoritative receiver even with the same
        # key and attempt.
        self.assertNotEqual(COM1_PRODUCER, factory_runner.PROGRESS_PRODUCER)
        authoritative = ReceiverState(
            ProtocolConfig(
                attempt=self.corpus["attempt"],
                producer=factory_runner.PROGRESS_PRODUCER,
                nonce=self.corpus["nonce"],
                phases=factory_runner.PROGRESS_PHASES,
                statuses=factory_runner.PROGRESS_STATUSES,
            ),
            self.key, deadline=1000.0)
        with self.assertRaises(AuthenticationError):
            authoritative.accept(
                self.windows[0]["canonical"].encode("utf-8"), received_at=1.0)

    def test_the_com1_phase_registry_is_disjoint_from_the_arch_one(self):
        self.assertFalse(
            set(COM1_PHASES) & set(factory_runner.PROGRESS_PHASES))


class ScriptTextTests(CorpusCase):
    """The PowerShell script is unexecuted here; its text is the evidence."""

    def test_the_script_field_order_is_the_protocol_sorted_order(self):
        order = script_field_order()
        with_mac = list(order)
        with_mac.insert(3, "mac")
        self.assertEqual(with_mac, sorted(with_mac))
        self.assertEqual(order[:3], ["attempt", "boot_id", "id"])
        self.assertIn('$fields.Insert(3, \'"mac":"\' + $mac + \'"\')',
                      script_text())

    def test_the_script_renders_the_corpus_bytes_exactly(self):
        order = script_field_order()
        for case in self.windows:
            with self.subTest(case=case["name"]):
                enriched = dict(case, attempt=self.corpus["attempt"])
                rendered = render_like_the_script(enriched, self.key, order)
                self.assertEqual(rendered, case["canonical"].encode("utf-8"))
                # And the host canonicaliser agrees with both.
                self.assertEqual(
                    canonical_json(json.loads(case["canonical"])), rendered)

    def test_the_script_never_reads_com1(self):
        folded = script_text().casefold()
        for token in FORBIDDEN_POWERSHELL:
            with self.subTest(token=token):
                self.assertNotIn(token, folded)

    def test_the_script_writes_only_framed_progress_lines(self):
        text = script_text()
        self.assertEqual(text.count(".WriteLine("), 4)
        self.assertEqual(
            text.count("$serial.WriteLine((New-TelosProgressLine"), 4)
        self.assertIn("$serial.NewLine = \"`n\"", text)

    def test_the_script_embeds_the_exact_protocol_constants(self):
        text = script_text()
        for required in (
            MARKER, COM1_PRODUCER, REPORTED_PHASE, TASK_NAME, VOLUME_LABEL,
            "telos-guest-progress-v1", protocol.SPEC_VERSION,
        ):
            with self.subTest(constant=required):
                self.assertIn(required, text)
        self.assertIn(str(MAX_LINE_BYTES), text)
        self.assertIn(".Replace('+', '-').Replace('/', '_').TrimEnd('=')", text)

    def test_the_script_registers_the_exact_bounded_boot_task(self):
        text = script_text()
        self.assertIn(progress_task_argument(), text)
        for required in (
            "New-ScheduledTaskTrigger -AtStartup",
            "-UserId 'SYSTEM' `",
            "-ExecutionTimeLimit (New-TimeSpan -Minutes 30)",
            "MSFT_TaskBootTrigger",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)

    def test_the_task_argument_bakes_in_no_drive_letter(self):
        argument = progress_task_argument()
        self.assertIn(VOLUME_LABEL, argument)
        self.assertNotRegex(argument, r"\b[A-Z]:\\TelosProgress")
        self.assertLess(len(argument), MAX_LINE_BYTES)
        self.assertLess(len(register_launch_command()), 241)

    def test_the_script_validates_its_material_before_rendering(self):
        text = script_text()
        self.assertIn(r"'^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z'", text)
        self.assertIn(r"'^(?:[0-9a-f]{2}){32,}\z'", text)
        # Anchored with \z, never $: a trailing newline must not be able to
        # smuggle a second line past a token check.
        self.assertNotIn("$'", text.replace("$TelosProgressToken", ""))


class IsoPayloadTests(CorpusCase):
    def test_the_tracked_payload_audits_clean(self):
        manifest = audit_payload()
        self.assertEqual(manifest["producer"], COM1_PRODUCER)
        self.assertEqual(manifest["phases"], [REPORTED_PHASE])
        self.assertIs(manifest["transport"]["authoritative"], False)
        self.assertIs(manifest["transport"]["acknowledged"], False)
        self.assertEqual(manifest["transport"]["direction"], "guest-to-host")
        self.assertEqual(manifest["transport"]["port"], "COM1")

    def test_material_validation_is_closed(self):
        good = {
            "attempt": "attempt-1", "nonce": "nonce-1", "key_hex": "0a" * 32,
        }
        self.assertEqual(validate_material(good), good)
        for broken in (
            {},
            dict(good, extra="x"),
            {"attempt": "attempt 1", "nonce": "nonce-1", "key_hex": "0a" * 32},
            {"attempt": "attempt-1", "nonce": "", "key_hex": "0a" * 32},
            {"attempt": "attempt-1", "nonce": "nonce-1", "key_hex": "0A" * 32},
            {"attempt": "attempt-1", "nonce": "nonce-1", "key_hex": "0a" * 31},
            {"attempt": "attempt-1", "nonce": "nonce-1", "key_hex": "zz" * 32},
        ):
            with self.subTest(material=broken):
                with self.assertRaises(WindowsProgressIsoError):
                    validate_material(broken)

    def test_the_payload_directory_holds_only_the_declared_files(self):
        root = Path(SCRIPT).parent
        self.assertEqual(
            {item.name for item in root.iterdir()},
            {"TelosProgress.ps1", "manifest.json"})


class IsoBuildTests(CorpusCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.material = {
            "attempt": "attempt-1", "nonce": "nonce-1", "key_hex": "0a" * 32,
        }

    def _runner(self, staged):
        def run(command, check=False):
            self.assertEqual(command[0], "xorriso")
            self.assertIn(VOLUME_LABEL, command)
            source = Path(command[-1])
            staged.update({
                item.name: (item.read_text(encoding="utf-8"),
                            item.stat().st_mode & 0o777)
                for item in source.iterdir()
            })
            Path(command[command.index("-o") + 1]).write_bytes(b"iso")
            return None
        return run

    def test_the_medium_carries_the_script_material_and_a_receipt(self):
        staged = {}
        output = self.root / "progress.iso"
        build_progress_iso(
            output, self.material, runner=self._runner(staged))
        self.assertEqual(
            set(staged), {"TelosProgress.ps1", "progress.json",
                          "receipt.json"})
        self.assertEqual(staged["progress.json"][1], 0o400)
        self.assertEqual(staged["TelosProgress.ps1"][1], 0o400)
        document = json.loads(staged["progress.json"][0])
        self.assertEqual(document["attempt"], "attempt-1")
        self.assertEqual(document["producer"], COM1_PRODUCER)
        self.assertEqual(document["phase"], REPORTED_PHASE)
        self.assertIs(document["authoritative"], False)
        receipt = json.loads(staged["receipt.json"][0])
        self.assertIs(receipt["authoritative"], False)
        self.assertIs(receipt["contains_per_attempt_channel_key"], True)
        self.assertEqual(receipt["task_name"], TASK_NAME)
        self.assertTrue(output.is_file())
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_the_material_never_reaches_the_command_line(self):
        seen = []

        def run(command, check=False):
            seen.append(list(command))
            Path(command[command.index("-o") + 1]).write_bytes(b"iso")

        build_progress_iso(
            self.root / "progress.iso", self.material, runner=run)
        joined = " ".join(seen[0])
        self.assertNotIn(self.material["key_hex"], joined)
        self.assertNotIn(self.material["nonce"], joined)

    def test_an_existing_destination_is_refused(self):
        output = self.root / "progress.iso"
        output.write_bytes(b"")
        with self.assertRaises(WindowsProgressIsoError):
            build_progress_iso(output, self.material, runner=lambda *a, **k: None)

    def test_a_world_readable_parent_is_refused(self):
        loose = self.root / "loose"
        loose.mkdir(mode=0o755)
        with self.assertRaises(WindowsProgressIsoError):
            build_progress_iso(
                loose / "progress.iso", self.material,
                runner=lambda *a, **k: None)


class SharedCorpusTests(CorpusCase):
    def test_every_case_validates_against_the_published_schema(self):
        for case in self.corpus["accept"]:
            with self.subTest(case=case["name"]):
                validate(self.schema, json.loads(case["canonical"]))

    def test_the_corpus_covers_both_reporters(self):
        producers = {case["producer"] for case in self.corpus["accept"]}
        self.assertEqual(producers, {
            factory_runner.PROGRESS_PRODUCER, COM1_PRODUCER})


if __name__ == "__main__":
    unittest.main()
