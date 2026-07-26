"""Tests for the prompt registry and the confirmation gate.

ADR 0058 makes this module the single source of truth shared by the installer
and the acceptance harness, so its structure is load-bearing: if a prompt
identifier changes, the harness stops being able to answer it. These tests pin
the parts the harness depends on, and prove the confirmation cannot be satisfied
by anything except the actual serial.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import prompts  # noqa: E402
from prompts import AnswerError  # noqa: E402


class TestRegistryShape(unittest.TestCase):
    def test_identifiers_are_unique(self):
        identifiers = [prompt.identifier for prompt in prompts.PROMPTS]
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_lookup_covers_every_prompt(self):
        self.assertEqual(len(prompts.BY_IDENTIFIER), len(prompts.PROMPTS))

    def test_every_prompt_has_help(self):
        # The harness does not need help text, but an operator standing at a
        # console at midnight does, and a prompt without it is a defect.
        for prompt in prompts.PROMPTS:
            with self.subTest(prompt=prompt.identifier):
                self.assertTrue(prompt.help_text.strip())

    def test_rendered_prompts_are_distinguishable(self):
        # The pty harness syncs on prompt text. Two identical prompts would be
        # ambiguous and it would answer the wrong one.
        rendered = [prompt.render() for prompt in prompts.PROMPTS]
        self.assertEqual(len(rendered), len(set(rendered)))


class TestApplicability(unittest.TestCase):
    def test_workstation_is_not_asked_controller_questions(self):
        applicable = [p.identifier for p in prompts.applicable({"profile": "workstation"})]
        self.assertIn("hostname", applicable)
        self.assertNotIn("managed_interface", applicable)
        self.assertNotIn("network_services", applicable)

    def test_controller_without_network_services_skips_the_plan(self):
        answers = {"profile": "controller", "network_services": "no"}
        applicable = [p.identifier for p in prompts.applicable(answers)]
        self.assertIn("managed_interface", applicable)
        self.assertNotIn("managed_ipv4_cidr", applicable)

    def test_controller_with_network_services_is_asked_all_four(self):
        answers = {"profile": "controller", "network_services": "yes"}
        applicable = [p.identifier for p in prompts.applicable(answers)]
        for field in ("managed_ipv4_cidr", "controller_ipv4_address",
                      "dhcp_pool_start", "dhcp_pool_end"):
            self.assertIn(field, applicable)


class TestValidators(unittest.TestCase):
    def test_profile_accepts_only_known_profiles(self):
        self.assertEqual(prompts.validate_profile(" Controller ", {}), "controller")
        with self.assertRaises(AnswerError):
            prompts.validate_profile("server", {})

    def test_hostname_rejects_a_fully_qualified_name(self):
        with self.assertRaisesRegex(AnswerError, "short hostname"):
            prompts.validate_hostname("polycarp.home.arpa", {})

    def test_hostname_rejects_leading_and_trailing_hyphens(self):
        for bad in ("-lab", "lab-", "lab_1", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(AnswerError):
                    prompts.validate_hostname(bad, {})

    def test_hostname_normalises_case(self):
        self.assertEqual(prompts.validate_hostname("Polycarp", {}), "polycarp")

    def test_yes_no(self):
        self.assertEqual(prompts.validate_yes_no("Y", {}), "yes")
        self.assertEqual(prompts.validate_yes_no("no", {}), "no")
        with self.assertRaises(AnswerError):
            prompts.validate_yes_no("maybe", {})

    def test_network_field_rejects_a_cidr_with_host_bits(self):
        prompt = prompts.BY_IDENTIFIER["managed_ipv4_cidr"]
        with self.assertRaisesRegex(AnswerError, "host bits set"):
            prompt.validate("10.0.7.5/24", {})

    def test_network_field_accepts_a_good_value(self):
        prompt = prompts.BY_IDENTIFIER["managed_ipv4_cidr"]
        self.assertEqual(prompt.validate(" 10.0.7.0/24 ", {}), "10.0.7.0/24")

    def test_network_field_judges_against_answers_already_given(self):
        # With no subnet answered yet, any syntactically valid address passes.
        prompt = prompts.BY_IDENTIFIER["controller_ipv4_address"]
        self.assertEqual(prompt.validate("192.168.9.2", {}), "192.168.9.2")

    def test_network_field_uses_the_subnet_once_it_is_known(self):
        prompt = prompts.BY_IDENTIFIER["controller_ipv4_address"]
        answers = {"managed_ipv4_cidr": "10.0.7.0/24"}
        self.assertEqual(prompt.validate("10.0.7.2", answers), "10.0.7.2")
        with self.assertRaisesRegex(AnswerError, "not inside"):
            prompt.validate("192.168.9.2", answers)

    def test_network_field_catches_a_controller_inside_the_pool(self):
        # The rule that matters most, reported at the prompt that broke it.
        prompt = prompts.BY_IDENTIFIER["dhcp_pool_end"]
        answers = {"managed_ipv4_cidr": "10.0.7.0/24",
                   "controller_ipv4_address": "10.0.7.150",
                   "dhcp_pool_start": "10.0.7.100"}
        with self.assertRaisesRegex(AnswerError, "DHCP pool"):
            prompt.validate("10.0.7.200", answers)


class TestConfirmation(unittest.TestCase):
    SERIAL = "S4EWNX0T123456A"

    def test_accepts_the_exact_serial(self):
        self.assertTrue(prompts.confirm_disk_serial(self.SERIAL, self.SERIAL))

    def test_forgives_case_and_surrounding_space(self):
        self.assertTrue(prompts.confirm_disk_serial(
            f"  {self.SERIAL.lower()}  ", self.SERIAL))

    def test_rejects_yes(self):
        # The entire point of ADR 0058's serial confirmation.
        for reflex in ("y", "yes", "Y", "YES", "ok"):
            with self.subTest(reflex=reflex):
                self.assertFalse(prompts.confirm_disk_serial(reflex, self.SERIAL))

    def test_rejects_empty_and_whitespace(self):
        for blank in ("", "   ", "\n"):
            with self.subTest(blank=blank):
                self.assertFalse(prompts.confirm_disk_serial(blank, self.SERIAL))

    def test_rejects_a_near_miss(self):
        self.assertFalse(prompts.confirm_disk_serial(self.SERIAL[:-1], self.SERIAL))
        self.assertFalse(prompts.confirm_disk_serial(self.SERIAL + "B", self.SERIAL))

    def test_rejects_internal_whitespace(self):
        # Only leading and trailing space is forgiven.
        spaced = self.SERIAL[:4] + " " + self.SERIAL[4:]
        self.assertFalse(prompts.confirm_disk_serial(spaced, self.SERIAL))

    def test_a_disk_with_no_serial_cannot_be_confirmed(self):
        # If the serial could not be read, no typed string should authorize the
        # wipe -- including the empty string.
        for typed in ("", "unknown", "none"):
            with self.subTest(typed=typed):
                self.assertFalse(prompts.confirm_disk_serial(typed, ""))


class TestNoUnattendedPath(unittest.TestCase):
    """ADR 0058: there must be nothing that skips a prompt."""

    def test_registry_exposes_no_skip_or_default_mechanism(self):
        for prompt in prompts.PROMPTS:
            with self.subTest(prompt=prompt.identifier):
                self.assertFalse(hasattr(prompt, "default"))
                self.assertFalse(hasattr(prompt, "skip"))

    def test_module_defines_no_unattended_entry_point(self):
        source = (Path(__file__).resolve().parents[1] / "lib/prompts.py").read_text()
        for forbidden in ("--unattended", "answers_file", "autoinstall", "noconfirm"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
