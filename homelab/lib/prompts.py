"""The installer's prompt registry --- one source of truth.

ADR 0058 says there is no unattended installation path. The acceptance matrix
drives the genuine interactive installer through a pseudo-terminal, which only
works if the installer and the harness agree exactly on what is being asked.

They agree by both importing this module. The installer renders these prompts;
the harness looks them up by identifier to know what to answer. Changing a
prompt's wording therefore cannot desynchronize the tests, because there is only
one copy of the wording.

A prompt is deliberately more than a string. It carries its own validator, so
the rule that a Controller address must sit outside the DHCP pool lives next to
the question that asks for it rather than three files away.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

import netplan


class AnswerError(ValueError):
    """A rejected answer. The message is shown to the operator verbatim."""


@dataclass(frozen=True)
class Prompt:
    """One question, its wording, and the rule its answer must satisfy."""

    identifier: str
    text: str
    help_text: str
    # (value, answers-so-far) -> normalised value. Passing the prior answers is
    # what lets a cross-field rule -- "outside the pool", "inside the subnet" --
    # be reported at the prompt that broke it rather than at the summary.
    validate: Callable[[str, dict], str]
    # Prompts that only apply in some configurations, e.g. the network plan is
    # not collected when the Controller will not own DHCP and DNS.
    applies_when: Callable[[dict], bool] = lambda answers: True

    def render(self) -> str:
        return f"{self.text}: "


# --------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------

PROFILES = ("controller", "workstation")

# RFC 1123: letters, digits and hyphens; not starting or ending with a hyphen.
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def validate_profile(value: str, answers: dict | None = None) -> str:
    text = value.strip().lower()
    if text not in PROFILES:
        raise AnswerError(f"choose one of: {', '.join(PROFILES)}")
    return text


def validate_hostname(value: str, answers: dict | None = None) -> str:
    text = value.strip().lower()
    if not text:
        raise AnswerError("a hostname is required")
    if "." in text:
        raise AnswerError(
            "enter the short hostname only; the domain is always home.arpa (ADR 0005)"
        )
    if not _HOSTNAME_RE.match(text):
        raise AnswerError(
            "use letters, digits and hyphens only, not starting or ending with a hyphen"
        )
    return text


def validate_yes_no(value: str, answers: dict | None = None) -> str:
    text = value.strip().lower()
    if text in ("y", "yes"):
        return "yes"
    if text in ("n", "no"):
        return "no"
    raise AnswerError("answer yes or no")


def _network_field(field: str) -> Callable[[str, dict], str]:
    """Validate one network input against the answers already given.

    An earlier version probed netplan.build_plan with placeholder values for the
    unanswered fields, which produced errors about the placeholders rather than
    about the operator's answer -- "192.168.9.2 is not inside 10.0.0.0/24" when
    10.0.0.0/24 was never entered by anybody. So instead this checks only rules
    whose inputs are actually known.

    The prompts are asked in order, so by the time the Controller address is
    requested the subnet is known and the rule can be enforced immediately. Every
    rule is checked again as a set by build_plan before the summary; this exists
    so the operator fixes a mistake at the prompt that caused it.
    """
    def validate(value: str, answers: dict) -> str:
        text = value.strip()
        known = {name: answers[name] for name in netplan.INPUT_FIELDS
                 if answers.get(name)}
        known[field] = text

        # 1. Syntax, always checkable on its own.
        try:
            if field == "managed_ipv4_cidr":
                network = netplan._parse_network(text, field)
                if network.prefixlen >= 31:
                    raise netplan.NetworkPlanError(
                        f"{field}: /{network.prefixlen} leaves no room for a "
                        "Controller and a pool; use /30 or larger")
            else:
                netplan._parse_address(text, field)
        except netplan.NetworkPlanError as error:
            raise AnswerError(str(error).split(": ", 1)[1]) from None

        # 2. Cross-field rules, only where every input they need is known.
        try:
            if len(known) == len(netplan.INPUT_FIELDS):
                netplan.build_plan(known)
            elif field != "managed_ipv4_cidr" and "managed_ipv4_cidr" in known:
                # Only the rule whose inputs are genuinely known: is this a
                # usable host address in the subnet already entered. Building a
                # whole plan here would require inventing the pool, and an
                # invented pool produces errors about values nobody typed.
                netplan.check_usable_address(text, known["managed_ipv4_cidr"], field)
        except netplan.NetworkPlanError as error:
            message = str(error)
            head, _, detail = message.partition(": ")
            raise AnswerError(detail if head in netplan.INPUT_FIELDS else message) from None
        return text
    return validate


def wants_network_services(answers: dict) -> bool:
    return (answers.get("profile") == "controller"
            and answers.get("network_services") == "yes")


# --------------------------------------------------------------------------
# The registry, in the order the installer asks
# --------------------------------------------------------------------------

PROMPTS: tuple[Prompt, ...] = (
    Prompt(
        "profile",
        "Profile to install",
        "controller = infrastructure host; workstation = user machine. "
        "Selecting a profile authorizes nothing on its own (ADR 0004).",
        validate_profile,
    ),
    Prompt(
        "hostname",
        "Hostname (short, no domain)",
        "The machine's own name. Its fully qualified name is always "
        "<hostname>.home.arpa (ADR 0005).",
        validate_hostname,
    ),
    Prompt(
        "target_disk",
        "Target disk (enter the number from the list above)",
        "The disk that will be COMPLETELY ERASED. Chosen from the enumerated "
        "list by number, never by /dev/sdX, which is not stable across boots.",
        lambda value, answers: value.strip(),
    ),
    Prompt(
        "managed_interface",
        "Managed network interface (enter the number from the list above)",
        "The one interface this Controller will serve DHCP and DNS on. It is "
        "pinned by permanent MAC address to the stable name lan0 (ADR 0050). "
        "There is no default.",
        lambda value, answers: value.strip(),
        applies_when=lambda answers: answers.get("profile") == "controller",
    ),
    Prompt(
        "network_services",
        "Should this Controller own DHCP and DNS for its network? (yes/no)",
        "yes = this machine becomes the sole DHCP authority and the DNS "
        "endpoint on its segment. no = external infrastructure owns them and "
        "the services stay stopped (ADR 0008, ADR 0012).",
        validate_yes_no,
        applies_when=lambda answers: answers.get("profile") == "controller",
    ),
    Prompt(
        "managed_ipv4_cidr",
        "Managed subnet, as network address and prefix",
        "For example 10.0.7.0/24. Enter the network address itself, not an "
        "address inside it. The netmask, broadcast and DNS server are derived, "
        "never asked for (ADR 0045).",
        _network_field("managed_ipv4_cidr"),
        applies_when=wants_network_services,
    ),
    Prompt(
        "controller_ipv4_address",
        "Controller static address",
        "This machine's own address, and the DNS server every client will be "
        "told to use. It must sit outside the DHCP pool.",
        _network_field("controller_ipv4_address"),
        applies_when=wants_network_services,
    ),
    Prompt(
        "dhcp_pool_start",
        "DHCP pool, first address",
        "The lowest address dnsmasq may lease.",
        _network_field("dhcp_pool_start"),
        applies_when=wants_network_services,
    ),
    Prompt(
        "dhcp_pool_end",
        "DHCP pool, last address",
        "The highest address dnsmasq may lease, inclusive.",
        _network_field("dhcp_pool_end"),
        applies_when=wants_network_services,
    ),
)

BY_IDENTIFIER = {prompt.identifier: prompt for prompt in PROMPTS}

# The final confirmation is not in the registry above because it is not a
# question about configuration. It is the authorization boundary, and it is
# asked only after the complete summary has been displayed.
CONFIRMATION_TEXT = "Type the target disk's serial number to authorize erasing it"
CONFIRMATION_HELP = (
    "Not 'yes'. The serial cannot be typed from muscle memory and cannot be "
    "answered correctly by someone who has not read the summary above "
    "(ADR 0004, ADR 0058)."
)
ABORT_MESSAGE = "Authorization not given. Nothing has been written to any disk."


def applicable(answers: dict) -> list[Prompt]:
    """The prompts that apply given the answers collected so far."""
    return [prompt for prompt in PROMPTS if prompt.applies_when(answers)]


def confirm_disk_serial(typed: str, expected_serial: str) -> bool:
    """Compare a typed confirmation against the target disk's serial.

    Whitespace and case are forgiven because a serial read off a label under
    poor light is easy to mistype in those ways and hard to mistype in any
    other. Nothing else is forgiven.

    A disk whose serial could not be read cannot be confirmed at all. Otherwise
    an empty expected serial would match an empty answer, and pressing Enter
    would authorize erasing a disk the installer could not even identify.
    """
    expected = (expected_serial or "").strip()
    if not expected:
        return False
    return typed.strip().casefold() == expected.casefold()
