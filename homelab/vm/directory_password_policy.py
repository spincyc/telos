"""The password policy a persistent Controller's directory enforces.

Samba AD judges every password set or changed in its domain against the
domain's password settings.  The durable stages judge an owner-typed password
the same way on the host, before anything boots
(``controller_principals.directory_password_problem``), because inside the
Controller a refused password surfaces only after a full boot.  That host-side
judgement is honest only if it uses the settings the directory really holds,
so this module models them as one small value:

* ``SAMBA_DEFAULT`` -- what provisioning leaves: at least seven characters,
  complexity on (three character classes, not containing the account name),
  a one-day minimum age.  Every instance enforces it until an owner records
  otherwise, so an instance whose marker records no policy is judged exactly
  as before a policy could be recorded.
* a RECORDED policy -- one ``make homelab-factory-persistent-password-policy``
  set with ``samba-tool domain passwordsettings set``, read back with
  ``samba-tool domain passwordsettings show``, and wrote into the instance
  marker only when the read-back matched (``persistent_password_policy``).

A policy is the DOMAIN's: it applies to every account in that directory.

Standard library only: ``simulation_overlay`` validates the marker record with
it in both of that module's run modes, and ``controller_principals`` judges
with it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Mapping

#: Samba refuses a minimum length above 14 (``samba-tool domain
#: passwordsettings set``).  It accepts 0, "no minimum"; this repository does
#: not: every durable password has at least one character.
MIN_LENGTH_FLOOR = 1
MIN_LENGTH_CEILING = 14
#: Samba's own bound on the minimum password age, in days.
MIN_AGE_CEILING_DAYS = 998
#: Complexity on: at least this many character classes, and no account name.
COMPLEXITY_CLASSES = 3
DEFAULT_SOURCE = "the directory's default policy"


class DirectoryPasswordPolicyError(ValueError):
    """A requested policy, a Samba read-back or a marker record is unusable.

    Messages name the setting, never a password: none reaches this module.
    """


def _bounded(label: str, value: object, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DirectoryPasswordPolicyError(f"{label} is not a whole number")
    if not low <= value <= high:
        raise DirectoryPasswordPolicyError(
            f"{label} must be from {low} to {high}")
    return value


@dataclass(frozen=True)
class DirectoryPasswordPolicy:
    """The three settings a typed password is judged by, and whose they are.

    ``source`` names the policy in a refusal ("the directory's default
    policy", "rehearsal's recorded directory policy"); it is never compared
    when a read-back is checked (``rules``).
    """

    min_length: int = 7
    complexity: bool = True
    min_age_days: int = 1
    source: str = DEFAULT_SOURCE

    def __post_init__(self) -> None:
        _bounded("the minimum password length", self.min_length,
                 MIN_LENGTH_FLOOR, MIN_LENGTH_CEILING)
        if not isinstance(self.complexity, bool):
            raise DirectoryPasswordPolicyError(
                "password complexity is not on or off")
        _bounded("the minimum password age in days", self.min_age_days,
                 0, MIN_AGE_CEILING_DAYS)
        if not isinstance(self.source, str) or not self.source:
            raise DirectoryPasswordPolicyError("a policy must name its source")

    @property
    def rules(self) -> tuple[int, bool, int]:
        return (self.min_length, self.complexity, self.min_age_days)

    @property
    def recorded(self) -> bool:
        return self.source != DEFAULT_SOURCE

    @property
    def relaxed(self) -> bool:
        """Weaker than Samba's default in length or complexity."""
        return (self.min_length < SAMBA_DEFAULT.min_length
                or (SAMBA_DEFAULT.complexity and not self.complexity))

    def describe(self) -> str:
        """The settings in words: ``minimum length 4, complexity off, ...``."""
        days = "day" if self.min_age_days == 1 else "days"
        return (f"minimum length {self.min_length}, complexity "
                f"{'on' if self.complexity else 'off'}, minimum age "
                f"{self.min_age_days} {days}")

    def requirement(self) -> str:
        """What a new password must be, as a plan line says it."""
        if self.complexity:
            return (f"at least {self.min_length} characters from "
                    f"{COMPLEXITY_CLASSES} classes, not containing the "
                    "account name")
        unit = "character" if self.min_length == 1 else "characters"
        return f"at least {self.min_length} {unit}; complexity off"

    def facts(self) -> dict[str, object]:
        """The settings alone, for a result document or a marker record."""
        return {"min_length": self.min_length, "complexity": self.complexity,
                "min_age_days": self.min_age_days}


SAMBA_DEFAULT = DirectoryPasswordPolicy()


def recorded_source(instance: str) -> str:
    return f"{instance}'s recorded directory policy"


def requested_policy(
    min_length: object, complexity: object, *, instance: str,
) -> DirectoryPasswordPolicy:
    """The policy an owner asked for, or a refusal naming the Make variable.

    A policy weaker than Samba's default also gets a minimum age of 0 days,
    so a password set under it can be changed again at once (the owner's
    "short now, change it later"); any other gets Samba's default of 1 day.
    """
    text = "" if min_length is None else str(min_length).strip()
    if not text:
        raise DirectoryPasswordPolicyError(
            "MIN_PASSWORD_LENGTH is required: a whole number from "
            f"{MIN_LENGTH_FLOOR} to {MIN_LENGTH_CEILING}")
    if not re.fullmatch(r"[0-9]{1,3}", text):
        raise DirectoryPasswordPolicyError(
            "MIN_PASSWORD_LENGTH must be a whole number from "
            f"{MIN_LENGTH_FLOOR} to {MIN_LENGTH_CEILING}")
    length = int(text)
    if not MIN_LENGTH_FLOOR <= length <= MIN_LENGTH_CEILING:
        raise DirectoryPasswordPolicyError(
            f"MIN_PASSWORD_LENGTH must be from {MIN_LENGTH_FLOOR} to "
            f"{MIN_LENGTH_CEILING} (Samba's maximum is {MIN_LENGTH_CEILING})")
    switch = "" if complexity is None else str(complexity).strip()
    if switch not in ("on", "off"):
        raise DirectoryPasswordPolicyError(
            "PASSWORD_COMPLEXITY is required and must be on or off")
    candidate = DirectoryPasswordPolicy(
        min_length=length, complexity=switch == "on",
        min_age_days=SAMBA_DEFAULT.min_age_days,
        source=recorded_source(instance))
    if candidate.relaxed:
        candidate = DirectoryPasswordPolicy(
            min_length=length, complexity=candidate.complexity,
            min_age_days=0, source=candidate.source)
    return candidate


# -- Samba's own words ------------------------------------------------------
#: ``samba-tool domain passwordsettings show`` labels, exactly as Samba prints
#: them, and the setting each one carries.
SHOW_LABELS = {
    "Password complexity": "complexity",
    "Minimum password length": "min_length",
    "Minimum password age (days)": "min_age_days",
}
#: The show output crosses the console as ONE line: its ``Label: value``
#: lines joined by this separator.  The header line, which carries the
#: domain's DN (instance data), is dropped on the guest.
SHOW_SEPARATOR = "|"
SHOW_COMMAND = (
    "/usr/bin/samba-tool domain passwordsettings show 2>/dev/null "
    "| /usr/bin/grep -E '^[A-Za-z][A-Za-z ()]*: [0-9A-Za-z-]+$' "
    f"| /usr/bin/paste -sd '{SHOW_SEPARATOR}' - "
    "| /usr/bin/grep . || echo NONE")
SHOW_VALUE = rb"[A-Za-z0-9 ():|-]{1,2048}"


def set_command(policy: DirectoryPasswordPolicy) -> str:
    """The one root command that applies *policy* to the directory."""
    return ("/usr/bin/samba-tool domain passwordsettings set "
            f"--min-pwd-length={int(policy.min_length)} "
            f"--complexity={'on' if policy.complexity else 'off'} "
            f"--min-pwd-age={int(policy.min_age_days)}")


def transported_show_text(value: bytes | str) -> str:
    """``SHOW_COMMAND``'s one console line, back as Samba's lines."""
    text = value.decode("ascii") if isinstance(value, bytes) else value
    return text.replace(SHOW_SEPARATOR, "\n")


def parse_passwordsettings_show(
    text: str, *, source: str = "the live directory",
) -> DirectoryPasswordPolicy:
    """The policy ``samba-tool domain passwordsettings show`` printed.

    Every other line (the header naming the domain, history, lockout, maximum
    age) is ignored; each of the three settings must appear exactly once.
    """
    found: dict[str, object] = {}
    for line in text.splitlines():
        label, separator, value = line.strip().partition(": ")
        field = SHOW_LABELS.get(label) if separator else None
        if field is None:
            continue
        if field in found:
            raise DirectoryPasswordPolicyError(
                f"passwordsettings show printed {label!r} twice")
        value = value.strip()
        if field == "complexity":
            if value not in ("on", "off"):
                raise DirectoryPasswordPolicyError(
                    f"passwordsettings show printed an unknown {label!r}")
            found[field] = value == "on"
        else:
            if not re.fullmatch(r"[0-9]{1,6}", value):
                raise DirectoryPasswordPolicyError(
                    f"passwordsettings show printed a non-numeric {label!r}")
            found[field] = int(value)
    missing = [label for label, field in SHOW_LABELS.items()
               if field not in found]
    if missing:
        raise DirectoryPasswordPolicyError(
            "passwordsettings show did not print " + ", ".join(missing))
    return DirectoryPasswordPolicy(
        min_length=found["min_length"], complexity=found["complexity"],
        min_age_days=found["min_age_days"], source=source)


# -- the instance marker ------------------------------------------------------
def policy_record(
    policy: DirectoryPasswordPolicy, *, run_id: str,
    now: str | None = None,
) -> dict[str, object]:
    """The marker record for a policy the directory was proven to hold."""
    return validated_record({
        **policy.facts(),
        "recorded_utc": now or datetime.now(UTC).isoformat(),
        "run_id": run_id,
        "proof": (
            "set with samba-tool domain passwordsettings set and read back "
            "with samba-tool domain passwordsettings show before this record "
            "was written"),
    })


def validated_record(record: object) -> dict:
    """Fail closed unless *record* is a usable recorded policy."""
    if not isinstance(record, dict):
        raise DirectoryPasswordPolicyError("the record is not an object")
    when = record.get("recorded_utc")
    if not isinstance(when, str) or not when:
        raise DirectoryPasswordPolicyError("the record has no recorded_utc")
    DirectoryPasswordPolicy(
        min_length=record.get("min_length"),
        complexity=record.get("complexity"),
        min_age_days=record.get("min_age_days"),
        source="a record")
    return record


def policy_from_record(
    record: Mapping | None, instance: str,
) -> DirectoryPasswordPolicy:
    """The recorded policy of *instance*, or Samba's default when none is."""
    if record is None:
        return SAMBA_DEFAULT
    validated_record(dict(record))
    return DirectoryPasswordPolicy(
        min_length=record["min_length"], complexity=record["complexity"],
        min_age_days=record["min_age_days"],
        source=recorded_source(instance))


def instance_policy(target: object) -> DirectoryPasswordPolicy:
    """``policy_from_record`` for a ``PersistentControllerInstance``."""
    name = getattr(target, "instance", None) or target.state.name
    return policy_from_record(target.directory_password_policy(), name)
