#!/usr/bin/env python3
"""Keep principal names out of the Windows guest scripts.

The Windows identity lane ships PowerShell into the guest on three discs: the
one-use join disc (TelosJoin.ps1 and TelosPostSubmitDiagnostic.ps1), the
one-use credential-action disc (TelosCredential.ps1) and the static control
disc (Invoke-TelosIdentityProbe.ps1).  A principal NAME written into one of
those scripts is a second roster.  It agrees with the real one only until the
owner's private overlay renames that principal; after that the guest refuses
or misjudges every account the host was told about, from inside Windows, over
a serial line, with nothing to say which side was wrong.  That is how the
probe's ``'operator@'`` and the diagnostic's ``-cne 'operator'`` would have
failed gate 6 the first time it ran against a seeded roster.

So names reach the guest from the host-derived roster by one of two routes,
and never from the script text:

* in the per-run document the host already writes beside the script
  (join.json, action.json; the join script copies the operator into the
  diagnostic's config.json), which the script validates without naming
  anyone (the join scripts check the account-name SHAPE); or
* for the control disc, which has no per-run document, by rendering a
  ``{{role}}`` placeholder into the staged copy at ISO build time
  (``render_guest_script``).

``audit_guest_script`` is the fail-closed static guard over the tracked
sources.  It lexes the PowerShell (comments, single- and double-quoted
strings, here-strings, ``$(...)`` subexpressions) and refuses:

* any UPN local part in a string literal (``'operator@' + $realm``,
  ``"someone@$realm"``), whatever the name -- a guest script never needs one,
  because the realm-qualified names arrive in documents or placeholders; and
* a synthetic contract name used as an account anywhere else: a whole string
  literal (``-cne 'operator'``, ``'student', ...``), after ``\\``, ``/`` or
  ``:`` (``$domain + '\\student'``), or as a bare word in code.

English prose that happens to contain the word ("daily operator local
Administrators ...") is not an account and is not refused.  The names the
roster currently resolves to are deliberately NOT guarded beyond the UPN
rule: an owner's short account name (initials such as ``mm`` or ``au``) would
collide with registry paths and time formats the scripts legitimately carry,
and refusing gate 6 for a valid roster is the failure this module exists to
remove.  Anything the lexer cannot account for -- non-ASCII text, an
unterminated string, comment or here-string, a placeholder in a script that
is never rendered -- is a refusal, never a pass.

The guard runs where each disc is built (windows_join_iso for the join
scripts, windows_control_iso for the probe), and
homelab/tests/test_windows_guest_principals.py sweeps every tracked guest
script, including the credential-action and progress scripts.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import Mapping

from .controller_principals import directory_principals, lazy_roster_attributes

# The contract that holds the synthetic acceptance names is read through the
# one roster module, imported by path for the reason controller_principals
# gives beside the same three lines.
_WORKSTATIONS = Path(__file__).resolve().parents[1] / "workstations"
if str(_WORKSTATIONS) not in sys.path:
    sys.path.insert(0, str(_WORKSTATIONS))
from arch_second import (  # noqa: E402
    CONTRACT_ROLES,
    DIRECTORY_ROLES,
    identity_contract_path,
)

# The directory principals are read from the roster at use, never bound at
# import: importing this module reads no file (controller_principals says why).
# The old attribute stays readable, resolved on access (PEP 562).
__getattr__ = lazy_roster_attributes(__name__, ("DIRECTORY_PRINCIPALS",))


class WindowsGuestPrincipalError(RuntimeError):
    """A guest script pins a principal, or its names cannot be rendered."""


# The roles a guest script may name through a placeholder: the directory
# principals.  local_rescue is a LOCAL Arch account and the Windows lane has
# no roster name for its own local account.
GUEST_ROLES = DIRECTORY_ROLES
# The one account-name shape every Windows guest script admits: lowercase,
# within the 20-character Active Directory sAMAccountName limit.  TelosJoin.ps1
# and TelosPostSubmitDiagnostic.ps1 validate the document's name against this
# same pattern, and the renderer refuses anything else, so a name the host can
# render is a name the guest will accept.
GUEST_NAME = re.compile(r"[a-z][a-z0-9-]{0,19}")
# ...spelled as the single-quoted, anchored PowerShell literal the scripts use.
GUEST_NAME_POWERSHELL = f"'^{GUEST_NAME.pattern}$'"
PLACEHOLDER = re.compile(r"\{\{([^{}\r\n]*)\}\}")

# A ``#`` opens a line comment only where a new token may start.  Elsewhere it
# is kept as code, which can only make the guard stricter.
_COMMENT_AFTER = frozenset(" \t\r\n;(){}|,=")
# Variable references are not principal names: ``$operator``,
# ``$script:operator``, ``${operator}`` and ``@operator`` splatting.
_VARIABLE = re.compile(
    r"\$(?:\{[^}]*\}|[A-Za-z0-9_:?]+)|@[A-Za-z_][A-Za-z0-9_]*")
_ACCOUNT_PREFIX = frozenset("\\/:")
# A literal UPN local part.  ``"$user@$realm"`` is a variable, not a literal,
# and a placeholder's ``}}@`` is rendered before it ships.
_UPN_LOCAL_PART = re.compile(
    r"(?<![A-Za-z0-9._$-])([A-Za-z0-9][A-Za-z0-9._-]*)@")


def contract_principals() -> dict[str, str]:
    """The synthetic acceptance names: the tracked contract, no overlay."""
    try:
        contract = json.loads(
            identity_contract_path().read_text(encoding="utf-8"))
        names = {
            role: contract["principals"][role]["name"]
            for role in CONTRACT_ROLES
        }
    except (OSError, UnicodeDecodeError, ValueError, KeyError,
            TypeError) as error:
        raise WindowsGuestPrincipalError(
            "the identity contract's principal names are unreadable"
        ) from error
    if any(type(name) is not str or not name for name in names.values()):
        raise WindowsGuestPrincipalError(
            "the identity contract's principal names are invalid")
    return names


def guest_roster() -> dict[str, str]:
    """The host-derived ``{role: name}`` the guest scripts must follow."""
    return dict(zip(GUEST_ROLES, directory_principals()))


def guarded_names() -> dict[str, str]:
    """The synthetic names no tracked guest script may use as an account.

    Keyed by casefolded name, valued by the role that owns it.  They are
    guarded whatever the overlay says: a pin of one is the regression that
    actually happens, and it has to fail with or without an overlay present,
    not only on the machine that has one.
    """
    return {
        name.casefold(): f"contract {role}"
        for role, name in contract_principals().items()
    }


def _lex_error(label: str, reason: str) -> WindowsGuestPrincipalError:
    return WindowsGuestPrincipalError(
        f"{label} cannot be audited for pinned principals: {reason}")


def _scan_code(
    source: str, index: int, strings: list[str], code: list[str],
    *, label: str, subexpression: bool,
) -> int:
    depth = 0
    length = len(source)
    while index < length:
        character = source[index]
        if source.startswith("<#", index):
            end = source.find("#>", index + 2)
            if end < 0:
                raise _lex_error(label, "unterminated block comment")
            index = end + 2
            code.append(" ")
            continue
        if character == "#" and (
                index == 0 or source[index - 1] in _COMMENT_AFTER):
            end = source.find("\n", index)
            index = length if end < 0 else end
            continue
        if source.startswith(("@'", '@"'), index):
            quote = source[index + 1]
            line_end = source.find("\n", index)
            if line_end < 0 or source[index + 2:line_end].strip(" \t\r"):
                raise _lex_error(label, "malformed here-string opener")
            close = source.find("\n" + quote + "@", line_end)
            if close < 0:
                raise _lex_error(label, "unterminated here-string")
            strings.append(source[line_end + 1:close])
            code.append(" ")
            index = close + 3
            continue
        if character == "'":
            cursor = index + 1
            body: list[str] = []
            while True:
                end = source.find("'", cursor)
                if end < 0:
                    raise _lex_error(label, "unterminated string")
                body.append(source[cursor:end])
                if not source.startswith("''", end):
                    break
                body.append("'")
                cursor = end + 2
            strings.append("".join(body))
            code.append(" ")
            index = end + 1
            continue
        if character == '"':
            cursor = index + 1
            body = []
            while True:
                if cursor >= length:
                    raise _lex_error(label, "unterminated string")
                current = source[cursor]
                if current == "`":
                    # An escape is a separator, so "a`nstudent" still
                    # exposes the name.
                    body.append(" ")
                    cursor += 2
                    continue
                if current == '"':
                    if source.startswith('""', cursor):
                        body.append('"')
                        cursor += 2
                        continue
                    break
                if source.startswith("$(", cursor):
                    body.append(" ")
                    cursor = _scan_code(
                        source, cursor + 2, strings, code,
                        label=label, subexpression=True)
                    continue
                body.append(current)
                cursor += 1
            strings.append("".join(body))
            code.append(" ")
            index = cursor + 1
            continue
        if subexpression:
            if character == "(":
                depth += 1
            elif character == ")":
                if depth == 0:
                    code.append(" ")
                    return index + 1
                depth -= 1
        code.append(character)
        index += 1
    if subexpression:
        raise _lex_error(label, "unterminated subexpression")
    return index


def _lex(source: str, label: str) -> tuple[list[str], str]:
    """Split PowerShell into string-literal bodies and comment-free code."""
    if not source.isascii():
        # Windows PowerShell reads a BOM-less script as the ANSI code page,
        # and it treats typographic quotes as quotes; neither is worth
        # modelling here.
        raise _lex_error(label, "non-ASCII text")
    strings: list[str] = []
    code: list[str] = []
    _scan_code(source, 0, strings, code, label=label, subexpression=False)
    return strings, "".join(code)


def principal_pins(
    source: str, names: Mapping[str, str], *, label: str = "script",
) -> list[str]:
    """Describe every pinned principal in *source*.

    *names* maps each casefolded guarded name to a short description of
    where it comes from.  Any literal UPN local part is a pin whatever its
    name; a guarded name is a pin in every other account shape.
    """
    if not names:
        raise WindowsGuestPrincipalError("no principal names to guard")
    alternation = "|".join(
        re.escape(name) for name in sorted(names, key=len, reverse=True))
    in_string = re.compile(
        rf"(?<![A-Za-z0-9_$-])(?:{alternation})(?![A-Za-z0-9_-])",
        re.IGNORECASE)
    # In code a hashtable key (``operator = ...``) and member access
    # (``$config.operator_name``) are field names, not accounts.
    in_code = re.compile(
        rf"(?<![A-Za-z0-9_.-])(?:{alternation})(?![A-Za-z0-9_-])"
        r"(?!\s*=(?!=))",
        re.IGNORECASE)
    strings, code = _lex(source, label)
    pins: list[str] = []
    for body in strings:
        excerpt = body if len(body) <= 60 else body[:57] + "..."
        for match in _UPN_LOCAL_PART.finditer(body):
            local = match.group(1)
            origin = names.get(local.casefold(), "a UPN local part")
            pins.append(
                f"{local!r} ({origin}) in string literal {excerpt!r}")
        for match in in_string.finditer(body):
            before = body[match.start() - 1] if match.start() else ""
            after = body[match.end():match.end() + 1]
            if after == "@":
                continue  # already reported as a UPN local part
            if (
                (before and before in _ACCOUNT_PREFIX)
                or body.strip().casefold() == match.group(0).casefold()
            ):
                pins.append(
                    f"{match.group(0)!r} ({names[match.group(0).casefold()]})"
                    f" in string literal {excerpt!r}")
    for match in in_code.finditer(_VARIABLE.sub(" ", code)):
        pins.append(
            f"{match.group(0)!r} ({names[match.group(0).casefold()]}) "
            "as a bare word")
    return pins


def audit_guest_script(
    source: str,
    *,
    label: str,
    placeholders: bool,
    names: Mapping[str, str] | None = None,
) -> frozenset[str]:
    """Refuse a guest script that pins a principal.

    Returns the roles the script names through placeholders.  *placeholders*
    says whether this script is rendered before it ships; a placeholder in a
    script that is not would reach the guest verbatim, so it is a refusal.
    """
    guarded = guarded_names() if names is None else {
        name.casefold(): source_name for name, source_name in names.items()
    }
    pins = principal_pins(source, guarded, label=label)
    if pins:
        raise WindowsGuestPrincipalError(
            f"{label} pins a principal name: {'; '.join(pins)}. Guest "
            "scripts take names from the host-derived roster (the per-run "
            "document, or a {{role}} placeholder rendered at ISO build "
            "time), never from their own text")
    roles = PLACEHOLDER.findall(source)
    if roles and not placeholders:
        raise WindowsGuestPrincipalError(
            f"{label} contains a principal placeholder but is shipped "
            "unrendered")
    if placeholders and source.count("{{") != len(roles):
        # A half-written placeholder would ship as literal text.
        raise WindowsGuestPrincipalError(
            f"{label} contains a malformed principal placeholder")
    unknown = sorted(set(roles) - set(GUEST_ROLES))
    if unknown:
        raise WindowsGuestPrincipalError(
            f"{label} names unknown principal role placeholder {unknown[0]!r}")
    return frozenset(roles)


def render_guest_script(source: str, roster: Mapping[str, str]) -> str:
    """Substitute each ``{{role}}`` with the roster's name for that role."""
    names = {role: roster.get(role) for role in GUEST_ROLES}
    if any(
        type(name) is not str or not GUEST_NAME.fullmatch(name)
        for name in names.values()
    ) or len(set(names.values())) != len(names):
        raise WindowsGuestPrincipalError(
            "the guest roster is not three distinct names the Windows guest "
            f"admits ({GUEST_NAME.pattern})")

    def substitute(match: re.Match[str]) -> str:
        role = match.group(1)
        if role not in names:
            raise WindowsGuestPrincipalError(
                f"unknown principal role placeholder {role!r}")
        return names[role]

    rendered = PLACEHOLDER.sub(substitute, source)
    if "{{" in rendered:
        raise WindowsGuestPrincipalError(
            "a malformed principal placeholder survived rendering")
    return rendered
