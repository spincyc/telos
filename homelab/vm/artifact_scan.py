#!/usr/bin/env python3
"""Scan a publishable artifact tree for the content gate 12 forbids.

``factory_verify._check_artifact_scan`` (check 15,
``no_forbidden_artifact_content``) reads one measurement field,
``artifact_scan``, shaped ``{"media": int, "credentials": int, "private": int,
"oversized": int}``, and passes only when all four counters are zero.  It
defines the shape and nothing else: no runner in this repository produces the
field, and until this module there was no scanner either
(``factory_runner.retain_evidence``'s docstring, ``arch_install_run``,
``windows_install_run`` and ``dualboot_acceptance`` all say so).  So this
module both states the criteria and implements them, which is why every rule
below is conservative, explicit, and carries the evidence it was drawn from.

This module is pure: it reads the tree it is pointed at and returns counters
and findings.  It never writes, mutates, opens a socket, boots anything, or
returns an absolute path, a matched secret, or a real hostname.  Importing it
does no work at all -- the leak rules it borrows are loaded on first use.

What the counters count
-----------------------
One finding is one ``(relative path, category, rule)`` triple, and the counter
for a category is the number of findings in it.  A file may be reported in more
than one category (an installation ISO is both ``media`` and ``oversized``), and
a repeated match of the same rule in one file counts once, so the counters
measure *reasons*, not bytes.  ``scan_artifacts`` returns the counters, which
are all check 15 consumes; ``scan_tree``/``scan_paths`` return the findings
beside them, which are what makes a non-zero counter diagnosable.

The categories
--------------
``oversized``
    ``size > SIZE_LIMIT``, where ``SIZE_LIMIT`` is imported from
    ``factory_verify.EVIDENCE_LIMIT`` (1 MiB) rather than restated, so the two
    modules can never drift.  That is the per-file bound the retained-evidence
    contract already lives by (``factory_runner`` truncates every retained log
    to it; ``factory_verify`` refuses to parse anything above it), and a
    publishable artifact has no claim to be larger than the evidence a whole
    factory run is allowed to keep.

``media``
    Installation media or another large binary payload.  The suffix set is
    the one this repository already uses to keep media out of Git
    (``tests/test_publication_sizes.INSTALLATION_MEDIA_SUFFIXES``), widened by
    the container formats an artifact could carry.  That gate decides on the
    suffix alone because it scans *tracked* files, where no legitimate file
    wears one; a staged artifact is not tracked, so here the decision is by
    *content-bearing extension or content magic* AND size, never by extension
    alone: a suffix from ``MEDIA_SUFFIXES`` or a header from ``MEDIA_MAGIC``
    (ISO 9660's ``CD001`` descriptor, qcow, WIM, VHD/VHDX, VMDK, VDI,
    SquashFS), together with ``size > MEDIA_MIN_BYTES``.  ``MEDIA_MIN_BYTES``
    is ``SIZE_LIMIT``: the smallest real installation medium this project
    handles is three orders of magnitude above it, while a hand-written
    ``notes.img`` of a few kilobytes is not a payload, so the threshold that
    separates them is exactly the one the evidence contract already draws.
    Consequently every ``media`` finding is also an ``oversized`` finding.  The
    redundancy is deliberate and costs nothing -- check 15 requires both to be
    zero -- and it buys the diagnosis: ``oversized`` says the file is too big,
    ``media`` says what it is.  A *small* credential-bearing ISO is not media
    and is not meant to be; it is ``credentials`` (below).

``credentials``
    Credential material.  Four rules, in order of confidence:
      * a known secret the caller supplies, counted by ``secret_scan``
        (``count_secret_occurrences`` over ``secret_needles``), which is the
        repository's existing scanner and already covers UTF-16 encodings and
        one layer of Base64 wrapping.  No parallel matcher is written here.
      * a credential-shaped name: a private-key or keystore suffix, a
        well-known credential filename, a stem carrying ``password`` /
        ``secret`` / ``credential`` / ``keytab``, or a credential-bearing image
        this project actually builds -- ``publication.iso`` (it carries
        ``install-password.txt`` and ``Autounattend.xml``; see
        ``windows_install_prepare.prepare`` and
        ``factory_publication.PRIVATE_WINDOWS_FILES``), ``control.iso``,
        ``credential-action.iso``, and any ``recovery``/``unlock`` image.
      * a private-key or keystore header in the file's first bytes (PEM
        ``BEGIN ... PRIVATE KEY``, PuTTY, KeePass), so a renamed key is still
        caught.
      * a labelled credential token in text, using ``factory_verify``'s own
        ``_CREDENTIAL`` pattern -- the single rule this repository has for
        "a credential value that survived redaction", tuned against real
        retained evidence, and matched to ``factory_runner._redact`` so that
        properly redacted text passes.  It is imported, never restated; if it
        ever disappears the scan reports a rule defect rather than a pass.

``private``
    Content from the gitignored private overlay (``/homelab/instance/`` in
    ``.gitignore``; ADR 0046) that must never be published: real addresses,
    MACs, disk serials, NAS hostnames.  The rules are ``scripts/site``'s
    instance-leak rules -- ``INSTANCE_CODE_PATTERNS`` judged against
    ``INSTANCE_SANCTIONED``, plus its NAS-hostname rule -- loaded from that
    file rather than copied, so the gate that already rejects the lab address
    from published pages and the gate that rejects it from a published artifact
    cannot disagree.  Its *reporting* is not reused: the site gate quotes the
    matched token into its message, and a finding here must never carry the
    match.  The sanctioned synthetic ranges are honoured, because a factory
    artifact legitimately names the simulated fabric.  Also private: a path
    inside the artifact that comes from the overlay (``homelab/instance/...``),
    and any entry that is not a regular file -- a symlink, device node, FIFO or
    socket exposes a reference to the host rather than content of its own, and
    is never publishable.

Failing closed
--------------
The scan never returns zeros it did not earn:
  * an unstattable path counts in all four categories (``unreadable``);
  * a readable-by-``stat`` file whose bytes cannot be read counts in ``media``,
    ``credentials`` and ``private`` (``oversized`` was already decided);
  * a file whose content was not inspected -- a binary matching no known
    benign type -- counts in ``credentials`` and ``private``
    (``content-not-inspectable``), because those are exactly the two rules that
    could not be evaluated;
  * a rule that cannot be loaded at all (a missing ``scripts/site``, a
    ``factory_verify`` without its credential pattern) yields a finding against
    the pseudo-path ``<scan>`` in the affected category, so the counter is
    non-zero and the gate fails rather than passing on an unrun rule.

The one place inspection is skipped without a fresh finding is a file already
counted as ``oversized``: it is reported, its remediation (do not publish it)
is unambiguous, and adding ``credentials``/``private`` findings for it would
assert leaks that were never observed.  This is also what keeps the scan
bounded -- see below.

Benign binaries whose content is not inspected (``BENIGN_MAGIC``: PNG, JPEG,
GIF, WebP, ICO, PDF, and the web font formats) are the deliberate residual
gap.  A PNG text chunk or a compressed PDF stream could carry a private value
this scan would not see; the compensating control is that this project's
published binaries are built from tracked sources, and ``scripts/site``'s gate
scans those sources.  Widening the allowlist widens that gap.

Bounded by construction
-----------------------
The tree this may be pointed at holds multi-gigabyte bundles, so nothing is
ever read whole beyond ``SIZE_LIMIT``: sizes come from ``stat``, a file within
the limit is read entirely (it is at most 1 MiB), and a file above it is
already a finding, so only its first ``HEADER_BYTES`` and the ISO 9660
descriptor window are read -- enough to name the payload, never enough to
stream a 241 GB image.  Reads use ``O_NOFOLLOW`` (as
``factory_verify._safe_regular_bytes`` and ``factory_measurements`` do), so a
symlink planted in a tree cannot redirect one.

Scope
-----
Point this at the tree that is about to be published, or hand ``scan_paths``
an explicit path list (``git ls-files`` for a tracked-content scan).  Do not
point it at a run bundle's working trees or at a sealed release set, where a
large payload is legitimate and ``factory_verify`` deliberately does not apply
the size limit either.
"""

from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Iterable, NamedTuple, Sequence

try:
    from homelab.vm import factory_verify, secret_scan
except ModuleNotFoundError as error:  # imported as a bare module by the tests
    if error.name not in ("homelab", "homelab.vm"):
        raise
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import factory_verify  # type: ignore[no-redef]
    import secret_scan  # type: ignore[no-redef]


SCHEMA = 1

#: The four counters ``factory_verify._check_artifact_scan`` requires.
CATEGORIES = ("media", "credentials", "private", "oversized")

#: Taken from the verifier, never restated: one limit, one definition.
SIZE_LIMIT = factory_verify.EVIDENCE_LIMIT
#: A payload is media only above the same limit (see the module docstring).
MEDIA_MIN_BYTES = SIZE_LIMIT
#: How much of an already-oversized file is sampled to classify it.
HEADER_BYTES = 4096

#: The pseudo-path a scan-wide rule defect is reported against.
SCAN_PATH = "<scan>"

RULE_UNREADABLE = "unreadable"
RULE_SYMLINK = "symlink"
RULE_NOT_REGULAR = "not-a-regular-file"
RULE_NOT_INSPECTABLE = "content-not-inspectable"
RULE_OVERSIZED = "exceeds-evidence-size-limit"

# A superset of tests/test_publication_sizes.INSTALLATION_MEDIA_SUFFIXES, which
# is this repository's existing statement of what installation media looks like.
MEDIA_SUFFIXES = frozenset({
    ".iso", ".img", ".raw", ".wim", ".swm", ".esd", ".qcow", ".qcow2",
    ".vhd", ".vhdx", ".vmdk", ".vdi", ".dmg", ".squashfs", ".sfs", ".erofs",
})

# (offset, magic, rule).  Each is a documented file-format signature; none is
# short enough to collide by accident at the offset it is checked at.
_ISO_DESCRIPTOR = 32769  # 0x8001: ISO 9660 primary volume descriptor
MEDIA_MAGIC = (
    (0, b"QFI\xfb", "media-magic-qcow"),
    (0, b"MSWIM\x00\x00\x00", "media-magic-wim"),
    (0, b"KDMV", "media-magic-vmdk"),
    (0, b"vhdxfile", "media-magic-vhdx"),
    (0, b"conectix", "media-magic-vhd"),
    (0, b"<<< Oracle VM VirtualBox Disk Image >>>", "media-magic-vdi"),
    (0, b"hsqs", "media-magic-squashfs"),
    (0, b"sqsh", "media-magic-squashfs"),
    (_ISO_DESCRIPTOR, b"CD001", "media-magic-iso9660"),
)

CREDENTIAL_SUFFIXES = frozenset({
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".keytab", ".kdb",
    ".kdbx", ".ppk", ".gpg", ".pgp", ".asc",
})
CREDENTIAL_NAMES = frozenset({
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "krb5.keytab",
    "shadow", "gshadow", "netrc", ".netrc", "htpasswd", ".htpasswd",
    "install-password.txt", "autounattend.xml", "unattend.xml",
})
# Substrings of the stem.  Deliberately narrow: "key" alone matches "keyboard"
# and "monkey", and "recovery" alone matches a recovery *log*, so those are
# admitted only through the image rule below.
CREDENTIAL_STEM_TOKENS = (
    "password", "passwd", "passphrase", "secret", "credential", "keytab",
    "private-key", "private_key", "privatekey",
)
# Credential-bearing images this project actually builds or would build.  A
# small ISO is not "media"; if it carries credentials it is credentials.
CREDENTIAL_IMAGE_STEMS = frozenset({
    "publication", "control", "credential-action", "recovery", "unlock",
})
CREDENTIAL_IMAGE_SUFFIXES = frozenset({".iso", ".img"})

CREDENTIAL_MAGIC = (
    (b"PuTTY-User-Key-File", "credential-putty-private-key"),
    (b"\x03\xd9\xa2\x9a", "credential-keepass-database"),
)
_PEM_PRIVATE_KEY = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")

# Binary types whose content this scan does not inspect and does not count.
# See "Benign binaries" in the module docstring: this list is the residual gap.
BENIGN_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"\x00\x00\x01\x00", "ico"),
    (b"%PDF-", "pdf"),
    (b"wOFF", "woff"),
    (b"wOF2", "woff2"),
    (b"OTTO", "otf"),
    (b"\x00\x01\x00\x00\x00", "ttf"),
)

# The private overlay, as .gitignore names it.  A copy of an overlay file keeps
# its path inside a staged artifact, and that path alone is the disclosure.
_OVERLAY_PREFIXES = ("homelab/instance/", "instance/")


class Finding(NamedTuple):
    """One reason, free of the thing that caused it.

    ``path`` is relative to the scanned root (or ``SCAN_PATH`` for a scan-wide
    rule defect), ``category`` is one of ``CATEGORIES``, and ``rule`` names the
    rule that fired.  A finding never carries a matched secret, a real
    hostname, or an absolute host path -- the counters and the rule name are
    what a receipt may hold.
    """

    path: str
    category: str
    rule: str

    def as_dict(self) -> dict:
        return {"path": self.path, "category": self.category, "rule": self.rule}


class ScanResult(NamedTuple):
    """The gate-12 counters plus the findings that explain them."""

    counters: dict
    findings: tuple

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "kind": "artifact-scan",
            "artifact_scan": dict(self.counters),
            "findings": [finding.as_dict() for finding in self.findings],
        }

    @property
    def clean(self) -> bool:
        return not any(self.counters.values())


# --------------------------------------------------------------------------
# Borrowed rules
# --------------------------------------------------------------------------

_SITE_GATE = Path(__file__).resolve().parents[2] / "scripts" / "site"
_private_rules_cache: tuple | None = None


def _load_site_gate():
    """Load ``scripts/site`` by path, without registering it as ``site``.

    The gate is an extension-less script, so it cannot be imported normally,
    and the stdlib already owns the name ``site`` -- hence the explicit loader
    and the deliberate absence of a ``sys.modules`` entry.  The alternative,
    copying its patterns here, is what this avoids: two leak rules that drift
    apart is how a real value reaches a published artifact.
    """
    loader = importlib.machinery.SourceFileLoader(
        "telos_site_gate", str(_SITE_GATE))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _private_rules() -> tuple:
    """``(patterns, sanctioned)`` from the site gate, or ``None`` on failure.

    Loaded on first use so that importing this module does no work.  The
    pattern set is the site gate's *code* rules -- which are judged against its
    sanctioned synthetic ranges -- plus its NAS-hostname rule.  Its prose rules
    are not used: they forbid every address literal, and a factory artifact
    legitimately names the simulated fabric.
    """
    global _private_rules_cache
    if _private_rules_cache is None:
        try:
            gate = _load_site_gate()
            nas = tuple(
                rule for rule in gate.INSTANCE_LEAK_PATTERNS
                if rule not in gate.RFC1918_PATTERNS)
            patterns = tuple(gate.INSTANCE_CODE_PATTERNS) + nas
            sanctioned = gate.INSTANCE_SANCTIONED
            if not patterns or sanctioned is None:
                raise RuntimeError("site gate exposes no instance-leak rules")
            _private_rules_cache = ((patterns, sanctioned),)
        except Exception:  # fail closed: an unloadable rule is not a pass
            _private_rules_cache = (None,)
    return _private_rules_cache[0]


def _credential_token_pattern():
    """``factory_verify``'s credential-token rule, or ``None`` if it is gone."""
    return getattr(factory_verify, "_CREDENTIAL", None)


def _rule_defects() -> list:
    """A finding for every rule that could not be loaded at all."""
    defects = []
    if _credential_token_pattern() is None:
        defects.append(
            Finding(SCAN_PATH, "credentials", "credential-token-rule-unavailable"))
    if _private_rules() is None:
        defects.append(
            Finding(SCAN_PATH, "private", "instance-leak-rules-unavailable"))
    return defects


def _slug(description: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", description.lower())).strip("-")


# --------------------------------------------------------------------------
# Bounded reading
# --------------------------------------------------------------------------


def _sample(path: Path, want: int) -> tuple:
    """Read at most ``want`` head bytes plus the ISO descriptor window.

    Refuses to follow a final symlink and refuses anything that is not a
    regular file, exactly as ``factory_verify._safe_regular_bytes`` does.  The
    second read is a positioned read of five bytes, so classifying a 241 GB
    image costs two reads and no memory.
    """
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"{path.name} is not a regular file")
        head = bytearray()
        while len(head) < want:
            chunk = os.read(descriptor, want - len(head))
            if not chunk:
                break
            head.extend(chunk)
        window = b""
        if info.st_size >= _ISO_DESCRIPTOR + 5:
            window = os.pread(descriptor, 5, _ISO_DESCRIPTOR)
        return bytes(head), window
    finally:
        os.close(descriptor)


def _text(data: bytes) -> str | None:
    """Decode a whole small file as text, or ``None`` if it is not text.

    A byte-order mark is honoured because this project's Windows inputs are
    UTF-16 (``Autounattend.xml``), and an unrecognised UTF-16 file would
    otherwise be an uninspected binary.
    """
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except (UnicodeDecodeError, ValueError):
            return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


# --------------------------------------------------------------------------
# Per-category rules
# --------------------------------------------------------------------------


def _media_rule(suffix: str, head: bytes, window: bytes) -> str | None:
    """Name the media rule a file's *content shape* fires, size aside."""
    for offset, magic, rule in MEDIA_MAGIC:
        if offset == 0:
            if head.startswith(magic):
                return rule
        elif offset == _ISO_DESCRIPTOR and window == magic:
            return rule
    if suffix in MEDIA_SUFFIXES:
        return "media-suffix"
    return None


def _credential_name_rule(name: str, stem: str, suffix: str) -> str | None:
    if suffix in CREDENTIAL_SUFFIXES:
        return "credential-suffix"
    if name in CREDENTIAL_NAMES:
        return "credential-filename"
    if suffix in CREDENTIAL_IMAGE_SUFFIXES and stem in CREDENTIAL_IMAGE_STEMS:
        return "credential-bearing-image"
    for token in CREDENTIAL_STEM_TOKENS:
        if token in stem:
            return "credential-name-token"
    return None


def _credential_magic_rule(head: bytes) -> str | None:
    if _PEM_PRIVATE_KEY.search(head[:HEADER_BYTES]):
        return "credential-pem-private-key"
    for magic, rule in CREDENTIAL_MAGIC:
        if head.startswith(magic):
            return rule
    return None


def _benign_binary(head: bytes) -> str | None:
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    for magic, kind in BENIGN_MAGIC:
        if head.startswith(magic):
            return kind
    return None


def _overlay_path(relative: str) -> bool:
    lowered = relative.lower()
    return any(
        lowered.startswith(prefix) or f"/{prefix}" in lowered
        for prefix in _OVERLAY_PREFIXES)


def _private_text_rules(relative: str, text: str) -> list:
    """Every instance-leak rule the text fires, deduplicated, match-free."""
    rules = _private_rules()
    if rules is None:  # the defect is reported once, scan-wide
        return []
    patterns, sanctioned = rules
    seen: dict = {}
    for line in text.splitlines():
        for pattern, description in patterns:
            for match in pattern.finditer(line):
                if sanctioned is not None and sanctioned.match(match.group(0)):
                    continue
                # The description names the shape; the match itself is dropped
                # here and never reaches a finding.
                seen.setdefault(f"instance-leak-{_slug(description)}", None)
    return [Finding(relative, "private", rule) for rule in sorted(seen)]


# --------------------------------------------------------------------------
# The scan
# --------------------------------------------------------------------------


def _file_findings(root: Path, relative: str, needles: tuple) -> list:
    path = root.joinpath(relative)
    found: list = []
    try:
        info = path.lstat()
    except OSError:
        # Nothing at all could be evaluated, including the size.
        return [Finding(relative, category, RULE_UNREADABLE)
                for category in CATEGORIES]
    mode = info.st_mode
    if stat.S_ISLNK(mode):
        return [Finding(relative, "private", RULE_SYMLINK)]
    if not stat.S_ISREG(mode):
        return [Finding(relative, "private", RULE_NOT_REGULAR)]

    size = info.st_size
    oversized = size > SIZE_LIMIT
    if oversized:
        found.append(Finding(relative, "oversized", RULE_OVERSIZED))
    if _overlay_path(relative):
        found.append(Finding(relative, "private", "instance-overlay-path"))

    name = PurePosixPath(relative).name.lower()
    suffix = PurePosixPath(name).suffix
    stem = name[: len(name) - len(suffix)] if suffix else name
    name_rule = _credential_name_rule(name, stem, suffix)
    if name_rule is not None:
        found.append(Finding(relative, "credentials", name_rule))

    try:
        head, window = _sample(path, size if not oversized else HEADER_BYTES)
    except OSError:
        found.extend(
            Finding(relative, category, RULE_UNREADABLE)
            for category in ("media", "credentials", "private"))
        return found

    media_rule = _media_rule(suffix, head, window)
    if media_rule is not None and size > MEDIA_MIN_BYTES:
        found.append(Finding(relative, "media", media_rule))
    magic_rule = _credential_magic_rule(head)
    if magic_rule is not None:
        found.append(Finding(relative, "credentials", magic_rule))
    if needles and secret_scan.count_secret_occurrences([head], needles):
        found.append(Finding(relative, "credentials", "known-secret"))

    if oversized:
        # Already reported, and its remediation is unambiguous.  Streaming a
        # multi-gigabyte file to add findings it would not change is exactly
        # what this scan must not do.
        return found

    text = _text(head)
    if text is None:
        if _benign_binary(head) is None:
            found.append(Finding(relative, "credentials", RULE_NOT_INSPECTABLE))
            found.append(Finding(relative, "private", RULE_NOT_INSPECTABLE))
        return found

    token = _credential_token_pattern()
    if token is not None and token.search(text.encode("utf-8")):
        # The count is never reported and the match is never echoed.
        found.append(Finding(relative, "credentials", "credential-token"))
    found.extend(_private_text_rules(relative, text))
    return found


def _walk(root: Path) -> tuple:
    """Enumerate the tree deterministically without following any symlink.

    Returns the relative paths of every regular-file candidate plus the
    findings the walk itself produced (a symlinked directory is reported and
    pruned rather than descended).
    """
    relatives: list = []
    found: list = []
    for parent, directories, files in os.walk(root, followlinks=False):
        parent_path = Path(parent)
        kept = []
        for name in sorted(directories):
            if (parent_path / name).is_symlink():
                found.append(Finding(
                    _relative(root, parent_path / name), "private", RULE_SYMLINK))
                continue
            kept.append(name)
        directories[:] = kept
        for name in sorted(files):
            relatives.append(_relative(root, parent_path / name))
    return sorted(relatives), found


def _relative(root: Path, path: Path) -> str:
    """A root-relative POSIX path; an absolute host path is never emitted."""
    return path.relative_to(root).as_posix()


def _needles(known_secrets: Iterable) -> tuple:
    secrets = tuple(known_secrets)
    if not secrets:
        return ()
    return secret_scan.secret_needles(secrets)


def _result(findings: Iterable) -> ScanResult:
    unique = sorted(set(findings))
    counters = {category: 0 for category in CATEGORIES}
    for finding in unique:
        if finding.category not in counters:  # unreachable; fail closed anyway
            raise RuntimeError(f"unknown scan category: {finding.category}")
        counters[finding.category] += 1
    return ScanResult(counters, tuple(unique))


def scan_paths(root, relatives: Sequence, *, known_secrets: Iterable = ()) -> ScanResult:
    """Scan an explicit list of root-relative paths (e.g. ``git ls-files``).

    A listed path that is absent or unstattable is a finding in every category,
    never a silent skip.
    """
    root = Path(root)
    needles = _needles(known_secrets)
    findings = list(_rule_defects())
    for relative in sorted({PurePosixPath(item).as_posix() for item in relatives}):
        candidate = PurePosixPath(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            # A listed path that leaves the artifact is a caller defect, and
            # naming it in the finding would put a host path in a receipt.
            findings.append(Finding(SCAN_PATH, "private", "path-outside-artifact"))
            continue
        findings.extend(_file_findings(root, relative, needles))
    return _result(findings)


def scan_tree(root, *, known_secrets: Iterable = ()) -> ScanResult:
    """Scan a whole publishable tree, counters and findings together."""
    root = Path(root)
    needles = _needles(known_secrets)
    findings = list(_rule_defects())
    if root.is_symlink():
        return _result(findings + [Finding(".", "private", RULE_SYMLINK)])
    if not root.is_dir():
        # An artifact that is not there was not scanned, and an unscanned
        # artifact is never clean.
        return _result(
            findings + [Finding(".", category, RULE_UNREADABLE)
                        for category in CATEGORIES])
    relatives, walk_findings = _walk(root)
    findings.extend(walk_findings)
    for relative in relatives:
        findings.extend(_file_findings(root, relative, needles))
    return _result(findings)


def scan_artifacts(root, *, known_secrets: Iterable = ()) -> dict:
    """The gate-12 ``artifact_scan`` measurement: the four counters alone.

    All four are zero only when the tree was fully scanned and nothing fired,
    which is exactly what ``factory_verify``'s check 15 requires to pass.
    """
    return scan_tree(root, known_secrets=known_secrets).counters


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=(
        "Scan a publishable artifact tree for media, credential, private-"
        "overlay and oversized content (gate-12 measurement artifact_scan)."))
    result.add_argument("root", type=Path, help="the tree about to be published")
    result.add_argument(
        "--quiet", action="store_true",
        help="print the counters only, without the findings that explain them")
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    result = scan_tree(args.root)
    payload = (
        {"schema": SCHEMA, "kind": "artifact-scan",
         "artifact_scan": result.counters}
        if args.quiet else result.as_dict())
    print(json.dumps(payload, indent=2, sort_keys=True))
    if result.clean:
        print("PASS: artifact-scan found no forbidden content", file=sys.stderr)
        return 0
    print(
        "FAIL: artifact-scan " + " ".join(
            f"{name}={result.counters[name]}" for name in CATEGORIES),
        file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
