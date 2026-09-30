"""Pin the identity-roster overlay for unit tests, so none reads the real one.

HANDOFF section 5: no unit test may read ``homelab/instance/``.  Called with
no path, ``arch_second.identity_roster`` resolves the owner's gitignored
private overlay at ``identity_overlay_path()``, and so does everything that
reaches it that way: ``render_installer`` and ``arch_identity_run``'s lazily
resolved roster.  A test that reaches the default loader therefore runs
inside ``pinned_identity_overlay``, which points it at a private temporary
path -- nothing there (the synthetic acceptance roster) or a synthetic overlay
the test wrote -- and the result no longer depends on which host runs it.

``arch_second`` is imported under several module names (``arch_second`` by
path, ``workstations.arch_second``, ``homelab.workstations.arch_second``), each
a separate module object with its own globals, so every loaded copy is
patched; a copy is recognised by its source file, not by its name.

``controller_principals`` still resolves its roster at import, so its
``POSIX_ALLOCATION`` holds whatever overlay the process saw first.
``arch_identity_run`` reads that allocation at call time for the pinned
operator, so each loaded copy's allocation is re-derived from the pinned
declaration, exactly as the module derives its own (additional standard users
dropped).  A test whose code under test imports ``controller_principals``
lazily imports it BEFORE pinning, so the copy is loaded and patched rather
than first imported, frozen to the pinned roster, and left that way for every
later test module in the process.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import sys
import tempfile
from pathlib import Path
from typing import Iterator, Mapping
from unittest import mock

HOMELAB = Path(__file__).resolve().parents[1]
_ARCH_SECOND = HOMELAB / "workstations" / "arch_second.py"
_CONTROLLER_PRINCIPALS = HOMELAB / "vm" / "controller_principals.py"
_ARCH_IDENTITY_RUN = HOMELAB / "vm" / "arch_identity_run.py"


def _loaded_copies(source: Path) -> list:
    """Every loaded module object whose source file is *source*."""
    copies = []
    for module in list(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if (filename and filename.endswith(source.name)
                and Path(filename).resolve() == source):
            copies.append(module)
    return copies


def overlay_document(
    names: Mapping[str, str],
    uid_numbers: Mapping[str, int] | None = None,
) -> dict:
    """A schema-1 overlay naming *names* (``{contract role: name}``)."""
    principals: dict[str, dict] = {
        role: {"name": name} for role, name in names.items()}
    for role, uid in (uid_numbers or {}).items():
        principals.setdefault(role, {})["uid_number"] = uid
    return {"schema_version": 1, "principals": principals}


@contextlib.contextmanager
def pinned_identity_overlay(
    document: Mapping | None = None,
) -> Iterator[Path]:
    """Resolve every default-path roster from a private temporary overlay.

    *document* ``None`` means no overlay at all: the path does not exist, so
    the loader answers the synthetic acceptance roster.  Otherwise it is
    written as the overlay (``overlay_document`` builds one).  Yields the
    overlay path, which a test may pass to the loader explicitly to compute
    what it expects.
    """
    # Imported for the canonical copy's sake: the modules under test reach
    # ``homelab.workstations.arch_second`` by that name.
    import homelab.workstations.arch_second  # noqa: F401

    with contextlib.ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(
            prefix="telos-identity-overlay-pin-")))
        overlay = root / "identity" / "principals.json"
        if document is not None:
            overlay.parent.mkdir()
            overlay.write_text(json.dumps(document), encoding="utf-8")
        for module in _loaded_copies(_ARCH_SECOND):
            stack.enter_context(mock.patch.object(
                module, "identity_overlay_path", return_value=overlay))
        for module in _loaded_copies(_CONTROLLER_PRINCIPALS):
            try:
                declaration = module.identity_declaration(overlay)
            except module.IdentityRosterError:
                # An overlay the loader refuses stages nothing; the test is
                # proving that its code under test refuses it first.
                continue
            acceptance = dataclasses.replace(
                declaration, additional_standard_users=())
            stack.enter_context(mock.patch.object(
                module, "POSIX_ALLOCATION",
                module._validated_posix_allocation(
                    module._posix_allocation(acceptance))))
        for module in _loaded_copies(_ARCH_IDENTITY_RUN):
            # Forget any earlier resolution on the way in AND out, so neither
            # this pin nor the one before it leaks into the next.
            module.resolved_roster.cache_clear()
            stack.callback(module.resolved_roster.cache_clear)
        yield overlay
