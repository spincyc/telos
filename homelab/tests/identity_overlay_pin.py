"""Pin the identity-roster overlay for unit tests, so none reads the real one.

It also pins the one ``build/`` path the persistent-instance tests reach by
default -- the reserved acceptance state (``pinned_acceptance_state``).

HANDOFF section 5: no unit test may read ``homelab/instance/``.  Called with
no path, ``arch_second.identity_roster`` resolves the owner's gitignored
private overlay at ``identity_overlay_path()``, and so does everything that
reaches it that way: ``render_installer``, ``arch_identity_run``'s lazily
resolved roster and ``controller_principals.acceptance_roster`` (which every
Windows-lane module reads at use).  A test that reaches the default loader
therefore runs inside ``pinned_identity_overlay``, which points it at a
private temporary path -- nothing there (the synthetic acceptance roster) or a
synthetic overlay the test wrote -- and the result no longer depends on which
host runs it.  A whole test module pins with ``setUpModule`` and
``unittest.enterModuleContext(pinned_identity_overlay())``; a module-level
constant read from the roster is read inside a ``with`` of the same pin.

``arch_second`` is imported under several module names (``arch_second`` by
path, ``workstations.arch_second``, ``homelab.workstations.arch_second``), each
a separate module object with its own globals, so every loaded copy is
patched; a copy is recognised by its source file, not by its name.

``arch_identity_run`` and ``controller_principals`` each cache one
resolution per process.  The pin forgets both on the way in AND out -- for
every copy loaded at either moment, so a copy first imported inside the pin is
forgotten too -- and neither this pin nor the one before it leaks into the
next.

One process is exempt from the no-overlay pin: the child that
``test_windows_identity_orchestrator.PrivateOverlayRegressionTests`` runs in a
COPIED checkout, marked by ``OVERLAY_CHECKOUT_MARKER`` and carrying no
``.git``.  That copy holds no lab state -- its only instance data is the
synthetic, every-role-renamed overlay the parent wrote -- and the child exists
to prove the Windows-lane suites follow exactly that overlay, so a pin asked
for no overlay leaves its default path alone there (caches are still
forgotten).  A pin given a document pins it everywhere.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Iterator, Mapping
from unittest import mock

HOMELAB = Path(__file__).resolve().parents[1]
#: Set by the overlay-regression test on the child it runs in a copied
#: checkout.  Honoured only where the checkout carries no ``.git``, which that
#: copy never does and the original working tree always does.
OVERLAY_CHECKOUT_MARKER = "TELOS_TEST_IDENTITY_OVERLAY_CHECKOUT"
_ARCH_SECOND = HOMELAB / "workstations" / "arch_second.py"
_CONTROLLER_PRINCIPALS = HOMELAB / "vm" / "controller_principals.py"
_ARCH_IDENTITY_RUN = HOMELAB / "vm" / "arch_identity_run.py"
_SIMULATION_OVERLAY = HOMELAB / "vm" / "simulation_overlay.py"
#: Each module's per-process roster cache, by the module's source file.
_ROSTER_CACHES = (
    (_CONTROLLER_PRINCIPALS, "acceptance_roster"),
    (_ARCH_IDENTITY_RUN, "resolved_roster"),
)


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
    # ``homelab.workstations.arch_second`` by that name.  controller_principals
    # (which reads nothing at import) loads the by-path ``arch_second`` copy
    # it and the Windows lane resolve through, so that copy is patched below
    # even when a test's first use of the roster comes inside this pin.
    import homelab.workstations.arch_second  # noqa: F401
    import homelab.vm.controller_principals  # noqa: F401

    with contextlib.ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(
            prefix="telos-identity-overlay-pin-")))
        overlay = root / "identity" / "principals.json"
        if document is not None:
            overlay.parent.mkdir()
            overlay.write_text(json.dumps(document), encoding="utf-8")
        if document is None and _in_overlaid_checkout():
            # The copy's own synthetic overlay IS what this child must follow.
            overlay = homelab.workstations.arch_second.identity_overlay_path()
        else:
            for module in _loaded_copies(_ARCH_SECOND):
                stack.enter_context(mock.patch.object(
                    module, "identity_overlay_path", return_value=overlay))
        # Forget any earlier resolution on the way in AND out, so neither
        # this pin nor the one before it leaks into the next.
        _forget_rosters()
        stack.callback(_forget_rosters)
        yield overlay


def _in_overlaid_checkout() -> bool:
    """True only in the overlay-regression child's copied checkout."""
    return (bool(os.environ.get(OVERLAY_CHECKOUT_MARKER))
            and not (HOMELAB.parent / ".git").exists())


def _forget_rosters() -> None:
    """Clear every loaded copy's cached roster resolution."""
    for source, cache in _ROSTER_CACHES:
        for module in _loaded_copies(source):
            getattr(module, cache).cache_clear()


@contextlib.contextmanager
def pinned_acceptance_state(
    root: Path | None = None,
) -> Iterator[tuple[Path, Path]]:
    """Reserve private spellings of the disposable acceptance state.

    HANDOFF section 5 also forbids ``build/``.  Every persistent-instance
    separation check (``simulation_overlay.assert_persistent_state_separate``)
    resolves and stats each spelling ``acceptance_state_candidates`` reserves
    -- the repository- and cwd-relative ``build/homelab/vm/bootstrap-dc`` --
    so a test that merely creates, binds or refuses an instance statted the
    operator's real tree.  Inside this pin every loaded copy of
    ``simulation_overlay`` reserves two private spellings under *root* (a
    temporary directory when omitted) instead: one that exists, judged by
    inode, and one that does not, judged textually, which are the two ways
    the real candidates are judged.  The refusals still run for real.  Yields
    ``(existing, absent)``; the real candidates are asserted separately
    (test_simulation_overlay), as pure path arithmetic.
    """
    import homelab.vm.simulation_overlay as canonical

    with contextlib.ExitStack() as stack:
        if root is None:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(
                prefix="telos-acceptance-state-pin-")))
        relative = canonical.ACCEPTANCE_STATE_RELATIVE
        existing = Path(root) / "reserved-repository" / relative
        existing.mkdir(parents=True)
        absent = Path(root) / "reserved-cwd" / relative
        for module in _loaded_copies(_SIMULATION_OVERLAY):
            stack.enter_context(mock.patch.object(
                module, "acceptance_state_candidates",
                return_value=(existing, absent)))
        yield existing, absent
