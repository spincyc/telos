"""Durable lifecycle vocabulary and deterministic transaction transforms."""

from __future__ import annotations

from typing import Collection, Iterable, Literal, MutableMapping, TypeAlias, TypeGuard


RunState: TypeAlias = Literal[
    "allocating",
    "allocation-failed",
    "ready",
    "running",
    "preserved",
    "failed-preserved",
    "interrupted",
    "quarantined",
    "retirement-pending",
    "retirement-ref-cleanup-pending",
    "cleaned",
    "cleaned-branch-retained",
    "integration-conflict",
    "integration-continue-pending",
    "integration-review-pending",
    "integration-manual-landing-pending",
    "integration-abort-pending",
    "integration-abort-recovery-failed",
    "integration-rebase-pending",
    "integration-rebase-recovery-failed",
    "integration-rebase-rollback-pending",
    "integration-rebase-rollback-failed",
    "integration-merge-pending",
    "integration-merge-failed",
    "integration-verification-pending",
    "integration-verification-failed",
    "integrated-pending-cleanup",
    "integration-cleanup-pending",
    "integration-cleanup-failed",
    "cleaned-ref-retained",
]

RETIREMENT_PENDING_STATES: set[RunState] = {
    "retirement-pending",
    "retirement-ref-cleanup-pending",
}

MANAGED_CONFLICT_STATES: set[RunState] = {
    "integration-conflict",
    "integration-continue-pending",
    "integration-abort-pending",
}

RUN_STATES: set[RunState] = {
    "allocating",
    "allocation-failed",
    "ready",
    "running",
    "preserved",
    "failed-preserved",
    "interrupted",
    "quarantined",
    *RETIREMENT_PENDING_STATES,
    "cleaned",
    "cleaned-branch-retained",
    "integration-conflict",
    "integration-continue-pending",
    "integration-review-pending",
    "integration-manual-landing-pending",
    "integration-abort-pending",
    "integration-abort-recovery-failed",
    "integration-rebase-pending",
    "integration-rebase-recovery-failed",
    "integration-rebase-rollback-pending",
    "integration-rebase-rollback-failed",
    "integration-merge-pending",
    "integration-merge-failed",
    "integration-verification-pending",
    "integration-verification-failed",
    "integrated-pending-cleanup",
    "integration-cleanup-pending",
    "integration-cleanup-failed",
    "cleaned-ref-retained",
}

MANUAL_LANDING_CHECKPOINT_FIELDS = (
    "integration_manual_landing_started_at",
    "integration_landing_expected_head",
    "integration_landing_candidate_head",
    "integration_landing_started_at",
)

INTEGRATION_TRANSACTION_FIELDS = (
    "integration_source_head",
    "integration_target_head",
    "integration_candidate_head",
    "integration_conflict_head",
    "integration_conflict_commit",
    "integration_precommit_commit",
    "integration_precommit_index_tree",
    "integration_conflict_paths",
    "integration_unmerged_paths",
    "integration_allowed_staged_paths",
    "integration_protected_index_paths",
    "integration_protected_index_hash",
    "integration_rebase_metadata_hash",
    "integration_conflicted_at",
    "integration_conflict_error",
    "integration_resolution_staged_at",
    "integration_resolver_scope_error",
    "integration_continue_started_at",
    "integration_manual_resolution",
    *MANUAL_LANDING_CHECKPOINT_FIELDS,
    "integration_abort_mode",
    "integration_abort_started_at",
    "integration_rollback_started_at",
    "integration_target_mismatch_head",
    "integration_target_mismatch_at",
    "integration_target_verification_error",
    "integration_started_at",
    "integration_source_anchor_created",
    "integration_rebased_at",
    "integration_previous_state",
)

ABORTED_INTEGRATION_ARCHIVE_FIELDS = (
    ("integration_source_head", "last_integration_source_head"),
    ("integration_target_head", "last_integration_target_head"),
    ("integration_candidate_head", "last_integration_candidate_head"),
    ("integration_conflict_paths", "last_integration_conflict_paths"),
)


def is_run_state(
    value: object,
    *,
    run_states: Collection[str] = RUN_STATES,
) -> TypeGuard[str]:
    """Return whether a value is one exact durable lifecycle state."""

    return isinstance(value, str) and value in run_states


def restore_integration_transaction(
    manifest: MutableMapping[str, object],
    *,
    transaction_fields: Iterable[str],
    archive_fields: Iterable[tuple[str, str]],
) -> None:
    """Remove one in-memory transaction and restore its recorded prior state."""

    previous_state = manifest.get("integration_previous_state")
    for current, archived in archive_fields:
        value = manifest.get(current)
        if value is not None:
            manifest[archived] = value
    for field in transaction_fields:
        manifest.pop(field, None)
    manifest["state"] = (
        previous_state if isinstance(previous_state, str) else "preserved"
    )
