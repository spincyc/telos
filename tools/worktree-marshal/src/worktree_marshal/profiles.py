"""Immutable runtime identities for Worktree Marshal lifecycle profiles."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class RuntimeProfile:
    """Names and durable identities bound to one lifecycle compatibility domain."""

    profile_id: str
    display_name: str
    schema_version: int
    diagnostic_name: str
    state_environment: str
    default_state_parts: tuple[str, ...]
    override_state_suffix: tuple[str, ...]
    role_environment: str
    real_codex_environment: str
    run_id_environment: str
    worker_branch_prefix: str
    source_anchor_prefix: str
    lock_reason_prefix: str
    format_id: str | None
    manifest_profile_id: str | None
    manifest_agent: str | None
    profile_environment: str | None
    agent_environment: str | None
    compatibility_triptych: bool
    resolver_prompt: str

    def manifest_identity(self) -> dict[str, str]:
        if self.manifest_profile_id is None:
            return {}
        if self.format_id is None:
            raise RuntimeError("a manifest-bearing profile requires a format ID")
        identity = {
            "format_id": self.format_id,
            "profile_id": self.manifest_profile_id,
        }
        if self.manifest_agent is not None:
            identity["agent"] = self.manifest_agent
        return identity

    def validate_manifest_identity(self, manifest: dict) -> bool:
        if self.manifest_profile_id is None:
            return True
        return all(
            manifest.get(name) == value
            for name, value in self.manifest_identity().items()
        )

    def lifecycle_command(self, action: str, run_id: str) -> str:
        if self.compatibility_triptych:
            return f"scripts/triptych-codex {self.lifecycle_hint(action)} {run_id}"
        return f"{self.lifecycle_hint(action)} {run_id}"

    def lifecycle_hint(self, action: str) -> str:
        if not self.compatibility_triptych:
            return f"worktree-marshal --profile {self.profile_id} {action}"
        options = {
            "abort": "--triptych-abort",
            "clean": "--triptych-clean",
            "continue": "--triptych-continue",
            "final-diff": "--triptych-final-diff",
            "integrate": "--triptych-integrate",
            "reopen": "--triptych-reopen",
            "resolve": "--triptych-resolve",
            "status": "--triptych-status",
        }
        return options[action]


TRIPTYCH_PROFILE = RuntimeProfile(
    profile_id="triptych",
    display_name="Triptych Codex",
    schema_version=1,
    diagnostic_name="triptych-codex",
    state_environment="TRIPTYCH_CODEX_STATE_DIR",
    default_state_parts=("triptych-codex",),
    override_state_suffix=(),
    role_environment="TRIPTYCH_CODEX_ROLE",
    real_codex_environment="TRIPTYCH_CODEX_REAL",
    run_id_environment="TRIPTYCH_CODEX_RUN_ID",
    worker_branch_prefix="codex/isolated/",
    source_anchor_prefix="refs/triptych-codex/runs/",
    lock_reason_prefix="triptych-codex ",
    format_id=None,
    manifest_profile_id=None,
    manifest_agent=None,
    profile_environment=None,
    agent_environment=None,
    compatibility_triptych=True,
    resolver_prompt=(
        "Resolve and stage only the launcher-recorded rebase conflicts in this managed "
        "worker. Inspect both sides and preserve intended content. Do not run git rebase "
        "--continue, --abort, or --skip; do not commit, amend, reset, switch branches, "
        "merge, or administer worktrees. Correct any path staged outside the recorded "
        "rebase changes. Stop after all intended resolutions are staged; "
        "the Triptych launcher owns continuation and abort."
    ),
)


GENERIC_V1_PROFILE = RuntimeProfile(
    profile_id="generic-v1",
    display_name="Worktree Marshal",
    schema_version=1,
    diagnostic_name="worktree-marshal",
    state_environment="WORKTREE_MARSHAL_STATE_DIR",
    default_state_parts=("worktree-marshal", "profiles", "generic-v1"),
    override_state_suffix=("profiles", "generic-v1"),
    role_environment="WORKTREE_MARSHAL_ROLE",
    real_codex_environment="WORKTREE_MARSHAL_REAL_CODEX",
    run_id_environment="WORKTREE_MARSHAL_RUN_ID",
    worker_branch_prefix="worktree-marshal/generic-v1/isolated/",
    source_anchor_prefix="refs/worktree-marshal/generic-v1/runs/",
    lock_reason_prefix="worktree-marshal generic-v1 ",
    format_id="worktree-marshal-run",
    manifest_profile_id="generic-v1",
    manifest_agent="codex",
    profile_environment="WORKTREE_MARSHAL_PROFILE_ID",
    agent_environment="WORKTREE_MARSHAL_AGENT_ID",
    compatibility_triptych=False,
    resolver_prompt=(
        "Resolve and stage only the supervisor-recorded rebase conflicts in this managed "
        "worker. Inspect both sides and preserve intended content. Do not run git rebase "
        "--continue, --abort, or --skip; do not commit, amend, reset, switch branches, "
        "merge, or administer worktrees. Correct any path staged outside the recorded "
        "rebase changes. Stop after all intended resolutions are staged; "
        "Worktree Marshal owns continuation and abort."
    ),
)


BUILTIN_PROFILES = MappingProxyType(
    {
        GENERIC_V1_PROFILE.profile_id: GENERIC_V1_PROFILE,
        TRIPTYCH_PROFILE.profile_id: TRIPTYCH_PROFILE,
    }
)


CONTROL_ENVIRONMENTS = frozenset(
    {
        name
        for profile in BUILTIN_PROFILES.values()
        for name in (
            profile.role_environment,
            profile.real_codex_environment,
            profile.run_id_environment,
            profile.profile_environment,
            profile.agent_environment,
        )
        if name is not None
    }
)


MANAGED_CONTEXT_ENVIRONMENTS = frozenset(
    {
        name
        for profile in BUILTIN_PROFILES.values()
        for name in (
            profile.role_environment,
            profile.run_id_environment,
            profile.profile_environment,
            profile.agent_environment,
        )
        if name is not None
    }
)
