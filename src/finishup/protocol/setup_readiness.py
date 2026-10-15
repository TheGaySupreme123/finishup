"""Bounded read-only setup continuation contract."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from finishup.protocol.canonical import JsonValue

type SetupReadinessReason = Literal[
    "service_unavailable",
    "service_not_ready",
    "vault_uninitialized",
    "vault_locked",
    "repository_privacy_scope_unavailable",
    "provider_binding_required",
    "repository_grant_required",
    "review_permission_required",
    "connection_unavailable",
    "host_selection_required",
    "installed_not_activated",
    "connection_required",
    "ready",
]


class SetupReadiness(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # Frozen legacy identifier (ADR-048): the protocol 0.1 tag namespace.
    schema_tag: Literal["yoetz.setup-readiness/1"] = Field(alias="schema")
    operation: Literal["local", "review", "connection"]
    reason: SetupReadinessReason
    project: str
    inspected_config_root: str | None
    next_command: str | None
    facts: dict[str, JsonValue] = Field(max_length=32)
    connection_observed: Literal[False] = False
