"""Service-owned boundary for host-observed subagent annotations.

Host adapters normalize their native payloads into
``finishup.domain.host_lineage.HostLineageObservation``.  This port owns the
smaller service contract that persists those observations, reconciles partial
aliases, and binds one already-observed correlation to an accepted child task.
The port never carries prompts, transcript paths, or host-provided prose.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final, Literal, Protocol

from finishup.domain.host_lineage import (
    HostLineageHost,
    HostLineageObservation,
    HostLineagePhase,
)
from finishup.domain.observation import ObservationSource
from finishup.domain.values import JsonObject, JsonValue, Timestamp, validate_commitment
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "HOST_LINEAGE_MAC_DOMAIN",
    "HostLineageAnnotation",
    "HostLineageRegistryError",
    "HostLineageRegistryPort",
    "HostLineageRegistryReason",
    "source_mask_for",
]


# The installation MAC handle is selected by the ready composition.  Keeping a
# single domain with typed message prefixes avoids reusing a commitment domain
# from repository, workspace, or session identity.
HOST_LINEAGE_MAC_DOMAIN: Final = b"yoetz/host-lineage/v1\x00"

_PHASE_ORDER: Final = {"start": 0, "stop": 1}
_SOURCE_MASKS: Final = {
    ObservationSource.CLAUDE_HOOK: 1,
    ObservationSource.CODEX_HOOK: 1,
    ObservationSource.CODEX_SESSION_STREAM: 2,
    ObservationSource.CURSOR_HOOK: 1,
}
_MAX_SAFE_INTEGER: Final = 2**53 - 1


def _id(kind: IdKind, value: object) -> str:
    try:
        return validate_id(kind, value)
    except (TypeError, ValueError) as exc:
        raise ValueError("host_lineage_id_invalid") from exc


def _commitment(value: object) -> str:
    if type(value) is not str:
        raise ValueError("host_lineage_commitment_invalid")
    try:
        return validate_commitment(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("host_lineage_commitment_invalid") from exc


class HostLineageRegistryReason(str, Enum):  # noqa: UP042 - exact internal error base
    MIGRATION_REQUIRED = "host_lineage_migration_required"
    STORAGE_BUSY = "host_lineage_storage_busy"
    STORAGE_CORRUPT = "host_lineage_storage_corrupt"
    ANNOTATION_NOT_FOUND = "host_lineage_annotation_not_found"
    ANNOTATION_AMBIGUOUS = "host_lineage_annotation_ambiguous"
    ANNOTATION_AFTER_INVALID = "host_lineage_annotation_after_invalid"
    IDENTITY_CONFLICT = "host_lineage_identity_conflict"
    BINDING_CONFLICT = "host_lineage_binding_conflict"
    CHILD_NOT_FOUND = "host_lineage_child_not_found"
    KEY_UNAVAILABLE = "host_lineage_key_unavailable"


class HostLineageRegistryError(Exception):
    """Bounded registry failure without host identity or secret text."""

    __slots__ = ("reason", "retryable")

    reason: HostLineageRegistryReason
    retryable: bool

    def __init__(self, reason: HostLineageRegistryReason, *, retryable: bool = False) -> None:
        if type(reason) is not HostLineageRegistryReason:
            raise TypeError("host_lineage_registry_reason_invalid")
        if type(retryable) is not bool:
            raise TypeError("host_lineage_registry_retryable_invalid")
        self.reason = reason
        self.retryable = retryable
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True, repr=False)
class HostLineageAnnotation:
    """Durable service-owned view of one provisional host observation.

    ``correlation_id`` and the host identity fields are installation-keyed
    commitments.  ``bound_child_task_id`` is retained internally for replay
    reconciliation; provisional status omits rows after it is populated.
    """

    parent_task_id: str
    host_profile: HostLineageHost
    correlation_id: str
    subagent_id: str
    parent_tool_call_id: str | None
    parent_conversation_id: str | None
    conversation_id: str | None
    origin: Literal["host_observed"]
    acceptance: Literal["pending"]
    observed_phases: tuple[HostLineagePhase, ...]
    source_mask: int
    last_session_commitment: str
    first_observed_at: Timestamp
    last_observed_at: Timestamp
    bound_child_task_id: str | None = None
    bound_at: Timestamp | None = None

    def __post_init__(self) -> None:
        _id(IdKind.TASK, self.parent_task_id)
        if type(self.host_profile) is not str or self.host_profile not in {
            "claude",
            "codex",
            "cursor",
        }:
            raise ValueError("host_lineage_host_invalid")
        for value in (self.correlation_id, self.subagent_id, self.last_session_commitment):
            _commitment(value)
        for value in (
            self.parent_tool_call_id,
            self.parent_conversation_id,
            self.conversation_id,
        ):
            if value is not None:
                _commitment(value)
        if self.origin != "host_observed" or self.acceptance != "pending":
            raise ValueError("host_lineage_annotation_state_invalid")
        if (
            type(self.observed_phases) is not tuple
            or not self.observed_phases
            or len(self.observed_phases) > 2
            or any(item not in _PHASE_ORDER for item in self.observed_phases)
            or tuple(sorted(set(self.observed_phases), key=_PHASE_ORDER.__getitem__))
            != self.observed_phases
        ):
            raise ValueError("host_lineage_annotation_phases_invalid")
        if (
            type(self.source_mask) is not int
            or isinstance(self.source_mask, bool)
            or not 1 <= self.source_mask <= 3
        ):
            raise ValueError("host_lineage_annotation_sources_invalid")
        if (
            type(self.first_observed_at) is not Timestamp
            or type(self.last_observed_at) is not Timestamp
        ):
            raise ValueError("host_lineage_annotation_time_invalid")
        if self.last_observed_at < self.first_observed_at:
            raise ValueError("host_lineage_annotation_time_invalid")
        if self.bound_child_task_id is None:
            if self.bound_at is not None:
                raise ValueError("host_lineage_annotation_binding_invalid")
        else:
            _id(IdKind.TASK, self.bound_child_task_id)
            if type(self.bound_at) is not Timestamp:
                raise ValueError("host_lineage_annotation_binding_invalid")

    @property
    def provisional(self) -> bool:
        return self.bound_child_task_id is None

    def as_status_wire(self) -> JsonObject:
        """Return the closed lineage annotation shape consumed by status."""

        values: dict[str, JsonValue] = {
            "acceptance": self.acceptance,
            "correlation_id": self.correlation_id,
            "origin": self.origin,
            "subagent_id": self.subagent_id,
        }
        if self.parent_tool_call_id is not None:
            values["parent_tool_call_id"] = self.parent_tool_call_id
        return JsonObject(values)

    def __repr__(self) -> str:
        return (
            "HostLineageAnnotation("
            f"parent_task_id={self.parent_task_id!r}, host_profile={self.host_profile!r}, "
            f"correlation_id={self.correlation_id!r}, provisional={self.provisional!r})"
        )


class HostLineageRegistryPort(Protocol):
    """Durable host annotation and binding operations."""

    async def record_host_lineage_observation(
        self,
        parent_task_id: str,
        observation: HostLineageObservation,
        *,
        observed_session_commitment: str,
        source: ObservationSource,
    ) -> HostLineageAnnotation: ...

    async def find_host_lineage_observation(
        self,
        parent_task_id: str,
        observation: HostLineageObservation,
    ) -> HostLineageAnnotation | None: ...

    async def list_provisional_annotations(
        self,
        parent_task_id: str,
        *,
        correlation_id: str | None = None,
        limit: int = 100,
        after_correlation_id: str | None = None,
    ) -> tuple[HostLineageAnnotation, ...]: ...

    async def latest_open_host_operation(
        self,
        parent_task_id: str,
        *,
        not_before: Timestamp,
        session_commitment: str,
    ) -> Timestamp | None:
        """Return the newest first observation of a started, not yet stopped host child.

        Bound and provisional annotations both count: the host operation runs under the parent
        session whether or not a FinishUP child task was ever bound to it.  Starts observed before
        ``not_before`` are ignored.  The operation must also belong to the exact currently bound
        host session; a parent task can rotate its FinishUP session while an older host annotation
        remains open.
        """
        ...

    async def bind_provisional_annotation(
        self,
        parent_task_id: str,
        correlation_id: str,
        child_task_id: str,
    ) -> HostLineageAnnotation: ...

    async def bind_host_lineage_identity(
        self,
        parent_task_id: str,
        child_task_id: str,
        *,
        host: HostLineageHost | None = None,
        subagent_id: str | None = None,
        parent_tool_call_id: str | None = None,
        correlation_id: str | None = None,
        validate_only: bool = False,
    ) -> HostLineageAnnotation | None: ...


def source_mask_for(source: ObservationSource) -> int:
    """Return the bounded source bit used by the durable registry."""

    try:
        return _SOURCE_MASKS[source]
    except KeyError as exc:
        raise ValueError("host_lineage_source_invalid") from exc
