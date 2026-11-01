"""Durable idempotency boundary for project lifecycle mutations.

The project catalog is an append-only event-derived surface, but its lifecycle commands also
touch encrypted task-bundle objects.  This port records the small structural recovery envelope
needed to retry one caller request without retaining project text in the catalog journal.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

from finishup.domain.coordination import MemberKind, ProjectTextRef
from finishup.domain.values import JsonValue

ProjectOperationDigest = Callable[[JsonValue], str]

ProjectOperationName = Literal[
    "create",
    "link",
    "unlink",
    "amend",
    "dissolve",
    "opt_out",
    "opt_in",
    "grant",
    "revoke",
]
ProjectOperationPhase = Literal["reserved", "text_ready", "effect_pending", "completed"]


class ProjectOperationConflict(ValueError):
    """One request id was reused for a different authenticated request digest."""


class ProjectOperationCorrupt(ValueError):
    """A journal row failed its structural or canonical validation."""


@dataclass(frozen=True, slots=True)
class ProjectOperationRecord:
    """Structural state for one project mutation request.

    No field contains title or description plaintext.  ``result_canonical`` is the exact
    structural response emitted by the project handler; encrypted text is represented only by
    ``ProjectTextRef`` pointers.
    """

    request_id: str
    request_digest: str
    operation: ProjectOperationName
    phase: ProjectOperationPhase
    project_id: str | None = None
    owner_task_id: str | None = None
    owner_route_generation: int | None = None
    member_kind: MemberKind | None = None
    member_commitment_or_id: str | None = None
    effect_generation: int | None = None
    audit_record_id: str | None = None
    reserved_project_id: str | None = None
    reserved_title_object_id: str | None = None
    reserved_description_object_id: str | None = None
    prior_title_ref: ProjectTextRef | None = None
    prior_description_ref: ProjectTextRef | None = None
    title_ref: ProjectTextRef | None = None
    description_ref: ProjectTextRef | None = None
    result_canonical: bytes | None = None
    result_digest: str | None = None

    @property
    def completed(self) -> bool:
        return self.phase == "completed" and self.result_canonical is not None


class ProjectOperationJournalPort(Protocol):
    """Reserve, advance, and complete one idempotent project request."""

    async def reserve(
        self,
        request_id: str,
        request_digest: str,
        operation: ProjectOperationName,
        *,
        project_id: str | None = None,
        owner_task_id: str | None = None,
        owner_route_generation: int | None = None,
        member_kind: MemberKind | None = None,
        member_commitment_or_id: str | None = None,
        effect_generation: int | None = None,
        audit_record_id: str | None = None,
        reserved_project_id: str | None = None,
        reserved_title_object_id: str | None = None,
        reserved_description_object_id: str | None = None,
        prior_title_ref: ProjectTextRef | None = None,
        prior_description_ref: ProjectTextRef | None = None,
    ) -> ProjectOperationRecord: ...

    async def advance(
        self,
        request_id: str,
        request_digest: str,
        *,
        phase: Literal["text_ready", "effect_pending"],
        project_id: str | None = None,
        member_kind: MemberKind | None = None,
        member_commitment_or_id: str | None = None,
        effect_generation: int | None = None,
        audit_record_id: str | None = None,
        title_ref: ProjectTextRef | None = None,
        description_ref: ProjectTextRef | None = None,
    ) -> ProjectOperationRecord: ...

    async def complete(
        self,
        request_id: str,
        request_digest: str,
        result_canonical: bytes,
    ) -> ProjectOperationRecord: ...

    async def get(
        self, request_id: str, request_digest: str | None = None
    ) -> ProjectOperationRecord | None: ...


__all__ = [
    "ProjectOperationConflict",
    "ProjectOperationCorrupt",
    "ProjectOperationDigest",
    "ProjectOperationJournalPort",
    "ProjectOperationName",
    "ProjectOperationPhase",
    "ProjectOperationRecord",
]
