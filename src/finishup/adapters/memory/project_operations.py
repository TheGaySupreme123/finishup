"""In-memory project-operation journal used by application tests."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from typing import Literal

from finishup.domain.coordination import MemberKind, ProjectTextRef
from finishup.domain.values import validate_commitment
from finishup.ports.project_operations import (
    ProjectOperationConflict,
    ProjectOperationJournalPort,
    ProjectOperationName,
    ProjectOperationRecord,
)
from finishup.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, validate_id

__all__ = ["InMemoryProjectOperationJournal"]


class InMemoryProjectOperationJournal(ProjectOperationJournalPort):
    """Reference journal with the same digest/conflict/replay semantics as SQLite."""

    def __init__(self) -> None:
        self.records: dict[str, ProjectOperationRecord] = {}

    @staticmethod
    def _validate(request_id: str, request_digest: str) -> tuple[str, str]:
        request = validate_id(IdKind.REQUEST, request_id)
        digest = validate_commitment(request_digest)
        return request, digest

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
    ) -> ProjectOperationRecord:
        request, digest = self._validate(request_id, request_digest)
        if owner_task_id is not None:
            owner_task_id = validate_id(IdKind.TASK, owner_task_id)
        if owner_route_generation is not None and (
            type(owner_route_generation) is not int or owner_route_generation < 1
        ):
            raise ValueError("project_operation_owner_route_invalid")
        if (owner_task_id is None) != (owner_route_generation is None):
            raise ValueError("project_operation_owner_route_invalid")
        if operation not in {"create", "amend"} and (
            owner_task_id is not None or owner_route_generation is not None
        ):
            raise ValueError("project_operation_owner_route_invalid")
        if operation != "amend" and (
            prior_title_ref is not None or prior_description_ref is not None
        ):
            raise ValueError("project_operation_prior_refs_invalid")
        current = self.records.get(request)
        if current is not None:
            if (
                not hmac.compare_digest(current.request_digest, digest)
                or current.operation != operation
            ):
                raise ProjectOperationConflict("project_operation_request_conflict")
            return current
        record = ProjectOperationRecord(
            request_id=request,
            request_digest=digest,
            operation=operation,
            phase="reserved",
            project_id=project_id,
            owner_task_id=owner_task_id,
            owner_route_generation=owner_route_generation,
            member_kind=member_kind,
            member_commitment_or_id=member_commitment_or_id,
            effect_generation=effect_generation,
            audit_record_id=audit_record_id,
            reserved_project_id=reserved_project_id,
            reserved_title_object_id=reserved_title_object_id,
            reserved_description_object_id=reserved_description_object_id,
            prior_title_ref=prior_title_ref,
            prior_description_ref=prior_description_ref,
        )
        self.records[request] = record
        return record

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
    ) -> ProjectOperationRecord:
        request, digest = self._validate(request_id, request_digest)
        current = self.records.get(request)
        if current is None:
            raise ValueError("project_operation_missing")
        if not hmac.compare_digest(current.request_digest, digest):
            raise ProjectOperationConflict("project_operation_request_conflict")
        if current.completed:
            return current
        order = {"reserved": 0, "text_ready": 1, "effect_pending": 2, "completed": 3}
        if phase not in order or order[phase] < order[current.phase]:
            raise ValueError("project_operation_phase_invalid")
        updated = ProjectOperationRecord(
            request_id=current.request_id,
            request_digest=current.request_digest,
            operation=current.operation,
            phase=phase,
            project_id=current.project_id if project_id is None else project_id,
            owner_task_id=current.owner_task_id,
            owner_route_generation=current.owner_route_generation,
            member_kind=current.member_kind if member_kind is None else member_kind,
            member_commitment_or_id=(
                current.member_commitment_or_id
                if member_commitment_or_id is None
                else member_commitment_or_id
            ),
            effect_generation=(
                current.effect_generation if effect_generation is None else effect_generation
            ),
            audit_record_id=current.audit_record_id if audit_record_id is None else audit_record_id,
            reserved_project_id=current.reserved_project_id,
            reserved_title_object_id=current.reserved_title_object_id,
            reserved_description_object_id=current.reserved_description_object_id,
            prior_title_ref=current.prior_title_ref,
            prior_description_ref=current.prior_description_ref,
            title_ref=current.title_ref if title_ref is None else title_ref,
            description_ref=current.description_ref if description_ref is None else description_ref,
            result_canonical=current.result_canonical,
            result_digest=current.result_digest,
        )
        self.records[request] = updated
        return updated

    async def complete(
        self,
        request_id: str,
        request_digest: str,
        result_canonical: bytes,
    ) -> ProjectOperationRecord:
        request, digest = self._validate(request_id, request_digest)
        current = self.records.get(request)
        if current is None:
            raise ValueError("project_operation_missing")
        if not hmac.compare_digest(current.request_digest, digest):
            raise ProjectOperationConflict("project_operation_request_conflict")
        parsed = strict_json_parse(result_canonical)
        if not isinstance(parsed, Mapping) or canonical_encode(parsed) != result_canonical:
            raise ValueError("project_operation_result_invalid")
        result_digest = canonical_digest(parsed)
        if current.completed:
            if current.result_canonical != result_canonical:
                raise ProjectOperationConflict("project_operation_result_conflict")
            return current
        updated = ProjectOperationRecord(
            request_id=current.request_id,
            request_digest=current.request_digest,
            operation=current.operation,
            phase="completed",
            project_id=current.project_id,
            owner_task_id=current.owner_task_id,
            owner_route_generation=current.owner_route_generation,
            member_kind=current.member_kind,
            member_commitment_or_id=current.member_commitment_or_id,
            effect_generation=current.effect_generation,
            audit_record_id=current.audit_record_id,
            reserved_project_id=current.reserved_project_id,
            reserved_title_object_id=current.reserved_title_object_id,
            reserved_description_object_id=current.reserved_description_object_id,
            prior_title_ref=current.prior_title_ref,
            prior_description_ref=current.prior_description_ref,
            title_ref=current.title_ref,
            description_ref=current.description_ref,
            result_canonical=result_canonical,
            result_digest=result_digest,
        )
        self.records[request] = updated
        return updated

    async def get(
        self, request_id: str, request_digest: str | None = None
    ) -> ProjectOperationRecord | None:
        request = validate_id(IdKind.REQUEST, request_id)
        current = self.records.get(request)
        if current is None:
            return None
        if request_digest is not None:
            digest = validate_commitment(request_digest)
            if not hmac.compare_digest(current.request_digest, digest):
                raise ProjectOperationConflict("project_operation_request_conflict")
        return current
