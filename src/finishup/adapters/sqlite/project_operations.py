"""SQLite project-operation journal.

This adapter deliberately stores a structural recovery envelope only.  Project title and
description values remain in encrypted task-bundle objects; the journal stores their references,
request digest, and the structural response needed for byte-exact replay.
"""

from __future__ import annotations

import hmac
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from typing import Final, Literal, cast

import apsw

from finishup.domain.coordination import MemberKind, ProjectTextRef, project_id
from finishup.domain.values import JsonValue, validate_commitment, validate_sha256_digest
from finishup.ports.project_operations import (
    ProjectOperationConflict,
    ProjectOperationCorrupt,
    ProjectOperationJournalPort,
    ProjectOperationName,
    ProjectOperationPhase,
    ProjectOperationRecord,
)
from finishup.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, validate_id

__all__ = ["SqliteProjectOperationJournal"]

_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"create", "link", "unlink", "amend", "dissolve", "opt_out", "opt_in", "grant", "revoke"}
)
_PHASES: Final[frozenset[str]] = frozenset(
    {"reserved", "text_ready", "effect_pending", "completed"}
)
_PHASE_ORDER: Final[dict[str, int]] = {
    "reserved": 0,
    "text_ready": 1,
    "effect_pending": 2,
    "completed": 3,
}
_MAX_REF_BYTES: Final = 2_048
_MAX_RESULT_BYTES: Final = 1_048_576


def _invalid() -> ProjectOperationCorrupt:
    return ProjectOperationCorrupt("project_operation_journal_invalid")


def _request(value: object) -> str:
    try:
        return validate_id(IdKind.REQUEST, value)
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _digest(value: object) -> str:
    if type(value) is not str:
        raise _invalid()
    try:
        return validate_commitment(value)
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _result_digest(value: object) -> str:
    if type(value) is not str:
        raise _invalid()
    try:
        return validate_sha256_digest(value)
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _project_or_none(value: object) -> str | None:
    if value is None:
        return None
    try:
        return project_id(value)
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _task_or_none(value: object) -> str | None:
    if value is None:
        return None
    try:
        return validate_id(IdKind.TASK, value)
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _member_kind_or_none(value: object) -> MemberKind | None:
    if value is None:
        return None
    if type(value) is MemberKind:
        return value
    try:
        return MemberKind(cast(str, value))
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _member_or_none(value: object, kind: MemberKind | None) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not value:
        raise _invalid()
    try:
        if kind is MemberKind.TASK:
            return validate_id(IdKind.TASK, value)
        if kind in {MemberKind.REPOSITORY, MemberKind.WORKSPACE}:
            return validate_commitment(value)
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc
    raise _invalid()


def _positive_or_none(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 1:
        raise _invalid()
    return value


def _object_or_none(value: object) -> str | None:
    if value is None:
        return None
    try:
        return validate_id(IdKind.OBJECT, value)
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _ref_blob(value: ProjectTextRef | None) -> bytes | None:
    if value is None:
        return None
    if type(value) is not ProjectTextRef:
        raise _invalid()
    encoded = canonical_encode(value.as_wire())
    if not 1 <= len(encoded) <= _MAX_REF_BYTES:
        raise _invalid()
    return encoded


def _ref_from_blob(value: object) -> ProjectTextRef | None:
    if value is None:
        return None
    if type(value) is not bytes or not 1 <= len(value) <= _MAX_REF_BYTES:
        raise _invalid()
    try:
        parsed = strict_json_parse(value)
        if not isinstance(parsed, Mapping) or canonical_encode(parsed) != value:
            raise ValueError("project_operation_ref_noncanonical")
        source = cast(Mapping[str, JsonValue], parsed)
        required = {
            "object_id",
            "content_digest",
            "plaintext_size",
            "owner_task_id",
            "route_generation",
        }
        if set(source) not in (required, required | {"envelope_digest"}):
            raise ValueError("project_operation_ref_shape")
        size = source["plaintext_size"]
        generation = source["route_generation"]
        if type(size) is not int or type(generation) is not str:
            raise ValueError("project_operation_ref_scalar")
        parsed_generation = int(generation, 10)
        if str(parsed_generation) != generation:
            raise ValueError("project_operation_ref_generation")
        return ProjectTextRef(
            cast(str, source["object_id"]),
            cast(str, source["content_digest"]),
            size,
            cast(str, source["owner_task_id"]),
            parsed_generation,
            cast(str | None, source.get("envelope_digest")),
        )
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise _invalid() from exc


def _result_bytes(value: object) -> bytes | None:
    if value is None:
        return None
    if type(value) is not bytes or not 1 <= len(value) <= _MAX_RESULT_BYTES:
        raise _invalid()
    try:
        parsed = strict_json_parse(value)
        if not isinstance(parsed, Mapping) or canonical_encode(parsed) != value:
            raise ValueError("project_operation_result_noncanonical")
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc
    return value


def _phase(value: object) -> ProjectOperationPhase:
    if type(value) is not str or value not in _PHASES:
        raise _invalid()
    return cast(ProjectOperationPhase, value)


def _record_from_row(row: tuple[object, ...]) -> ProjectOperationRecord:
    if len(row) != 21:
        raise _invalid()
    try:
        request_id = _request(row[0])
        request_digest = _digest(row[1])
        operation = cast(ProjectOperationName, row[2])
        if type(operation) is not str or operation not in _OPERATIONS:
            raise _invalid()
        phase = _phase(row[3])
        project = _project_or_none(row[4])
        owner_task = _task_or_none(row[5])
        owner_route_generation = _positive_or_none(row[6])
        if (owner_task is None) != (owner_route_generation is None):
            raise _invalid()
        if operation not in {"create", "amend"} and (
            owner_task is not None or owner_route_generation is not None
        ):
            raise _invalid()
        member_kind = _member_kind_or_none(row[7])
        member = _member_or_none(row[8], member_kind)
        effect_generation = _positive_or_none(row[9])
        audit_record_id = None if row[10] is None else row[10]
        if audit_record_id is not None and (
            type(audit_record_id) is not str
            or not 1 <= len(audit_record_id) <= 128
            or any(
                char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
                for char in audit_record_id
            )
        ):
            raise _invalid()
        reserved_project = _project_or_none(row[11])
        reserved_title = _object_or_none(row[12])
        reserved_description = _object_or_none(row[13])
        prior_title_ref = _ref_from_blob(row[14])
        prior_description_ref = _ref_from_blob(row[15])
        if operation != "amend" and (
            prior_title_ref is not None or prior_description_ref is not None
        ):
            raise _invalid()
        title_ref = _ref_from_blob(row[16])
        description_ref = _ref_from_blob(row[17])
        result = _result_bytes(row[18])
        result_digest = None if row[19] is None else _result_digest(row[19])
        if (phase == "completed") != (result is not None):
            raise _invalid()
        if result is None and result_digest is not None:
            raise _invalid()
        if result is not None and result_digest != canonical_digest(strict_json_parse(result)):
            raise _invalid()
        return ProjectOperationRecord(
            request_id=request_id,
            request_digest=request_digest,
            operation=operation,
            phase=phase,
            project_id=project,
            owner_task_id=owner_task,
            owner_route_generation=owner_route_generation,
            member_kind=member_kind,
            member_commitment_or_id=member,
            effect_generation=effect_generation,
            audit_record_id=audit_record_id,
            reserved_project_id=reserved_project,
            reserved_title_object_id=reserved_title,
            reserved_description_object_id=reserved_description,
            prior_title_ref=prior_title_ref,
            prior_description_ref=prior_description_ref,
            title_ref=title_ref,
            description_ref=description_ref,
            result_canonical=result,
            result_digest=result_digest,
        )
    except ProjectOperationCorrupt:
        raise
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


class SqliteProjectOperationJournal(ProjectOperationJournalPort):
    """Single-connection journal sharing the catalog writer's transaction boundary."""

    def __init__(self, connection: apsw.Connection, *, installation_id: str) -> None:
        if type(connection) is not apsw.Connection:
            raise TypeError("project_operation_connection_invalid")
        try:
            self._installation_id = validate_id(IdKind.INSTALLATION, installation_id)
        except (TypeError, ValueError) as exc:
            raise TypeError("project_operation_installation_invalid") from exc
        self._db = connection

    @contextmanager
    def _transaction(self) -> Generator[None]:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        else:
            self._db.execute("COMMIT")

    def _load(self, request_id: str) -> ProjectOperationRecord | None:
        row = self._db.execute(
            "SELECT request_id, request_digest, operation, phase, project_id, owner_task_id, "
            "owner_route_generation, member_kind, member_commitment_or_id, effect_generation, "
            "audit_record_id, reserved_project_id, reserved_title_object_id, "
            "reserved_description_object_id, prior_title_ref_canonical, "
            "prior_description_ref_canonical, title_ref_canonical, description_ref_canonical, "
            "result_canonical, result_digest, updated_at "
            "FROM project_operations WHERE installation_id = ? AND request_id = ? LIMIT 2",
            (self._installation_id, request_id),
        ).fetchall()
        if not row:
            return None
        if len(row) != 1:
            raise _invalid()
        return _record_from_row(cast(tuple[object, ...], row[0]))

    @staticmethod
    def _validate_common(
        request_id: object,
        request_digest: object,
        operation: object,
    ) -> tuple[str, str, ProjectOperationName]:
        request = _request(request_id)
        digest = _digest(request_digest)
        if type(operation) is not str or operation not in _OPERATIONS:
            raise _invalid()
        return request, digest, cast(ProjectOperationName, operation)

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
        request, digest, operation_name = self._validate_common(
            request_id, request_digest, operation
        )
        project = _project_or_none(project_id)
        owner_task = _task_or_none(owner_task_id)
        owner_route = _positive_or_none(owner_route_generation)
        if (owner_task is None) != (owner_route is None):
            raise _invalid()
        if operation_name not in {"create", "amend"} and (
            owner_task is not None or owner_route is not None
        ):
            raise _invalid()
        kind = _member_kind_or_none(member_kind)
        member = _member_or_none(member_commitment_or_id, kind)
        generation = _positive_or_none(effect_generation)
        if audit_record_id is not None and (
            type(audit_record_id) is not str
            or not 1 <= len(audit_record_id) <= 128
            or any(
                char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
                for char in audit_record_id
            )
        ):
            raise _invalid()
        reserved_project_value = _project_or_none(reserved_project_id)
        reserved_title_value = _object_or_none(reserved_title_object_id)
        reserved_description_value = _object_or_none(reserved_description_object_id)
        prior_title_blob = _ref_blob(prior_title_ref)
        prior_description_blob = _ref_blob(prior_description_ref)
        if operation_name != "amend" and (
            prior_title_blob is not None or prior_description_blob is not None
        ):
            raise _invalid()
        if operation_name == "create" and reserved_project_value is None:
            raise _invalid()
        with self._transaction():
            current = self._load(request)
            if current is not None:
                if not hmac.compare_digest(current.request_digest, digest):
                    raise ProjectOperationConflict("project_operation_request_conflict")
                if current.operation != operation_name:
                    raise ProjectOperationConflict("project_operation_operation_conflict")
                return current
            now = "1970-01-01T00:00:00.000Z"
            # ``updated_at`` is structural housekeeping.  The catalog clock is intentionally not
            # a journal dependency; monotonic phase semantics are what recovery relies on.
            self._db.execute(
                "INSERT INTO project_operations("
                "installation_id, request_id, request_digest, operation, phase, project_id, "
                "owner_task_id, owner_route_generation, member_kind, member_commitment_or_id, "
                "effect_generation, audit_record_id, reserved_project_id, reserved_title_object_id, "
                "reserved_description_object_id, prior_title_ref_canonical, prior_description_ref_canonical, "
                "title_ref_canonical, description_ref_canonical, "
                "result_canonical, result_digest, created_at, updated_at"
                ") VALUES (?, ?, ?, ?, 'reserved', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)",
                (
                    self._installation_id,
                    request,
                    digest,
                    operation_name,
                    project,
                    owner_task,
                    owner_route,
                    None if kind is None else kind.value,
                    member,
                    generation,
                    audit_record_id,
                    reserved_project_value,
                    reserved_title_value,
                    reserved_description_value,
                    prior_title_blob,
                    prior_description_blob,
                    now,
                    now,
                ),
            )
            result = self._load(request)
            if result is None:
                raise _invalid()
            return result

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
        request, digest, _ = self._validate_common(request_id, request_digest, "create")
        if phase not in {"text_ready", "effect_pending"}:
            raise _invalid()
        project = _project_or_none(project_id)
        kind = _member_kind_or_none(member_kind)
        member = _member_or_none(member_commitment_or_id, kind)
        generation = _positive_or_none(effect_generation)
        if audit_record_id is not None and (
            type(audit_record_id) is not str
            or not 1 <= len(audit_record_id) <= 128
            or any(
                char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
                for char in audit_record_id
            )
        ):
            raise _invalid()
        title_blob = _ref_blob(title_ref)
        description_blob = _ref_blob(description_ref)
        with self._transaction():
            current = self._load(request)
            if current is None:
                raise ProjectOperationCorrupt("project_operation_missing")
            if not hmac.compare_digest(current.request_digest, digest):
                raise ProjectOperationConflict("project_operation_request_conflict")
            if current.completed:
                return current
            if _PHASE_ORDER[phase] < _PHASE_ORDER[current.phase]:
                raise _invalid()
            self._db.execute(
                "UPDATE project_operations SET phase = ?, project_id = COALESCE(?, project_id), "
                "member_kind = COALESCE(?, member_kind), member_commitment_or_id = "
                "COALESCE(?, member_commitment_or_id), effect_generation = COALESCE(?, effect_generation), "
                "audit_record_id = COALESCE(?, audit_record_id), "
                "title_ref_canonical = COALESCE(?, title_ref_canonical), "
                "description_ref_canonical = COALESCE(?, description_ref_canonical), updated_at = ? "
                "WHERE installation_id = ? AND request_id = ? AND phase != 'completed'",
                (
                    phase,
                    project,
                    None if kind is None else kind.value,
                    member,
                    generation,
                    audit_record_id,
                    title_blob,
                    description_blob,
                    "1970-01-01T00:00:00.000Z",
                    self._installation_id,
                    request,
                ),
            )
            result = self._load(request)
            if result is None:
                raise _invalid()
            return result

    async def complete(
        self,
        request_id: str,
        request_digest: str,
        result_canonical: bytes,
    ) -> ProjectOperationRecord:
        request, digest, _ = self._validate_common(request_id, request_digest, "create")
        result = _result_bytes(result_canonical)
        if result is None:
            raise _invalid()
        result_digest = canonical_digest(strict_json_parse(result))
        with self._transaction():
            current = self._load(request)
            if current is None:
                raise ProjectOperationCorrupt("project_operation_missing")
            if not hmac.compare_digest(current.request_digest, digest):
                raise ProjectOperationConflict("project_operation_request_conflict")
            if current.completed:
                if current.result_canonical != result or current.result_digest != result_digest:
                    raise ProjectOperationConflict("project_operation_result_conflict")
                return current
            self._db.execute(
                "UPDATE project_operations SET phase = 'completed', result_canonical = ?, "
                "result_digest = ?, updated_at = ? WHERE installation_id = ? AND request_id = ? "
                "AND phase != 'completed'",
                (
                    result,
                    result_digest,
                    "1970-01-01T00:00:00.000Z",
                    self._installation_id,
                    request,
                ),
            )
            stored = self._load(request)
            if stored is None:
                raise _invalid()
            return stored

    async def get(
        self, request_id: str, request_digest: str | None = None
    ) -> ProjectOperationRecord | None:
        request = _request(request_id)
        digest = None if request_digest is None else _digest(request_digest)
        current = self._load(request)
        if current is None:
            return None
        if digest is not None and not hmac.compare_digest(current.request_digest, digest):
            raise ProjectOperationConflict("project_operation_request_conflict")
        return current
