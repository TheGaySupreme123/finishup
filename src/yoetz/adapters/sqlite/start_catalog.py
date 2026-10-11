"""Generation-fenced start catalog state machine over the catalog database."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from functools import partial
from pathlib import Path
from types import TracebackType
from typing import Final, Literal, cast

import apsw

from yoetz.adapters.privacy.catalog import (
    CatalogPrivacyPolicyStore,
    _policy_for_repository,  # pyright: ignore[reportPrivateUsage]
    _policy_from_bytes,  # pyright: ignore[reportPrivateUsage]
    _scope_digest,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.adapters.sqlite.connection import open_read_only
from yoetz.domain.coordination import (
    SESSION_LEASE_SECONDS,
    CoordinationGrant,
    GrantState,
    LineageAcceptance,
    LineageOrigin,
    MemberKind,
    ProjectDescriptor,
    ProjectKind,
    ProjectMembership,
    ProjectTextRef,
    SessionHealth,
    WorkState,
    general_link_conflicts,
    provenance_spans_general_projects,
)
from yoetz.domain.privacy import AuthorizationScope, AuthorizationScopeKind, LocalDisclosureSink
from yoetz.domain.values import (
    format_rfc3339_millis,
    parse_rfc3339_millis,
    validate_commitment,
    validate_sha256_digest,
)
from yoetz.ports.clock import ClockPort
from yoetz.ports.ids import IdPort
from yoetz.ports.keys import MacKeyHandle
from yoetz.ports.publish_response_catalog import PublishResponseKey, StoredPublishResponse
from yoetz.ports.runtime import StartCompletionEvidence, StartMilestone
from yoetz.ports.start_catalog import (
    EXTERNAL_REF_DOMAIN,
    START_TITLE_DOMAIN,
    WORKSPACE_REF_DOMAIN,
    EncryptedResultRef,
    SafeReason,
    SessionBinding,
    SessionState,
    StartAllocation,
    StartCommand,
    StartIdentityCommitments,
    StartIdentityInput,
    StartMode,
    StartOperationLease,
    StartPhase,
    TaskLineage,
    TaskRoute,
    TaskRouteState,
    TaskSourceProvenance,
)
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind, validate_actor_id, validate_id
from yoetz.protocol.recovery import REASON_REMEDIES

__all__ = [
    "CATALOG_SCHEMA_VERSION",
    "SqliteStartCatalog",
    "StartQuarantineCode",
    "external_ref_commitment",
    "workspace_ref_commitment",
]

CATALOG_SCHEMA_VERSION: Final = 4
# Start-operation leases fence one start attempt; session leases are the shared contact lease.
_LEASE_SECONDS: Final = 60
_SESSION_LEASE_SECONDS: Final = SESSION_LEASE_SECONDS
_PHASE_SUCCESSOR: Final = {
    StartPhase.ROUTE_RESERVED: StartPhase.BUNDLE_READY,
    StartPhase.BUNDLE_READY: StartPhase.LIFECYCLE_COMMITTED,
    StartPhase.LIFECYCLE_COMMITTED: StartPhase.RESULT_PUBLISHED,
}


class StartQuarantineCode(str, Enum):  # noqa: UP042 - mirrors the durable text vocabulary
    START_ALLOCATION_AMBIGUOUS = "start_allocation_ambiguous"
    START_BUNDLE_INVALID = "start_bundle_invalid"
    START_CATALOG_INTEGRITY = "start_catalog_integrity"
    START_LIFECYCLE_CONTRADICTION = "start_lifecycle_contradiction"
    START_RESULT_OBJECT_MISSING = "start_result_object_missing"
    START_ROUTE_CONTRADICTION = "start_route_contradiction"


@dataclass(frozen=True, slots=True)
class _RouteRow:
    task_id: str
    workspace_ref_commitment: str | None
    external_ref_commitment: str | None
    active_session_id: str
    bundle_relpath: str
    route_generation: int
    route_identity_digest: str
    state: TaskRouteState
    repository_privacy_commitment: str | None
    parent_task_id: str | None
    depth: int
    lineage_digest: str
    origin: LineageOrigin | None
    acceptance: LineageAcceptance | None
    work_state: WorkState


@dataclass(frozen=True, slots=True)
class _OperationRow:
    installation_id: str
    operation_id: str
    request_digest: str
    requested_mode: StartMode
    route_action: str
    state: str
    phase: StartPhase
    task_id: str
    session_id: str
    writer_id: str
    lifecycle_event_id: str
    route_generation: int
    route_identity_digest: str
    owner_generation: int | None
    lease_owner_id: str | None
    lease_generation: int | None
    lease_expires_at: datetime | None
    response_object_id: str | None
    response_envelope_digest: str | None
    terminal_result_canonical: bytes | None
    terminal_result_digest: str | None
    quarantine_code: str | None


class _Transaction:
    def __init__(self, db: apsw.Connection) -> None:
        self._db = db

    def __enter__(self) -> None:
        try:
            self._db.execute("BEGIN IMMEDIATE")
        except apsw.BusyError as exc:
            raise _error(
                PublicErrorCode.BUNDLE_BUSY,
                retryable=True,
                safe_details={"reason_code": "catalog_busy"},
            ) from exc

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        if exc_type is None:
            self._db.execute("COMMIT")
        else:
            self._db.execute("ROLLBACK")
        return False


def _error(
    code: PublicErrorCode,
    *,
    retryable: bool = False,
    message: str | None = None,
    safe_details: object | None = None,
) -> PublicOperationError:
    messages = {
        PublicErrorCode.INVALID_REQUEST: "The start request is invalid.",
        PublicErrorCode.IDEMPOTENCY_CONFLICT: "The request ID was already used.",
        PublicErrorCode.OPERATION_PENDING: "The start operation is still pending.",
        PublicErrorCode.SESSION_CONFLICT: "The requested task attachment conflicts.",
        PublicErrorCode.SESSION_NOT_FOUND: "The requested task attachment was not found.",
        PublicErrorCode.BUNDLE_BUSY: "The task is temporarily busy.",
        PublicErrorCode.STORAGE_CORRUPT: "The local catalog is inconsistent.",
        PublicErrorCode.MIGRATION_REQUIRED: "The local catalog needs a newer schema migration.",
        PublicErrorCode.INTERNAL_ERROR: (
            "The start state is inconsistent. " + REASON_REMEDIES["start_state_inconsistent"]
        ),
    }
    if code is PublicErrorCode.INTERNAL_ERROR and safe_details is None:
        # An inconsistent start state is a typed stage, never a bare internal error (tb4n3 RC-2).
        safe_details = {"reason_code": "start_state_inconsistent"}
    return PublicOperationError(
        code,
        messages[code] if message is None else message,
        retryable,
        safe_details=safe_details,
    )


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str:
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    return value


def _text(value: object) -> str:
    result = _optional_text(value)
    if result is None:
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    return result


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int:
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    return value


def _integer(value: object) -> int:
    result = _optional_int(value)
    if result is None:
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    return result


def _optional_bytes(value: object) -> bytes | None:
    if value is None:
        return None
    if type(value) is not bytes:
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    return value


def _bytes(value: object) -> bytes:
    result = _optional_bytes(value)
    if result is None:
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    return result


def _publish_response_from_row(row: tuple[object, ...]) -> StoredPublishResponse:
    if len(row) != 8:
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    try:
        key = PublishResponseKey(
            task_id=_text(row[3]),
            session_id=_text(row[4]),
            writer_id=_text(row[0]),
            request_id=_text(row[1]),
            request_digest=_text(row[5]),
            sink=LocalDisclosureSink(_text(row[2])),
        )
        return StoredPublishResponse(
            key=key,
            result_canonical=_bytes(row[6]),
            result_digest=_text(row[7]),
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _commitment(lookup: MacKeyHandle, domain: bytes, value: JsonValue) -> str:
    result = lookup.mac(domain, canonical_encode(value))
    if type(result) is not str:
        raise _error(PublicErrorCode.INVALID_REQUEST)
    return result


def workspace_ref_commitment(lookup: MacKeyHandle, workspace_ref: JsonValue) -> str:
    return _commitment(lookup, WORKSPACE_REF_DOMAIN, workspace_ref)


def external_ref_commitment(lookup: MacKeyHandle, external_ref: JsonValue) -> str:
    return _commitment(lookup, EXTERNAL_REF_DOMAIN, external_ref)


def _route_from_row(row: tuple[object, ...]) -> _RouteRow:
    if len(row) not in (9, 15):
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    try:
        if len(row) == 9:
            return _RouteRow(
                task_id=_text(row[0]),
                workspace_ref_commitment=_optional_text(row[1]),
                external_ref_commitment=_optional_text(row[2]),
                active_session_id=_text(row[3]),
                bundle_relpath=_text(row[4]),
                route_generation=_integer(row[5]),
                route_identity_digest=_text(row[6]),
                state=TaskRouteState(_text(row[7])),
                repository_privacy_commitment=_optional_text(row[8]),
                parent_task_id=None,
                depth=0,
                lineage_digest=_text(row[6]),
                origin=None,
                acceptance=None,
                work_state=WorkState.OPEN,
            )
        return _RouteRow(
            task_id=_text(row[0]),
            workspace_ref_commitment=_optional_text(row[1]),
            external_ref_commitment=_optional_text(row[2]),
            active_session_id=_text(row[3]),
            bundle_relpath=_text(row[4]),
            route_generation=_integer(row[5]),
            route_identity_digest=_text(row[6]),
            state=TaskRouteState(_text(row[7])),
            repository_privacy_commitment=_optional_text(row[8]),
            parent_task_id=_optional_text(row[9]),
            depth=_integer(row[10]),
            lineage_digest=_text(row[11]),
            origin=None if row[12] is None else LineageOrigin(_text(row[12])),
            acceptance=None if row[13] is None else LineageAcceptance(_text(row[13])),
            work_state=WorkState(_text(row[14])),
        )
    except ValueError as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _route_value(row: _RouteRow) -> TaskRoute:
    try:
        return TaskRoute(
            task_id=row.task_id,
            session_id=row.active_session_id,
            bundle_relpath=row.bundle_relpath,
            route_generation=row.route_generation,
            state=row.state,
            route_identity_digest=row.route_identity_digest,
            repository_privacy_commitment=row.repository_privacy_commitment,
            parent_task_id=row.parent_task_id,
            depth=row.depth,
            lineage_digest=row.lineage_digest,
            origin=row.origin,
            acceptance=row.acceptance,
            work_state=row.work_state,
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _operation_from_row(row: tuple[object, ...]) -> _OperationRow:
    if len(row) != 22:
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    owner_generation_text = _optional_text(row[13])
    try:
        owner_generation = None if owner_generation_text is None else int(owner_generation_text, 10)
        lease_expires_at = None if row[16] is None else parse_rfc3339_millis(_text(row[16]))
        return _OperationRow(
            installation_id=_text(row[0]),
            operation_id=_text(row[1]),
            request_digest=_text(row[2]),
            requested_mode=StartMode(_text(row[3])),
            route_action=_text(row[4]),
            state=_text(row[5]),
            phase=StartPhase(_text(row[6])),
            task_id=_text(row[7]),
            session_id=_text(row[8]),
            writer_id=_text(row[9]),
            lifecycle_event_id=_text(row[10]),
            route_generation=_integer(row[11]),
            route_identity_digest=_text(row[12]),
            owner_generation=owner_generation,
            lease_owner_id=_optional_text(row[14]),
            lease_generation=_optional_int(row[15]),
            lease_expires_at=lease_expires_at,
            response_object_id=_optional_text(row[17]),
            response_envelope_digest=_optional_text(row[18]),
            terminal_result_canonical=_optional_bytes(row[19]),
            terminal_result_digest=_optional_text(row[20]),
            quarantine_code=_optional_text(row[21]),
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _lease(row: _OperationRow) -> StartOperationLease | None:
    if row.state != "pending":
        return None
    if (
        row.owner_generation is None
        or row.lease_owner_id is None
        or row.lease_generation is None
        or row.lease_expires_at is None
    ):
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    try:
        return StartOperationLease(
            row.owner_generation,
            row.lease_owner_id,
            row.lease_generation,
            row.lease_expires_at,
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _allocation(row: _OperationRow, outcome: str) -> StartAllocation:
    replayed = row.terminal_result_canonical if outcome == "replayed" else None
    expose_response = row.state == "complete" or (
        row.state == "pending" and row.phase is StartPhase.RESULT_PUBLISHED
    )
    try:
        return StartAllocation(
            outcome=outcome,  # type: ignore[arg-type]
            route_action=row.route_action,  # type: ignore[arg-type]
            task_id=row.task_id,
            session_id=row.session_id,
            writer_id=row.writer_id,
            lifecycle_event_id=row.lifecycle_event_id,
            bundle_relpath=f"tasks/{row.task_id}",
            route_generation=row.route_generation,
            route_identity_digest=row.route_identity_digest,
            phase=row.phase,
            response_object_id=row.response_object_id if expose_response else None,
            response_envelope_digest=(row.response_envelope_digest if expose_response else None),
            response_result_canonical=(row.terminal_result_canonical if expose_response else None),
            response_result_digest=(row.terminal_result_digest if expose_response else None),
            lease=_lease(row),
            replayed_result=replayed,
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _same_allocation(row: _OperationRow, allocation: StartAllocation) -> bool:
    return (
        row.task_id == allocation.task_id
        and row.session_id == allocation.session_id
        and row.writer_id == allocation.writer_id
        and row.lifecycle_event_id == allocation.lifecycle_event_id
        and row.route_generation == allocation.route_generation
        and hmac.compare_digest(row.route_identity_digest, allocation.route_identity_digest)
        and row.response_object_id == allocation.response_object_id
        and row.response_envelope_digest == allocation.response_envelope_digest
        and row.terminal_result_canonical == allocation.response_result_canonical
        and row.terminal_result_digest == allocation.response_result_digest
    )


def _evidence_value(evidence: StartCompletionEvidence) -> dict[str, JsonValue]:
    frontier: JsonValue = None
    if evidence.lifecycle_frontier is not None:
        frontier = dict(evidence.lifecycle_frontier.as_wire())
    return {
        "lifecycle_event_id": evidence.lifecycle_event_id,
        "lifecycle_frontier": frontier,
        "milestone": evidence.milestone.value,
        "owner_generation": evidence.owner_generation,
        "response_envelope_digest": evidence.response_envelope_digest,
        "response_object_id": evidence.response_object_id,
        "result_digest": evidence.result_digest,
        "route_generation": evidence.route_generation,
        "route_identity_digest": evidence.route_identity_digest,
        "session_id": evidence.session_id,
        "task_id": evidence.task_id,
        "writer_id": evidence.writer_id,
    }


def _validate_completion_evidence(
    row: _OperationRow,
    result: EncryptedResultRef,
    evidence: StartCompletionEvidence,
) -> None:
    if (
        evidence.milestone is not StartMilestone.RESULT_PUBLISHED
        or evidence.owner_generation != row.owner_generation
        or evidence.task_id != row.task_id
        or evidence.session_id != row.session_id
        or evidence.writer_id != row.writer_id
        or evidence.lifecycle_event_id != row.lifecycle_event_id
        or evidence.route_generation != row.route_generation
        or not hmac.compare_digest(evidence.route_identity_digest, row.route_identity_digest)
        or evidence.response_object_id != result.response_object_id
        or evidence.response_envelope_digest != result.envelope_digest
        or evidence.result_digest != result.result_digest
        or not hmac.compare_digest(
            evidence.evidence_digest, canonical_digest(_evidence_value(evidence))
        )
    ):
        raise _error(PublicErrorCode.INTERNAL_ERROR)


def _quarantine_envelope(row: _OperationRow, reason: SafeReason) -> bytes:
    return canonical_encode(
        {
            "lifecycle_event_id": row.lifecycle_event_id,
            "quarantine_code": reason.code,
            "route_identity_digest": row.route_identity_digest,
            "session_id": row.session_id,
            "task_id": row.task_id,
            "writer_id": row.writer_id,
        }
    )


_ROUTE_COLUMNS_V3: Final = """
task_id, workspace_ref_commitment, external_ref_commitment, active_session_id,
bundle_relpath, route_generation, active_route_identity_digest, state,
repository_privacy_commitment
"""
_ROUTE_COLUMNS_V4: Final = """
task_id, workspace_ref_commitment, external_ref_commitment, active_session_id,
bundle_relpath, route_generation, active_route_identity_digest, state,
repository_privacy_commitment, parent_task_id, depth, lineage_digest, origin,
acceptance, work_state
"""
_PROJECT_COLUMNS: Final = """
project_id, kind, repository_commitment, auto_grouping, membership_generation,
created_at, dissolved_at, title_ref_canonical, description_ref_canonical
"""
_OPERATION_COLUMNS: Final = """
installation_id, operation_id, request_digest, requested_mode, route_action, state, phase,
task_id, session_id, writer_id, lifecycle_event_id, route_generation, route_identity_digest,
owner_generation, lease_owner_id, lease_generation, lease_expires_at, response_object_id,
response_envelope_digest, terminal_result_canonical, terminal_result_digest, quarantine_code
"""

_PUBLISH_RESPONSE_COLUMNS: Final = """
writer_id, request_id, sink, task_id, session_id, request_digest,
result_canonical, result_digest
"""


def _lineage_from_route(route: _RouteRow) -> TaskLineage:
    try:
        return TaskLineage(
            task_id=route.task_id,
            parent_task_id=route.parent_task_id,
            depth=route.depth,
            lineage_digest=route.lineage_digest,
            origin=route.origin,
            acceptance=route.acceptance,
            work_state=route.work_state,
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _source_from_route(route: _RouteRow) -> TaskSourceProvenance:
    try:
        return TaskSourceProvenance(
            task_id=route.task_id,
            workspace_ref_commitment=route.workspace_ref_commitment,
            external_ref_commitment=route.external_ref_commitment,
            repository_privacy_commitment=route.repository_privacy_commitment,
            route_generation=route.route_generation,
            route_identity_digest=route.route_identity_digest,
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _project_text_ref_blob(reference: ProjectTextRef | None) -> bytes | None:
    if reference is None:
        return None
    try:
        encoded = canonical_encode(reference.as_wire())
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.INVALID_REQUEST) from exc
    if len(encoded) > 2_048:
        raise _error(PublicErrorCode.INVALID_REQUEST)
    return encoded


def _project_text_ref_from_blob(value: object) -> ProjectTextRef | None:
    if value is None:
        return None
    if type(value) is not bytes or not 1 <= len(value) <= 2_048:
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    try:
        parsed = strict_json_parse(value)
        if not isinstance(parsed, Mapping) or canonical_encode(parsed) != value:
            raise ValueError("project_text_ref_noncanonical")
        source = cast(Mapping[str, object], parsed)
        required = {
            "object_id",
            "content_digest",
            "plaintext_size",
            "owner_task_id",
            "route_generation",
        }
        keys = set(source)
        if keys not in (required, required | {"envelope_digest"}):
            raise ValueError("project_text_ref_shape_invalid")
        plaintext_size = source["plaintext_size"]
        route_generation = source["route_generation"]
        if type(plaintext_size) is not int or type(route_generation) is not str:
            raise ValueError("project_text_ref_scalar_invalid")
        parsed_generation = int(route_generation, 10)
        if str(parsed_generation) != route_generation:
            raise ValueError("project_text_ref_generation_invalid")
        return ProjectTextRef(
            object_id=cast(str, source["object_id"]),
            content_digest=cast(str, source["content_digest"]),
            plaintext_size=plaintext_size,
            owner_task_id=cast(str, source["owner_task_id"]),
            route_generation=parsed_generation,
            envelope_digest=cast(str | None, source.get("envelope_digest")),
        )
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _project_from_row(row: tuple[object, ...]) -> ProjectDescriptor:
    if len(row) not in (7, 9):
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    try:
        project_id = _text(row[0])
        kind = ProjectKind(_text(row[1]))
        repository = _optional_text(row[2])
        auto_grouping = row[3]
        generation = _integer(row[4])
        created_at = parse_rfc3339_millis(_text(row[5]))
        dissolved_at = None if row[6] is None else parse_rfc3339_millis(_text(row[6]))
        title_ref = None if len(row) == 7 else _project_text_ref_from_blob(row[7])
        description_ref = None if len(row) == 7 else _project_text_ref_from_blob(row[8])
        if type(auto_grouping) is not int or auto_grouping not in (0, 1):
            raise ValueError("auto_grouping_invalid")
        return ProjectDescriptor(
            project_id=project_id,
            kind=kind,
            repository_commitment=repository,
            auto_grouping=bool(auto_grouping),
            membership_generation=generation,
            title_ref=title_ref,
            description_ref=description_ref,
            created_at=created_at,
            dissolved_at=dissolved_at,
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _membership_from_row(row: tuple[object, ...]) -> ProjectMembership:
    if len(row) != 6:
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    try:
        return ProjectMembership(
            project_id=_text(row[0]),
            membership_generation=_integer(row[1]),
            member_kind=MemberKind(_text(row[2])),
            member_commitment_or_id=_text(row[3]),
            bound_at=parse_rfc3339_millis(_text(row[4])),
            unbound_at=None if row[5] is None else parse_rfc3339_millis(_text(row[5])),
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _grant_from_row(row: tuple[object, ...]) -> CoordinationGrant:
    if len(row) != 6:
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    try:
        return CoordinationGrant(
            project_id=_text(row[0]),
            membership_generation=_integer(row[1]),
            state=GrantState(_text(row[2])),
            audit_record_id=_text(row[3]),
            granted_at=parse_rfc3339_millis(_text(row[4])),
            revoked_at=None if row[5] is None else parse_rfc3339_millis(_text(row[5])),
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _grouping_preference_from_row(row: tuple[object, ...]) -> bool:
    if len(row) != 1 or type(row[0]) is not int or row[0] not in (0, 1):
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    return bool(row[0])


def _session_from_row(row: tuple[object, ...]) -> SessionState:
    if len(row) != 6:
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    try:
        return SessionState(
            task_id=_text(row[0]),
            session_id=_text(row[1]),
            health=SessionHealth(_text(row[2])),
            changed_at=parse_rfc3339_millis(_text(row[3])),
            lease_expires_at=None if row[4] is None else parse_rfc3339_millis(_text(row[4])),
            actor_id=_optional_text(row[5]),
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


class SqliteStartCatalog:
    """Durable ``StartCatalogPort`` implementation using the frozen catalog schema."""

    def __init__(
        self,
        connection: apsw.Connection,
        *,
        installation_id: str,
        lookup: MacKeyHandle,
        clock: ClockPort,
        ids: IdPort,
    ) -> None:
        if type(connection) is not apsw.Connection:
            raise TypeError("catalog_connection_invalid")
        self._db = connection
        # A file-backed recovery scan owns a separate inspection connection for
        # its entire lifetime. Never send the shared writer to an executor.
        self._recovery_path = Path(connection.filename) if connection.filename else None
        self._installation_id = validate_id(IdKind.INSTALLATION, installation_id)
        self._lookup = lookup
        self._clock = clock
        self._ids = ids
        version_row = self._db.execute("PRAGMA user_version").fetchone()
        if version_row is None or type(version_row[0]) is not int or version_row[0] < 0:
            raise TypeError("catalog_schema_version_invalid")
        self._catalog_schema_version = version_row[0]
        self._route_columns = (
            _ROUTE_COLUMNS_V4 if self._catalog_schema_version >= 4 else _ROUTE_COLUMNS_V3
        )
        self._lease_owner_id = ids.new(IdKind.SERVICE_INSTANCE)
        validate_id(IdKind.SERVICE_INSTANCE, self._lease_owner_id)

    @property
    def generation(self) -> int:
        return self._owner_generation()

    def _require_lineage_schema(self) -> None:
        if self._catalog_schema_version < 4:
            raise _error(
                PublicErrorCode.MIGRATION_REQUIRED,
                safe_details={"catalog_user_version": self._catalog_schema_version},
            )

    async def recovery_routes(self) -> tuple[TaskRoute, ...]:
        """Decode every durable route for recovery verification without exposing identities."""

        if self._recovery_path is None:
            # In-memory reference fixtures have no separately openable file.
            return self._decode_recovery_routes(self._db, self._route_columns)
        worker = asyncio.get_running_loop().run_in_executor(
            None, partial(self._read_recovery_routes, self._recovery_path, self._route_columns)
        )
        try:
            await asyncio.wait((worker,))
            return worker.result()
        except asyncio.CancelledError:
            # Keep connection cleanup owned, even under repeated READY teardown
            # cancellation. The enclosing capture lock/runtime outlive the read.
            cancellation: asyncio.CancelledError | None = None
            current = asyncio.current_task()
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError as exc:
                    if cancellation is None:
                        cancellation = exc
                    # A shutdown coordinator may cancel this task repeatedly while
                    # the reader owns its connection. Consume those requests until
                    # the worker joins, then propagate one cancellation below.
                    if current is not None:
                        while current.cancelling():
                            current.uncancel()
            worker.exception()
            if cancellation is not None:
                raise cancellation
            raise asyncio.CancelledError

    @staticmethod
    def _read_recovery_routes(path: Path, columns: str) -> tuple[TaskRoute, ...]:
        db = open_read_only(path)
        try:
            return SqliteStartCatalog._decode_recovery_routes(db, columns)
        finally:
            db.close()

    @staticmethod
    def _decode_recovery_routes(db: apsw.Connection, columns: str) -> tuple[TaskRoute, ...]:
        rows = db.execute(f"SELECT {columns} FROM task_routes ORDER BY task_id ASC")
        routes: list[TaskRoute] = []
        for row in rows:
            try:
                routes.append(_route_value(_route_from_row(row)))
            except (TypeError, ValueError) as exc:
                raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
        return tuple(routes)

    async def commit_identity(self, value: StartIdentityInput) -> StartIdentityCommitments:
        if type(value) is not StartIdentityInput:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        title = _commitment(self._lookup, START_TITLE_DOMAIN, value.task_title)
        workspace = None
        external = None
        if value.workspace_ref is not None and value.external_ref is not None:
            workspace = workspace_ref_commitment(self._lookup, value.workspace_ref)
            external = external_ref_commitment(self._lookup, value.external_ref)
        return StartIdentityCommitments(title, workspace, external)

    async def resolve_route(self, session_id: str) -> TaskRoute | None:
        try:
            session = validate_id(IdKind.SESSION, session_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        rows = self._rows(
            f"SELECT {self._route_columns} FROM task_routes WHERE active_session_id = ? LIMIT 2",
            (session,),
        )
        if not rows:
            return None
        if len(rows) != 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return _route_value(_route_from_row(rows[0]))

    async def session_binding(self, session_id: str) -> SessionBinding | None:
        try:
            session = validate_id(IdKind.SESSION, session_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        route = self._route_for_session(session)
        if route is None:
            return None
        return self._binding_for_route(route)

    async def list_workspace_task_ids(self, workspace_ref_commitment: str) -> tuple[str, ...]:
        """Return non-quarantined task ids under one workspace commitment, ascending.

        Returns task ids only — never refs, titles, or commitments — so the seam carries
        no user-controlled content. Future cross-conversation discovery builds on this.
        """

        try:
            validate_commitment(workspace_ref_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        rows = self._rows(
            "SELECT task_id FROM task_routes "
            "WHERE workspace_ref_commitment = ? AND state != 'quarantined' "
            "ORDER BY task_id ASC",
            (workspace_ref_commitment,),
        )
        return self._task_ids_from_rows(rows)

    async def list_project_task_ids(self, project_id: str) -> tuple[str, ...]:
        self._require_lineage_schema()
        try:
            project = validate_id(IdKind.PROJECT, project_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        project_rows = self._rows(
            f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
            (project,),
        )
        if len(project_rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        if not project_rows:
            return ()
        descriptor = _project_from_row(project_rows[0])
        if descriptor.dissolved_at is not None:
            return ()
        rows = self._rows(
            "SELECT memberships.member_commitment_or_id "
            "FROM project_memberships AS memberships "
            "JOIN task_routes AS routes ON routes.task_id = memberships.member_commitment_or_id "
            "WHERE memberships.project_id = ? AND memberships.member_kind = 'task' "
            "AND memberships.unbound_at IS NULL AND routes.state != 'quarantined' "
            "ORDER BY memberships.member_commitment_or_id ASC",
            (project,),
        )
        task_ids = set(self._task_ids_from_rows(rows))
        if (
            descriptor.kind is ProjectKind.REPOSITORY
            and descriptor.repository_commitment is not None
            and descriptor.dissolved_at is None
            and descriptor.auto_grouping
        ):
            implicit_rows = self._rows(
                "SELECT task_id FROM task_routes WHERE repository_privacy_commitment = ? "
                "AND state != 'quarantined' ORDER BY task_id ASC",
                (descriptor.repository_commitment,),
            )
            task_ids.update(self._task_ids_from_rows(implicit_rows))
        elif descriptor.kind is ProjectKind.GENERAL:
            general_rows = self._rows(
                "SELECT routes.task_id "
                "FROM project_memberships AS memberships "
                "JOIN task_routes AS routes ON ("
                "  memberships.member_kind = 'repository' "
                "  AND routes.repository_privacy_commitment = memberships.member_commitment_or_id "
                "  OR memberships.member_kind = 'workspace' "
                "  AND routes.workspace_ref_commitment = memberships.member_commitment_or_id"
                ") WHERE memberships.project_id = ? AND memberships.unbound_at IS NULL "
                "AND routes.state != 'quarantined' ORDER BY routes.task_id ASC",
                (project,),
            )
            task_ids.update(self._task_ids_from_rows(general_rows))
        return tuple(sorted(task_ids))

    async def list_repository_task_ids(self, repository_privacy_commitment: str) -> tuple[str, ...]:
        try:
            validate_commitment(repository_privacy_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        rows = self._rows(
            "SELECT task_id FROM task_routes "
            "WHERE repository_privacy_commitment = ? AND state != 'quarantined' "
            "ORDER BY task_id ASC",
            (repository_privacy_commitment,),
        )
        return self._task_ids_from_rows(rows)

    @staticmethod
    def _task_ids_from_rows(rows: list[tuple[object, ...]]) -> tuple[str, ...]:
        task_ids: list[str] = []
        for row in rows:
            if len(row) != 1 or type(row[0]) is not str:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            try:
                task_ids.append(validate_id(IdKind.TASK, row[0]))
            except (TypeError, ValueError) as exc:
                raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
        return tuple(task_ids)

    def _route_for_task_id(self, task_id: str) -> _RouteRow | None:
        rows = self._rows(
            f"SELECT {self._route_columns} FROM task_routes WHERE task_id = ? LIMIT 2",
            (task_id,),
        )
        if len(rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return None if not rows else _route_from_row(rows[0])

    async def task_lineage(self, task_id: str) -> TaskLineage | None:
        self._require_lineage_schema()
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        route = self._route_for_task_id(task)
        return None if route is None else _lineage_from_route(route)

    async def task_source_provenance(self, task_id: str) -> TaskSourceProvenance | None:
        self._require_lineage_schema()
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        route = self._route_for_task_id(task)
        return None if route is None else _source_from_route(route)

    async def task_route_generation(self, task_id: str) -> int:
        self._require_lineage_schema()
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        route = self._route_for_task_id(task)
        if route is None:
            raise _error(PublicErrorCode.SESSION_NOT_FOUND)
        return route.route_generation

    async def task_work_state(self, task_id: str) -> WorkState:
        self._require_lineage_schema()
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        route = self._route_for_task_id(task)
        if route is None:
            raise _error(PublicErrorCode.SESSION_NOT_FOUND)
        return route.work_state

    async def task_session_state(self, session_id: str) -> SessionState | None:
        self._require_lineage_schema()
        try:
            session = validate_id(IdKind.SESSION, session_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        rows = self._rows(
            "SELECT task_id, session_id, health, changed_at, lease_expires_at, actor_id FROM task_sessions "
            "WHERE session_id = ? LIMIT 2",
            (session,),
        )
        if len(rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        if not rows:
            return None
        state = _session_from_row(rows[0])
        now = self._clock.now_utc()
        if state.health is SessionHealth.ACTIVE and (
            state.lease_expires_at is None or state.lease_expires_at <= now
        ):
            # Status reads are read-only.  The injected clock derives the expired health; the
            # service's lease/abandonment sweep owns the durable transition.
            return SessionState(
                task_id=state.task_id,
                session_id=state.session_id,
                health=SessionHealth.CONTACT_LOST,
                changed_at=now,
                lease_expires_at=None,
                actor_id=state.actor_id,
            )
        return state

    async def task_session_states(self, task_id: str) -> tuple[SessionState, ...]:
        self._require_lineage_schema()
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        rows = self._rows(
            "SELECT task_id, session_id, health, changed_at, lease_expires_at, actor_id "
            "FROM task_sessions WHERE task_id = ? ORDER BY session_id ASC",
            (task,),
        )
        # Run the same expiry repair through the public single-session method so injected-clock
        # behavior is identical for callers of either API.
        result: list[SessionState] = []
        for row in rows:
            state = _session_from_row(row)
            resolved = await self.task_session_state(state.session_id)
            if resolved is None:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            result.append(resolved)
        return tuple(result)

    async def list_child_task_ids(self, parent_task_id: str) -> tuple[str, ...]:
        self._require_lineage_schema()
        try:
            parent = validate_id(IdKind.TASK, parent_task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        rows = self._rows(
            "SELECT task_id FROM task_routes WHERE parent_task_id = ? "
            "AND state != 'quarantined' ORDER BY task_id ASC",
            (parent,),
        )
        return self._task_ids_from_rows(rows)

    async def list_task_project_ids(self, task_id: str) -> tuple[str, ...]:
        return await self._list_task_project_ids(task_id, include_quarantined=False)

    async def list_task_project_ids_for_consent_invalidation(self, task_id: str) -> tuple[str, ...]:
        """Enumerate durable project associations for a consent fence.

        Quarantined routes are excluded from the normal disclosure enumeration, but their
        already-recorded project associations still need fencing before source consent can be
        granted again.  This private structural path does not make those associations visible to
        callers of the normal membership API.
        """

        return await self._list_task_project_ids(task_id, include_quarantined=True)

    async def _list_task_project_ids(
        self, task_id: str, *, include_quarantined: bool
    ) -> tuple[str, ...]:
        self._require_lineage_schema()
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        route = self._route_for_task_id(task)
        if (
            not include_quarantined
            and route is not None
            and route.state is TaskRouteState.QUARANTINED
        ):
            return ()
        rows = self._rows(
            "SELECT memberships.project_id FROM project_memberships AS memberships "
            "JOIN projects ON projects.project_id = memberships.project_id "
            "WHERE memberships.member_kind = 'task' "
            "AND memberships.member_commitment_or_id = ? AND memberships.unbound_at IS NULL "
            "AND projects.dissolved_at IS NULL ORDER BY memberships.project_id ASC",
            (task,),
        )
        project_ids: list[str] = []
        for row in rows:
            if len(row) != 1 or type(row[0]) is not str:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            try:
                project_ids.append(validate_id(IdKind.PROJECT, row[0]))
            except (TypeError, ValueError) as exc:
                raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
        if route is not None and route.repository_privacy_commitment is not None:
            implicit_rows = self._rows(
                "SELECT project_id FROM projects WHERE kind = 'repository' "
                "AND repository_commitment = ? AND auto_grouping = 1 AND dissolved_at IS NULL "
                "LIMIT 2",
                (route.repository_privacy_commitment,),
            )
            if len(implicit_rows) > 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            if implicit_rows:
                if len(implicit_rows[0]) != 1 or type(implicit_rows[0][0]) is not str:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
                try:
                    project_ids.append(validate_id(IdKind.PROJECT, implicit_rows[0][0]))
                except (TypeError, ValueError) as exc:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
        # General-project repository/workspace memberships are selectors for every task with
        # matching authenticated route provenance.  Keep this inference aligned with the
        # reference catalog so a pre-linked child repository can resolve the same project before
        # its task membership row exists (the cross-repository lineage admission path).
        if route is not None:
            general_rows = self._rows(
                "SELECT memberships.project_id "
                "FROM project_memberships AS memberships "
                "JOIN projects ON projects.project_id = memberships.project_id "
                "WHERE projects.kind = 'general' AND projects.dissolved_at IS NULL "
                "AND memberships.unbound_at IS NULL AND ("
                "  memberships.member_kind = 'repository' "
                "  AND memberships.member_commitment_or_id = ?"
                "  OR memberships.member_kind = 'workspace' "
                "  AND memberships.member_commitment_or_id = ?"
                ") ORDER BY memberships.project_id ASC",
                (route.repository_privacy_commitment, route.workspace_ref_commitment),
            )
            for row in general_rows:
                if len(row) != 1 or type(row[0]) is not str:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
                try:
                    project_ids.append(validate_id(IdKind.PROJECT, row[0]))
                except (TypeError, ValueError) as exc:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
        return tuple(sorted(set(project_ids)))

    async def task_route(self, task_id: str) -> TaskRoute | None:
        self._require_lineage_schema()
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        route = self._route_for_task_id(task)
        return None if route is None else _route_value(route)

    async def repository_state(self, repository_commitment: str) -> ProjectDescriptor | None:
        self._require_lineage_schema()
        try:
            validate_commitment(repository_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        rows = self._rows(
            f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE kind = 'repository' "
            "AND repository_commitment = ? LIMIT 2",
            (repository_commitment,),
        )
        if len(rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return None if not rows else _project_from_row(rows[0])

    async def repository_auto_grouping_enabled(self, repository_commitment: str) -> bool:
        self._require_lineage_schema()
        try:
            validate_commitment(repository_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            return self._repository_auto_grouping_locked(repository_commitment)

    def _repository_auto_grouping_locked(self, repository_commitment: str) -> bool:
        preference_rows = self._rows(
            "SELECT auto_grouping FROM repository_grouping_preferences "
            "WHERE repository_commitment = ? LIMIT 2",
            (repository_commitment,),
        )
        if len(preference_rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        preference = (
            None if not preference_rows else _grouping_preference_from_row(preference_rows[0])
        )
        project_rows = self._rows(
            "SELECT auto_grouping FROM projects "
            "WHERE kind = 'repository' AND repository_commitment = ? LIMIT 2",
            (repository_commitment,),
        )
        if len(project_rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        project = None if not project_rows else _grouping_preference_from_row(project_rows[0])
        if preference is not None and project is not None and preference is not project:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        if preference is not None:
            return preference
        return True if project is None else project

    async def project_state(self, project_id: str) -> ProjectDescriptor | None:
        self._require_lineage_schema()
        try:
            project = validate_id(IdKind.PROJECT, project_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        rows = self._rows(
            f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
            (project,),
        )
        if len(rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return None if not rows else _project_from_row(rows[0])

    async def list_project_ids(self) -> tuple[str, ...]:
        self._require_lineage_schema()
        rows = self._rows(
            "SELECT project_id FROM projects WHERE dissolved_at IS NULL ORDER BY project_id ASC",
            (),
        )
        values: list[str] = []
        for row in rows:
            if len(row) != 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            try:
                values.append(validate_id(IdKind.PROJECT, row[0]))
            except (TypeError, ValueError) as exc:
                raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
        return tuple(values)

    async def project_memberships(self, project_id: str) -> tuple[ProjectMembership, ...]:
        self._require_lineage_schema()
        try:
            project = validate_id(IdKind.PROJECT, project_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        rows = self._rows(
            "SELECT project_id, membership_generation, member_kind, "
            "member_commitment_or_id, bound_at, unbound_at FROM project_memberships "
            "WHERE project_id = ? ORDER BY membership_generation ASC, member_kind ASC, "
            "member_commitment_or_id ASC",
            (project,),
        )
        return tuple(_membership_from_row(row) for row in rows)

    async def coordination_grant(
        self, project_id: str, membership_generation: int
    ) -> CoordinationGrant | None:
        self._require_lineage_schema()
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            if type(membership_generation) is not int or membership_generation <= 0:
                raise ValueError("membership_generation_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        rows = self._rows(
            "SELECT project_id, membership_generation, grant_state, audit_record_id, "
            "granted_at, revoked_at FROM coordination_grants "
            "WHERE project_id = ? AND membership_generation = ? LIMIT 2",
            (project, membership_generation),
        )
        if len(rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return None if not rows else _grant_from_row(rows[0])

    async def record_task_lineage(
        self,
        task_id: str,
        *,
        parent_task_id: str | None,
        depth: int,
        lineage_digest: str,
        origin: LineageOrigin | None,
        acceptance: LineageAcceptance | None,
    ) -> TaskLineage:
        self._require_lineage_schema()
        try:
            task = validate_id(IdKind.TASK, task_id)
            parent = None if parent_task_id is None else validate_id(IdKind.TASK, parent_task_id)
            validate_sha256_digest(lineage_digest)
            desired = TaskLineage(
                task_id=task,
                parent_task_id=parent,
                depth=depth,
                lineage_digest=lineage_digest,
                origin=origin,
                acceptance=acceptance,
                work_state=WorkState.OPEN,
            )
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            route = self._route_for_task_id(task)
            if route is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if parent is not None:
                parent_route = self._route_for_task_id(parent)
                if parent_route is None:
                    raise _error(PublicErrorCode.SESSION_NOT_FOUND)
                if parent_route.state is TaskRouteState.QUARANTINED:
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
                if parent_route.depth + 1 != depth:
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
                if (
                    route.repository_privacy_commitment is not None
                    and parent_route.repository_privacy_commitment is not None
                    and not hmac.compare_digest(
                        route.repository_privacy_commitment,
                        parent_route.repository_privacy_commitment,
                    )
                ):
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
            current = _lineage_from_route(route)
            if current == desired:
                return current
            # Work state is intentionally preserved when lineage is recorded after route reserve.
            if (
                current.parent_task_id is not None
                or current.origin is not None
                or current.acceptance is not None
                or current.depth != 0
            ):
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            try:
                self._db.execute(
                    "UPDATE task_routes SET parent_task_id = ?, depth = ?, lineage_digest = ?, "
                    "origin = ?, acceptance = ?, updated_at = ? "
                    "WHERE task_id = ? AND parent_task_id IS NULL AND depth = 0 "
                    "AND origin IS NULL AND acceptance IS NULL",
                    (
                        parent,
                        depth,
                        lineage_digest,
                        None if origin is None else origin.value,
                        None if acceptance is None else acceptance.value,
                        format_rfc3339_millis(self._clock.now_utc()),
                        task,
                    ),
                )
            except apsw.ConstraintError as exc:
                raise _error(PublicErrorCode.SESSION_CONFLICT) from exc
            if self._db.changes() != 1:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            updated = self._route_for_task_id(task)
            if updated is None:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _lineage_from_route(updated)

    @staticmethod
    def _work_state_transition_allowed(current: WorkState, requested: WorkState) -> bool:
        if current is requested:
            return True
        if current is not WorkState.OPEN:
            return False
        return requested in {
            WorkState.CLOSED,
            WorkState.CANCELLED,
            WorkState.ABANDONED,
            WorkState.WRITTEN_OFF,
        }

    async def set_task_work_state(self, task_id: str, state: WorkState) -> TaskLineage:
        self._require_lineage_schema()
        try:
            task = validate_id(IdKind.TASK, task_id)
            if type(state) is not WorkState:
                raise ValueError("work_state_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            route = self._route_for_task_id(task)
            if route is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if not self._work_state_transition_allowed(route.work_state, state):
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            if route.work_state is not state:
                self._db.execute(
                    "UPDATE task_routes SET work_state = ?, updated_at = ? WHERE task_id = ?",
                    (state.value, format_rfc3339_millis(self._clock.now_utc()), task),
                )
                if self._db.changes() != 1:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
            updated = self._route_for_task_id(task)
            if updated is None:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _lineage_from_route(updated)

    async def record_session_state(
        self,
        task_id: str,
        session_id: str,
        *,
        health: SessionHealth,
        changed_at: datetime,
        lease_expires_at: datetime | None = None,
        actor_id: str | None = None,
    ) -> SessionState:
        self._require_lineage_schema()
        try:
            task = validate_id(IdKind.TASK, task_id)
            session = validate_id(IdKind.SESSION, session_id)
            if type(health) is not SessionHealth:
                raise ValueError("session_health_invalid")
            changed_wire = format_rfc3339_millis(changed_at)
            if lease_expires_at is not None:
                lease_wire = format_rfc3339_millis(lease_expires_at)
                if health is SessionHealth.ACTIVE and lease_expires_at <= changed_at:
                    raise ValueError("session_lease_expired")
            else:
                lease_wire = None
            if health is SessionHealth.ACTIVE and lease_expires_at is None:
                lease_expires_at = changed_at + timedelta(seconds=_SESSION_LEASE_SECONDS)
                lease_wire = format_rfc3339_millis(lease_expires_at)
            if actor_id is not None:
                validate_actor_id(actor_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            route = self._route_for_task_id(task)
            if route is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            rows = self._rows(
                "SELECT task_id, session_id, health, changed_at, lease_expires_at, actor_id FROM task_sessions "
                "WHERE session_id = ? LIMIT 2",
                (session,),
            )
            if len(rows) > 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            if rows:
                current = _session_from_row(rows[0])
                if current.task_id != task:
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
                if current.health is not health:
                    try:
                        self._db.execute(
                            "UPDATE task_sessions SET health = ?, changed_at = ?, ended_at = ?, "
                            "lease_expires_at = ?, actor_id = ? "
                            "WHERE session_id = ? AND task_id = ?",
                            (
                                health.value,
                                changed_wire,
                                changed_wire if health is SessionHealth.ENDED else None,
                                lease_wire if health is SessionHealth.ACTIVE else None,
                                actor_id if actor_id is not None else current.actor_id,
                                session,
                                task,
                            ),
                        )
                    except apsw.ConstraintError as exc:
                        raise _error(PublicErrorCode.SESSION_CONFLICT) from exc
                    if self._db.changes() != 1:
                        raise _error(PublicErrorCode.STORAGE_CORRUPT)
                elif (
                    current.changed_at != changed_at
                    or current.lease_expires_at
                    != (lease_expires_at if health is SessionHealth.ACTIVE else None)
                    or (actor_id is not None and current.actor_id != actor_id)
                ):
                    try:
                        self._db.execute(
                            "UPDATE task_sessions SET changed_at = ?, lease_expires_at = ?, actor_id = ? "
                            "WHERE session_id = ? AND task_id = ?",
                            (
                                changed_wire,
                                lease_wire if health is SessionHealth.ACTIVE else None,
                                actor_id if actor_id is not None else current.actor_id,
                                session,
                                task,
                            ),
                        )
                    except apsw.ConstraintError as exc:
                        raise _error(PublicErrorCode.SESSION_CONFLICT) from exc
                    if self._db.changes() != 1:
                        raise _error(PublicErrorCode.STORAGE_CORRUPT)
            else:
                self._db.execute(
                    "INSERT INTO task_sessions(session_id, task_id, health, changed_at, created_at, "
                    "ended_at, lease_expires_at, actor_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        session,
                        task,
                        health.value,
                        changed_wire,
                        changed_wire,
                        changed_wire if health is SessionHealth.ENDED else None,
                        lease_wire if health is SessionHealth.ACTIVE else None,
                        actor_id,
                    ),
                )
            updated_rows = self._rows(
                "SELECT task_id, session_id, health, changed_at, lease_expires_at, actor_id FROM task_sessions "
                "WHERE session_id = ? LIMIT 2",
                (session,),
            )
            if len(updated_rows) != 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _session_from_row(updated_rows[0])

    async def extend_session_lease(
        self,
        task_id: str,
        session_id: str,
        *,
        changed_at: datetime,
        lease_expires_at: datetime,
    ) -> SessionState:
        """Atomically offer a later lease without overwriting newer catalog state."""

        self._require_lineage_schema()
        try:
            task = validate_id(IdKind.TASK, task_id)
            session = validate_id(IdKind.SESSION, session_id)
            changed_wire = format_rfc3339_millis(changed_at)
            lease_wire = format_rfc3339_millis(lease_expires_at)
            if lease_expires_at <= changed_at:
                raise ValueError("session_lease_expired")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            route = self._route_for_task_id(task)
            if route is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            rows = self._rows(
                "SELECT task_id, session_id, health, changed_at, lease_expires_at, actor_id "
                "FROM task_sessions WHERE session_id = ? LIMIT 2",
                (session,),
            )
            if len(rows) > 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            if not rows:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            current = _session_from_row(rows[0])
            if current.task_id != task:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            if current.health is SessionHealth.ENDED:
                return current
            current_changed_wire = format_rfc3339_millis(current.changed_at)
            if current.changed_at <= changed_at and (
                current.lease_expires_at is None or current.lease_expires_at < lease_expires_at
            ):
                self._db.execute(
                    "UPDATE task_sessions SET health = 'active', changed_at = ?, "
                    "ended_at = NULL, lease_expires_at = ? "
                    "WHERE session_id = ? AND task_id = ? "
                    "AND health IN ('active', 'contact_lost') "
                    "AND changed_at = ? "
                    "AND (lease_expires_at IS NULL OR lease_expires_at < ?)",
                    (
                        changed_wire,
                        lease_wire,
                        session,
                        task,
                        current_changed_wire,
                        lease_wire,
                    ),
                )
                if self._db.changes() not in {0, 1}:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
            updated_rows = self._rows(
                "SELECT task_id, session_id, health, changed_at, lease_expires_at, actor_id "
                "FROM task_sessions WHERE session_id = ? LIMIT 2",
                (session,),
            )
            if len(updated_rows) != 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _session_from_row(updated_rows[0])

    async def expire_session_leases(
        self, now: datetime | None = None, *, limit: int = 256
    ) -> tuple[SessionState, ...]:
        """Persist contact loss for expired session leases in a bounded service sweep.

        Status reads deliberately derive ``contact_lost`` without writing.  The service owns this
        explicit write path, which makes the transition observable and retryable without allowing
        an arbitrary status request to mutate the catalog.
        """

        effective_now = self._clock.now_utc() if now is None else now
        try:
            now_wire = format_rfc3339_millis(effective_now)
            if type(limit) is not int or not 1 <= limit <= 256:
                raise ValueError("session_expiry_limit_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            rows = self._rows(
                "SELECT task_id, session_id, health, changed_at, lease_expires_at, actor_id "
                "FROM task_sessions WHERE health = 'active' "
                "AND (lease_expires_at IS NULL OR lease_expires_at <= ?) "
                "ORDER BY session_id ASC LIMIT ?",
                (now_wire, limit),
            )
            expired: list[SessionState] = []
            for row in rows:
                current = _session_from_row(row)
                self._db.execute(
                    "UPDATE task_sessions SET health = 'contact_lost', changed_at = ?, "
                    "lease_expires_at = NULL WHERE session_id = ? AND task_id = ? "
                    "AND health = 'active' AND (lease_expires_at IS NULL OR lease_expires_at <= ?)",
                    (now_wire, current.session_id, current.task_id, now_wire),
                )
                if self._db.changes() != 1:
                    continue
                updated = _session_from_row(
                    (
                        current.task_id,
                        current.session_id,
                        SessionHealth.CONTACT_LOST.value,
                        now_wire,
                        None,
                        current.actor_id,
                    )
                )
                expired.append(updated)
            return tuple(expired)

    async def accept_task_lineage(self, task_id: str) -> TaskLineage:
        self._require_lineage_schema()
        return await self._set_lineage_acceptance(task_id, LineageAcceptance.ACCEPTED)

    async def reject_task_lineage(self, task_id: str) -> TaskLineage:
        self._require_lineage_schema()
        return await self._set_lineage_acceptance(task_id, LineageAcceptance.REJECTED)

    async def _set_lineage_acceptance(
        self, task_id: str, acceptance: LineageAcceptance
    ) -> TaskLineage:
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            route = self._route_for_task_id(task)
            if route is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if route.parent_task_id is None:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            if route.acceptance is acceptance:
                return _lineage_from_route(route)
            if route.acceptance is not LineageAcceptance.PENDING:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            try:
                self._db.execute(
                    "UPDATE task_routes SET acceptance = ?, updated_at = ? WHERE task_id = ? "
                    "AND acceptance = 'pending'",
                    (acceptance.value, format_rfc3339_millis(self._clock.now_utc()), task),
                )
            except apsw.ConstraintError as exc:
                raise _error(PublicErrorCode.SESSION_CONFLICT) from exc
            if self._db.changes() != 1:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            updated = self._route_for_task_id(task)
            if updated is None:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _lineage_from_route(updated)

    def _ensure_repository_project_locked(
        self, repository_commitment: str, *, only_if_auto_grouping: bool
    ) -> ProjectDescriptor | None:
        rows = self._rows(
            f"SELECT {_PROJECT_COLUMNS} FROM projects "
            "WHERE kind = 'repository' AND repository_commitment = ? LIMIT 2",
            (repository_commitment,),
        )
        if len(rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        if rows:
            project = _project_from_row(rows[0])
            if project.dissolved_at is not None:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            if only_if_auto_grouping and not project.auto_grouping:
                return None
            return project
        auto_grouping = self._repository_auto_grouping_locked(repository_commitment)
        if only_if_auto_grouping and not auto_grouping:
            return None
        project_id = self._ids.new(IdKind.PROJECT)
        try:
            validate_id(IdKind.PROJECT, project_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
        now_wire = format_rfc3339_millis(self._clock.now_utc())
        try:
            self._db.execute(
                "INSERT INTO projects(project_id, kind, repository_commitment, auto_grouping, "
                "membership_generation, created_at, dissolved_at, title_ref_canonical, "
                "description_ref_canonical) VALUES (?, 'repository', ?, ?, 1, ?, NULL, NULL, NULL)",
                (project_id, repository_commitment, int(auto_grouping), now_wire),
            )
            self._db.execute(
                "INSERT INTO project_memberships(project_id, membership_generation, member_kind, "
                "member_commitment_or_id, bound_at, unbound_at) VALUES (?, 1, 'repository', ?, ?, NULL)",
                (project_id, repository_commitment, now_wire),
            )
        except apsw.ConstraintError as exc:
            raise _error(PublicErrorCode.SESSION_CONFLICT) from exc
        rows = self._rows(
            f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
            (project_id,),
        )
        if len(rows) != 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return _project_from_row(rows[0])

    async def ensure_repository_project(self, repository_commitment: str) -> ProjectDescriptor:
        self._require_lineage_schema()
        try:
            validate_commitment(repository_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            project = self._ensure_repository_project_locked(
                repository_commitment, only_if_auto_grouping=False
            )
            assert project is not None
            return project

    async def ensure_repository_project_if_auto_grouping_enabled(
        self, repository_commitment: str
    ) -> ProjectDescriptor | None:
        self._require_lineage_schema()
        try:
            validate_commitment(repository_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            return self._ensure_repository_project_locked(
                repository_commitment, only_if_auto_grouping=True
            )

    async def create_general_project(
        self, project_id: str, *, auto_grouping: bool = True
    ) -> ProjectDescriptor:
        self._require_lineage_schema()
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            if type(auto_grouping) is not bool:
                raise ValueError("auto_grouping_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            if self._rows("SELECT 1 FROM projects WHERE project_id = ? LIMIT 2", (project,)):
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            now_wire = format_rfc3339_millis(self._clock.now_utc())
            try:
                self._db.execute(
                    "INSERT INTO projects(project_id, kind, repository_commitment, auto_grouping, "
                    "membership_generation, created_at, dissolved_at, title_ref_canonical, "
                    "description_ref_canonical) VALUES (?, 'general', NULL, ?, 1, ?, NULL, NULL, NULL)",
                    (project, 1 if auto_grouping else 0, now_wire),
                )
            except apsw.ConstraintError as exc:
                raise _error(PublicErrorCode.SESSION_CONFLICT) from exc
            rows = self._rows(
                f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
                (project,),
            )
            if len(rows) != 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _project_from_row(rows[0])

    @staticmethod
    def _validate_membership_identity(
        member_kind: MemberKind, member_commitment_or_id: str
    ) -> tuple[MemberKind, str]:
        if type(member_kind) is not MemberKind or type(member_commitment_or_id) is not str:
            raise ValueError("membership_identity_invalid")
        if member_kind is MemberKind.TASK:
            return member_kind, validate_id(IdKind.TASK, member_commitment_or_id)
        validate_commitment(member_commitment_or_id)
        return member_kind, member_commitment_or_id

    def _active_general_memberships(self) -> list[tuple[str, MemberKind, str]]:
        rows = self._rows(
            "SELECT memberships.project_id, memberships.member_kind, "
            "memberships.member_commitment_or_id "
            "FROM project_memberships AS memberships "
            "JOIN projects ON projects.project_id = memberships.project_id "
            "WHERE projects.kind = 'general' AND projects.dissolved_at IS NULL "
            "AND memberships.unbound_at IS NULL",
            (),
        )
        facts: list[tuple[str, MemberKind, str]] = []
        for row in rows:
            if len(row) != 3 or type(row[0]) is not str or type(row[2]) is not str:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            try:
                kind = MemberKind(row[1])
            except ValueError as exc:
                raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
            facts.append((row[0], kind, row[2]))
        return facts

    def _route_provenance(self) -> list[tuple[str, str | None, str | None]]:
        rows = self._rows(
            "SELECT task_id, repository_privacy_commitment, workspace_ref_commitment "
            "FROM task_routes WHERE state != 'quarantined'",
            (),
        )
        provenance: list[tuple[str, str | None, str | None]] = []
        for row in rows:
            if len(row) != 3 or type(row[0]) is not str:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            repository = row[1] if type(row[1]) is str else None
            workspace = row[2] if type(row[2]) is str else None
            provenance.append((row[0], repository, workspace))
        return provenance

    def _general_link_conflicts(self, project: str, kind: MemberKind, member: str) -> bool:
        return general_link_conflicts(
            target_project_id=project,
            member_kind=kind,
            member=member,
            other_memberships=[
                item for item in self._active_general_memberships() if item[0] != project
            ],
            provenance=self._route_provenance(),
        )

    def _provenance_spans_general_projects(
        self,
        task_id: str,
        repository_commitment: str | None,
        workspace_commitment: str | None,
    ) -> bool:
        # Repository binding also serves v3 catalogs, before projects exist.
        # Missing v4 tables on a v4 catalog must still fail rather than skip the guard.
        if self._catalog_schema_version < 4:
            return False
        return provenance_spans_general_projects(
            task_id=task_id,
            repository_commitment=repository_commitment,
            workspace_commitment=workspace_commitment,
            memberships=self._active_general_memberships(),
        )

    async def record_project_membership(
        self,
        project_id: str,
        *,
        member_kind: MemberKind,
        member_commitment_or_id: str,
    ) -> ProjectMembership:
        self._require_lineage_schema()
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            kind, member = self._validate_membership_identity(member_kind, member_commitment_or_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            project_rows = self._rows(
                f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
                (project,),
            )
            if len(project_rows) != 1:
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND
                    if not project_rows
                    else PublicErrorCode.STORAGE_CORRUPT
                )
            descriptor = _project_from_row(project_rows[0])
            if descriptor.dissolved_at is not None:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            existing_rows = self._rows(
                "SELECT project_id, membership_generation, member_kind, member_commitment_or_id, "
                "bound_at, unbound_at FROM project_memberships WHERE project_id = ? "
                "AND member_kind = ? AND member_commitment_or_id = ? AND unbound_at IS NULL LIMIT 2",
                (project, kind.value, member),
            )
            if len(existing_rows) > 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            if existing_rows:
                return _membership_from_row(existing_rows[0])
            if descriptor.kind is ProjectKind.GENERAL and self._general_link_conflicts(
                project, kind, member
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    safe_details={"reason_code": "general_project_membership_conflict"},
                )
            generation_rows = self._rows(
                "SELECT MAX(membership_generation) FROM project_memberships WHERE project_id = ?",
                (project,),
            )
            current = descriptor.membership_generation
            if generation_rows and generation_rows[0][0] is not None:
                if type(generation_rows[0][0]) is not int:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
                current = max(current, generation_rows[0][0])
            generation = current + 1
            now_wire = format_rfc3339_millis(self._clock.now_utc())
            try:
                self._db.execute(
                    "INSERT INTO project_memberships(project_id, membership_generation, member_kind, "
                    "member_commitment_or_id, bound_at, unbound_at) VALUES (?, ?, ?, ?, ?, NULL)",
                    (project, generation, kind.value, member, now_wire),
                )
                self._db.execute(
                    "UPDATE projects SET membership_generation = ? WHERE project_id = ? "
                    "AND membership_generation = ?",
                    (generation, project, descriptor.membership_generation),
                )
                if self._db.changes() != 1:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
            except apsw.ConstraintError as exc:
                raise _error(PublicErrorCode.SESSION_CONFLICT) from exc
            rows = self._rows(
                "SELECT project_id, membership_generation, member_kind, member_commitment_or_id, "
                "bound_at, unbound_at FROM project_memberships WHERE project_id = ? "
                "AND membership_generation = ? AND member_kind = ? AND member_commitment_or_id = ? LIMIT 2",
                (project, generation, kind.value, member),
            )
            if len(rows) != 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _membership_from_row(rows[0])

    async def record_coordination_grant(
        self,
        project_id: str,
        membership_generation: int,
        *,
        grant_state: GrantState,
        audit_ref: str,
    ) -> CoordinationGrant:
        self._require_lineage_schema()
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            if type(membership_generation) is not int or membership_generation <= 0:
                raise ValueError("membership_generation_invalid")
            if type(grant_state) is not GrantState:
                raise ValueError("grant_state_invalid")
            if type(audit_ref) is not str or not 1 <= len(audit_ref) <= 128:
                raise ValueError("grant_audit_ref_invalid")
            if any(
                char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
                for char in audit_ref
            ):
                raise ValueError("grant_audit_ref_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            project_rows = self._rows(
                f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
                (project,),
            )
            if len(project_rows) != 1:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            descriptor = _project_from_row(project_rows[0])
            if (
                descriptor.dissolved_at is not None
                or membership_generation > descriptor.membership_generation
            ):
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            rows = self._rows(
                "SELECT project_id, membership_generation, grant_state, audit_record_id, granted_at, revoked_at "
                "FROM coordination_grants WHERE project_id = ? AND membership_generation = ? LIMIT 2",
                (project, membership_generation),
            )
            if len(rows) > 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            now = self._clock.now_utc()
            now_wire = format_rfc3339_millis(now)
            if rows:
                current = _grant_from_row(rows[0])
                if current.audit_record_id != audit_ref:
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
                if current.state is grant_state:
                    return current
                if current.state is GrantState.REVOKED or grant_state is not GrantState.REVOKED:
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
                try:
                    self._db.execute(
                        "UPDATE coordination_grants SET grant_state = 'revoked', revoked_at = ? "
                        "WHERE project_id = ? AND membership_generation = ? AND grant_state = 'active'",
                        (now_wire, project, membership_generation),
                    )
                except apsw.ConstraintError as exc:
                    raise _error(PublicErrorCode.SESSION_CONFLICT) from exc
                if self._db.changes() != 1:
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
            else:
                try:
                    self._db.execute(
                        "INSERT INTO coordination_grants(project_id, membership_generation, grant_state, "
                        "audit_record_id, granted_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            project,
                            membership_generation,
                            grant_state.value,
                            audit_ref,
                            now_wire,
                            now_wire if grant_state is GrantState.REVOKED else None,
                        ),
                    )
                except apsw.ConstraintError as exc:
                    raise _error(PublicErrorCode.SESSION_CONFLICT) from exc
            rows = self._rows(
                "SELECT project_id, membership_generation, grant_state, audit_record_id, granted_at, revoked_at "
                "FROM coordination_grants WHERE project_id = ? AND membership_generation = ? LIMIT 2",
                (project, membership_generation),
            )
            if len(rows) != 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _grant_from_row(rows[0])

    async def dissolve_project(self, project_id: str) -> ProjectDescriptor:
        self._require_lineage_schema()
        try:
            project = validate_id(IdKind.PROJECT, project_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            rows = self._rows(
                f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
                (project,),
            )
            if len(rows) != 1:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            current = _project_from_row(rows[0])
            if current.dissolved_at is not None:
                return current
            now_wire = format_rfc3339_millis(self._clock.now_utc())
            self._db.execute(
                "UPDATE project_memberships SET unbound_at = ? WHERE project_id = ? AND unbound_at IS NULL",
                (now_wire, project),
            )
            next_generation = current.membership_generation + 1
            self._db.execute(
                "UPDATE projects SET membership_generation = ?, dissolved_at = ? WHERE project_id = ? "
                "AND dissolved_at IS NULL",
                (next_generation, now_wire, project),
            )
            if self._db.changes() != 1:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            rows = self._rows(
                f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
                (project,),
            )
            if len(rows) != 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _project_from_row(rows[0])

    async def advance_project_generation(
        self, project_id: str, *, reason: str, expected_generation: int | None = None
    ) -> ProjectDescriptor:
        self._require_lineage_schema()
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            if type(reason) is not str or not 1 <= len(reason) <= 128:
                raise ValueError("project_generation_reason_invalid")
            if any(
                character
                not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
                for character in reason
            ):
                raise ValueError("project_generation_reason_invalid")
            if expected_generation is not None and (
                type(expected_generation) is not int or expected_generation < 1
            ):
                raise ValueError("project_generation_expected_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            rows = self._rows(
                f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
                (project,),
            )
            if len(rows) != 1:
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND
                    if not rows
                    else PublicErrorCode.STORAGE_CORRUPT
                )
            current = _project_from_row(rows[0])
            if expected_generation is not None:
                if current.membership_generation < expected_generation:
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
                if current.membership_generation > expected_generation:
                    return current
            self._db.execute(
                "UPDATE projects SET membership_generation = membership_generation + 1 "
                "WHERE project_id = ? AND membership_generation = ?",
                (project, current.membership_generation),
            )
            if self._db.changes() != 1:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            rows = self._rows(
                f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
                (project,),
            )
            if len(rows) != 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _project_from_row(rows[0])

    async def set_project_auto_grouping(
        self, repository_commitment: str, *, enabled: bool
    ) -> ProjectDescriptor | None:
        self._require_lineage_schema()
        try:
            validate_commitment(repository_commitment)
            if type(enabled) is not bool:
                raise ValueError("project_auto_grouping_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            rows = self._rows(
                f"SELECT {_PROJECT_COLUMNS} FROM projects "
                "WHERE kind = 'repository' AND repository_commitment = ? LIMIT 2",
                (repository_commitment,),
            )
            if len(rows) > 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            now_wire = format_rfc3339_millis(self._clock.now_utc())
            if not rows:
                self._db.execute(
                    "INSERT INTO repository_grouping_preferences(repository_commitment, "
                    "auto_grouping, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(repository_commitment) DO UPDATE SET "
                    "auto_grouping = excluded.auto_grouping, updated_at = excluded.updated_at",
                    (repository_commitment, int(enabled), now_wire),
                )
                return None
            current = _project_from_row(rows[0])
            if current.dissolved_at is not None:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            self._db.execute(
                "INSERT INTO repository_grouping_preferences(repository_commitment, "
                "auto_grouping, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(repository_commitment) DO UPDATE SET "
                "auto_grouping = excluded.auto_grouping, updated_at = excluded.updated_at",
                (repository_commitment, int(enabled), now_wire),
            )
            if current.auto_grouping is enabled:
                return current
            self._db.execute(
                "UPDATE projects SET auto_grouping = ?, membership_generation = membership_generation + 1 "
                "WHERE project_id = ? AND membership_generation = ?",
                (1 if enabled else 0, current.project_id, current.membership_generation),
            )
            if self._db.changes() != 1:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            rows = self._rows(
                f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
                (current.project_id,),
            )
            if len(rows) != 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _project_from_row(rows[0])

    async def record_project_text_refs(
        self,
        project_id: str,
        *,
        title_ref: ProjectTextRef | None,
        description_ref: ProjectTextRef | None,
        expected_current_refs: tuple[ProjectTextRef | None, ProjectTextRef | None] | None = None,
    ) -> ProjectDescriptor:
        self._require_lineage_schema()
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            if title_ref is not None and type(title_ref) is not ProjectTextRef:
                raise ValueError("project_title_ref_invalid")
            if description_ref is not None and type(description_ref) is not ProjectTextRef:
                raise ValueError("project_description_ref_invalid")
            title_blob = _project_text_ref_blob(title_ref)
            description_blob = _project_text_ref_blob(description_ref)
            if expected_current_refs is not None:
                if (
                    type(expected_current_refs) is not tuple
                    or len(expected_current_refs) != 2
                    or any(
                        item is not None and type(item) is not ProjectTextRef
                        for item in expected_current_refs
                    )
                ):
                    raise ValueError("project_text_expected_refs_invalid")
                expected_title_blob = _project_text_ref_blob(expected_current_refs[0])
                expected_description_blob = _project_text_ref_blob(expected_current_refs[1])
            else:
                expected_title_blob = expected_description_blob = None
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            rows = self._rows(
                f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
                (project,),
            )
            if len(rows) != 1:
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND
                    if not rows
                    else PublicErrorCode.STORAGE_CORRUPT
                )
            if expected_current_refs is None:
                self._db.execute(
                    "UPDATE projects SET title_ref_canonical = ?, description_ref_canonical = ? "
                    "WHERE project_id = ?",
                    (title_blob, description_blob, project),
                )
            else:
                self._db.execute(
                    "UPDATE projects SET title_ref_canonical = ?, description_ref_canonical = ? "
                    "WHERE project_id = ? AND title_ref_canonical IS ? "
                    "AND description_ref_canonical IS ?",
                    (
                        title_blob,
                        description_blob,
                        project,
                        expected_title_blob,
                        expected_description_blob,
                    ),
                )
            if self._db.changes() != 1:
                current_rows = self._rows(
                    f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
                    (project,),
                )
                if len(current_rows) != 1:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
                current = _project_from_row(current_rows[0])
                if current.title_ref == title_ref and current.description_ref == description_ref:
                    return current
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            rows = self._rows(
                f"SELECT {_PROJECT_COLUMNS} FROM projects WHERE project_id = ? LIMIT 2",
                (project,),
            )
            if len(rows) != 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _project_from_row(rows[0])

    async def amend_project(
        self,
        project_id: str,
        *,
        title_ref: ProjectTextRef | None,
        description_ref: ProjectTextRef | None,
        expected_current_refs: tuple[ProjectTextRef | None, ProjectTextRef | None] | None = None,
    ) -> ProjectDescriptor:
        return await self.record_project_text_refs(
            project_id,
            title_ref=title_ref,
            description_ref=description_ref,
            expected_current_refs=expected_current_refs,
        )

    async def unbind_project_membership(
        self,
        project_id: str,
        membership_generation: int,
        *,
        member_kind: MemberKind | None = None,
        member_commitment_or_id: str | None = None,
    ) -> ProjectMembership:
        self._require_lineage_schema()
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            if type(membership_generation) is not int or membership_generation <= 0:
                raise ValueError("membership_generation_invalid")
            if (member_kind is None) != (member_commitment_or_id is None):
                raise ValueError("membership_selector_invalid")
            if member_kind is not None and member_commitment_or_id is not None:
                member_kind, member_commitment_or_id = self._validate_membership_identity(
                    member_kind, member_commitment_or_id
                )
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with self._transaction():
            sql = (
                "SELECT project_id, membership_generation, member_kind, member_commitment_or_id, "
                "bound_at, unbound_at FROM project_memberships WHERE project_id = ? "
                "AND membership_generation = ? AND unbound_at IS NULL"
            )
            bindings: tuple[apsw.Binding, ...] = (project, membership_generation)
            if member_kind is not None and member_commitment_or_id is not None:
                sql += " AND member_kind = ? AND member_commitment_or_id = ?"
                bindings += (member_kind.value, member_commitment_or_id)
            sql += " LIMIT 2"
            rows = self._rows(sql, bindings)
            if not rows:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if len(rows) != 1:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            current = _membership_from_row(rows[0])
            now_wire = format_rfc3339_millis(self._clock.now_utc())
            try:
                self._db.execute(
                    "UPDATE project_memberships SET unbound_at = ? WHERE project_id = ? "
                    "AND membership_generation = ? AND member_kind = ? "
                    "AND member_commitment_or_id = ? AND unbound_at IS NULL",
                    (
                        now_wire,
                        project,
                        membership_generation,
                        current.member_kind.value,
                        current.member_commitment_or_id,
                    ),
                )
            except apsw.ConstraintError as exc:
                raise _error(PublicErrorCode.SESSION_CONFLICT) from exc
            if self._db.changes() != 1:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            generation_rows = self._rows(
                "SELECT membership_generation FROM projects WHERE project_id = ? LIMIT 2",
                (project,),
            )
            if len(generation_rows) != 1 or type(generation_rows[0][0]) is not int:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            next_generation = max(generation_rows[0][0], membership_generation) + 1
            self._db.execute(
                "UPDATE projects SET membership_generation = ? WHERE project_id = ?",
                (next_generation, project),
            )
            if self._db.changes() != 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            rows = self._rows(
                "SELECT project_id, membership_generation, member_kind, member_commitment_or_id, "
                "bound_at, unbound_at FROM project_memberships WHERE project_id = ? "
                "AND membership_generation = ? AND member_kind = ? AND member_commitment_or_id = ? LIMIT 2",
                (
                    project,
                    current.membership_generation,
                    current.member_kind.value,
                    current.member_commitment_or_id,
                ),
            )
            if len(rows) != 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _membership_from_row(rows[0])

    def _bind_repository_privacy_in_transaction(
        self,
        route: _RouteRow,
        repository_privacy_commitment: str,
        now_wire: str,
        *,
        allow_unentitled: bool,
    ) -> _RouteRow:
        """Bind and consume any eligible migration grant inside the caller's transaction."""

        existing = route.repository_privacy_commitment
        if existing is not None:
            if not hmac.compare_digest(existing, repository_privacy_commitment):
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            return route
        entitlement = self._db.execute(
            "SELECT route_identity_digest, migration_policy_digest, "
            "migration_policy_canonical FROM privacy_legacy_route_entitlements "
            "WHERE task_id = ? AND entitlement_state = 'available'",
            (route.task_id,),
        ).fetchone()
        if entitlement is not None and entitlement[0] != route.route_identity_digest:
            raise _error(PublicErrorCode.SESSION_CONFLICT)
        first = self._db.execute(
            "SELECT first_repository_carry_forward_state, migration_policy_digest, "
            "migration_policy_canonical FROM privacy_installation_authority "
            "WHERE installation_id = ?",
            (self._installation_id,),
        ).fetchone()
        first_available = first is not None and first[0] == "available"
        if entitlement is None and not first_available and not allow_unentitled:
            raise _error(PublicErrorCode.SESSION_CONFLICT)

        frontier_row = (
            entitlement if entitlement is not None else first if first_available else None
        )
        scope = AuthorizationScope(
            AuthorizationScopeKind.WORKSPACE,
            self._installation_id,
            repository_privacy_commitment,
        )
        if frontier_row is not None:
            grant = self._db.execute(
                "SELECT 1 FROM privacy_policy_versions WHERE scope_digest = ? "
                "AND state = 'current'",
                (_scope_digest(scope),),
            ).fetchone()
            if grant is None:
                machine_row = self._db.execute(
                    "SELECT policy_canonical FROM privacy_policy_versions "
                    "WHERE installation_id = ? AND scope_kind = 'machine' "
                    "AND state = 'current'",
                    (self._installation_id,),
                ).fetchone()
                if machine_row is None or type(machine_row[0]) is not bytes:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
                digest_index = 1
                canonical_index = 2
                if type(frontier_row[canonical_index]) is not bytes:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
                machine = _policy_from_bytes(machine_row[0])
                frontier = _policy_from_bytes(frontier_row[canonical_index])
                if frontier.policy_digest != frontier_row[digest_index]:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
                if machine.network_egress_permitted and frontier.network_egress_permitted:
                    generation_row = self._db.execute(
                        "SELECT COALESCE(MAX(policy_generation), 0) + 1 "
                        "FROM privacy_policy_versions"
                    ).fetchone()
                    if generation_row is None or type(generation_row[0]) is not int:
                        raise _error(PublicErrorCode.STORAGE_CORRUPT)
                    policy = _policy_for_repository(frontier.meet(machine), scope)
                    CatalogPrivacyPolicyStore(self._db, self._clock)._insert_policy(  # pyright: ignore[reportPrivateUsage]
                        policy, generation_row[0], "seed", None
                    )

        if self._provenance_spans_general_projects(
            route.task_id,
            repository_privacy_commitment,
            route.workspace_ref_commitment,
        ):
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                safe_details={"reason_code": "general_project_membership_conflict"},
            )
        self._db.execute(
            "UPDATE task_routes SET repository_privacy_commitment = ?, updated_at = ? "
            "WHERE task_id = ? AND active_route_identity_digest = ? "
            "AND repository_privacy_commitment IS NULL",
            (
                repository_privacy_commitment,
                now_wire,
                route.task_id,
                route.route_identity_digest,
            ),
        )
        if entitlement is not None:
            self._db.execute(
                "UPDATE privacy_legacy_route_entitlements SET entitlement_state = 'consumed', "
                "repository_privacy_commitment = ?, consumed_at = ? "
                "WHERE task_id = ? AND entitlement_state = 'available'",
                (repository_privacy_commitment, now_wire, route.task_id),
            )
        elif first_available:
            self._db.execute(
                "UPDATE privacy_installation_authority SET "
                "first_repository_carry_forward_state = 'consumed', "
                "first_repository_carry_forward_commitment = ?, updated_at = ? "
                "WHERE installation_id = ? AND "
                "first_repository_carry_forward_state = 'available'",
                (repository_privacy_commitment, now_wire, self._installation_id),
            )
        rows = self._rows(
            f"SELECT {self._route_columns} FROM task_routes WHERE task_id = ? LIMIT 2",
            (route.task_id,),
        )
        if len(rows) != 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        bound = _route_from_row(rows[0])
        if bound.repository_privacy_commitment != repository_privacy_commitment:
            raise _error(PublicErrorCode.SESSION_CONFLICT)
        return bound

    async def bind_repository_privacy(
        self,
        task_id: str,
        route_identity_digest: str,
        repository_privacy_commitment: str,
    ) -> TaskRoute:
        try:
            task = validate_id(IdKind.TASK, task_id)
            validate_sha256_digest(route_identity_digest)
            validate_commitment(repository_privacy_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        with _Transaction(self._db):
            rows = self._rows(
                f"SELECT {self._route_columns} FROM task_routes WHERE task_id = ? LIMIT 2", (task,)
            )
            if len(rows) != 1:
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND
                    if not rows
                    else PublicErrorCode.STORAGE_CORRUPT
                )
            route = _route_from_row(rows[0])
            if route.route_identity_digest != route_identity_digest:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            route = self._bind_repository_privacy_in_transaction(
                route,
                repository_privacy_commitment,
                format_rfc3339_millis(self._clock.now_utc()),
                allow_unentitled=True,
            )
        return _route_value(route)

    async def lookup(self, key: PublishResponseKey) -> StoredPublishResponse | None:
        if type(key) is not PublishResponseKey:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        existing = self._publish_response_by_identity(key)
        if existing is not None and existing.key != key:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return existing

    async def put_if_absent(self, value: StoredPublishResponse) -> StoredPublishResponse:
        if type(value) is not StoredPublishResponse:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        key = value.key
        with self._transaction():
            self._db.execute(
                """INSERT OR IGNORE INTO publish_responses (
                    writer_id, request_id, sink, task_id, session_id, request_digest,
                    result_canonical, result_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    key.writer_id,
                    key.request_id,
                    key.sink.value,
                    key.task_id,
                    key.session_id,
                    key.request_digest,
                    value.result_canonical,
                    value.result_digest,
                ),
            )
            winner = self._publish_response_by_identity(key)
            if winner is None or winner.key != key:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return winner

    async def reserve_or_resume(self, request: StartCommand) -> StartAllocation:
        if type(request) is not StartCommand:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        recomputed = await self.commit_identity(request.identity_input)
        if not self._commitments_match(recomputed, request.identity_commitments):
            raise _error(PublicErrorCode.INVALID_REQUEST)
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)
        proposed = {
            IdKind.TASK: self._ids.new(IdKind.TASK),
            IdKind.SESSION: self._ids.new(IdKind.SESSION),
            IdKind.WRITER: self._ids.new(IdKind.WRITER),
            IdKind.EVENT: self._ids.new(IdKind.EVENT),
        }
        for kind, candidate in proposed.items():
            validate_id(kind, candidate)
        with self._transaction():
            owner_generation = self._owner_generation()
            existing = self._operation_by_key(request.operation_id)
            if existing is not None:
                return self._resume_existing(existing, request, now, now_wire, owner_generation)

            route = self._resolve_requested_route(request)
            if route is not None and route.state is TaskRouteState.QUARANTINED:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            if request.mode is StartMode.CREATE and route is not None:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    safe_details={
                        "reason_code": (
                            "workspace_task_exists"
                            if request.identity_commitments.workspace_ref_commitment is not None
                            and request.identity_commitments.external_ref_commitment is not None
                            else "selector_conflict"
                        )
                    },
                )
            if request.mode is StartMode.ATTACH and route is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if route is not None and route.work_state is not WorkState.OPEN:
                # Terminal work has no transition back to open, so a resume can only fail later
                # at the lineage binding.  Refuse inside this transaction instead: no session is
                # reserved and the route is not rotated, so a session the caller still holds
                # keeps reading and publishing its recorded history (#837).
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    safe_details={"reason_code": "lineage_resume_work_terminal"},
                )
            if route is not None:
                self._require_no_exclusive_maintenance(route.task_id)
                expected = route.repository_privacy_commitment
                actual = request.repository_privacy_commitment
                if expected is not None and (
                    actual is None or not hmac.compare_digest(expected, actual)
                ):
                    raise _error(
                        PublicErrorCode.SESSION_CONFLICT,
                        safe_details={
                            "reason_code": (
                                "repository_identity_required"
                                if actual is None
                                else "repository_identity_mismatch"
                            )
                        },
                    )
                if expected is None and actual is not None:
                    route = self._bind_repository_privacy_in_transaction(
                        route,
                        actual,
                        now_wire,
                        allow_unentitled=False,
                    )

            created = route is None
            if created:
                task_id = proposed[IdKind.TASK]
                session_id = proposed[IdKind.SESSION]
                bundle_relpath = f"tasks/{task_id}"
                route_digest = canonical_digest(
                    {
                        "bundle_relpath": bundle_relpath,
                        "route_generation": 1,
                        "task_id": task_id,
                    }
                )
                if self._catalog_schema_version >= 4:
                    self._db.execute(
                        """INSERT INTO task_routes (
                            task_id, workspace_ref_commitment, external_ref_commitment,
                            active_session_id, bundle_relpath, route_generation,
                            active_route_identity_digest, state, quarantine_code, created_at, updated_at,
                            repository_privacy_commitment, parent_task_id, depth, lineage_digest,
                            origin, acceptance, work_state
                        ) VALUES (?, ?, ?, ?, ?, 1, ?, 'initializing', NULL, ?, ?, NULL, NULL, 0, ?, NULL, NULL, 'open')""",
                        (
                            task_id,
                            request.identity_commitments.workspace_ref_commitment,
                            request.identity_commitments.external_ref_commitment,
                            session_id,
                            bundle_relpath,
                            route_digest,
                            now_wire,
                            now_wire,
                            route_digest,
                        ),
                    )
                    self._db.execute(
                        "INSERT INTO task_sessions(session_id, task_id, health, changed_at, created_at, "
                        "ended_at, lease_expires_at, actor_id) VALUES (?, ?, 'active', ?, ?, NULL, ?, NULL)",
                        (
                            session_id,
                            task_id,
                            now_wire,
                            now_wire,
                            format_rfc3339_millis(now + timedelta(seconds=_SESSION_LEASE_SECONDS)),
                        ),
                    )
                else:
                    self._db.execute(
                        """INSERT INTO task_routes (
                            task_id, workspace_ref_commitment, external_ref_commitment,
                            active_session_id, bundle_relpath, route_generation,
                            active_route_identity_digest, state, quarantine_code, created_at, updated_at,
                            repository_privacy_commitment
                        ) VALUES (?, ?, ?, ?, ?, 1, ?, 'initializing', NULL, ?, ?, NULL)""",
                        (
                            task_id,
                            request.identity_commitments.workspace_ref_commitment,
                            request.identity_commitments.external_ref_commitment,
                            session_id,
                            bundle_relpath,
                            route_digest,
                            now_wire,
                            now_wire,
                        ),
                    )
                route = _RouteRow(
                    task_id,
                    request.identity_commitments.workspace_ref_commitment,
                    request.identity_commitments.external_ref_commitment,
                    session_id,
                    bundle_relpath,
                    1,
                    route_digest,
                    TaskRouteState.INITIALIZING,
                    None,
                    None,
                    0,
                    route_digest,
                    None,
                    None,
                    WorkState.OPEN,
                )
                if request.repository_privacy_commitment is not None:
                    route = self._bind_repository_privacy_in_transaction(
                        route,
                        request.repository_privacy_commitment,
                        now_wire,
                        allow_unentitled=True,
                    )
            else:
                session_id = proposed[IdKind.SESSION]
                if self._catalog_schema_version >= 4:
                    self._db.execute(
                        "INSERT INTO task_sessions(session_id, task_id, health, changed_at, created_at, "
                        "ended_at, lease_expires_at, actor_id) VALUES (?, ?, 'active', ?, ?, NULL, ?, NULL)",
                        (
                            session_id,
                            route.task_id,
                            now_wire,
                            now_wire,
                            format_rfc3339_millis(now + timedelta(seconds=_SESSION_LEASE_SECONDS)),
                        ),
                    )

            lease_expires_at = format_rfc3339_millis(now + timedelta(seconds=_LEASE_SECONDS))
            self._db.execute(
                """INSERT INTO start_operations (
                    installation_id, operation_id, request_digest, requested_mode, route_action,
                    state, phase, task_id, session_id, writer_id, lifecycle_event_id,
                    route_generation, route_identity_digest, owner_generation, lease_owner_id,
                    lease_generation, lease_expires_at, response_object_id, response_envelope_digest,
                    terminal_result_canonical, terminal_result_digest, quarantine_code,
                    terminal_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', 'route_reserved', ?, ?, ?, ?, ?, ?, ?, ?, 1,
                    ?, NULL, NULL, NULL, NULL, NULL, NULL, ?, ?)""",
                (
                    self._installation_id,
                    request.operation_id,
                    request.request_digest,
                    request.mode.value,
                    "created" if created else "attached",
                    route.task_id,
                    session_id,
                    proposed[IdKind.WRITER],
                    proposed[IdKind.EVENT],
                    route.route_generation,
                    route.route_identity_digest,
                    str(owner_generation),
                    self._lease_owner_id,
                    lease_expires_at,
                    now_wire,
                    now_wire,
                ),
            )
            inserted = self._operation_by_key(request.operation_id)
            if inserted is None:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _allocation(inserted, "reserved")

    async def yield_lease(self, allocation: StartAllocation) -> None:
        if type(allocation) is not StartAllocation:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)
        with self._transaction():
            row = self._operation_for(allocation)
            self._require_lease(row, allocation, now, self._owner_generation())
            self._db.execute(
                """UPDATE start_operations SET lease_expires_at = ?, updated_at = ?
                   WHERE installation_id = ? AND operation_id = ? AND state = 'pending'
                     AND owner_generation = ? AND lease_owner_id = ?
                     AND lease_generation = ? AND lease_expires_at = ?""",
                (
                    now_wire,
                    now_wire,
                    row.installation_id,
                    row.operation_id,
                    str(row.owner_generation),
                    row.lease_owner_id,
                    row.lease_generation,
                    format_rfc3339_millis(cast(datetime, row.lease_expires_at)),
                ),
            )
            if self._db.changes() != 1:
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)

    async def advance_phase(
        self,
        allocation: StartAllocation,
        phase: StartPhase,
        result: EncryptedResultRef | None = None,
    ) -> StartAllocation:
        if type(allocation) is not StartAllocation or type(phase) is not StartPhase:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        if phase is StartPhase.RESULT_PUBLISHED:
            if type(result) is not EncryptedResultRef:
                raise _error(PublicErrorCode.INTERNAL_ERROR)
        elif result is not None:
            raise _error(PublicErrorCode.INTERNAL_ERROR)
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)
        with self._transaction():
            row = self._operation_for(allocation)
            self._require_lease(row, allocation, now, self._owner_generation())
            if row.phase is phase:
                if result is not None and (
                    row.response_object_id != result.response_object_id
                    or row.response_envelope_digest != result.envelope_digest
                    or row.terminal_result_canonical != result.result_canonical
                    or row.terminal_result_digest != result.result_digest
                ):
                    raise _error(PublicErrorCode.INTERNAL_ERROR)
                return _allocation(row, allocation.outcome)
            if _PHASE_SUCCESSOR.get(row.phase) is not phase:
                raise _error(PublicErrorCode.INTERNAL_ERROR)
            response_object_id = result.response_object_id if result is not None else None
            response_envelope_digest = result.envelope_digest if result is not None else None
            result_canonical = result.result_canonical if result is not None else None
            result_digest = result.result_digest if result is not None else None
            cursor = self._db.execute(
                """UPDATE start_operations SET phase = ?, response_object_id = ?,
                   response_envelope_digest = ?, terminal_result_canonical = ?,
                   terminal_result_digest = ?, updated_at = ?
                   WHERE installation_id = ? AND operation_id = ? AND state = 'pending'
                     AND phase = ? AND owner_generation = ? AND lease_owner_id = ?
                     AND lease_generation = ? AND lease_expires_at = ?""",
                (
                    phase.value,
                    response_object_id,
                    response_envelope_digest,
                    result_canonical,
                    result_digest,
                    now_wire,
                    row.installation_id,
                    row.operation_id,
                    row.phase.value,
                    str(row.owner_generation),
                    row.lease_owner_id,
                    row.lease_generation,
                    format_rfc3339_millis(cast(datetime, row.lease_expires_at)),
                ),
            )
            if cursor.getconnection().changes() != 1:
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            updated = self._operation_by_key(row.operation_id)
            if updated is None:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _allocation(updated, allocation.outcome)

    async def complete(
        self,
        allocation: StartAllocation,
        result: EncryptedResultRef,
        evidence: StartCompletionEvidence,
    ) -> None:
        if (
            type(allocation) is not StartAllocation
            or type(result) is not EncryptedResultRef
            or type(evidence) is not StartCompletionEvidence
        ):
            raise _error(PublicErrorCode.INVALID_REQUEST)
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)
        with self._transaction():
            row = self._operation_for(allocation)
            self._require_lease(row, allocation, now, self._owner_generation())
            if row.phase is not StartPhase.RESULT_PUBLISHED:
                raise _error(PublicErrorCode.INTERNAL_ERROR)
            if (
                row.response_object_id != result.response_object_id
                or row.response_envelope_digest != result.envelope_digest
                or row.terminal_result_canonical != result.result_canonical
                or row.terminal_result_digest != result.result_digest
            ):
                raise _error(PublicErrorCode.INTERNAL_ERROR)
            _validate_completion_evidence(row, result, evidence)
            route = self._require_current_route(row)
            self._require_no_exclusive_maintenance(row.task_id)
            self._db.execute(
                """UPDATE task_routes
                   SET active_session_id = ?, state = 'active', quarantine_code = NULL, updated_at = ?
                   WHERE task_id = ? AND route_generation = ?
                     AND active_route_identity_digest = ?""",
                (
                    row.session_id,
                    now_wire,
                    route.task_id,
                    route.route_generation,
                    route.route_identity_digest,
                ),
            )
            if self._db.changes() != 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            if self._catalog_schema_version >= 4:
                self._db.execute(
                    "UPDATE task_sessions SET health = 'ended', changed_at = ?, ended_at = ?, "
                    "lease_expires_at = NULL WHERE task_id = ? AND session_id != ? "
                    "AND health != 'ended'",
                    (now_wire, now_wire, row.task_id, row.session_id),
                )
                self._db.execute(
                    "UPDATE task_sessions SET health = 'active', changed_at = ?, "
                    "lease_expires_at = ? WHERE task_id = ? AND session_id = ?",
                    (
                        now_wire,
                        format_rfc3339_millis(now + timedelta(seconds=_SESSION_LEASE_SECONDS)),
                        row.task_id,
                        row.session_id,
                    ),
                )
                if self._db.changes() != 1:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
            self._db.execute(
                """UPDATE start_operations SET
                    state = 'complete', phase = 'terminal', owner_generation = NULL,
                    lease_owner_id = NULL, lease_generation = NULL, lease_expires_at = NULL,
                    terminal_result_canonical = ?, terminal_result_digest = ?, terminal_at = ?,
                    updated_at = ?
                   WHERE installation_id = ? AND operation_id = ? AND state = 'pending'
                     AND phase = 'result_published'""",
                (
                    result.result_canonical,
                    result.result_digest,
                    now_wire,
                    now_wire,
                    row.installation_id,
                    row.operation_id,
                ),
            )
            if self._db.changes() != 1:
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)

    async def quarantine(self, allocation: StartAllocation, reason: SafeReason) -> None:
        if type(allocation) is not StartAllocation or type(reason) is not SafeReason:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)
        with self._transaction():
            row = self._operation_for(allocation)
            self._require_lease(row, allocation, now, self._owner_generation())
            route = self._require_current_route(row)
            terminal = _quarantine_envelope(row, reason)
            terminal_digest = f"sha256:{hashlib.sha256(terminal).hexdigest()}"
            if row.route_action == "created" and route.state is TaskRouteState.INITIALIZING:
                self._db.execute(
                    """UPDATE task_routes SET state = 'quarantined', quarantine_code = ?,
                       updated_at = ? WHERE task_id = ? AND state = 'initializing'""",
                    (reason.code, now_wire, route.task_id),
                )
                if self._db.changes() != 1:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
            self._db.execute(
                """UPDATE start_operations SET
                    state = 'quarantined', phase = 'terminal', owner_generation = NULL,
                    lease_owner_id = NULL, lease_generation = NULL, lease_expires_at = NULL,
                    response_object_id = NULL, response_envelope_digest = NULL,
                    terminal_result_canonical = ?, terminal_result_digest = ?, quarantine_code = ?,
                    terminal_at = ?, updated_at = ?
                   WHERE installation_id = ? AND operation_id = ? AND state = 'pending'""",
                (
                    terminal,
                    terminal_digest,
                    reason.code,
                    now_wire,
                    now_wire,
                    row.installation_id,
                    row.operation_id,
                ),
            )
            if self._db.changes() != 1:
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)

    def _transaction(self) -> _Transaction:
        return _Transaction(self._db)

    def _rows(self, sql: str, bindings: tuple[apsw.Binding, ...]) -> list[tuple[object, ...]]:
        cursor = self._db.execute(sql, bindings)
        return [cast(tuple[object, ...], row) for row in cursor]

    def _owner_generation(self) -> int:
        values = self._rows(
            "SELECT key, value FROM catalog_meta WHERE key IN ('installation_id', 'owner_generation')",
            (),
        )
        metadata = {_text(row[0]): _text(row[1]) for row in values if len(row) == 2}
        if metadata.get("installation_id") != self._installation_id:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        try:
            generation = int(metadata["owner_generation"], 10)
        except (KeyError, ValueError) as exc:
            raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
        if generation <= 0:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return generation

    def _operation_by_key(self, operation_id: str) -> _OperationRow | None:
        rows = self._rows(
            f"SELECT {_OPERATION_COLUMNS} FROM start_operations "
            "WHERE installation_id = ? AND operation_id = ? LIMIT 2",
            (self._installation_id, operation_id),
        )
        if not rows:
            return None
        if len(rows) != 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return _operation_from_row(rows[0])

    def _publish_response_by_identity(
        self, key: PublishResponseKey
    ) -> StoredPublishResponse | None:
        rows = self._rows(
            f"""SELECT {_PUBLISH_RESPONSE_COLUMNS} FROM publish_responses
               WHERE writer_id = ? AND request_id = ? AND sink = ? LIMIT 2""",
            (key.writer_id, key.request_id, key.sink.value),
        )
        if not rows:
            return None
        if len(rows) != 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return _publish_response_from_row(rows[0])

    def _operation_for(self, allocation: StartAllocation) -> _OperationRow:
        rows = self._rows(
            f"SELECT {_OPERATION_COLUMNS} FROM start_operations WHERE installation_id = ? "
            "AND task_id = ? AND session_id = ? AND writer_id = ? AND lifecycle_event_id = ? LIMIT 2",
            (
                self._installation_id,
                allocation.task_id,
                allocation.session_id,
                allocation.writer_id,
                allocation.lifecycle_event_id,
            ),
        )
        if len(rows) != 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        row = _operation_from_row(rows[0])
        if not _same_allocation(row, allocation):
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return row

    @staticmethod
    def _commitments_match(
        actual: StartIdentityCommitments,
        expected: StartIdentityCommitments,
    ) -> bool:
        pairs = (
            (actual.title_commitment, expected.title_commitment),
            (actual.workspace_ref_commitment, expected.workspace_ref_commitment),
            (actual.external_ref_commitment, expected.external_ref_commitment),
        )
        return all(
            left is None
            and right is None
            or left is not None
            and right is not None
            and hmac.compare_digest(left, right)
            for left, right in pairs
        )

    def _resolve_requested_route(self, request: StartCommand) -> _RouteRow | None:
        # A handle or self-registration is authenticated by the lineage coordinator before this
        # catalog is called.  Keep the resulting task selector internal and exact: pair/workspace
        # membership is never allowed to discover a route for this path.
        if request.target_task_id is not None:
            target = validate_id(IdKind.TASK, request.target_task_id)
            route = self._route_for_task_id(target)
            if route is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if request.session_id is not None and route.active_session_id != request.session_id:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    safe_details={"reason_code": "selector_conflict"},
                )
            return route
        by_commitment: _RouteRow | None = None
        workspace = request.identity_commitments.workspace_ref_commitment
        external = request.identity_commitments.external_ref_commitment
        if workspace is not None and external is not None:
            rows = self._rows(
                f"SELECT {self._route_columns} FROM task_routes "
                "WHERE workspace_ref_commitment = ? AND external_ref_commitment = ?",
                (workspace, external),
            )
            root_rows = [row for row in rows if _route_from_row(row).parent_task_id is None]
            if len(root_rows) > 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            if root_rows:
                by_commitment = _route_from_row(root_rows[0])
        by_session: _RouteRow | None = None
        if request.session_id is not None:
            by_session = self._route_for_session(request.session_id)
        if by_commitment is not None and by_session is not None:
            if by_commitment.task_id != by_session.task_id:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    safe_details={"reason_code": "selector_conflict"},
                )
            return by_commitment
        if by_session is not None and workspace is not None and by_commitment is None:
            # A host-session rotation may carry the new paired identity together
            # with a selector it already holds. Admit that narrow recovery only
            # while the selector is still active and selects a root in the same workspace;
            # neither the pair nor workspace possession discovers a route.
            workspace_rows = self._rows(
                f"SELECT {self._route_columns} FROM task_routes "
                "WHERE workspace_ref_commitment = ? AND state != 'quarantined'",
                (workspace,),
            )
            root_workspace_rows = [
                row for row in workspace_rows if _route_from_row(row).parent_task_id is None
            ]
            if (
                request.mode is not StartMode.ATTACH
                or request.session_id != by_session.active_session_id
                or by_session.state is TaskRouteState.QUARANTINED
                or by_session.workspace_ref_commitment is None
                or not hmac.compare_digest(by_session.workspace_ref_commitment, workspace)
                or not any(
                    _route_from_row(row).task_id == by_session.task_id
                    for row in root_workspace_rows
                )
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    safe_details={"reason_code": "selector_conflict"},
                )
            pending = self._rows(
                "SELECT 1 FROM start_operations WHERE task_id = ? AND state = 'pending' LIMIT 1",
                (by_session.task_id,),
            )
            if pending:
                # One route rotation at a time. The pending operation owns recovery
                # through its own request id and lease; a second rotation must not
                # reserve against the same predecessor session. Scoped to this
                # recovery admission so an abandoned pending operation never wedges
                # the ordinary same-pair attach that still self-heals the route.
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            return by_session
        if request.session_id is not None and (by_session is None and by_commitment is not None):
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                safe_details={"reason_code": "selector_conflict"},
            )
        return by_commitment or by_session

    def _route_for_session(self, session_id: str) -> _RouteRow | None:
        rows = self._rows(
            f"SELECT {self._route_columns} FROM task_routes WHERE active_session_id = ? LIMIT 2",
            (session_id,),
        )
        if len(rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        if rows:
            return _route_from_row(rows[0])
        op_rows = self._rows(
            "SELECT task_id FROM start_operations WHERE session_id = ? LIMIT 2",
            (session_id,),
        )
        if len(op_rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        if not op_rows:
            return None
        task_id = op_rows[0][0]
        if type(task_id) is not str:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        route_rows = self._rows(
            f"SELECT {self._route_columns} FROM task_routes WHERE task_id = ? LIMIT 2",
            (task_id,),
        )
        if len(route_rows) != 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return _route_from_row(route_rows[0])

    def _writer_for_session(self, session_id: str) -> str | None:
        rows = self._rows(
            "SELECT writer_id FROM start_operations WHERE session_id = ? LIMIT 2",
            (session_id,),
        )
        if len(rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        if not rows:
            return None
        writer_id = rows[0][0]
        if type(writer_id) is not str:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return writer_id

    def _binding_for_route(self, route: _RouteRow) -> SessionBinding | None:
        if route.state is TaskRouteState.QUARANTINED:
            return None
        writer_id = self._writer_for_session(route.active_session_id)
        if writer_id is None:
            return None
        try:
            return SessionBinding(route.task_id, route.active_session_id, writer_id)
        except ValueError as exc:
            raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc

    def _resume_existing(
        self,
        row: _OperationRow,
        request: StartCommand,
        now: datetime,
        now_wire: str,
        owner_generation: int,
    ) -> StartAllocation:
        if not hmac.compare_digest(row.request_digest, request.request_digest):
            raise _error(PublicErrorCode.IDEMPOTENCY_CONFLICT)
        if row.state != "pending":
            if row.terminal_result_canonical is None:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _allocation(row, "replayed")
        if (
            row.owner_generation == owner_generation
            and row.lease_expires_at is not None
            and row.lease_expires_at > now
        ):
            raise _error(
                PublicErrorCode.OPERATION_PENDING,
                retryable=True,
                safe_details={"reason_code": "start_lease_pending"},
            )
        if row.lease_generation is None:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        expires_wire = format_rfc3339_millis(now + timedelta(seconds=_LEASE_SECONDS))
        self._db.execute(
            """UPDATE start_operations SET owner_generation = ?, lease_owner_id = ?,
               lease_generation = ?, lease_expires_at = ?, updated_at = ?
               WHERE installation_id = ? AND operation_id = ? AND state = 'pending'
                 AND owner_generation IS ? AND lease_owner_id IS ? AND lease_generation IS ?
                 AND lease_expires_at IS ?""",
            (
                str(owner_generation),
                self._lease_owner_id,
                row.lease_generation + 1,
                expires_wire,
                now_wire,
                row.installation_id,
                row.operation_id,
                None if row.owner_generation is None else str(row.owner_generation),
                row.lease_owner_id,
                row.lease_generation,
                None
                if row.lease_expires_at is None
                else format_rfc3339_millis(row.lease_expires_at),
            ),
        )
        if self._db.changes() != 1:
            raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
        reclaimed = self._operation_by_key(row.operation_id)
        if reclaimed is None:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return _allocation(reclaimed, "resumed")

    def _require_lease(
        self,
        row: _OperationRow,
        allocation: StartAllocation,
        now: datetime,
        owner_generation: int,
    ) -> None:
        supplied = allocation.lease
        if (
            row.state != "pending"
            or supplied is None
            or row.owner_generation != owner_generation
            or row.owner_generation != supplied.owner_generation
            or row.lease_owner_id != supplied.lease_owner_id
            or row.lease_generation != supplied.lease_generation
            or row.lease_expires_at != supplied.lease_expires_at
            or row.lease_expires_at is None
            or row.lease_expires_at <= now
        ):
            raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)

    def _require_current_route(self, row: _OperationRow) -> _RouteRow:
        rows = self._rows(
            f"SELECT {self._route_columns} FROM task_routes WHERE task_id = ? LIMIT 2",
            (row.task_id,),
        )
        if len(rows) != 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        route = _route_from_row(rows[0])
        if (
            route.route_generation != row.route_generation
            or not hmac.compare_digest(route.route_identity_digest, row.route_identity_digest)
            or route.bundle_relpath != f"tasks/{row.task_id}"
        ):
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return route

    def _require_no_exclusive_maintenance(self, task_id: str) -> None:
        rows = self._rows(
            """SELECT operation_id FROM maintenance_operations
               WHERE task_id = ? AND state = 'pending' AND kind IN ('restore', 'migration')
               LIMIT 1""",
            (task_id,),
        )
        if rows:
            raise _error(
                PublicErrorCode.BUNDLE_BUSY,
                retryable=True,
                safe_details={"reason_code": "catalog_maintenance_busy"},
            )
