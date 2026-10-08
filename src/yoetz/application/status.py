"""Bounded read-only status projections at an authenticated stable frontier."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Final, Literal, Protocol, cast

from pydantic import BaseModel

from yoetz.application.check import CheckScope, run_deterministic_policies
from yoetz.application.coordination import CoordinationAdvice
from yoetz.application.ledger_snapshot import projection_for_records
from yoetz.application.projects import ProjectApplication, ProjectCommandError
from yoetz.application.status_faults import (
    StatusFault,
    StatusFaultStage,
    classify_status_fault,
    fault_source,
    status_stage,
)
from yoetz.application.task_views import LineageStatusSnapshot, ProjectStatusSnapshot
from yoetz.domain.findings import FINDING_KIND_TRAITS, FindingOrigin
from yoetz.domain.observation import AdviceSnapshot
from yoetz.domain.privacy import ProjectionItemAuthorship
from yoetz.domain.values import (
    Frontier,
    SemanticContinuation,
    disclosure_continuation,
    format_rfc3339_millis,
    repository_grant_continuation,
    review_input_continuation,
)
from yoetz.kernel.closure_readiness import (
    GAP_CLASSIFICATION_VERSION,
    derive_closure_readiness,
    live_lineage_blockers,
)
from yoetz.kernel.deterministic_checks import (
    DeterministicAssessment,
    build_deterministic_case,
    finding_basis_to_status_json,
)
from yoetz.observability.logging import record_unexpected_exception_without_raising
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.host_lineage import HostLineageRegistryPort
from yoetz.ports.ledger import (
    AssignmentProjectionFilter,
    CheckAdmissionRecord,
    CheckSuspensionKind,
    EvidenceProjectionFilter,
    FindingProjectionPosition,
    FindingsProjectionFilter,
    HistoryProjectionFilter,
    HistoryProjectionPosition,
    IdProjectionPosition,
    ObligationsProjectionFilter,
    OperationKind,
    OperationRecord,
    OperationState,
    ProjectionFilter,
    ProjectionPage,
    ProjectionPosition,
    ProjectionQuery,
    ProjectionView,
    SemanticProgressRecord,
)
from yoetz.ports.runtime import BundleRuntimePort, RouteAccess, RouteCommand, TaskRuntime
from yoetz.ports.start_catalog import StartCatalogPort
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from yoetz.protocol.coverage import (
    ARTIFACT_OBSERVATION_ORDER,
    AUTHORSHIP_ASSURANCE_ORDER,
    EVIDENCE_IMMUTABILITY_ORDER,
    LEDGER_FRESHNESS_ORDER,
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
    coverage_to_json,
)
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import (
    SemanticProgressPhase,
    StatusAdvicePageModel,
    StatusAssignmentFilterModel,
    StatusAssignmentPageModel,
    StatusBlockedObligationModel,
    StatusCandidateFindingItemModel,
    StatusCandidateFindingsFilterModel,
    StatusCandidateFindingsPageModel,
    StatusCheckAdmissionModel,
    StatusClosureReadinessModel,
    StatusCompactItemModel,
    StatusCompactPageModel,
    StatusEvidenceFilterModel,
    StatusEvidencePageModel,
    StatusFilter,
    StatusFindingsFilterModel,
    StatusFindingsPageModel,
    StatusHistoryFilterModel,
    StatusHistoryPageModel,
    StatusImportStatusModel,
    StatusLineagePageModel,
    StatusObligationsFilterModel,
    StatusObligationsPageModel,
    StatusOperationFilterModel,
    StatusOperationPageModel,
    StatusPage,
    StatusProjectPageModel,
    StatusRequest,
    StatusResultsPageModel,
    StatusSemanticProgressModel,
    StatusVersionSliceModel,
    StatusVersionsPageModel,
)
from yoetz.protocol.policy_packs import (
    RESEARCH_EVIDENCE_POLICY_ID,
    WORK_INTEGRITY_POLICY_ID,
    current_policy_pack,
)

__all__ = [
    "Application",
    "StatusInternalResult",
    "execute_status",
    "semantic_progress_wire",
]

_PACKS = (
    current_policy_pack(RESEARCH_EVIDENCE_POLICY_ID),
    current_policy_pack(WORK_INTEGRITY_POLICY_ID),
)
_CURSOR_VERSION = "1"


def _dump_closed_omitting_optional_nulls(model: BaseModel) -> dict[str, JsonValue]:
    """Dump one closed model tree for the internal status body.

    Required nullable leaves (for example ``revision_event_id`` and ``next_cursor``) stay present
    as JSON null. Fields declared in ``optional_non_null_fields`` that are unset are omitted
    entirely — never reintroduced as null — so the closed wire models accept the body.
    """

    dumped = cast(
        dict[str, JsonValue], model.model_dump(mode="json", by_alias=True, exclude_none=False)
    )
    return _strip_optional_non_null_nulls(model, dumped)


def _strip_optional_non_null_nulls(
    model: BaseModel, dumped: Mapping[str, JsonValue]
) -> dict[str, JsonValue]:
    """Drop null leaves that ``optional_non_null_fields`` forbids, recursively."""

    optional_fields: frozenset[str] = frozenset()
    declared = getattr(type(model), "optional_non_null_fields", None)
    if isinstance(declared, frozenset):
        optional_fields = cast(frozenset[str], declared)
    result: dict[str, JsonValue] = {}
    for key, value in dumped.items():
        if key in optional_fields and value is None:
            continue
        attr_name = key
        if key not in type(model).model_fields:
            for name, field in type(model).model_fields.items():
                if field.alias == key:
                    attr_name = name
                    break
        attr: object = getattr(model, attr_name)
        if isinstance(attr, BaseModel) and isinstance(value, Mapping):
            result[key] = cast(
                JsonValue,
                _strip_optional_non_null_nulls(attr, cast(Mapping[str, JsonValue], value)),
            )
            continue
        if (
            isinstance(attr, Sequence)
            and not isinstance(attr, (str, bytes))
            and isinstance(value, list)
        ):
            children = cast(Sequence[object], attr)
            items: list[JsonValue] = []
            for child, child_dump in zip(children, cast(list[JsonValue], value), strict=True):
                if isinstance(child, BaseModel) and isinstance(child_dump, Mapping):
                    items.append(
                        cast(
                            JsonValue,
                            _strip_optional_non_null_nulls(
                                child, cast(Mapping[str, JsonValue], child_dump)
                            ),
                        )
                    )
                else:
                    items.append(child_dump)
            result[key] = items
            continue
        result[key] = value
    return result


class Application(Protocol):
    runtime: BundleRuntimePort
    status_cursor_key: bytes
    start_catalog: StartCatalogPort
    project_application: ProjectApplication | None
    host_lineage_registry: HostLineageRegistryPort | None


@dataclass(frozen=True, slots=True)
class StatusInternalResult:
    protocol_version: str
    schema_version: str
    request_id: str
    ok: bool
    task_id: str
    session_id: str
    writer_id: str
    view: str
    requested_frontier: Frontier
    head_frontier: Frontier
    subject_frontier: Frontier
    result_frontier: Frontier
    projection_lag: int
    projection_version: str
    rebuild_state: str
    page: StatusPage
    coverage: Coverage
    gaps: tuple[str, ...]
    import_status: StatusImportStatusModel
    closure_readiness: StatusClosureReadinessModel
    # Service-read ledger authorship of the page's evidence rows at ``subject_frontier``. It feeds
    # the agent-context provenance decision and is deliberately not part of ``as_json``.
    item_authorship: tuple[ProjectionItemAuthorship, ...] = ()

    def as_json(self) -> dict[str, JsonValue]:
        # Unset optional non-null leaves (today: obligation ``acceptance_criteria``, structural
        # subject-state digests) must be entirely absent from the internal body, never present as
        # explicit null. A blanket ``exclude_none`` would also drop required nullable keys such as
        # ``revision_event_id`` and ``next_cursor``; a blanket ``exclude_unset`` drops defaults
        # that the frozen schema still requires as null. The page dump therefore strips only the
        # fields each closed model lists in ``optional_non_null_fields``.
        return {
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "ok": self.ok,
            "task_id": self.task_id,
            "session_id": self.session_id,
            "writer_id": self.writer_id,
            "view": self.view,
            "requested_frontier": dict(self.requested_frontier.as_wire().items()),
            "head_frontier": dict(self.head_frontier.as_wire().items()),
            "subject_frontier": dict(self.subject_frontier.as_wire().items()),
            "result_frontier": dict(self.result_frontier.as_wire().items()),
            "projection_lag": str(self.projection_lag),
            "projection_version": self.projection_version,
            "rebuild_state": self.rebuild_state,
            "page": cast(JsonValue, _dump_closed_omitting_optional_nulls(self.page)),
            "coverage": coverage_to_json(self.coverage),
            "gaps": self.gaps,
            "import_status": cast(
                JsonValue, _dump_closed_omitting_optional_nulls(self.import_status)
            ),
            "closure_readiness": cast(
                JsonValue, _dump_closed_omitting_optional_nulls(self.closure_readiness)
            ),
        }


def _error(code: PublicErrorCode, message: str) -> PublicOperationError:
    return PublicOperationError(code, message, False)


async def _coordination_advice_status_items(
    app: Application,
    runtime: TaskRuntime,
    coverage: Coverage,
    *,
    limit: int,
) -> tuple[dict[str, JsonValue], ...]:
    """Project currently delivered coordination advice into the ordinary advice page.

    The project application performs the source-consent, recipient-consent, delivery-pair, and
    membership-generation checks.  Status only retains rows addressed to this task and exposes
    structural commitments; counterpart paths and text stay behind the existing project detail
    and disclosure gates.
    """

    project_application = getattr(app, "project_application", None)
    if not isinstance(project_application, ProjectApplication):
        return ()
    list_projects = getattr(project_application.catalog, "list_task_project_ids", None)
    advice_for = getattr(project_application, "coordination_advice_for", None)
    if not callable(list_projects) or not callable(advice_for):
        return ()
    try:
        project_ids = await cast(Callable[[str], Awaitable[tuple[str, ...]]], list_projects)(
            runtime.task_id
        )
    except ProjectCommandError, PublicOperationError:
        return ()
    items: list[dict[str, JsonValue]] = []
    for project_id in sorted(set(project_ids), key=str.encode):
        try:
            rows = await cast(Callable[..., Awaitable[tuple[CoordinationAdvice, ...]]], advice_for)(
                runtime.task_id, project=project_id
            )
        except ProjectCommandError, PublicOperationError:
            continue
        for advice in rows:
            target = getattr(advice, "target_task_id", None)
            if target != runtime.task_id:
                continue
            detection_id = getattr(advice, "detection_id", None)
            project_value = getattr(advice, "project_id", None)
            generation = getattr(advice, "membership_generation", None)
            counterpart = getattr(advice, "counterpart_task_id", None)
            if (
                type(detection_id) is not str
                or type(project_value) is not str
                or type(generation) is not int
                or type(counterpart) is not str
            ):
                continue
            evidence = canonical_digest(cast(JsonValue, advice.as_wire()))
            items.append(
                {
                    # The advice page predates the coordination-specific item shape and uses a
                    # finding-shaped stable identity.  Preserve the detection UUID while changing
                    # only its typed prefix; this is an advice identity, not a recorded finding.
                    "finding_id": "fnd_" + detection_id.removeprefix("evt_"),
                    "rule_code": "coordination_overlap",
                    "priority": 50,
                    "evidence_commitments": (evidence,),
                    "coverage": coverage_to_json(coverage),
                    "freshness_frontier": f"membership_generation:{generation}",
                    "verification_state": "not_required",
                    "semantic_state": "disabled",
                    "recommended_next_action": "review_coordination_advice",
                    "coordination_project_id": project_value,
                    "coordination_detection_id": detection_id,
                    "coordination_membership_generation": str(generation),
                    "coordination_counterpart_task_id": counterpart,
                    "coordination_resource_paths": {
                        "omitted": True,
                        "category": "repository_excerpt",
                        "reason": "local_disclosure_not_authorized",
                    },
                }
            )
    return tuple(items[:limit])


def _task_snapshot_size(snapshot: LineageStatusSnapshot | ProjectStatusSnapshot) -> int:
    if isinstance(snapshot, LineageStatusSnapshot):
        return len(snapshot.children) + len(snapshot.annotations)
    return (
        len(snapshot.members)
        + _task_snapshot_size(snapshot.lineage)
        + len(snapshot.detections)
        + len(snapshot.coverage)
        + len(snapshot.receipts)
    )


def _task_snapshot_page(
    snapshot: LineageStatusSnapshot | ProjectStatusSnapshot,
    offset: int,
    limit: int,
    next_cursor: str | None,
) -> StatusLineagePageModel | StatusProjectPageModel:
    """One shared item budget covers every collection in a task/project response."""

    end = offset + limit
    if isinstance(snapshot, LineageStatusSnapshot):
        count = len(snapshot.children)
        return StatusLineagePageModel(
            parent_task_id=snapshot.parent_task_id,
            children=snapshot.children[offset:end],
            annotations=snapshot.annotations[max(0, offset - count) : max(0, end - count)],
            next_cursor=next_cursor,
        )
    members_end = len(snapshot.members)
    children_end = members_end + len(snapshot.lineage.children)
    annotations_end = children_end + len(snapshot.lineage.annotations)
    detections_end = annotations_end + len(snapshot.detections)
    coverage_end = detections_end + len(snapshot.coverage)
    return StatusProjectPageModel.model_validate(
        {
            **snapshot.metadata,
            "members": snapshot.members[offset:end],
            "lineage": {
                "parent_task_id": snapshot.lineage.parent_task_id,
                "children": snapshot.lineage.children[
                    max(0, offset - members_end) : max(0, end - members_end)
                ],
                "annotations": snapshot.lineage.annotations[
                    max(0, offset - children_end) : max(0, end - children_end)
                ],
                "next_cursor": None,
            },
            "detections": snapshot.detections[
                max(0, offset - annotations_end) : max(0, end - annotations_end)
            ],
            "coverage": snapshot.coverage[
                max(0, offset - detections_end) : max(0, end - detections_end)
            ],
            "receipts": snapshot.receipts[
                max(0, offset - coverage_end) : max(0, end - coverage_end)
            ],
            "next_cursor": next_cursor,
        }
    )


def _filter_json(value: StatusFilter | None) -> JsonValue:
    if value is None:
        return None
    dumped = cast(dict[str, JsonValue], value.model_dump(mode="json", exclude_none=False))
    if type(value) is StatusEvidenceFilterModel and value.author is None:
        # The later ``author`` selector is omitted when unset so a cursor minted before it
        # existed keeps binding to the same filter digest.
        del dumped["author"]
    return cast(JsonValue, dumped)


def _filter_digest(request: StatusRequest) -> str:
    selectors = {
        name: getattr(request, name, None)
        for name in ("task_id", "project_id", "correlation_id")
        if getattr(request, name, None) is not None
    }
    if not selectors:
        return canonical_digest(_filter_json(request.filter))
    return canonical_digest({"filter": _filter_json(request.filter), **selectors})


# A SHA-256 HMAC digest is always exactly 32 bytes, so its unpadded base64url encoding is
# always exactly this many characters -- fixed regardless of content. This lets the cursor
# encode body and signature back-to-back with no separator character, matching the frozen
# wire ``CursorWire`` pattern (``^[A-Za-z0-9_-]+$``), which admits no ``.`` or other delimiter.
_SIGNATURE_B64_LEN: Final = 43


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise _error(PublicErrorCode.INVALID_REQUEST, "The status cursor is invalid.") from exc


def _position_json(position: ProjectionPosition | int | None) -> JsonValue:
    if position is None:
        return None
    if type(position) is int:
        return {"kind": "candidate", "offset": str(position)}
    if type(position) is IdProjectionPosition:
        return {"kind": "id", "last_id": position.last_id}
    if type(position) is HistoryProjectionPosition:
        return {"kind": "history", "sequence": str(position.ingestion_sequence)}
    assert type(position) is FindingProjectionPosition
    return {
        "kind": "finding",
        "priority": position.priority,
        "actionable": position.actionable,
        "artifact_ordinal": position.artifact_ordinal,
        "immutability_ordinal": position.immutability_ordinal,
        "freshness_ordinal": position.freshness_ordinal,
        "authorship_ordinal": position.authorship_ordinal,
        "real_check_present": position.real_check_present,
        "known_gap_count": position.known_gap_count,
        "origin_ordinal": position.origin_ordinal,
        "finding_id": position.finding_id,
    }


def _position_from_json(value: object) -> ProjectionPosition | int | None:
    if value is None:
        return None
    if type(value) is not dict:
        raise ValueError("cursor_position_invalid")
    source = cast(dict[str, object], value)
    kind = source.get("kind")
    if kind == "candidate" and frozenset(source) == frozenset({"kind", "offset"}):
        offset = int(cast(str, source["offset"]))
        if offset < 0:
            raise ValueError("cursor_position_invalid")
        return offset
    if kind == "id" and frozenset(source) == frozenset({"kind", "last_id"}):
        return IdProjectionPosition(cast(str, source["last_id"]))
    if kind == "history" and frozenset(source) == frozenset({"kind", "sequence"}):
        return HistoryProjectionPosition(int(cast(str, source["sequence"])))
    if kind == "finding":
        return FindingProjectionPosition(
            cast(int, source["priority"]),
            cast(bool, source["actionable"]),
            cast(int, source["artifact_ordinal"]),
            cast(int, source["immutability_ordinal"]),
            cast(int, source["freshness_ordinal"]),
            cast(int, source["authorship_ordinal"]),
            cast(bool, source["real_check_present"]),
            cast(int, source["known_gap_count"]),
            cast(int, source["origin_ordinal"]),
            cast(str, source["finding_id"]),
        )
    raise ValueError("cursor_position_invalid")


def _encode_cursor(
    app: Application,
    request: StatusRequest,
    frontier: Frontier,
    projection_version: str,
    position: ProjectionPosition | int,
) -> str:
    body = canonical_encode(
        {
            "v": _CURSOR_VERSION,
            "session_id": request.session_id,
            "view": request.view,
            "filter_digest": _filter_digest(request),
            "frontier": frontier.as_wire(),
            "projection_version": projection_version,
            "limit": request.limit,
            "position": _position_json(position),
        }
    )
    signature = hmac.new(app.status_cursor_key, body, hashlib.sha256).digest()
    encoded_signature = _b64(signature)
    assert len(encoded_signature) == _SIGNATURE_B64_LEN
    return f"{_b64(body)}{encoded_signature}"


def _decode_cursor(
    app: Application, request: StatusRequest
) -> tuple[Frontier, str, ProjectionPosition | int] | None:
    if request.cursor is None:
        return None
    if type(app.status_cursor_key) is not bytes or len(app.status_cursor_key) < 32:
        raise _error(PublicErrorCode.SERVICE_UNAVAILABLE, "Status pagination is unavailable.")
    try:
        if len(request.cursor) <= _SIGNATURE_B64_LEN:
            raise ValueError("cursor_shape_invalid")
        body_part = request.cursor[:-_SIGNATURE_B64_LEN]
        signature_part = request.cursor[-_SIGNATURE_B64_LEN:]
        body = _unb64(body_part)
        signature = _unb64(signature_part)
        expected = hmac.new(app.status_cursor_key, body, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("cursor_signature_invalid")
        raw = strict_json_parse(body)
        if type(raw) is not dict:
            raise ValueError("cursor_shape_invalid")
        source = cast(dict[str, object], raw)
        if (
            source.get("v") != _CURSOR_VERSION
            or source.get("session_id") != request.session_id
            or source.get("view") != request.view
            or source.get("filter_digest") != _filter_digest(request)
            or source.get("limit") != request.limit
        ):
            raise ValueError("cursor_binding_invalid")
        frontier_raw = cast(dict[str, object], source["frontier"])
        frontier = Frontier(
            int(cast(str, frontier_raw["sequence"])),
            cast(str, frontier_raw["head_digest"]),
        )
        position = _position_from_json(source["position"])
        if position is None:
            raise ValueError("cursor_position_invalid")
        return frontier, cast(str, source["projection_version"]), position
    except PublicOperationError:
        raise
    except Exception as exc:
        raise _error(PublicErrorCode.INVALID_REQUEST, "The status cursor is invalid.") from exc


def _port_filter(value: StatusFilter | None) -> ProjectionFilter | None:
    if value is None:
        return None
    if type(value) is StatusAssignmentFilterModel:
        return AssignmentProjectionFilter(value.actor_id, value.include_resolved)
    if type(value) is StatusObligationsFilterModel:
        return ObligationsProjectionFilter(value.actor_id, value.include_resolved, value.status)
    if type(value) is StatusFindingsFilterModel:
        return FindingsProjectionFilter(
            value.origin, value.priority, value.disposition, value.include_resolved
        )
    if type(value) is StatusEvidenceFilterModel:
        return EvidenceProjectionFilter(
            value.strength, value.freshness, value.include_unavailable, value.author
        )
    if type(value) is StatusHistoryFilterModel:
        return HistoryProjectionFilter(
            value.schema_name,
            value.actor_id,
            None if value.after_sequence is None else int(value.after_sequence),
        )
    if type(value) is StatusOperationFilterModel:
        # Operation recovery is ledger-operation keyed, not a projection row query.
        raise ValueError("status_filter_invalid")
    raise ValueError("status_filter_invalid")


def _mapping(value: JsonValue) -> dict[str, JsonValue]:
    if type(value) is not dict:
        raise ValueError("status_operation_result_invalid")
    source = cast(dict[str, object], value)
    if any(type(key) is not str for key in source):
        raise ValueError("status_operation_result_invalid")
    return cast(dict[str, JsonValue], source)


async def _operation_continuation(
    runtime: TaskRuntime,
    operation: OperationRecord,
) -> dict[str, JsonValue] | None:
    """Rebuild the continuation for one suspended check from durable state.

    Recovery must never depend on the caller having kept the original result, and it must never
    require reading Yoetz's storage by hand. A ledger without the wait API, or any fault reading
    it, simply yields no continuation: recovery is best-effort enrichment and must not turn a
    readable operation page into an error.
    """

    operation_request_id = operation.operation_id
    load = getattr(runtime.ledger, "load_disclosure_wait", None)
    continuation: SemanticContinuation | None = None
    if operation.suspension_kind is CheckSuspensionKind.REPOSITORY_GRANT:
        continuation = repository_grant_continuation(request_id=operation_request_id)
    elif operation.suspension_kind is CheckSuspensionKind.REVIEW_INPUT:
        continuation = review_input_continuation(request_id=operation_request_id)
    elif load is not None:
        try:
            wait = await load(operation.writer_id, operation_request_id)
        except Exception:
            wait = None
        if wait is not None and getattr(wait, "state", None) == "awaiting":
            try:
                continuation = disclosure_continuation(
                    pending_id=wait.pending_id,
                    expires_at=wait.pending_expires_at,
                    request_id=operation_request_id,
                )
            except TypeError, ValueError:
                continuation = None
    if continuation is None:
        return None
    result: dict[str, JsonValue] = {
        "kind": continuation.kind,
        "command": continuation.command,
        "replay_request_id": continuation.request_id,
        "instruction": continuation.instruction,
    }
    if continuation.pending_id is not None:
        result["pending_id"] = continuation.pending_id
    if continuation.expires_at is not None:
        result["expires_at"] = continuation.expires_at.wire
    return result


def semantic_progress_wire(
    record: SemanticProgressRecord, observed_at: datetime
) -> dict[str, JsonValue]:
    """Project one durable progress record onto the bounded structural wire (issue #571 A2).

    Durations are derived here, at one service observation time, so every rendering of the same
    page agrees. Only closed phase/outcome/reason values, an ordinal, and service timestamps leave.
    """

    if type(record) is not SemanticProgressRecord or type(observed_at) is not datetime:
        raise ValueError("status_semantic_progress_invalid")
    observed = observed_at.replace(microsecond=observed_at.microsecond // 1000 * 1000)

    def _ms(start: datetime, end: datetime) -> int:
        return max(0, int((end - start).total_seconds() * 1000))

    terminal = record.phase is SemanticProgressPhase.TERMINAL
    wire: dict[str, JsonValue] = {
        "phase": record.phase.value,
        "attempt_ordinal": str(record.attempt_ordinal),
        "queued_at": format_rfc3339_millis(record.queued_at),
        "phase_entered_at": format_rfc3339_millis(record.phase_entered_at),
        "deadline_at": format_rfc3339_millis(record.deadline_at),
        "observed_at": format_rfc3339_millis(observed),
        "elapsed_ms": str(_ms(record.queued_at, record.phase_entered_at if terminal else observed)),
    }
    if terminal:
        assert record.terminal_outcome is not None and record.terminal_reason is not None
        wire["condition"] = "terminal"
        wire["terminal_outcome"] = record.terminal_outcome
        wire["terminal_reason"] = record.terminal_reason.value
    else:
        remaining = _ms(observed, record.deadline_at)
        wire["remaining_ms"] = str(remaining)
        wire["condition"] = "active" if remaining > 0 else "overdue"
    return wire


async def _operation_semantic_progress(
    app: Application, runtime: TaskRuntime, operation: object | None
) -> dict[str, JsonValue] | None:
    """Read best-effort structural progress for one check operation; never fail recovery."""

    if (
        type(operation) is not OperationRecord
        or operation.operation_kind is not OperationKind.CHECK
        or operation.state not in {OperationState.PENDING, OperationState.COMPLETE}
    ):
        return None
    load = getattr(runtime.ledger, "load_semantic_progress", None)
    if not callable(load):
        return None
    try:
        record = await cast(Callable[[str, str], Awaitable[SemanticProgressRecord | None]], load)(
            operation.writer_id, operation.operation_id
        )
        if record is None:
            return None
        clock = getattr(app, "clock", None)
        now = clock.now_utc() if clock is not None else datetime.now(UTC)
        wire = semantic_progress_wire(record, now)
        StatusSemanticProgressModel.model_validate(wire)
        return wire
    except Exception as exc:  # noqa: BLE001 - progress enriches recovery, never blocks it
        record_unexpected_exception_without_raising(
            exc,
            component="application.status",
            operation="status_semantic_progress_unavailable",
            request_id=operation.operation_id,
        )
        return None


async def _operation_semantic_withheld_items(
    runtime: TaskRuntime, operation: object | None
) -> tuple[dict[str, JsonValue], ...] | None:
    """Recover withheld opaque identities from the completed check event, when present."""

    if (
        type(operation) is not OperationRecord
        or operation.operation_kind is not OperationKind.CHECK
        or operation.state is not OperationState.COMPLETE
        or operation.result_locator is None
        or operation.result_locator.first_ingestion_sequence is None
        or operation.result_locator.last_ingestion_sequence is None
    ):
        return None
    locator = operation.result_locator
    first_sequence = locator.first_ingestion_sequence
    last_sequence = locator.last_ingestion_sequence
    if first_sequence is None or last_sequence is None:
        return None
    event_ids = frozenset(locator.structural_ids)
    try:
        records = [
            record
            async for record in runtime.ledger.load_events(
                runtime.session_id,
                after=first_sequence - 1,
                through=last_sequence,
            )
        ]
        for record in records:
            if str(record.event_id) not in event_ids:
                continue
            if getattr(record.schema, "name", None) != "check_recorded":
                continue
            payload = getattr(record, "payload", None)
            raw_item_ids = getattr(payload, "semantic_withheld_item_ids", ())
            if type(raw_item_ids) is not tuple or not raw_item_ids:
                return None
            raw_items = cast(tuple[object, ...], raw_item_ids)
            if any(type(item_id) is not str for item_id in raw_items):
                return None
            item_ids = cast(tuple[str, ...], raw_items)
            return tuple(
                {"item_id": item_id, "reason": "never_send_heuristic"} for item_id in item_ids
            )
    except Exception as exc:  # noqa: BLE001 - status enrichment must never block recovery
        record_unexpected_exception_without_raising(
            exc,
            component="application.status",
            operation="status_semantic_withheld_items_unavailable",
            request_id=operation.operation_id,
        )
    return None


def check_admission_wire(
    record: CheckAdmissionRecord, observed_at: datetime
) -> dict[str, JsonValue]:
    """Project one transient admission record onto the bounded structural wire (issue #838).

    Only the closed stage, a count, service timestamps, and durations derived at one service
    observation time leave; the page never names another request or any payload.
    """

    if type(record) is not CheckAdmissionRecord or type(observed_at) is not datetime:
        raise ValueError("status_check_admission_invalid")
    observed = observed_at.replace(microsecond=observed_at.microsecond // 1000 * 1000)
    first = record.first_observed_at
    last = record.last_observed_at
    observed = max(observed, last)
    return {
        "stage": record.stage.value,
        "refusal_count": str(record.refusal_count),
        "first_observed_at": format_rfc3339_millis(first),
        "last_observed_at": format_rfc3339_millis(last),
        "observed_at": format_rfc3339_millis(observed),
        "elapsed_ms": str(max(0, int((observed - first).total_seconds() * 1000))),
        "retry_after_ms": str(record.retry_after_ms),
    }


async def _operation_admission(
    app: Application, runtime: TaskRuntime, writer_id: str, operation_request_id: str
) -> dict[str, JsonValue] | None:
    """Read best-effort pre-admission state for an absent check request; never fail recovery."""

    lookup = getattr(runtime.ledger, "lookup_check_admission", None)
    if not callable(lookup):
        return None
    try:
        record = await cast(Callable[[str, str], Awaitable[CheckAdmissionRecord | None]], lookup)(
            writer_id, operation_request_id
        )
        if record is None:
            return None
        clock = getattr(app, "clock", None)
        now = clock.now_utc() if clock is not None else datetime.now(UTC)
        wire = check_admission_wire(record, now)
        StatusCheckAdmissionModel.model_validate(wire)
        return wire
    except Exception as exc:  # noqa: BLE001 - admission enriches recovery, never blocks it
        record_unexpected_exception_without_raising(
            exc,
            component="application.status",
            operation="status_check_admission_unavailable",
            request_id=operation_request_id,
        )
        return None


def _operation_page_from_record(
    operation_request_id: str,
    operation: object | None,
    continuation: Mapping[str, JsonValue] | None = None,
    semantic_progress: Mapping[str, JsonValue] | None = None,
    semantic_withheld_items: tuple[Mapping[str, JsonValue], ...] | None = None,
    admission: Mapping[str, JsonValue] | None = None,
) -> StatusOperationPageModel:
    """Project one operation record into the recovery page, or a bounded not-found page.

    Every exit is either a validated page or ``ValueError``. Attribute and type faults on a
    stored record (corrupt shape, missing enum members) collapse to the same bounded error so
    the operation status branch never raises an unbounded exception into the daemon. An absent
    page carries ``admission`` only when a check under this exact key was refused before
    admission or is being admitted right now (issue #838).
    """

    if operation is None:
        absent: dict[str, JsonValue] = {
            "operation_request_id": operation_request_id,
            "found": False,
            "state": "absent",
        }
        if admission is not None:
            absent["admission"] = cast(JsonValue, dict(admission))
        return StatusOperationPageModel.model_validate(absent)
    from yoetz.ports.ledger import OperationRecord as _OperationRecord

    try:
        if type(operation) is not _OperationRecord:
            raise ValueError("status_operation_result_invalid")
        record = operation
        kind = record.operation_kind.value
        if record.state is OperationState.PENDING:
            pending: dict[str, JsonValue] = {
                "operation_request_id": operation_request_id,
                "found": True,
                "state": "pending",
                "operation_kind": kind,
            }
            # Only a suspended check has one; it is what makes recovery possible after the
            # original result scrolled away or the context was compacted.
            if continuation is not None and kind == "check":
                pending["continuation"] = cast(JsonValue, dict(continuation))
            if semantic_progress is not None and kind == "check":
                pending["semantic_progress"] = cast(JsonValue, dict(semantic_progress))
            return StatusOperationPageModel.model_validate(pending)
        if record.state is OperationState.QUARANTINED:
            return StatusOperationPageModel.model_validate(
                {
                    "operation_request_id": operation_request_id,
                    "found": True,
                    "state": "quarantined",
                    "operation_kind": kind,
                }
            )
        if record.state is not OperationState.COMPLETE or record.result_canonical is None:
            raise ValueError("status_operation_result_invalid")
        # Only publish_work stores the AppendResult shape used here. Other complete kinds surface
        # without accepted-event detail so recovery stays bounded and honest.
        if record.operation_kind is not OperationKind.PUBLISH_WORK:
            complete: dict[str, JsonValue] = {
                "operation_request_id": operation_request_id,
                "found": True,
                "state": "complete",
                "operation_kind": kind,
            }
            if semantic_progress is not None and kind == "check":
                complete["semantic_progress"] = cast(JsonValue, dict(semantic_progress))
            if semantic_withheld_items is not None and kind == "check":
                complete["semantic_withheld_items"] = cast(
                    JsonValue, tuple(dict(item) for item in semantic_withheld_items)
                )
            return StatusOperationPageModel.model_validate(complete)
        source = _mapping(strict_json_parse(record.result_canonical))
        accepted_raw = source["accepted"]
        if type(accepted_raw) is not tuple and type(accepted_raw) is not list:
            raise ValueError("status_operation_result_invalid")
        accepted = tuple(
            {
                "event_id": cast(str, item["event_id"]),
                "entry_digest": cast(str, item["entry_digest"]),
                "ingestion_sequence": cast(str, item["ingestion_sequence"]),
                "writer_sequence": cast(str, item["writer_sequence"]),
                "projection_status": cast(str, item["projection_status"]),
            }
            for item in (
                _mapping(cast(JsonValue, value))
                for value in cast(tuple[object, ...] | list[object], accepted_raw)
            )
        )
        subject = cast(dict[str, object], source["subject_frontier"])
        result = cast(dict[str, object], source["result_frontier"])
        return StatusOperationPageModel.model_validate(
            {
                "operation_request_id": operation_request_id,
                "found": True,
                "state": "complete",
                "operation_kind": "publish_work",
                "outcome": "accepted",
                "subject_frontier": {
                    "sequence": cast(str, subject["sequence"]),
                    "head_digest": cast(str, subject["head_digest"]),
                },
                "result_frontier": {
                    "sequence": cast(str, result["sequence"]),
                    "head_digest": cast(str, result["head_digest"]),
                },
                "accepted_events": accepted,
            }
        )
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("status_operation_result_invalid") from exc


async def _exact_frontier(runtime: TaskRuntime, sequence: int | None) -> tuple[Frontier, Frontier]:
    stored = await runtime.ledger.load_projection(runtime.session_id, ProjectionView.COMPACT)
    if stored is None:
        head = Frontier.genesis()
    else:
        head = stored.frontier
    target = head.sequence if sequence is None else sequence
    if target > head.sequence:
        # Status is a read-only query: a requested sequence beyond the observed head is invalid
        # query input, never a stale optimistic mutation guard. See
        # See the status error mapping in docs/INTERFACES.md.
        raise _error(PublicErrorCode.INVALID_REQUEST, "The requested frontier is in the future.")
    if target == head.sequence:
        return head, head
    if target == 0:
        return Frontier.genesis(), head
    found: Frontier | None = None
    async for record in runtime.ledger.load_events(runtime.session_id, through=target):
        found = Frontier(record.ledger.ingestion_sequence, record.entry_digest)
    if found is None or found.sequence != target:
        raise PublicOperationError(
            PublicErrorCode.FRONTIER_CONFLICT,
            (
                "The requested frontier is unavailable. Call status to read the current frontier, "
                "then retry idempotently with the same request_id."
            ),
            True,
            safe_details={
                "reason_code": "frontier_changed",
                "sequence": head.sequence,
                "head_digest": head.head_digest,
            },
        )
    return found, head


def _finding_attempt_budget(app: Application) -> int | None:
    """The owner's per-item review-round budget, when this application carries one (#905)."""

    policy = getattr(app, "verification_policy", None)
    budget = getattr(policy, "finding_attempt_budget", None)
    return budget if type(budget) is int else None


def _page_model(
    page: ProjectionPage, next_cursor: str | None, *, attempt_budget: int | None = None
) -> StatusPage:
    value: dict[str, object] = {"items": page.items, "next_cursor": next_cursor}
    if page.view == "findings" and attempt_budget is not None:
        value["attempt_budget"] = str(attempt_budget)
    constructors = {
        "assignment": StatusAssignmentPageModel,
        "compact": StatusCompactPageModel,
        "evidence": StatusEvidencePageModel,
        "findings": StatusFindingsPageModel,
        "history": StatusHistoryPageModel,
        "obligations": StatusObligationsPageModel,
        "results": StatusResultsPageModel,
        "versions": StatusVersionsPageModel,
    }
    return constructors[page.view].model_validate(value)


def _candidate_rank(item: DeterministicAssessment, ordinal: int) -> tuple[object, ...]:
    candidate = item.candidate
    coverage = candidate.coverage
    priority, actionable = FINDING_KIND_TRAITS[candidate.kind]
    real_check = int(
        CheckType.DETERMINISTIC in coverage.check_types
        or CheckType.SEMANTIC_MODEL_DERIVED in coverage.check_types
    )
    return (
        priority,
        -int(actionable),
        -ARTIFACT_OBSERVATION_ORDER[coverage.artifact_observation],
        -EVIDENCE_IMMUTABILITY_ORDER[coverage.evidence_immutability],
        -LEDGER_FRESHNESS_ORDER[coverage.ledger_freshness],
        -AUTHORSHIP_ASSURANCE_ORDER[coverage.authorship_assurance],
        -real_check,
        len(coverage.known_gaps),
        int(candidate.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED),
        ordinal,
    )


async def _candidate_page(
    app: Application,
    request: StatusRequest,
    runtime: TaskRuntime,
    frontier: Frontier,
    head: Frontier,
    offset: int,
) -> tuple[StatusPage, Coverage, tuple[str, ...], str | None]:
    records = tuple(
        [
            record
            async for record in runtime.ledger.load_events(
                runtime.session_id, through=frontier.sequence
            )
        ]
    )
    try:
        projection = await projection_for_records(
            runtime.ledger, runtime.session_id, frontier, records
        )
    except ValueError as exc:
        # Replay is genesis-anchored; a chain it rejects is a storage fact, not an engine bug, so
        # it leaves here as a bounded public error rather than an unbounded internal one. The
        # status boundary records its class and origin under the public correlation id.
        raise StatusFault(StatusFaultStage.REPLAY, "The task ledger is unreadable.") from exc
    if Frontier(projection.frontier, projection.head_digest) != frontier:
        with status_stage(StatusFaultStage.REPLAY, "The status frontier is inconsistent."):
            raise ValueError("status_frontier_inconsistent")
    availability = await runtime.ledger.load_case_availability(
        runtime.session_id, frontier, projection
    )
    try:
        case = await asyncio.to_thread(
            build_deterministic_case,
            projection,
            records,
            availability,
            _projection_validated=True,
        )
    except ValueError as exc:
        if str(exc) == "deterministic_case_invalid":
            raise StatusFault(StatusFaultStage.REPLAY, "The status case is unreadable.") from exc
        raise
    assessments, _ = run_deterministic_policies(case, CheckScope((), ()), _PACKS)
    indexed = tuple(enumerate(assessments))
    ordered = tuple(
        item
        for _, item in sorted(indexed, key=lambda row: _candidate_rank(row[1], row[0]))
        if type(request.filter) is not StatusCandidateFindingsFilterModel
        or request.filter.priority is None
        or item.candidate.priority == request.filter.priority
    )
    limit = int(request.limit)
    selected = ordered[offset : offset + limit]
    with status_stage(StatusFaultStage.MODEL):
        items = tuple(
            StatusCandidateFindingItemModel.model_validate(
                {
                    "kind": item.candidate.kind.value,
                    "origin": "deterministic",
                    "priority": item.candidate.priority,
                    "summary": item.candidate.summary,
                    "detail": item.candidate.detail,
                    "subject_refs": item.candidate.subject_refs,
                    "policy_id": item.candidate.policy_id,
                    "policy_version": item.candidate.policy_version,
                    "subject_frontier": dict(item.candidate.subject_frontier.as_wire().items()),
                    "coverage": coverage_to_json(item.candidate.coverage),
                    "basis": finding_basis_to_status_json(item),
                }
            )
            for item in selected
        )
    next_offset = offset + len(selected)
    next_cursor = (
        _encode_cursor(app, request, frontier, runtime.projection_version, next_offset)
        if next_offset < len(ordered)
        else None
    )
    from yoetz.application.check import case_coverage

    coverage = case_coverage(case)
    return (
        StatusCandidateFindingsPageModel(items=items, next_cursor=next_cursor),
        coverage,
        coverage.known_gaps,
        next_cursor,
    )


async def _import_status(runtime: TaskRuntime) -> StatusImportStatusModel:
    snapshot = await runtime.importer.status(runtime.session_id)
    phase: (
        Literal[
            "plan_ready",
            "publishing",
            "report_published",
            "report_ready",
            "source_reserved",
            "terminal",
        ]
        | None
    ) = None
    report_evidence_id: str | None = None
    identity: str | None = None
    if snapshot.active_jobs:
        active = snapshot.active_jobs[0]
        phase = cast(
            Literal[
                "plan_ready",
                "publishing",
                "report_published",
                "report_ready",
                "source_reserved",
            ],
            active["phase"],
        )
        identity = cast(str, active["identity_digest"])
    elif snapshot.terminal_report_locators:
        terminal = snapshot.terminal_report_locators[0]
        phase = "terminal"
        report_evidence_id = cast(str, terminal["report_evidence_id"])
        identity = cast(str, terminal["identity_digest"])
    return StatusImportStatusModel(
        pending_count=str(snapshot.active_job_count),
        terminal_count=str(snapshot.terminal_job_count),
        phase=phase,
        report_evidence_id=report_evidence_id,
        source_identity_digest=identity,
    )


def _unknown_structural_coverage() -> Coverage:
    """Honest coverage when a structural recovery path cannot load a projection page."""

    return Coverage(
        publication_channels=(PublicationChannel.LOCAL_CLI,),
        authorship_assurance=AuthorshipAssurance.SELF_ASSERTED,
        artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.UNKNOWN,
        check_types=(CheckType.NONE,),
        known_gaps=(),
    )


def _readiness_unknown() -> StatusClosureReadinessModel:
    # Unknown is never "nothing to do": the one checklist entry is to read status again once the
    # projection can be read.
    return StatusClosureReadinessModel(
        declared_obligation_count=None,
        no_obligations_reason=None,
        open_obligation_count=None,
        unanswered_finding_count=None,
        receipt_blocking_finding_count=None,
        blocking_conditions=("readiness_unknown",),
        state="unknown",
        gap_classification_version=GAP_CLASSIFICATION_VERSION,
        agent_actionable=("readiness_unknown",),
        standing_limitations=(),
        acknowledged_not_done=(),
        acknowledged_not_done_count="0",
        blocked_obligations=(),
    )


def _semantic_review_required(
    app: object, route_profile: Literal["policy", "strict"] | None
) -> bool:
    """True only when the serving route can and must run AI-powered review.

    That is the one route on which ``semantic_review_not_requested`` stays agent-actionable
    (ADR-032). A composition without a verification policy never makes it actionable. A strict
    MCP process never dispatches AI-powered review (ADR-018; ``execute_check`` requests the
    semantic capability only on the policy route), so there the missing review is a route-side
    limitation the owner lifts by serving the policy route, not something the agent can do.
    Callers without a route (CLI, TUI, closure preparation) check on the policy route.
    """

    if route_profile == "strict":
        return False
    policy = getattr(app, "verification_policy", None)
    return getattr(policy, "semantic", None) == "required"


async def _closure_readiness(
    runtime: TaskRuntime,
    frontier: Frontier,
    compact_page: ProjectionPage | None = None,
    request_id: str | None = None,
    *,
    lineage_gaps: tuple[str, ...] = (),
    semantic_review_required: bool = False,
    check_in_flight: bool = False,
    lineage_self_verified: bool = False,
) -> StatusClosureReadinessModel:
    """Derive what currently bounds a completion conclusion, from the compact projection.

    Computed on every view so an agent never has to switch views — or spend a check and a receipt
    — to learn that the record cannot yet support a completion claim. This reads only: it creates
    no task-ledger consequence and changes no coverage. Its one write is the owner-only bounded
    diagnostic below, emitted when the page it is handed has an unexpected shape.

    ``view=compact`` already loads exactly this page, so it passes it in rather than paying for a
    second identical query. Compact admits no filter or position, so the page is equivalent.

    Because it runs on *every* view, it is also the one enrichment that can strand every view at
    once. It is therefore total over the page it is handed: an unexpected page shape degrades to
    ``readiness_unknown`` — the same honest answer a lagging projection already produces — and
    leaves a bounded diagnostic, rather than raising into the daemon as an unbounded internal
    error on a read that changed nothing.

    The checklist split (ADR-032) is derived here, per request, from the page's own gaps and
    readiness facts; nothing about it is cached across frontiers or recorded.
    """

    if compact_page is not None:
        page = compact_page
    else:
        try:
            page = await runtime.ledger.query_projection(
                ProjectionQuery(
                    runtime.session_id,
                    "compact",
                    None,
                    frontier,
                    1,
                    None,
                    None,
                )
            )
        except PublicOperationError:
            # Secondary enrichment only: do not fail a structural status page because the
            # compact projection is lagging, rebuilding, or temporarily unreadable.
            return _readiness_unknown()
    try:
        item = page.items[0] if page.items else None
        if type(item) is not StatusCompactItemModel:
            # Compact omits its singleton when the task title is unreadable. Counting that as
            # zero open obligations would manufacture a clean record out of missing data.
            return _readiness_unknown()
        if item.declared_obligation_count is None or item.open_obligation_count is None:
            return _readiness_unknown()
        declared_obligations = int(item.declared_obligation_count)
        open_obligations = int(item.open_obligation_count)
        # "Is this finding still unanswered" has one source: the compact row's count from
        # yoetz.kernel.projections.unanswered_finding_count. Readiness never recounts findings.
        unanswered_findings = int(item.unanswered_finding_count)
        receipt_blocking_findings = int(item.receipt_blocking_finding_count)
        has_plan = item.current_plan_event_id is not None
        no_obligations_reason = item.no_obligations_reason
        stale = page.rebuild_state != "current" or bool(page.lag)
        # Recorded gaps (the ones a receipt folds) are classified; live lineage tokens that no
        # recorded evaluation carries yet cannot be promised as receipt disclosures (#913).
        gap_markers = tuple(page.gaps)
        live_blockers = live_lineage_blockers(lineage_gaps, gap_markers)
        declared_gaps = bool(gap_markers or lineage_gaps)
        facts = page.readiness_facts
        if facts is None:
            # Without the per-request facts readiness cannot tell whether a check applies or an
            # item was acknowledged; "done" would be manufactured out of missing data.
            return _readiness_unknown()
    except (AttributeError, IndexError, TypeError, ValueError) as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="application.status",
            operation="status_closure_readiness_page_invalid",
            request_id=request_id,
        )
        return _readiness_unknown()
    blocking: list[str] = []
    if open_obligations:
        blocking.append("obligations_open")
    if unanswered_findings:
        blocking.append("findings_unanswered")
    if receipt_blocking_findings:
        blocking.append("receipt_findings_unresolved")
    if not has_plan:
        blocking.append("no_plan_published")
    elif declared_obligations == 0 and no_obligations_reason is None:
        blocking.append("no_obligations_declared")
    if stale:
        blocking.append("projection_stale")
    if declared_gaps:
        blocking.append("coverage_gaps_declared")
    checklist = derive_closure_readiness(
        blocking,
        gap_markers,
        facts,
        semantic_review_required=semantic_review_required,
        check_in_flight=check_in_flight,
        live_blockers=live_blockers,
        lineage_self_verified=lineage_self_verified,
    )
    confirmations = dict(facts.blocked_obligation_confirmations)
    return StatusClosureReadinessModel(
        declared_obligation_count=str(declared_obligations),
        no_obligations_reason=no_obligations_reason,
        open_obligation_count=str(open_obligations),
        unanswered_finding_count=str(unanswered_findings),
        receipt_blocking_finding_count=str(receipt_blocking_findings),
        state=checklist.state,
        gap_classification_version=GAP_CLASSIFICATION_VERSION,
        agent_actionable=checklist.agent_actionable,
        standing_limitations=checklist.standing_limitations,
        acknowledged_not_done=checklist.acknowledged_not_done,
        acknowledged_not_done_count=str(checklist.acknowledged_not_done_count),
        acknowledged_obligation_count=str(len(facts.acknowledged_obligation_ids)),
        blocked_obligations=tuple(
            StatusBlockedObligationModel(
                obligation_id=obligation,
                blocker_kind=cast(
                    Literal["authority", "consent", "credential", "dependency_unavailable"], kind
                ),
                decision_event_id=decision,
                # #985: a claimed blocker is still agent work until a later decision confirms it.
                confirmation="confirmed" if obligation in confirmations else "claimed",
                **(
                    {"confirmation_event_id": confirmations[obligation]}
                    if obligation in confirmations
                    else {}
                ),
            )
            for obligation, kind, decision in facts.blocked_obligation_details[:64]
        ),
        # F3: what a whole-task completion claim must name in limitation_refs (ids only).
        limitation_refs_required=tuple(facts.limitation_refs_required[:64]),
        limitation_refs_required_count=str(len(facts.limitation_refs_required)),
        blocking_conditions=cast(
            tuple[
                Literal[
                    "obligations_open",
                    "findings_unanswered",
                    "receipt_findings_unresolved",
                    "no_plan_published",
                    "no_obligations_declared",
                    "readiness_unknown",
                    "projection_stale",
                    "coverage_gaps_declared",
                ],
                ...,
            ],
            tuple(blocking),
        ),
    )


async def _check_in_flight(runtime: TaskRuntime) -> bool:
    """True while a check holds this session's frontier (issue #913).

    Readiness must not say "nothing further to do" while a check's result — and any finding it
    returns — is still to come. A ledger that cannot answer is treated as in flight.
    """

    probe = getattr(runtime.ledger, "has_active_frozen_case", None)
    if not callable(probe):
        return True
    try:
        return bool(await cast(Callable[[str], Awaitable[bool]], probe)(runtime.session_id))
    except Exception:  # noqa: BLE001 - a secondary read; unknown is reported as in flight
        return True


async def _task_coverage(
    runtime: TaskRuntime,
    frontier: Frontier,
    raw_page: ProjectionPage,
) -> tuple[ProjectionPage | None, Coverage, tuple[str, ...]]:
    """Return the compact page and its task coverage for a non-compact projection view.

    A compact page that cannot be read leaves the view's own page coverage in place, but never
    lets it read cleaner than unknown freshness: the task fold was not available to bound it.
    """

    try:
        compact = await runtime.ledger.query_projection(
            ProjectionQuery(runtime.session_id, "compact", None, frontier, 1, None, None)
        )
        return compact, compact.coverage, compact.gaps
    except PublicOperationError:
        # Lagging, rebuilding or temporarily unreadable, exactly as closure readiness treats it.
        return (
            None,
            replace(raw_page.coverage, ledger_freshness=LedgerFreshness.UNKNOWN),
            raw_page.gaps,
        )


async def _lineage_readiness_gaps(
    app: Application, runtime: TaskRuntime, frontier: Frontier, request_id: str
) -> tuple[tuple[str, ...], bool]:
    """Compare accepted catalog children with recorded facts without opening child bundles.

    These are current advisory gaps only. Checks and receipts still replay service-stamped
    manifests, and this read never refreshes one or awards verification to a live catalog row.
    """

    from yoetz.application.task_views import lineage_status_page

    try:
        if not await app.start_catalog.list_child_task_ids(runtime.task_id):
            return (), False
        snapshot = await lineage_status_page(app.start_catalog, runtime, frontier)
        accepted = tuple(child for child in snapshot.children if child.acceptance == "accepted")
        # Issue #984/#996 (S2): an accepted child with self-verified findings keeps the parent
        # receipt at best insufficient_coverage, so readiness discloses it as standing.
        return (
            tuple(sorted({gap for child in accepted for gap in child.blocking_conditions})),
            any(child.self_verified_finding_count is not None for child in accepted),
        )
    except Exception as exc:
        # A secondary read must neither strand operation recovery nor turn an unreadable
        # dependency inventory into an apparently clean parent. Record the original under any
        # stage marker so the class and origin still name the defect.
        record_unexpected_exception_without_raising(
            fault_source(exc),
            component="application.status",
            operation="status_lineage_readiness_unavailable",
            request_id=request_id,
        )
        return ("lineage_readiness_unavailable",), False


async def execute_status(
    app: Application,
    request: StatusRequest,
    *,
    route_profile: Literal["policy", "strict"] | None = None,
) -> StatusInternalResult:
    """Return one typed status page without creating a task-ledger consequence."""

    if route_profile not in {None, "policy", "strict"}:
        raise TypeError("status_route_profile_invalid")
    decoded = _decode_cursor(app, request)
    runtime = await app.runtime.route(
        RouteCommand(
            request.session_id,
            request.writer_id,
            RouteAccess.PAYLOAD_READ,
            frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}),
        )
    )
    try:
        if runtime.session_id != request.session_id or runtime.writer_id != request.writer_id:
            raise _error(PublicErrorCode.SESSION_CONFLICT, "The writer route is inconsistent.")
        if decoded is None:
            frontier, head = await _exact_frontier(
                runtime, None if request.at_frontier is None else int(request.at_frontier)
            )
            expected_version: str | None = None
            position: ProjectionPosition | int | None = None
        else:
            frontier, expected_version, position = decoded
            exact, head = await _exact_frontier(runtime, frontier.sequence)
            if exact != frontier:
                raise _error(PublicErrorCode.INVALID_REQUEST, "The status cursor is invalid.")
            if request.at_frontier is not None and int(request.at_frontier) != frontier.sequence:
                raise _error(PublicErrorCode.INVALID_REQUEST, "The status cursor is invalid.")

        result_view = request.view
        import_status = await _import_status(runtime)
        item_authorship: tuple[ProjectionItemAuthorship, ...] = ()
        compact_page: ProjectionPage | None = None
        if request.view == "operation":
            if position is not None:
                raise _error(PublicErrorCode.INVALID_REQUEST, "The status cursor is invalid.")
            if type(request.filter) is not StatusOperationFilterModel:
                raise _error(PublicErrorCode.INVALID_REQUEST, "The status filter is invalid.")
            if request.cursor is not None:
                raise _error(PublicErrorCode.INVALID_REQUEST, "The status cursor is invalid.")
            operation = await runtime.ledger.lookup_task_operation(
                request.writer_id, request.filter.operation_request_id
            )
            continuation = None
            if (
                operation is not None
                and getattr(operation, "state", None) is OperationState.PENDING
                and getattr(operation, "operation_kind", None) is OperationKind.CHECK
            ):
                continuation = await _operation_continuation(
                    runtime,
                    operation,
                )
            semantic_progress = await _operation_semantic_progress(app, runtime, operation)
            semantic_withheld_items = await _operation_semantic_withheld_items(runtime, operation)
            admission = (
                await _operation_admission(
                    app, runtime, request.writer_id, request.filter.operation_request_id
                )
                if operation is None
                else None
            )
            try:
                page = _operation_page_from_record(
                    request.filter.operation_request_id,
                    operation,
                    continuation=continuation,
                    semantic_progress=semantic_progress,
                    semantic_withheld_items=semantic_withheld_items,
                    admission=admission,
                )
            except (AttributeError, TypeError, ValueError) as exc:
                raise StatusFault(
                    StatusFaultStage.REPLAY, "The stored operation result is invalid."
                ) from exc
            # Operation recovery is structural: the operation page is authoritative. Compact
            # projection only enriches coverage/closure/frontiers and must not fail recovery
            # when lagging, rebuilding, or missing.
            #
            # Totality: capture frontier/head-derived enrichment first, then optionally replace
            # from a successful compact page. Every path that reaches StatusInternalResult has
            # head, effective, lag, projection_version, and rebuild_state bound — the shape of
            # the run-4 AttributeError was an unbound/stale local on a recovery path.
            structural_head = head
            structural_effective = frontier
            structural_lag = structural_head.sequence - frontier.sequence
            structural_version = runtime.projection_version
            compact_page = None
            coverage = _unknown_structural_coverage()
            gaps: tuple[str, ...] = ()
            head = structural_head
            effective = structural_effective
            lag = structural_lag
            projection_version = structural_version
            rebuild_state: Literal["current", "rebuild_required", "rebuilding"] = "rebuild_required"
            try:
                raw_page = await runtime.ledger.query_projection(
                    ProjectionQuery(
                        runtime.session_id,
                        ProjectionView.COMPACT.value,
                        None,
                        frontier,
                        1,
                        None,
                        expected_version,
                    )
                )
            except PublicOperationError:
                pass
            else:
                try:
                    next_coverage = raw_page.coverage
                    next_gaps = raw_page.gaps
                    next_head = raw_page.head_frontier
                    next_effective = raw_page.effective_frontier
                    next_lag = raw_page.lag
                    next_version = raw_page.projection_version
                    next_rebuild = raw_page.rebuild_state
                except AttributeError as exc:
                    # Unexpected page shape. Recovery still succeeds on the structural defaults
                    # already bound above — the operation page is authoritative and enrichment is
                    # secondary — but degrading silently would discard the only signal that the
                    # compact projection is returning something it should not. Record the bounded
                    # reason so the next occurrence is diagnosable instead of invisible.
                    record_unexpected_exception_without_raising(
                        exc,
                        component="application.status",
                        operation="status_operation_compact_enrichment_invalid",
                        request_id=request.request_id,
                    )
                else:
                    compact_page = raw_page
                    coverage = next_coverage
                    gaps = next_gaps
                    head = next_head
                    effective = next_effective
                    lag = next_lag
                    projection_version = next_version
                    rebuild_state = next_rebuild
        elif request.view == "advice":
            if position is not None:
                raise _error(PublicErrorCode.INVALID_REQUEST, "The status cursor is invalid.")
            raw_page = await runtime.ledger.query_projection(
                ProjectionQuery(
                    runtime.session_id,
                    ProjectionView.COMPACT.value,
                    None,
                    frontier,
                    1,
                    None,
                    expected_version,
                )
            )
            # The advice view derives from the same compact page closure readiness needs.
            compact_page = raw_page
            snapshot: AdviceSnapshot | None = None
            if runtime.observation is not None:
                workspace = None
                lookup = getattr(runtime.observation, "workspace_for_yoetz_session", None)
                if callable(lookup):
                    workspace = lookup(runtime.session_id)
                if type(workspace) is str:
                    session_load = getattr(
                        runtime.observation, "load_advice_snapshot_for_session", None
                    )
                    if callable(session_load):
                        loaded = session_load(
                            workspace=workspace, yoetz_session_id=runtime.session_id
                        )
                        snapshot = loaded if isinstance(loaded, AdviceSnapshot) else None
                    else:
                        loaded = runtime.observation.load_advice_snapshot(workspace)
                        snapshot = loaded if isinstance(loaded, AdviceSnapshot) else None
            items: tuple[dict[str, JsonValue], ...] = ()
            if snapshot is not None:
                advice = snapshot
                verification_state = (
                    "stale"
                    if "verification_stale" in advice.confidence_coverage.known_gaps
                    else (
                        "unavailable"
                        if "policy_untrusted" in advice.confidence_coverage.known_gaps
                        else "current"
                    )
                )
                items = tuple(
                    {
                        "finding_id": str(item.finding_id),
                        "rule_code": item.rule_code,
                        "priority": item.priority,
                        "evidence_commitments": tuple(
                            sorted(
                                {
                                    advice.evidence_basis_digest,
                                    *(
                                        ref
                                        for ref in item.evidence_refs
                                        if ref.startswith(("sha256:", "hmac-sha256:"))
                                    ),
                                },
                                key=str.encode,
                            )
                        ),
                        "coverage": coverage_to_json(item.coverage),
                        "freshness_frontier": item.freshness_frontier,
                        "verification_state": verification_state,
                        "semantic_state": advice.semantic_attempt_state,
                        "recommended_next_action": item.recommended_next_action,
                    }
                    for item in advice.ranked_items[: int(request.limit)]
                )
            coordination_items = await _coordination_advice_status_items(
                app,
                runtime,
                raw_page.coverage,
                limit=max(0, min(int(request.limit), 64 - len(items))),
            )
            items = (*items, *coordination_items)
            page = StatusAdvicePageModel.model_validate(
                {
                    "projection_format": "yoetz.advice-snapshot/1",
                    "items": items,
                    "next_cursor": None,
                }
            )
            coverage = snapshot.confidence_coverage if snapshot is not None else raw_page.coverage
            gaps = (
                snapshot.confidence_coverage.known_gaps if snapshot is not None else raw_page.gaps
            )
            head = raw_page.head_frontier
            effective = raw_page.effective_frontier
            lag = raw_page.lag
            projection_version = raw_page.projection_version
            rebuild_state = raw_page.rebuild_state
        elif request.view == "lineage" or request.view == "project":
            from yoetz.application.task_views import lineage_status_page, project_status_snapshot

            if frontier != head:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Current task views require the current task frontier.",
                )
            if position is not None and type(position) is not int:
                raise _error(PublicErrorCode.INVALID_REQUEST, "The status cursor is invalid.")
            if request.view == "lineage":
                if request.task_id is not None and request.task_id != runtime.task_id:
                    raise _error(
                        PublicErrorCode.SESSION_CONFLICT, "The task selector is inconsistent."
                    )
                full_page = await lineage_status_page(
                    app.start_catalog,
                    runtime,
                    frontier,
                    host_lineage_registry=app.host_lineage_registry,
                    correlation_id=request.correlation_id,
                )
            else:
                if app.project_application is None:
                    raise _error(
                        PublicErrorCode.SERVICE_UNAVAILABLE, "Project status is unavailable."
                    )
                full_page = await project_status_snapshot(
                    app.project_application,
                    app.start_catalog,
                    app.runtime,
                    runtime,
                    frontier,
                    selected_task_id=request.task_id,
                    project_id=request.project_id,
                    host_lineage_registry=app.host_lineage_registry,
                    correlation_id=request.correlation_id,
                    request_id=request.request_id,
                )
            if isinstance(full_page, LineageStatusSnapshot):
                result_view = "lineage"
            with status_stage(StatusFaultStage.DIGEST):
                snapshot_identity = canonical_digest(cast(JsonValue, full_page.as_wire()))
            if expected_version is not None and expected_version != snapshot_identity:
                raise _error(PublicErrorCode.INVALID_REQUEST, "The task view cursor is stale.")
            offset = position or 0
            limit = int(request.limit)
            next_offset = offset + limit
            next_cursor = (
                _encode_cursor(app, request, frontier, snapshot_identity, next_offset)
                if next_offset < _task_snapshot_size(full_page)
                else None
            )
            with status_stage(StatusFaultStage.MODEL):
                page = _task_snapshot_page(full_page, offset, limit, next_cursor)
            effective = frontier
            lag = 0
            projection_version = runtime.projection_version
            rebuild_state = "current"
            compact_page = await runtime.ledger.query_projection(
                ProjectionQuery(runtime.session_id, "compact", None, frontier, 1, None, None)
            )
            coverage = compact_page.coverage
            view_gaps = (
                full_page.known_gaps
                if isinstance(full_page, LineageStatusSnapshot)
                else full_page.gaps
            )
            gaps = tuple(sorted(set(compact_page.gaps) | set(view_gaps)))
        elif request.view == "candidate_findings":
            if position is not None and type(position) is not int:
                raise _error(PublicErrorCode.INVALID_REQUEST, "The status cursor is invalid.")
            page, coverage, gaps, _ = await _candidate_page(
                app, request, runtime, frontier, head, position or 0
            )
            effective = frontier
            lag = head.sequence - frontier.sequence
            projection_version = runtime.projection_version
            rebuild_state = "current"
        else:
            if type(position) is int:
                raise _error(PublicErrorCode.INVALID_REQUEST, "The status cursor is invalid.")
            try:
                query = ProjectionQuery(
                    runtime.session_id,
                    request.view,
                    _port_filter(request.filter),
                    frontier,
                    int(request.limit),
                    cast(ProjectionPosition | None, position),
                    expected_version,
                    runtime.writer_id,
                )
            except (TypeError, ValueError) as exc:
                # The one remaining caller-shape stage: this view, filter, and cursor position do
                # not form a projection query. Every later failure is service-owned.
                raise _error(
                    PublicErrorCode.INVALID_REQUEST, "The status request is invalid."
                ) from exc
            raw_page = await runtime.ledger.query_projection(query)
            if request.view == "compact":
                compact_page = raw_page
            item_authorship = tuple(
                ProjectionItemAuthorship(f"/page/items/{index}", sources)
                for index, sources in enumerate(raw_page.item_sources)
                if sources
            )
            next_cursor = (
                None
                if raw_page.next_position is None
                else _encode_cursor(
                    app,
                    request,
                    frontier,
                    raw_page.projection_version,
                    raw_page.next_position,
                )
            )
            with status_stage(StatusFaultStage.MODEL):
                page = _page_model(
                    raw_page, next_cursor, attempt_budget=_finding_attempt_budget(app)
                )
            if route_profile is not None and type(page) is StatusVersionsPageModel:
                page = StatusVersionsPageModel(
                    items=tuple(
                        StatusVersionSliceModel.model_validate(
                            {
                                **item.model_dump(mode="json", exclude_none=True),
                                "route_profile": route_profile,
                            }
                        )
                        for item in page.items
                    ),
                    next_cursor=None,
                )
            coverage = raw_page.coverage
            gaps = raw_page.gaps
            if compact_page is None:
                # One coverage definition on every view (issue #913): the envelope reports the
                # task's coverage — the compact fold of the applicable check over the newest
                # record — not the newest record's own envelope, which routinely read
                # `service_authenticated / current / 0 gaps` beside a partial task. The compact
                # page is the one closure readiness reads, so it is fetched once for both.
                compact_page, coverage, gaps = await _task_coverage(runtime, frontier, raw_page)
            head = raw_page.head_frontier
            effective = raw_page.effective_frontier
            lag = raw_page.lag
            projection_version = raw_page.projection_version
            rebuild_state = raw_page.rebuild_state
        lineage_gaps, lineage_self_verified = await _lineage_readiness_gaps(
            app, runtime, frontier, request.request_id
        )
        if lineage_gaps:
            gaps = tuple(sorted(set(gaps) | set(lineage_gaps)))
            coverage = replace(
                coverage,
                known_gaps=tuple(sorted(set(coverage.known_gaps) | set(lineage_gaps))),
                ledger_freshness=(
                    LedgerFreshness.PARTIAL
                    if coverage.ledger_freshness is LedgerFreshness.CURRENT
                    else coverage.ledger_freshness
                ),
            )
        closure_readiness = await _closure_readiness(
            runtime,
            frontier,
            compact_page,
            request.request_id,
            lineage_gaps=lineage_gaps,
            lineage_self_verified=lineage_self_verified,
            semantic_review_required=_semantic_review_required(app, route_profile),
            check_in_flight=frontier == head and await _check_in_flight(runtime),
        )
        return StatusInternalResult(
            "0.1",
            "1.0.0",
            request.request_id,
            True,
            runtime.task_id,
            runtime.session_id,
            cast(str, runtime.writer_id),
            result_view,
            frontier,
            head,
            effective,
            effective,
            lag,
            projection_version,
            rebuild_state,
            page,
            coverage,
            gaps,
            import_status,
            closure_readiness,
            item_authorship,
        )
    except (StatusFault, TypeError, ValueError) as exc:
        # The request passed schema validation and every caller-shape rejection above is explicit,
        # so a fault reaching here is stored state or the service's own projection. Reporting it
        # as INVALID_REQUEST sent agents to repair a valid request and discarded the evidence
        # (issue #840); classify it and join the public correlation id to the bounded origin.
        raise classify_status_fault(exc, view=request.view, request_id=request.request_id) from exc
    finally:
        await app.runtime.release(runtime)
