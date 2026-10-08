"""Build, store, record, replay, and render one honest receipt."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, replace
from typing import Final, Literal, Protocol, cast

from yoetz.application.ledger_snapshot import projection_for_records
from yoetz.application.unit_of_work import (
    PreparedMutation,
    PreSubmissionCancelled,
    abandon_preappend_objects,
    run_prepared_append,
)
from yoetz.domain.events import (
    CheckRecordedPayload,
    EventDraft,
    EventSchema,
    LedgerRecord,
    ReceiptRecordedPayload,
    encode_payload,
    is_observation_authored,
    media_type_for,
)
from yoetz.domain.receipts import (
    CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP,
    CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP,
    ReceiptDocument,
    ReceiptVersionSlice,
    live_receipt_gap_codes,
    receipt_document_from_json,
    receipt_document_to_json,
    render_receipt_human,
    semantic_coverage_gap_code,
)
from yoetz.domain.values import (
    Actor,
    ActorType,
    Frontier,
    actor_id,
    event_id,
    object_id,
    receipt_id,
    session_id,
    task_id,
    timestamp_from_datetime,
)
from yoetz.kernel.deterministic_checks import CaseGap, build_deterministic_case, case_coverage
from yoetz.kernel.finding_resolution import (
    unverified_resolution_finding_ids,
)
from yoetz.kernel.finding_todo import (
    FindingTodoState,
    duplicate_link_target,
    finding_todo_state,
)
from yoetz.kernel.lineage import evaluate_recorded_lineage
from yoetz.kernel.projections import ProjectionState, observation_limitation_finding_ids
from yoetz.kernel.receipt_builder import (
    CheckSuffixClass,
    ReceiptBuildContext,
    ReceiptFindingState,
    build_receipt,
)
from yoetz.kernel.receipt_capacity import current_receipt_findings
from yoetz.kernel.reducers import (
    invalidates_recorded_check,
    is_material_event_family,
)
from yoetz.observability.logging import (
    record_classified_exception_without_raising,
    record_public_error_without_raising,
)
from yoetz.ports.clock import ClockPort
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.ids import IdPort
from yoetz.ports.ledger import (
    AppendCommand,
    AppendEntry,
    OperationKind,
    OperationRecord,
    OperationState,
)
from yoetz.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectSource,
    StagedObject,
)
from yoetz.ports.runtime import BundleRuntimePort, RouteAccess, RouteCommand, TaskRuntime
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    request_digest,
    strict_json_parse,
)
from yoetz.protocol.coverage import (
    Coverage,
    LedgerFreshness,
    PublicationChannel,
    coverage_for_channel,
    coverage_to_json,
    weakest,
)
from yoetz.protocol.errors import ProtocolValueError, PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind
from yoetz.protocol.models import (
    ReceiptFormat,
    ReceiptInclude,
    ReceiptRedactionProfile,
    ReceiptRequest,
)

__all__ = ["Application", "ReceiptInternalResult", "execute_receipt"]

_RECEIPT_MEDIA_TYPE = "application/vnd.yoetz.receipt+json"
_RECEIPT_REPLAY_MISMATCH_REASONS: Final = frozenset(
    {
        "receipt_conclusion_mismatch",
        "receipt_digest_mismatch",
        "receipt_frontier_mismatch",
        "receipt_id_mismatch",
        "receipt_redaction_profile_mismatch",
    }
)


class Application(Protocol):
    runtime: BundleRuntimePort
    clock: ClockPort
    ids: IdPort

    def receipt_versions_for(self, runtime: TaskRuntime) -> ReceiptVersionSlice: ...


@dataclass(frozen=True, slots=True)
class ReceiptInternalResult:
    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: str
    ok: Literal[True]
    receipt_id: str
    task_id: str
    session_id: str
    subject_frontier: Frontier
    result_frontier: Frontier
    receipt_object_id: str
    receipt_digest: str
    conclusion: str
    redaction_profile: ReceiptRedactionProfile
    format: ReceiptFormat
    include: ReceiptInclude
    document: JsonValue | None
    human_text: str | None
    coverage: Coverage
    suppressed_finding_count: int
    versions: ReceiptVersionSlice

    def as_json(self) -> dict[str, JsonValue]:
        versions = {
            "package_name": self.versions.package_name,
            "package_version": self.versions.package_version,
            "protocol_version": self.versions.protocol_version,
            "engine_version": self.versions.engine_version,
            "projection_version": self.versions.projection_version,
            "object_format_version": self.versions.object_format_version,
            "catalog_schema_version": self.versions.catalog_schema_version,
            "bundle_schema_version": self.versions.bundle_schema_version,
            "policy_versions": tuple(
                {
                    "policy_id": item.policy_id,
                    "policy_version": item.policy_version,
                }
                for item in self.versions.policy_versions
            ),
            "schema_versions": tuple(
                {
                    "schema_id": item.schema_id,
                    "schema_version": item.schema_version,
                }
                for item in self.versions.schema_versions
            ),
            "resource_manifest_digest": self.versions.resource_manifest_digest,
        }
        return {
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "ok": self.ok,
            "receipt_id": self.receipt_id,
            "task_id": self.task_id,
            "session_id": self.session_id,
            "subject_frontier": dict(self.subject_frontier.as_wire().items()),
            "result_frontier": dict(self.result_frontier.as_wire().items()),
            "receipt_object_id": self.receipt_object_id,
            "receipt_digest": self.receipt_digest,
            "conclusion": self.conclusion,
            "redaction_profile": self.redaction_profile.value,
            "format": self.format.value,
            "include": self.include.value,
            "document": self.document,
            "human_text": self.human_text,
            "coverage": coverage_to_json(self.coverage),
            "suppressed_finding_count": self.suppressed_finding_count,
            "versions": cast(JsonValue, versions),
        }


def _error(code: PublicErrorCode, message: str, *, retryable: bool = False) -> PublicOperationError:
    return PublicOperationError(code, message, retryable)


def _classified_storage_error(
    code: PublicErrorCode,
    message: str,
    exc: BaseException,
    *,
    retryable: bool = False,
    request_id: str | None = None,
    operation: str,
    diagnostic_reason: str | None = None,
) -> PublicOperationError:
    """Classify one object-store exception as a public error with a resolvable correlation id."""

    if diagnostic_reason is None:
        correlation_id = record_classified_exception_without_raising(
            exc,
            component="application.receipt",
            operation=operation,
            request_id=request_id,
        )
    else:
        if diagnostic_reason not in _RECEIPT_REPLAY_MISMATCH_REASONS:
            raise ValueError("receipt_diagnostic_reason_invalid") from exc
        # Replay integrity mismatches are application-derived facts, not exception classes. Keep
        # their reason closed and structural while recording the same application-site correlation
        # contract as object-store exceptions.
        correlation_id = record_public_error_without_raising(
            component="application.receipt",
            operation=operation,
            reason=diagnostic_reason,
            request_id=request_id,
        )
    return PublicOperationError(code, message, retryable, correlation_id=correlation_id)


def _version_json(value: ReceiptVersionSlice) -> JsonValue:
    return {
        "package_name": value.package_name,
        "package_version": value.package_version,
        "protocol_version": value.protocol_version,
        "engine_version": value.engine_version,
        "projection_version": value.projection_version,
        "object_format_version": value.object_format_version,
        "catalog_schema_version": value.catalog_schema_version,
        "bundle_schema_version": value.bundle_schema_version,
        "policy_versions": tuple(
            {"policy_id": item.policy_id, "policy_version": item.policy_version}
            for item in value.policy_versions
        ),
        "schema_versions": tuple(
            {"schema_id": item.schema_id, "schema_version": item.schema_version}
            for item in value.schema_versions
        ),
        "resource_manifest_digest": value.resource_manifest_digest,
    }


def _identity(request: ReceiptRequest, versions: ReceiptVersionSlice) -> JsonValue:
    return {
        "protocol_version": request.protocol_version,
        "schema_version": request.schema_version,
        "request_id": request.request_id,
        "task_id": request.task_id,
        "session_id": request.session_id,
        "writer_id": request.writer_id,
        "expected_frontier": request.expected_frontier.model_dump(mode="json"),
        "format": request.format.value,
        "include": request.include.value,
        "redaction_profile": request.redaction_profile.value,
        "actor": {
            "actor_id": request.actor.actor_id,
            "actor_type": request.actor.actor_type.value,
        },
        "client": {
            "integration": request.client.integration.value,
            "kind": request.client.kind.value,
            "version": request.client.version,
        },
        "versions": _version_json(versions),
    }


async def _read_object(
    runtime: TaskRuntime, ref: ObjectRef, *, request_id: str | None = None
) -> bytes:
    try:
        chunks = [chunk async for chunk in runtime.objects.open_verified(ref)]
        data = b"".join(chunks)
    except OSError as exc:
        raise _classified_storage_error(
            PublicErrorCode.STORAGE_UNSAFE,
            "Receipt object storage is unavailable.",
            exc,
            retryable=True,
            request_id=request_id,
            operation="receipt_object_read",
        ) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise _classified_storage_error(
            PublicErrorCode.STORAGE_CORRUPT,
            "The stored receipt is invalid.",
            exc,
            request_id=request_id,
            operation="receipt_object_read",
        ) from exc
    if len(data) != ref.plaintext_size:
        mismatch = ValueError("receipt_object_size_mismatch")
        raise _classified_storage_error(
            PublicErrorCode.STORAGE_CORRUPT,
            "The receipt object is invalid.",
            mismatch,
            request_id=request_id,
            operation="receipt_object_read",
        ) from mismatch
    return data


async def _stage_object(
    runtime: TaskRuntime,
    source: ObjectSource,
    metadata: ObjectMetadata,
    *,
    request_id: str | None = None,
) -> StagedObject:
    try:
        return await runtime.objects.stage(source, metadata)
    except OSError as exc:
        raise _classified_storage_error(
            PublicErrorCode.STORAGE_UNSAFE,
            "Receipt object storage is unavailable.",
            exc,
            retryable=True,
            request_id=request_id,
            operation="receipt_object_persist",
        ) from exc


async def _finalize_object(
    runtime: TaskRuntime,
    staged: StagedObject,
    *,
    request_id: str | None = None,
) -> ObjectRef:
    try:
        return await runtime.objects.finalize(staged)
    except OSError as exc:
        raise _classified_storage_error(
            PublicErrorCode.STORAGE_UNSAFE,
            "Receipt object storage is unavailable.",
            exc,
            retryable=True,
            request_id=request_id,
            operation="receipt_object_persist",
        ) from exc


async def _abandon_preappend_objects(
    runtime: TaskRuntime,
    staged_objects: tuple[StagedObject, ...],
    *,
    request_id: str,
) -> None:
    """Best-effort cleanup for exact stages whose refs were never submitted to the ledger."""
    await abandon_preappend_objects(
        runtime.objects,
        staged_objects,
        component="application.receipt",
        operation="receipt_object_abandon_failed",
        request_id=request_id,
    )


async def _preflight(
    runtime: TaskRuntime, request: ReceiptRequest, digest: str
) -> OperationRecord | None:
    operation = await runtime.ledger.lookup_operation(request.writer_id, request.request_id)
    if operation is None:
        return None
    if operation.request_digest != digest or operation.operation_kind is not OperationKind.RECEIPT:
        raise _error(PublicErrorCode.IDEMPOTENCY_CONFLICT, "The request ID was already used.")
    if operation.state is OperationState.COMPLETE:
        return operation
    if operation.state is OperationState.QUARANTINED:
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The receipt operation is quarantined.")
    raise _error(
        PublicErrorCode.OPERATION_PENDING,
        "The receipt operation is pending.",
        retryable=True,
    )


async def _records_through(
    runtime: TaskRuntime, frontier: Frontier
) -> tuple[tuple[LedgerRecord, ...], ProjectionState]:
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
        # it leaves here as a bounded public error rather than an unbounded internal one.
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The task ledger is unreadable.") from exc
    replayed = Frontier(projection.frontier, projection.head_digest)
    if replayed != frontier:
        # The shared frontier-conflict retry contract: the replayed head is the repair fact, and
        # the flags must match the ledger's own mint for the same request.
        raise PublicOperationError(
            PublicErrorCode.FRONTIER_CONFLICT,
            "The receipt frontier is not current.",
            True,
            safe_details={
                "reason_code": "frontier_changed",
                "sequence": replayed.sequence,
                "head_digest": replayed.head_digest,
            },
        )
    return records, projection


def _finding_states(projection: object) -> tuple[ReceiptFindingState, ...]:
    assert type(projection) is ProjectionState
    # Resolution is proof-based: the projection carries which later qualifying check, if any,
    # proved each current issue absent, and a response disposition never sets it. Reading the
    # shared rule here is what keeps the receipt and ``receipt_blocking_finding_count`` equal.
    states: list[ReceiptFindingState] = []
    for item in current_receipt_findings(projection):
        todo = finding_todo_state(projection, item.finding_id)
        states.append(
            ReceiptFindingState(
                item.finding_id,
                todo is FindingTodoState.VERIFIED_RESOLVED,
                acknowledged_not_done=todo is FindingTodoState.ACKNOWLEDGED_NOT_DONE,
                rejection_accepted=todo is FindingTodoState.REJECTION_ACCEPTED,
                self_verified=todo is FindingTodoState.SELF_VERIFIED,
                disputed_after_rebuttal=todo is FindingTodoState.DISPUTED_AFTER_REBUTTAL,
                # Issue #996: the flags above are derived from the linked earlier finding.
                duplicate_of_finding_id=duplicate_link_target(projection, item.finding_id),
            )
        )
    return tuple(states)


def _check_change_resolution_gaps(
    projection: ProjectionState, finding_states: tuple[ReceiptFindingState, ...]
) -> list[CaseGap]:
    """Disclose resolutions that compared a legacy raising view by length only (R945-02).

    Such a resolution stands, but a receipt never presents it as content-verified. One task-wide
    marker carries the code however many findings it covers, so the disclosure can never exhaust
    the receipt's 64-gap bound; the receipt builder names the affected findings, boundedly.
    """

    affected = unverified_resolution_finding_ids(
        projection, (state.finding_id for state in finding_states if state.resolved)
    )
    if not affected:
        return []
    return [
        CaseGap(
            CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP,
            CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP,
            (),
        )
    ]


def _context(
    projection: object,
    frontier: Frontier,
    case: object,
    records: tuple[LedgerRecord, ...],
) -> ReceiptBuildContext:
    from yoetz.kernel.deterministic_checks import DeterministicCase

    assert type(projection) is ProjectionState
    assert type(case) is DeterministicCase
    applicable: CheckRecordedPayload | None = None
    check_suffix: CheckSuffixClass | None = None
    finding_states = _finding_states(projection)
    gaps = list(case.gaps)
    latest = projection.latest_tested_state
    check_record: LedgerRecord | None = None
    if latest is not None:
        for record in records:
            if record.event_id == latest.source_check_event_id:
                check_record = record
                break
    limitations = observation_limitation_finding_ids(projection, records)
    if latest is None:
        gaps.append(CaseGap("check_not_recorded", "check_not_recorded", ()))
    elif check_record is not None and any(
        invalidates_recorded_check(
            record,
            check_record.ledger.ingestion_sequence,
            latest.returned_finding_ids,
            limitation_finding_ids=limitations,
        )
        for record in records
    ):
        # Applicability follows the material state, not frontier equality: a check applies to
        # this receipt when no material-family event superseded it. Its own events (returned
        # findings plus check_recorded) land atomically right after the tested frontier, so
        # anything later is genuinely newer work, except a response answering a finding the
        # check itself returned, which reports on that check rather than replacing what it read,
        # and an acknowledgement of an observation-authored limitation no check returns (#911).
        gaps.append(CaseGap("check_not_applicable", "check_not_applicable", ()))
    elif check_record is not None and type(check_record.payload) is CheckRecordedPayload:
        applicable = check_record.payload
        later_material = tuple(
            record
            for record in records
            if is_material_event_family(record.schema.name)
            and record.ledger.ingestion_sequence > check_record.ledger.ingestion_sequence
        )
        if later_material:
            # Check-answering responses and finding-free observation-authored records can reach
            # here. The verdict still covers the frontier it tested rather than this one, so the
            # receipt names that frontier instead of reading as though the work were re-checked.
            gaps.append(
                CaseGap(
                    CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP,
                    CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP,
                    (),
                )
            )
            # Classify that suffix for the explanation (issue #657). The applicability rule above
            # already proved every later material record is one of the two attributable kinds, so
            # the class is exact here; it is render context, never a wire field or a gap code.
            observed = any(is_observation_authored(record) for record in later_material)
            responded = any(not is_observation_authored(record) for record in later_material)
            if observed and responded:
                check_suffix = CheckSuffixClass.MIXED
            elif observed:
                check_suffix = CheckSuffixClass.OBSERVATIONS_ONLY
            else:
                check_suffix = CheckSuffixClass.RESPONSES_ONLY
    else:
        gaps.append(
            CaseGap(
                f"check_payload_unavailable:{latest.source_check_event_id}",
                "check_payload_unavailable",
                (latest.source_check_event_id,),
            )
        )
    if applicable is None and not any(
        gap.code in {"check_not_recorded", "check_not_applicable", "check_payload_unavailable"}
        for gap in gaps
    ):
        gaps.append(CaseGap("check_not_recorded", "check_not_recorded", ()))
    if applicable is not None:
        semantic_gap = semantic_coverage_gap_code(
            applicable.semantic_status, applicable.semantic_reason
        )
        if semantic_gap is not None and not any(gap.code == semantic_gap for gap in gaps):
            gaps.append(CaseGap(f"semantic_outcome:{semantic_gap}", semantic_gap, ()))
        for code in applicable.coverage.known_gaps:
            if not any(gap.code == code for gap in gaps):
                gaps.append(CaseGap(f"check_coverage:{code}", code, ()))
    coverage = case_coverage(case)
    if applicable is not None:
        coverage = weakest(coverage, applicable.coverage)
    # Findings are historical material, not merely presentation rows. Observation advice can
    # retain a finding stamped while delivery was stale after the current projection and latest
    # check have recovered. Fold every current retained row before constructing the context so the
    # builder's corruption guard remains strict while the application supplies the honest weakest
    # coverage the receipt document already promises. A resolved row stays in the document as
    # history, but a later qualifying check proved its issue absent, so its coverage no longer
    # lowers the conclusion or adds ``retained_finding_coverage`` gaps (issue #912).
    for state in finding_states:
        if state.resolved:
            continue
        record = projection.findings[state.finding_id]
        assert record.payload is not None
        coverage = weakest(coverage, record.payload.coverage)
    gaps.extend(_check_change_resolution_gaps(projection, finding_states))

    # Lineage is replay-only.  The coordinator may have read live children earlier, but a
    # receipt never does: it evaluates the aggregate manifest events already present in this
    # parent prefix.  When a check applies, evaluate the manifest at the check's subject frontier
    # and retain any later recorded aggregate as an uncovered reference.
    lineage = evaluate_recorded_lineage(
        records,
        tested_through_sequence=(
            None if applicable is None else applicable.subject_frontier.sequence
        ),
        base_coverage=coverage,
    )
    coverage = lineage.coverage
    blocking_children = {
        rollup.child_task_id
        for rollup in lineage.children
        if rollup.blocks_clean_completion and rollup.tested_manifest_ref is not None
    }
    # Pending and informational children are annotations.  Keep their full evaluator gaps in
    # the structured child section, but do not project those gaps into receipt coverage: doing so
    # would turn an explicitly non-blocking relationship into an insufficient-completion result.
    for lineage_gap in lineage.gaps:
        if (
            lineage_gap.child_task_id is not None
            and lineage_gap.child_task_id not in blocking_children
        ):
            continue
        event_ref = lineage_gap.manifest_event_id
        child_ref = "" if lineage_gap.child_task_id is None else str(lineage_gap.child_task_id)
        event_token = "" if event_ref is None else str(event_ref)
        marker = ":".join(
            token for token in ("lineage", lineage_gap.code, child_ref, event_token) if token
        )
        subject_refs = () if event_ref is None else (event_ref,)
        candidate = CaseGap(marker, lineage_gap.code, subject_refs)
        if not any(gap.marker == candidate.marker and gap.code == candidate.code for gap in gaps):
            gaps.append(candidate)

    # ReceiptBuildContext requires exact equality between Coverage.known_gaps and CaseGap codes.
    # Check-derived codes were materialized above; a code introduced only by a retained finding
    # receives one task-global structural marker so many historical findings cannot exhaust the
    # receipt's bounded 64-gap surface.
    represented_codes = {gap.code for gap in gaps}
    retained_only_codes: set[str] = set()
    for code in coverage.known_gaps:
        if code not in represented_codes:
            gaps.append(CaseGap(f"retained_finding_coverage:{code}", code, ()))
            represented_codes.add(code)
            retained_only_codes.add(code)
    ordered_gaps = tuple(
        sorted(
            gaps,
            key=lambda gap: (
                gap.marker.encode("ascii"),
                tuple(ref.encode("ascii") for ref in gap.subject_refs),
            ),
        )
    )
    codes = tuple(sorted({gap.code for gap in ordered_gaps}, key=str.encode))
    if codes != coverage.known_gaps:
        freshness = coverage.ledger_freshness
        if codes and freshness is LedgerFreshness.CURRENT:
            freshness = LedgerFreshness.PARTIAL
        coverage = replace(coverage, ledger_freshness=freshness, known_gaps=codes)
    return ReceiptBuildContext(
        projection,
        frontier,
        case.availability,
        coverage,
        ordered_gaps,
        finding_states,
        applicable,
        lineage,
        check_suffix=check_suffix,
        records=records,
        historical_gaps=_historical_gaps(records, check_record, retained_only_codes),
    )


def _historical_gaps(
    records: tuple[LedgerRecord, ...],
    latest_check: LedgerRecord | None,
    candidates: set[str],
) -> tuple[tuple[str, Frontier], ...]:
    """Name the retained-only gap codes a later recorded check cleared (issue #1017).

    A code reaches the receipt only through a retained finding's coverage when neither the case
    nor the latest check carries it. If an earlier ``check_recorded`` carried it and a later one
    (through the latest tested check) no longer did, a later check cleared it: the receipt keeps
    it as history, cleared at the subject frontier of the first check after the last one that
    carried it. A code no recorded check ever carried stays live. Replay-only and deterministic.
    """

    if (
        not candidates
        or latest_check is None
        or type(latest_check.payload) is not CheckRecordedPayload
    ):
        return ()
    checks = tuple(
        record.payload
        for record in sorted(records, key=lambda record: record.ledger.ingestion_sequence)
        if type(record.payload) is CheckRecordedPayload
        and record.ledger.ingestion_sequence <= latest_check.ledger.ingestion_sequence
    )
    historical: list[tuple[str, Frontier]] = []
    for code in sorted(candidates, key=str.encode):
        carried = [index for index, check in enumerate(checks) if code in check.coverage.known_gaps]
        if not carried or carried[-1] == len(checks) - 1:
            continue
        historical.append((code, checks[carried[-1] + 1].subject_frontier))
    return tuple(historical)


async def _accepted_receipt_event(
    runtime: TaskRuntime, operation: OperationRecord
) -> tuple[LedgerRecord, ObjectRef]:
    locator = operation.result_locator
    if (
        locator is None
        or locator.first_ingestion_sequence is None
        or locator.first_ingestion_sequence != locator.last_ingestion_sequence
        or locator.result_object_ref is None
        or locator.result_object_ref.metadata.kind is not ObjectKind.RECEIPT
    ):
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The receipt locator is invalid.")
    records = tuple(
        [
            record
            async for record in runtime.ledger.load_events(
                runtime.session_id,
                after=locator.first_ingestion_sequence - 1,
                through=locator.first_ingestion_sequence,
            )
        ]
    )
    if len(records) != 1:
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The receipt locator is invalid.")
    record = records[0]
    payload = record.payload
    if (
        type(payload) is not ReceiptRecordedPayload
        or payload.receipt_object_id != locator.result_object_ref.object_id
        or record.schema.name != "receipt_recorded"
    ):
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The receipt locator is invalid.")
    return record, locator.result_object_ref


def _internal_result(
    request: ReceiptRequest,
    document: ReceiptDocument,
    receipt_ref: ObjectRef,
    digest: str,
    result_frontier: Frontier,
) -> ReceiptInternalResult:
    document_json = cast(JsonValue, receipt_document_to_json(document))
    human = (
        None
        if request.format is ReceiptFormat.JSON
        else render_receipt_human(document, markdown=request.format is ReceiptFormat.MARKDOWN)
    )
    return ReceiptInternalResult(
        "0.1",
        document.schema_version,
        request.request_id,
        True,
        str(document.receipt_id),
        str(document.task_id),
        str(document.session_id),
        document.subject_frontier,
        result_frontier,
        receipt_ref.object_id,
        digest,
        document.conclusion.value,
        request.redaction_profile,
        request.format,
        request.include,
        document_json if request.format is ReceiptFormat.JSON else None,
        human,
        # Issue #1017: the result's coverage names live gaps only, so every surface that counts
        # limitations from it skips gaps a later check cleared; the document keeps the full union
        # and marks those gap rows ``historical``.
        replace(document.coverage, known_gaps=live_receipt_gap_codes(document)),
        document.suppressed_finding_count,
        document.versions,
    )


async def _replay_result(
    runtime: TaskRuntime, request: ReceiptRequest, operation: OperationRecord
) -> ReceiptInternalResult:
    record, receipt_ref = await _accepted_receipt_event(runtime, operation)
    payload = cast(ReceiptRecordedPayload, record.payload)
    data = await _read_object(runtime, receipt_ref, request_id=request.request_id)
    try:
        document = receipt_document_from_json(strict_json_parse(data))
    except (TypeError, ValueError) as exc:
        raise _classified_storage_error(
            PublicErrorCode.STORAGE_CORRUPT,
            "The stored receipt is invalid.",
            exc,
            request_id=request.request_id,
            operation="receipt_object_read",
        ) from exc
    digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
    mismatch_reason: str | None = None
    if digest != payload.receipt_digest:
        mismatch_reason = "receipt_digest_mismatch"
    elif str(document.receipt_id) != str(payload.receipt_id):
        mismatch_reason = "receipt_id_mismatch"
    elif document.subject_frontier != payload.subject_frontier:
        mismatch_reason = "receipt_frontier_mismatch"
    elif document.conclusion is not payload.conclusion_code:
        mismatch_reason = "receipt_conclusion_mismatch"
    elif request.redaction_profile is not payload.redaction_profile:
        mismatch_reason = "receipt_redaction_profile_mismatch"
    if mismatch_reason is not None:
        mismatch = ValueError("receipt_replay_integrity_mismatch")
        raise _classified_storage_error(
            PublicErrorCode.STORAGE_CORRUPT,
            "The stored receipt is invalid.",
            mismatch,
            request_id=request.request_id,
            operation="receipt_object_read",
            diagnostic_reason=mismatch_reason,
        ) from mismatch
    return _internal_result(
        request,
        document,
        receipt_ref,
        digest,
        Frontier(record.ledger.ingestion_sequence, record.entry_digest),
    )


async def execute_receipt(app: Application, request: ReceiptRequest) -> ReceiptInternalResult:
    """Freeze an exact case, publish its canonical document, and append one locator event."""

    runtime = await app.runtime.route(
        RouteCommand(
            request.session_id,
            request.writer_id,
            RouteAccess.WRITE,
            frozenset({RuntimeCapability.WRITE, RuntimeCapability.PAYLOAD_READ}),
        )
    )
    try:
        if (
            runtime.task_id != request.task_id
            or runtime.session_id != request.session_id
            or runtime.writer_id != request.writer_id
        ):
            raise _error(PublicErrorCode.SESSION_CONFLICT, "The writer route is inconsistent.")
        import_status = await runtime.importer.status(runtime.session_id)
        if import_status.active_job_count:
            raise _error(
                PublicErrorCode.OPERATION_PENDING,
                "An import is still pending.",
                retryable=True,
            )
        versions = app.receipt_versions_for(runtime)
        logical_digest = request_digest(_identity(request, versions))
        operation = await _preflight(runtime, request, logical_digest)
        if operation is not None:
            return await _replay_result(runtime, request, operation)

        frontier = Frontier(
            int(request.expected_frontier.sequence), request.expected_frontier.head_digest
        )
        records, projection = await _records_through(runtime, frontier)
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
            context = _context(projection, frontier, case, records)
            now = app.clock.now_utc()
            document = build_receipt(
                context,
                receipt_id(app.ids.new(IdKind.RECEIPT)),
                task_id(runtime.task_id),
                session_id(runtime.session_id),
                timestamp_from_datetime(now),
                versions,
                request.redaction_profile,
                request.include,
            )
        except ValueError as exc:
            if isinstance(exc, ProtocolValueError) and exc.reason_code == "invalid_known_gap":
                # A legacy task may predate append-time receipt-capacity admission. Its exact
                # retained union is a representational limit, never a malformed receipt request.
                raise _error(
                    PublicErrorCode.LIMIT_EXCEEDED,
                    "The receipt coverage capacity is exceeded.",
                ) from exc
            # Remaining case/receipt construction failures are a storage or projection
            # inconsistency. Finding citations that name events outside the accepted prefix
            # are represented as missing_ref gaps inside build_deterministic_case and must
            # not reach this path. Do not collapse a classified ledger condition to
            # INTERNAL_ERROR.
            if str(exc) in {
                "deterministic_case_invalid",
                "receipt_build_context_invalid",
                "projection_corrupt",
            }:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The receipt case is unreadable.",
                ) from exc
            raise
        document_json = cast(JsonValue, receipt_document_to_json(document))
        document_bytes = canonical_encode(document_json)
        digest = canonical_digest(document_json)
        staged_objects: tuple[StagedObject, ...] = ()
        try:
            receipt_staged = await _stage_object(
                runtime,
                ObjectSource(data=document_bytes, declared_size=len(document_bytes)),
                ObjectMetadata(ObjectKind.RECEIPT, _RECEIPT_MEDIA_TYPE, runtime.task_id, now),
                request_id=request.request_id,
            )
            staged_objects = (receipt_staged,)
            receipt_ref = await _finalize_object(
                runtime, receipt_staged, request_id=request.request_id
            )
            payload = ReceiptRecordedPayload(
                document.receipt_id,
                frontier,
                digest,
                object_id(receipt_ref.object_id),
                document.conclusion,
                request.redaction_profile,
            )
            draft = EventDraft(
                event_id(app.ids.new(IdKind.EVENT)),
                EventSchema("receipt_recorded", "1.0.0"),
                timestamp_from_datetime(now),
                (),
                payload,
                (object_id(receipt_ref.object_id),),
                (),
            )
            payload_bytes = canonical_encode(encode_payload(payload))
            payload_metadata = ObjectMetadata(
                ObjectKind.EVENT_PAYLOAD,
                media_type_for("receipt_recorded"),
                runtime.task_id,
                now,
            )
            payload_staged = await _stage_object(
                runtime,
                ObjectSource(data=payload_bytes, declared_size=len(payload_bytes)),
                payload_metadata,
                request_id=request.request_id,
            )
            staged_objects = (receipt_staged, payload_staged)
            payload_ref = await _finalize_object(
                runtime, payload_staged, request_id=request.request_id
            )
            coverage = coverage_for_channel(PublicationChannel.ENGINE_DERIVED)
            command = AppendCommand(
                runtime.task_id,
                runtime.session_id,
                cast(str, runtime.writer_id),
                request.request_id,
                OperationKind.RECEIPT,
                logical_digest,
                frontier.sequence,
                (
                    AppendEntry(
                        draft,
                        Actor(
                            actor_id("yoetz.engine"),
                            ActorType.YOETZ_ENGINE,
                            coverage.authorship_assurance,
                        ),
                        payload_ref,
                        payload_ref.commitment,
                        payload_metadata.media_type,
                        payload_ref.plaintext_size,
                        PublicationChannel.ENGINE_DERIVED,
                        coverage,
                        "projected",
                    ),
                ),
                receipt_ref,
            )
            prepared = PreparedMutation(
                cast(str, runtime.writer_id),
                request.request_id,
                logical_digest,
                frontier.sequence,
                (payload_ref, receipt_ref),
                command,
            )
        except BaseException:
            await _abandon_preappend_objects(runtime, staged_objects, request_id=request.request_id)
            raise
        try:
            result = await run_prepared_append(runtime.ledger, prepared)
        except PreSubmissionCancelled:
            # The commit boundary refused the mutation before the ledger coroutine was ever
            # started, so no durable write can reference either object. Every other failure or
            # cancellation from here on leaves an ambiguous commit outcome and must not abandon.
            await _abandon_preappend_objects(runtime, staged_objects, request_id=request.request_id)
            raise
        return _internal_result(request, document, receipt_ref, digest, result.result_frontier)
    except ProtocolValueError as exc:
        raise _error(PublicErrorCode.INVALID_REQUEST, "The receipt request is invalid.") from exc
    finally:
        await app.runtime.release(runtime)
