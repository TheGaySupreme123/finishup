"""Build, store, record, replay, and render one honest receipt."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, replace
from typing import Final, Literal, Protocol, cast

from yoetz.application import closure_basis as _closure_basis
from yoetz.application.ledger_snapshot import projection_for_records
from yoetz.application.unit_of_work import (
    PreparedMutation,
    PreSubmissionCancelled,
    abandon_preappend_objects,
    run_prepared_append,
)
from yoetz.domain.events import (
    EventDraft,
    EventSchema,
    LedgerRecord,
    ReceiptRecordedPayload,
    encode_payload,
    media_type_for,
)
from yoetz.domain.receipts import (
    ReceiptDocument,
    ReceiptVersionSlice,
    live_receipt_gap_codes,
    receipt_document_from_json,
    receipt_document_to_json,
    render_receipt_human,
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
from yoetz.kernel.deterministic_checks import build_deterministic_case
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.receipt_builder import (
    build_receipt,
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
    PublicationChannel,
    coverage_for_channel,
    coverage_to_json,
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

# The receipt context moved to ``application.closure_basis`` so status builds the same one
# (ADR-046); the names the receipt always exposed stay importable from here.
_finding_states = _closure_basis.finding_states
_check_change_resolution_gaps = _closure_basis.check_change_resolution_gaps
_historical_gaps = _closure_basis.historical_gaps
_context = _closure_basis.receipt_context

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
