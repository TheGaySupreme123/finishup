"""Crash-safe import orchestration and bounded recorded-evidence review support."""

from __future__ import annotations

import base64
import binascii
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from finishup.application.check import Application as CheckApplication
from finishup.application.check import check_internal_json, execute_check
from finishup.application.publish_work import PublishWorkInternalResult, execute_publish_work
from finishup.domain.events import PAYLOAD_TYPES, EventDraft, EventPayload, encode_payload
from finishup.domain.values import (
    Frontier,
    JsonObject,
    RequestId,
    SessionId,
    WriterId,
    frontier_from_json,
    object_id,
    request_id,
    session_id,
    task_id,
    timestamp_from_datetime,
    validate_sha256_digest,
    writer_id,
)
from finishup.domain.values import (
    JsonValue as DomainJsonValue,
)
from finishup.ports.clock import ClockPort
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.importer import (
    CapturedImportSource,
    EncryptedImportReportRef,
    ImportAllocation,
    ImportAllocationOutcome,
    ImportByteSource,
    ImportCaptureInput,
    ImportCommand,
    ImportLineStatus,
    ImportPhase,
    ImportReviewSource,
    ImportSourceIdentity,
    ImportState,
)
from finishup.ports.ledger import (
    AcceptedEventSummary,
    AppendResult,
    AppendWarning,
    CheckCommitResult,
    OperationKind,
    OperationState,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
from finishup.ports.runtime import BundleRuntimePort, RouteAccess, RouteCommand, TaskRuntime
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.coverage import (
    Coverage,
    PublicationChannel,
    coverage_from_json,
    coverage_to_json,
    weakest,
)
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import (
    CheckRequestModel,
    PublishWorkRequestModel,
)

__all__ = [
    "Application",
    "ImportCodexJsonlRequest",
    "ImportReportInternal",
    "ReviewCounts",
    "ReviewRequest",
    "ReviewInternal",
    "execute_import_codex_jsonl",
    "execute_review",
    "import_request_from_control",
]

_MAPPING_VERSION = "codex-jsonl/1.0.0"
_SCHEMA_VERSION = "1.0.0"
_REPORT_MEDIA_TYPE = "application/vnd.yoetz.import_report+json"


def _error(
    code: PublicErrorCode,
    message: str,
    *,
    retryable: bool = False,
    safe_details: object | None = None,
) -> PublicOperationError:
    return PublicOperationError(code, message, retryable, safe_details=safe_details)


def _sorted_digests(values: tuple[str, ...], *, maximum: int) -> tuple[str, ...]:
    if not 1 <= len(values) <= maximum:
        raise ValueError("import_review_selection_invalid")
    for value in values:
        validate_sha256_digest(value)
    if values != tuple(sorted(set(values), key=str.encode)):
        raise ValueError("import_review_selection_invalid")
    return values


@dataclass(frozen=True, slots=True, repr=False)
class ImportCodexJsonlRequest:
    """Application request after control-boundary base64 decoding."""

    schema_version: Literal["1.0.0"]
    codex_capability_profile_id: str
    codex_version: str
    exit_status: int
    mapping_version: str
    request_id: RequestId
    session_id: SessionId
    source: ImportByteSource
    source_kind: Literal["file", "stdin"]
    stderr_captured_bytes: Literal[0]
    stderr_present: Literal[False]
    stderr_truncated: Literal[False]
    writer_id: WriterId

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or type(self.codex_capability_profile_id) is not str
            or not 1 <= len(self.codex_capability_profile_id) <= 128
            or type(self.codex_version) is not str
            or not 5 <= len(self.codex_version) <= 128
            or type(self.exit_status) is not int
            or not -1 <= self.exit_status <= 255
            or self.mapping_version != _MAPPING_VERSION
            or not hasattr(self.source, "__aiter__")
            or not hasattr(self.source, "close")
            or self.source_kind not in {"file", "stdin"}
            or self.stderr_captured_bytes != 0
            or self.stderr_present is not False
            or self.stderr_truncated is not False
        ):
            raise ValueError("import_request_invalid")
        object.__setattr__(self, "request_id", request_id(self.request_id))
        object.__setattr__(self, "session_id", session_id(self.session_id))
        object.__setattr__(self, "writer_id", writer_id(self.writer_id))

    def __repr__(self) -> str:
        return "ImportCodexJsonlRequest(<redacted>)"

    __str__ = __repr__


class _ControlImportByteSource:
    def __init__(self, value: bytes) -> None:
        self._value = value
        self._closed = False

    @property
    def declared_size(self) -> int:
        return len(self._value)

    async def _chunks(self) -> AsyncIterator[bytes]:
        if not self._closed:
            yield self._value

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self._chunks()

    async def close(self) -> None:
        self._closed = True


def import_request_from_control(value: object) -> ImportCodexJsonlRequest:
    """Decode the already schema-bounded control body without retaining its base64 copy."""

    if not isinstance(value, Mapping):
        raise _error(PublicErrorCode.INVALID_REQUEST, "The import request is invalid.")
    source = cast(Mapping[str, object], value)
    try:
        if source["source_encoding"] != "base64":
            raise ValueError("import_source_encoding_invalid")
        encoded = source["source_bytes_base64"]
        if type(encoded) is not str:
            raise ValueError("import_source_encoding_invalid")
        raw = base64.b64decode(encoded, validate=True)
        return ImportCodexJsonlRequest(
            schema_version=cast(Literal["1.0.0"], source["schema_version"]),
            codex_capability_profile_id=cast(str, source["codex_capability_profile_id"]),
            codex_version=cast(str, source["codex_version"]),
            exit_status=cast(int, source["exit_status"]),
            mapping_version=cast(str, source["mapping_version"]),
            request_id=request_id(source["request_id"]),
            session_id=session_id(source["session_id"]),
            source=_ControlImportByteSource(raw),
            source_kind=cast(Literal["file", "stdin"], source["source_kind"]),
            stderr_captured_bytes=cast(Literal[0], source["stderr_captured_bytes"]),
            stderr_present=cast(Literal[False], source["stderr_present"]),
            stderr_truncated=cast(Literal[False], source["stderr_truncated"]),
            writer_id=writer_id(source["writer_id"]),
        )
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise _error(PublicErrorCode.INVALID_REQUEST, "The import request is invalid.") from exc


@dataclass(frozen=True, slots=True)
class ImportReportInternal:
    schema_version: Literal["1.0.0"]
    request_id: RequestId
    task_id: str
    session_id: SessionId
    source_identity_digest: str
    report_object_id: str
    report_digest: str
    imported_count: int
    quarantined_count: int
    unknown_count: int
    malformed_count: int
    batch_count: int
    first_frontier: Frontier
    last_frontier: Frontier
    coverage: Coverage
    gap_codes: tuple[str, ...]
    codex_capability_profile_id: str
    mapping_version: str

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_VERSION:
            raise ValueError("import_report_invalid")
        object.__setattr__(self, "request_id", request_id(self.request_id))
        object.__setattr__(self, "task_id", task_id(self.task_id))
        object.__setattr__(self, "session_id", session_id(self.session_id))
        validate_sha256_digest(self.source_identity_digest)
        object.__setattr__(self, "report_object_id", object_id(self.report_object_id))
        validate_sha256_digest(self.report_digest)
        for value in (
            self.imported_count,
            self.quarantined_count,
            self.unknown_count,
            self.malformed_count,
            self.batch_count,
        ):
            if type(value) is not int or value < 0:
                raise ValueError("import_report_invalid")
        if (
            type(self.first_frontier) is not Frontier
            or type(self.last_frontier) is not Frontier
            or self.last_frontier < self.first_frontier
            or type(self.coverage) is not Coverage
            or self.gap_codes != tuple(sorted(set(self.gap_codes), key=str.encode))
        ):
            raise ValueError("import_report_invalid")

    def as_json(self) -> JsonObject:
        return JsonObject(
            {
                "schema_version": self.schema_version,
                "request_id": self.request_id,
                "task_id": self.task_id,
                "session_id": self.session_id,
                "source_identity_digest": self.source_identity_digest,
                "report_object_id": self.report_object_id,
                "report_digest": self.report_digest,
                "imported_count": self.imported_count,
                "quarantined_count": self.quarantined_count,
                "unknown_count": self.unknown_count,
                "malformed_count": self.malformed_count,
                "batch_count": self.batch_count,
                "first_frontier": self.first_frontier.as_wire(),
                "last_frontier": self.last_frontier.as_wire(),
                "coverage": coverage_to_json(self.coverage),
                "gap_codes": self.gap_codes,
                "codex_capability_profile_id": self.codex_capability_profile_id,
                "mapping_version": self.mapping_version,
            }
        )


@dataclass(frozen=True, slots=True)
class ReviewRequest:
    schema_version: Literal["1.0.0"]
    request_id: RequestId
    session_id: SessionId
    writer_id: WriterId
    at_frontier: Frontier
    source_identity_digests: tuple[str, ...]
    mode: Literal["deterministic_only", "semantic_if_configured", "semantic_required"]

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_VERSION or type(self.at_frontier) is not Frontier:
            raise ValueError("import_review_request_invalid")
        object.__setattr__(self, "request_id", request_id(self.request_id))
        object.__setattr__(self, "session_id", session_id(self.session_id))
        object.__setattr__(self, "writer_id", writer_id(self.writer_id))
        object.__setattr__(
            self,
            "source_identity_digests",
            _sorted_digests(self.source_identity_digests, maximum=32),
        )
        if self.mode not in {
            "deterministic_only",
            "semantic_if_configured",
            "semantic_required",
        }:
            raise ValueError("import_review_request_invalid")


@dataclass(frozen=True, slots=True)
class ReviewCounts:
    cooperative: int
    imported: int
    artifact_evidence: int
    unmatched: int
    unknown: int
    redacted: int
    unavailable: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (
                self.cooperative,
                self.imported,
                self.artifact_evidence,
                self.unmatched,
                self.unknown,
                self.redacted,
                self.unavailable,
            )
        ):
            raise ValueError("import_review_counts_invalid")


@dataclass(frozen=True, slots=True)
class ReviewInternal:
    schema_version: Literal["1.0.0"]
    request_id: RequestId
    task_id: str
    session_id: SessionId
    at_frontier: Frontier
    source_identity_digests: tuple[str, ...]
    check_result: CheckCommitResult
    comparison_coverage: Coverage
    counts: ReviewCounts

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or type(self.at_frontier) is not Frontier
            or type(self.check_result) is not CheckCommitResult
            or type(self.comparison_coverage) is not Coverage
            or type(self.counts) is not ReviewCounts
        ):
            raise ValueError("import_review_result_invalid")
        object.__setattr__(self, "request_id", request_id(self.request_id))
        object.__setattr__(self, "task_id", task_id(self.task_id))
        object.__setattr__(self, "session_id", session_id(self.session_id))
        object.__setattr__(
            self,
            "source_identity_digests",
            _sorted_digests(self.source_identity_digests, maximum=32),
        )

    def as_json(self) -> JsonObject:
        return JsonObject(
            {
                "schema_version": self.schema_version,
                "request_id": self.request_id,
                "task_id": self.task_id,
                "session_id": self.session_id,
                "at_frontier": self.at_frontier.as_wire(),
                "source_identity_digests": self.source_identity_digests,
                "check_result": check_internal_json(self.check_result),
                "comparison_coverage": coverage_to_json(self.comparison_coverage),
                "counts": {
                    "cooperative": self.counts.cooperative,
                    "imported": self.counts.imported,
                    "artifact_evidence": self.counts.artifact_evidence,
                    "unmatched": self.counts.unmatched,
                    "unknown": self.counts.unknown,
                    "redacted": self.counts.redacted,
                    "unavailable": self.counts.unavailable,
                },
            }
        )


class Application(Protocol):
    runtime: BundleRuntimePort
    clock: ClockPort

    def authorizes_import_publication(self, request: PublishWorkRequestModel) -> bool: ...

    def activate_import_publication(self, allocation: ImportAllocation) -> object: ...

    def bind_import_publication(
        self,
        token: object,
        *,
        request_id: str,
        event_ids: tuple[str, ...],
    ) -> None: ...

    def deactivate_import_publication(self, token: object, *, completed: bool) -> None: ...

    def reconcile_completed_import_publication(self, allocation: ImportAllocation) -> None: ...


def _draft_json(value: EventDraft) -> JsonObject:
    payload = (
        encode_payload(cast(EventPayload, value.payload))
        if value.schema in PAYLOAD_TYPES
        else cast(DomainJsonValue, value.payload)
    )
    return JsonObject(
        {
            "event_id": value.event_id,
            "schema": {"name": value.schema.name, "version": value.schema.version},
            "occurred_at": value.occurred_at.wire,
            "causal_parents": value.causal_parents,
            "payload": payload,
            "artifact_refs": value.artifact_refs,
            "evidence_refs": value.evidence_refs,
        }
    )


def _append_from_public(result: PublishWorkInternalResult) -> AppendResult:
    return AppendResult(
        result.outcome,
        tuple(
            AcceptedEventSummary(
                item.event_id,
                int(item.ingestion_sequence),
                int(item.writer_sequence),
                item.entry_digest,
                item.projection_status,
            )
            for item in result.accepted_events
        ),
        result.subject_frontier,
        result.result_frontier,
        tuple(AppendWarning(value) for value in result.warning_codes),
    )


async def _publish(
    app: Application,
    runtime: TaskRuntime,
    request_id_value: str,
    drafts: tuple[EventDraft, ...],
) -> AppendResult:
    frontier = await _publication_frontier(runtime, request_id_value)
    request = PublishWorkRequestModel.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": _SCHEMA_VERSION,
            "request_id": request_id_value,
            "session_id": runtime.session_id,
            "writer_id": runtime.writer_id,
            # Pydantic's closed wire model expects a concrete mapping here.  ``as_wire`` returns
            # the domain's deeply frozen ``JsonObject``; materialize only this structural frontier
            # at the application boundary, as the other public request builders do.
            "expected_frontier": dict(frontier.as_wire().items()),
            "event_drafts": tuple(_draft_json(draft) for draft in drafts),
            "actor": {"actor_id": "importer", "actor_type": "importer"},
            "client": {
                "kind": "importer",
                "version": _MAPPING_VERSION,
                "integration": "codex_jsonl_import",
            },
        }
    )
    public = await execute_publish_work(app, request)
    if type(public) is not PublishWorkInternalResult:
        raise _error(
            PublicErrorCode.INTERNAL_ERROR,
            "Import publication did not return an accepted result (stage: publish); it may or may "
            "not be recorded. Read status view=compact before repeating the import.",
            safe_details={"reason_code": "import_publication_failed"},
        )
    return _append_from_public(public)


async def _publication_frontier(runtime: TaskRuntime, request_id_value: str) -> Frontier:
    """Recover the original pre-append frontier when importer recording lagged the ledger."""

    if runtime.writer_id is None:
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The import writer route is invalid.")
    operation = await runtime.ledger.lookup_operation(runtime.writer_id, request_id_value)
    if (
        operation is None
        or operation.operation_kind is not OperationKind.PUBLISH_WORK
        or operation.state is not OperationState.COMPLETE
    ):
        return await runtime.ledger.load_frontier()
    if operation.result_canonical is None:
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The stored publication result is invalid.")
    try:
        stored = strict_json_parse(operation.result_canonical)
        if not isinstance(stored, Mapping):
            raise ValueError("stored_publication_result_invalid")
        return frontier_from_json(stored["subject_frontier"])
    except (KeyError, TypeError, ValueError) as exc:
        raise _error(
            PublicErrorCode.STORAGE_CORRUPT,
            "The stored publication result is invalid.",
        ) from exc


def _identity(
    runtime: TaskRuntime, captured: CapturedImportSource, request: ImportCodexJsonlRequest
) -> ImportSourceIdentity:
    identity_value: dict[str, JsonValue] = {
        "codex_capability_profile_id": captured.codex_capability_profile_id,
        "mapping_version": request.mapping_version,
        "source_commitment": captured.source_commitment,
        "task_id": runtime.task_id,
    }
    return ImportSourceIdentity(
        task_id(runtime.task_id),
        captured.source_commitment,
        captured.codex_capability_profile_id,
        request.mapping_version,
        canonical_digest(identity_value),
    )


def _command(
    request: ImportCodexJsonlRequest,
    identity: ImportSourceIdentity,
    captured: CapturedImportSource,
) -> ImportCommand:
    digest = canonical_digest(
        {
            "capture_metadata_digest": captured.metadata_digest,
            "exit_status": captured.exit_status,
            "mapping_version": request.mapping_version,
            "request_id": request.request_id,
            "session_id": request.session_id,
            "source_identity_digest": identity.identity_digest,
            "writer_id": request.writer_id,
        }
    )
    return ImportCommand(
        request.session_id,
        request.writer_id,
        request.request_id,
        digest,
        identity,
        request.mapping_version,
    )


def _report_from_json(value: JsonObject) -> ImportReportInternal:
    try:
        return ImportReportInternal(
            cast(Literal["1.0.0"], value["schema_version"]),
            request_id(value["request_id"]),
            cast(str, value["task_id"]),
            session_id(value["session_id"]),
            cast(str, value["source_identity_digest"]),
            cast(str, value["report_object_id"]),
            cast(str, value["report_digest"]),
            cast(int, value["imported_count"]),
            cast(int, value["quarantined_count"]),
            cast(int, value["unknown_count"]),
            cast(int, value["malformed_count"]),
            cast(int, value["batch_count"]),
            frontier_from_json(value["first_frontier"]),
            frontier_from_json(value["last_frontier"]),
            coverage_from_json(value["coverage"]),
            cast(tuple[str, ...], value["gap_codes"]),
            cast(str, value["codex_capability_profile_id"]),
            cast(str, value["mapping_version"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise _error(
            PublicErrorCode.STORAGE_CORRUPT, "The stored import report is invalid."
        ) from exc


def _frontiers(source: ImportReviewSource, fallback: Frontier) -> tuple[Frontier, Frontier]:
    if not source.completed_batch_results:
        return fallback, fallback
    first = source.completed_batch_results[0].subject_frontier
    last = source.completed_batch_results[-1].result_frontier
    return first, last


async def _build_report(
    app: Application,
    runtime: TaskRuntime,
    request: ImportCodexJsonlRequest,
    captured: CapturedImportSource,
    source: ImportReviewSource,
) -> tuple[ImportReportInternal, EncryptedImportReportRef]:
    fallback = await runtime.ledger.load_frontier()
    first, last = _frontiers(source, fallback)
    unknown = sum(
        value.status
        in {ImportLineStatus.UNKNOWN, ImportLineStatus.OVERSIZED, ImportLineStatus.UNSUPPORTED}
        for value in source.line_outcomes
    )
    malformed = sum(value.status is ImportLineStatus.MALFORMED for value in source.line_outcomes)
    gap_codes = tuple(sorted({gap.code for gap in source.gaps}, key=str.encode))
    report_content = JsonObject(
        {
            "batch_count": len(source.completed_batch_results),
            "capture_metadata_digest": captured.metadata_digest,
            "capture_metadata_object_id": captured.capture_metadata_object.object_id,
            "codex_capability_profile_id": source.codex_capability_profile_id,
            "coverage": coverage_to_json(source.coverage),
            "first_frontier": first.as_wire(),
            "gap_codes": gap_codes,
            "imported_count": len(source.mapped_event_ids),
            "last_frontier": last.as_wire(),
            "malformed_count": malformed,
            "mapping_version": source.mapping_version,
            "source_identity_digest": source.identity.identity_digest,
            "source_object_id": source.source_object.object_id,
            "unknown_count": unknown,
        }
    )
    report_bytes = canonical_encode(report_content)
    metadata = ObjectMetadata(
        ObjectKind.IMPORT_REPORT,
        _REPORT_MEDIA_TYPE,
        runtime.task_id,
        app.clock.now_utc(),
    )
    expected_commitment = await runtime.objects.commitment_for(
        report_bytes, ObjectKind.IMPORT_REPORT
    )
    staged = await runtime.objects.stage(
        ObjectSource(data=report_bytes, declared_size=len(report_bytes)), metadata
    )
    if staged.commitment != expected_commitment:
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The import report commitment changed.")
    report_object = await runtime.objects.finalize(staged)
    if (
        report_object.metadata != metadata
        or report_object.commitment != expected_commitment
        or report_object.plaintext_size != len(report_bytes)
    ):
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The import report object is invalid.")
    report_digest = canonical_digest(report_content)
    report = ImportReportInternal(
        _SCHEMA_VERSION,
        request.request_id,
        runtime.task_id,
        request.session_id,
        source.identity.identity_digest,
        report_object.object_id,
        report_digest,
        len(source.mapped_event_ids),
        0,
        unknown,
        malformed,
        len(source.completed_batch_results),
        first,
        last,
        source.coverage,
        gap_codes,
        source.codex_capability_profile_id,
        source.mapping_version,
    )
    terminal_bytes = canonical_encode(report.as_json())
    return report, EncryptedImportReportRef(
        report_object,
        report_digest,
        terminal_bytes,
        canonical_digest(report.as_json()),
    )


def _report_ref(allocation: ImportAllocation) -> EncryptedImportReportRef:
    if (
        allocation.report_object is None
        or allocation.report_digest is None
        or allocation.terminal_result_bytes is None
        or allocation.terminal_result_digest is None
    ):
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The stored import report is incomplete.")
    return EncryptedImportReportRef(
        allocation.report_object,
        allocation.report_digest,
        allocation.terminal_result_bytes,
        allocation.terminal_result_digest,
    )


async def execute_import_codex_jsonl(
    app: Application, request: ImportCodexJsonlRequest
) -> ImportReportInternal:
    """Capture, publish, report, and terminally acknowledge one retained JSONL stream."""

    if (
        request.stderr_present is not False
        or request.stderr_captured_bytes != 0
        or request.stderr_truncated is not False
    ):
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            "The v0.1 import surface requires stderr to be absent.",
        )
    runtime = await app.runtime.route(
        RouteCommand(
            request.session_id,
            request.writer_id,
            RouteAccess.WRITE,
            frozenset({RuntimeCapability.WRITE}),
        )
    )
    try:
        captured = await runtime.importer.capture(
            ImportCaptureInput(
                request.source,
                request.codex_version,
                request.codex_capability_profile_id,
                (),
                "control-import",
                request.exit_status,
                timestamp_from_datetime(app.clock.now_utc()),
                request.source_kind,
            )
        )
        if (
            captured.codex_capability_profile_id != request.codex_capability_profile_id
            or captured.codex_version != request.codex_version
            or captured.exit_status != request.exit_status
            or captured.source_kind != request.source_kind
        ):
            raise _error(PublicErrorCode.STORAGE_CORRUPT, "Import capture metadata changed.")
        identity = _identity(runtime, captured, request)
        allocation = await runtime.importer.reserve_or_resume(
            _command(request, identity, captured), captured
        )
        if allocation.outcome is ImportAllocationOutcome.REPLAYED:
            if allocation.state is ImportState.QUARANTINED:
                raise _error(PublicErrorCode.STORAGE_CORRUPT, "The import is quarantined.")
            if allocation.terminal_result is None:
                raise _error(PublicErrorCode.STORAGE_CORRUPT, "The import replay is incomplete.")
            app.reconcile_completed_import_publication(allocation)
            return _report_from_json(allocation.terminal_result)

        if allocation.phase is ImportPhase.SOURCE_RESERVED:
            plan = await runtime.importer.prepare_plan(allocation)
            allocation = await runtime.importer.publish_plan(allocation, plan)
        try:
            authority_token = app.activate_import_publication(allocation)
        except BaseException:
            await runtime.importer.release_lease_for_authorization(allocation)
            raise
        completed = False
        try:
            while allocation.phase in {ImportPhase.PLAN_READY, ImportPhase.PUBLISHING}:
                selection = await runtime.importer.next_batch(allocation)
                allocation = selection.allocation
                if selection.batch is None:
                    break
                app.bind_import_publication(
                    authority_token,
                    request_id=selection.batch.request_id,
                    event_ids=tuple(selection.batch.event_ids),
                )
                result = await _publish(
                    app,
                    runtime,
                    selection.batch.request_id,
                    selection.batch.event_drafts,
                )
                allocation = await runtime.importer.record_batch(
                    allocation, selection.batch, result
                )

            report: ImportReportInternal
            report_ref: EncryptedImportReportRef
            if allocation.phase in {ImportPhase.PLAN_READY, ImportPhase.PUBLISHING}:
                frontier = await runtime.ledger.load_frontier()
                review_source = await runtime.importer.load_review_source(
                    identity.identity_digest, frontier
                )
                if review_source is None:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT, "The import source disappeared.")
                report, report_ref = await _build_report(
                    app, runtime, request, allocation.captured_source, review_source
                )
                allocation = await runtime.importer.prepare_report(allocation, report_ref)
            else:
                report_ref = _report_ref(allocation)
                if allocation.terminal_result is None:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT, "The stored report result is missing."
                    )
                report = _report_from_json(allocation.terminal_result)

            if allocation.phase is ImportPhase.REPORT_READY:
                if allocation.report_evidence_draft is None or allocation.report_request_id is None:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT, "Report evidence is incomplete.")
                app.bind_import_publication(
                    authority_token,
                    request_id=allocation.report_request_id,
                    event_ids=(allocation.report_evidence_draft.event_id,),
                )
                evidence_result = await _publish(
                    app,
                    runtime,
                    allocation.report_request_id,
                    (allocation.report_evidence_draft,),
                )
                allocation = await runtime.importer.publish_report(
                    allocation, report_ref, evidence_result
                )
            if allocation.phase is ImportPhase.REPORT_PUBLISHED:
                allocation = await runtime.importer.complete(allocation)
            if (
                allocation.state is not ImportState.COMPLETE
                or allocation.phase is not ImportPhase.TERMINAL
            ):
                raise _error(PublicErrorCode.STORAGE_CORRUPT, "Import completion is inconsistent.")
            completed = True
            return report
        finally:
            app.deactivate_import_publication(authority_token, completed=completed)
    finally:
        await app.runtime.release(runtime)


async def _review_sources(
    runtime: TaskRuntime, request: ReviewRequest
) -> tuple[ImportReviewSource, ...]:
    status = await runtime.importer.status(request.session_id)
    if status.active_job_count:
        raise _error(
            PublicErrorCode.OPERATION_PENDING,
            "An import is still pending.",
            retryable=True,
        )
    available = tuple(cast(str, row["identity_digest"]) for row in status.terminal_report_locators)
    if (
        status.terminal_job_count != len(available)
        or tuple(sorted(available, key=str.encode)) != request.source_identity_digests
    ):
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            "The review selection must name the complete bounded import set.",
        )
    sources: list[ImportReviewSource] = []
    for digest in request.source_identity_digests:
        source = await runtime.importer.load_review_source(digest, request.at_frontier)
        if source is None or source.import_incomplete:
            raise _error(PublicErrorCode.INVALID_REQUEST, "The review source is unavailable.")
        sources.append(source)
    return tuple(sources)


async def execute_review(app: Application, request: ReviewRequest) -> ReviewInternal:
    """Review one exact complete selected import set at recorded frontier only."""

    runtime = await app.runtime.route(
        RouteCommand(
            request.session_id,
            request.writer_id,
            RouteAccess.IMPORT_REVIEW,
            frozenset({RuntimeCapability.WRITE}),
        )
    )
    try:
        head = await runtime.ledger.load_frontier()
        if request.at_frontier > head:
            raise _error(PublicErrorCode.INVALID_REQUEST, "The review frontier is unavailable.")
        sources = await _review_sources(runtime, request)
        comparison_coverage = sources[0].coverage
        for source in sources[1:]:
            comparison_coverage = weakest(comparison_coverage, source.coverage)

        cooperative = 0
        artifact_evidence = 0
        async for record in runtime.ledger.load_events(
            runtime.session_id, after=0, through=request.at_frontier.sequence
        ):
            if record.publication_channel is not PublicationChannel.CODEX_JSONL_IMPORT:
                cooperative += 1
            if record.schema.name == "evidence_recorded":
                artifact_evidence += 1
        imported = sum(len(source.mapped_event_ids) for source in sources)
        unknown = sum(
            outcome.status
            in {
                ImportLineStatus.MALFORMED,
                ImportLineStatus.OVERSIZED,
                ImportLineStatus.UNKNOWN,
                ImportLineStatus.UNSUPPORTED,
            }
            for source in sources
            for outcome in source.line_outcomes
        )
        unmatched = sum(len(source.gaps) for source in sources)
        counts = ReviewCounts(
            cooperative,
            imported,
            artifact_evidence,
            unmatched,
            unknown,
            0,
            0,
        )
        check_request = CheckRequestModel.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": _SCHEMA_VERSION,
                "request_id": request.request_id,
                "session_id": request.session_id,
                "writer_id": request.writer_id,
                "expected_frontier": request.at_frontier.as_wire(),
                "mode": request.mode,
                "actor": {"actor_id": "import-review", "actor_type": "yoetz_engine"},
                "client": {
                    "kind": "importer",
                    "version": _MAPPING_VERSION,
                    "integration": "local_cli",
                },
            }
        )
    finally:
        await app.runtime.release(runtime)

    check_result = await execute_check(cast(CheckApplication, app), check_request)
    # A review summarizes a completed check. A check suspended on a local disclosure decision has
    # no verdict or coverage to summarize, and inventing one would report a review that never ran.
    if type(check_result) is not CheckCommitResult:
        raise PublicOperationError(
            PublicErrorCode.OPERATION_PENDING,
            "The review's check is awaiting a local disclosure decision.",
            True,
        )
    return ReviewInternal(
        _SCHEMA_VERSION,
        request.request_id,
        check_result.task_id,
        request.session_id,
        request.at_frontier,
        request.source_identity_digests,
        check_result,
        comparison_coverage,
        counts,
    )
