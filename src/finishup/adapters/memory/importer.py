"""In-memory reference persistence for the bounded importer state machine.

Parsing and mapping are deliberately supplied by the later Codex JSONL adapter.  This module
owns the crash-stable structural half of the contract: aliases, leases, plans, publication
reservations, batch/report checkpoints, terminal replay, status, and the shared ledger seam.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum
from typing import Final, Literal, Protocol, cast

from finishup.domain.events import (
    EVIDENCE_TYPED_SCHEMA_VERSION,
    PAYLOAD_TYPES,
    EventDraft,
    EventPayload,
    EventSchema,
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceKind,
    EvidenceRecordedPayload,
    decode_payload,
    encode_payload,
)
from finishup.domain.values import (
    EventId,
    EvidenceId,
    Frontier,
    JsonObject,
    RequestId,
    SessionId,
    Timestamp,
    WriterId,
    event_id,
    evidence_id,
    frontier_from_json,
    object_id,
    session_id,
    timestamp_from_datetime,
    timestamp_from_string,
    validate_sha256_digest,
)
from finishup.domain.values import (
    JsonValue as DomainJsonValue,
)
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.importer import (
    CapturedImportSource,
    EncryptedImportReportRef,
    ImportAllocation,
    ImportAllocationOutcome,
    ImportBatch,
    ImportBatchSelection,
    ImportByteSource,
    ImportCaptureInput,
    ImportCommand,
    ImportGap,
    ImportLineOutcome,
    ImportPhase,
    ImportReviewSource,
    ImportSafeReason,
    ImportSourceIdentity,
    ImportState,
    ImportStatusSnapshot,
    PreparedImportPlan,
)
from finishup.ports.ledger import AcceptedEventSummary, AppendResult, AppendWarning, LedgerPort
from finishup.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectSource,
    ObjectStorePort,
)
from finishup.ports.runtime import OwnershipFence
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.coverage import (
    Coverage,
    EvidenceImmutability,
    PublicationChannel,
    coverage_for_channel,
    coverage_from_json,
    weakest,
)
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import MAX_CANONICAL_REQUEST_BYTES, MAX_EVENTS_PER_BATCH

__all__ = [
    "MemoryImportFaultPoint",
    "MemoryImportPolicy",
    "MemoryImportState",
    "MemoryImporter",
    "MemoryPublicationReservation",
    "ImportPlanMaterial",
]

_PLAN_MEDIA_TYPE: Final = "application/vnd.yoetz.import_plan+json"
_SOURCE_MEDIA_TYPE: Final = "application/x-ndjson"
_MANIFEST_MEDIA_TYPE: Final = "application/vnd.yoetz.import_source_manifest+json"


def _error(code: PublicErrorCode, message: str, *, retryable: bool) -> PublicOperationError:
    return PublicOperationError(code, message, retryable)


def digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _frontier_at_or_before(value: Frontier, through: Frontier) -> bool:
    if value.sequence < through.sequence:
        return True
    return value.sequence == through.sequence and value.head_digest == through.head_digest


async def _read_bounded(source: ImportByteSource, limit: int) -> tuple[bytes, bool]:
    declared = source.declared_size
    if declared is not None and declared > limit:
        raise _error(
            PublicErrorCode.LIMIT_EXCEEDED, "Import input exceeds its limit.", retryable=False
        )
    collected = bytearray()
    try:
        async for chunk in source:
            if type(chunk) is not bytes:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Import byte source is invalid.",
                    retryable=False,
                )
            remaining = limit + 1 - len(collected)
            if remaining > 0:
                collected.extend(chunk[:remaining])
            if len(collected) > limit:
                return bytes(collected[:limit]), True
        return bytes(collected), False
    finally:
        await source.close()


@dataclass(frozen=True, slots=True)
class MemoryImportPolicy:
    source_bytes: int = 4 * 1024 * 1024
    line_bytes: int = 1024 * 1024
    line_count: int = 20_000
    batch_count: int = 1_024
    lease_seconds: int = 60
    publication_window_seconds: int = 30
    status_jobs: int = 64

    def __post_init__(self) -> None:
        if (
            self.source_bytes != 4 * 1024 * 1024
            or self.line_bytes != 1024 * 1024
            or self.line_count != 20_000
            or self.batch_count != 1_024
            or self.lease_seconds != 60
            or self.publication_window_seconds != 30
            or self.status_jobs != 64
        ):
            raise ValueError("memory_import_policy_not_release_frozen")


class MemoryImportFaultPoint(str, Enum):  # noqa: UP042 - stable test vocabulary
    BEFORE_RESERVATION_COMMIT = "before_reservation_commit"
    AFTER_RESERVATION_COMMIT = "after_reservation_commit"
    BEFORE_PLAN_COMMIT = "before_plan_commit"
    AFTER_PLAN_COMMIT = "after_plan_commit"
    BEFORE_BATCH_COMMIT = "before_batch_commit"
    AFTER_BATCH_COMMIT = "after_batch_commit"
    BEFORE_REPORT_READY_COMMIT = "before_report_ready_commit"
    AFTER_REPORT_READY_COMMIT = "after_report_ready_commit"
    BEFORE_REPORT_PUBLISHED_COMMIT = "before_report_published_commit"
    AFTER_REPORT_PUBLISHED_COMMIT = "after_report_published_commit"
    BEFORE_TERMINAL_COMMIT = "before_terminal_commit"
    AFTER_TERMINAL_COMMIT = "after_terminal_commit"


type FaultHook = Callable[[MemoryImportFaultPoint], Awaitable[None] | None]
type PlanPreparer = Callable[[ImportAllocation], Awaitable[PreparedImportPlan]]
type PlanReader = Callable[[ObjectRef], Awaitable[ImportPlanMaterial]]


@dataclass(frozen=True, slots=True)
class ImportPlanMaterial:
    event_drafts: tuple[EventDraft, ...]
    line_outcomes: tuple[ImportLineOutcome, ...]
    gaps: tuple[ImportGap, ...]
    coverage: Coverage

    def __post_init__(self) -> None:
        if (
            type(self.event_drafts) is not tuple
            or any(type(value) is not EventDraft for value in self.event_drafts)
            or type(self.line_outcomes) is not tuple
            or any(type(value) is not ImportLineOutcome for value in self.line_outcomes)
            or type(self.gaps) is not tuple
            or any(type(value) is not ImportGap for value in self.gaps)
            or type(self.coverage) is not Coverage
        ):
            raise ValueError("import_plan_material_invalid")


@dataclass(frozen=True, slots=True)
class MemoryPublicationReservation:
    publishing_writer_id: str
    request_id: str
    source_identity_digest: str
    publication_ordinal: int


@dataclass(frozen=True, slots=True)
class _Alias:
    request_digest: str
    source_identity_digest: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class _Batch:
    index: int
    request_id: RequestId
    plan_object: ObjectRef
    plan_digest: str
    event_ids: tuple[EventId, ...]
    gaps: tuple[ImportGap, ...]
    result: AppendResult | None = None
    result_bytes: bytes | None = None
    result_digest: str | None = None


@dataclass(frozen=True, slots=True)
class _Job:
    identity: ImportSourceIdentity
    session_id: SessionId
    publishing_writer_id: WriterId
    source: CapturedImportSource
    state: ImportState
    phase: ImportPhase
    revision: int
    owner_generation: int | None
    lease_owner_id: str | None
    lease_generation: int | None
    lease_expires_at: datetime | None
    plan_digest: str | None = None
    report_request_id: RequestId | None = None
    report_event_id: EventId | None = None
    report_evidence_id: EvidenceId | None = None
    report_ref: EncryptedImportReportRef | None = None
    report_evidence_draft: EventDraft | None = None
    report_evidence_draft_bytes: bytes | None = None
    report_evidence_draft_digest: str | None = None
    report_append_result: AppendResult | None = None
    terminal_at: datetime | None = None
    quarantine_code: str | None = None


@dataclass(slots=True, repr=False)
class MemoryImportState:
    aliases: dict[tuple[str, str], _Alias] = field(default_factory=lambda: {})
    jobs: dict[str, _Job] = field(default_factory=lambda: {})
    batches: dict[tuple[str, int], _Batch] = field(default_factory=lambda: {})
    publication_by_request: dict[tuple[str, str], MemoryPublicationReservation] = field(
        default_factory=lambda: {}
    )
    publication_by_ordinal: dict[tuple[str, int], MemoryPublicationReservation] = field(
        default_factory=lambda: {}
    )
    revision: int = 0

    def __repr__(self) -> str:
        return "MemoryImportState(<redacted>)"

    def has_pending_import(self, session_id: str) -> bool:
        """Return the atomic ledger-gate predicate; caller must hold the shared lock."""

        return any(
            job.session_id == session_id and job.state is ImportState.PENDING
            for job in self.jobs.values()
        )

    def publication_reservation(
        self, publishing_writer_id: str, request_id: str
    ) -> MemoryPublicationReservation | None:
        """Return one permanent importer publication reservation under the shared lock."""

        return self.publication_by_request.get((publishing_writer_id, request_id))


class MemoryImporter:
    def __init__(
        self,
        *,
        task_id: str,
        admitted_session_id: str,
        ownership_fence: OwnershipFence,
        state: MemoryImportState,
        transaction_lock: asyncio.Lock,
        objects: ObjectStorePort,
        ledger: LedgerPort,
        clock: ClockPort,
        ids: IdPort,
        plan_preparer: PlanPreparer,
        plan_reader: PlanReader,
        policy: MemoryImportPolicy = MemoryImportPolicy(),
        fault_hook: FaultHook | None = None,
    ) -> None:
        if type(ownership_fence) is not OwnershipFence or type(state) is not MemoryImportState:
            raise TypeError("memory_importer_construction_invalid")
        if type(transaction_lock) is not asyncio.Lock:
            raise TypeError("memory_importer_lock_invalid")
        if not callable(plan_preparer) or not callable(plan_reader):
            raise TypeError("memory_importer_plan_dependencies_invalid")
        self._task_id = task_id
        self._session_id = session_id(admitted_session_id)
        self._fence = ownership_fence
        self._state = state
        self._lock = transaction_lock
        self._objects = objects
        self._ledger = ledger
        self._clock = clock
        self._ids = ids
        self._plan_preparer = plan_preparer
        self._plan_reader = plan_reader
        self._policy = policy
        self._fault_hook = fault_hook

    def rebind_session(self, admitted_session_id: str) -> None:
        """Move this task-owned importer to the currently attached session.

        A task bundle can be re-attached without reopening its durable ports.  The runtime
        therefore has to refresh the session fence held by the importer before a new capture;
        the route itself remains the authority for which session may call it.
        """

        self._session_id = session_id(admitted_session_id)

    async def _fault(self, point: MemoryImportFaultPoint) -> None:
        if self._fault_hook is None:
            return
        result = self._fault_hook(point)
        if result is not None:
            await result

    async def capture(self, value: ImportCaptureInput) -> CapturedImportSource:
        if type(value) is not ImportCaptureInput:
            raise _error(
                PublicErrorCode.INVALID_REQUEST, "Import capture is invalid.", retryable=False
            )
        source_bytes, exceeded = await _read_bounded(value.source, self._policy.source_bytes)
        if exceeded:
            raise _error(
                PublicErrorCode.LIMIT_EXCEEDED, "Import source is too large.", retryable=False
            )
        final_newline = source_bytes.endswith(b"\n")
        line_count = source_bytes.count(b"\n") + (1 if source_bytes and not final_newline else 0)
        if line_count > self._policy.line_count:
            raise _error(
                PublicErrorCode.LIMIT_EXCEEDED, "Import source has too many lines.", retryable=False
            )
        now = self._clock.now_utc()
        source_ref = await self._finalize_object(
            source_bytes, ObjectKind.IMPORT_SOURCE, _SOURCE_MEDIA_TYPE, now
        )
        safe_metadata = JsonObject(
            {
                "codex_capability_profile_id": value.codex_capability_profile_id,
                "codex_version": value.codex_version,
                "exit_status": value.exit_status,
                "source_kind": value.source_kind,
                "stderr_present": False,
                "stderr_captured_bytes": 0,
                "stderr_truncated": False,
            }
        )
        audit_manifest = JsonObject(
            {
                "argv": value.argv,
                "captured_at": value.captured_at.wire,
                "cwd_commitment": await self._objects.commitment_for(
                    value.working_directory_identity_input.encode("utf-8"),
                    ObjectKind.IMPORT_SOURCE_MANIFEST,
                ),
                "safe_metadata": safe_metadata,
                "source_audit_digest": digest_bytes(source_bytes),
                "source_object_id": source_ref.object_id,
            }
        )
        manifest_ref = await self._finalize_object(
            canonical_encode(audit_manifest),
            ObjectKind.IMPORT_SOURCE_MANIFEST,
            _MANIFEST_MEDIA_TYPE,
            now,
        )
        return CapturedImportSource(
            source_object=source_ref,
            source_commitment=source_ref.commitment,
            byte_count=len(source_bytes),
            line_count=line_count,
            final_newline=final_newline,
            metadata_digest=canonical_digest(safe_metadata),
            codex_capability_profile_id=value.codex_capability_profile_id,
            codex_version=value.codex_version,
            exit_status=value.exit_status,
            source_kind=value.source_kind,
            capture_metadata_object=manifest_ref,
            stderr_present=False,
            stderr_captured_bytes=0,
            stderr_truncated=False,
            stderr_commitment=None,
        )

    async def _finalize_object(
        self, data: bytes, kind: ObjectKind, media_type: str, now: datetime
    ) -> ObjectRef:
        staged = await self._objects.stage(
            ObjectSource(data=data, declared_size=len(data)),
            ObjectMetadata(kind=kind, media_type=media_type, task_id=self._task_id, created_at=now),
        )
        return await self._objects.finalize(staged)

    def _validate_source(self, command: ImportCommand, source: CapturedImportSource) -> None:
        identity = command.source_identity
        expected = canonical_digest(
            {
                "codex_capability_profile_id": source.codex_capability_profile_id,
                "mapping_version": command.mapping_version,
                "source_commitment": source.source_commitment,
                "task_id": self._task_id,
            }
        )
        if (
            command.session_id != self._session_id
            or identity.task_id != self._task_id
            or identity.source_commitment != source.source_commitment
            or identity.codex_capability_profile_id != source.codex_capability_profile_id
            or identity.mapping_version != command.mapping_version
            or identity.identity_digest != expected
        ):
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Import source identity is invalid.",
                retryable=False,
            )

    async def reserve_or_resume(
        self, command: ImportCommand, source: CapturedImportSource
    ) -> ImportAllocation:
        self._validate_source(command, source)
        now = self._clock.now_utc()
        alias_key = (command.requesting_writer_id, command.request_id)
        identity_digest = command.source_identity.identity_digest
        await self._fault(MemoryImportFaultPoint.BEFORE_RESERVATION_COMMIT)
        async with self._lock:
            alias = self._state.aliases.get(alias_key)
            if alias is not None and (
                alias.request_digest != command.request_digest
                or alias.source_identity_digest != identity_digest
            ):
                raise _error(
                    PublicErrorCode.IDEMPOTENCY_CONFLICT,
                    "Import request conflicts with prior use.",
                    retryable=False,
                )
            job = self._state.jobs.get(identity_digest)
            if job is None:
                lease_expiry = now + timedelta(seconds=self._policy.lease_seconds)
                job = _Job(
                    identity=command.source_identity,
                    session_id=command.session_id,
                    publishing_writer_id=command.requesting_writer_id,
                    source=source,
                    state=ImportState.PENDING,
                    phase=ImportPhase.SOURCE_RESERVED,
                    revision=0,
                    owner_generation=self._fence.owner_generation,
                    lease_owner_id=self._fence.service_instance_id,
                    lease_generation=1,
                    lease_expires_at=lease_expiry,
                )
                self._state.jobs[identity_digest] = job
                self._state.aliases[alias_key] = _Alias(
                    command.request_digest, identity_digest, now
                )
                self._state.revision += 1
                outcome = ImportAllocationOutcome.RESERVED
            else:
                # The writer boundary is decided before any job state is read or recorded.
                # A terminal job replays the publishing writer's report, request id, and
                # report locator, so a foreign writer has to be refused ahead of that branch
                # rather than one branch after it. Deciding here also keeps the caller's
                # request id unaliased to a job it can never own. A foreign writer could
                # never resume a pending job either, so the refusal is not retryable.
                if job.publishing_writer_id != command.requesting_writer_id:
                    raise _error(
                        PublicErrorCode.INVALID_REQUEST,
                        "This import source belongs to a different writer.",
                        retryable=False,
                    )
                if alias is None:
                    self._state.aliases[alias_key] = _Alias(
                        command.request_digest, identity_digest, now
                    )
                if job.state is not ImportState.PENDING:
                    self._state.revision += alias is None
                    return self._allocation(job, command, ImportAllocationOutcome.REPLAYED)
                live = (
                    job.owner_generation == self._fence.owner_generation
                    and job.lease_expires_at is not None
                    and job.lease_expires_at > now
                )
                if live:
                    raise _error(
                        PublicErrorCode.OPERATION_PENDING,
                        "Import is already pending.",
                        retryable=True,
                    )
                job = replace(
                    job,
                    revision=job.revision + 1,
                    owner_generation=self._fence.owner_generation,
                    lease_owner_id=self._fence.service_instance_id,
                    lease_generation=cast(int, job.lease_generation) + 1,
                    lease_expires_at=now + timedelta(seconds=self._policy.lease_seconds),
                )
                self._state.jobs[identity_digest] = job
                self._state.revision += 1
                outcome = ImportAllocationOutcome.RESUMED
            result = self._allocation(job, command, outcome)
        await self._fault(MemoryImportFaultPoint.AFTER_RESERVATION_COMMIT)
        return result

    async def prepare_plan(self, allocation: ImportAllocation) -> PreparedImportPlan:
        async with self._lock:
            self._require_lease(allocation, {ImportPhase.SOURCE_RESERVED})
        plan = await self._plan_preparer(allocation)
        if (
            type(plan) is not PreparedImportPlan
            or plan.source_identity != allocation.source_identity
        ):
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "Prepared import plan contradicts its allocation.",
                retryable=False,
            )
        return plan

    async def publish_plan(
        self, allocation: ImportAllocation, plan: PreparedImportPlan
    ) -> ImportAllocation:
        if plan.source_identity != allocation.source_identity:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "Import plan identity contradicts its source.",
                retryable=False,
            )
        groups: list[tuple[EventId, ...]] = []
        for ref in plan.batch_plan_objects:
            ids = tuple(
                candidate.event_id for candidate in plan.candidates if candidate.plan_object == ref
            )
            if not 1 <= len(ids) <= MAX_EVENTS_PER_BATCH:
                raise _error(
                    PublicErrorCode.LIMIT_EXCEEDED,
                    "Import batch is outside release bounds.",
                    retryable=False,
                )
            groups.append(ids)
        if len(groups) > self._policy.batch_count or len(groups) != len(plan.batch_request_ids):
            raise _error(
                PublicErrorCode.LIMIT_EXCEEDED,
                "Import plan is outside release bounds.",
                retryable=False,
            )
        if (
            len(
                canonical_encode(
                    {"request_ids": plan.batch_request_ids, "event_ids": tuple(groups)}
                )
            )
            > MAX_CANONICAL_REQUEST_BYTES
        ):
            raise _error(
                PublicErrorCode.LIMIT_EXCEEDED,
                "Import plan aggregate is outside release bounds.",
                retryable=False,
            )
        await self._fault(MemoryImportFaultPoint.BEFORE_PLAN_COMMIT)
        async with self._lock:
            job = self._require_lease(allocation, {ImportPhase.SOURCE_RESERVED})
            reservations = tuple(
                MemoryPublicationReservation(
                    job.publishing_writer_id, request, job.identity.identity_digest, index
                )
                for index, request in enumerate((*plan.batch_request_ids, plan.report_request_id))
            )
            self._verify_reservations(reservations)
            now = self._clock.now_utc()
            for index, (request, ref, event_ids) in enumerate(
                zip(plan.batch_request_ids, plan.batch_plan_objects, groups, strict=True)
            ):
                gaps = tuple(
                    gap
                    for gap in plan.gaps
                    if any(
                        candidate.plan_object == ref
                        and not (
                            gap.byte_end <= candidate.byte_start
                            or gap.byte_start >= candidate.byte_end
                        )
                        for candidate in plan.candidates
                    )
                )
                self._state.batches[(job.identity.identity_digest, index)] = _Batch(
                    index, request, ref, plan.plan_digest, event_ids, gaps
                )
            for reservation in reservations:
                self._state.publication_by_request[
                    (reservation.publishing_writer_id, reservation.request_id)
                ] = reservation
                self._state.publication_by_ordinal[
                    (reservation.source_identity_digest, reservation.publication_ordinal)
                ] = reservation
            job = replace(
                job,
                phase=ImportPhase.PLAN_READY,
                revision=job.revision + 1,
                plan_digest=plan.plan_digest,
                report_request_id=plan.report_request_id,
                report_event_id=plan.report_event_id,
                report_evidence_id=plan.report_evidence_id,
                lease_expires_at=max(
                    cast(datetime, job.lease_expires_at),
                    now + timedelta(seconds=self._policy.publication_window_seconds),
                ),
            )
            self._state.jobs[job.identity.identity_digest] = job
            self._state.revision += 1
            result = self._allocation(job, allocation, ImportAllocationOutcome.RESUMED)
        await self._fault(MemoryImportFaultPoint.AFTER_PLAN_COMMIT)
        return result

    def _verify_reservations(self, reservations: tuple[MemoryPublicationReservation, ...]) -> None:
        for reservation in reservations:
            by_request = self._state.publication_by_request.get(
                (reservation.publishing_writer_id, reservation.request_id)
            )
            by_ordinal = self._state.publication_by_ordinal.get(
                (reservation.source_identity_digest, reservation.publication_ordinal)
            )
            if (by_request is not None and by_request != reservation) or (
                by_ordinal is not None and by_ordinal != reservation
            ):
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Import publication identity is contradictory.",
                    retryable=False,
                )

    async def next_batch(self, allocation: ImportAllocation) -> ImportBatchSelection:
        async with self._lock:
            job = self._require_lease(allocation, {ImportPhase.PLAN_READY, ImportPhase.PUBLISHING})
            now = self._clock.now_utc()
            renewed = max(
                cast(datetime, job.lease_expires_at),
                now + timedelta(seconds=self._policy.publication_window_seconds),
            )
            job = replace(job, revision=job.revision + 1, lease_expires_at=renewed)
            self._state.jobs[job.identity.identity_digest] = job
            self._state.revision += 1
            pending = next(
                (
                    row
                    for (identity, _), row in sorted(self._state.batches.items())
                    if identity == job.identity.identity_digest and row.result is None
                ),
                None,
            )
            refreshed = self._allocation(job, allocation, ImportAllocationOutcome.RESUMED)
        if pending is None:
            return ImportBatchSelection(refreshed, None)
        material = await self._plan_reader(pending.plan_object)
        if tuple(draft.event_id for draft in material.event_drafts) != pending.event_ids:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "Import batch object contradicts its manifest.",
                retryable=False,
            )
        batch = ImportBatch(
            batch_index=pending.index,
            batch_count=refreshed.batch_count,
            request_id=pending.request_id,
            event_ids=pending.event_ids,
            event_drafts=material.event_drafts,
            plan_object=pending.plan_object,
            plan_digest=pending.plan_digest,
            gaps=material.gaps or pending.gaps,
        )
        return ImportBatchSelection(refreshed, batch)

    async def release_lease_for_authorization(self, allocation: ImportAllocation) -> None:
        """Make a prepared, unpublished plan immediately resumable after consent."""

        async with self._lock:
            job = self._require_lease(allocation, {ImportPhase.PLAN_READY})
            self._state.jobs[job.identity.identity_digest] = replace(
                job,
                revision=job.revision + 1,
                lease_expires_at=self._clock.now_utc(),
            )
            self._state.revision += 1

    async def record_batch(
        self, allocation: ImportAllocation, batch: ImportBatch, result: AppendResult
    ) -> ImportAllocation:
        result_bytes = append_result_bytes(result)
        if tuple(item.event_id for item in result.accepted) != batch.event_ids:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "Import batch result contradicts its plan.",
                retryable=False,
            )
        await self._fault(MemoryImportFaultPoint.BEFORE_BATCH_COMMIT)
        async with self._lock:
            job = self._require_lease(allocation, {ImportPhase.PLAN_READY, ImportPhase.PUBLISHING})
            key = (job.identity.identity_digest, batch.batch_index)
            row = self._state.batches.get(key)
            if (
                row is None
                or row.request_id != batch.request_id
                or row.event_ids != batch.event_ids
            ):
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Import batch identity is contradictory.",
                    retryable=False,
                )
            digest = digest_bytes(result_bytes)
            if row.result is not None:
                if row.result_bytes != result_bytes:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Import batch completion is contradictory.",
                        retryable=False,
                    )
                return self._allocation(job, allocation, ImportAllocationOutcome.RESUMED)
            self._state.batches[key] = replace(
                row, result=result, result_bytes=result_bytes, result_digest=digest
            )
            job = replace(job, phase=ImportPhase.PUBLISHING, revision=job.revision + 1)
            self._state.jobs[job.identity.identity_digest] = job
            self._state.revision += 1
            answer = self._allocation(job, allocation, ImportAllocationOutcome.RESUMED)
        await self._fault(MemoryImportFaultPoint.AFTER_BATCH_COMMIT)
        return answer

    async def prepare_report(
        self, allocation: ImportAllocation, report: EncryptedImportReportRef
    ) -> ImportAllocation:
        await read_exact_object(self._objects, report.report_object)
        await self._fault(MemoryImportFaultPoint.BEFORE_REPORT_READY_COMMIT)
        async with self._lock:
            job = self._require_lease(
                allocation,
                {ImportPhase.PLAN_READY, ImportPhase.PUBLISHING, ImportPhase.REPORT_READY},
            )
            rows = self._job_batches(job.identity.identity_digest)
            if any(row.result is None for row in rows):
                raise _error(
                    PublicErrorCode.OPERATION_PENDING,
                    "Import batches are not complete.",
                    retryable=True,
                )
            if job.phase is ImportPhase.REPORT_READY:
                if job.report_ref != report:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Import report identity is contradictory.",
                        retryable=False,
                    )
                return self._allocation(job, allocation, ImportAllocationOutcome.RESUMED)
            draft = report_evidence_draft(
                job, report, timestamp_from_datetime(self._clock.now_utc())
            )
            draft_bytes = event_draft_bytes(draft)
            terminal = JsonObject(
                cast(Mapping[object, object], strict_json_parse(report.terminal_result_bytes))
            )
            if canonical_digest(terminal) != report.terminal_result_digest:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Import report result is contradictory.",
                    retryable=False,
                )
            now = self._clock.now_utc()
            job = replace(
                job,
                phase=ImportPhase.REPORT_READY,
                revision=job.revision + 1,
                report_ref=report,
                report_evidence_draft=draft,
                report_evidence_draft_bytes=draft_bytes,
                report_evidence_draft_digest=digest_bytes(draft_bytes),
                lease_expires_at=max(
                    cast(datetime, job.lease_expires_at),
                    now + timedelta(seconds=self._policy.publication_window_seconds),
                ),
            )
            self._state.jobs[job.identity.identity_digest] = job
            self._state.revision += 1
            answer = self._allocation(job, allocation, ImportAllocationOutcome.RESUMED)
        await self._fault(MemoryImportFaultPoint.AFTER_REPORT_READY_COMMIT)
        return answer

    async def publish_report(
        self,
        allocation: ImportAllocation,
        report: EncryptedImportReportRef,
        evidence_result: AppendResult,
    ) -> ImportAllocation:
        if tuple(item.event_id for item in evidence_result.accepted) != (
            allocation.report_event_id,
        ):
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "Import report append is contradictory.",
                retryable=False,
            )
        await self._fault(MemoryImportFaultPoint.BEFORE_REPORT_PUBLISHED_COMMIT)
        async with self._lock:
            job = self._require_lease(
                allocation, {ImportPhase.REPORT_READY, ImportPhase.REPORT_PUBLISHED}
            )
            if job.report_ref != report:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Import report identity is contradictory.",
                    retryable=False,
                )
            if job.phase is ImportPhase.REPORT_PUBLISHED:
                if append_result_bytes(
                    cast(AppendResult, job.report_append_result)
                ) != append_result_bytes(evidence_result):
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Import report completion is contradictory.",
                        retryable=False,
                    )
                return self._allocation(job, allocation, ImportAllocationOutcome.RESUMED)
            job = replace(
                job,
                phase=ImportPhase.REPORT_PUBLISHED,
                revision=job.revision + 1,
                report_append_result=evidence_result,
            )
            self._state.jobs[job.identity.identity_digest] = job
            self._state.revision += 1
            answer = self._allocation(job, allocation, ImportAllocationOutcome.RESUMED)
        await self._fault(MemoryImportFaultPoint.AFTER_REPORT_PUBLISHED_COMMIT)
        return answer

    async def complete(self, allocation: ImportAllocation) -> ImportAllocation:
        await self._fault(MemoryImportFaultPoint.BEFORE_TERMINAL_COMMIT)
        async with self._lock:
            job = self._require_lease(allocation, {ImportPhase.REPORT_PUBLISHED})
            if job.report_ref is None or job.report_append_result is None:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Import terminal facts are incomplete.",
                    retryable=False,
                )
            job = replace(
                job,
                state=ImportState.COMPLETE,
                phase=ImportPhase.TERMINAL,
                revision=job.revision + 1,
                owner_generation=None,
                lease_owner_id=None,
                lease_generation=None,
                lease_expires_at=None,
                terminal_at=self._clock.now_utc(),
            )
            self._state.jobs[job.identity.identity_digest] = job
            self._state.revision += 1
            answer = self._allocation(job, allocation, ImportAllocationOutcome.REPLAYED)
        await self._fault(MemoryImportFaultPoint.AFTER_TERMINAL_COMMIT)
        return answer

    async def quarantine(self, allocation: ImportAllocation, reason: ImportSafeReason) -> None:
        async with self._lock:
            job = self._require_lease(allocation, set(ImportPhase) - {ImportPhase.TERMINAL})
            job = replace(
                job,
                state=ImportState.QUARANTINED,
                phase=ImportPhase.TERMINAL,
                revision=job.revision + 1,
                owner_generation=None,
                lease_owner_id=None,
                lease_generation=None,
                lease_expires_at=None,
                terminal_at=self._clock.now_utc(),
                quarantine_code=reason.code,
            )
            self._state.jobs[job.identity.identity_digest] = job
            self._state.revision += 1

    async def status(self, session_id: str) -> ImportStatusSnapshot:
        if session_id != self._session_id:
            raise _error(
                PublicErrorCode.INVALID_REQUEST, "Import session is invalid.", retryable=False
            )
        async with self._lock:
            jobs = tuple(job for job in self._state.jobs.values() if job.session_id == session_id)
            active = tuple(
                sorted(
                    (job for job in jobs if job.state is ImportState.PENDING),
                    key=lambda value: value.identity.identity_digest.encode("ascii"),
                )
            )
            terminal = tuple(
                sorted(
                    (
                        job
                        for job in jobs
                        if job.state is not ImportState.PENDING
                        and job.report_append_result is not None
                    ),
                    key=lambda value: value.identity.identity_digest.encode("ascii"),
                )
            )
            active_rows = tuple(
                JsonObject(
                    {
                        "identity_digest": job.identity.identity_digest,
                        "phase": job.phase.value,
                        "completed_batch_count": self._completed_count(
                            job.identity.identity_digest
                        ),
                        "batch_count": len(self._job_batches(job.identity.identity_digest)),
                    }
                )
                for job in active[: self._policy.status_jobs]
            )
            terminal_rows = tuple(
                JsonObject(
                    {
                        "identity_digest": job.identity.identity_digest,
                        "report_evidence_id": job.report_evidence_id,
                    }
                )
                for job in terminal[: self._policy.status_jobs]
            )
        return ImportStatusSnapshot(
            self._session_id, len(active), len(jobs) - len(active), active_rows, terminal_rows
        )

    async def load_review_source(
        self, identity_digest: str, through: Frontier
    ) -> ImportReviewSource | None:
        validate_sha256_digest(identity_digest)
        async with self._lock:
            job = self._state.jobs.get(identity_digest)
            if job is None:
                return None
            if job.identity.identity_digest != identity_digest:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Import review identity is contradictory.",
                    retryable=False,
                )
            if job.state is ImportState.QUARANTINED:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Import review source is quarantined.",
                    retryable=False,
                )
            rows = self._job_batches(identity_digest)
            completed = tuple(row.result for row in rows if row.result is not None)
            report_result = job.report_append_result
        await read_exact_object(self._objects, job.source.source_object)
        await read_exact_object(self._objects, job.source.capture_metadata_object)
        if job.report_ref is not None:
            await read_exact_object(self._objects, job.report_ref.report_object)
        selected_frontiers = tuple(result.result_frontier for result in completed) + (
            () if report_result is None else (report_result.result_frontier,)
        )
        if any(not _frontier_at_or_before(value, through) for value in selected_frontiers):
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Review frontier cuts an import batch.",
                retryable=False,
            )
        outcomes_by_ordinal: dict[int, ImportLineOutcome] = {}
        gaps_by_range: dict[tuple[int, int, int, str], ImportGap] = {}
        mapped: list[EventId] = []
        coverage = coverage_for_channel(PublicationChannel.CODEX_JSONL_IMPORT)
        for row in rows:
            material = await self._plan_reader(row.plan_object)
            if tuple(draft.event_id for draft in material.event_drafts) != row.event_ids:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Import review plan identity is contradictory.",
                    retryable=False,
                )
            coverage = weakest(coverage, material.coverage)
            for outcome in material.line_outcomes:
                prior = outcomes_by_ordinal.setdefault(outcome.line_ordinal, outcome)
                if prior != outcome:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Import review line outcome is contradictory.",
                        retryable=False,
                    )
            for gap in material.gaps:
                key = (gap.line_ordinal, gap.byte_start, gap.byte_end, gap.code)
                prior_gap = gaps_by_range.setdefault(key, gap)
                if prior_gap != gap:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Import review gap is contradictory.",
                        retryable=False,
                    )
            if row.result is not None:
                mapped.extend(row.event_ids)
        if job.state is ImportState.COMPLETE and report_result is None:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "Complete import review is missing report evidence.",
                retryable=False,
            )
        return ImportReviewSource(
            identity=job.identity,
            through=through,
            state=job.state,
            phase=job.phase,
            publishing_writer_id=job.publishing_writer_id,
            source_object=job.source.source_object,
            source_commitment=job.source.source_commitment,
            plan_object_refs=tuple(row.plan_object for row in rows),
            plan_digest=job.plan_digest,
            report_object=None if job.report_ref is None else job.report_ref.report_object,
            report_digest=None if job.report_ref is None else job.report_ref.report_digest,
            completed_batch_results=completed,
            mapped_event_ids=tuple(mapped),
            line_outcomes=tuple(
                outcomes_by_ordinal[index] for index in sorted(outcomes_by_ordinal)
            ),
            gaps=tuple(gaps_by_range[index] for index in sorted(gaps_by_range)),
            coverage=coverage,
            codex_capability_profile_id=job.identity.codex_capability_profile_id,
            mapping_version=job.identity.mapping_version,
            import_incomplete=job.state is ImportState.PENDING,
        )

    def _require_lease(self, supplied: ImportAllocation, phases: set[ImportPhase]) -> _Job:
        job = self._state.jobs.get(supplied.source_identity.identity_digest)
        now = self._clock.now_utc()
        if (
            job is None
            or job.state is not ImportState.PENDING
            or job.phase not in phases
            or job.owner_generation != self._fence.owner_generation
            or job.owner_generation != supplied.owner_generation
            or job.lease_owner_id != self._fence.service_instance_id
            or job.lease_owner_id != supplied.lease_owner_id
            or job.lease_generation != supplied.lease_generation
            or job.lease_expires_at is None
            or job.lease_expires_at <= now
            or job.publishing_writer_id != supplied.publishing_writer_id
        ):
            raise _error(
                PublicErrorCode.OPERATION_PENDING,
                "Import lease is no longer current.",
                retryable=True,
            )
        return job

    def _job_batches(self, identity_digest: str) -> tuple[_Batch, ...]:
        return tuple(
            row
            for (identity, _), row in sorted(self._state.batches.items())
            if identity == identity_digest
        )

    def _completed_count(self, identity_digest: str) -> int:
        return sum(row.result is not None for row in self._job_batches(identity_digest))

    def _allocation(
        self,
        job: _Job,
        command: ImportCommand | ImportAllocation,
        outcome: ImportAllocationOutcome,
    ) -> ImportAllocation:
        rows = self._job_batches(job.identity.identity_digest)
        report = job.report_ref
        terminal_result = None
        terminal_bytes = None
        terminal_digest = None
        if report is not None:
            terminal_bytes = report.terminal_result_bytes
            terminal_digest = report.terminal_result_digest
            terminal_result = JsonObject(
                cast(Mapping[object, object], strict_json_parse(terminal_bytes))
            )
        elif job.state is ImportState.QUARANTINED:
            terminal_result = JsonObject(
                {"quarantine_code": cast(str, job.quarantine_code), "state": "quarantined"}
            )
            terminal_bytes = canonical_encode(terminal_result)
            terminal_digest = canonical_digest(terminal_result)
        replayed = (
            report
            if outcome is ImportAllocationOutcome.REPLAYED and job.state is ImportState.COMPLETE
            else None
        )
        return ImportAllocation(
            outcome=outcome,
            source_identity=job.identity,
            session_id=job.session_id,
            requesting_writer_id=command.requesting_writer_id,
            request_id=command.request_id,
            publishing_writer_id=job.publishing_writer_id,
            state=job.state,
            phase=job.phase,
            owner_generation=job.owner_generation or self._fence.owner_generation,
            lease_owner_id=job.lease_owner_id,
            lease_generation=job.lease_generation,
            lease_expires_at=None
            if job.lease_expires_at is None
            else timestamp_from_datetime(job.lease_expires_at),
            captured_source=job.source,
            source_object=job.source.source_object,
            source_commitment=job.source.source_commitment,
            plan_digest=job.plan_digest,
            plan_object_refs=tuple(row.plan_object for row in rows),
            batch_count=len(rows),
            completed_batch_count=sum(row.result is not None for row in rows),
            report_object=None if report is None else report.report_object,
            report_digest=None if report is None else report.report_digest,
            terminal_result=terminal_result,
            terminal_result_bytes=terminal_bytes,
            terminal_result_digest=terminal_digest,
            report_request_id=job.report_request_id,
            report_event_id=job.report_event_id,
            report_evidence_id=job.report_evidence_id,
            report_evidence_draft=job.report_evidence_draft,
            report_evidence_draft_bytes=job.report_evidence_draft_bytes,
            report_evidence_draft_digest=job.report_evidence_draft_digest,
            replayed_report=replayed,
        )


class _ReportIdentity(Protocol):
    @property
    def report_event_id(self) -> EventId | None: ...

    @property
    def report_evidence_id(self) -> EvidenceId | None: ...


def report_evidence_draft(
    job: _ReportIdentity, report: EncryptedImportReportRef, observed_at: Timestamp
) -> EventDraft:
    return EventDraft(
        event_id=event_id(job.report_event_id),
        schema=EventSchema("evidence_recorded", EVIDENCE_TYPED_SCHEMA_VERSION),
        occurred_at=observed_at,
        causal_parents=(),
        payload=EvidenceRecordedPayload(
            evidence_id=evidence_id(job.report_evidence_id),
            evidence_kind=EvidenceKind.IMPORT_REPORT,
            strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
            observed_at=observed_at,
            captured_object_id=object_id(report.report_object.object_id),
            content_digest=report.report_digest,
            digest_binding=EvidenceDigestBinding(
                subject=EvidenceDigestSubject.IMPORT_REPORT,
                content_availability=EvidenceContentAvailability.CAPTURED,
                byte_count=report.report_object.plaintext_size,
                provenance=EvidenceDigestProvenance.IMPORT_OBSERVED,
            ),
        ),
        artifact_refs=(object_id(report.report_object.object_id),),
        evidence_refs=(),
    )


def _event_draft_json(value: EventDraft) -> JsonObject:
    payload = (
        encode_payload(cast(EventPayload, value.payload))
        if value.schema in PAYLOAD_TYPES
        else cast(JsonValue, value.payload)
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


def event_draft_bytes(value: EventDraft) -> bytes:
    return canonical_encode(_event_draft_json(value))


def event_draft_from_json(value: object) -> EventDraft:
    row = cast(Mapping[str, object], value)
    schema_row = cast(Mapping[str, object], row["schema"])
    schema = EventSchema(cast(str, schema_row["name"]), cast(str, schema_row["version"]))
    return EventDraft(
        event_id=event_id(row["event_id"]),
        schema=schema,
        occurred_at=timestamp_from_string(row["occurred_at"]),
        causal_parents=tuple(
            event_id(item) for item in cast(tuple[object, ...], row["causal_parents"])
        ),
        payload=(
            decode_payload(schema, cast(DomainJsonValue, row["payload"]))
            if schema in PAYLOAD_TYPES
            else cast(DomainJsonValue, row["payload"])
        ),
        artifact_refs=tuple(
            object_id(item) for item in cast(tuple[object, ...], row["artifact_refs"])
        ),
        evidence_refs=tuple(
            evidence_id(item) for item in cast(tuple[object, ...], row["evidence_refs"])
        ),
    )


async def read_exact_object(objects: ObjectStorePort, ref: ObjectRef) -> bytes:
    chunks = bytearray()
    async for chunk in objects.open_verified(ref):
        chunks.extend(chunk)
    value = bytes(chunks)
    if len(value) != ref.plaintext_size:
        raise _error(
            PublicErrorCode.STORAGE_CORRUPT, "Import object size is contradictory.", retryable=False
        )
    return value


async def decode_plan_object(
    objects: ObjectStorePort, ref: ObjectRef
) -> tuple[tuple[EventDraft, ...], tuple[ImportGap, ...]]:
    raw = await read_exact_object(objects, ref)
    parsed = strict_json_parse(raw)
    if not isinstance(parsed, Mapping) or canonical_encode(parsed) != raw:
        raise _error(
            PublicErrorCode.STORAGE_CORRUPT, "Import plan object is not canonical.", retryable=False
        )
    drafts = tuple(
        event_draft_from_json(value) for value in cast(tuple[object, ...], parsed["event_drafts"])
    )
    gaps: list[ImportGap] = []
    for value in cast(tuple[object, ...], parsed.get("gaps", ())):
        row = cast(Mapping[str, object], value)
        gaps.append(
            ImportGap(
                code=cast(str, row["code"]),
                source_object_id=cast(str, row["source_object_id"]),
                line_ordinal=cast(int, row["line_ordinal"]),
                byte_start=cast(int, row["byte_start"]),
                byte_end=cast(int, row["byte_end"]),
                coverage=coverage_from_json(cast(JsonValue, row["coverage"])),
            )
        )
    return drafts, tuple(gaps)


def _append_result_json(result: AppendResult) -> JsonObject:
    return JsonObject(
        {
            "outcome": result.outcome,
            "accepted": tuple(
                {
                    "event_id": item.event_id,
                    "ingestion_sequence": item.ingestion_sequence,
                    "writer_sequence": item.writer_sequence,
                    "entry_digest": item.entry_digest,
                    "projection_status": item.projection_status,
                }
                for item in result.accepted
            ),
            "subject_frontier": result.subject_frontier.as_wire(),
            "result_frontier": result.result_frontier.as_wire(),
            "warnings": tuple(item.value for item in result.warnings),
        }
    )


def append_result_bytes(result: AppendResult) -> bytes:
    return canonical_encode(_append_result_json(result))


def append_result_from_bytes(value: bytes) -> AppendResult:
    parsed = cast(Mapping[str, object], strict_json_parse(value))
    return AppendResult(
        outcome=cast(Literal["accepted", "replayed"], parsed["outcome"]),
        accepted=tuple(
            AcceptedEventSummary(
                event_id=cast(str, row["event_id"]),
                ingestion_sequence=cast(int, row["ingestion_sequence"]),
                writer_sequence=cast(int, row["writer_sequence"]),
                entry_digest=cast(str, row["entry_digest"]),
                projection_status=cast(
                    Literal["projected", "unknown_unprojected"], row["projection_status"]
                ),
            )
            for row in cast(tuple[Mapping[str, object], ...], parsed["accepted"])
        ),
        subject_frontier=frontier_from_json(parsed["subject_frontier"]),
        result_frontier=frontier_from_json(parsed["result_frontier"]),
        warnings=tuple(
            AppendWarning(cast(str, item)) for item in cast(tuple[object, ...], parsed["warnings"])
        ),
    )
