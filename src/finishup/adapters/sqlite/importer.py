"""Durable SQLite persistence for the bounded importer state machine."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal, cast

import apsw

from finishup.adapters.memory.importer import (
    ImportPlanMaterial,
    MemoryImporter,
    MemoryImportPolicy,
    MemoryImportState,
    append_result_bytes,
    append_result_from_bytes,
    digest_bytes,
    event_draft_bytes,
    event_draft_from_json,
    read_exact_object,
    report_evidence_draft,
)
from finishup.adapters.sqlite.connection import SqliteWriterThread
from finishup.domain.values import (
    EventId,
    EvidenceId,
    Frontier,
    JsonObject,
    event_id,
    evidence_id,
    format_rfc3339_millis,
    parse_rfc3339_millis,
    request_id,
    task_id,
    timestamp_from_datetime,
    validate_sha256_digest,
    writer_id,
)
from finishup.domain.values import (
    session_id as validate_session_id,
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
from finishup.ports.ledger import AppendResult, LedgerPort
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectStorePort
from finishup.ports.runtime import OwnershipFence
from finishup.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse
from finishup.protocol.coverage import PublicationChannel, coverage_for_channel, weakest
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import MAX_CANONICAL_REQUEST_BYTES, MAX_EVENTS_PER_BATCH

__all__ = ["IMPORT_SCHEMA_VERSION", "SqliteImportPolicy", "SqliteImporter"]

IMPORT_SCHEMA_VERSION: Final = 1

type ReadFactory = Callable[[], apsw.Connection]
type PlanPreparer = Callable[[ImportAllocation], Awaitable[PreparedImportPlan]]
type PlanReader = Callable[[ObjectRef], Awaitable[ImportPlanMaterial]]


@dataclass(frozen=True, slots=True)
class SqliteImportPolicy:
    source_bytes: int = 4 * 1024 * 1024
    line_bytes: int = 1024 * 1024
    line_count: int = 20_000
    batch_count: int = 1_024
    lease_seconds: int = 60
    publication_window_seconds: int = 30
    status_jobs: int = 64

    def __post_init__(self) -> None:
        MemoryImportPolicy(
            self.source_bytes,
            self.line_bytes,
            self.line_count,
            self.batch_count,
            self.lease_seconds,
            self.publication_window_seconds,
            self.status_jobs,
        )


@dataclass(frozen=True, slots=True)
class _ReportIds:
    report_event_id: EventId
    report_evidence_id: EvidenceId


def _error(code: PublicErrorCode, message: str, *, retryable: bool) -> PublicOperationError:
    return PublicOperationError(code, message, retryable)


def _frontier_at_or_before(value: Frontier, through: Frontier) -> bool:
    if value.sequence < through.sequence:
        return True
    return value.sequence == through.sequence and value.head_digest == through.head_digest


class SqliteImporter:
    def __init__(
        self,
        *,
        task_id: str,
        admitted_session_id: str,
        ownership_fence: OwnershipFence,
        writer: SqliteWriterThread,
        read_factory: ReadFactory,
        objects: ObjectStorePort,
        ledger: LedgerPort,
        clock: ClockPort,
        ids: IdPort,
        plan_preparer: PlanPreparer,
        plan_reader: PlanReader,
        policy: SqliteImportPolicy = SqliteImportPolicy(),
    ) -> None:
        if (
            type(ownership_fence) is not OwnershipFence
            or not callable(read_factory)
            or not callable(plan_preparer)
            or not callable(plan_reader)
        ):
            raise TypeError("sqlite_importer_construction_invalid")
        self._task_id = task_id
        self._session_id = admitted_session_id
        self._fence = ownership_fence
        self._writer = writer
        self._read_factory = read_factory
        self._objects = objects
        self._ledger = ledger
        self._clock = clock
        self._ids = ids
        self._plan_preparer = plan_preparer
        self._plan_reader = plan_reader
        self._policy = policy
        self._refs: dict[str, ObjectRef] = {}
        self._capture_delegate = MemoryImporter(
            task_id=task_id,
            admitted_session_id=admitted_session_id,
            ownership_fence=ownership_fence,
            state=MemoryImportState(),
            transaction_lock=asyncio.Lock(),
            objects=objects,
            ledger=ledger,
            clock=clock,
            ids=ids,
            plan_preparer=plan_preparer,
            plan_reader=plan_reader,
            policy=MemoryImportPolicy(),
        )

    def rebind_session(self, admitted_session_id: str) -> None:
        """Refresh the route session held by the task-owned capture delegate.

        Runtime attachment may rotate a task's session while retaining its open SQLite bundle
        ports. Import identity remains task-bound, while the session fence follows the active
        authenticated route.
        """

        current = validate_session_id(admitted_session_id)
        self._session_id = current
        self._capture_delegate.rebind_session(current)

    async def _submit[T](self, function: Callable[[apsw.Connection], T]) -> T:
        future: Future[T] = self._writer.submit(function)
        try:
            return await asyncio.wrap_future(future)
        except apsw.ConstraintError as exc:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "Importer persistence constraint failed.",
                retryable=False,
            ) from exc

    async def capture(self, value: ImportCaptureInput) -> CapturedImportSource:
        result = await self._capture_delegate.capture(value)
        self._refs[result.source_object.object_id] = result.source_object
        self._refs[result.capture_metadata_object.object_id] = result.capture_metadata_object
        return result

    def _validate_source(self, command: ImportCommand, source: CapturedImportSource) -> None:
        expected = canonical_digest(
            {
                "codex_capability_profile_id": source.codex_capability_profile_id,
                "mapping_version": command.mapping_version,
                "source_commitment": source.source_commitment,
                "task_id": self._task_id,
            }
        )
        identity = command.source_identity
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
        self._refs[source.source_object.object_id] = source.source_object
        self._refs[source.capture_metadata_object.object_id] = source.capture_metadata_object
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)

        def transaction(db: apsw.Connection) -> tuple[tuple[object, ...], ImportAllocationOutcome]:
            self._begin(db)
            try:
                self._verify_meta(db)
                alias = db.execute(
                    "SELECT request_digest, source_identity_digest FROM import_request_aliases "
                    "WHERE requesting_writer_id=? AND request_id=?",
                    (command.requesting_writer_id, command.request_id),
                ).fetchone()
                if alias is not None and (
                    alias[0] != command.request_digest
                    or alias[1] != command.source_identity.identity_digest
                ):
                    raise _error(
                        PublicErrorCode.IDEMPOTENCY_CONFLICT,
                        "Import request conflicts with prior use.",
                        retryable=False,
                    )
                row = self._job_row(db, command.source_identity.identity_digest)
                if row is None:
                    self._insert_object(db, source.source_object)
                    self._insert_object(db, source.capture_metadata_object)
                    expires = format_rfc3339_millis(
                        now + timedelta(seconds=self._policy.lease_seconds)
                    )
                    db.execute(
                        """INSERT INTO import_jobs(
                        source_identity_digest, task_id, session_id, source_commitment,
                        codex_capability_profile_id, mapping_version, publishing_writer_id,
                        source_object_id, capture_metadata_object_id,
                        capture_metadata_object_commitment, source_byte_count, source_line_count,
                        source_final_newline, codex_version, source_kind, source_exit_status,
                        stderr_present, stderr_captured_byte_count, stderr_truncated,
                        stderr_commitment, metadata_digest, state, phase, job_revision,
                        owner_generation, lease_owner_id, lease_generation, lease_expires_at,
                        batch_count, completed_batch_count, created_at, updated_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
                                  'pending','source_reserved',0,?,?,?,?,0,0,?,?)""",
                        (
                            command.source_identity.identity_digest,
                            self._task_id,
                            self._session_id,
                            source.source_commitment,
                            source.codex_capability_profile_id,
                            command.mapping_version,
                            command.requesting_writer_id,
                            source.source_object.object_id,
                            source.capture_metadata_object.object_id,
                            source.capture_metadata_object.commitment,
                            source.byte_count,
                            source.line_count,
                            int(source.final_newline),
                            source.codex_version,
                            source.source_kind,
                            source.exit_status,
                            int(source.stderr_present),
                            source.stderr_captured_bytes,
                            int(source.stderr_truncated),
                            source.stderr_commitment,
                            source.metadata_digest,
                            str(self._fence.owner_generation),
                            self._fence.service_instance_id,
                            1,
                            expires,
                            now_wire,
                            now_wire,
                        ),
                    )
                    outcome = ImportAllocationOutcome.RESERVED
                else:
                    # Same boundary and same order as MemoryImporter: refuse a foreign writer
                    # before the terminal branch can replay the publishing writer's report,
                    # request id, and report locator, and before the alias insert below binds
                    # the caller's request id to a job it can never own. row[6] is
                    # publishing_writer_id.
                    if row[6] != command.requesting_writer_id:
                        raise _error(
                            PublicErrorCode.INVALID_REQUEST,
                            "This import source belongs to a different writer.",
                            retryable=False,
                        )
                    state = cast(str, row[21])
                    if state != ImportState.PENDING.value:
                        outcome = ImportAllocationOutcome.REPLAYED
                    else:
                        live = (
                            row[24] == str(self._fence.owner_generation)
                            and row[27] is not None
                            and parse_rfc3339_millis(row[27]) > now
                        )
                        if live:
                            raise _error(
                                PublicErrorCode.OPERATION_PENDING,
                                "Import is already pending.",
                                retryable=True,
                            )
                        expires = format_rfc3339_millis(
                            now + timedelta(seconds=self._policy.lease_seconds)
                        )
                        db.execute(
                            "UPDATE import_jobs SET owner_generation=?, lease_owner_id=?, "
                            "lease_generation=lease_generation+1, lease_expires_at=?, "
                            "job_revision=job_revision+1, updated_at=? "
                            "WHERE source_identity_digest=?",
                            (
                                str(self._fence.owner_generation),
                                self._fence.service_instance_id,
                                expires,
                                now_wire,
                                command.source_identity.identity_digest,
                            ),
                        )
                        outcome = ImportAllocationOutcome.RESUMED
                db.execute(
                    "INSERT OR IGNORE INTO import_request_aliases VALUES (?,?,?,?,?)",
                    (
                        command.requesting_writer_id,
                        command.request_id,
                        command.request_digest,
                        command.source_identity.identity_digest,
                        now_wire,
                    ),
                )
                row = cast(
                    tuple[object, ...], self._job_row(db, command.source_identity.identity_digest)
                )
                db.execute("COMMIT")
                return row, outcome
            except BaseException:
                self._rollback(db)
                raise

        row, outcome = await self._submit(transaction)
        return await self._allocation(row, command, outcome)

    async def prepare_plan(self, allocation: ImportAllocation) -> PreparedImportPlan:
        now = self._clock.now_utc()

        def snapshot(db: apsw.Connection) -> None:
            self._begin(db)
            try:
                self._require_lease_row(db, allocation, {ImportPhase.SOURCE_RESERVED}, now)
                db.execute("COMMIT")
            except BaseException:
                self._rollback(db)
                raise

        await self._submit(snapshot)
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
            self._refs[ref.object_id] = ref
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
        manifest_bytes = canonical_encode(
            {"request_ids": plan.batch_request_ids, "event_ids": tuple(groups)}
        )
        if (
            len(groups) > self._policy.batch_count
            or len(groups) != len(plan.batch_request_ids)
            or len(manifest_bytes) > MAX_CANONICAL_REQUEST_BYTES
        ):
            raise _error(
                PublicErrorCode.LIMIT_EXCEEDED,
                "Import plan aggregate is outside release bounds.",
                retryable=False,
            )
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)

        def transaction(db: apsw.Connection) -> tuple[object, ...]:
            self._begin(db)
            try:
                self._verify_meta(db)
                row = self._require_lease_row(db, allocation, {ImportPhase.SOURCE_RESERVED}, now)
                for index, (request, ref, event_ids) in enumerate(
                    zip(plan.batch_request_ids, plan.batch_plan_objects, groups, strict=True)
                ):
                    self._insert_object(db, ref)
                    event_bytes = canonical_encode(event_ids)
                    db.execute(
                        "INSERT INTO import_batches VALUES "
                        "(?,?,'planned',?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,?,?)",
                        (
                            allocation.source_identity.identity_digest,
                            index,
                            request,
                            ref.object_id,
                            ref.commitment,
                            plan.plan_digest,
                            event_bytes,
                            digest_bytes(event_bytes),
                            len(event_ids),
                            now_wire,
                            now_wire,
                        ),
                    )
                for ordinal, request in enumerate(
                    (*plan.batch_request_ids, plan.report_request_id)
                ):
                    db.execute(
                        "INSERT INTO import_publication_requests VALUES (?,?,?,?)",
                        (
                            allocation.publishing_writer_id,
                            request,
                            allocation.source_identity.identity_digest,
                            ordinal,
                        ),
                    )
                expires = max(
                    parse_rfc3339_millis(cast(str, row[27])),
                    now + timedelta(seconds=self._policy.publication_window_seconds),
                )
                db.execute(
                    "UPDATE import_jobs SET phase='plan_ready', job_revision=job_revision+1, "
                    "plan_digest=?, batch_count=?, report_request_id=?, report_event_id=?, "
                    "report_evidence_id=?, lease_expires_at=?, updated_at=? "
                    "WHERE source_identity_digest=?",
                    (
                        plan.plan_digest,
                        len(groups),
                        plan.report_request_id,
                        plan.report_event_id,
                        plan.report_evidence_id,
                        format_rfc3339_millis(expires),
                        now_wire,
                        allocation.source_identity.identity_digest,
                    ),
                )
                updated = cast(
                    tuple[object, ...],
                    self._job_row(db, allocation.source_identity.identity_digest),
                )
                db.execute("COMMIT")
                return updated
            except BaseException:
                self._rollback(db)
                raise

        row = await self._submit(transaction)
        return await self._allocation(row, allocation, ImportAllocationOutcome.RESUMED)

    async def next_batch(self, allocation: ImportAllocation) -> ImportBatchSelection:
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)

        def transaction(
            db: apsw.Connection,
        ) -> tuple[tuple[object, ...], tuple[object, ...] | None]:
            self._begin(db)
            try:
                row = self._require_lease_row(
                    db, allocation, {ImportPhase.PLAN_READY, ImportPhase.PUBLISHING}, now
                )
                expires = max(
                    parse_rfc3339_millis(cast(str, row[27])),
                    now + timedelta(seconds=self._policy.publication_window_seconds),
                )
                db.execute(
                    "UPDATE import_jobs SET job_revision=job_revision+1, lease_expires_at=?, "
                    "updated_at=? WHERE source_identity_digest=?",
                    (
                        format_rfc3339_millis(expires),
                        now_wire,
                        allocation.source_identity.identity_digest,
                    ),
                )
                batch = db.execute(
                    "SELECT batch_index, request_id, plan_object_id, plan_digest, "
                    "event_ids_canonical FROM import_batches WHERE source_identity_digest=? "
                    "AND state='planned' ORDER BY batch_index LIMIT 1",
                    (allocation.source_identity.identity_digest,),
                ).fetchone()
                updated = cast(
                    tuple[object, ...],
                    self._job_row(db, allocation.source_identity.identity_digest),
                )
                db.execute("COMMIT")
                return updated, None if batch is None else tuple(batch)
            except BaseException:
                self._rollback(db)
                raise

        row, batch_row = await self._submit(transaction)
        refreshed = await self._allocation(row, allocation, ImportAllocationOutcome.RESUMED)
        if batch_row is None:
            return ImportBatchSelection(refreshed, None)
        ref = self._object_ref(cast(str, batch_row[2]), ObjectKind.IMPORT_PLAN)
        material = await self._plan_reader(ref)
        parsed_ids = cast(tuple[object, ...], strict_json_parse(cast(bytes, batch_row[4])))
        ids = tuple(event_id(item) for item in parsed_ids)
        if tuple(draft.event_id for draft in material.event_drafts) != ids:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "Import batch object contradicts its manifest.",
                retryable=False,
            )
        return ImportBatchSelection(
            refreshed,
            ImportBatch(
                batch_index=cast(int, batch_row[0]),
                batch_count=refreshed.batch_count,
                request_id=request_id(batch_row[1]),
                event_ids=ids,
                event_drafts=material.event_drafts,
                plan_object=ref,
                plan_digest=cast(str, batch_row[3]),
                gaps=material.gaps,
            ),
        )

    async def release_lease_for_authorization(self, allocation: ImportAllocation) -> None:
        """Make a prepared, unpublished plan immediately resumable after consent."""

        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)

        def transaction(db: apsw.Connection) -> None:
            self._begin(db)
            try:
                self._require_lease_row(db, allocation, {ImportPhase.PLAN_READY}, now)
                db.execute(
                    "UPDATE import_jobs SET job_revision=job_revision+1, lease_expires_at=?, "
                    "updated_at=? WHERE source_identity_digest=?",
                    (now_wire, now_wire, allocation.source_identity.identity_digest),
                )
                db.execute("COMMIT")
            except BaseException:
                self._rollback(db)
                raise

        await self._submit(transaction)

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
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)

        def transaction(db: apsw.Connection) -> tuple[object, ...]:
            self._begin(db)
            try:
                self._require_lease_row(
                    db, allocation, {ImportPhase.PLAN_READY, ImportPhase.PUBLISHING}, now
                )
                row = db.execute(
                    "SELECT state, request_id, event_ids_canonical, append_result_canonical "
                    "FROM import_batches WHERE source_identity_digest=? AND batch_index=?",
                    (allocation.source_identity.identity_digest, batch.batch_index),
                ).fetchone()
                if (
                    row is None
                    or row[1] != batch.request_id
                    or tuple(
                        event_id(item)
                        for item in cast(tuple[object, ...], strict_json_parse(row[2]))
                    )
                    != batch.event_ids
                ):
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Import batch identity is contradictory.",
                        retryable=False,
                    )
                if row[0] == "complete":
                    if row[3] != result_bytes:
                        raise _error(
                            PublicErrorCode.STORAGE_CORRUPT,
                            "Import batch completion is contradictory.",
                            retryable=False,
                        )
                else:
                    first = result.accepted[0].ingestion_sequence
                    last = result.accepted[-1].ingestion_sequence
                    db.execute(
                        "UPDATE import_batches SET state='complete', append_result_canonical=?, "
                        "append_result_digest=?, subject_frontier_seq=?, subject_frontier_digest=?, "
                        "result_frontier_seq=?, result_frontier_digest=?, first_ingestion_seq=?, "
                        "last_ingestion_seq=?, completed_at=?, updated_at=? "
                        "WHERE source_identity_digest=? AND batch_index=?",
                        (
                            result_bytes,
                            digest_bytes(result_bytes),
                            result.subject_frontier.sequence,
                            result.subject_frontier.head_digest,
                            result.result_frontier.sequence,
                            result.result_frontier.head_digest,
                            first,
                            last,
                            now_wire,
                            now_wire,
                            allocation.source_identity.identity_digest,
                            batch.batch_index,
                        ),
                    )
                    db.execute(
                        "UPDATE import_jobs SET phase='publishing', "
                        "completed_batch_count=completed_batch_count+1, "
                        "job_revision=job_revision+1, updated_at=? "
                        "WHERE source_identity_digest=?",
                        (now_wire, allocation.source_identity.identity_digest),
                    )
                updated = cast(
                    tuple[object, ...],
                    self._job_row(db, allocation.source_identity.identity_digest),
                )
                db.execute("COMMIT")
                return updated
            except BaseException:
                self._rollback(db)
                raise

        row = await self._submit(transaction)
        return await self._allocation(row, allocation, ImportAllocationOutcome.RESUMED)

    async def prepare_report(
        self, allocation: ImportAllocation, report: EncryptedImportReportRef
    ) -> ImportAllocation:
        await read_exact_object(self._objects, report.report_object)
        self._refs[report.report_object.object_id] = report.report_object
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)

        def transaction(db: apsw.Connection) -> tuple[object, ...]:
            self._begin(db)
            try:
                row = self._require_lease_row(
                    db,
                    allocation,
                    {ImportPhase.PLAN_READY, ImportPhase.PUBLISHING, ImportPhase.REPORT_READY},
                    now,
                )
                if row[22] == ImportPhase.REPORT_READY.value:
                    if row[34] != report.report_object.object_id or row[35] != report.report_digest:
                        raise _error(
                            PublicErrorCode.STORAGE_CORRUPT,
                            "Import report identity is contradictory.",
                            retryable=False,
                        )
                else:
                    if row[30] != row[29]:
                        raise _error(
                            PublicErrorCode.OPERATION_PENDING,
                            "Import batches are not complete.",
                            retryable=True,
                        )
                    self._insert_object(db, report.report_object)
                    shadow = _ReportIds(event_id(row[32]), evidence_id(row[33]))
                    draft = report_evidence_draft(shadow, report, timestamp_from_datetime(now))
                    draft_bytes = event_draft_bytes(draft)
                    expires = max(
                        parse_rfc3339_millis(cast(str, row[27])),
                        now + timedelta(seconds=self._policy.publication_window_seconds),
                    )
                    db.execute(
                        "UPDATE import_jobs SET phase='report_ready', job_revision=job_revision+1, "
                        "report_object_id=?, report_digest=?, report_result_canonical=?, "
                        "report_result_digest=?, report_evidence_draft_canonical=?, "
                        "report_evidence_draft_digest=?, lease_expires_at=?, updated_at=? "
                        "WHERE source_identity_digest=?",
                        (
                            report.report_object.object_id,
                            report.report_digest,
                            report.terminal_result_bytes,
                            report.terminal_result_digest,
                            draft_bytes,
                            digest_bytes(draft_bytes),
                            format_rfc3339_millis(expires),
                            now_wire,
                            allocation.source_identity.identity_digest,
                        ),
                    )
                updated = cast(
                    tuple[object, ...],
                    self._job_row(db, allocation.source_identity.identity_digest),
                )
                db.execute("COMMIT")
                return updated
            except BaseException:
                self._rollback(db)
                raise

        row = await self._submit(transaction)
        return await self._allocation(row, allocation, ImportAllocationOutcome.RESUMED)

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
        result_bytes = append_result_bytes(evidence_result)
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)

        def transaction(db: apsw.Connection) -> tuple[object, ...]:
            self._begin(db)
            try:
                row = self._require_lease_row(
                    db,
                    allocation,
                    {ImportPhase.REPORT_READY, ImportPhase.REPORT_PUBLISHED},
                    now,
                )
                if row[34] != report.report_object.object_id or row[35] != report.report_digest:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Import report identity is contradictory.",
                        retryable=False,
                    )
                if row[22] == ImportPhase.REPORT_PUBLISHED.value:
                    if row[40] != result_bytes:
                        raise _error(
                            PublicErrorCode.STORAGE_CORRUPT,
                            "Import report completion is contradictory.",
                            retryable=False,
                        )
                else:
                    accepted = evidence_result.accepted[0]
                    db.execute(
                        "UPDATE import_jobs SET phase='report_published', job_revision=job_revision+1, "
                        "report_append_result_canonical=?, report_append_result_digest=?, "
                        "report_ingestion_seq=?, report_entry_digest=?, updated_at=? "
                        "WHERE source_identity_digest=?",
                        (
                            result_bytes,
                            digest_bytes(result_bytes),
                            accepted.ingestion_sequence,
                            accepted.entry_digest,
                            now_wire,
                            allocation.source_identity.identity_digest,
                        ),
                    )
                updated = cast(
                    tuple[object, ...],
                    self._job_row(db, allocation.source_identity.identity_digest),
                )
                db.execute("COMMIT")
                return updated
            except BaseException:
                self._rollback(db)
                raise

        row = await self._submit(transaction)
        return await self._allocation(row, allocation, ImportAllocationOutcome.RESUMED)

    async def complete(self, allocation: ImportAllocation) -> ImportAllocation:
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)

        def transaction(db: apsw.Connection) -> tuple[object, ...]:
            self._begin(db)
            try:
                self._require_lease_row(db, allocation, {ImportPhase.REPORT_PUBLISHED}, now)
                db.execute(
                    "UPDATE import_jobs SET state='complete', phase='terminal', "
                    "job_revision=job_revision+1, owner_generation=NULL, lease_owner_id=NULL, "
                    "lease_generation=NULL, lease_expires_at=NULL, "
                    "terminal_result_canonical=report_result_canonical, "
                    "terminal_result_digest=report_result_digest, terminal_at=?, updated_at=? "
                    "WHERE source_identity_digest=?",
                    (now_wire, now_wire, allocation.source_identity.identity_digest),
                )
                updated = cast(
                    tuple[object, ...],
                    self._job_row(db, allocation.source_identity.identity_digest),
                )
                db.execute("COMMIT")
                return updated
            except BaseException:
                self._rollback(db)
                raise

        row = await self._submit(transaction)
        return await self._allocation(row, allocation, ImportAllocationOutcome.REPLAYED)

    async def quarantine(self, allocation: ImportAllocation, reason: ImportSafeReason) -> None:
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)
        terminal = JsonObject({"quarantine_code": reason.code, "state": "quarantined"})
        terminal_bytes = canonical_encode(terminal)

        def transaction(db: apsw.Connection) -> None:
            self._begin(db)
            try:
                self._require_lease_row(
                    db,
                    allocation,
                    {
                        ImportPhase.SOURCE_RESERVED,
                        ImportPhase.PLAN_READY,
                        ImportPhase.PUBLISHING,
                        ImportPhase.REPORT_READY,
                        ImportPhase.REPORT_PUBLISHED,
                    },
                    now,
                )
                db.execute(
                    "UPDATE import_jobs SET state='quarantined', phase='terminal', "
                    "job_revision=job_revision+1, owner_generation=NULL, lease_owner_id=NULL, "
                    "lease_generation=NULL, lease_expires_at=NULL, terminal_result_canonical=?, "
                    "terminal_result_digest=?, quarantine_code=?, terminal_at=?, updated_at=? "
                    "WHERE source_identity_digest=?",
                    (
                        terminal_bytes,
                        canonical_digest(terminal),
                        reason.code,
                        now_wire,
                        now_wire,
                        allocation.source_identity.identity_digest,
                    ),
                )
                db.execute("COMMIT")
            except BaseException:
                self._rollback(db)
                raise

        await self._submit(transaction)

    async def status(self, session_id: str) -> ImportStatusSnapshot:
        db = self._read_factory()
        try:
            counts = db.execute(
                "SELECT sum(state='pending'), count(*) FROM import_jobs WHERE session_id=?",
                (session_id,),
            ).fetchone()
            active_count = 0 if counts is None or counts[0] is None else cast(int, counts[0])
            total_count = 0 if counts is None else cast(int, counts[1])
            active_rows = tuple(
                JsonObject(
                    {
                        "identity_digest": row[0],
                        "phase": row[1],
                        "completed_batch_count": row[2],
                        "batch_count": row[3],
                    }
                )
                for row in db.execute(
                    "SELECT source_identity_digest, phase, completed_batch_count, batch_count "
                    "FROM import_jobs WHERE session_id=? AND state='pending' "
                    "ORDER BY source_identity_digest LIMIT ?",
                    (session_id, self._policy.status_jobs),
                )
            )
            terminal_rows = tuple(
                JsonObject(
                    {
                        "identity_digest": row[0],
                        "report_evidence_id": row[1],
                    }
                )
                for row in db.execute(
                    "SELECT source_identity_digest, report_evidence_id "
                    "FROM import_jobs WHERE session_id=? AND state!='pending' "
                    "AND report_append_result_canonical IS NOT NULL "
                    "ORDER BY source_identity_digest LIMIT ?",
                    (session_id, self._policy.status_jobs),
                )
            )
            return ImportStatusSnapshot(
                validate_session_id(session_id),
                active_count,
                total_count - active_count,
                active_rows,
                terminal_rows,
            )
        finally:
            db.close()

    async def load_review_source(
        self, identity_digest: str, through: Frontier
    ) -> ImportReviewSource | None:
        validate_sha256_digest(identity_digest)
        db = self._read_factory()
        try:
            row = self._job_row(db, identity_digest)
            if row is None:
                return None
            batches = tuple(
                tuple(value)
                for value in db.execute(
                    "SELECT plan_object_id, event_ids_canonical, append_result_canonical "
                    "FROM import_batches WHERE source_identity_digest=? ORDER BY batch_index",
                    (identity_digest,),
                )
            )
        finally:
            db.close()
        identity = self._identity_from_row(row)
        if identity.identity_digest != identity_digest:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "Import review identity is contradictory.",
                retryable=False,
            )
        state = ImportState(cast(str, row[21]))
        phase = ImportPhase(cast(str, row[22]))
        if state is ImportState.QUARANTINED:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "Import review source is quarantined.",
                retryable=False,
            )
        source_ref = self._object_ref(cast(str, row[7]), ObjectKind.IMPORT_SOURCE)
        manifest_ref = self._object_ref(cast(str, row[8]), ObjectKind.IMPORT_SOURCE_MANIFEST)
        await read_exact_object(self._objects, source_ref)
        await read_exact_object(self._objects, manifest_ref)
        report_object = (
            None
            if row[34] is None
            else self._object_ref(cast(str, row[34]), ObjectKind.IMPORT_REPORT)
        )
        if report_object is not None:
            await read_exact_object(self._objects, report_object)
        completed: list[AppendResult] = []
        mapped: list[EventId] = []
        outcomes_by_ordinal: dict[int, ImportLineOutcome] = {}
        gaps_by_range: dict[tuple[int, int, int, str], ImportGap] = {}
        coverage = coverage_for_channel(PublicationChannel.CODEX_JSONL_IMPORT)
        plan_refs: list[ObjectRef] = []
        for plan_object_id, event_ids_bytes, append_bytes in batches:
            plan_ref = self._object_ref(cast(str, plan_object_id), ObjectKind.IMPORT_PLAN)
            plan_refs.append(plan_ref)
            material = await self._plan_reader(plan_ref)
            event_ids = tuple(
                event_id(value)
                for value in cast(
                    tuple[object, ...], strict_json_parse(cast(bytes, event_ids_bytes))
                )
            )
            if tuple(draft.event_id for draft in material.event_drafts) != event_ids:
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
            if append_bytes is not None:
                result = append_result_from_bytes(cast(bytes, append_bytes))
                if tuple(item.event_id for item in result.accepted) != event_ids:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Import review batch result is contradictory.",
                        retryable=False,
                    )
                completed.append(result)
                mapped.extend(event_ids)
        report_result = None if row[40] is None else append_result_from_bytes(cast(bytes, row[40]))
        selected_frontiers = tuple(result.result_frontier for result in completed) + (
            () if report_result is None else (report_result.result_frontier,)
        )
        if any(not _frontier_at_or_before(value, through) for value in selected_frontiers):
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Review frontier cuts an import batch.",
                retryable=False,
            )
        if state is ImportState.COMPLETE and (
            report_object is None or report_result is None or row[35] is None
        ):
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "Complete import review is missing report evidence.",
                retryable=False,
            )
        verify_db = self._read_factory()
        try:
            current = verify_db.execute(
                "SELECT job_revision FROM import_jobs WHERE source_identity_digest=?",
                (identity.identity_digest,),
            ).fetchone()
        finally:
            verify_db.close()
        if current != (row[23],):
            raise _error(
                PublicErrorCode.OPERATION_PENDING,
                "Import review changed while loading.",
                retryable=True,
            )
        return ImportReviewSource(
            identity=identity,
            through=through,
            state=state,
            phase=phase,
            publishing_writer_id=writer_id(row[6]),
            source_object=source_ref,
            source_commitment=cast(str, row[3]),
            plan_object_refs=tuple(plan_refs),
            plan_digest=cast(str | None, row[28]),
            report_object=report_object,
            report_digest=cast(str | None, row[35]),
            completed_batch_results=tuple(completed),
            mapped_event_ids=tuple(mapped),
            line_outcomes=tuple(
                outcomes_by_ordinal[index] for index in sorted(outcomes_by_ordinal)
            ),
            gaps=tuple(gaps_by_range[index] for index in sorted(gaps_by_range)),
            coverage=coverage,
            codex_capability_profile_id=identity.codex_capability_profile_id,
            mapping_version=identity.mapping_version,
            import_incomplete=state is ImportState.PENDING,
        )

    def _begin(self, db: apsw.Connection) -> None:
        db.execute("BEGIN IMMEDIATE")

    def _rollback(self, db: apsw.Connection) -> None:
        try:
            db.execute("ROLLBACK")
        except apsw.SQLError:
            pass

    def _verify_meta(self, db: apsw.Connection) -> None:
        rows = dict(
            db.execute(
                "SELECT key, value FROM bundle_meta WHERE key IN "
                "('task_id','owner_generation','owner_nonce','import_schema_version')"
            )
        )
        if rows.get("import_schema_version") != str(IMPORT_SCHEMA_VERSION):
            raise _error(
                PublicErrorCode.MIGRATION_REQUIRED,
                "Importer schema is not current.",
                retryable=False,
            )
        if (
            rows.get("task_id") not in {None, self._task_id}
            or rows.get("owner_generation") != str(self._fence.owner_generation)
            or rows.get("owner_nonce") != self._fence.nonce
        ):
            raise _error(
                PublicErrorCode.BUNDLE_BUSY,
                "Bundle ownership changed.",
                retryable=True,
            )

    def _job_row(self, db: apsw.Connection, identity_digest: str) -> tuple[object, ...] | None:
        row = db.execute(
            "SELECT * FROM import_jobs WHERE source_identity_digest=?", (identity_digest,)
        ).fetchone()
        return None if row is None else tuple(row)

    def _insert_object(self, db: apsw.Connection, ref: ObjectRef) -> None:
        db.execute(
            "INSERT OR IGNORE INTO objects VALUES (?,?,?,?,?,?,?, 'present', ?)",
            (
                ref.object_id,
                ref.metadata.kind.value,
                ref.plaintext_size,
                ref.commitment,
                ref.envelope_digest,
                ref.encryption_format,
                ref.key_slot,
                format_rfc3339_millis(ref.metadata.created_at),
            ),
        )
        row = db.execute(
            "SELECT kind, plaintext_size, commitment, envelope_digest, encryption_format, key_slot "
            "FROM objects WHERE object_id=?",
            (ref.object_id,),
        ).fetchone()
        if row != (
            ref.metadata.kind.value,
            ref.plaintext_size,
            ref.commitment,
            ref.envelope_digest,
            ref.encryption_format,
            ref.key_slot,
        ):
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "Importer object inventory is contradictory.",
                retryable=False,
            )

    def _require_lease_row(
        self,
        db: apsw.Connection,
        allocation: ImportAllocation,
        phases: set[ImportPhase],
        now: datetime,
    ) -> tuple[object, ...]:
        self._verify_meta(db)
        row = self._job_row(db, allocation.source_identity.identity_digest)
        if (
            row is None
            or row[21] != ImportState.PENDING.value
            or row[22] not in {phase.value for phase in phases}
            or row[24] != str(self._fence.owner_generation)
            or row[25] != self._fence.service_instance_id
            or row[26] != allocation.lease_generation
            or row[27] is None
            or parse_rfc3339_millis(row[27]) <= now
            or row[6] != allocation.publishing_writer_id
        ):
            raise _error(
                PublicErrorCode.OPERATION_PENDING,
                "Import lease is no longer current.",
                retryable=True,
            )
        return row

    def _identity_from_row(self, row: tuple[object, ...]) -> ImportSourceIdentity:
        return ImportSourceIdentity(
            task_id=task_id(row[1]),
            source_commitment=cast(str, row[3]),
            codex_capability_profile_id=cast(str, row[4]),
            mapping_version=cast(str, row[5]),
            identity_digest=cast(str, row[0]),
        )

    def _object_ref(self, object_id: str, kind: ObjectKind) -> ObjectRef:
        cached = self._refs.get(object_id)
        if cached is not None:
            return cached
        db = self._read_factory()
        try:
            row = db.execute(
                "SELECT plaintext_size, commitment, envelope_digest, encryption_format, key_slot, "
                "durable_at FROM objects WHERE object_id=? AND kind=?",
                (object_id, kind.value),
            ).fetchone()
        finally:
            db.close()
        if row is None:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "Importer object inventory is missing.",
                retryable=False,
            )
        media = {
            ObjectKind.IMPORT_SOURCE: "application/x-ndjson",
            ObjectKind.IMPORT_SOURCE_MANIFEST: "application/vnd.yoetz.import_source_manifest+json",
            ObjectKind.IMPORT_PLAN: "application/vnd.yoetz.import_plan+json",
            ObjectKind.IMPORT_REPORT: "application/vnd.yoetz.import_report+json",
        }[kind]
        result = ObjectRef(
            object_id=object_id,
            plaintext_size=cast(int, row[0]),
            commitment=cast(str, row[1]),
            envelope_digest=cast(str, row[2]),
            encryption_format=cast(Literal["yoetz-object/1"], row[3]),
            key_slot=cast(str, row[4]),
            metadata=ObjectMetadata(
                kind=kind,
                media_type=media,
                task_id=self._task_id,
                created_at=parse_rfc3339_millis(row[5]),
            ),
        )
        self._refs[object_id] = result
        return result

    async def _allocation(
        self,
        row: tuple[object, ...],
        command: ImportCommand | ImportAllocation,
        outcome: ImportAllocationOutcome,
    ) -> ImportAllocation:
        identity = self._identity_from_row(row)
        source_ref = self._object_ref(cast(str, row[7]), ObjectKind.IMPORT_SOURCE)
        manifest_ref = self._object_ref(cast(str, row[8]), ObjectKind.IMPORT_SOURCE_MANIFEST)
        captured_source = CapturedImportSource(
            source_object=source_ref,
            source_commitment=cast(str, row[3]),
            byte_count=cast(int, row[10]),
            line_count=cast(int, row[11]),
            final_newline=bool(row[12]),
            metadata_digest=cast(str, row[20]),
            codex_capability_profile_id=cast(str, row[4]),
            codex_version=cast(str, row[13]),
            exit_status=cast(int, row[15]),
            source_kind=cast(Literal["file", "stdin"], row[14]),
            capture_metadata_object=manifest_ref,
            stderr_present=False,
            stderr_captured_bytes=0,
            stderr_truncated=False,
            stderr_commitment=None,
        )
        db = self._read_factory()
        try:
            batches = tuple(
                db.execute(
                    "SELECT plan_object_id FROM import_batches WHERE source_identity_digest=? "
                    "ORDER BY batch_index",
                    (identity.identity_digest,),
                )
            )
        finally:
            db.close()
        plan_refs = tuple(
            self._object_ref(cast(str, item[0]), ObjectKind.IMPORT_PLAN) for item in batches
        )
        report_ref = None
        terminal_result = None
        terminal_bytes = cast(bytes | None, row[44])
        terminal_digest = cast(str | None, row[45])
        if row[34] is not None:
            report_object = self._object_ref(cast(str, row[34]), ObjectKind.IMPORT_REPORT)
            report_ref = EncryptedImportReportRef(
                report_object,
                cast(str, row[35]),
                cast(bytes, row[36]),
                cast(str, row[37]),
            )
        if terminal_bytes is not None:
            terminal_result = JsonObject(
                cast(Mapping[object, object], strict_json_parse(terminal_bytes))
            )
        elif report_ref is not None:
            terminal_bytes = report_ref.terminal_result_bytes
            terminal_digest = report_ref.terminal_result_digest
            terminal_result = JsonObject(
                cast(Mapping[object, object], strict_json_parse(terminal_bytes))
            )
        evidence_draft = (
            None
            if row[38] is None
            else event_draft_from_json(strict_json_parse(cast(bytes, row[38])))
        )
        replayed = (
            report_ref
            if outcome is ImportAllocationOutcome.REPLAYED and row[21] == ImportState.COMPLETE.value
            else None
        )
        return ImportAllocation(
            outcome=outcome,
            source_identity=identity,
            session_id=validate_session_id(row[2]),
            requesting_writer_id=command.requesting_writer_id,
            request_id=command.request_id,
            publishing_writer_id=writer_id(row[6]),
            state=ImportState(cast(str, row[21])),
            phase=ImportPhase(cast(str, row[22])),
            owner_generation=(
                self._fence.owner_generation if row[24] is None else int(cast(str, row[24]), 10)
            ),
            lease_owner_id=cast(str | None, row[25]),
            lease_generation=cast(int | None, row[26]),
            lease_expires_at=(
                None if row[27] is None else timestamp_from_datetime(parse_rfc3339_millis(row[27]))
            ),
            captured_source=captured_source,
            source_object=source_ref,
            source_commitment=cast(str, row[3]),
            plan_digest=cast(str | None, row[28]),
            plan_object_refs=plan_refs,
            batch_count=cast(int, row[29]),
            completed_batch_count=cast(int, row[30]),
            report_object=None if report_ref is None else report_ref.report_object,
            report_digest=None if report_ref is None else report_ref.report_digest,
            terminal_result=terminal_result,
            terminal_result_bytes=terminal_bytes,
            terminal_result_digest=terminal_digest,
            report_request_id=None if row[31] is None else request_id(row[31]),
            report_event_id=None if row[32] is None else event_id(row[32]),
            report_evidence_id=None if row[33] is None else evidence_id(row[33]),
            report_evidence_draft=evidence_draft,
            report_evidence_draft_bytes=cast(bytes | None, row[38]),
            report_evidence_draft_digest=cast(str | None, row[39]),
            replayed_report=replayed,
        )
