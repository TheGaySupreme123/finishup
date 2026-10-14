"""Fault-free memory/SQLite importer persistence parity."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from concurrent.futures import Future
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import apsw
import pytest

from finishup.adapters.memory.importer import (
    ImportPlanMaterial,
    MemoryImporter,
    MemoryImportState,
)
from finishup.adapters.sqlite.connection import SqliteWriterThread
from finishup.adapters.sqlite.importer import SqliteImporter
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.domain.events import EventDraft, EventSchema
from finishup.domain.values import (
    Frontier,
    JsonObject,
    event_id,
    evidence_id,
    format_rfc3339_millis,
    request_id,
    session_id,
    task_id,
    timestamp_from_datetime,
    writer_id,
)
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.importer import (
    CapturedImportSource,
    EncryptedImportReportRef,
    ImportAllocation,
    ImportAllocationOutcome,
    ImportBatch,
    ImportCommand,
    ImportEventCandidate,
    ImportGap,
    ImportLineOutcome,
    ImportLineStatus,
    ImportSafeReason,
    ImportSourceIdentity,
    PreparedImportPlan,
)
from finishup.ports.ledger import AcceptedEventSummary, AppendResult, LedgerPort
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectStorePort
from finishup.ports.runtime import OwnershipFence
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind

_TASK = "tsk_00000000-0000-4000-8000-000000000001"
_SESSION = "ses_00000000-0000-4000-8000-000000000002"
_WRITER = "wri_00000000-0000-4000-8000-000000000003"
_OTHER_WRITER = "wri_00000000-0000-4000-8000-000000000009"
_SERVICE = "svc_00000000-0000-4000-8000-000000000004"
_DIGEST = "sha256:" + "0" * 64
_NOW = datetime(2026, 7, 19, tzinfo=UTC)
_NONCE = "importer-owner-nonce-0001"


class _Clock:
    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return 0.0


class _Ids:
    def new(self, kind: IdKind) -> str:
        raise AssertionError(f"unexpected identifier request: {kind.value}")


class _ImmediateWriter:
    def __init__(self, db: apsw.Connection) -> None:
        self._db = db

    def submit[T](self, function: Callable[[apsw.Connection], T]) -> Future[T]:
        future: Future[T] = Future()
        try:
            future.set_result(function(self._db))
        except BaseException as exc:
            future.set_exception(exc)
        return future


def _uuid_id(prefix: str, number: int) -> str:
    return f"{prefix}_00000000-0000-4000-8000-{number:012x}"


def _object(
    kind: ObjectKind, number: int, commitment: str, *, plaintext_size: int = 1
) -> ObjectRef:
    return ObjectRef(
        object_id=_uuid_id("obj", number),
        plaintext_size=plaintext_size,
        commitment=commitment,
        envelope_digest=_DIGEST,
        encryption_format="yoetz-object/1",
        key_slot="slot-1",
        metadata=ObjectMetadata(
            kind=kind,
            media_type="application/octet-stream",
            task_id=_TASK,
            created_at=_NOW,
        ),
    )


def _source(number: int) -> tuple[CapturedImportSource, ImportSourceIdentity]:
    commitment = "hmac-sha256:" + f"{number:064x}"
    source = CapturedImportSource(
        source_object=_object(
            ObjectKind.IMPORT_SOURCE, number * 10 + 1, commitment, plaintext_size=2
        ),
        source_commitment=commitment,
        byte_count=2,
        line_count=2,
        final_newline=False,
        metadata_digest=_DIGEST,
        codex_capability_profile_id="codex-0.144.5",
        codex_version="0.144.5",
        exit_status=0,
        source_kind="stdin",
        capture_metadata_object=_object(
            ObjectKind.IMPORT_SOURCE_MANIFEST, number * 10 + 2, commitment
        ),
        stderr_present=False,
        stderr_captured_bytes=0,
        stderr_truncated=False,
        stderr_commitment=None,
    )
    identity = ImportSourceIdentity(
        task_id=task_id(_TASK),
        source_commitment=commitment,
        codex_capability_profile_id="codex-0.144.5",
        mapping_version="mapping-1",
        identity_digest=canonical_digest(
            {
                "codex_capability_profile_id": "codex-0.144.5",
                "mapping_version": "mapping-1",
                "source_commitment": commitment,
                "task_id": _TASK,
            }
        ),
    )
    return source, identity


def _command(identity: ImportSourceIdentity, number: int, writer: str = _WRITER) -> ImportCommand:
    return ImportCommand(
        session_id=session_id(_SESSION),
        requesting_writer_id=writer_id(writer),
        request_id=request_id(_uuid_id("req", number)),
        request_digest=_DIGEST,
        source_identity=identity,
        mapping_version="mapping-1",
    )


def _coverage(*, known_gaps: tuple[str, ...] = ()) -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.CODEX_JSONL_IMPORT,),
        authorship_assurance=AuthorshipAssurance.HARNESS_OBSERVED,
        artifact_observation=ArtifactObservation.IMPORT_OBSERVED,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.PARTIAL,
        check_types=(CheckType.NONE,),
        known_gaps=known_gaps,
    )


def _plan(identity: ImportSourceIdentity, number: int) -> tuple[PreparedImportPlan, EventDraft]:
    commitment = "hmac-sha256:" + f"{number + 100:064x}"
    plan_object = _object(ObjectKind.IMPORT_PLAN, number * 10 + 3, commitment)
    event = EventDraft(
        event_id=event_id(_uuid_id("evt", number * 10 + 4)),
        schema=EventSchema("future_event", "1.0.0"),
        occurred_at=timestamp_from_datetime(_NOW),
        causal_parents=(),
        payload=JsonObject({"observed": True}),
        artifact_refs=(),
        evidence_refs=(),
    )
    candidate = ImportEventCandidate(
        candidate_index=0,
        event_id=event.event_id,
        payload_logical_ids=(),
        source_line_ordinal=1,
        byte_start=0,
        byte_end=1,
        target_schema=event.schema,
        source_category="item.completed",
        intended_refs=(),
        coverage=_coverage(),
        plan_object=plan_object,
    )
    gap_coverage = _coverage(known_gaps=("unsupported_codex_item",))
    gap = ImportGap(
        code="unsupported_codex_item",
        source_object_id=_uuid_id("obj", number * 10 + 1),
        line_ordinal=2,
        byte_start=1,
        byte_end=2,
        coverage=gap_coverage,
    )
    return (
        PreparedImportPlan(
            source_identity=identity,
            mapping_version="mapping-1",
            line_outcomes=(
                ImportLineOutcome(1, 0, 1, ImportLineStatus.MAPPED, "item.completed", (0,), None),
                ImportLineOutcome(
                    2,
                    1,
                    2,
                    ImportLineStatus.UNSUPPORTED,
                    "unsupported.item",
                    (),
                    "unsupported_codex_item",
                ),
            ),
            candidates=(candidate,),
            gaps=(gap,),
            candidate_count=1,
            gap_count=1,
            batch_plan_objects=(plan_object,),
            batch_request_ids=(request_id(_uuid_id("req", number * 10 + 5)),),
            report_request_id=request_id(_uuid_id("req", number * 10 + 6)),
            report_event_id=event_id(_uuid_id("evt", number * 10 + 7)),
            report_evidence_id=evidence_id(_uuid_id("evd", number * 10 + 8)),
            plan_digest=_DIGEST,
        ),
        event,
    )


def _append(event: EventDraft) -> AppendResult:
    return AppendResult(
        outcome="accepted",
        accepted=(AcceptedEventSummary(event.event_id, 1, 1, _DIGEST, "projected"),),
        subject_frontier=Frontier.genesis(),
        result_frontier=Frontier(1, _DIGEST),
        warnings=(),
    )


def _report_append(report_event_id: str) -> AppendResult:
    return AppendResult(
        outcome="accepted",
        accepted=(AcceptedEventSummary(report_event_id, 2, 2, _DIGEST, "projected"),),
        subject_frontier=Frontier(1, _DIGEST),
        result_frontier=Frontier(2, _DIGEST),
        warnings=(),
    )


class _Objects:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def remember(self, ref: ObjectRef, value: bytes) -> None:
        assert len(value) == ref.plaintext_size
        self.values[ref.object_id] = value

    def open_verified(self, ref: ObjectRef) -> AsyncIterator[bytes]:
        async def chunks() -> AsyncIterator[bytes]:
            yield self.values[ref.object_id]

        return chunks()


class _Plans:
    def __init__(self) -> None:
        self.plans: dict[str, PreparedImportPlan] = {}
        self.material: dict[str, ImportPlanMaterial] = {}

    def remember(self, plan: PreparedImportPlan, event: EventDraft) -> None:
        self.plans[plan.source_identity.identity_digest] = plan
        for ref in plan.batch_plan_objects:
            self.material[ref.object_id] = ImportPlanMaterial(
                event_drafts=(event,),
                line_outcomes=plan.line_outcomes,
                gaps=plan.gaps,
                coverage=_coverage(known_gaps=("unsupported_codex_item",)),
            )

    async def prepare(self, allocation: ImportAllocation) -> PreparedImportPlan:
        return self.plans[allocation.source_identity.identity_digest]

    async def read(self, ref: ObjectRef) -> ImportPlanMaterial:
        return self.material[ref.object_id]


async def _unexpected_prepare_plan(_allocation: ImportAllocation) -> PreparedImportPlan:
    raise AssertionError("prepare_plan is not exercised by quarantine replay fixtures")


async def _unexpected_read_plan(_object: ObjectRef) -> ImportPlanMaterial:
    raise AssertionError("plan material is not read by quarantine replay fixtures")


async def _exercise(importer: MemoryImporter | SqliteImporter, phase: str, number: int) -> object:
    source, identity = _source(number)
    allocation = await importer.reserve_or_resume(_command(identity, number * 100 + 1), source)
    if phase != "source_reserved":
        plan, event = _plan(identity, number)
        allocation = await importer.publish_plan(allocation, plan)
        if phase == "mid_batch":
            batch = ImportBatch(
                batch_index=0,
                batch_count=1,
                request_id=plan.batch_request_ids[0],
                event_ids=(event.event_id,),
                event_drafts=(event,),
                plan_object=plan.batch_plan_objects[0],
                plan_digest=plan.plan_digest,
                gaps=(),
            )
            allocation = await importer.record_batch(allocation, batch, _append(event))
    await importer.quarantine(allocation, ImportSafeReason("import_phase_state_contradiction"))
    return await importer.reserve_or_resume(_command(identity, number * 100 + 2), source)


@pytest.mark.anyio
@pytest.mark.parametrize("phase", ["source_reserved", "plan_ready", "mid_batch"])
async def test_fault_free_quarantine_replay_is_byte_equivalent(tmp_path: Path, phase: str) -> None:
    fence = OwnershipFence(_SERVICE, 1, 1, _NONCE)
    clock = cast(ClockPort, _Clock())
    ids = cast(IdPort, _Ids())
    objects = cast(ObjectStorePort, None)
    ledger = cast(LedgerPort, None)
    memory_state = MemoryImportState()
    memory = MemoryImporter(
        task_id=_TASK,
        admitted_session_id=_SESSION,
        ownership_fence=fence,
        state=memory_state,
        transaction_lock=asyncio.Lock(),
        objects=objects,
        ledger=ledger,
        clock=clock,
        ids=ids,
        plan_preparer=_unexpected_prepare_plan,
        plan_reader=_unexpected_read_plan,
    )

    database_path = tmp_path / f"{phase}.sqlite3"
    writer_db = apsw.Connection(str(database_path))
    initialize_bundle(
        writer_db,
        {
            "task_id": _TASK,
            "owner_generation": "1",
            "owner_nonce": _NONCE,
        },
    )
    writer_db.execute(
        "INSERT INTO writers VALUES (?,?,?,?,?,?,?)",
        (_WRITER, _TASK, _SESSION, 1, "genesis", "active", format_rfc3339_millis(_NOW)),
    )

    def read_factory() -> apsw.Connection:
        return apsw.Connection(str(database_path))

    sqlite = SqliteImporter(
        task_id=_TASK,
        admitted_session_id=_SESSION,
        ownership_fence=fence,
        writer=cast(SqliteWriterThread, _ImmediateWriter(writer_db)),
        read_factory=read_factory,
        objects=objects,
        ledger=ledger,
        clock=clock,
        ids=ids,
        plan_preparer=_unexpected_prepare_plan,
        plan_reader=_unexpected_read_plan,
    )
    memory_replay = await _exercise(memory, phase, 10)
    sqlite_replay = await _exercise(sqlite, phase, 10)
    assert memory_replay == sqlite_replay
    assert memory_state.publication_by_request == memory_state.publication_by_request.copy()
    if phase == "source_reserved":
        expected_reservations = 0
    else:
        expected_reservations = 2
    assert writer_db.execute("SELECT count(*) FROM import_publication_requests").fetchone() == (
        expected_reservations,
    )
    assert len(memory_state.publication_by_request) == expected_reservations
    writer_db.close()


@pytest.mark.anyio
async def test_prepare_and_review_sources_are_memory_sqlite_equivalent(tmp_path: Path) -> None:
    fence = OwnershipFence(_SERVICE, 1, 1, _NONCE)
    clock = cast(ClockPort, _Clock())
    ids = cast(IdPort, _Ids())
    object_values = _Objects()
    objects = cast(ObjectStorePort, object_values)
    plans = _Plans()
    ledger = cast(LedgerPort, None)
    memory = MemoryImporter(
        task_id=_TASK,
        admitted_session_id=_SESSION,
        ownership_fence=fence,
        state=MemoryImportState(),
        transaction_lock=asyncio.Lock(),
        objects=objects,
        ledger=ledger,
        clock=clock,
        ids=ids,
        plan_preparer=plans.prepare,
        plan_reader=plans.read,
    )

    database_path = tmp_path / "review.sqlite3"
    writer_db = apsw.Connection(str(database_path))
    initialize_bundle(
        writer_db,
        {
            "task_id": _TASK,
            "owner_generation": "1",
            "owner_nonce": _NONCE,
        },
    )
    writer_db.execute(
        "INSERT INTO writers VALUES (?,?,?,?,?,?,?)",
        (_WRITER, _TASK, _SESSION, 1, "genesis", "active", format_rfc3339_millis(_NOW)),
    )

    def read_factory() -> apsw.Connection:
        return apsw.Connection(str(database_path))

    sqlite = SqliteImporter(
        task_id=_TASK,
        admitted_session_id=_SESSION,
        ownership_fence=fence,
        writer=cast(SqliteWriterThread, _ImmediateWriter(writer_db)),
        read_factory=read_factory,
        objects=objects,
        ledger=ledger,
        clock=clock,
        ids=ids,
        plan_preparer=plans.prepare,
        plan_reader=plans.read,
    )

    source, identity = _source(40)
    object_values.remember(source.source_object, b"xy")
    object_values.remember(source.capture_metadata_object, b"m")
    plan, event = _plan(identity, 40)
    object_values.remember(plan.batch_plan_objects[0], b"p")
    plans.remember(plan, event)

    async def run_complete(
        importer: MemoryImporter | SqliteImporter,
    ) -> tuple[object, object, object]:
        allocation = await importer.reserve_or_resume(_command(identity, 4_001), source)
        prepared = await importer.prepare_plan(allocation)
        assert prepared == plan
        allocation = await importer.publish_plan(allocation, prepared)
        await importer.release_lease_for_authorization(allocation)
        allocation = await importer.reserve_or_resume(_command(identity, 4_002), source)
        assert allocation.outcome is ImportAllocationOutcome.RESUMED
        assert allocation.plan_digest == plan.plan_digest
        pending_review = await importer.load_review_source(
            identity.identity_digest, Frontier.genesis()
        )
        assert pending_review is not None
        assert pending_review.mapped_event_ids == ()
        assert pending_review.gaps == plan.gaps
        assert pending_review.line_outcomes == plan.line_outcomes
        assert "unsupported_codex_item" in pending_review.coverage.known_gaps

        selection = await importer.next_batch(allocation)
        assert selection.batch is not None
        allocation = await importer.record_batch(
            selection.allocation, selection.batch, _append(event)
        )
        publishing_review = await importer.load_review_source(
            identity.identity_digest, Frontier(1, _DIGEST)
        )
        assert publishing_review is not None
        assert publishing_review.mapped_event_ids == (event.event_id,)
        with pytest.raises(PublicOperationError) as cut:
            await importer.load_review_source(identity.identity_digest, Frontier.genesis())
        assert cut.value.code is PublicErrorCode.INVALID_REQUEST

        report_object = _object(
            ObjectKind.IMPORT_REPORT,
            409,
            "hmac-sha256:" + "9" * 64,
        )
        object_values.remember(report_object, b"r")
        terminal = JsonObject({"imported_count": 1})
        report = EncryptedImportReportRef(
            report_object=report_object,
            report_digest=_DIGEST,
            terminal_result_bytes=canonical_encode(terminal),
            terminal_result_digest=canonical_digest(terminal),
        )
        allocation = await importer.prepare_report(allocation, report)
        assert allocation.report_event_id is not None
        allocation = await importer.publish_report(
            allocation, report, _report_append(allocation.report_event_id)
        )
        completed = await importer.complete(allocation)
        assert completed.replayed_report == report
        complete_review = await importer.load_review_source(
            identity.identity_digest, Frontier(2, _DIGEST)
        )
        assert complete_review is not None
        assert not complete_review.import_incomplete
        assert complete_review.report_object == report_object
        return pending_review, publishing_review, complete_review

    memory_reviews = await run_complete(memory)
    sqlite_reviews = await run_complete(sqlite)
    assert memory_reviews == sqlite_reviews

    quarantined_source, quarantined_identity = _source(41)
    object_values.remember(quarantined_source.source_object, b"xy")
    object_values.remember(quarantined_source.capture_metadata_object, b"m")
    for importer in (memory, sqlite):
        allocation = await importer.reserve_or_resume(
            _command(quarantined_identity, 4_101), quarantined_source
        )
        await importer.quarantine(allocation, ImportSafeReason("import_phase_state_contradiction"))
        with pytest.raises(PublicOperationError) as quarantined:
            await importer.load_review_source(
                quarantined_identity.identity_digest, Frontier.genesis()
            )
        assert quarantined.value.code is PublicErrorCode.STORAGE_CORRUPT

    writer_db.close()


@pytest.mark.anyio
async def test_reserve_or_resume_refuses_a_foreign_writer(tmp_path: Path) -> None:
    """A writer that did not publish an import never reaches its job.

    Both adapters keyed replay on the source identity alone, so a second writer submitting
    the same source bytes was handed the publishing writer's terminal report, original
    request id, and report object locator. The writer boundary now decides before the
    terminal branch, in both adapters, for pending and terminal jobs alike.
    """

    fence = OwnershipFence(_SERVICE, 1, 1, _NONCE)
    clock = cast(ClockPort, _Clock())
    ids = cast(IdPort, _Ids())
    objects = cast(ObjectStorePort, None)
    ledger = cast(LedgerPort, None)
    memory_state = MemoryImportState()
    memory = MemoryImporter(
        task_id=_TASK,
        admitted_session_id=_SESSION,
        ownership_fence=fence,
        state=memory_state,
        transaction_lock=asyncio.Lock(),
        objects=objects,
        ledger=ledger,
        clock=clock,
        ids=ids,
        plan_preparer=_unexpected_prepare_plan,
        plan_reader=_unexpected_read_plan,
    )

    database_path = tmp_path / "foreign-writer.sqlite3"
    writer_db = apsw.Connection(str(database_path))
    initialize_bundle(
        writer_db,
        {
            "task_id": _TASK,
            "owner_generation": "1",
            "owner_nonce": _NONCE,
        },
    )
    for writer in (_WRITER, _OTHER_WRITER):
        # The foreign writer is a real, admitted writer: the refusal has to come from the
        # import writer boundary, not from an absent row or a foreign-key failure.
        writer_db.execute(
            "INSERT INTO writers VALUES (?,?,?,?,?,?,?)",
            (writer, _TASK, _SESSION, 1, "genesis", "active", format_rfc3339_millis(_NOW)),
        )

    def read_factory() -> apsw.Connection:
        return apsw.Connection(str(database_path))

    sqlite = SqliteImporter(
        task_id=_TASK,
        admitted_session_id=_SESSION,
        ownership_fence=fence,
        writer=cast(SqliteWriterThread, _ImmediateWriter(writer_db)),
        read_factory=read_factory,
        objects=objects,
        ledger=ledger,
        clock=clock,
        ids=ids,
        plan_preparer=_unexpected_prepare_plan,
        plan_reader=_unexpected_read_plan,
    )

    def aliases_for(writer: str) -> int:
        rows = writer_db.execute(
            "SELECT count(*) FROM import_request_aliases WHERE requesting_writer_id=?", (writer,)
        ).fetchone()
        return cast(int, cast(tuple[object, ...], rows)[0])

    for number, importer in ((50, memory), (51, sqlite)):
        source, identity = _source(number)
        owned = await importer.reserve_or_resume(_command(identity, number * 100 + 1), source)

        # Pending: a foreign writer could never resume this job, so it is refused outright.
        with pytest.raises(PublicOperationError) as pending:
            await importer.reserve_or_resume(
                _command(identity, number * 100 + 2, _OTHER_WRITER), source
            )
        assert pending.value.code is PublicErrorCode.INVALID_REQUEST
        assert pending.value.retryable is False

        await importer.quarantine(owned, ImportSafeReason("import_phase_state_contradiction"))

        # Terminal: the branch that used to hand back the publishing writer's report.
        with pytest.raises(PublicOperationError) as terminal:
            await importer.reserve_or_resume(
                _command(identity, number * 100 + 3, _OTHER_WRITER), source
            )
        assert terminal.value.code is PublicErrorCode.INVALID_REQUEST
        assert terminal.value.retryable is False

        # The publishing writer still replays its own terminal job.
        replayed = await importer.reserve_or_resume(_command(identity, number * 100 + 4), source)
        assert replayed.outcome is ImportAllocationOutcome.REPLAYED

    # A refused writer leaves no trace: its request ids stay unbound and free to reuse.
    assert not [key for key in memory_state.aliases if key[0] == _OTHER_WRITER]
    assert aliases_for(_OTHER_WRITER) == 0
    assert aliases_for(_WRITER) > 0
    writer_db.close()
