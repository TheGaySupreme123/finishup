"""SQLite implementation of the authoritative task-ledger boundary."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal, cast

import apsw

from yoetz.adapters.memory.ledger import (
    MemoryLedgerAdapter,
    MemoryLedgerState,
    _AttemptState,  # pyright: ignore[reportPrivateUsage]
    _case_dependency_digest,  # pyright: ignore[reportPrivateUsage]
    build_append_operation_record,
    check_admission_record,
    compact_status_coverage,
    load_frozen_case_from_resume,
    note_check_admission_refusal,
    quarantine_resume_object_invalid,
)
from yoetz.adapters.sqlite.observation import SqliteObservationStore
from yoetz.domain.events import (
    AcceptedEvent,
    CheckChangeShownFiles,
    CheckRecordedPayload,
    EventSchema,
    EvidenceDigestProvenance,
    FindingRecordedPayload,
    LedgerChain,
    LedgerRecord,
    MissingForAssessmentItem,
    PayloadRef,
    ProjectionLocator,
    RedactionState,
    UnknownEvent,
    WriterChain,
    accepted_record_to_json,
    decode_payload,
)
from yoetz.domain.findings import (
    PriorFindingVerdictRecord,
    RankedFindings,
    RuntimeTokenUsage,
    SemanticProvenance,
    rank_key,
)
from yoetz.domain.values import (
    Actor,
    ActorType,
    EventId,
    Frontier,
    JsonObject,
    ObjectId,
    actor_id,
    format_rfc3339_millis,
    frontier_from_json,
    object_id,
    parse_rfc3339_millis,
    timestamp_from_datetime,
    writer_id,
)
from yoetz.domain.values import (
    JsonValue as DomainJsonValue,
)
from yoetz.kernel.deterministic_checks import CaseAvailabilityFacts
from yoetz.kernel.projections import (
    PROJECTION_VERSION,
    ProjectionState,
    projection_digest,
    unanswered_finding_count,
)
from yoetz.kernel.reducers import replay
from yoetz.ports.change_capture import TASK_CHANGE_BASE_MEDIA_TYPE
from yoetz.ports.clock import ClockPort
from yoetz.ports.ids import IdPort
from yoetz.ports.ledger import (
    CHECK_ACQUISITION_RESERVATION_SECONDS,
    AcceptedEventSummary,
    AppendCommand,
    AppendResult,
    AppendWarning,
    AttemptOutcome,
    CheckAdmissionRecord,
    CheckAdmissionStage,
    CheckCommitResult,
    CheckPhase,
    CheckPolicyExecution,
    CheckSuspensionKind,
    CheckVersionSlice,
    FrozenCase,
    OperationKind,
    OperationLease,
    OperationQuarantineCode,
    OperationRecord,
    OperationResultLocator,
    OperationState,
    PendingVerdict,
    ProjectionPage,
    ProjectionQuery,
    ProjectionView,
    SelectedAttempt,
    SemanticAttemptHandle,
    SemanticAttemptRecord,
    SemanticDisclosureWait,
    SemanticJobRecord,
    SemanticProgressRecord,
    StoredProjection,
    check_admission_refused,
    check_admission_stage,
)
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectStorePort
from yoetz.ports.runtime import OwnershipFence
from yoetz.protocol.canonical import canonical_encode, strict_json_parse
from yoetz.protocol.coverage import (
    AuthorshipAssurance,
    PublicationChannel,
    coverage_from_json,
    coverage_to_json,
)
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import (
    SEMANTIC_PROGRESS_PHASE_RANK,
    CheckScopeModel,
    SemanticProgressPhase,
    SemanticReason,
    SemanticStatus,
)
from yoetz.protocol.redacted_values import SemanticRedactedValue

__all__ = ["CheckpointReport", "SqliteLedger"]

_GENESIS_DIGEST: Final = "genesis"
# ``bundle_meta`` key of the task-start base pointer (ADR-031); the base itself is encrypted.
_TASK_CHANGE_BASE_META_KEY: Final = "task_change_base"
_CAPTURE_TICKET_SCHEMA_VERSION: Final = 11


@dataclass(frozen=True, slots=True)
class _FreezeReservation:
    """SQLite-local view of the memory oracle's transient acquisition barrier."""

    session_id: str
    expires_at: datetime


def _public_error(
    code: PublicErrorCode,
    *,
    retryable: bool = False,
    reason_code: str | None = None,
    sequence: int | None = None,
    head_digest: str | None = None,
) -> PublicOperationError:
    details: dict[str, str | int] = {}
    if reason_code is not None:
        details["reason_code"] = reason_code
    if sequence is not None:
        details["sequence"] = sequence
    if head_digest is not None:
        details["head_digest"] = head_digest
    return PublicOperationError(
        code, code.value.lower(), retryable, safe_details=details if details else None
    )


def _has_os_error_cause(exc: BaseException) -> bool:
    """Report whether an environmental fault produced this error.

    Several recovery arms convert ``OSError`` into ``STORAGE_CORRUPT`` alongside the decode
    failures they are really about, so the public code alone cannot tell a bad byte from a
    descriptor limit, a read error, or a mount that went away. Walking the causal chain keeps
    the difference: only a verdict with no ``OSError`` anywhere under it is deterministic.
    """

    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, OSError):
            return True
        seen.add(id(current))
        current = current.__cause__ if current.__cause__ is not None else current.__context__
    return False


def _frontier_conflict(head: Frontier) -> PublicOperationError:
    return _public_error(
        PublicErrorCode.FRONTIER_CONFLICT,
        retryable=True,
        reason_code="frontier_changed",
        sequence=head.sequence,
        head_digest=head.head_digest,
    )


@dataclass(frozen=True, slots=True)
class CheckpointReport:
    busy: int
    log: int
    checkpointed: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (self.busy, self.log, self.checkpointed)
        ):
            raise ValueError("checkpoint_report_invalid")


@dataclass(frozen=True, slots=True)
class _Reservation:
    source_identity_digest: str
    publication_ordinal: int


class _SqliteImportShim:
    """Lets the memory oracle prepare a candidate after SQLite has verified W-C-001."""

    reservation: _Reservation | None = None

    def has_pending_import(self, session_id: str) -> bool:
        del session_id
        return False

    def publication_reservation(self, writer_id: str, request_id: str) -> _Reservation | None:
        del writer_id, request_id
        return self.reservation


def _head(db: apsw.Connection) -> Frontier:
    row = db.execute(
        "SELECT ingestion_seq, entry_digest FROM events ORDER BY ingestion_seq DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return Frontier.genesis()
    if type(row[0]) is not int or type(row[1]) is not str:
        raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
    return Frontier(row[0], row[1])


def _operation_digest_row(
    db: apsw.Connection, writer_id: str, operation_id: str
) -> tuple[str, str] | None:
    row = db.execute(
        "SELECT request_digest, state FROM operations WHERE writer_id=? AND operation_id=?",
        (writer_id, operation_id),
    ).fetchone()
    if row is None:
        return None
    if type(row[0]) is not str or type(row[1]) is not str:
        raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
    return row[0], row[1]


def _latest_check_column_values(
    projection: ProjectionState,
) -> tuple[str | None, int | None, str | None, str | None, bytes | None, int | None, bytes | None]:
    """Bind params for the seven ``p1_projection_state`` latest-check columns.

    Always all-null or all-non-null so the ``0001.sql`` consistency CHECK holds. When the
    reducer has cleared ``latest_tested_state`` (for example redaction of the current
    check), the durable mirror must clear with it — leaving prior values would advertise a
    redacted verdict after restart.
    """

    latest = projection.latest_tested_state
    if latest is None:
        return (None, None, None, None, None, None, None)
    return (
        latest.source_check_event_id,
        latest.subject_frontier.sequence,
        latest.subject_frontier.head_digest,
        latest.verdict.value,
        canonical_encode(latest.returned_finding_ids),
        latest.suppressed_count,
        canonical_encode(coverage_to_json(latest.coverage)),
    )


def _import_reservation(db: apsw.Connection, command: AppendCommand) -> _Reservation:
    row = db.execute(
        "SELECT ipr.source_identity_digest, ipr.publication_ordinal, "
        "j.session_id, j.publishing_writer_id, j.state, j.phase, j.batch_count, "
        "j.report_request_id, j.report_event_id "
        "FROM import_publication_requests AS ipr "
        "JOIN import_jobs AS j USING(source_identity_digest) "
        "WHERE ipr.publishing_writer_id=? AND ipr.request_id=?",
        (command.writer_id, command.operation_id),
    ).fetchone()
    if row is None or len(row) != 9:
        raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
    source, ordinal, session, publisher, state, phase, count, report_request, report_event = row
    if (
        type(source) is not str
        or type(ordinal) is not int
        or session != command.session_id
        or publisher != command.writer_id
        or type(count) is not int
        or ordinal < 0
        or ordinal > count
        or state not in {"pending", "complete"}
        or type(phase) is not str
    ):
        raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
    event_ids = tuple(entry.draft.event_id for entry in command.entries)
    if ordinal < count:
        batch = db.execute(
            "SELECT state, request_id, event_ids_canonical, event_count "
            "FROM import_batches WHERE source_identity_digest=? AND batch_index=?",
            (source, ordinal),
        ).fetchone()
        if batch is None or len(batch) != 4:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
        batch_state, request_id, encoded_ids, event_count = batch
        if (
            batch_state != "planned"
            or request_id != command.operation_id
            or type(encoded_ids) is not bytes
            or type(event_count) is not int
            or event_count != len(event_ids)
            or encoded_ids != canonical_encode(event_ids)
        ):
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
    elif (
        command.operation_id != report_request
        or len(event_ids) != 1
        or event_ids[0] != report_event
        or phase not in {"report_ready", "report_published", "terminal"}
    ):
        raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
    return _Reservation(source, ordinal)


class SqliteLedger:
    """Durable ledger over one initialized task-bundle connection."""

    def __init__(
        self,
        *,
        db: apsw.Connection,
        task_id: str,
        ownership_fence: OwnershipFence,
        clock: ClockPort | None = None,
        ids: IdPort | None = None,
        objects: ObjectStorePort | None = None,
    ) -> None:
        self._db = db
        self._task_id = task_id
        self._fence = ownership_fence
        self._clock = clock
        self._ids = ids
        self._objects = objects
        self._lock = asyncio.Lock()
        self._state: MemoryLedgerState = MemoryLedgerState()
        self._requires_recovery = _head(db).sequence != 0
        self._recovery_task: asyncio.Task[None] | None = None
        self._recovery_failed = False

    def open_observation_store(self) -> SqliteObservationStore:
        """Public durable-observation seam over this bundle's connection.

        Production code obtains the mapped-task observation store through this
        accessor rather than reaching into the ledger's private connection.
        """

        return SqliteObservationStore(self._db)

    def _pending_capture_ticket(self, task_id: str) -> tuple[object, ...] | None:
        """Return one unfinished native handoff for this task.

        The ticket table was added by bundle migration 0011.  Older bundles
        intentionally retain the pre-handoff freeze behavior, but a current
        schema must never silently bypass this barrier because a ticket query
        failed for an unrelated SQLite reason.
        """

        try:
            version_row = self._db.execute("PRAGMA user_version").fetchone()
        except apsw.Error as exc:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc
        if version_row is None or type(version_row[0]) is not int:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
        if version_row[0] < _CAPTURE_TICKET_SCHEMA_VERSION:
            return None
        try:
            pending = self._db.execute(
                "SELECT workspace_commitment,logical_identity "
                "FROM observation_capture_tickets "
                "WHERE task_id=? AND state IN ('staging','pending') LIMIT 1",
                (task_id,),
            ).fetchone()
        except apsw.Error as exc:
            # A bundle claiming migration 0011 but missing its ticket table is
            # corrupt.  Silently treating it like a legacy bundle would let a
            # freeze outrun an encrypted handoff that the service can no
            # longer inspect.
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc
        if pending is None:
            return None
        if len(pending) != 2 or type(pending[0]) is not str or type(pending[1]) is not str:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
        try:
            ticket = self.open_observation_store().load_capture_ticket(
                workspace=pending[0],
                logical_identity=pending[1],
            )
        except PublicOperationError:
            raise
        except apsw.Error as exc:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc
        if (
            ticket is None
            or ticket.task_id != task_id
            or ticket.state not in {"staging", "pending"}
        ):
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
        return pending

    def _object_ref_from_inventory(self, object_id: str, task: str, media_type: str) -> ObjectRef:
        row = self._db.execute(
            "SELECT kind,plaintext_size,commitment,envelope_digest,encryption_format,key_slot,"
            "durable_at FROM objects WHERE object_id=?",
            (object_id,),
        ).fetchone()
        if row is None or len(row) != 7:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
        try:
            kind = ObjectKind(row[0])
            created_at = parse_rfc3339_millis(cast(str, row[6]))
            return ObjectRef(
                object_id,
                cast(int, row[1]),
                cast(str, row[2]),
                cast(str, row[3]),
                cast(Literal["yoetz-object/1"], row[4]),
                cast(str, row[5]),
                ObjectMetadata(kind, media_type, task, created_at),
            )
        except (TypeError, ValueError) as exc:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc

    async def _hydrate_artifact_ref(self, object_id: str, task: str) -> None:
        """Restore one optional artifact from its authenticated object envelope.

        The durable object inventory deliberately stores structural fields only; in particular it
        does not store the media type.  Replaying an artifact therefore cannot reconstruct an
        ``ObjectRef`` by guessing a media type from ``ObjectKind``.  Ask the object store to
        authenticate the inventory-pinned envelope instead, then retain it only when the returned
        header agrees with the task and every structural inventory column.  A missing, corrupt, or
        mismatched optional artifact is left out of ``_state.object_refs`` so case-availability
        reports the normal captured-content gap without treating the event ledger as corrupt.
        """

        if self._objects is None:
            return
        row = self._db.execute(
            "SELECT kind,plaintext_size,commitment,envelope_digest,encryption_format,key_slot,state "
            "FROM objects WHERE object_id=?",
            (object_id,),
        ).fetchone()
        if row is None or len(row) != 7 or row[6] != "present":
            return
        try:
            kind = ObjectKind(row[0])
            expected_size = cast(int, row[1])
            expected_commitment = cast(str, row[2])
            expected_envelope_digest = cast(str, row[3])
            expected_encryption_format = cast(Literal["yoetz-object/1"], row[4])
            expected_key_slot = cast(str, row[5])
            resolved = await self._objects.resolve_verified(object_id, expected_envelope_digest)
            if (
                type(resolved) is not ObjectRef
                or resolved.object_id != object_id
                or resolved.metadata.task_id != task
                or resolved.metadata.kind is not kind
                or resolved.plaintext_size != expected_size
                or resolved.commitment != expected_commitment
                or resolved.envelope_digest != expected_envelope_digest
                or resolved.encryption_format != expected_encryption_format
                or resolved.key_slot != expected_key_slot
            ):
                return
        except KeyError, OSError, TypeError, ValueError:
            return
        self._state.object_refs[resolved.object_id] = resolved

    def _terminal_at(self) -> datetime:
        return self._clock.now_utc() if self._clock is not None else datetime.now(UTC)

    def _stored_check_error(self, result_canonical: bytes) -> PublicOperationError:
        try:
            failure_json = strict_json_parse(result_canonical)
            if not isinstance(failure_json, Mapping):
                raise ValueError("check_terminal_error_invalid")
            if frozenset(failure_json) == frozenset(
                {"code", "message", "retryable", "safe_details"}
            ):
                retryable = failure_json["retryable"]
                if retryable is not False:
                    raise ValueError("check_terminal_error_retryable")
                return PublicOperationError(
                    PublicErrorCode(cast(str, failure_json["code"])),
                    cast(str, failure_json["message"]),
                    retryable,
                    safe_details=failure_json["safe_details"],
                )
            if frozenset(failure_json) == frozenset(
                {"code", "reason_code", "sequence", "head_digest"}
            ):
                if (
                    failure_json["code"] != PublicErrorCode.FRONTIER_CONFLICT.value
                    or failure_json["reason_code"] != "frontier_changed"
                ):
                    raise ValueError("check_terminal_error_invalid")
                return _public_error(
                    PublicErrorCode.FRONTIER_CONFLICT,
                    retryable=True,
                    reason_code="frontier_changed",
                    sequence=cast(int, failure_json["sequence"]),
                    head_digest=cast(str, failure_json["head_digest"]),
                )
            raise ValueError("check_terminal_error_invalid")
        except (TypeError, ValueError) as exc:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc

    def _persist_quarantined_operations(self, records: tuple[OperationRecord, ...]) -> None:
        if not records:
            return
        now = format_rfc3339_millis(self._terminal_at())
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._verify_owner()
            for record in records:
                if (
                    record.state is not OperationState.QUARANTINED
                    or record.quarantine_code is None
                    or record.result_canonical is None
                    or record.result_digest is None
                    or record.terminal_at is None
                ):
                    raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
                self._db.execute(
                    "UPDATE operations SET resume_object_id=NULL,state=?,phase=?,"
                    "owner_generation=NULL,lease_owner_id=NULL,lease_generation=NULL,"
                    "lease_expires_at=NULL,result_canonical=?,result_digest=?,"
                    "result_object_id=NULL,quarantine_code=?,terminal_at=?,"
                    "suspension_kind=NULL,updated_at=? "
                    "WHERE writer_id=? AND operation_id=? AND state='pending'",
                    (
                        record.state.value,
                        record.phase.value,
                        record.result_canonical,
                        record.result_digest,
                        record.quarantine_code.value,
                        format_rfc3339_millis(record.terminal_at),
                        now,
                        record.writer_id,
                        record.operation_id,
                    ),
                )
                if self._db.changes() != 1:
                    raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
            self._db.execute("COMMIT")
        except BaseException:
            if self._db.get_autocommit() is False:
                self._db.execute("ROLLBACK")
            raise

    async def _decode_durable_record(self, row: tuple[object, ...]) -> LedgerRecord:
        if len(row) != 5 or type(row[0]) is not bytes:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
        canonical, status, logical_key, payload_digest, _ = row
        try:
            parsed = strict_json_parse(cast(bytes, canonical))
            if canonical_encode(parsed) != canonical or not isinstance(parsed, Mapping):
                raise ValueError("canonical_entry_invalid")
            source = cast(Mapping[str, object], parsed)
            schema_source = cast(Mapping[str, object], source["schema"])
            author_source = cast(Mapping[str, object], source["author"])
            writer_source = cast(Mapping[str, object], source["writer"])
            ledger_source = cast(Mapping[str, object], source["ledger"])
            payload_source = cast(Mapping[str, object], source["payload_ref"])
            schema = EventSchema(
                cast(str, schema_source["name"]), cast(str, schema_source["version"])
            )
            actor = Actor(
                actor_id(cast(str, author_source["actor_id"])),
                ActorType(cast(str, author_source["actor_type"])),
                AuthorshipAssurance(cast(str, author_source["assurance"])),
            )
            writer = WriterChain(
                writer_id(cast(str, writer_source["writer_id"])),
                int(cast(str, writer_source["sequence"])),
                cast(str, writer_source["previous_entry_digest"]),
            )
            ledger = LedgerChain(
                int(cast(str, ledger_source["ingestion_sequence"])),
                cast(str, ledger_source["previous_entry_digest"]),
                timestamp_from_datetime(
                    parse_rfc3339_millis(cast(str, ledger_source["accepted_at"]))
                ),
            )
            payload_ref = PayloadRef(
                object_id(cast(str, payload_source["object_id"])),
                cast(str, payload_source["media_type"]),
                cast(int, payload_source["plaintext_size"]),
                cast(str, payload_source["commitment"]),
                cast(Literal["yoetz-object/1"], payload_source["encryption_format"]),
            )
            target_events_raw = strict_json_parse(cast(bytes, row[4]))
            target_objects_row = self._db.execute(
                "SELECT redaction_target_object_ids FROM event_projection_locators "
                "WHERE event_id=?",
                (cast(str, source["event_id"]),),
            ).fetchone()
            if target_objects_row is None or type(target_objects_row[0]) is not bytes:
                raise ValueError("locator_missing")
            target_objects_raw = strict_json_parse(target_objects_row[0])
            locator = ProjectionLocator(
                schema,
                cast(str | None, logical_key),
                cast(str, payload_digest),
                cast(
                    tuple[EventId, ...],
                    tuple(cast(list[str] | tuple[str, ...], target_events_raw)),
                ),
                cast(
                    tuple[ObjectId, ...],
                    tuple(cast(list[str] | tuple[str, ...], target_objects_raw)),
                ),
            )
            ref = self._object_ref_from_inventory(
                payload_ref.object_id, cast(str, source["task_id"]), payload_ref.media_type
            )
            self._state.object_refs[ref.object_id] = ref
            # Artifact objects are not event payloads.  Their durable inventory row is written
            # before the event is published, so hydrate the exact authenticated descriptor on
            # replay when the object is still present.  This includes captured observation and
            # approved-check artifacts, whose media types are distinct despite sharing a captured
            # object kind.
            for artifact_value in cast(list[str] | tuple[str, ...], source["artifact_refs"]):
                if artifact_value in self._state.object_refs:
                    continue
                await self._hydrate_artifact_ref(artifact_value, cast(str, source["task_id"]))
            payload = None
            if source["redaction"] == "present" and self._objects is not None:
                try:
                    chunks = [chunk async for chunk in self._objects.open_verified(ref)]
                except KeyError, OSError, ValueError:
                    chunks = []
                if chunks:
                    payload_json = strict_json_parse(b"".join(chunks))
                    payload = (
                        payload_json
                        if status == "unknown_unprojected"
                        else decode_payload(schema, cast(DomainJsonValue, payload_json))
                    )
            common: Any = dict(
                event_id=cast(str, source["event_id"]),
                task_id=cast(str, source["task_id"]),
                session_id=cast(str, source["session_id"]),
                schema=schema,
                author=actor,
                writer=writer,
                ledger=ledger,
                operation_id=cast(str, source["operation_id"]),
                occurred_at=timestamp_from_datetime(
                    parse_rfc3339_millis(cast(str, source["occurred_at"]))
                ),
                causal_parents=tuple(cast(list[str] | tuple[str, ...], source["causal_parents"])),
                publication_channel=PublicationChannel(cast(str, source["publication_channel"])),
                coverage=coverage_from_json(cast(DomainJsonValue, source["coverage"])),
                payload_ref=payload_ref,
                redaction=RedactionState(cast(str, source["redaction"])),
                artifact_refs=tuple(cast(list[str] | tuple[str, ...], source["artifact_refs"])),
                evidence_refs=tuple(cast(list[str] | tuple[str, ...], source["evidence_refs"])),
                entry_digest=cast(str, source["entry_digest"]),
                payload=payload,
                projection_locator=locator,
            )
            record: LedgerRecord
            if status == "unknown_unprojected":
                record = UnknownEvent(**common, canonical_payload_digest=cast(str, payload_digest))
            else:
                record = AcceptedEvent(**common)
            if canonical_encode(accepted_record_to_json(record)) != canonical:
                raise ValueError("canonical_index_mismatch")
            return record
        except PublicOperationError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc

    async def _ensure_recovered(self) -> None:
        if not self._requires_recovery:
            return
        if self._recovery_failed:
            # A corrupt durable row makes recovery deterministically terminal. Re-running the
            # whole replay for every later call spent O(ledger) CPU and allocation per RPC and
            # starved the control plane for minutes (#238); the verdict is already known.
            # Invariant: only a decode verdict with no OSError under it may latch here, so a
            # transient environmental fault can never brick an intact bundle until restart.
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
        task = self._recovery_task
        if task is None:
            task = asyncio.create_task(self._recover_once())
            self._recovery_task = task
        try:
            await asyncio.shield(task)
        finally:
            if task.done() and self._recovery_task is task:
                self._recovery_task = None

    async def verify_recovery_objects(self) -> int:
        """Authenticate every object that the replayed ledger still declares present."""

        await self._ensure_recovered()
        objects = self._objects
        if objects is None:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
        verified: set[str] = set()
        try:
            for record in self._state.records:
                if record.redaction is not RedactionState.PRESENT:
                    continue
                ref = self._state.object_refs.get(record.payload_ref.object_id)
                if ref is None:
                    raise ValueError("object_reference_missing")
                async for _chunk in objects.open_verified(ref):
                    pass
                verified.add(ref.object_id)
        except (KeyError, OSError, TypeError, ValueError) as exc:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc
        return len(verified)

    async def _recover_once(self) -> None:
        """Latch a terminal recovery verdict so it is reached at most once."""

        try:
            await self._recover_projection()
        except PublicOperationError as exc:
            if exc.code is PublicErrorCode.STORAGE_CORRUPT and not _has_os_error_cause(exc):
                self._recovery_failed = True
            raise

    async def _recover_projection(self) -> None:
        """Rebuild one shared projection without duplicating work on caller cancellation."""

        if not self._requires_recovery:
            return
        async with self._lock:
            if not self._requires_recovery:
                return
            rows = cast(
                list[tuple[object, ...]],
                self._db.execute(
                    "SELECT e.canonical_entry,e.projection_status,l.logical_key,"
                    "l.canonical_payload_digest,l.redaction_target_event_ids "
                    "FROM events AS e JOIN event_projection_locators AS l USING(event_id) "
                    "ORDER BY e.ingestion_seq"
                ).fetchall(),
            )
            decoded_records: list[LedgerRecord] = []
            for index, row in enumerate(rows, start=1):
                decoded_records.append(await self._decode_durable_record(row))
                if index % 32 == 0:
                    await asyncio.sleep(0)
            records = tuple(decoded_records)
            try:
                # Reducer replay is pure but can be CPU-heavy for a mature ledger.  Keep it off
                # the service daemon's event loop so recovery of one task cannot starve control
                # handshakes or unrelated task routes.
                projection = await asyncio.to_thread(replay, records)
            except ValueError as exc:
                raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc
            for (
                writer_id_value,
                task_value,
                session_value,
                next_seq,
                head_digest,
            ) in self._db.execute(
                "SELECT writer_id,task_id,session_id,next_writer_seq,head_entry_digest FROM writers"
            ):
                self._state.restore_writer(
                    cast(str, writer_id_value),
                    cast(str, task_value),
                    cast(str, session_value),
                    cast(int, next_seq),
                    cast(str, head_digest),
                )
            self._state.records = records
            self._state.projection = projection
            self._state.trusted_projections.remember(projection, records)
            newly_quarantined: list[OperationRecord] = []
            for pending_row in self._db.execute(
                "SELECT writer_id,operation_id,operation_kind,request_digest,phase,"
                "owner_generation,lease_owner_id,lease_generation,lease_expires_at,"
                "resume_object_id,suspension_kind FROM operations WHERE state='pending'"
            ):
                (
                    writer_value,
                    operation_value,
                    kind_value,
                    digest_value,
                    phase_value,
                    owner_generation,
                    lease_owner_id,
                    lease_generation,
                    lease_expires_at,
                    resume_object_id,
                    suspension_kind_value,
                ) = pending_row
                try:
                    phase = CheckPhase(cast(str, phase_value))
                    media_type = (
                        "application/vnd.yoetz.check-resume+json"
                        if phase is CheckPhase.RESERVED
                        else "application/vnd.yoetz.deterministic-result+json"
                    )
                    resume_ref = self._object_ref_from_inventory(
                        cast(str, resume_object_id), self._task_id, media_type
                    )
                    operation = OperationRecord(
                        cast(str, writer_value),
                        cast(str, operation_value),
                        OperationKind(cast(str, kind_value)),
                        cast(str, digest_value),
                        OperationState.PENDING,
                        phase,
                        cast(str, owner_generation),
                        cast(str, lease_owner_id),
                        cast(int, lease_generation),
                        parse_rfc3339_millis(cast(str, lease_expires_at)),
                        resume_ref,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None
                        if suspension_kind_value is None
                        else CheckSuspensionKind(cast(str, suspension_kind_value)),
                    )
                    writer = self._state.writers[operation.writer_id]
                    if self._objects is None:
                        raise ValueError("object_store_missing")
                except PublicOperationError:
                    raise
                except (KeyError, OSError, TypeError, ValueError) as exc:
                    raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc
                key = (operation.writer_id, operation.operation_id)
                assert self._objects is not None
                try:
                    case = await load_frozen_case_from_resume(
                        self._objects,
                        operation,
                        task=self._task_id,
                        session=writer.session_id,
                    )
                except OSError as exc:
                    raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc
                except KeyError, TypeError, ValueError:
                    # Decode/shape/binding of this resume pointer is operation-scoped. The
                    # event chain already replayed; latching _recovery_failed here would make
                    # every later call STORAGE_CORRUPT for an intact ledger (#443).
                    quarantined, stored_error = quarantine_resume_object_invalid(
                        operation, now=self._terminal_at()
                    )
                    self._state.operations[key] = (quarantined, None)
                    self._state.check_errors[key] = stored_error
                    newly_quarantined.append(quarantined)
                    await asyncio.sleep(0)
                    continue
                self._state.frozen_cases[key] = case
                self._state.operations[key] = (operation, None)
                await asyncio.sleep(0)
            for operation_row in self._db.execute(
                "SELECT writer_id,operation_id,operation_kind,request_digest,state,phase,"
                "result_canonical,result_digest,first_ingestion_seq,last_ingestion_seq,"
                "result_object_id,terminal_at "
                "FROM operations WHERE state='complete'"
            ):
                (
                    writer_value,
                    operation_value,
                    kind_value,
                    digest_value,
                    state_value,
                    phase_value,
                    result_canonical,
                    result_digest,
                    first,
                    last,
                    result_object_id,
                    terminal,
                ) = operation_row
                structural = (
                    ()
                    if first is None or last is None
                    else tuple(
                        item[0]
                        for item in self._db.execute(
                            "SELECT event_id FROM events WHERE ingestion_seq BETWEEN ? AND ? "
                            "ORDER BY event_id",
                            (first, last),
                        )
                    )
                )
                result_ref = (
                    None
                    if result_object_id is None
                    else self._object_ref_from_inventory(
                        cast(str, result_object_id),
                        self._task_id,
                        "application/vnd.yoetz.receipt+json",
                    )
                )
                locator = (
                    None
                    if first is None and last is None and result_ref is None
                    else OperationResultLocator(first, last, result_ref, structural)
                )
                operation = OperationRecord(
                    writer_value,
                    operation_value,
                    OperationKind(kind_value),
                    digest_value,
                    OperationState(state_value),
                    CheckPhase(phase_value),
                    None,
                    None,
                    None,
                    None,
                    None,
                    result_canonical,
                    result_digest,
                    locator,
                    None,
                    parse_rfc3339_millis(terminal),
                )
                append_result = None
                check_result = None
                check_error: PublicOperationError | None = None
                if operation.operation_kind is not OperationKind.CHECK:
                    result_json = strict_json_parse(result_canonical)
                    result_map = cast(Mapping[str, object], result_json)
                    accepted_rows = cast(list[Mapping[str, object]], result_map["accepted"])
                    append_result = AppendResult(
                        "accepted",
                        tuple(
                            AcceptedEventSummary(
                                cast(str, item["event_id"]),
                                int(cast(str, item["ingestion_sequence"])),
                                int(cast(str, item["writer_sequence"])),
                                cast(str, item["entry_digest"]),
                                cast(
                                    Literal["projected", "unknown_unprojected"],
                                    item["projection_status"],
                                ),
                            )
                            for item in accepted_rows
                        ),
                        frontier_from_json(result_map["subject_frontier"]),
                        frontier_from_json(result_map["result_frontier"]),
                        tuple(
                            AppendWarning(cast(str, value))
                            for value in cast(list[object], result_map["warnings"])
                        ),
                    )
                elif locator is not None:
                    operation_records = records[cast(int, first) - 1 : cast(int, last)]
                    check_event = next(
                        (
                            item
                            for item in reversed(operation_records)
                            if type(item) is AcceptedEvent
                            and type(item.payload) is CheckRecordedPayload
                        ),
                        None,
                    )
                    if check_event is not None:
                        check_payload = cast(CheckRecordedPayload, check_event.payload)
                        # A converged recheck can return an existing finding ID without emitting a
                        # duplicate finding_recorded event. Recover those exact payloads from the
                        # historical prefix ending at this check, never from the latest projection
                        # where later work could change what a replay returns.
                        historical_findings = {
                            cast(FindingRecordedPayload, item.payload).finding_id: cast(
                                FindingRecordedPayload, item.payload
                            )
                            for item in records[: cast(int, last)]
                            if type(item) is AcceptedEvent
                            and item.schema.name == "finding_recorded"
                            and item.payload is not None
                        }
                        try:
                            # returned_finding_ids is the canonical set, not rank order.
                            # Reconstruct presentation order with the registered rank_key so a
                            # durable replay matches the original check result.
                            finding_payloads = tuple(
                                sorted(
                                    (
                                        historical_findings[finding]
                                        for finding in check_payload.returned_finding_ids
                                    ),
                                    key=rank_key,
                                )
                            )
                        except KeyError as exc:
                            raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc
                        executions = tuple(
                            CheckPolicyExecution(
                                item.policy_id,
                                item.policy_version,
                                item.outcome,
                                item.reason,
                            )
                            for item in check_payload.policy_executions
                        )
                        check_result = CheckCommitResult(
                            "committed",
                            check_event.task_id,
                            check_event.session_id,
                            check_event.writer.writer_id,
                            check_event.operation_id,
                            check_payload.subject_frontier,
                            Frontier(
                                operation_records[-1].ledger.ingestion_sequence,
                                operation_records[-1].entry_digest,
                            ),
                            check_payload.verdict,
                            finding_payloads,
                            check_payload.suppressed_count,
                            executions,
                            check_payload.semantic_status,
                            check_payload.semantic_reason,
                            check_payload.semantic_provenance,
                            check_payload.coverage,
                            CheckVersionSlice(
                                "0.1",
                                check_payload.engine_version,
                                check_payload.projection_version,
                                tuple(
                                    f"{item.policy_id}/{item.policy_version}" for item in executions
                                ),
                            ),
                            semantic_conclusion=check_payload.semantic_conclusion,
                            review_summary=check_payload.review_summary,
                            verified=check_payload.verified,
                            missing_for_assessment=check_payload.missing_for_assessment,
                            review_input_manifest=check_payload.review_input_manifest,
                            totals=check_payload.totals,
                            # Recovery rebuilds the same result the commit returned (#982).
                            semantic_withheld_item_ids=check_payload.semantic_withheld_item_ids,
                            semantic_redacted_values=check_payload.semantic_redacted_values,
                            semantic_route_required=check_payload.semantic_route_required,
                        )
                else:
                    check_error = self._stored_check_error(cast(bytes, result_canonical))
                self._state.operations[(writer_value, operation_value)] = (
                    operation,
                    append_result,
                )
                if check_result is not None:
                    self._state.check_results[(writer_value, operation_value)] = check_result
                if operation.operation_kind is OperationKind.CHECK and locator is None:
                    assert check_error is not None
                    self._state.check_errors[(writer_value, operation_value)] = check_error
            for quarantine_row in self._db.execute(
                "SELECT writer_id,operation_id,operation_kind,request_digest,phase,"
                "result_canonical,result_digest,quarantine_code,terminal_at "
                "FROM operations WHERE state='quarantined'"
            ):
                (
                    writer_value,
                    operation_value,
                    kind_value,
                    digest_value,
                    phase_value,
                    result_canonical,
                    result_digest,
                    quarantine_code_value,
                    terminal,
                ) = quarantine_row
                try:
                    operation = OperationRecord(
                        cast(str, writer_value),
                        cast(str, operation_value),
                        OperationKind(cast(str, kind_value)),
                        cast(str, digest_value),
                        OperationState.QUARANTINED,
                        CheckPhase(cast(str, phase_value)),
                        None,
                        None,
                        None,
                        None,
                        None,
                        cast(bytes, result_canonical),
                        cast(str, result_digest),
                        None,
                        OperationQuarantineCode(cast(str, quarantine_code_value)),
                        parse_rfc3339_millis(cast(str, terminal)),
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc
                key = (operation.writer_id, operation.operation_id)
                self._state.operations[key] = (operation, None)
                if operation.operation_kind is OperationKind.CHECK:
                    self._state.check_errors[key] = self._stored_check_error(
                        cast(bytes, result_canonical)
                    )
                await asyncio.sleep(0)
            self._persist_quarantined_operations(tuple(newly_quarantined))
            # AI-powered review jobs and attempts back every durable disclosure wait. Recovering only the
            # side-table marker makes operation status look resumable while the attempt
            # coordinator sees no job and cannot actually resume it after restart.
            for job_row in self._db.execute(
                "SELECT job_id,writer_id,operation_id,case_digest,case_object_id,state,"
                "active_attempt_id,selected_attempt_id,attempt_count,lease_owner_id,"
                "lease_generation,lease_expires_at,selected_result_object_id,terminal_code,"
                "terminal_at FROM semantic_jobs AS jobs WHERE EXISTS ("
                "SELECT 1 FROM operations AS operations "
                "WHERE operations.writer_id=jobs.writer_id "
                "AND operations.operation_id=jobs.operation_id "
                "AND operations.state='pending')"
            ):
                (
                    job_id_value,
                    job_writer,
                    job_operation,
                    case_digest,
                    case_object_id,
                    job_state,
                    active_attempt_id,
                    selected_attempt_id,
                    attempt_count,
                    job_lease_owner,
                    job_lease_generation,
                    job_lease_expires,
                    selected_result_object_id,
                    terminal_code,
                    terminal_at,
                ) = job_row
                try:
                    case_ref = self._object_ref_from_inventory(
                        cast(str, case_object_id),
                        self._task_id,
                        "application/json",
                    )
                    selected_ref = (
                        None
                        if selected_result_object_id is None
                        else self._object_ref_from_inventory(
                            cast(str, selected_result_object_id),
                            self._task_id,
                            "application/json",
                        )
                    )
                    job = SemanticJobRecord(
                        cast(str, job_id_value),
                        cast(str, job_writer),
                        cast(str, job_operation),
                        cast(str, case_digest),
                        case_ref,
                        cast(
                            Literal["queued", "leased", "succeeded", "failed", "quarantined"],
                            job_state,
                        ),
                        cast(int, attempt_count),
                        cast(str | None, active_attempt_id),
                        cast(str | None, selected_attempt_id),
                        cast(str | None, job_lease_owner),
                        cast(int | None, job_lease_generation),
                        None
                        if job_lease_expires is None
                        else parse_rfc3339_millis(cast(str, job_lease_expires)),
                        selected_ref,
                        None if terminal_code is None else SemanticReason(cast(str, terminal_code)),
                        None
                        if terminal_at is None
                        else parse_rfc3339_millis(cast(str, terminal_at)),
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc
                self._state.jobs[job.job_id] = job
                self._state.job_by_case[(job.writer_id, job.operation_id, job.case_digest)] = (
                    job.job_id
                )

            for attempt_row in self._db.execute(
                "SELECT attempt_id,job_id,attempt_ordinal,provider_request_id,owner_generation,"
                "lease_owner_id,lease_generation,state,result_object_id,terminal_code,started_at,"
                "usage_input_tokens,usage_cached_input_tokens,usage_cache_write_input_tokens,"
                "usage_output_tokens,usage_reasoning_output_tokens,usage_total_tokens "
                "FROM semantic_attempts WHERE job_id IN ("
                "SELECT job_id FROM semantic_jobs AS jobs WHERE EXISTS ("
                "SELECT 1 FROM operations AS operations "
                "WHERE operations.writer_id=jobs.writer_id "
                "AND operations.operation_id=jobs.operation_id "
                "AND operations.state='pending'))"
            ):
                (
                    attempt_id_value,
                    attempt_job_id,
                    attempt_ordinal,
                    provider_request_id,
                    attempt_owner_generation,
                    attempt_lease_owner,
                    attempt_lease_generation,
                    attempt_state,
                    attempt_result_object_id,
                    attempt_terminal_code,
                    attempt_started_at,
                    usage_input_tokens,
                    usage_cached_input_tokens,
                    usage_cache_write_input_tokens,
                    usage_output_tokens,
                    usage_reasoning_output_tokens,
                    usage_total_tokens,
                ) = attempt_row
                try:
                    job = self._state.jobs[cast(str, attempt_job_id)]
                    operation = self._state.operations[(job.writer_id, job.operation_id)][0]
                    case = self._state.frozen_cases[(job.writer_id, job.operation_id)]
                    if operation.lease_expires_at is None:
                        raise ValueError("semantic_attempt_operation_lease_missing")
                    result_ref = (
                        None
                        if attempt_result_object_id is None
                        else self._object_ref_from_inventory(
                            cast(str, attempt_result_object_id),
                            self._task_id,
                            "application/vnd.yoetz.semantic-response+json",
                        )
                    )
                    usage_values = (
                        usage_input_tokens,
                        usage_cached_input_tokens,
                        usage_cache_write_input_tokens,
                        usage_output_tokens,
                        usage_reasoning_output_tokens,
                        usage_total_tokens,
                    )
                    if all(value is None for value in usage_values):
                        token_usage = None
                    elif any(value is None for value in usage_values):
                        raise ValueError("semantic_attempt_usage_partial")
                    elif any(type(value) is not int for value in usage_values):
                        raise ValueError("semantic_attempt_usage_type")
                    else:
                        token_usage = RuntimeTokenUsage(*cast(tuple[int, ...], usage_values))
                    handle = SemanticAttemptHandle(
                        job.job_id,
                        cast(str, attempt_id_value),
                        cast(int, attempt_ordinal),
                        cast(str, provider_request_id),
                        job.writer_id,
                        job.operation_id,
                        cast(str, attempt_owner_generation),
                        cast(str, attempt_lease_owner),
                        cast(int, attempt_lease_generation),
                        operation.lease_expires_at,
                        case.frontier,
                        _case_dependency_digest(case),
                    )
                    attempt = _AttemptState(
                        handle,
                        cast(str, attempt_state),
                        result_ref,
                        None
                        if attempt_terminal_code is None
                        else SemanticReason(cast(str, attempt_terminal_code)),
                        parse_rfc3339_millis(cast(str, attempt_started_at)),
                        token_usage,
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc
                self._state.attempts[handle.attempt_id] = attempt

            # Disclosure waits are durable but the oracle is in-memory, so a restart would
            # otherwise answer "no continuation" for a check that is genuinely still suspended —
            # exactly the unrecoverable state this work exists to remove.
            for wait_row in self._db.execute(
                "SELECT job_id,attempt_id,writer_id,operation_id,pending_id,"
                "pending_expires_at,state,resolved_at FROM semantic_disclosure_waits "
                "WHERE job_id IN (SELECT job_id FROM semantic_jobs AS jobs WHERE EXISTS ("
                "SELECT 1 FROM operations AS operations "
                "WHERE operations.writer_id=jobs.writer_id "
                "AND operations.operation_id=jobs.operation_id "
                "AND operations.state='pending'))"
            ):
                (
                    job_value,
                    attempt_value,
                    wait_writer,
                    wait_operation,
                    pending_value,
                    pending_expires,
                    wait_state,
                    resolved_at,
                ) = wait_row
                try:
                    wait = SemanticDisclosureWait(
                        cast(str, job_value),
                        cast(str, attempt_value),
                        cast(str, wait_writer),
                        cast(str, wait_operation),
                        cast(str, pending_value),
                        parse_rfc3339_millis(cast(str, pending_expires)),
                        cast(Literal["awaiting", "resolved"], wait_state),
                        None
                        if resolved_at is None
                        else parse_rfc3339_millis(cast(str, resolved_at)),
                    )
                except (TypeError, ValueError) as exc:
                    raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc
                self._state.disclosure_waits[wait.job_id] = wait
            self._requires_recovery = False

    def _inventory_object(self, ref: ObjectRef) -> None:
        existing = self._db.execute(
            "SELECT kind,plaintext_size,commitment,envelope_digest,encryption_format,key_slot "
            "FROM objects WHERE object_id=?",
            (ref.object_id,),
        ).fetchone()
        descriptor = (
            ref.metadata.kind.value,
            ref.plaintext_size,
            ref.commitment,
            ref.envelope_digest,
            ref.encryption_format,
            ref.key_slot,
        )
        if existing is None:
            self._db.execute(
                "INSERT INTO objects(object_id,kind,plaintext_size,commitment,envelope_digest,"
                "encryption_format,key_slot,state,durable_at) VALUES(?,?,?,?,?,?,?,'present',?)",
                (ref.object_id, *descriptor, format_rfc3339_millis(ref.metadata.created_at)),
            )
        elif tuple(existing) != descriptor:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT)

    def _sync_runtime_state(self) -> None:
        now = format_rfc3339_millis(
            self._clock.now_utc() if self._clock is not None else datetime.now(UTC)
        )
        for key, (record, _) in self._state.operations.items():
            if record.resume_object_ref is not None:
                self._inventory_object(record.resume_object_ref)
            if (
                record.result_locator is not None
                and record.result_locator.result_object_ref is not None
            ):
                self._inventory_object(record.result_locator.result_object_ref)
            exists = self._db.execute(
                "SELECT 1 FROM operations WHERE writer_id=? AND operation_id=?", key
            ).fetchone()
            locator = record.result_locator
            values = (
                record.operation_kind.value,
                record.request_digest,
                None if record.resume_object_ref is None else record.resume_object_ref.object_id,
                record.state.value,
                record.phase.value,
                record.owner_generation,
                record.lease_owner_id,
                record.lease_generation,
                None
                if record.lease_expires_at is None
                else format_rfc3339_millis(record.lease_expires_at),
                None if locator is None else locator.first_ingestion_sequence,
                None if locator is None else locator.last_ingestion_sequence,
                record.result_canonical,
                record.result_digest,
                None
                if locator is None or locator.result_object_ref is None
                else locator.result_object_ref.object_id,
                None if record.quarantine_code is None else record.quarantine_code.value,
                None if record.terminal_at is None else format_rfc3339_millis(record.terminal_at),
                None if record.suspension_kind is None else record.suspension_kind.value,
            )
            if exists is None:
                self._db.execute(
                    "INSERT INTO operations(writer_id,operation_id,operation_kind,request_digest,"
                    "resume_object_id,state,phase,owner_generation,lease_owner_id,lease_generation,"
                    "lease_expires_at,first_ingestion_seq,last_ingestion_seq,result_canonical,"
                    "result_digest,result_object_id,quarantine_code,terminal_at,suspension_kind,"
                    "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (key[0], key[1], *values, now, now),
                )
            else:
                self._db.execute(
                    "UPDATE operations SET operation_kind=?,request_digest=?,resume_object_id=?,"
                    "state=?,phase=?,owner_generation=?,lease_owner_id=?,lease_generation=?,"
                    "lease_expires_at=?,first_ingestion_seq=?,last_ingestion_seq=?,"
                    "result_canonical=?,result_digest=?,result_object_id=?,quarantine_code=?,"
                    "terminal_at=?,suspension_kind=?,updated_at=? "
                    "WHERE writer_id=? AND operation_id=?",
                    (*values, now, key[0], key[1]),
                )
        for job in self._state.jobs.values():
            self._inventory_object(job.case_object_ref)
            if job.selected_result_object_ref is not None:
                self._inventory_object(job.selected_result_object_ref)
            # ON CONFLICT DO UPDATE, not INSERT OR REPLACE, for two reasons. It preserves
            # created_at: the old form rewrote it to "now" on every sync of every job, so a job
            # could appear to have been created after it terminated and the durable rows could
            # not be used to reconstruct what happened. And it updates the row in place instead
            # of deleting and re-inserting it, which matters because semantic_jobs and
            # semantic_attempts reference each other — the delete was only survivable because of
            # the deferred-foreign-keys pragma.
            self._db.execute(
                "INSERT INTO semantic_jobs(job_id,writer_id,operation_id,case_digest,"
                "case_object_id,state,active_attempt_id,selected_attempt_id,attempt_count,"
                "owner_generation,lease_owner_id,lease_generation,lease_expires_at,"
                "selected_result_object_id,terminal_code,terminal_at,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET "
                "state=excluded.state,active_attempt_id=excluded.active_attempt_id,"
                "selected_attempt_id=excluded.selected_attempt_id,"
                "attempt_count=excluded.attempt_count,"
                "owner_generation=excluded.owner_generation,"
                "lease_owner_id=excluded.lease_owner_id,"
                "lease_generation=excluded.lease_generation,"
                "lease_expires_at=excluded.lease_expires_at,"
                "selected_result_object_id=excluded.selected_result_object_id,"
                "terminal_code=excluded.terminal_code,"
                # Stamped once, on the transition; never dragged forward by a later sync.
                "terminal_at=COALESCE(semantic_jobs.terminal_at,excluded.terminal_at),"
                "updated_at=excluded.updated_at",
                (
                    job.job_id,
                    job.writer_id,
                    job.operation_id,
                    job.case_digest,
                    job.case_object_ref.object_id,
                    job.state,
                    job.active_attempt_id,
                    job.selected_attempt_id,
                    job.attempt_count,
                    str(self._fence.owner_generation) if job.state == "leased" else None,
                    job.lease_owner_id,
                    job.lease_generation,
                    None
                    if job.lease_expires_at is None
                    else format_rfc3339_millis(job.lease_expires_at),
                    None
                    if job.selected_result_object_ref is None
                    else job.selected_result_object_ref.object_id,
                    None if job.terminal_code is None else job.terminal_code.value,
                    None if job.terminal_at is None else format_rfc3339_millis(job.terminal_at),
                    now,
                    now,
                ),
            )
        for attempt in self._state.attempts.values():
            if attempt.result_object_ref is not None:
                self._inventory_object(attempt.result_object_ref)
            handle = attempt.handle
            # started_at is the claim time and must survive every later sync; the old form
            # rewrote it to "now" each time, which is why the recorded attempt timestamps from
            # the stranded dogfood run could not be trusted.
            self._db.execute(
                "INSERT INTO semantic_attempts(attempt_id,job_id,attempt_ordinal,"
                "provider_request_id,owner_generation,lease_owner_id,lease_generation,state,"
                "result_object_id,terminal_code,started_at,terminal_at,"
                "usage_input_tokens,usage_cached_input_tokens,usage_cache_write_input_tokens,"
                "usage_output_tokens,usage_reasoning_output_tokens,usage_total_tokens) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(attempt_id) DO UPDATE SET "
                "state=excluded.state,result_object_id=excluded.result_object_id,"
                "terminal_code=excluded.terminal_code,"
                "usage_input_tokens=excluded.usage_input_tokens,"
                "usage_cached_input_tokens=excluded.usage_cached_input_tokens,"
                "usage_cache_write_input_tokens=excluded.usage_cache_write_input_tokens,"
                "usage_output_tokens=excluded.usage_output_tokens,"
                "usage_reasoning_output_tokens=excluded.usage_reasoning_output_tokens,"
                "usage_total_tokens=excluded.usage_total_tokens,"
                "terminal_at=COALESCE(semantic_attempts.terminal_at,excluded.terminal_at)",
                (
                    handle.attempt_id,
                    handle.job_id,
                    handle.attempt_ordinal,
                    handle.provider_request_id,
                    handle.owner_generation,
                    handle.lease_owner_id,
                    handle.lease_generation,
                    attempt.state,
                    None
                    if attempt.result_object_ref is None
                    else attempt.result_object_ref.object_id,
                    None if attempt.terminal_code is None else attempt.terminal_code.value,
                    now
                    if attempt.started_at is None
                    else format_rfc3339_millis(attempt.started_at),
                    now if attempt.state in {"selected", "failed", "expired", "late"} else None,
                    None if attempt.token_usage is None else attempt.token_usage.input_tokens,
                    None
                    if attempt.token_usage is None
                    else attempt.token_usage.cached_input_tokens,
                    None
                    if attempt.token_usage is None
                    else attempt.token_usage.cache_write_input_tokens,
                    None if attempt.token_usage is None else attempt.token_usage.output_tokens,
                    None
                    if attempt.token_usage is None
                    else attempt.token_usage.reasoning_output_tokens,
                    None if attempt.token_usage is None else attempt.token_usage.total_tokens,
                ),
            )
        for wait in self._state.disclosure_waits.values():
            # created_at is preserved on conflict for the same reason job/attempt timestamps are:
            # a wait that appears to have been created after it resolved cannot be used to
            # reconstruct how long a decision actually took.
            self._db.execute(
                "INSERT INTO semantic_disclosure_waits(job_id,attempt_id,writer_id,"
                "operation_id,pending_id,pending_expires_at,state,resolved_at,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET "
                # A fresh physical attempt supersedes a resolved wait on the same job, so every
                # identity and pending field is replaced. Carrying the old resolved_at forward
                # through COALESCE would write state='awaiting' beside a non-null resolved_at,
                # which the table CHECK rejects. Only created_at survives.
                "attempt_id=excluded.attempt_id,"
                "writer_id=excluded.writer_id,"
                "operation_id=excluded.operation_id,"
                "pending_id=excluded.pending_id,"
                "pending_expires_at=excluded.pending_expires_at,"
                "state=excluded.state,"
                "resolved_at=excluded.resolved_at",
                (
                    wait.job_id,
                    wait.attempt_id,
                    wait.writer_id,
                    wait.operation_id,
                    wait.pending_id,
                    format_rfc3339_millis(wait.pending_expires_at),
                    wait.state,
                    None if wait.resolved_at is None else format_rfc3339_millis(wait.resolved_at),
                    now,
                ),
            )

    def _verify_owner(self) -> None:
        rows = dict(
            cast(
                list[tuple[str, str]],
                self._db.execute(
                    "SELECT key, value FROM bundle_meta WHERE key IN ('owner_generation','owner_nonce')"
                ).fetchall(),
            )
        )
        stored_generation = rows.get("owner_generation")
        stored_nonce = rows.get("owner_nonce")
        if stored_generation is not None and stored_generation != str(self._fence.owner_generation):
            raise _public_error(PublicErrorCode.STORAGE_UNSAFE)
        if stored_nonce is not None and stored_nonce != self._fence.nonce:
            raise _public_error(PublicErrorCode.STORAGE_UNSAFE)

    def _ensure_writer(self, command: AppendCommand, now: str) -> None:
        row = self._db.execute(
            "SELECT task_id, session_id FROM writers WHERE writer_id=?",
            (command.writer_id,),
        ).fetchone()
        if row is None:
            self._db.execute(
                "INSERT INTO writers(writer_id,task_id,session_id,next_writer_seq,"
                "head_entry_digest,state,created_at) VALUES(?,?,?,1,'genesis','active',?)",
                (command.writer_id, command.task_id, command.session_id, now),
            )
        elif row != (command.task_id, command.session_id):
            raise _public_error(PublicErrorCode.EVENT_INVALID)

    def _persist_append(
        self, command: AppendCommand, result: AppendResult, records: tuple[LedgerRecord, ...]
    ) -> None:
        now = records[-1].ledger.accepted_at.wire
        self._verify_owner()
        self._ensure_writer(command, now)
        current = _head(self._db)
        if current != result.subject_frontier:
            raise _frontier_conflict(current)
        for artifact_ref in command.artifact_object_refs:
            self._inventory_object(artifact_ref)
        for record, entry in zip(records, command.entries, strict=True):
            ref = entry.payload_object
            existing = self._db.execute(
                "SELECT kind,plaintext_size,commitment,envelope_digest,encryption_format,key_slot "
                "FROM objects WHERE object_id=?",
                (ref.object_id,),
            ).fetchone()
            descriptor = (
                ref.metadata.kind.value,
                ref.plaintext_size,
                ref.commitment,
                ref.envelope_digest,
                ref.encryption_format,
                ref.key_slot,
            )
            if existing is None:
                self._db.execute(
                    "INSERT INTO objects(object_id,kind,plaintext_size,commitment,envelope_digest,"
                    "encryption_format,key_slot,state,durable_at) VALUES(?,?,?,?,?,?,?,'present',?)",
                    (ref.object_id, *descriptor, format_rfc3339_millis(ref.metadata.created_at)),
                )
            elif tuple(existing) != descriptor:
                raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
            status = "unknown_unprojected" if type(record) is UnknownEvent else "projected"
            summary = "opaque_unknown" if type(record) is UnknownEvent else record.schema.name
            canonical = canonical_encode(accepted_record_to_json(record))
            self._db.execute(
                "INSERT INTO events(ingestion_seq,event_id,task_id,session_id,schema_name,"
                "schema_version,projection_status,summary_code,author_id,author_type,"
                "author_assurance,writer_id,writer_seq,operation_id,previous_ledger_digest,"
                "previous_writer_digest,entry_digest,canonical_entry,payload_object_id,"
                "payload_commitment,publication_channel,redaction_state,occurred_at,accepted_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.ledger.ingestion_sequence,
                    record.event_id,
                    record.task_id,
                    record.session_id,
                    record.schema.name,
                    record.schema.version,
                    status,
                    summary,
                    record.author.actor_id,
                    record.author.actor_type.value,
                    record.author.assurance.value,
                    record.writer.writer_id,
                    record.writer.sequence,
                    record.operation_id,
                    record.ledger.previous_entry_digest,
                    record.writer.previous_entry_digest,
                    record.entry_digest,
                    canonical,
                    record.payload_ref.object_id,
                    record.payload_ref.commitment,
                    record.publication_channel.value,
                    record.redaction.value,
                    record.occurred_at.wire,
                    record.ledger.accepted_at.wire,
                ),
            )
            locator = record.projection_locator
            self._db.execute(
                "INSERT INTO event_projection_locators(event_id,schema_name,schema_version,"
                "logical_key,canonical_payload_digest,redaction_target_event_ids,"
                "redaction_target_object_ids) VALUES(?,?,?,?,?,?,?)",
                (
                    record.event_id,
                    record.schema.name,
                    record.schema.version,
                    locator.logical_key,
                    locator.canonical_payload_digest,
                    canonical_encode(locator.redaction_target_event_ids),
                    canonical_encode(locator.redaction_target_object_ids),
                ),
            )
            self._db.executemany(
                "INSERT INTO event_parents(child_event_id,parent_event_id) VALUES(?,?)",
                ((record.event_id, parent) for parent in record.causal_parents),
            )
            refs: list[tuple[str, str, str]] = [
                (record.event_id, "artifact", value) for value in record.artifact_refs
            ]
            refs.extend(
                (record.event_id, "evidence" if value.startswith("evd_") else "result", value)
                for value in record.evidence_refs
            )
            if refs:
                self._db.executemany(
                    "INSERT INTO event_refs(event_id,ref_type,target_id) VALUES(?,?,?)", refs
                )
        final = records[-1]
        self._db.execute(
            "UPDATE counters SET next_value=? WHERE name='ingestion_sequence'",
            (final.ledger.ingestion_sequence + 1,),
        )
        self._db.execute(
            "UPDATE writers SET next_writer_seq=?,head_entry_digest=? WHERE writer_id=?",
            (final.writer.sequence + 1, final.entry_digest, command.writer_id),
        )
        operation = build_append_operation_record(
            command, result, datetime.fromisoformat(now.replace("Z", "+00:00"))
        )
        locator = operation.result_locator
        assert operation.result_canonical is not None and operation.result_digest is not None
        assert operation.terminal_at is not None and locator is not None
        if locator.result_object_ref is not None:
            self._inventory_object(locator.result_object_ref)
        self._db.execute(
            "INSERT INTO operations(writer_id,operation_id,operation_kind,request_digest,"
            "resume_object_id,state,phase,owner_generation,lease_owner_id,lease_generation,"
            "lease_expires_at,first_ingestion_seq,last_ingestion_seq,result_canonical,"
            "result_digest,result_object_id,quarantine_code,terminal_at,created_at,updated_at) "
            "VALUES(?,?,?,?,NULL,'complete','terminal',NULL,NULL,NULL,NULL,?,?,?,?,?,NULL,?,?,?)",
            (
                command.writer_id,
                command.operation_id,
                command.operation_kind.value,
                command.request_digest,
                locator.first_ingestion_sequence,
                locator.last_ingestion_sequence,
                operation.result_canonical,
                operation.result_digest,
                None if locator.result_object_ref is None else locator.result_object_ref.object_id,
                format_rfc3339_millis(operation.terminal_at),
                now,
                now,
            ),
        )
        projection = self._state.projection
        self._db.execute(
            "UPDATE projection_state SET applied_through_seq=?,state_digest=? "
            "WHERE projection_name='work'",
            (projection.frontier, projection_digest(projection)),
        )
        # Status coverage is the applicable-check fold, not the last event's envelope
        # (engine-derived check/receipt envelopes hardcode check_types=none). Always mirror
        # latest_tested_state too — including clearing it when redaction drops the check.
        self._db.execute(
            "UPDATE p1_projection_state SET frontier_seq=?,head_digest=?,"
            "open_obligation_count=?,unresolved_finding_count=?,freshness=?,"
            "unknown_event_count=?,task_title_source_event_id=?,"
            "status_coverage_canonical=?,status_gap_codes_canonical=?,"
            "latest_check_event_id=?,latest_subject_frontier_seq=?,"
            "latest_subject_frontier_digest=?,latest_verdict=?,"
            "latest_returned_finding_ids=?,latest_suppressed_count=?,"
            "latest_coverage_canonical=? "
            "WHERE projection_name='work'",
            (
                projection.frontier,
                projection.head_digest,
                len(projection.obligations),
                unanswered_finding_count(projection, self._state.records),
                projection.freshness.value,
                projection.unknown_event_count,
                records[0].event_id,
                canonical_encode(
                    coverage_to_json(compact_status_coverage(self._state.records, projection))
                ),
                canonical_encode(projection.coverage_gaps),
                *_latest_check_column_values(projection),
            ),
        )

    def _persist_derived_records(self, records: tuple[LedgerRecord, ...]) -> None:
        """Persist already-reduced engine records inside the final check transaction."""

        if not records:
            return
        self._verify_owner()
        head = _head(self._db)
        if (
            records[0].ledger.ingestion_sequence != head.sequence + 1
            or records[0].ledger.previous_entry_digest != head.head_digest
        ):
            raise _frontier_conflict(head)
        for record in records:
            ref = self._state.object_refs.get(record.payload_ref.object_id)
            if ref is None:
                raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
            self._inventory_object(ref)
            status = "unknown_unprojected" if type(record) is UnknownEvent else "projected"
            summary = "opaque_unknown" if type(record) is UnknownEvent else record.schema.name
            self._db.execute(
                "INSERT INTO events(ingestion_seq,event_id,task_id,session_id,schema_name,"
                "schema_version,projection_status,summary_code,author_id,author_type,"
                "author_assurance,writer_id,writer_seq,operation_id,previous_ledger_digest,"
                "previous_writer_digest,entry_digest,canonical_entry,payload_object_id,"
                "payload_commitment,publication_channel,redaction_state,occurred_at,accepted_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.ledger.ingestion_sequence,
                    record.event_id,
                    record.task_id,
                    record.session_id,
                    record.schema.name,
                    record.schema.version,
                    status,
                    summary,
                    record.author.actor_id,
                    record.author.actor_type.value,
                    record.author.assurance.value,
                    record.writer.writer_id,
                    record.writer.sequence,
                    record.operation_id,
                    record.ledger.previous_entry_digest,
                    record.writer.previous_entry_digest,
                    record.entry_digest,
                    canonical_encode(accepted_record_to_json(record)),
                    record.payload_ref.object_id,
                    record.payload_ref.commitment,
                    record.publication_channel.value,
                    record.redaction.value,
                    record.occurred_at.wire,
                    record.ledger.accepted_at.wire,
                ),
            )
            locator = record.projection_locator
            self._db.execute(
                "INSERT INTO event_projection_locators(event_id,schema_name,schema_version,"
                "logical_key,canonical_payload_digest,redaction_target_event_ids,"
                "redaction_target_object_ids) VALUES(?,?,?,?,?,?,?)",
                (
                    record.event_id,
                    record.schema.name,
                    record.schema.version,
                    locator.logical_key,
                    locator.canonical_payload_digest,
                    canonical_encode(locator.redaction_target_event_ids),
                    canonical_encode(locator.redaction_target_object_ids),
                ),
            )
            if record.causal_parents:
                self._db.executemany(
                    "INSERT INTO event_parents(child_event_id,parent_event_id) VALUES(?,?)",
                    ((record.event_id, parent) for parent in record.causal_parents),
                )
            refs: list[tuple[str, str, str]] = [
                (record.event_id, "artifact", value) for value in record.artifact_refs
            ]
            refs.extend(
                (record.event_id, "evidence" if value.startswith("evd_") else "result", value)
                for value in record.evidence_refs
            )
            if refs:
                self._db.executemany(
                    "INSERT INTO event_refs(event_id,ref_type,target_id) VALUES(?,?,?)", refs
                )
        final = records[-1]
        self._db.execute(
            "UPDATE counters SET next_value=? WHERE name='ingestion_sequence'",
            (final.ledger.ingestion_sequence + 1,),
        )
        self._db.execute(
            "UPDATE writers SET next_writer_seq=?,head_entry_digest=? WHERE writer_id=?",
            (final.writer.sequence + 1, final.entry_digest, final.writer.writer_id),
        )
        projection = self._state.projection
        self._db.execute(
            "UPDATE projection_state SET applied_through_seq=?,state_digest=? "
            "WHERE projection_name='work'",
            (projection.frontier, projection_digest(projection)),
        )
        # Mirror the reducer's applicable-check coverage and latest-check aggregate, never
        # the last event envelope. When latest_tested_state is absent, clear the seven
        # latest_* columns atomically so a redacted check cannot survive restart.
        self._db.execute(
            "UPDATE p1_projection_state SET frontier_seq=?,head_digest=?,"
            "open_obligation_count=?,unresolved_finding_count=?,freshness=?,"
            "unknown_event_count=?,status_coverage_canonical=?,status_gap_codes_canonical=?,"
            "latest_check_event_id=?,latest_subject_frontier_seq=?,"
            "latest_subject_frontier_digest=?,latest_verdict=?,"
            "latest_returned_finding_ids=?,latest_suppressed_count=?,"
            "latest_coverage_canonical=? "
            "WHERE projection_name='work'",
            (
                projection.frontier,
                projection.head_digest,
                len(projection.obligations),
                unanswered_finding_count(projection, self._state.records),
                projection.freshness.value,
                projection.unknown_event_count,
                canonical_encode(
                    coverage_to_json(compact_status_coverage(self._state.records, projection))
                ),
                canonical_encode(projection.coverage_gaps),
                *_latest_check_column_values(projection),
            ),
        )

    async def append_batch(self, command: AppendCommand) -> AppendResult:
        await self._ensure_recovered()
        async with self._lock:
            durable_writer = self._db.execute(
                "SELECT next_writer_seq,head_entry_digest FROM writers WHERE writer_id=?",
                (command.writer_id,),
            ).fetchone()
            cached_writer = self._state.writers.get(command.writer_id)
            if durable_writer is not None and (
                cached_writer is None
                or durable_writer != (cached_writer.next_sequence, cached_writer.head_digest)
            ):
                raise _public_error(PublicErrorCode.EVENT_INVALID)
            existing = _operation_digest_row(self._db, command.writer_id, command.operation_id)
            if existing is not None:
                digest, state = existing
                if digest != command.request_digest:
                    raise _public_error(PublicErrorCode.IDEMPOTENCY_CONFLICT)
                cached = self._state.operations.get((command.writer_id, command.operation_id))
                if state == "complete" and cached is not None and cached[1] is not None:
                    return replace(cached[1], outcome="replayed")
                raise _public_error(PublicErrorCode.STORAGE_CORRUPT)

            importer = any(
                row.publication_channel.value == "codex_jsonl_import" for row in command.entries
            )
            reservation: _Reservation | None = None
            if importer:
                reservation = _import_reservation(self._db, command)
            if command.operation_kind.value == "receipt":
                pending = self._db.execute(
                    "SELECT 1 FROM import_jobs WHERE session_id=? AND state='pending' LIMIT 1",
                    (command.session_id,),
                ).fetchone()
                if pending is not None:
                    raise _public_error(PublicErrorCode.OPERATION_PENDING, retryable=True)

            clone = self._clone_state()
            shim = _SqliteImportShim()
            shim.reservation = reservation
            oracle = MemoryLedgerAdapter(
                task_id=self._task_id,
                ownership_fence=self._fence,
                state=clone,
                import_state=shim,
                transaction_lock=asyncio.Lock(),
                clock=self._clock,
                ids=self._ids,
                objects=self._objects,
            )
            result = await oracle.append_batch(command)
            new_records = clone.records[len(self._state.records) :]
            prior_state = self._state
            try:
                self._db.execute("BEGIN IMMEDIATE")
                if (
                    _operation_digest_row(self._db, command.writer_id, command.operation_id)
                    is not None
                ):
                    raise _public_error(PublicErrorCode.IDEMPOTENCY_CONFLICT)
                if importer:
                    _import_reservation(self._db, command)
                if (
                    command.operation_kind.value == "receipt"
                    and self._db.execute(
                        "SELECT 1 FROM import_jobs WHERE session_id=? AND state='pending' LIMIT 1",
                        (command.session_id,),
                    ).fetchone()
                    is not None
                ):
                    raise _public_error(PublicErrorCode.OPERATION_PENDING, retryable=True)
                self._state = clone
                self._persist_append(command, result, new_records)
                self._db.execute("COMMIT")
            except BaseException:
                self._state = prior_state
                if self._db.get_autocommit() is False:
                    self._db.execute("ROLLBACK")
                raise
            self._adopt_state(prior_state, clone)
            self._state = prior_state
            return result

    async def _load_events_recovered(
        self, session_id: str, *, after: int, through: int | None
    ) -> AsyncIterator[LedgerRecord]:
        await self._ensure_recovered()
        async for record in self._oracle().load_events(session_id, after=after, through=through):
            yield record

    def load_events(
        self, session_id: str, *, after: int = 0, through: int | None = None
    ) -> AsyncIterator[LedgerRecord]:
        return self._load_events_recovered(session_id, after=after, through=through)

    def _oracle(self, *, transaction_lock: asyncio.Lock | None = None) -> MemoryLedgerAdapter:
        return MemoryLedgerAdapter(
            task_id=self._task_id,
            ownership_fence=self._fence,
            state=self._state,
            import_state=_SqliteImportShim(),
            transaction_lock=self._lock if transaction_lock is None else transaction_lock,
            clock=self._clock,
            ids=self._ids,
            objects=self._objects,
        )

    def _clone_state(self) -> MemoryLedgerState:
        """Copy the oracle state so a failed SQLite sync cannot leak an in-memory commit."""

        return MemoryLedgerState(
            records=self._state.records,
            operations=dict(self._state.operations),
            writers=dict(self._state.writers),
            projection=self._state.projection,
            trusted_projections=self._state.trusted_projections,
            case_dependency_digests=self._state.case_dependency_digests,
            frozen_cases=dict(self._state.frozen_cases),
            check_results=dict(self._state.check_results),
            check_errors=dict(self._state.check_errors),
            jobs=dict(self._state.jobs),
            job_by_case=dict(self._state.job_by_case),
            attempts=dict(self._state.attempts),
            disclosure_waits=dict(self._state.disclosure_waits),
            object_refs=dict(self._state.object_refs),
            check_reservations=dict(self._state.check_reservations),
        )

    @staticmethod
    def _freeze_state_snapshot(state: MemoryLedgerState) -> tuple[object, ...]:
        """Capture every durable state component that a staged freeze could overwrite.

        The acquisition lock is intentionally released while the resume object is staged.  A
        records-only comparison is insufficient during that window: AI-powered review lifecycle writes
        can advance operations, jobs, attempts, or object inventory without adding a ledger
        record.  Copy each mutable map so in-place mutations on the stable state object remain
        visible to the final compare.  Transient check reservations are merged separately because
        another acquisition may legitimately arm one while this case is staging.
        """

        return (
            state.records,
            dict(state.operations),
            dict(state.writers),
            state.projection,
            dict(state.frozen_cases),
            dict(state.check_results),
            dict(state.check_errors),
            dict(state.jobs),
            dict(state.job_by_case),
            dict(state.attempts),
            dict(state.disclosure_waits),
            dict(state.object_refs),
        )

    @staticmethod
    def _adopt_state(target: MemoryLedgerState, source: MemoryLedgerState) -> None:
        """Adopt a durable clone without invalidating in-flight oracle state references."""

        target.records = source.records
        target.operations = source.operations
        target.writers = source.writers
        target.projection = source.projection
        target.frozen_cases = source.frozen_cases
        target.check_results = source.check_results
        target.check_errors = source.check_errors
        target.jobs = source.jobs
        target.job_by_case = source.job_by_case
        target.attempts = source.attempts
        target.disclosure_waits = source.disclosure_waits
        target.object_refs = source.object_refs
        target.check_reservations = source.check_reservations

    def _sync_clone_locked(
        self,
        prior: MemoryLedgerState,
        clone: MemoryLedgerState,
        new_records: tuple[LedgerRecord, ...] = (),
    ) -> None:
        """Persist one clone, then update the stable state object only after commit."""

        self._state = clone
        try:
            self._sync_after_mutation_locked(new_records)
        except BaseException:
            self._state = prior
            raise
        self._adopt_state(prior, clone)
        self._state = prior

    def _sync_after_mutation_locked(
        self,
        new_records: tuple[LedgerRecord, ...] = (),
        *,
        pending_capture_task_id: str | None = None,
    ) -> None:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute("PRAGMA defer_foreign_keys=ON")
            self._verify_owner()
            if pending_capture_task_id is not None:
                pending_capture = self._pending_capture_ticket(pending_capture_task_id)
                if pending_capture is not None:
                    # Only a new check's admission passes this task id: the handoff that landed
                    # while it staged must be in any frozen case, so admission waits for it.
                    raise check_admission_refused(CheckAdmissionStage.CAPTURE_HANDOFF_PENDING)
            self._persist_derived_records(new_records)
            self._sync_runtime_state()
            self._db.execute("COMMIT")
        except BaseException:
            if self._db.get_autocommit() is False:
                self._db.execute("ROLLBACK")
            raise

    async def _sync_after_mutation(
        self,
        new_records: tuple[LedgerRecord, ...] = (),
        *,
        pending_capture_task_id: str | None = None,
    ) -> None:
        async with self._lock:
            self._sync_after_mutation_locked(
                new_records,
                pending_capture_task_id=pending_capture_task_id,
            )

    async def load_trusted_projection(
        self, session_id: str, frontier: Frontier
    ) -> ProjectionState | None:
        await self._ensure_recovered()
        return await self._oracle().load_trusted_projection(session_id, frontier)

    async def load_projection(
        self, session_id: str, view: ProjectionView
    ) -> StoredProjection | None:
        await self._ensure_recovered()
        return await self._oracle().load_projection(session_id, view)

    async def load_frontier(self) -> Frontier:
        await self._ensure_recovered()
        return await self._oracle().load_frontier()

    async def load_case_availability(
        self, session_id: str, frontier: Frontier, projection: ProjectionState
    ) -> CaseAvailabilityFacts:
        await self._ensure_recovered()
        self._refresh_native_capture_refs(projection)
        return await self._oracle().load_case_availability(session_id, frontier, projection)

    def _refresh_native_capture_refs(self, projection: ProjectionState) -> None:
        """Rehydrate only live referenced native captures inventoried by observation.

        Observation persists its encrypted objects independently of ledger payload objects.
        Their descriptors must enter the oracle's availability snapshot after recovery too.
        This restores descriptors only: the oracle still authenticates physical bytes before
        declaring availability, and redacted/missing objects never earn readable coverage.
        """
        for record in projection.evidence.values():
            payload = record.payload
            if (
                payload is None
                or payload.captured_object_id is None
                or payload.digest_binding is None
                or payload.digest_binding.provenance
                is not EvidenceDigestProvenance.OBSERVATION_CAPTURED
                or not record.object_available
            ):
                continue
            captured_id = payload.captured_object_id
            self._state.object_refs.pop(captured_id, None)
            row = self._db.execute(
                "SELECT 1 FROM observation_content_manifests AS manifests "
                "JOIN objects ON objects.object_id=manifests.object_id "
                "WHERE manifests.object_id=? AND manifests.content_digest=? "
                "AND manifests.content_bytes=? AND objects.state='present' "
                "AND objects.kind='captured_content'",
                (captured_id, payload.content_digest, payload.digest_binding.byte_count),
            ).fetchone()
            if row is None:
                continue
            self._state.object_refs[captured_id] = self._object_ref_from_inventory(
                captured_id,
                self._task_id,
                "application/vnd.yoetz.observation-content+json",
            )

    async def query_projection(self, query: ProjectionQuery) -> ProjectionPage:
        await self._ensure_recovered()
        return await self._oracle().query_projection(query)

    async def lookup_operation(self, writer_id: str, operation_id: str) -> OperationRecord | None:
        await self._ensure_recovered()
        return await self._oracle().lookup_operation(writer_id, operation_id)

    async def projected_action_event(self, action: str) -> str | None:
        """Return the event that records one action in the current task projection (#917)."""

        await self._ensure_recovered()
        return await self._oracle().projected_action_event(action)

    async def lookup_task_operation(
        self, writer_id: str, operation_id: str
    ) -> OperationRecord | None:
        await self._ensure_recovered()
        return await self._oracle().lookup_task_operation(writer_id, operation_id)

    async def has_active_frozen_case(self, session_id: str) -> bool:
        await self._ensure_recovered()
        return await self._oracle().has_active_frozen_case(session_id)

    async def reclaim_operation(
        self, writer_id: str, operation_id: str, request_digest: str
    ) -> OperationLease | PendingVerdict:
        await self._ensure_recovered()
        async with self._lock:
            prior = self._state
            clone = self._clone_state()
            oracle = MemoryLedgerAdapter(
                task_id=self._task_id,
                ownership_fence=self._fence,
                state=clone,
                import_state=_SqliteImportShim(),
                transaction_lock=asyncio.Lock(),
                clock=self._clock,
                ids=self._ids,
                objects=self._objects,
            )
            result = await oracle.reclaim_operation(writer_id, operation_id, request_digest)
            if type(result) is OperationLease:
                self._sync_clone_locked(prior, clone)
            return result

    async def freeze_case(
        self,
        session_id: str,
        writer_id: str,
        expected_frontier: int | None,
        request_id: str,
        request_digest: str,
    ) -> FrozenCase | CheckCommitResult:
        key = (writer_id, request_id)
        try:
            result = await self._freeze_case_unrecorded(
                session_id, writer_id, expected_frontier, request_id, request_digest
            )
        except PublicOperationError as exc:
            stage = check_admission_stage(exc)
            if stage is not None:
                # No await separates this from the refusal, so the stable live state is current;
                # the oracle's own note landed in its discarded clone.
                note_check_admission_refusal(self._state, key, stage, self._terminal_at())
            raise
        self._state.check_admissions.pop(key, None)
        return result

    async def lookup_check_admission(
        self, writer_id: str, operation_id: str
    ) -> CheckAdmissionRecord | None:
        await self._ensure_recovered()
        async with self._lock:
            return check_admission_record(
                self._state, (writer_id, operation_id), self._terminal_at()
            )

    def _merge_freeze_over_lifecycle_motion(
        self,
        current: MemoryLedgerState,
        baseline: tuple[object, ...],
        staged: MemoryLedgerState,
        operation_key: tuple[str, str],
    ) -> MemoryLedgerState | None:
        """Carry one acquisition's own delta over lifecycle writes that moved no ledger record.

        Staging releases the repository lock, so another check's lease renewal, phase advance,
        or AI-powered review bookkeeping may commit meanwhile. None of that can change this case:
        it was built from the unchanged record prefix, projection, writers, and object inventory.
        Adopting the staged clone wholesale would overwrite those writes, and discarding the
        admission turned them into a no-record ``OPERATION_PENDING`` (issue #838). Only this
        key's operation row and frozen case move; any change to the case's own inputs or to this
        key refuses as contended instead.
        """

        (
            _records,
            operations,
            writers,
            projection,
            frozen_cases,
            check_results,
            check_errors,
            *_rest,
        ) = baseline
        operations_before = cast(dict[tuple[str, str], object], operations)
        frozen_before = cast(dict[tuple[str, str], object], frozen_cases)
        results_before = cast(dict[tuple[str, str], object], check_results)
        errors_before = cast(dict[tuple[str, str], object], check_errors)
        object_refs_before = baseline[11]
        if (
            current.projection is not projection
            or current.writers != writers
            or current.object_refs != object_refs_before
            or current.operations.get(operation_key) is not operations_before.get(operation_key)
            or current.frozen_cases.get(operation_key) is not frozen_before.get(operation_key)
            or current.check_results.get(operation_key) is not results_before.get(operation_key)
            or current.check_errors.get(operation_key) is not errors_before.get(operation_key)
        ):
            return None
        admitted = staged.operations.get(operation_key)
        case = staged.frozen_cases.get(operation_key)
        if admitted is None or case is None:
            return None
        merged = self._clone_state()
        merged.operations[operation_key] = admitted
        merged.frozen_cases[operation_key] = case
        return merged

    async def _freeze_case_unrecorded(
        self,
        session_id: str,
        writer_id: str,
        expected_frontier: int | None,
        request_id: str,
        request_digest: str,
    ) -> FrozenCase | CheckCommitResult:
        await self._ensure_recovered()
        async with self._lock:
            operation_key = (writer_id, request_id)
            existing_operation = self._state.operations.get(operation_key)
            new_freeze = existing_operation is None
            prior = self._state
            self._refresh_native_capture_refs(prior.projection)
            baseline = self._freeze_state_snapshot(prior)
            clone = self._clone_state()
            reservation: _FreezeReservation | None = None
            if new_freeze:
                pending_capture = self._pending_capture_ticket(self._task_id)
                if pending_capture is not None:
                    raise check_admission_refused(CheckAdmissionStage.CAPTURE_HANDOFF_PENDING)
                now = self._terminal_at()
                reservations = cast(dict[tuple[str, str], object], prior.check_reservations)
                existing_reservation = reservations.get(operation_key)
                if existing_reservation is not None and not isinstance(
                    existing_reservation, _FreezeReservation
                ):
                    raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
                if existing_reservation is not None and existing_reservation.expires_at > now:
                    raise check_admission_refused(CheckAdmissionStage.ACQUIRING)

                # Install the transient barrier in the live state before releasing the repository
                # lock.  The clone deliberately precedes this write: the oracle must create its
                # own reservation and later remove it, while concurrent append calls inspect the
                # live reservation and either defer observation or advance the real frontier.
                reservation = _FreezeReservation(
                    session_id, now + timedelta(seconds=CHECK_ACQUISITION_RESERVATION_SECONDS)
                )
                reservations[operation_key] = reservation

        try:
            # Object staging is an awaitable boundary.  It must not retain the shared repository
            # lock: observation append needs to see the reservation, and an agent append must be
            # allowed to advance the frontier so final revalidation can return FRONTIER_CONFLICT.
            oracle = MemoryLedgerAdapter(
                task_id=self._task_id,
                ownership_fence=self._fence,
                state=clone,
                import_state=_SqliteImportShim(),
                transaction_lock=asyncio.Lock(),
                clock=self._clock,
                ids=self._ids,
                objects=self._objects,
            )
            result = await oracle.freeze_case(
                session_id, writer_id, expected_frontier, request_id, request_digest
            )
            async with self._lock:
                current = self._state
                reservations = cast(dict[tuple[str, str], object], current.check_reservations)
                if reservation is not None and reservations.get(operation_key) is not reservation:
                    # This acquisition stalled past its reservation. A successor holding the key
                    # is still acquiring; otherwise nothing durable was staged under it.
                    raise check_admission_refused(
                        CheckAdmissionStage.ACQUIRING
                        if reservations.get(operation_key) is not None
                        else CheckAdmissionStage.ACQUISITION_CONTENDED
                    )

                if type(result) is not FrozenCase:
                    # A completed same-request replay is immutable and changed no state, so
                    # concurrent motion cannot invalidate it.
                    if reservation is not None and reservations.get(operation_key) is reservation:
                        reservations.pop(operation_key, None)
                    return result

                if self._freeze_state_snapshot(current) != baseline:
                    # An append moved the ledger head, so retain the adapter-parity conflict
                    # details. Other concurrent lifecycle mutations do not change the event
                    # frontier and must not be misreported as one.
                    if current.records is not baseline[0]:
                        if (
                            reservation is not None
                            and reservations.get(operation_key) is reservation
                        ):
                            reservations.pop(operation_key, None)
                        raise _frontier_conflict(
                            Frontier(current.projection.frontier, current.projection.head_digest)
                        )
                    merged = self._merge_freeze_over_lifecycle_motion(
                        current, baseline, clone, operation_key
                    )
                    if merged is None:
                        if (
                            reservation is not None
                            and reservations.get(operation_key) is reservation
                        ):
                            reservations.pop(operation_key, None)
                        raise check_admission_refused(CheckAdmissionStage.ACQUISITION_CONTENDED)
                    clone = merged

                # Keep reservations installed by another acquisition while adopting the durable
                # clone. The local token is removed only by its owner, and this merge also avoids
                # replacing a concurrently armed barrier with the clone's stale copy.
                clone.check_reservations = cast(Any, dict(reservations))
                if reservation is not None:
                    clone.check_reservations.pop(operation_key, None)
                try:
                    self._state = clone
                    self._sync_after_mutation_locked(
                        pending_capture_task_id=self._task_id if new_freeze else None,
                    )
                except BaseException:
                    if reservation is not None and reservations.get(operation_key) is reservation:
                        reservations.pop(operation_key, None)
                    self._state = current
                    raise
                self._adopt_state(current, clone)
                self._state = current
                return result
        except BaseException:
            if reservation is not None:
                async with self._lock:
                    reservations = cast(
                        dict[tuple[str, str], object], self._state.check_reservations
                    )
                    if reservations.get(operation_key) is reservation:
                        reservations.pop(operation_key, None)
            raise

    async def advance_check_phase(
        self,
        lease: OperationLease,
        expected_phase: CheckPhase,
        next_phase: CheckPhase,
        durable_object_ref: ObjectRef | None = None,
    ) -> OperationLease:
        await self._ensure_recovered()
        result = await self._oracle().advance_check_phase(
            lease, expected_phase, next_phase, durable_object_ref
        )
        await self._sync_after_mutation()
        return result

    async def enqueue_semantic_job(
        self, lease: OperationLease, case_digest: str, case_object_ref: ObjectRef
    ) -> SemanticJobRecord:
        await self._ensure_recovered()
        result = await self._oracle().enqueue_semantic_job(lease, case_digest, case_object_ref)
        await self._sync_after_mutation()
        return result

    async def suspend_check_for_repository_grant(self, lease: OperationLease) -> None:
        await self._ensure_recovered()
        await self._oracle().suspend_check_for_repository_grant(lease)
        await self._sync_after_mutation()

    async def suspend_check_for_review_input(self, lease: OperationLease) -> None:
        await self._ensure_recovered()
        await self._oracle().suspend_check_for_review_input(lease)
        await self._sync_after_mutation()

    async def claim_semantic_job(self, lease: OperationLease, job_id: str) -> SemanticAttemptHandle:
        await self._ensure_recovered()
        result = await self._oracle().claim_semantic_job(lease, job_id)
        await self._sync_after_mutation()
        return result

    async def record_attempt_outcome(
        self,
        handle: SemanticAttemptHandle,
        outcome: AttemptOutcome,
        result_object_ref: ObjectRef | None = None,
        terminal_code: SemanticReason | None = None,
        token_usage: RuntimeTokenUsage | None = None,
    ) -> None:
        await self._ensure_recovered()
        await self._oracle().record_attempt_outcome(
            handle, outcome, result_object_ref, terminal_code, token_usage
        )
        await self._sync_after_mutation()

    async def fail_semantic_job(
        self,
        lease: OperationLease,
        job_id: str,
        terminal_code: SemanticReason,
    ) -> SemanticJobRecord:
        await self._ensure_recovered()
        result = await self._oracle().fail_semantic_job(lease, job_id, terminal_code)
        await self._sync_after_mutation()
        return result

    async def select_attempt(
        self,
        lease: OperationLease,
        handle: SemanticAttemptHandle,
        selected_result_object_ref: ObjectRef,
    ) -> SelectedAttempt:
        await self._ensure_recovered()
        result = await self._oracle().select_attempt(lease, handle, selected_result_object_ref)
        await self._sync_after_mutation()
        return result

    async def load_semantic_job(
        self, writer_id: str, operation_id: str
    ) -> SemanticJobRecord | None:
        await self._ensure_recovered()
        return await self._oracle().load_semantic_job(writer_id, operation_id)

    async def list_semantic_attempts(self, job_id: str) -> tuple[SemanticAttemptRecord, ...]:
        await self._ensure_recovered()
        return await self._oracle().list_semantic_attempts(job_id)

    async def record_disclosure_wait(
        self,
        handle: SemanticAttemptHandle,
        pending_id: str,
        pending_expires_at: datetime,
    ) -> SemanticDisclosureWait:
        await self._ensure_recovered()
        result = await self._oracle().record_disclosure_wait(handle, pending_id, pending_expires_at)
        await self._sync_after_mutation()
        return result

    async def load_disclosure_wait(
        self, writer_id: str, operation_id: str
    ) -> SemanticDisclosureWait | None:
        await self._ensure_recovered()
        return await self._oracle().load_disclosure_wait(writer_id, operation_id)

    async def resolve_disclosure_wait(self, job_id: str) -> SemanticDisclosureWait:
        await self._ensure_recovered()
        result = await self._oracle().resolve_disclosure_wait(job_id)
        await self._sync_after_mutation()
        return result

    def _progress_write_locked(self, statement: str, parameters: tuple[str | int, ...]) -> int:
        """Run one progress statement in its own owner-fenced write transaction."""

        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._verify_owner()
            self._db.execute(statement, parameters)
            changed = self._db.changes()
            self._db.execute("COMMIT")
        except BaseException:
            if self._db.get_autocommit() is False:
                self._db.execute("ROLLBACK")
            raise
        return changed

    async def begin_semantic_progress(
        self, job_id: str, queued_at: datetime, deadline_at: datetime
    ) -> None:
        # Validates identifiers and exact-millisecond UTC before any SQL runs.
        SemanticProgressRecord(
            job_id, 0, SemanticProgressPhase.QUEUED, queued_at, queued_at, deadline_at
        )
        await self._ensure_recovered()
        queued = format_rfc3339_millis(queued_at)
        async with self._lock:
            # Progress rows are written directly rather than through the in-memory oracle: they
            # are telemetry beside the job, and a completed operation's job is not reloaded into
            # the oracle after restart, yet its terminal progress must stay readable.
            self._progress_write_locked(
                "INSERT INTO semantic_progress(job_id,attempt_ordinal,phase,phase_rank,"
                "phase_entered_at,queued_at,deadline_at) "
                "SELECT ?,0,'queued',1,?,?,? WHERE EXISTS ("
                "SELECT 1 FROM semantic_jobs WHERE job_id=? AND state IN ('queued','leased')) "
                "ON CONFLICT(job_id) DO NOTHING",
                (job_id, queued, queued, format_rfc3339_millis(deadline_at), job_id),
            )

    async def advance_semantic_progress(
        self,
        handle: SemanticAttemptHandle,
        phase: SemanticProgressPhase,
        observed_at: datetime,
    ) -> bool:
        if (
            type(handle) is not SemanticAttemptHandle
            or type(phase) is not SemanticProgressPhase
            or phase is SemanticProgressPhase.TERMINAL
        ):
            raise _public_error(PublicErrorCode.INVALID_REQUEST)
        observed = format_rfc3339_millis(observed_at)
        rank = SEMANTIC_PROGRESS_PHASE_RANK[phase]
        await self._ensure_recovered()
        async with self._lock:
            changed = self._progress_write_locked(
                "UPDATE semantic_progress SET attempt_ordinal=?,phase=?,phase_rank=?,"
                "phase_entered_at=max(phase_entered_at,?) "
                "WHERE job_id=? AND (attempt_ordinal<? OR (attempt_ordinal=? AND phase_rank<?)) "
                "AND EXISTS (SELECT 1 FROM semantic_jobs WHERE job_id=? AND state='leased' "
                "AND active_attempt_id=?)",
                (
                    handle.attempt_ordinal,
                    phase.value,
                    rank,
                    observed,
                    handle.job_id,
                    handle.attempt_ordinal,
                    handle.attempt_ordinal,
                    rank,
                    handle.job_id,
                    handle.attempt_id,
                ),
            )
        return changed == 1

    async def load_semantic_progress(
        self, writer_id: str, operation_id: str
    ) -> SemanticProgressRecord | None:
        await self._ensure_recovered()
        async with self._lock:
            row = self._db.execute(
                "SELECT progress.job_id,progress.attempt_ordinal,progress.phase,"
                "progress.phase_entered_at,progress.queued_at,progress.deadline_at,"
                "jobs.state,jobs.terminal_code,jobs.terminal_at "
                "FROM semantic_jobs AS jobs JOIN semantic_progress AS progress "
                "ON progress.job_id=jobs.job_id "
                "WHERE jobs.writer_id=? AND jobs.operation_id=? "
                "ORDER BY jobs.attempt_count DESC, jobs.job_id DESC LIMIT 1",
                (writer_id, operation_id),
            ).fetchone()
        if row is None:
            return None
        (
            job_value,
            ordinal,
            phase_value,
            entered,
            queued,
            deadline,
            job_state,
            terminal_code,
            terminal_at,
        ) = row
        try:
            entered_at = parse_rfc3339_millis(cast(str, entered))
            if job_state in {"queued", "leased"}:
                return SemanticProgressRecord(
                    cast(str, job_value),
                    cast(int, ordinal),
                    SemanticProgressPhase(cast(str, phase_value)),
                    entered_at,
                    parse_rfc3339_millis(cast(str, queued)),
                    parse_rfc3339_millis(cast(str, deadline)),
                )
            ended_at = parse_rfc3339_millis(cast(str, terminal_at))
            return SemanticProgressRecord(
                cast(str, job_value),
                cast(int, ordinal),
                SemanticProgressPhase.TERMINAL,
                max(ended_at, entered_at),
                parse_rfc3339_millis(cast(str, queued)),
                parse_rfc3339_millis(cast(str, deadline)),
                cast(Literal["succeeded", "failed", "quarantined"], job_state),
                SemanticReason(cast(str, terminal_code)),
            )
        except (TypeError, ValueError) as exc:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc

    async def record_task_change_base(self, ref: ObjectRef) -> bool:
        """Keep the task-start base object (ADR-031) as a durable root, once per task.

        The pointer lives in ``bundle_meta`` beside the bundle's other identity facts and the
        object joins the inventory, so orphan sweeps and backups keep it. A second call keeps the
        first base: the base is the state when the task was created, never a later one.
        """

        if (
            type(ref) is not ObjectRef
            or ref.metadata.kind is not ObjectKind.CHANGE_CAPTURE
            or ref.metadata.media_type != TASK_CHANGE_BASE_MEDIA_TYPE
            or ref.metadata.task_id != self._task_id
        ):
            raise ValueError("task_change_base_invalid")
        pointer = canonical_encode(
            {
                "commitment": ref.commitment,
                "envelope_digest": ref.envelope_digest,
                "object_id": ref.object_id,
            }
        ).decode("ascii")
        await self._ensure_recovered()
        async with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._verify_owner()
                existing = self._db.execute(
                    "SELECT 1 FROM bundle_meta WHERE key=?", (_TASK_CHANGE_BASE_META_KEY,)
                ).fetchone()
                if existing is None:
                    self._inventory_object(ref)
                    self._db.execute(
                        "INSERT INTO bundle_meta(key, value) VALUES (?, ?)",
                        (_TASK_CHANGE_BASE_META_KEY, pointer),
                    )
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.get_autocommit() is False:
                    self._db.execute("ROLLBACK")
                raise
        return existing is None

    async def load_task_change_base(self) -> ObjectRef | None:
        """Return the authenticated task-start base object, or ``None`` when none was kept."""

        await self._ensure_recovered()
        objects = self._objects
        if objects is None:
            return None
        async with self._lock:
            row = self._db.execute(
                "SELECT value FROM bundle_meta WHERE key=?", (_TASK_CHANGE_BASE_META_KEY,)
            ).fetchone()
        if row is None:
            return None
        try:
            parsed = strict_json_parse(cast(str, row[0]).encode("ascii"))
            if type(parsed) is not dict:
                raise ValueError("task_change_base_pointer_invalid")
            pointer = cast(dict[str, object], parsed)
            if set(pointer) != {"commitment", "envelope_digest", "object_id"}:
                raise ValueError("task_change_base_pointer_invalid")
            ref = await objects.resolve_verified(
                cast(str, pointer["object_id"]), cast(str, pointer["envelope_digest"])
            )
            if (
                ref.commitment != pointer["commitment"]
                or ref.metadata.kind is not ObjectKind.CHANGE_CAPTURE
                or ref.metadata.task_id != self._task_id
            ):
                raise ValueError("task_change_base_pointer_invalid")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT) from exc
        return ref

    async def renew_leases(self, lease: OperationLease) -> OperationLease:
        await self._ensure_recovered()
        async with self._lock:
            prior = self._state
            clone = self._clone_state()
            oracle = MemoryLedgerAdapter(
                task_id=self._task_id,
                ownership_fence=self._fence,
                state=clone,
                import_state=_SqliteImportShim(),
                transaction_lock=asyncio.Lock(),
                clock=self._clock,
                ids=self._ids,
                objects=self._objects,
            )
            result = await oracle.renew_leases(lease)
            self._sync_clone_locked(prior, clone)
            return result

    async def commit_check_if_current(
        self,
        frozen: FrozenCase,
        findings: RankedFindings,
        policy_executions: tuple[CheckPolicyExecution, ...],
        semantic_status: SemanticStatus,
        semantic_reason: SemanticReason,
        semantic_provenance: SemanticProvenance | None,
        request_id: str,
        *,
        scope: CheckScopeModel | None = None,
        semantic_conclusion: str | None = None,
        review_summary: str | None = None,
        verified: tuple[JsonObject, ...] = (),
        prior_finding_verdicts: tuple[PriorFindingVerdictRecord, ...] = (),
        missing_for_assessment: tuple[MissingForAssessmentItem, ...] = (),
        check_change_files: CheckChangeShownFiles | None = None,
        semantic_included_refs: tuple[str, ...] | None = None,
        semantic_withheld_item_ids: tuple[str, ...] = (),
        review_input_manifest: JsonObject | None = None,
        totals: JsonObject | None = None,
        semantic_redacted_values: tuple[SemanticRedactedValue, ...] = (),
        semantic_route_required: bool | None = None,
    ) -> CheckCommitResult:
        await self._ensure_recovered()
        async with self._lock:
            prior = self._state
            clone = self._clone_state()
            oracle = MemoryLedgerAdapter(
                task_id=self._task_id,
                ownership_fence=self._fence,
                state=clone,
                import_state=_SqliteImportShim(),
                transaction_lock=asyncio.Lock(),
                clock=self._clock,
                ids=self._ids,
                objects=self._objects,
            )
            try:
                result = await oracle.commit_check_if_current(
                    frozen,
                    findings,
                    policy_executions,
                    semantic_status,
                    semantic_reason,
                    semantic_provenance,
                    request_id,
                    scope=scope,
                    semantic_conclusion=semantic_conclusion,
                    review_summary=review_summary,
                    verified=verified,
                    missing_for_assessment=missing_for_assessment,
                    prior_finding_verdicts=prior_finding_verdicts,
                    check_change_files=check_change_files,
                    semantic_included_refs=semantic_included_refs,
                    semantic_withheld_item_ids=semantic_withheld_item_ids,
                    review_input_manifest=review_input_manifest,
                    totals=totals,
                    semantic_redacted_values=semantic_redacted_values,
                    semantic_route_required=semantic_route_required,
                )
            except PublicOperationError:
                # The memory oracle terminalizes a frontier conflict before raising it. Preserve
                # that durable error transition just as the pre-clone implementation did.
                self._sync_clone_locked(prior, clone)
                raise
            new_records = clone.records[len(prior.records) :]
            self._sync_clone_locked(prior, clone, new_records)
            return result

    async def fail_check_if_current(
        self, lease: OperationLease, failure: PublicOperationError
    ) -> None:
        await self._ensure_recovered()
        async with self._lock:
            prior = self._state
            clone = self._clone_state()
            oracle = MemoryLedgerAdapter(
                task_id=self._task_id,
                ownership_fence=self._fence,
                state=clone,
                import_state=_SqliteImportShim(),
                transaction_lock=asyncio.Lock(),
                clock=self._clock,
                ids=self._ids,
                objects=self._objects,
            )
            await oracle.fail_check_if_current(lease, failure)
            self._sync_clone_locked(prior, clone)

    async def run_passive_checkpoint(self, wal_page_threshold: int) -> CheckpointReport:
        await self._ensure_recovered()
        if type(wal_page_threshold) is not int or wal_page_threshold < 1:
            raise _public_error(PublicErrorCode.INVALID_REQUEST)
        async with self._lock:
            self._verify_owner()
            journal_mode = self._db.pragma("journal_mode")
            filename = self._db.filename
            if journal_mode != "wal" or not filename:
                return CheckpointReport(0, 0, 0)
            page_size = self._db.pragma("page_size")
            if type(page_size) is not int or page_size < 1:
                raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
            wal_path = Path(f"{filename}-wal")
            try:
                wal_bytes = wal_path.stat().st_size
            except FileNotFoundError:
                return CheckpointReport(0, 0, 0)
            wal_pages = (wal_bytes + page_size - 1) // page_size
            if wal_pages < wal_page_threshold:
                return CheckpointReport(0, wal_pages, 0)
            row = self._db.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
        if row is None or len(row) != 3 or any(type(value) is not int for value in row):
            raise _public_error(PublicErrorCode.STORAGE_CORRUPT)
        return CheckpointReport(row[0], row[1], row[2])

    async def rebuild_projection(self, projection_name: str) -> None:
        await self._ensure_recovered()
        if projection_name != "work":
            raise _public_error(PublicErrorCode.INVALID_REQUEST)
        async with self._lock:
            projection = self._state.projection
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._verify_owner()
                self._db.execute(
                    "UPDATE projection_state SET projection_version=?,applied_through_seq=?,"
                    "state_digest=? WHERE projection_name='work'",
                    (PROJECTION_VERSION, projection.frontier, projection_digest(projection)),
                )
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.get_autocommit() is False:
                    self._db.execute("ROLLBACK")
                raise
