"""Memory/SQLite parity for the authoritative append and replay contract."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import apsw
import pytest

from builders.replay import replay_records
from yoetz.adapters.memory.importer import MemoryImportState
from yoetz.adapters.memory.ledger import MemoryLedgerAdapter, MemoryLedgerState
from yoetz.adapters.sqlite.migrations import initialize_bundle
from yoetz.adapters.sqlite.repository import SqliteLedger
from yoetz.domain.events import (
    REVIEW_CHECK_EVENT_SCHEMA_VERSION,
    CheckChangePartialFile,
    CheckChangeShownFiles,
    CheckRecordedPayload,
    EventDraft,
    EventPayload,
    EventSchema,
    MissingForAssessmentItem,
    UnknownEvent,
)
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    CheckVerdict,
    Finding,
    FindingKind,
    FindingOrigin,
    RankedFindings,
    RuntimeTokenUsage,
    SemanticDispatchKind,
    SemanticFailureClass,
    SemanticProvenance,
)
from yoetz.domain.values import (
    Actor,
    ActorType,
    Frontier,
    actor_id,
    event_id,
    finding_id,
    object_id,
    obligation_id,
    parse_rfc3339_millis,
)
from yoetz.kernel.deterministic_checks import (
    deterministic_case_from_json,
    deterministic_case_to_json,
)
from yoetz.kernel.projections import ProjectionState, projection_snapshot
from yoetz.kernel.ranking import CheckCompleteness, RankingContext, rank_findings
from yoetz.ports.change_capture import (
    TASK_CHANGE_BASE_MEDIA_TYPE,
    TaskChangeBase,
    encode_task_change_base,
)
from yoetz.ports.ledger import (
    AppendCommand,
    AppendEntry,
    AppendResult,
    AppendWarning,
    AttemptOutcome,
    CheckCommitResult,
    CheckPhase,
    CheckPolicyExecution,
    CheckSuspensionKind,
    FrozenCase,
    OperationKind,
    OperationLease,
    ProjectionView,
    SelectedAttempt,
    SemanticAttemptHandle,
    SemanticJobRecord,
    SemanticProgressRecord,
)
from yoetz.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectRootSnapshot,
    ObjectSource,
    StagedObject,
)
from yoetz.ports.runtime import OwnershipFence
from yoetz.ports.semantic import SamplingParams
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.coverage import (
    AuthorshipAssurance,
    Coverage,
    LedgerFreshness,
    PublicationChannel,
    coverage_for_channel,
)
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import PREFIX_BY_KIND, IdKind
from yoetz.protocol.models import SemanticProgressPhase, SemanticReason, SemanticStatus


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 7, 19, 12, 0, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return 1.0


class _Ids:
    def __init__(self) -> None:
        self._next = 100

    def new(self, kind: IdKind) -> str:
        self._next += 1
        return PREFIX_BY_KIND[kind] + str(uuid.UUID(int=self._next, version=4))


class _Objects:
    def __init__(self, ids: _Ids) -> None:
        self._ids = ids
        self._data: dict[str, bytes] = {}
        self._refs: dict[str, ObjectRef] = {}

    async def commitment_for(self, data: bytes, kind: ObjectKind) -> str:
        del kind
        return "hmac-sha256:" + hashlib.sha256(data).hexdigest()

    async def stage(
        self, source: ObjectSource, metadata: ObjectMetadata, *, object_id: str | None = None
    ) -> StagedObject:
        assert source.data is not None
        object_id = object_id if object_id is not None else self._ids.new(IdKind.OBJECT)
        if object_id in self._data and self._data[object_id] != source.data:
            raise ValueError("object_identity_conflict")
        commitment = await self.commitment_for(source.data, metadata.kind)
        self._data[object_id] = source.data
        return StagedObject(
            object_id,
            len(source.data),
            commitment,
            "sha256:" + hashlib.sha256(b"envelope" + source.data).hexdigest(),
            "yoetz-object/1",
            "slot-1",
            metadata,
            object(),
        )

    async def finalize(self, staged: StagedObject) -> ObjectRef:
        ref = ObjectRef(
            staged.object_id,
            staged.plaintext_size,
            staged.commitment,
            staged.envelope_digest,
            staged.encryption_format,
            staged.key_slot,
            staged.metadata,
        )
        self._refs[ref.object_id] = ref
        return ref

    async def abandon(self, staged: StagedObject) -> None:
        self._data.pop(staged.object_id, None)
        self._refs.pop(staged.object_id, None)

    async def resolve_verified(self, object_id: str, envelope_digest: str) -> ObjectRef:
        ref = self._refs[object_id]
        if ref.envelope_digest != envelope_digest:
            raise ValueError("object_verification_failed")
        return ref

    async def _open(self, ref: ObjectRef) -> AsyncIterator[bytes]:
        yield self._data[ref.object_id]

    def open_verified(self, ref: ObjectRef) -> AsyncIterator[bytes]:
        return self._open(ref)

    async def sweep_orphans(self, root_snapshot: ObjectRootSnapshot, now: datetime) -> int:
        del root_snapshot, now
        return 0


def _fence() -> OwnershipFence:
    return OwnershipFence(
        "svc_00000000-0000-4000-8000-000000000001",
        1,
        1,
        "ledger-test-nonce",
    )


def ledger_command(
    *,
    request_suffix: str = "1",
    unknown: bool = False,
    index: int = 0,
    session_id: str | None = None,
    writer_id: str | None = None,
    expected_frontier: int = 0,
) -> AppendCommand:
    vector = "unknown-schema" if unknown else "projection-rebuild"
    records = replay_records(vector)
    record = (
        next(row for row in records if type(row) is UnknownEvent) if unknown else records[index]
    )
    assert record.payload is not None
    operation_id = f"req_00000000-0000-4000-8000-00000000000{request_suffix}"
    draft = EventDraft(
        event_id=record.event_id,
        schema=record.schema,
        occurred_at=record.occurred_at,
        causal_parents=() if unknown else record.causal_parents,
        payload=cast(EventPayload, record.payload) if not unknown else record.payload,
        artifact_refs=record.artifact_refs,
        evidence_refs=record.evidence_refs,
    )
    metadata = ObjectMetadata(
        ObjectKind.EVENT_PAYLOAD,
        record.payload_ref.media_type,
        record.task_id,
        parse_rfc3339_millis(record.ledger.accepted_at.wire),
    )
    ref = ObjectRef(
        record.payload_ref.object_id,
        record.payload_ref.plaintext_size,
        record.payload_ref.commitment,
        "sha256:" + "1" * 64,
        "yoetz-object/1",
        "slot-1",
        metadata,
    )
    entry = AppendEntry(
        draft,
        record.author,
        ref,
        ref.commitment,
        metadata.media_type,
        ref.plaintext_size,
        record.publication_channel,
        record.coverage,
        "unknown_unprojected" if unknown else "projected",
    )
    return AppendCommand(
        record.task_id,
        record.session_id if session_id is None else session_id,
        record.writer.writer_id if writer_id is None else writer_id,
        operation_id,
        OperationKind.PUBLISH_WORK,
        "sha256:" + "2" * 64,
        expected_frontier,
        (entry,),
    )


def memory_ledger(command: AppendCommand) -> MemoryLedgerAdapter:
    ids = _Ids()
    return MemoryLedgerAdapter(
        task_id=command.task_id,
        ownership_fence=_fence(),
        state=MemoryLedgerState(),
        import_state=MemoryImportState(),
        transaction_lock=asyncio.Lock(),
        clock=_Clock(),
        ids=ids,
        objects=_Objects(ids),
    )


def sqlite_ledger(command: AppendCommand) -> SqliteLedger:
    db = apsw.Connection(":memory:")
    initialize_bundle(
        db,
        {
            "task_id": command.task_id,
            "owner_generation": "1",
            "owner_nonce": "ledger-test-nonce",
        },
    )
    ids = _Ids()
    return SqliteLedger(
        db=db,
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=_Clock(),
        ids=ids,
        objects=_Objects(ids),
    )


@pytest.mark.anyio
async def test_append_batch_contract() -> None:
    command = ledger_command()
    memory = memory_ledger(command)
    sqlite = sqlite_ledger(command)
    expected = await memory.append_batch(command)
    actual = await sqlite.append_batch(command)
    assert actual == expected
    assert (await memory.append_batch(command)).outcome == "replayed"
    assert (await sqlite.append_batch(command)).outcome == "replayed"

    conflict = replace(command, request_digest="sha256:" + "3" * 64)
    for adapter in (memory, sqlite):
        with pytest.raises(PublicOperationError) as caught:
            await adapter.append_batch(conflict)
        assert caught.value.code is PublicErrorCode.IDEMPOTENCY_CONFLICT


@pytest.mark.anyio
async def test_observation_only_frontier_advance_is_tolerated_with_adapter_parity() -> None:
    base = ledger_command(unknown=True)
    observation = replace(
        base,
        writer_id="wri_00000000-0000-4000-8000-000000000091",
        entries=(
            replace(
                base.entries[0],
                author=Actor(
                    actor_id("yoetz:observation-coordinator"),
                    ActorType.HARNESS,
                    AuthorshipAssurance.HARNESS_OBSERVED,
                ),
                publication_channel=PublicationChannel.HOOK_OBSERVED,
                coverage=coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
            ),
        ),
    )
    held = ledger_command(request_suffix="3", unknown=True, expected_frontier=0)
    held = replace(
        held,
        entries=(
            replace(
                held.entries[0],
                draft=replace(
                    held.entries[0].draft,
                    event_id=event_id("evt_00000000-0000-4000-8000-000000000092"),
                ),
                payload_object=replace(
                    held.entries[0].payload_object,
                    object_id=object_id("obj_00000000-0000-4000-8000-000000000093"),
                ),
            ),
        ),
    )

    results: list[AppendResult] = []
    for adapter in (memory_ledger(observation), sqlite_ledger(observation)):
        await adapter.append_batch(observation)
        results.append(await adapter.append_batch(held))
    assert results[0] == results[1]
    assert results[0].subject_frontier.sequence == 1


@pytest.mark.anyio
async def test_spoofed_observation_actor_does_not_bypass_frontier_guard() -> None:
    base = ledger_command(unknown=True)
    spoofed = replace(
        base,
        entries=(
            replace(
                base.entries[0],
                author=Actor(
                    actor_id("yoetz:observation-coordinator"),
                    ActorType.HARNESS,
                    AuthorshipAssurance.SELF_ASSERTED,
                ),
                publication_channel=PublicationChannel.LOCAL_CLI,
                coverage=coverage_for_channel(PublicationChannel.LOCAL_CLI),
            ),
        ),
    )
    held = ledger_command(request_suffix="3", unknown=True, expected_frontier=0)
    held = replace(
        held,
        entries=(
            replace(
                held.entries[0],
                draft=replace(
                    held.entries[0].draft,
                    event_id=event_id("evt_00000000-0000-4000-8000-000000000093"),
                ),
            ),
        ),
    )

    for adapter in (memory_ledger(spoofed), sqlite_ledger(spoofed)):
        await adapter.append_batch(spoofed)
        with pytest.raises(PublicOperationError) as caught:
            await adapter.append_batch(held)
        assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT


@pytest.mark.anyio
async def test_observation_append_waits_while_check_case_is_frozen() -> None:
    base = ledger_command(unknown=True)
    observation = ledger_command(request_suffix="3", unknown=True, expected_frontier=1)
    observation = replace(
        observation,
        writer_id="wri_00000000-0000-4000-8000-000000000094",
        entries=(
            replace(
                observation.entries[0],
                draft=replace(
                    observation.entries[0].draft,
                    event_id=event_id("evt_00000000-0000-4000-8000-000000000095"),
                ),
                author=Actor(
                    actor_id("yoetz:observation-coordinator"),
                    ActorType.HARNESS,
                    AuthorshipAssurance.HARNESS_OBSERVED,
                ),
                publication_channel=PublicationChannel.HOOK_OBSERVED,
                coverage=coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
            ),
        ),
    )

    for adapter in (memory_ledger(base), sqlite_ledger(base)):
        result = await adapter.append_batch(base)
        frozen = await adapter.freeze_case(
            base.session_id,
            base.writer_id,
            result.result_frontier.sequence,
            "req_00000000-0000-4000-8000-000000000096",
            "sha256:" + "9" * 64,
        )
        assert isinstance(frozen, FrozenCase)
        with pytest.raises(PublicOperationError) as caught:
            await adapter.append_batch(observation)
        assert caught.value.code is PublicErrorCode.OPERATION_PENDING
        assert caught.value.retryable is True


@pytest.mark.anyio
async def test_observation_append_resumes_after_frozen_check_terminalizes() -> None:
    base = ledger_command()
    observation = ledger_command(request_suffix="3", index=1, expected_frontier=1)
    observation = replace(
        observation,
        writer_id="wri_00000000-0000-4000-8000-000000000097",
        entries=(
            replace(
                observation.entries[0],
                author=Actor(
                    actor_id("yoetz:observation-coordinator"),
                    ActorType.HARNESS,
                    AuthorshipAssurance.HARNESS_OBSERVED,
                ),
                publication_channel=PublicationChannel.HOOK_OBSERVED,
                coverage=coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
            ),
        ),
    )

    for adapter in (memory_ledger(base), sqlite_ledger(base)):
        result = await adapter.append_batch(base)
        frozen = await adapter.freeze_case(
            base.session_id,
            base.writer_id,
            result.result_frontier.sequence,
            "req_00000000-0000-4000-8000-000000000099",
            "sha256:" + "9" * 64,
        )
        assert isinstance(frozen, FrozenCase)
        await adapter.fail_check_if_current(
            frozen.lease,
            PublicOperationError(PublicErrorCode.STORAGE_UNSAFE, "terminal", False),
        )

        appended = await adapter.append_batch(observation)
        assert appended.result_frontier.sequence == 2


def _observation_command(
    *, request_suffix: str, expected_frontier: int, seed: str
) -> AppendCommand:
    command = ledger_command(
        request_suffix=request_suffix, unknown=True, expected_frontier=expected_frontier
    )
    return replace(
        command,
        writer_id=f"wri_00000000-0000-4000-8000-0000000000{seed}1",
        entries=(
            replace(
                command.entries[0],
                draft=replace(
                    command.entries[0].draft,
                    event_id=event_id(f"evt_00000000-0000-4000-8000-0000000000{seed}2"),
                ),
                payload_object=replace(
                    command.entries[0].payload_object,
                    object_id=object_id(f"obj_00000000-0000-4000-8000-0000000000{seed}4"),
                ),
                author=Actor(
                    actor_id("yoetz:observation-coordinator"),
                    ActorType.HARNESS,
                    AuthorshipAssurance.HARNESS_OBSERVED,
                ),
                publication_channel=PublicationChannel.HOOK_OBSERVED,
                coverage=coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
            ),
        ),
    )


@pytest.mark.anyio
async def test_freeze_case_tolerates_observation_only_motion_with_adapter_parity() -> None:
    """Freeze acquisition accepts an observation-only-stale frontier and freezes at the real
    head, so a check retried under active observation drain converges (issue #320)."""

    base = ledger_command(unknown=True)
    observation = _observation_command(request_suffix="3", expected_frontier=1, seed="a")
    for adapter in (memory_ledger(base), sqlite_ledger(base)):
        held = await adapter.append_batch(base)
        drained = await adapter.append_batch(observation)
        frozen = await adapter.freeze_case(
            base.session_id,
            base.writer_id,
            held.result_frontier.sequence,
            "req_00000000-0000-4000-8000-0000000000a3",
            "sha256:" + "9" * 64,
        )
        assert isinstance(frozen, FrozenCase)
        assert frozen.case.frontier == drained.result_frontier


@pytest.mark.anyio
async def test_freeze_case_agent_motion_still_conflicts_with_repair_facts() -> None:
    """Material (agent-authored) motion past the caller's frontier stays a real conflict, and
    the error keeps the shared retry contract: retryable with the live head in safe_details."""

    base = ledger_command()
    second = ledger_command(request_suffix="3", index=1, expected_frontier=1)
    for adapter in (memory_ledger(base), sqlite_ledger(base)):
        held = await adapter.append_batch(base)
        moved = await adapter.append_batch(second)
        with pytest.raises(PublicOperationError) as caught:
            await adapter.freeze_case(
                base.session_id,
                base.writer_id,
                held.result_frontier.sequence,
                "req_00000000-0000-4000-8000-0000000000b3",
                "sha256:" + "9" * 64,
            )
        assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
        assert caught.value.retryable is True
        assert caught.value.safe_details["sequence"] == moved.result_frontier.sequence


@pytest.mark.anyio
async def test_freeze_case_spoofed_observation_suffix_still_conflicts() -> None:
    """The freeze tolerance uses the same unforgeable authorship predicate as ``append_batch``:
    caller-supplied actor fields alone never earn it."""

    base = ledger_command(unknown=True)
    spoofed = replace(
        base,
        entries=(
            replace(
                base.entries[0],
                author=Actor(
                    actor_id("yoetz:observation-coordinator"),
                    ActorType.HARNESS,
                    AuthorshipAssurance.SELF_ASSERTED,
                ),
                publication_channel=PublicationChannel.LOCAL_CLI,
                coverage=coverage_for_channel(PublicationChannel.LOCAL_CLI),
            ),
        ),
    )
    for adapter in (memory_ledger(spoofed), sqlite_ledger(spoofed)):
        await adapter.append_batch(spoofed)
        with pytest.raises(PublicOperationError) as caught:
            await adapter.freeze_case(
                spoofed.session_id,
                spoofed.writer_id,
                0,
                "req_00000000-0000-4000-8000-0000000000c3",
                "sha256:" + "9" * 64,
            )
        assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT


@pytest.mark.anyio
async def test_historical_case_availability_rejects_forged_projection_with_adapter_parity() -> None:
    """A ledger-prefix digest authenticates the records, not an arbitrary ProjectionState.

    Historical receipt tolerance must therefore replay and compare the exact prefix before it
    returns availability facts, even when the live suffix is observation-authored and finding-free.
    """

    base = ledger_command(unknown=True)
    observation = _observation_command(request_suffix="3", expected_frontier=1, seed="e")
    for adapter in (memory_ledger(base), sqlite_ledger(base)):
        held = await adapter.append_batch(base)
        stored = await adapter.load_projection(base.session_id, ProjectionView.CANDIDATE_FINDINGS)
        assert stored is not None
        assert type(stored.state) is ProjectionState
        await adapter.append_batch(observation)
        availability = await adapter.load_case_availability(
            base.session_id, held.result_frontier, stored.state
        )
        assert availability.unavailable_event_ids == ()
        forged_freshness = (
            LedgerFreshness.PARTIAL
            if stored.state.freshness is LedgerFreshness.CURRENT
            else LedgerFreshness.CURRENT
        )
        forged = replace(stored.state, freshness=forged_freshness)

        with pytest.raises(PublicOperationError) as caught:
            await adapter.load_case_availability(base.session_id, held.result_frontier, forged)

        assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT


class _GatedObjects(_Objects):
    """Block the first check-resume staging call so a test can act inside the freeze window."""

    def __init__(self, ids: _Ids) -> None:
        super().__init__(ids)
        self.freeze_entered = asyncio.Event()
        self.release_freeze = asyncio.Event()

    async def stage(
        self, source: ObjectSource, metadata: ObjectMetadata, *, object_id: str | None = None
    ) -> StagedObject:
        if metadata.kind is ObjectKind.CHECK_RESUME:
            self.freeze_entered.set()
            await self.release_freeze.wait()
        return await super().stage(source, metadata, object_id=object_id)


@pytest.mark.anyio
async def test_observation_append_defers_while_freeze_is_acquiring() -> None:
    """The observation barrier arms at freeze acquisition, not only once the frozen case exists;
    otherwise the drain the acquisition just tolerated races the freeze itself (issue #320)."""

    base = ledger_command(unknown=True)
    observation = _observation_command(request_suffix="3", expected_frontier=1, seed="d")

    def gated_memory() -> tuple[MemoryLedgerAdapter, _GatedObjects]:
        ids = _Ids()
        gate = _GatedObjects(ids)
        adapter = MemoryLedgerAdapter(
            task_id=base.task_id,
            ownership_fence=_fence(),
            state=MemoryLedgerState(),
            import_state=MemoryImportState(),
            transaction_lock=asyncio.Lock(),
            clock=_Clock(),
            ids=ids,
            objects=gate,
        )
        return adapter, gate

    def gated_sqlite() -> tuple[SqliteLedger, _GatedObjects]:
        db = apsw.Connection(":memory:")
        initialize_bundle(
            db,
            {
                "task_id": base.task_id,
                "owner_generation": "1",
                "owner_nonce": "ledger-test-nonce",
            },
        )
        ids = _Ids()
        gate = _GatedObjects(ids)
        adapter = SqliteLedger(
            db=db,
            task_id=base.task_id,
            ownership_fence=_fence(),
            clock=_Clock(),
            ids=ids,
            objects=gate,
        )
        return adapter, gate

    for adapter, gate in (gated_memory(), gated_sqlite()):
        await adapter.append_batch(base)
        freeze = asyncio.ensure_future(
            adapter.freeze_case(
                base.session_id,
                base.writer_id,
                1,
                "req_00000000-0000-4000-8000-0000000000d3",
                "sha256:" + "9" * 64,
            )
        )
        await asyncio.wait_for(gate.freeze_entered.wait(), timeout=5)
        with pytest.raises(PublicOperationError) as caught:
            await adapter.append_batch(observation)
        assert caught.value.code is PublicErrorCode.OPERATION_PENDING
        assert caught.value.retryable is True
        gate.release_freeze.set()
        frozen = await asyncio.wait_for(freeze, timeout=5)
        assert isinstance(frozen, FrozenCase)


@pytest.mark.anyio
async def test_agent_append_during_freeze_invalidates_acquisition_with_adapter_parity() -> None:
    """Material motion in the acquisition window must reach final revalidation in both adapters.

    SQLite uses copy-on-write state for append durability. A freeze oracle must continue to see the
    adopted state after that swap rather than reserving a case against its stale object snapshot.
    """

    base = ledger_command(unknown=True)
    observation_shaped = _observation_command(request_suffix="5", expected_frontier=1, seed="f")
    agent = replace(
        observation_shaped,
        entries=(
            replace(
                observation_shaped.entries[0],
                author=base.entries[0].author,
                publication_channel=PublicationChannel.LOCAL_CLI,
                coverage=coverage_for_channel(PublicationChannel.LOCAL_CLI),
            ),
        ),
    )

    def gated_memory() -> tuple[MemoryLedgerAdapter, _GatedObjects]:
        ids = _Ids()
        gate = _GatedObjects(ids)
        adapter = MemoryLedgerAdapter(
            task_id=base.task_id,
            ownership_fence=_fence(),
            state=MemoryLedgerState(),
            import_state=MemoryImportState(),
            transaction_lock=asyncio.Lock(),
            clock=_Clock(),
            ids=ids,
            objects=gate,
        )
        return adapter, gate

    def gated_sqlite() -> tuple[SqliteLedger, _GatedObjects]:
        db = apsw.Connection(":memory:")
        initialize_bundle(
            db,
            {
                "task_id": base.task_id,
                "owner_generation": "1",
                "owner_nonce": "ledger-test-nonce",
            },
        )
        ids = _Ids()
        gate = _GatedObjects(ids)
        adapter = SqliteLedger(
            db=db,
            task_id=base.task_id,
            ownership_fence=_fence(),
            clock=_Clock(),
            ids=ids,
            objects=gate,
        )
        return adapter, gate

    for adapter, gate in (gated_memory(), gated_sqlite()):
        await adapter.append_batch(base)
        freeze = asyncio.ensure_future(
            adapter.freeze_case(
                base.session_id,
                base.writer_id,
                1,
                "req_00000000-0000-4000-8000-0000000000f3",
                "sha256:" + "9" * 64,
            )
        )
        await asyncio.wait_for(gate.freeze_entered.wait(), timeout=5)
        moved = await adapter.append_batch(agent)
        gate.release_freeze.set()

        with pytest.raises(PublicOperationError) as caught:
            await asyncio.wait_for(freeze, timeout=5)

        assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
        assert caught.value.safe_details["sequence"] == moved.result_frontier.sequence


@pytest.mark.anyio
async def test_load_and_freeze_contract() -> None:
    command = ledger_command()
    adapters = (memory_ledger(command), sqlite_ledger(command))
    loaded: list[tuple[object, ...]] = []
    for adapter in adapters:
        await adapter.append_batch(command)
        loaded.append(tuple([row async for row in adapter.load_events(command.session_id)]))
    assert loaded[0] == loaded[1]


@pytest.mark.anyio
async def test_load_events_gives_every_attached_session_the_whole_task_chain() -> None:
    """``session_id`` scopes membership, not rows (issue #200).

    A task's ingestion sequence and digest chain are task-global: a second session appending to
    the same task continues one chain rather than starting its own. Both adapters therefore hand
    either session the full chain, and hand a session that never appended here nothing at all.
    """

    first = ledger_command()
    second = ledger_command(
        request_suffix="3",
        index=1,
        session_id="ses_20000007-0000-4000-8000-000000000012",
        writer_id="wri_20000007-0000-4000-8000-000000000013",
        expected_frontier=1,
    )
    stranger = "ses_20000007-0000-4000-8000-000000000099"
    loaded: list[tuple[object, ...]] = []
    for adapter in (memory_ledger(first), sqlite_ledger(first)):
        await adapter.append_batch(first)
        await adapter.append_batch(second)
        resumed = tuple([row async for row in adapter.load_events(second.session_id)])
        assert tuple(row.ledger.ingestion_sequence for row in resumed) == (1, 2)
        assert tuple(str(row.session_id) for row in resumed) == (
            first.session_id,
            second.session_id,
        )
        original = tuple([row async for row in adapter.load_events(first.session_id)])
        assert original == resumed
        # ``after``/``through`` still bound the window, and they count task ingestion sequence.
        windowed = tuple(
            [row async for row in adapter.load_events(second.session_id, after=1, through=2)]
        )
        assert windowed == resumed[1:]
        assert [row async for row in adapter.load_events(stranger)] == []
        loaded.append(resumed)
    assert loaded[0] == loaded[1]


@pytest.mark.anyio
async def test_append_warning_contract() -> None:
    command = ledger_command(request_suffix="2", unknown=True)
    results = [
        await adapter.append_batch(command)
        for adapter in (memory_ledger(command), sqlite_ledger(command))
    ]
    assert results[0] == results[1]
    assert results[0].warnings == (AppendWarning.UNKNOWN_EVENT_SCHEMA_PRESERVED,)


@pytest.mark.anyio
async def test_lookup_operation_contract() -> None:
    command = ledger_command()
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        result = await adapter.append_batch(command)
        operation = await adapter.lookup_operation(command.writer_id, command.operation_id)
        assert operation is not None
        assert operation.request_digest == command.request_digest
        assert operation.result_locator is not None
        assert (
            operation.result_locator.first_ingestion_sequence
            == result.accepted[0].ingestion_sequence
        )


async def _local_result_ref(
    adapter: MemoryLedgerAdapter | SqliteLedger, command: AppendCommand
) -> ObjectRef:
    objects = adapter._objects  # pyright: ignore[reportPrivateUsage]
    assert objects is not None
    staged = await objects.stage(
        ObjectSource(data=b"{}", declared_size=2),
        ObjectMetadata(
            ObjectKind.DETERMINISTIC_RESULT,
            "application/vnd.yoetz.deterministic-result+json",
            command.task_id,
            datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
        ),
    )
    return await objects.finalize(staged)


async def _object_ref(
    adapter: MemoryLedgerAdapter | SqliteLedger,
    command: AppendCommand,
    kind: ObjectKind,
    *,
    semantic_case_digest: str | None = None,
    semantic_case_primary_expires_at: str = "2026-07-19T12:04:00.000Z",
    semantic_case_expires_at: str = "2026-07-19T12:05:00.000Z",
    semantic_case_with_fallback: bool = False,
) -> ObjectRef:
    objects = adapter._objects  # pyright: ignore[reportPrivateUsage]
    assert objects is not None
    payload = b"{}"
    if kind is ObjectKind.SEMANTIC_CASE:
        assert semantic_case_digest is not None
        execution: dict[str, object] = {
            "provider": {
                "provider_id": "fake",
                "model_id": "fake/model",
                "endpoint_profile_id": "fake",
                "endpoint_profile_version": "1.0.0",
                "transport": "external",
            },
            "fallback_binding": None,
            "fallback_plan": None,
            "max_retries": 0,
            "primary_expires_at": semantic_case_primary_expires_at,
            "expires_at": semantic_case_expires_at,
            "fallback_timeout_seconds": 60,
        }
        if semantic_case_with_fallback:
            execution["fallback_binding"] = {
                "provider_id": "fallback",
                "model_id": "fallback/model",
                "endpoint_profile_id": "fallback",
                "endpoint_profile_version": "1.0.0",
                "transport": "external",
            }
            execution["fallback_plan"] = {
                "primary": {
                    "provider_id": "fake",
                    "model_id": "fake/model",
                    "endpoint_profile_id": "fake",
                    "endpoint_profile_version": "1.0.0",
                    "max_retries": 0,
                },
                "fallback_max_retries": 0,
                "primary_predispatch_reason": None,
            }
        payload = canonical_encode(
            cast(
                JsonValue,
                {
                    "schema": "yoetz.semantic-case/2",
                    "case_id": "case_ledger_test",
                    "case_digest": semantic_case_digest,
                    "dependency_digest": "sha256:" + "1" * 64,
                    "execution": execution,
                },
            )
        )
    staged = await objects.stage(
        ObjectSource(data=payload, declared_size=len(payload)),
        ObjectMetadata(
            kind,
            "application/json",
            command.task_id,
            datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
        ),
    )
    return await objects.finalize(staged)


async def _semantic_wait_lease(
    adapter: MemoryLedgerAdapter | SqliteLedger,
    command: AppendCommand,
    operation_id: str,
) -> OperationLease:
    frozen = await adapter.freeze_case(
        command.session_id,
        command.writer_id,
        1,
        operation_id,
        "sha256:" + "7" * 64,
    )
    assert type(frozen) is FrozenCase
    operation = await adapter.lookup_operation(command.writer_id, operation_id)
    assert operation is not None and operation.resume_object_ref is not None
    prior = operation.resume_object_ref
    canonical = canonical_encode(
        {
            "schema_version": "1.0.0",
            "request_id": operation_id,
            "request_digest": "sha256:" + "7" * 64,
            "task_id": command.task_id,
            "session_id": command.session_id,
            "writer_id": command.writer_id,
            "subject_frontier": frozen.case.frontier.as_wire(),
            "dependency_digest": frozen.lease.dependency_digest,
            "prior_resume": {
                "object_id": prior.object_id,
                "envelope_digest": prior.envelope_digest,
                "commitment": prior.commitment,
            },
            "policy_executions": (),
            "assessments": (),
        }
    )
    objects = adapter._objects  # pyright: ignore[reportPrivateUsage]
    assert objects is not None
    staged = await objects.stage(
        ObjectSource(data=canonical, declared_size=len(canonical)),
        ObjectMetadata(
            ObjectKind.DETERMINISTIC_RESULT,
            "application/vnd.yoetz.deterministic-result+json",
            command.task_id,
            datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
        ),
    )
    local_result = await objects.finalize(staged)
    lease = await adapter.advance_check_phase(
        frozen.lease,
        CheckPhase.RESERVED,
        CheckPhase.LOCAL_READY,
        local_result,
    )
    return await adapter.advance_check_phase(
        lease, CheckPhase.LOCAL_READY, CheckPhase.SEMANTIC_WAIT
    )


@pytest.mark.anyio
async def test_repository_grant_suspension_is_exact_and_clears_on_same_request_resume() -> None:
    command = ledger_command(request_suffix="6")
    operation_id = "req_00000000-0000-4000-8000-000000000031"
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        lease = await _semantic_wait_lease(adapter, command, operation_id)
        await adapter.suspend_check_for_repository_grant(lease)
        suspended = await adapter.lookup_operation(command.writer_id, operation_id)
        assert suspended is not None
        assert suspended.suspension_kind is CheckSuspensionKind.REPOSITORY_GRANT
        assert not any(
            job.writer_id == command.writer_id and job.operation_id == operation_id
            for job in adapter._state.jobs.values()  # pyright: ignore[reportPrivateUsage]
        )

        resumed = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            operation_id,
            "sha256:" + "7" * 64,
        )
        assert type(resumed) is FrozenCase
        current = await adapter.lookup_operation(command.writer_id, operation_id)
        assert current is not None
        assert current.suspension_kind is None


@pytest.mark.anyio
async def test_repository_grant_suspension_rejects_wrong_phase_and_existing_job() -> None:
    command = ledger_command(request_suffix="7")
    for offset, adapter in enumerate((memory_ledger(command), sqlite_ledger(command)), start=1):
        await adapter.append_batch(command)
        wrong_id = f"req_00000000-0000-4000-8000-00000000003{offset}"
        frozen = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            wrong_id,
            "sha256:" + "8" * 64,
        )
        assert type(frozen) is FrozenCase
        with pytest.raises(PublicOperationError) as wrong_phase:
            await adapter.suspend_check_for_repository_grant(frozen.lease)
        assert wrong_phase.value.code is PublicErrorCode.OPERATION_PENDING
        wrong_record = await adapter.lookup_operation(command.writer_id, wrong_id)
        assert wrong_record is not None and wrong_record.suspension_kind is None

        job_id = f"req_00000000-0000-4000-8000-00000000004{offset}"
        lease = await _semantic_wait_lease(adapter, command, job_id)
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest="sha256:" + "9" * 64,
        )
        await adapter.enqueue_semantic_job(lease, "sha256:" + "9" * 64, case_ref)
        with pytest.raises(PublicOperationError) as existing_job:
            await adapter.suspend_check_for_repository_grant(lease)
        assert existing_job.value.code is PublicErrorCode.OPERATION_PENDING
        job_record = await adapter.lookup_operation(command.writer_id, job_id)
        assert job_record is not None and job_record.suspension_kind is None


@pytest.mark.anyio
async def test_repository_grant_suspension_survives_memory_rebind_and_sqlite_restart(
    tmp_path: Path,
) -> None:
    command = ledger_command(request_suffix="8")
    operation_id = "req_00000000-0000-4000-8000-000000000035"

    memory_ids = _Ids()
    memory_objects = _Objects(memory_ids)
    memory_state = MemoryLedgerState()
    memory = MemoryLedgerAdapter(
        task_id=command.task_id,
        ownership_fence=_fence(),
        state=memory_state,
        import_state=MemoryImportState(),
        transaction_lock=asyncio.Lock(),
        clock=_Clock(),
        ids=memory_ids,
        objects=memory_objects,
    )
    await memory.append_batch(command)
    await memory.suspend_check_for_repository_grant(
        await _semantic_wait_lease(memory, command, operation_id)
    )
    rebound = MemoryLedgerAdapter(
        task_id=command.task_id,
        ownership_fence=_fence(),
        state=memory_state,
        import_state=MemoryImportState(),
        transaction_lock=asyncio.Lock(),
        clock=_Clock(),
        ids=memory_ids,
        objects=memory_objects,
    )
    rebound_record = await rebound.lookup_operation(command.writer_id, operation_id)
    assert rebound_record is not None
    assert rebound_record.suspension_kind is CheckSuspensionKind.REPOSITORY_GRANT

    database = tmp_path / "repository-grant-suspension.sqlite3"
    first_db = apsw.Connection(str(database))
    initialize_bundle(
        first_db,
        {
            "task_id": command.task_id,
            "owner_generation": "1",
            "owner_nonce": "ledger-test-nonce",
        },
    )
    sqlite_ids = _Ids()
    sqlite_objects = _Objects(sqlite_ids)
    first = SqliteLedger(
        db=first_db,
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=_Clock(),
        ids=sqlite_ids,
        objects=sqlite_objects,
    )
    await first.append_batch(command)
    await first.suspend_check_for_repository_grant(
        await _semantic_wait_lease(first, command, operation_id)
    )
    first_db.close()

    second = SqliteLedger(
        db=apsw.Connection(str(database)),
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=_Clock(),
        ids=sqlite_ids,
        objects=sqlite_objects,
    )
    restarted = await second.lookup_operation(command.writer_id, operation_id)
    assert restarted is not None
    assert restarted.suspension_kind is CheckSuspensionKind.REPOSITORY_GRANT
    resumed = await second.freeze_case(
        command.session_id,
        command.writer_id,
        1,
        operation_id,
        "sha256:" + "7" * 64,
    )
    assert type(resumed) is FrozenCase
    cleared = await second.lookup_operation(command.writer_id, operation_id)
    assert cleared is not None and cleared.suspension_kind is None


def _grant_park_observation(request_suffix: str, writer_suffix: str) -> AppendCommand:
    """Observation append on the projection-rebuild task used by grant-park checks."""

    observation = ledger_command(request_suffix=request_suffix, index=1, expected_frontier=1)
    return replace(
        observation,
        writer_id=f"wri_00000000-0000-4000-8000-0000000000{writer_suffix}",
        entries=(
            replace(
                observation.entries[0],
                author=Actor(
                    actor_id("yoetz:observation-coordinator"),
                    ActorType.HARNESS,
                    AuthorshipAssurance.HARNESS_OBSERVED,
                ),
                publication_channel=PublicationChannel.HOOK_OBSERVED,
                coverage=coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
            ),
        ),
    )


@pytest.mark.anyio
async def test_repository_grant_suspension_releases_observation_barrier() -> None:
    """A parked standing-grant check must not starve observation for the session (#445)."""

    command = ledger_command(request_suffix="9")
    operation_id = "req_00000000-0000-4000-8000-000000000036"
    observation = _grant_park_observation("a", "c1")
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        lease = await _semantic_wait_lease(adapter, command, operation_id)
        assert await adapter.has_active_frozen_case(command.session_id)
        with pytest.raises(PublicOperationError) as blocked:
            await adapter.append_batch(observation)
        assert blocked.value.code is PublicErrorCode.OPERATION_PENDING
        await adapter.suspend_check_for_repository_grant(lease)
        assert not await adapter.has_active_frozen_case(command.session_id)
        appended = await adapter.append_batch(observation)
        assert appended.result_frontier.sequence == 2


@pytest.mark.anyio
async def test_repository_grant_resume_commits_across_observation_only_suffix() -> None:
    """Same-request replay after a grant park must complete if only observation moved (#445)."""

    command = ledger_command(request_suffix="c")
    operation_id = "req_00000000-0000-4000-8000-000000000037"
    observation = _grant_park_observation("d", "d1")
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        await adapter.suspend_check_for_repository_grant(
            await _semantic_wait_lease(adapter, command, operation_id)
        )
        drained = await adapter.append_batch(observation)
        resumed = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            operation_id,
            "sha256:" + "7" * 64,
        )
        assert type(resumed) is FrozenCase
        assert resumed.case.frontier.sequence == 1
        ready = await adapter.advance_check_phase(
            resumed.lease,
            CheckPhase.SEMANTIC_WAIT,
            CheckPhase.READY_TO_FINALIZE,
        )
        ranked = RankedFindings((), 0, CheckVerdict.NO_ISSUE_DETECTED, command.entries[0].coverage)
        result = await adapter.commit_check_if_current(
            FrozenCase(resumed.case, ready),
            ranked,
            (CheckPolicyExecution("research-evidence", "0.1.0", "run", "completed"),),
            SemanticStatus.NOT_REQUESTED,
            SemanticReason.DETERMINISTIC_MODE,
            None,
            operation_id,
        )
        assert result.outcome == "committed"
        assert result.subject_frontier.sequence == 1
        assert result.result_frontier.sequence > drained.result_frontier.sequence


@pytest.mark.anyio
async def test_repository_grant_resume_conflicts_on_cooperative_suffix() -> None:
    """Cooperative motion during a grant park still conflicts at commit (#445)."""

    command = ledger_command(request_suffix="e")
    operation_id = "req_00000000-0000-4000-8000-000000000038"
    second = ledger_command(request_suffix="f", index=1, expected_frontier=1)
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        await adapter.suspend_check_for_repository_grant(
            await _semantic_wait_lease(adapter, command, operation_id)
        )
        await adapter.append_batch(second)
        resumed = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            operation_id,
            "sha256:" + "7" * 64,
        )
        assert type(resumed) is FrozenCase
        ready = await adapter.advance_check_phase(
            resumed.lease,
            CheckPhase.SEMANTIC_WAIT,
            CheckPhase.READY_TO_FINALIZE,
        )
        ranked = RankedFindings((), 0, CheckVerdict.NO_ISSUE_DETECTED, command.entries[0].coverage)
        with pytest.raises(PublicOperationError) as caught:
            await adapter.commit_check_if_current(
                FrozenCase(resumed.case, ready),
                ranked,
                (CheckPolicyExecution("research-evidence", "0.1.0", "run", "completed"),),
                SemanticStatus.NOT_REQUESTED,
                SemanticReason.DETERMINISTIC_MODE,
                None,
                operation_id,
            )
        assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT


@pytest.mark.anyio
async def test_commit_check_if_current_contract() -> None:
    command = ledger_command()
    results: list[CheckCommitResult] = []
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        frozen = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            "req_00000000-0000-4000-8000-000000000009",
            "sha256:" + "9" * 64,
        )
        assert type(frozen) is FrozenCase
        lease = await adapter.advance_check_phase(
            frozen.lease,
            CheckPhase.RESERVED,
            CheckPhase.LOCAL_READY,
            await _local_result_ref(adapter, command),
        )
        lease = await adapter.advance_check_phase(
            lease,
            CheckPhase.LOCAL_READY,
            CheckPhase.READY_TO_FINALIZE,
        )
        ranked = RankedFindings((), 0, CheckVerdict.NO_ISSUE_DETECTED, command.entries[0].coverage)
        result = await adapter.commit_check_if_current(
            FrozenCase(frozen.case, lease),
            ranked,
            (CheckPolicyExecution("research-evidence", "0.1.0", "run", "completed"),),
            SemanticStatus.NOT_REQUESTED,
            SemanticReason.DETERMINISTIC_MODE,
            None,
            lease.operation_id,
        )
        assert result.outcome == "committed"
        results.append(result)
        committed = [
            row.schema
            async for row in adapter.load_events(command.session_id)
            if row.schema.name == "check_recorded"
        ]
        # Every newly completed check carries frozen-work totals, so it commits as 1.4.0.
        assert committed == [EventSchema("check_recorded", REVIEW_CHECK_EVENT_SCHEMA_VERSION)]
        stored_check = [
            row.payload
            async for row in adapter.load_events(command.session_id)
            if row.schema.name == "check_recorded"
        ]
        assert isinstance(stored_check[0], CheckRecordedPayload)
        assert stored_check[0].totals is not None
    assert results[0] == results[1]


def _descending_rank_findings(
    frontier: Frontier,
    coverage: Coverage,
    *,
    semantic_lead: bool,
) -> tuple[Finding, ...]:
    """Two findings whose rank order is the reverse of ASCII finding-ID order.

    The later ID is the higher-priority finding, so ``rank_findings`` returns
    ``(...0002, ...0001)`` — the exact commit-path mismatch in issue #248.
    """

    lower = Finding(
        finding_id=finding_id("fnd_00000000-0000-4000-8000-000000000001"),
        kind=FindingKind.LEDGER_STALE_OR_INCOMPLETE,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[FindingKind.LEDGER_STALE_OR_INCOMPLETE][0],
        summary="Ledger stale or incomplete",
        detail="The recorded subject is missing required current evidence.",
        subject_refs=(obligation_id("obl_00000000-0000-4000-8000-000000000001"),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=frontier,
        coverage=coverage,
    )
    higher = Finding(
        finding_id=finding_id("fnd_00000000-0000-4000-8000-000000000002"),
        kind=FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        origin=(
            FindingOrigin.SEMANTIC_MODEL_DERIVED if semantic_lead else FindingOrigin.DETERMINISTIC
        ),
        priority=FINDING_KIND_TRAITS[FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE][0],
        summary="Claim lacks admissible evidence",
        detail="Cite admissible evidence or narrow the completion claim.",
        subject_refs=(obligation_id("obl_00000000-0000-4000-8000-000000000001"),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=frontier,
        coverage=coverage,
        provenance=(
            SemanticProvenance(
                provider="fake",
                endpoint_profile_id="fake",
                endpoint_profile_version="1.0.0",
                model="fake/model",
                sdk_version="1.0.0",
                prompt_digest="sha256:" + "1" * 64,
                schema_digest="sha256:" + "2" * 64,
                policy_digest="sha256:" + "3" * 64,
                privacy_policy_digest="sha256:" + "4" * 64,
                sampling_params=SamplingParams(128),
                latency_ms=1,
                semantic_attempt_id="att_00000000-0000-4000-8000-000000000002",
                dispatch_kind=SemanticDispatchKind.EXTERNAL,
                privacy_receipt_id="egr_00000000-0000-4000-8000-000000000002",
                status=SemanticStatus.SUCCEEDED,
                reason=SemanticReason.SEMANTIC_COMPLETED,
                provider_request_id="fake-semantic-request-248",
                egress_authorization_id="aut_00000000-0000-4000-8000-000000000002",
                request_commitment="hmac-sha256:" + "5" * 64,
            )
            if semantic_lead
            else None
        ),
    )
    ranked = rank_findings(
        (lower,) if semantic_lead else (lower, higher),
        (higher,) if semantic_lead else (),
        RankingContext(coverage, CheckCompleteness.COMPLETE),
        4,
    )
    ids = tuple(item.finding_id for item in ranked.findings)
    assert ids == (higher.finding_id, lower.finding_id)
    assert ids != tuple(sorted(ids, key=str.encode))
    return ranked.findings


async def _ready_case(
    adapter: MemoryLedgerAdapter | SqliteLedger,
    command: AppendCommand,
    request_id: str,
    request_digest: str,
) -> FrozenCase:
    frozen = await adapter.freeze_case(
        command.session_id,
        command.writer_id,
        1,
        request_id,
        request_digest,
    )
    assert type(frozen) is FrozenCase
    lease = await adapter.advance_check_phase(
        frozen.lease,
        CheckPhase.RESERVED,
        CheckPhase.LOCAL_READY,
        await _local_result_ref(adapter, command),
    )
    lease = await adapter.advance_check_phase(
        lease,
        CheckPhase.LOCAL_READY,
        CheckPhase.READY_TO_FINALIZE,
    )
    return FrozenCase(frozen.case, lease)


@pytest.mark.anyio
@pytest.mark.parametrize("semantic_lead", [False, True], ids=["deterministic_only", "mixed"])
async def test_commit_sorts_returned_finding_ids_without_reordering_ranked_findings(
    semantic_lead: bool,
) -> None:
    """A multi-finding check whose rank order is not ASCII order must still commit.

    Issue #248: commit copied ranked IDs into CheckRecordedPayload.returned_finding_ids,
    which is a canonical set. Both adapters and both check modes share this boundary.
    """

    command = ledger_command()
    results: list[CheckCommitResult] = []
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        suffix = "a" if semantic_lead else "b"
        frozen = await _ready_case(
            adapter,
            command,
            f"req_00000000-0000-4000-8000-00000000004{suffix}",
            "sha256:" + ("a" if semantic_lead else "b") * 64,
        )
        selected = _descending_rank_findings(
            frozen.case.frontier,
            command.entries[0].coverage,
            semantic_lead=semantic_lead,
        )
        ranked = RankedFindings(
            selected,
            0,
            CheckVerdict.ACTION_REQUIRED,
            command.entries[0].coverage,
        )
        if semantic_lead:
            result = await adapter.commit_check_if_current(
                frozen,
                ranked,
                (CheckPolicyExecution("work-integrity", "0.1.0", "run", "completed"),),
                SemanticStatus.SUCCEEDED,
                SemanticReason.SEMANTIC_COMPLETED,
                selected[0].provenance,
                frozen.lease.operation_id,
            )
        else:
            result = await adapter.commit_check_if_current(
                frozen,
                ranked,
                (CheckPolicyExecution("work-integrity", "0.1.0", "run", "completed"),),
                SemanticStatus.NOT_REQUESTED,
                SemanticReason.DETERMINISTIC_MODE,
                None,
                frozen.lease.operation_id,
            )
        assert result.outcome == "committed"
        assert tuple(item.finding_id for item in result.findings) == (
            selected[0].finding_id,
            selected[1].finding_id,
        )
        assert result.findings[0].finding_id.encode() > result.findings[1].finding_id.encode()
        events = [row async for row in adapter.load_events(command.session_id)]
        recorded = next(row.payload for row in events if type(row.payload) is CheckRecordedPayload)
        assert recorded.returned_finding_ids == (
            selected[1].finding_id,
            selected[0].finding_id,
        )
        assert recorded.returned_finding_ids == tuple(
            sorted(recorded.returned_finding_ids, key=str.encode)
        )
        if semantic_lead:
            assert result.semantic_status is SemanticStatus.SUCCEEDED
            assert result.semantic_reason is SemanticReason.SEMANTIC_COMPLETED
            assert result.semantic_provenance is selected[0].provenance
            assert result.findings[0].origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
            assert result.findings[0].provenance is not None
            assert recorded.semantic_status is SemanticStatus.SUCCEEDED
            assert recorded.semantic_provenance is not None
        results.append(result)
    assert results[0].findings == results[1].findings
    assert results[0].verdict == results[1].verdict


@pytest.mark.anyio
async def test_sqlite_reopen_replays_ranked_order_after_canonical_set_commit() -> None:
    """Durable replay must restore rank order, not the stored ASCII set order."""

    command = ledger_command()
    adapter = sqlite_ledger(command)
    await adapter.append_batch(command)
    frozen = await _ready_case(
        adapter,
        command,
        "req_00000000-0000-4000-8000-00000000004c",
        "sha256:" + "c" * 64,
    )
    selected = _descending_rank_findings(
        frozen.case.frontier,
        command.entries[0].coverage,
        semantic_lead=True,
    )
    committed = await adapter.commit_check_if_current(
        frozen,
        RankedFindings(
            selected,
            0,
            CheckVerdict.ACTION_REQUIRED,
            command.entries[0].coverage,
        ),
        (CheckPolicyExecution("work-integrity", "0.1.0", "run", "completed"),),
        SemanticStatus.SUCCEEDED,
        SemanticReason.SEMANTIC_COMPLETED,
        selected[0].provenance,
        frozen.lease.operation_id,
    )
    assert tuple(item.finding_id for item in committed.findings) == (
        selected[0].finding_id,
        selected[1].finding_id,
    )

    restarted = SqliteLedger(
        db=adapter._db,  # pyright: ignore[reportPrivateUsage]
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=adapter._clock,  # pyright: ignore[reportPrivateUsage]
        ids=adapter._ids,  # pyright: ignore[reportPrivateUsage]
        objects=adapter._objects,  # pyright: ignore[reportPrivateUsage]
    )
    replayed = await restarted.freeze_case(
        command.session_id,
        command.writer_id,
        1,
        frozen.lease.operation_id,
        "sha256:" + "c" * 64,
    )
    assert type(replayed) is CheckCommitResult
    assert replayed.outcome == "replayed"
    assert tuple(item.finding_id for item in replayed.findings) == (
        selected[0].finding_id,
        selected[1].finding_id,
    )
    assert replayed.findings[0].origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    assert replayed.findings[0].provenance is not None
    assert replayed.semantic_status is SemanticStatus.SUCCEEDED
    assert replayed.semantic_provenance is not None


@pytest.mark.anyio
async def test_named_missing_items_commit_as_check_recorded_1_4_and_replay_after_restart() -> None:
    """Issue #907: both ledgers record the structural items and a restart replays them."""

    items = (
        MissingForAssessmentItem("command_identity", (), "structurally_unavailable_on_this_host"),
    )
    for adapter_factory in (memory_ledger, sqlite_ledger):
        command = ledger_command()
        adapter = adapter_factory(command)
        await adapter.append_batch(command)
        frozen = await _ready_case(
            adapter,
            command,
            "req_00000000-0000-4000-8000-00000000004d",
            "sha256:" + "d" * 64,
        )
        provenance = _descending_rank_findings(
            frozen.case.frontier, command.entries[0].coverage, semantic_lead=True
        )[0].provenance
        committed = await adapter.commit_check_if_current(
            frozen,
            RankedFindings((), 0, CheckVerdict.INSUFFICIENT_COVERAGE, command.entries[0].coverage),
            (CheckPolicyExecution("work-integrity", "0.1.0", "run", "completed"),),
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            provenance,
            frozen.lease.operation_id,
            semantic_conclusion="insufficient_packet",
            missing_for_assessment=items,
        )
        assert committed.missing_for_assessment == items
        events = [row async for row in adapter.load_events(command.session_id)]
        # Totals now accompany every completed check, so the conclusion rides on 1.4.0.
        assert [row.schema.version for row in events if row.schema.name == "check_recorded"] == [
            "1.4.0"
        ]
        stored = await adapter.load_projection(
            command.session_id, ProjectionView.CANDIDATE_FINDINGS
        )
        assert stored is not None and type(stored.state) is ProjectionState
        pending = stored.state.pending_missing_for_assessment
        assert pending is not None and pending.items == items
    assert type(adapter) is SqliteLedger
    restarted = SqliteLedger(
        db=adapter._db,  # pyright: ignore[reportPrivateUsage]
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=adapter._clock,  # pyright: ignore[reportPrivateUsage]
        ids=adapter._ids,  # pyright: ignore[reportPrivateUsage]
        objects=adapter._objects,  # pyright: ignore[reportPrivateUsage]
    )
    replayed = await restarted.freeze_case(
        command.session_id,
        command.writer_id,
        1,
        frozen.lease.operation_id,
        "sha256:" + "d" * 64,
    )
    assert type(replayed) is CheckCommitResult
    assert replayed.outcome == "replayed"
    assert replayed.missing_for_assessment == items


@pytest.mark.anyio
async def test_frozen_case_names_hook_events_recorded_after_a_missing_item_request() -> None:
    """Issue #907: hook capture after an ``insufficient_packet`` request is never the answer.

    Authorship is a service-stamped envelope fact the projection does not keep, so the frozen
    case carries the observation-authored events recorded after the pending request, in both
    ledgers and through the persisted case JSON.
    """

    items = (MissingForAssessmentItem("verification_output", (), "agent_suppliable"),)
    for adapter_factory in (memory_ledger, sqlite_ledger):
        # The unknown-family vector freezes cleanly after a hook ingest in both test adapters.
        command = ledger_command(unknown=True)
        adapter = adapter_factory(command)
        await adapter.append_batch(command)
        frozen = await _ready_case(
            adapter,
            command,
            "req_00000000-0000-4000-8000-00000000004e",
            "sha256:" + "e" * 64,
        )
        assert frozen.case.observation_event_ids == frozenset()
        provenance = _descending_rank_findings(
            frozen.case.frontier, command.entries[0].coverage, semantic_lead=True
        )[0].provenance
        committed = await adapter.commit_check_if_current(
            frozen,
            RankedFindings((), 0, CheckVerdict.INSUFFICIENT_COVERAGE, command.entries[0].coverage),
            (CheckPolicyExecution("work-integrity", "0.1.0", "run", "completed"),),
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            provenance,
            frozen.lease.operation_id,
            semantic_conclusion="insufficient_packet",
            missing_for_assessment=items,
        )
        hook = _observation_command(
            request_suffix="5", expected_frontier=committed.result_frontier.sequence, seed="c"
        )
        drained = await adapter.append_batch(hook)
        refrozen = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            drained.result_frontier.sequence,
            "req_00000000-0000-4000-8000-00000000004f",
            "sha256:" + "f" * 64,
        )
        assert isinstance(refrozen, FrozenCase)
        pending = refrozen.case.projection.pending_missing_for_assessment
        assert pending is not None and pending.items == items
        assert refrozen.case.observation_event_ids == frozenset({hook.entries[0].draft.event_id})
        encoded = deterministic_case_to_json(refrozen.case)
        assert encoded["observation_event_ids"] == [str(hook.entries[0].draft.event_id)]
        assert deterministic_case_from_json(encoded) == refrozen.case


@pytest.mark.anyio
async def test_an_itemless_insufficient_packet_keeps_the_pending_request_on_both_ledgers() -> None:
    """Greptile P1 on #940: a later insufficient_packet that recorded no item (a reply that named
    nothing) assessed nothing, so both ledgers keep the earlier request, and SQLite replays it."""

    items = (MissingForAssessmentItem("verification_output", (), "agent_suppliable"),)
    pending_by_adapter: list[object] = []
    for adapter_factory in (memory_ledger, sqlite_ledger):
        command = ledger_command()
        adapter = adapter_factory(command)
        await adapter.append_batch(command)
        coverage = command.entries[0].coverage
        ranked = RankedFindings((), 0, CheckVerdict.INSUFFICIENT_COVERAGE, coverage)
        executions = (CheckPolicyExecution("work-integrity", "0.1.0", "run", "completed"),)
        first = await _ready_case(
            adapter,
            command,
            "req_00000000-0000-4000-8000-000000000051",
            "sha256:" + "5" * 64,
        )
        provenance = _descending_rank_findings(first.case.frontier, coverage, semantic_lead=True)[
            0
        ].provenance
        requested = await adapter.commit_check_if_current(
            first,
            ranked,
            executions,
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            provenance,
            first.lease.operation_id,
            semantic_conclusion="insufficient_packet",
            missing_for_assessment=items,
        )
        again = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            requested.result_frontier.sequence,
            "req_00000000-0000-4000-8000-000000000052",
            "sha256:" + "6" * 64,
        )
        assert type(again) is FrozenCase
        lease = await adapter.advance_check_phase(
            again.lease,
            CheckPhase.RESERVED,
            CheckPhase.LOCAL_READY,
            await _local_result_ref(adapter, command),
        )
        lease = await adapter.advance_check_phase(
            lease, CheckPhase.LOCAL_READY, CheckPhase.READY_TO_FINALIZE
        )
        await adapter.commit_check_if_current(
            FrozenCase(again.case, lease),
            ranked,
            executions,
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            provenance,
            again.lease.operation_id,
            semantic_conclusion="insufficient_packet",
        )
        stored = await adapter.load_projection(
            command.session_id, ProjectionView.CANDIDATE_FINDINGS
        )
        assert stored is not None and type(stored.state) is ProjectionState
        pending = stored.state.pending_missing_for_assessment
        assert pending is not None and pending.items == items
        assert pending.source_frontier == requested.result_frontier.sequence
        pending_by_adapter.append(pending)
    assert pending_by_adapter[0] == pending_by_adapter[1]
    assert type(adapter) is SqliteLedger
    restarted = SqliteLedger(
        db=adapter._db,  # pyright: ignore[reportPrivateUsage]
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=adapter._clock,  # pyright: ignore[reportPrivateUsage]
        ids=adapter._ids,  # pyright: ignore[reportPrivateUsage]
        objects=adapter._objects,  # pyright: ignore[reportPrivateUsage]
    )
    replayed = await restarted.load_projection(
        command.session_id, ProjectionView.CANDIDATE_FINDINGS
    )
    assert replayed is not None and type(replayed.state) is ProjectionState
    assert replayed.state.pending_missing_for_assessment == pending_by_adapter[1]


@pytest.mark.anyio
async def test_check_change_shown_files_replay_to_the_same_raise_facts_in_both_ledgers() -> None:
    """ADR-031: the raising check's shown files reach the finding row identically on replay."""

    files = CheckChangeShownFiles(
        ("hmac-sha256:" + "1" * 64, "hmac-sha256:" + "2" * 64),
        (CheckChangePartialFile("hmac-sha256:" + "3" * 64, 2_048, 1, True, 67),),
        complete=True,
    )
    command = ledger_command()
    snapshots: list[JsonValue] = []
    memory = memory_ledger(command)
    sqlite = sqlite_ledger(command)
    for adapter in (memory, sqlite):
        await adapter.append_batch(command)
        frozen = await _ready_case(
            adapter,
            command,
            "req_00000000-0000-4000-8000-00000000004d",
            "sha256:" + "d" * 64,
        )
        selected = _descending_rank_findings(
            frozen.case.frontier, command.entries[0].coverage, semantic_lead=True
        )
        await adapter.commit_check_if_current(
            frozen,
            RankedFindings(selected, 0, CheckVerdict.ACTION_REQUIRED, command.entries[0].coverage),
            (CheckPolicyExecution("work-integrity", "0.1.0", "run", "completed"),),
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            selected[0].provenance,
            frozen.lease.operation_id,
            semantic_conclusion="challenges_returned",
            check_change_files=files,
        )
        checks = [
            row
            async for row in adapter.load_events(command.session_id)
            if row.schema.name == "check_recorded"
        ]
        assert [row.schema.version for row in checks] == ["1.4.0"]
        payload = checks[0].payload
        assert isinstance(payload, CheckRecordedPayload) and payload.check_change_files == files
        stored = await adapter.load_projection(
            command.session_id, ProjectionView.CANDIDATE_FINDINGS
        )
        assert stored is not None and type(stored.state) is ProjectionState
        raised = stored.state.findings[selected[0].finding_id]
        assert raised.check_change_raising_check_event_ids == (checks[0].event_id,)
        assert raised.check_change_raised_files == files
        assert stored.state.findings[selected[1].finding_id].check_change_raised_files is None
        snapshots.append(projection_snapshot(stored.state))

    restarted = SqliteLedger(
        db=sqlite._db,  # pyright: ignore[reportPrivateUsage]
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=sqlite._clock,  # pyright: ignore[reportPrivateUsage]
        ids=sqlite._ids,  # pyright: ignore[reportPrivateUsage]
        objects=sqlite._objects,  # pyright: ignore[reportPrivateUsage]
    )
    replayed = await restarted.load_projection(
        command.session_id, ProjectionView.CANDIDATE_FINDINGS
    )
    assert replayed is not None and type(replayed.state) is ProjectionState
    snapshots.append(projection_snapshot(replayed.state))
    assert snapshots[0] == snapshots[1] == snapshots[2]


@pytest.mark.anyio
async def test_invalid_semantic_outcome_commits_and_does_not_poison_later_checks() -> None:
    """A designed provider-invalid outcome must be durable in both ledger adapters."""

    command = ledger_command()
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        frozen = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            "req_00000000-0000-4000-8000-000000000038",
            "sha256:" + "8" * 64,
        )
        assert type(frozen) is FrozenCase
        lease = await adapter.advance_check_phase(
            frozen.lease,
            CheckPhase.RESERVED,
            CheckPhase.LOCAL_READY,
            await _local_result_ref(adapter, command),
        )
        lease = await adapter.advance_check_phase(
            lease,
            CheckPhase.LOCAL_READY,
            CheckPhase.SEMANTIC_WAIT,
        )
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest="sha256:" + "7" * 64,
        )
        job = await adapter.enqueue_semantic_job(lease, "sha256:" + "7" * 64, case_ref)
        handle = await adapter.claim_semantic_job(lease, job.job_id)
        await adapter.record_attempt_outcome(
            handle,
            AttemptOutcome.FAILED,
            terminal_code=SemanticReason.RESPONSE_CONTENT_INVALID,
        )
        lease = await adapter.renew_leases(lease)
        lease = await adapter.advance_check_phase(
            lease,
            CheckPhase.SEMANTIC_WAIT,
            CheckPhase.READY_TO_FINALIZE,
        )
        provenance = SemanticProvenance(
            provider="fake",
            endpoint_profile_id="fake",
            endpoint_profile_version="1.0.0",
            model="fake/model",
            sdk_version="1.0.0",
            prompt_digest="sha256:" + "1" * 64,
            schema_digest="sha256:" + "2" * 64,
            policy_digest="sha256:" + "3" * 64,
            privacy_policy_digest="sha256:" + "4" * 64,
            sampling_params=SamplingParams(128),
            latency_ms=1,
            semantic_attempt_id=handle.attempt_id,
            dispatch_kind=SemanticDispatchKind.EXTERNAL,
            privacy_receipt_id="egr_00000000-0000-4000-8000-000000000038",
            status=SemanticStatus.INVALID,
            reason=SemanticReason.RESPONSE_CONTENT_INVALID,
            provider_request_id=handle.provider_request_id,
            failure_class=SemanticFailureClass.RESPONSE_CONTENT,
            egress_authorization_id="aut_00000000-0000-4000-8000-000000000038",
            request_commitment="hmac-sha256:" + "5" * 64,
        )
        ranked = RankedFindings(
            (),
            0,
            CheckVerdict.INCOMPLETE_CHECK,
            command.entries[0].coverage,
        )
        result = await adapter.commit_check_if_current(
            FrozenCase(frozen.case, lease),
            ranked,
            (CheckPolicyExecution("research-evidence", "0.1.0", "run", "completed"),),
            SemanticStatus.INVALID,
            SemanticReason.RESPONSE_CONTENT_INVALID,
            provenance,
            lease.operation_id,
        )
        assert result.semantic_status is SemanticStatus.INVALID
        assert result.semantic_reason is SemanticReason.RESPONSE_CONTENT_INVALID
        operation = await adapter.lookup_operation(command.writer_id, lease.operation_id)
        assert operation is not None
        assert operation.state.value == "complete"


@pytest.mark.anyio
async def test_failed_check_terminalization_replays_and_allows_a_fresh_check() -> None:
    command = ledger_command()
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        request_id = "req_00000000-0000-4000-8000-000000000058"
        request_digest = "sha256:" + "8" * 64
        frozen = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            request_id,
            request_digest,
        )
        assert type(frozen) is FrozenCase

        await adapter.fail_check_if_current(
            frozen.lease,
            PublicOperationError(
                PublicErrorCode.INTERNAL_ERROR,
                "The check failed internally.",
                False,
            ),
        )

        operation = await adapter.lookup_operation(command.writer_id, request_id)
        assert operation is not None
        assert operation.state.value == "complete"
        assert operation.phase is CheckPhase.TERMINAL
        with pytest.raises(PublicOperationError) as replayed:
            await adapter.freeze_case(
                command.session_id,
                command.writer_id,
                1,
                request_id,
                request_digest,
            )
        assert replayed.value.code is PublicErrorCode.INTERNAL_ERROR
        fresh = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            "req_00000000-0000-4000-8000-000000000059",
            "sha256:" + "9" * 64,
        )
        assert type(fresh) is FrozenCase


@pytest.mark.anyio
async def test_task_operation_lookup_recovers_a_unique_prior_writer() -> None:
    command = ledger_command()
    successor_writer = "wri_00000000-0000-4000-8000-000000000099"
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        owned = await adapter.lookup_task_operation(command.writer_id, command.operation_id)
        assert owned is not None
        assert owned.writer_id == command.writer_id
        inherited = await adapter.lookup_task_operation(successor_writer, command.operation_id)
        assert inherited is not None
        assert inherited.writer_id == command.writer_id


@pytest.mark.anyio
async def test_failed_check_terminalization_survives_sqlite_restart() -> None:
    command = ledger_command()
    first = sqlite_ledger(command)
    await first.append_batch(command)
    request_id = "req_00000000-0000-4000-8000-000000000068"
    request_digest = "sha256:" + "8" * 64
    frozen = await first.freeze_case(
        command.session_id,
        command.writer_id,
        1,
        request_id,
        request_digest,
    )
    assert type(frozen) is FrozenCase
    await first.fail_check_if_current(
        frozen.lease,
        PublicOperationError(
            PublicErrorCode.INTERNAL_ERROR,
            "The check failed internally.",
            False,
        ),
    )

    restarted = SqliteLedger(
        db=first._db,  # pyright: ignore[reportPrivateUsage]
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=first._clock,  # pyright: ignore[reportPrivateUsage]
        ids=first._ids,  # pyright: ignore[reportPrivateUsage]
        objects=first._objects,  # pyright: ignore[reportPrivateUsage]
    )
    with pytest.raises(PublicOperationError) as replayed:
        await restarted.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            request_id,
            request_digest,
        )
    assert replayed.value.code is PublicErrorCode.INTERNAL_ERROR


@pytest.mark.anyio
async def test_frontier_conflict_terminalization_survives_sqlite_restart() -> None:
    command = ledger_command()
    first = sqlite_ledger(command)
    await first.append_batch(command)

    async def ready(request_id: str, request_digest: str) -> FrozenCase:
        frozen = await first.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            request_id,
            request_digest,
        )
        assert type(frozen) is FrozenCase
        lease = await first.advance_check_phase(
            frozen.lease,
            CheckPhase.RESERVED,
            CheckPhase.LOCAL_READY,
            await _local_result_ref(first, command),
        )
        lease = await first.advance_check_phase(
            lease,
            CheckPhase.LOCAL_READY,
            CheckPhase.READY_TO_FINALIZE,
        )
        return FrozenCase(frozen.case, lease)

    winning = await ready(
        "req_00000000-0000-4000-8000-000000000078",
        "sha256:" + "7" * 64,
    )
    stale = await ready(
        "req_00000000-0000-4000-8000-000000000079",
        "sha256:" + "8" * 64,
    )
    ranked = RankedFindings(
        (),
        0,
        CheckVerdict.NO_ISSUE_DETECTED,
        command.entries[0].coverage,
    )
    executions = (CheckPolicyExecution("research-evidence", "0.1.0", "run", "completed"),)
    await first.commit_check_if_current(
        winning,
        ranked,
        executions,
        SemanticStatus.NOT_REQUESTED,
        SemanticReason.DETERMINISTIC_MODE,
        None,
        winning.lease.operation_id,
    )
    with pytest.raises(PublicOperationError) as conflicted:
        await first.commit_check_if_current(
            stale,
            ranked,
            executions,
            SemanticStatus.NOT_REQUESTED,
            SemanticReason.DETERMINISTIC_MODE,
            None,
            stale.lease.operation_id,
        )
    assert conflicted.value.code is PublicErrorCode.FRONTIER_CONFLICT

    restarted = SqliteLedger(
        db=first._db,  # pyright: ignore[reportPrivateUsage]
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=first._clock,  # pyright: ignore[reportPrivateUsage]
        ids=first._ids,  # pyright: ignore[reportPrivateUsage]
        objects=first._objects,  # pyright: ignore[reportPrivateUsage]
    )
    with pytest.raises(PublicOperationError) as replayed:
        await restarted.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            stale.lease.operation_id,
            "sha256:" + "8" * 64,
        )
    assert replayed.value.code is PublicErrorCode.FRONTIER_CONFLICT


@pytest.mark.anyio
async def test_semantic_attempt_selection_contract() -> None:
    command = ledger_command()
    selected: list[SelectedAttempt] = []
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        frozen = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            "req_00000000-0000-4000-8000-000000000008",
            "sha256:" + "8" * 64,
        )
        assert type(frozen) is FrozenCase
        lease = await adapter.advance_check_phase(
            frozen.lease,
            CheckPhase.RESERVED,
            CheckPhase.LOCAL_READY,
            await _local_result_ref(adapter, command),
        )
        lease = await adapter.advance_check_phase(
            lease,
            CheckPhase.LOCAL_READY,
            CheckPhase.SEMANTIC_WAIT,
        )
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest="sha256:" + "7" * 64,
        )
        job = await adapter.enqueue_semantic_job(lease, "sha256:" + "7" * 64, case_ref)
        handle = await adapter.claim_semantic_job(lease, job.job_id)
        response_ref = await _object_ref(adapter, command, ObjectKind.SEMANTIC_RESPONSE)
        await adapter.record_attempt_outcome(handle, AttemptOutcome.RESPONSE_DURABLE, response_ref)
        selected.append(await adapter.select_attempt(lease, handle, response_ref))
        loaded = await adapter.load_semantic_job(command.writer_id, frozen.lease.operation_id)
        assert loaded is not None
        assert loaded.selected_attempt_id == selected[-1].attempt_id
        attempts = await adapter.list_semantic_attempts(loaded.job_id)
        assert len(attempts) == 1
        assert attempts[0].state == "selected"
        assert attempts[0].attempt_id == selected[-1].attempt_id
    assert selected[0] == selected[1]


@pytest.mark.anyio
async def test_semantic_attempt_usage_survives_retry_and_sqlite_restart() -> None:
    """Every physical attempt keeps its bounded counters, including failed/retried rows."""

    command = ledger_command(request_suffix="b")
    usage_one = RuntimeTokenUsage(120, 60, 10, 30, 8, 150)
    usage_two = RuntimeTokenUsage(240, 120, 20, 40, 12, 280)
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        lease = await _semantic_wait_lease(
            adapter, command, "req_00000000-0000-4000-8000-0000000000bb"
        )
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest="sha256:" + "b" * 64,
        )
        job = await adapter.enqueue_semantic_job(lease, "sha256:" + "b" * 64, case_ref)
        first = await adapter.claim_semantic_job(lease, job.job_id)
        if isinstance(adapter, SqliteLedger):
            with pytest.raises(apsw.ConstraintError):
                adapter._db.execute(  # pyright: ignore[reportPrivateUsage]
                    "UPDATE semantic_attempts SET usage_total_tokens=1 WHERE attempt_id=?",
                    (first.attempt_id,),
                )
            with pytest.raises(apsw.ConstraintError):
                adapter._db.execute(  # pyright: ignore[reportPrivateUsage]
                    "UPDATE semantic_attempts SET usage_input_tokens=?,"
                    "usage_cached_input_tokens=?,usage_cache_write_input_tokens=?,"
                    "usage_output_tokens=?,usage_reasoning_output_tokens=?,"
                    "usage_total_tokens=? WHERE attempt_id=?",
                    (
                        usage_one.input_tokens,
                        usage_one.cached_input_tokens,
                        usage_one.cache_write_input_tokens,
                        usage_one.output_tokens,
                        usage_one.reasoning_output_tokens,
                        usage_one.total_tokens,
                        first.attempt_id,
                    ),
                )
        await adapter.record_attempt_outcome(
            first,
            AttemptOutcome.EXPIRED,
            terminal_code=SemanticReason.PROVIDER_TIMEOUT,
            token_usage=usage_one,
        )
        second = await adapter.claim_semantic_job(lease, job.job_id)
        await adapter.record_attempt_outcome(
            second,
            AttemptOutcome.FAILED,
            terminal_code=SemanticReason.TRANSPORT_UNAVAILABLE,
            token_usage=usage_two,
        )

        if isinstance(adapter, SqliteLedger):
            restarted = SqliteLedger(
                db=adapter._db,  # pyright: ignore[reportPrivateUsage]
                task_id=command.task_id,
                ownership_fence=_fence(),
                clock=adapter._clock,  # pyright: ignore[reportPrivateUsage]
                ids=adapter._ids,  # pyright: ignore[reportPrivateUsage]
                objects=adapter._objects,  # pyright: ignore[reportPrivateUsage]
            )
        else:
            restarted = adapter
        rows = await restarted.list_semantic_attempts(job.job_id)
        assert [(row.state, row.token_usage) for row in rows] == [
            ("expired", usage_one),
            ("failed", usage_two),
        ]


@pytest.mark.anyio
async def test_sqlite_recovery_with_queued_semantic_job_has_no_attempt_rows() -> None:
    """Recovery keeps a queued job valid when no physical attempt was claimed yet."""

    command = ledger_command(request_suffix="c")
    adapter = sqlite_ledger(command)
    await adapter.append_batch(command)
    lease = await _semantic_wait_lease(adapter, command, "req_00000000-0000-4000-8000-0000000000cc")
    case_ref = await _object_ref(
        adapter,
        command,
        ObjectKind.SEMANTIC_CASE,
        semantic_case_digest="sha256:" + "c" * 64,
    )
    job = await adapter.enqueue_semantic_job(lease, "sha256:" + "c" * 64, case_ref)
    restarted = SqliteLedger(
        db=adapter._db,  # pyright: ignore[reportPrivateUsage]
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=adapter._clock,  # pyright: ignore[reportPrivateUsage]
        ids=adapter._ids,  # pyright: ignore[reportPrivateUsage]
        objects=adapter._objects,  # pyright: ignore[reportPrivateUsage]
    )

    recovered = await restarted.load_semantic_job(command.writer_id, lease.operation_id)
    assert recovered is not None and recovered.job_id == job.job_id
    assert recovered.state == "queued"
    assert await restarted.list_semantic_attempts(job.job_id) == ()


@pytest.mark.anyio
async def test_sqlite_recovery_rehydrates_disclosure_wait_with_attempt() -> None:
    """Recovery restores the wait side table alongside its still-started attempt."""

    command = ledger_command(request_suffix="d")
    adapter = sqlite_ledger(command)
    await adapter.append_batch(command)
    lease = await _semantic_wait_lease(adapter, command, "req_00000000-0000-4000-8000-0000000000dd")
    case_ref = await _object_ref(
        adapter,
        command,
        ObjectKind.SEMANTIC_CASE,
        semantic_case_digest="sha256:" + "d" * 64,
    )
    job = await adapter.enqueue_semantic_job(lease, "sha256:" + "d" * 64, case_ref)
    handle = await adapter.claim_semantic_job(lease, job.job_id)
    expiry = datetime(2026, 7, 19, 12, 1, tzinfo=UTC)
    pending_id = "ppr_00000000-0000-4000-8000-0000000000dd"
    await adapter.record_disclosure_wait(handle, pending_id, expiry)
    restarted = SqliteLedger(
        db=adapter._db,  # pyright: ignore[reportPrivateUsage]
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=adapter._clock,  # pyright: ignore[reportPrivateUsage]
        ids=adapter._ids,  # pyright: ignore[reportPrivateUsage]
        objects=adapter._objects,  # pyright: ignore[reportPrivateUsage]
    )

    recovered = await restarted.load_semantic_job(command.writer_id, lease.operation_id)
    assert recovered is not None and recovered.job_id == job.job_id
    attempts = await restarted.list_semantic_attempts(job.job_id)
    assert len(attempts) == 1 and attempts[0].state == "started"
    wait = await restarted.load_disclosure_wait(command.writer_id, lease.operation_id)
    assert wait is not None
    assert wait.state == "awaiting" and wait.pending_id == pending_id


@pytest.mark.anyio
async def test_semantic_claim_resumes_same_started_attempt_for_owner() -> None:
    """Crash before authorization consumption resumes the same attempt identity."""

    command = ledger_command()
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        frozen = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            "req_00000000-0000-4000-8000-000000000018",
            "sha256:" + "8" * 64,
        )
        assert type(frozen) is FrozenCase
        lease = await adapter.advance_check_phase(
            frozen.lease,
            CheckPhase.RESERVED,
            CheckPhase.LOCAL_READY,
            await _local_result_ref(adapter, command),
        )
        lease = await adapter.advance_check_phase(
            lease,
            CheckPhase.LOCAL_READY,
            CheckPhase.SEMANTIC_WAIT,
        )
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest="sha256:" + "7" * 64,
        )
        job = await adapter.enqueue_semantic_job(lease, "sha256:" + "7" * 64, case_ref)
        first = await adapter.claim_semantic_job(lease, job.job_id)
        second = await adapter.claim_semantic_job(lease, job.job_id)
        assert first.attempt_id == second.attempt_id
        assert first.provider_request_id == second.provider_request_id
        assert first.attempt_ordinal == 1


@pytest.mark.anyio
async def test_expired_started_attempt_rebinds_once_in_each_real_ledger() -> None:
    """A successor lease rebinds one started attempt without creating a duplicate."""

    class _AdvancingClock:
        def __init__(self) -> None:
            self.now = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)

        def now_utc(self) -> datetime:
            return self.now

        def monotonic_seconds(self) -> float:
            return (self.now - datetime(2026, 7, 19, 12, 0, tzinfo=UTC)).total_seconds()

    command = ledger_command(request_suffix="9")
    request_id = "req_00000000-0000-4000-8000-000000000099"
    request_digest = "sha256:" + "7" * 64
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        lease = await _semantic_wait_lease(adapter, command, request_id)
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest="sha256:" + "7" * 64,
        )
        job = await adapter.enqueue_semantic_job(lease, "sha256:" + "7" * 64, case_ref)
        first = await adapter.claim_semantic_job(lease, job.job_id)

        clock = _AdvancingClock()
        adapter._clock = clock  # pyright: ignore[reportPrivateUsage]
        clock.now += timedelta(seconds=61)
        successor = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            request_id,
            request_digest,
        )
        assert type(successor) is FrozenCase
        current = await adapter.load_semantic_job(command.writer_id, request_id)
        assert current is not None
        second, concurrent = await asyncio.gather(
            adapter.claim_semantic_job(successor.lease, current.job_id),
            adapter.claim_semantic_job(successor.lease, current.job_id),
        )
        assert second.attempt_id == first.attempt_id
        assert second.provider_request_id == first.provider_request_id
        assert second.attempt_ordinal == 1
        assert concurrent.attempt_id == first.attempt_id
        assert concurrent.provider_request_id == first.provider_request_id

        rows = await adapter.list_semantic_attempts(current.job_id)
        assert [row.state for row in rows] == ["started"]

        # Repeating the claim while the successor lease is live resumes it, rather than minting
        # another provider request or changing the original successor identity.
        repeated = await adapter.claim_semantic_job(successor.lease, current.job_id)
        assert repeated.attempt_id == first.attempt_id
        assert repeated.provider_request_id == second.provider_request_id
        assert repeated.attempt_ordinal == 1
        assert len(await adapter.list_semantic_attempts(current.job_id)) == 1


@pytest.mark.anyio
async def test_semantic_lease_uses_persisted_deadline_and_rebinds_after_restart() -> None:
    """A v2 AI-powered review case extends one operation to its cap and preserves the started attempt."""

    class _AdvancingClock:
        def __init__(self) -> None:
            self.now = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)

        def now_utc(self) -> datetime:
            return self.now

        def monotonic_seconds(self) -> float:
            return (self.now - datetime(2026, 7, 19, 12, 0, tzinfo=UTC)).total_seconds()

    command = ledger_command(request_suffix="a")
    operation_id = "req_00000000-0000-4000-8000-0000000000aa"
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        clock = _AdvancingClock()
        adapter._clock = clock  # pyright: ignore[reportPrivateUsage]
        await adapter.append_batch(command)
        lease = await _semantic_wait_lease(adapter, command, operation_id)
        case_digest = "sha256:" + "a" * 64
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest=case_digest,
            semantic_case_with_fallback=True,
        )
        job = await adapter.enqueue_semantic_job(lease, case_digest, case_ref)

        # The old operation TTL is 60s; the persisted total execution deadline is 5 minutes,
        # so the first AI-powered review renewal must take the operation all the way to deadline + 5s.
        renewed = await adapter.renew_leases(lease)
        expected_expiry = datetime(2026, 7, 19, 12, 5, 5, tzinfo=UTC)
        assert renewed.lease_expires_at == expected_expiry
        queued = await adapter.load_semantic_job(command.writer_id, operation_id)
        assert queued is not None and queued.lease_expires_at is None

        first, second = await asyncio.gather(
            adapter.claim_semantic_job(renewed, job.job_id),
            adapter.claim_semantic_job(renewed, job.job_id),
        )
        assert first.attempt_id == second.attempt_id
        assert first.provider_request_id == second.provider_request_id
        assert first.lease_expires_at == expected_expiry

        # A provider dispatch may cross the former 60s TTL. Renewal keeps the same bounded
        # authority and updates the active job atomically rather than minting a new attempt.
        clock.now += timedelta(seconds=61)
        renewed_again = await adapter.renew_leases(renewed)
        assert renewed_again.lease_expires_at == expected_expiry
        active = await adapter.load_semantic_job(command.writer_id, operation_id)
        assert active is not None
        assert active.lease_expires_at == expected_expiry
        assert active.active_attempt_id == first.attempt_id

        current_adapter: MemoryLedgerAdapter | SqliteLedger = adapter
        if isinstance(adapter, SqliteLedger):
            restarted = SqliteLedger(
                db=adapter._db,  # pyright: ignore[reportPrivateUsage]
                task_id=command.task_id,
                ownership_fence=_fence(),
                clock=clock,
                ids=adapter._ids,  # pyright: ignore[reportPrivateUsage]
                objects=adapter._objects,  # pyright: ignore[reportPrivateUsage]
            )
            active = await restarted.load_semantic_job(command.writer_id, operation_id)
            assert active is not None
            resumed_lease = await restarted.renew_leases(renewed_again)
            assert resumed_lease.lease_expires_at == expected_expiry
            rebound = await restarted.claim_semantic_job(resumed_lease, active.job_id)
            current_adapter = restarted
        else:
            resumed_lease = renewed_again
            rebound = await adapter.claim_semantic_job(resumed_lease, job.job_id)
        assert rebound.attempt_id == first.attempt_id
        assert rebound.provider_request_id == first.provider_request_id
        assert len(await adapter.list_semantic_attempts(job.job_id)) == 1

        # Once the fixed cleanup grace has elapsed, renewal cannot create another lease.
        clock.now = expected_expiry + timedelta(seconds=1)
        with pytest.raises(PublicOperationError) as expired:
            await current_adapter.renew_leases(renewed_again)
        assert expired.value.code is PublicErrorCode.OPERATION_PENDING


@pytest.mark.anyio
async def test_short_semantic_execution_does_not_get_a_sixty_second_floor() -> None:
    """A short authenticated execution retains only its fixed cleanup grace."""

    class _AdvancingClock:
        def __init__(self) -> None:
            self.now = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)

        def now_utc(self) -> datetime:
            return self.now

        def monotonic_seconds(self) -> float:
            return (self.now - datetime(2026, 7, 19, 12, 0, tzinfo=UTC)).total_seconds()

    command = ledger_command(request_suffix="b")
    operation_id = "req_00000000-0000-4000-8000-0000000000ab"
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        clock = _AdvancingClock()
        adapter._clock = clock  # pyright: ignore[reportPrivateUsage]
        await adapter.append_batch(command)
        lease = await _semantic_wait_lease(adapter, command, operation_id)
        case_digest = "sha256:" + "b" * 64
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest=case_digest,
            semantic_case_primary_expires_at="2026-07-19T12:00:15.000Z",
            semantic_case_expires_at="2026-07-19T12:00:20.000Z",
        )
        job = await adapter.enqueue_semantic_job(lease, case_digest, case_ref)
        renewed = await adapter.renew_leases(lease)
        expected_expiry = datetime(2026, 7, 19, 12, 0, 25, tzinfo=UTC)
        assert renewed.lease_expires_at == expected_expiry
        handle = await adapter.claim_semantic_job(renewed, job.job_id)
        assert handle.lease_expires_at == expected_expiry

        clock.now += timedelta(seconds=26)
        with pytest.raises(PublicOperationError) as expired:
            await adapter.renew_leases(renewed)
        assert expired.value.code is PublicErrorCode.OPERATION_PENDING


@pytest.mark.anyio
@pytest.mark.parametrize("budget", [120, 900, 3600])
async def test_real_attempt_loop_crosses_old_lease_without_duplicate_dispatch(budget: int) -> None:
    """The shipped attempt loop dispatches once beyond 60s under the frozen AI-powered review cap."""

    from yoetz.application.semantic_attempts import run_durable_semantic_attempts
    from yoetz.ports.semantic import Deadline

    @dataclass(frozen=True, slots=True)
    class _Eval:
        status: SemanticStatus
        reason: SemanticReason
        judgment: object | None = None
        provenance: object | None = None

    class _AdvancingClock:
        def __init__(self) -> None:
            self.now = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)

        def now_utc(self) -> datetime:
            return self.now

        def monotonic_seconds(self) -> float:
            return (self.now - datetime(2026, 7, 19, 12, 0, tzinfo=UTC)).total_seconds()

    expiry = datetime(2026, 7, 19, 12, 0, tzinfo=UTC) + timedelta(seconds=budget)
    expiry_wire = expiry.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    command = ledger_command(request_suffix="c")
    operation_id = "req_00000000-0000-4000-8000-0000000000ac"
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        clock = _AdvancingClock()
        adapter._clock = clock  # pyright: ignore[reportPrivateUsage]
        await adapter.append_batch(command)
        lease = await _semantic_wait_lease(adapter, command, operation_id)
        case_digest = "sha256:" + "c" * 64
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest=case_digest,
            semantic_case_primary_expires_at=expiry_wire,
            semantic_case_expires_at=expiry_wire,
        )
        job = await adapter.enqueue_semantic_job(lease, case_digest, case_ref)
        dispatches: list[str] = []

        async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
            dispatches.append(handle.provider_request_id)
            assert deadline.monotonic_deadline == float(budget)
            clock.now += timedelta(seconds=budget * 0.75)
            return _Eval(SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED)

        async def publish(_handle: SemanticAttemptHandle, _evaluation: object) -> ObjectRef:
            return await _object_ref(adapter, command, ObjectKind.SEMANTIC_RESPONSE)

        def build_final(
            status: SemanticStatus,
            reason: SemanticReason,
            _evaluation: object | None,
            _accounting: object,
        ) -> object:
            return status, reason

        result = await run_durable_semantic_attempts(
            ledger=adapter,
            lease=lease,
            job=job,
            deadline=Deadline(expiry, float(budget)),
            max_retries=0,
            now_monotonic=clock.monotonic_seconds,
            dispatch=dispatch,
            publish_success_response=publish,
            build_final=build_final,
        )
        assert result == (SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED)
        assert len(dispatches) == 1
        loaded = await adapter.load_semantic_job(command.writer_id, operation_id)
        assert loaded is not None
        assert loaded.state == "succeeded"
        attempts = await adapter.list_semantic_attempts(loaded.job_id)
        assert len(attempts) == 1
        assert attempts[0].state == "selected"


@pytest.mark.anyio
@pytest.mark.parametrize("fault", ["missing", "wrong_envelope"], ids=["missing", "wrong_envelope"])
async def test_semantic_lease_rejects_unverifiable_case_without_mutation(fault: str) -> None:
    """A missing or mismatched case object cannot extend the operation lease."""

    command = ledger_command(request_suffix="d")
    operation_id = "req_00000000-0000-4000-8000-0000000000ad"
    case_digest = "sha256:" + "d" * 64
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        lease = await _semantic_wait_lease(adapter, command, operation_id)
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest=case_digest,
        )
        job = await adapter.enqueue_semantic_job(lease, case_digest, case_ref)
        before = await adapter.lookup_operation(command.writer_id, operation_id)
        assert before is not None
        objects = adapter._objects  # pyright: ignore[reportPrivateUsage]
        assert objects is not None
        if fault == "missing":
            cast(_Objects, objects)._refs.pop(case_ref.object_id)  # pyright: ignore[reportPrivateUsage]
        else:
            adapter._state.jobs[job.job_id] = replace(  # pyright: ignore[reportPrivateUsage]
                job,
                case_object_ref=replace(case_ref, envelope_digest="sha256:" + "e" * 64),
            )
        with pytest.raises(PublicOperationError) as caught:
            await adapter.renew_leases(lease)
        assert caught.value.code is PublicErrorCode.STORAGE_CORRUPT
        after = await adapter.lookup_operation(command.writer_id, operation_id)
        assert after == before


@pytest.mark.anyio
async def test_semantic_job_can_fail_terminally_without_fabricating_an_attempt() -> None:
    """A total deadline may expire while a job is queued, before any dispatch is claimed."""

    command = ledger_command()
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        frozen = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            "req_00000000-0000-4000-8000-000000000028",
            "sha256:" + "8" * 64,
        )
        assert type(frozen) is FrozenCase
        lease = await adapter.advance_check_phase(
            frozen.lease,
            CheckPhase.RESERVED,
            CheckPhase.LOCAL_READY,
            await _local_result_ref(adapter, command),
        )
        lease = await adapter.advance_check_phase(
            lease,
            CheckPhase.LOCAL_READY,
            CheckPhase.SEMANTIC_WAIT,
        )
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest="sha256:" + "6" * 64,
        )
        job = await adapter.enqueue_semantic_job(lease, "sha256:" + "6" * 64, case_ref)
        failed = await adapter.fail_semantic_job(
            lease,
            job.job_id,
            SemanticReason.PROVIDER_TIMEOUT,
        )
        assert failed.state == "failed"
        assert failed.attempt_count == 0
        assert failed.terminal_code is SemanticReason.PROVIDER_TIMEOUT
        assert await adapter.list_semantic_attempts(job.job_id) == ()


@pytest.mark.anyio
async def test_semantic_lifecycle_timestamps_survive_later_syncs() -> None:
    """Durable job/attempt timestamps must record when things happened, not when we last synced.

    Every ``_sync_runtime_state`` rewrote ``created_at`` / ``started_at`` / ``terminal_at`` to the
    current clock for *every* job and attempt, so the stranded 2026-07-30 rows showed a claim time
    later than the failure that caused them. Reconstructing a durable lifecycle from rows that get
    restamped on unrelated writes is not possible, which is exactly what recovery needs to do.
    """

    command = ledger_command()

    class _AdvancingClock:
        """A clock that moves, so identical timestamps prove preservation rather than a fixed clock.

        With the suite's fixed clock every write stamps the same instant, so a test asserting
        "created_at is unchanged" would pass even with the original rewrite-everything-to-now
        behaviour. Advancing time is what makes the assertion mean something.
        """

        def __init__(self) -> None:
            self._ticks = 0

        def now_utc(self) -> datetime:
            self._ticks += 1
            return datetime(2026, 7, 19, 12, 0, tzinfo=UTC) + timedelta(seconds=self._ticks)

        def monotonic_seconds(self) -> float:
            return float(self._ticks)

    db = apsw.Connection(":memory:")
    initialize_bundle(
        db,
        {
            "task_id": command.task_id,
            "owner_generation": "1",
            "owner_nonce": "ledger-test-nonce",
        },
    )
    ids = _Ids()
    adapter = SqliteLedger(
        db=db,
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=_AdvancingClock(),
        ids=ids,
        objects=_Objects(ids),
    )
    await adapter.append_batch(command)
    frozen = await adapter.freeze_case(
        command.session_id,
        command.writer_id,
        1,
        "req_00000000-0000-4000-8000-000000000012",
        "sha256:" + "c" * 64,
    )
    assert type(frozen) is FrozenCase
    lease = await adapter.advance_check_phase(
        frozen.lease,
        CheckPhase.RESERVED,
        CheckPhase.LOCAL_READY,
        await _local_result_ref(adapter, command),
    )
    lease = await adapter.advance_check_phase(
        lease, CheckPhase.LOCAL_READY, CheckPhase.SEMANTIC_WAIT
    )
    case_ref = await _object_ref(
        adapter,
        command,
        ObjectKind.SEMANTIC_CASE,
        semantic_case_digest="sha256:" + "d" * 64,
    )
    job = await adapter.enqueue_semantic_job(lease, "sha256:" + "d" * 64, case_ref)
    handle = await adapter.claim_semantic_job(lease, job.job_id)

    def _row(table: str, column: str, key: str) -> str:
        key_column = "job_id" if table == "semantic_jobs" else "attempt_id"
        cursor = adapter._db.execute(  # pyright: ignore[reportPrivateUsage]
            f"SELECT {column} FROM {table} WHERE {key_column}=?", (key,)
        )
        value = next(iter(cursor))[0]
        assert type(value) is str
        return value

    created_at = _row("semantic_jobs", "created_at", job.job_id)
    started_at = _row("semantic_attempts", "started_at", handle.attempt_id)

    # An unrelated durable write drives another full runtime sync.
    await adapter.record_attempt_outcome(
        handle, AttemptOutcome.FAILED, terminal_code=SemanticReason.COORDINATOR_FAILURE
    )
    terminal_at = _row("semantic_attempts", "terminal_at", handle.attempt_id)
    assert _row("semantic_jobs", "created_at", job.job_id) == created_at
    assert _row("semantic_attempts", "started_at", handle.attempt_id) == started_at

    await adapter.renew_leases(lease)
    assert _row("semantic_jobs", "created_at", job.job_id) == created_at
    assert _row("semantic_attempts", "started_at", handle.attempt_id) == started_at
    # Terminal instants are stamped once, never dragged forward by a later sync either.
    assert _row("semantic_attempts", "terminal_at", handle.attempt_id) == terminal_at


@pytest.mark.anyio
async def test_raising_dispatch_strands_nothing_in_either_real_ledger() -> None:
    """The attempt loop must leave no leased job or started attempt, against real adapters.

    Every existing attempt-loop test drives a hand-written fake ledger, so the invariant that
    actually failed in production — durable rows left mid-flight after a raise — was only ever
    asserted against a stand-in for the thing that holds them. This runs the real loop against
    both shipped adapters.
    """

    from yoetz.application.semantic_attempts import (
        SemanticAttemptAccounting,
        run_durable_semantic_attempts,
    )
    from yoetz.ports.semantic import Deadline

    @dataclass(frozen=True, slots=True)
    class _Eval:
        """Satisfies the dispatch return protocol; never actually constructed here."""

        status: SemanticStatus
        reason: SemanticReason
        judgment: object | None = None
        provenance: object | None = None

    for factory in (memory_ledger, sqlite_ledger):
        command = ledger_command()
        adapter = factory(command)
        await adapter.append_batch(command)
        frozen = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            "req_00000000-0000-4000-8000-000000000013",
            "sha256:" + "e" * 64,
        )
        assert type(frozen) is FrozenCase
        lease = await adapter.advance_check_phase(
            frozen.lease,
            CheckPhase.RESERVED,
            CheckPhase.LOCAL_READY,
            await _local_result_ref(adapter, command),
        )
        lease = await adapter.advance_check_phase(
            lease, CheckPhase.LOCAL_READY, CheckPhase.SEMANTIC_WAIT
        )
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest="sha256:" + "f" * 64,
        )
        job = await adapter.enqueue_semantic_job(lease, "sha256:" + "f" * 64, case_ref)

        async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
            raise ValueError("semantic_case_envelope_too_large")

        async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
            raise AssertionError("publish_must_not_run")

        def build_final(
            status: SemanticStatus,
            reason: SemanticReason,
            evaluation: object | None,
            accounting: SemanticAttemptAccounting,
        ) -> object:
            return (status, reason)

        outcome = await run_durable_semantic_attempts(
            ledger=adapter,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1_000.0),
            max_retries=2,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=publish,
            build_final=build_final,
        )
        assert outcome == (SemanticStatus.FAILED, SemanticReason.COORDINATOR_FAILURE)

        loaded = await adapter.load_semantic_job(command.writer_id, frozen.lease.operation_id)
        assert loaded is not None
        assert loaded.state == "failed"
        assert loaded.active_attempt_id is None
        attempts = await adapter.list_semantic_attempts(loaded.job_id)
        assert [row.state for row in attempts] == ["failed"]


@pytest.mark.anyio
async def test_expired_started_attempt_gets_local_cleanup_without_provider_dispatch() -> None:
    """A reclaimed operation can close stale local state after the provider deadline only."""

    from yoetz.application.semantic_attempts import run_durable_semantic_attempts
    from yoetz.ports.semantic import Deadline

    class _AdvancingClock:
        def __init__(self) -> None:
            self.now = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)

        def now_utc(self) -> datetime:
            return self.now

        def monotonic_seconds(self) -> float:
            return (self.now - datetime(2026, 7, 19, 12, 0, tzinfo=UTC)).total_seconds()

    @dataclass(frozen=True, slots=True)
    class _Eval:
        status: SemanticStatus
        reason: SemanticReason
        judgment: object | None = None
        provenance: object | None = None

    command = ledger_command(request_suffix="e")
    operation_id = "req_00000000-0000-4000-8000-0000000000ae"
    case_digest = "sha256:" + "e" * 64
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        clock = _AdvancingClock()
        adapter._clock = clock  # pyright: ignore[reportPrivateUsage]
        await adapter.append_batch(command)
        lease = await _semantic_wait_lease(adapter, command, operation_id)
        case_ref = await _object_ref(
            adapter, command, ObjectKind.SEMANTIC_CASE, semantic_case_digest=case_digest
        )
        job = await adapter.enqueue_semantic_job(lease, case_digest, case_ref)
        first = await adapter.claim_semantic_job(lease, job.job_id)

        # The v2 case expires at 12:05, with only five seconds of local cleanup grace. Reclaim
        # the operation after both the provider deadline and that grace have elapsed.
        clock.now += timedelta(seconds=306)
        reclaimed = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            operation_id,
            "sha256:" + "7" * 64,
        )
        assert type(reclaimed) is FrozenCase
        current = await adapter.load_semantic_job(command.writer_id, operation_id)
        assert current is not None

        dispatches: list[str] = []

        async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
            dispatches.append(handle.provider_request_id)
            raise AssertionError("provider_dispatch_after_frozen_deadline")

        async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
            raise AssertionError("publish_after_frozen_deadline")

        def build_final(
            status: SemanticStatus,
            reason: SemanticReason,
            evaluation: object | None,
            accounting: object,
        ) -> object:
            return status, reason

        outcome = await run_durable_semantic_attempts(
            ledger=adapter,
            lease=reclaimed.lease,
            job=current,
            deadline=Deadline(datetime(2026, 7, 19, 12, 5, tzinfo=UTC), 300.0),
            max_retries=0,
            now_monotonic=clock.monotonic_seconds,
            dispatch=dispatch,
            publish_success_response=publish,
            build_final=build_final,
        )
        assert outcome == (SemanticStatus.UNAVAILABLE, SemanticReason.OUTCOME_UNKNOWN)
        assert dispatches == []
        loaded = await adapter.load_semantic_job(command.writer_id, operation_id)
        assert loaded is not None and loaded.state == "failed"
        attempts = await adapter.list_semantic_attempts(loaded.job_id)
        assert len(attempts) == 1
        assert attempts[0].attempt_id == first.attempt_id
        assert attempts[0].provider_request_id == first.provider_request_id
        assert attempts[0].terminal_code is SemanticReason.OUTCOME_UNKNOWN


@pytest.mark.anyio
async def test_response_durable_replay_selects_existing_response_without_new_dispatch() -> None:
    """A crash after response publication reuses and selects that exact response object."""

    from yoetz.application.semantic_attempts import run_durable_semantic_attempts
    from yoetz.ports.semantic import Deadline

    class _AdvancingClock:
        def __init__(self) -> None:
            self.now = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)

        def now_utc(self) -> datetime:
            return self.now

        def monotonic_seconds(self) -> float:
            return (self.now - datetime(2026, 7, 19, 12, 0, tzinfo=UTC)).total_seconds()

    @dataclass(frozen=True, slots=True)
    class _Eval:
        status: SemanticStatus
        reason: SemanticReason
        judgment: object | None = None
        provenance: object | None = None

    command = ledger_command(request_suffix="f")
    operation_id = "req_00000000-0000-4000-8000-0000000000af"
    case_digest = "sha256:" + "f" * 64
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        clock = _AdvancingClock()
        adapter._clock = clock  # pyright: ignore[reportPrivateUsage]
        await adapter.append_batch(command)
        lease = await _semantic_wait_lease(adapter, command, operation_id)
        case_ref = await _object_ref(
            adapter, command, ObjectKind.SEMANTIC_CASE, semantic_case_digest=case_digest
        )
        job = await adapter.enqueue_semantic_job(lease, case_digest, case_ref)
        first = await adapter.claim_semantic_job(lease, job.job_id)
        response_ref = await _object_ref(adapter, command, ObjectKind.SEMANTIC_RESPONSE)
        await adapter.record_attempt_outcome(first, AttemptOutcome.RESPONSE_DURABLE, response_ref)

        # Let the operation lease expire while retaining the response-durable row, then replay
        # through the normal frozen-case recovery path. This is the crash window before select.
        clock.now += timedelta(seconds=61)
        reclaimed = await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            operation_id,
            "sha256:" + "7" * 64,
        )
        assert type(reclaimed) is FrozenCase
        current = await adapter.load_semantic_job(command.writer_id, operation_id)
        assert current is not None
        recovered = _Eval(SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED)
        dispatches: list[str] = []

        async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
            dispatches.append(handle.provider_request_id)
            raise AssertionError("response_durable_replay_dispatched_provider")

        async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
            raise AssertionError("response_durable_replay_published_duplicate")

        async def recover_selected(row: SemanticJobRecord) -> _Eval:
            assert row.state == "succeeded"
            assert row.selected_result_object_ref == response_ref
            return recovered

        def build_final(
            status: SemanticStatus,
            reason: SemanticReason,
            evaluation: object | None,
            accounting: object,
        ) -> object:
            return status, reason, evaluation

        outcome = await run_durable_semantic_attempts(
            ledger=adapter,
            lease=reclaimed.lease,
            job=current,
            deadline=Deadline(datetime(2026, 7, 19, 12, 5, tzinfo=UTC), 300.0),
            max_retries=0,
            now_monotonic=clock.monotonic_seconds,
            dispatch=dispatch,
            publish_success_response=publish,
            build_final=build_final,
            recover_selected=recover_selected,
        )
        assert outcome == (
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            recovered,
        )
        assert dispatches == []
        loaded = await adapter.load_semantic_job(command.writer_id, operation_id)
        assert loaded is not None
        assert loaded.state == "succeeded"
        assert loaded.selected_result_object_ref == response_ref
        attempts = await adapter.list_semantic_attempts(loaded.job_id)
        assert len(attempts) == 1
        assert attempts[0].attempt_id == first.attempt_id
        assert attempts[0].provider_request_id == first.provider_request_id
        assert attempts[0].state == "selected"


@pytest.mark.anyio
async def test_sqlite_reclaim_persistence_failure_does_not_adopt_clone() -> None:
    """A failed SQLite reclaim transaction leaves the shared oracle and DB unchanged."""

    command = ledger_command(request_suffix="0")
    operation_id = "req_00000000-0000-4000-8000-0000000000b0"
    adapter = sqlite_ledger(command)
    await adapter.append_batch(command)
    await _semantic_wait_lease(adapter, command, operation_id)
    before = await adapter.lookup_operation(command.writer_id, operation_id)
    assert before is not None and before.lease_expires_at is not None
    expiry = before.lease_expires_at

    class _ReclaimClock:
        def now_utc(self) -> datetime:
            return expiry + timedelta(seconds=1)

        def monotonic_seconds(self) -> float:
            return 61.0

    adapter._clock = _ReclaimClock()  # pyright: ignore[reportPrivateUsage]
    prior_state = adapter._state  # pyright: ignore[reportPrivateUsage]
    original_persist = adapter._persist_derived_records  # pyright: ignore[reportPrivateUsage]

    def fail_persist(records: tuple[object, ...]) -> None:
        del records
        raise RuntimeError("test_reclaim_persist_failure")

    adapter._persist_derived_records = fail_persist  # pyright: ignore[reportPrivateUsage,method-assign]
    with pytest.raises(RuntimeError, match="test_reclaim_persist_failure"):
        await adapter.reclaim_operation(
            command.writer_id,
            operation_id,
            "sha256:" + "7" * 64,
        )
    adapter._persist_derived_records = original_persist  # pyright: ignore[reportPrivateUsage,method-assign]
    assert adapter._state is prior_state  # pyright: ignore[reportPrivateUsage]
    after = await adapter.lookup_operation(command.writer_id, operation_id)
    assert after == before


def _restarted_sqlite(adapter: SqliteLedger, command: AppendCommand) -> SqliteLedger:
    return SqliteLedger(
        db=adapter._db,  # pyright: ignore[reportPrivateUsage]
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=adapter._clock,  # pyright: ignore[reportPrivateUsage]
        ids=adapter._ids,  # pyright: ignore[reportPrivateUsage]
        objects=adapter._objects,  # pyright: ignore[reportPrivateUsage]
    )


@pytest.mark.anyio
async def test_semantic_progress_is_monotonic_durable_and_ends_in_one_terminal_state() -> None:
    """Issue #571 A2: phases only move forward, survive restart, and terminate exactly once."""

    command = ledger_command(request_suffix="d")
    operation_id = "req_00000000-0000-4000-8000-0000000000dd"
    queued_at = datetime(2026, 7, 19, 11, 59, tzinfo=UTC)
    deadline_at = queued_at + timedelta(minutes=15)
    observed: list[tuple[object, ...]] = []
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        lease = await _semantic_wait_lease(adapter, command, operation_id)
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest="sha256:" + "d" * 64,
        )
        job = await adapter.enqueue_semantic_job(lease, "sha256:" + "d" * 64, case_ref)
        assert await adapter.load_semantic_progress(command.writer_id, operation_id) is None

        await adapter.begin_semantic_progress(job.job_id, queued_at, deadline_at)
        # A replayed begin never restarts the elapsed-time origin or moves the deadline.
        await adapter.begin_semantic_progress(
            job.job_id, queued_at + timedelta(minutes=1), deadline_at + timedelta(hours=1)
        )
        queued = await adapter.load_semantic_progress(command.writer_id, operation_id)
        assert queued == SemanticProgressRecord(
            job.job_id, 0, SemanticProgressPhase.QUEUED, queued_at, queued_at, deadline_at
        )

        first = await adapter.claim_semantic_job(lease, job.job_id)
        at = queued_at + timedelta(seconds=1)
        assert await adapter.advance_semantic_progress(first, SemanticProgressPhase.QUEUED, at)
        assert await adapter.advance_semantic_progress(
            first, SemanticProgressPhase.CASE_ADMITTED, at + timedelta(seconds=1)
        )
        assert await adapter.advance_semantic_progress(
            first, SemanticProgressPhase.PROVIDER_SAMPLING, at + timedelta(seconds=2)
        )
        # Regressions and repeats are ignored; the recorded phase never moves backward.
        assert not await adapter.advance_semantic_progress(
            first, SemanticProgressPhase.RUNTIME_STARTING, at + timedelta(seconds=3)
        )
        assert not await adapter.advance_semantic_progress(
            first, SemanticProgressPhase.PROVIDER_SAMPLING, at + timedelta(seconds=4)
        )
        with pytest.raises(PublicOperationError):
            await adapter.advance_semantic_progress(
                first, SemanticProgressPhase.TERMINAL, at + timedelta(seconds=5)
            )
        sampling = await adapter.load_semantic_progress(command.writer_id, operation_id)
        assert sampling is not None
        assert (sampling.attempt_ordinal, sampling.phase, sampling.phase_entered_at) == (
            1,
            SemanticProgressPhase.PROVIDER_SAMPLING,
            at + timedelta(seconds=2),
        )
        if isinstance(adapter, SqliteLedger):
            restarted = _restarted_sqlite(adapter, command)
            assert await restarted.load_semantic_progress(command.writer_id, operation_id) == (
                sampling
            )

        await adapter.record_attempt_outcome(
            first, AttemptOutcome.EXPIRED, terminal_code=SemanticReason.TRANSPORT_UNAVAILABLE
        )
        second = await adapter.claim_semantic_job(lease, job.job_id)
        # A superseded attempt can no longer write; the next attempt restarts at queued.
        assert not await adapter.advance_semantic_progress(
            first, SemanticProgressPhase.CLEANUP, at + timedelta(seconds=6)
        )
        assert await adapter.advance_semantic_progress(
            second, SemanticProgressPhase.QUEUED, at + timedelta(seconds=7)
        )
        retry = await adapter.load_semantic_progress(command.writer_id, operation_id)
        assert retry is not None
        assert (retry.attempt_ordinal, retry.phase) == (2, SemanticProgressPhase.QUEUED)

        await adapter.record_attempt_outcome(
            second, AttemptOutcome.FAILED, terminal_code=SemanticReason.PROVIDER_TIMEOUT
        )
        # A failed final attempt terminalizes the job in the same durable write.
        terminal_job = await adapter.load_semantic_job(command.writer_id, operation_id)
        assert terminal_job is not None and terminal_job.state == "failed"
        assert terminal_job.terminal_at is not None
        terminal = await adapter.load_semantic_progress(command.writer_id, operation_id)
        assert terminal is not None
        assert terminal.phase is SemanticProgressPhase.TERMINAL
        assert terminal.terminal_outcome == "failed"
        assert terminal.terminal_reason is SemanticReason.PROVIDER_TIMEOUT
        assert terminal.attempt_ordinal == 2
        assert terminal.phase_entered_at == max(terminal_job.terminal_at, retry.phase_entered_at)
        # Nothing can follow the terminal state.
        assert not await adapter.advance_semantic_progress(
            second, SemanticProgressPhase.CLEANUP, at + timedelta(seconds=8)
        )
        await adapter.begin_semantic_progress(job.job_id, queued_at, deadline_at)
        assert await adapter.load_semantic_progress(command.writer_id, operation_id) == terminal

        await adapter.fail_check_if_current(
            lease,
            PublicOperationError(PublicErrorCode.INTERNAL_ERROR, "The check failed.", False),
        )
        if isinstance(adapter, SqliteLedger):
            # A completed operation's job is not reloaded into the oracle after restart, but
            # its terminal progress is still read from the durable rows.
            restarted = _restarted_sqlite(adapter, command)
            assert await restarted.load_semantic_progress(command.writer_id, operation_id) == (
                terminal
            )
            with pytest.raises(apsw.ConstraintError):
                adapter._db.execute(  # pyright: ignore[reportPrivateUsage]
                    "UPDATE semantic_progress SET phase='terminal' WHERE job_id=?",
                    (job.job_id,),
                )
            with pytest.raises(apsw.ConstraintError):
                adapter._db.execute(  # pyright: ignore[reportPrivateUsage]
                    "UPDATE semantic_progress SET phase_rank=5 WHERE job_id=?",
                    (job.job_id,),
                )
        observed.append(
            (
                terminal.attempt_ordinal,
                terminal.phase,
                terminal.queued_at,
                terminal.deadline_at,
                terminal.terminal_outcome,
                terminal.terminal_reason,
            )
        )
    assert observed[0] == observed[1]


@pytest.mark.anyio
async def test_semantic_progress_selected_attempt_terminates_as_succeeded() -> None:
    command = ledger_command(request_suffix="e")
    operation_id = "req_00000000-0000-4000-8000-0000000000ee"
    queued_at = datetime(2026, 7, 19, 11, 59, tzinfo=UTC)
    for adapter in (memory_ledger(command), sqlite_ledger(command)):
        await adapter.append_batch(command)
        lease = await _semantic_wait_lease(adapter, command, operation_id)
        case_ref = await _object_ref(
            adapter,
            command,
            ObjectKind.SEMANTIC_CASE,
            semantic_case_digest="sha256:" + "e" * 64,
        )
        job = await adapter.enqueue_semantic_job(lease, "sha256:" + "e" * 64, case_ref)
        await adapter.begin_semantic_progress(
            job.job_id, queued_at, queued_at + timedelta(minutes=15)
        )
        handle = await adapter.claim_semantic_job(lease, job.job_id)
        assert await adapter.advance_semantic_progress(
            handle, SemanticProgressPhase.RESPONSE_VALIDATION, queued_at + timedelta(seconds=40)
        )
        response_ref = await _object_ref(adapter, command, ObjectKind.SEMANTIC_RESPONSE)
        await adapter.record_attempt_outcome(handle, AttemptOutcome.RESPONSE_DURABLE, response_ref)
        await adapter.select_attempt(lease, handle, response_ref)
        progress = await adapter.load_semantic_progress(command.writer_id, operation_id)
        assert progress is not None
        assert progress.phase is SemanticProgressPhase.TERMINAL
        assert progress.terminal_outcome == "succeeded"
        assert progress.terminal_reason is SemanticReason.SEMANTIC_COMPLETED


async def _task_change_base_ref(
    adapter: MemoryLedgerAdapter | SqliteLedger, command: AppendCommand, commit: str
) -> ObjectRef:
    objects = adapter._objects  # pyright: ignore[reportPrivateUsage]
    assert objects is not None
    payload = encode_task_change_base(TaskChangeBase("sha1", commit))
    staged = await objects.stage(
        ObjectSource(data=payload, declared_size=len(payload)),
        ObjectMetadata(
            ObjectKind.CHANGE_CAPTURE,
            TASK_CHANGE_BASE_MEDIA_TYPE,
            command.task_id,
            datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
        ),
    )
    return await objects.finalize(staged)


@pytest.mark.anyio
async def test_task_change_base_is_kept_once_with_adapter_parity(tmp_path: Path) -> None:
    """ADR-031: the task-start base is one durable, inventoried root that a later call never moves."""

    command = ledger_command(request_suffix="9")
    database = tmp_path / "task-change-base.sqlite3"
    db = apsw.Connection(str(database))
    initialize_bundle(
        db,
        {
            "task_id": command.task_id,
            "owner_generation": "1",
            "owner_nonce": "ledger-test-nonce",
        },
    )
    sqlite_ids = _Ids()
    sqlite_objects = _Objects(sqlite_ids)
    sqlite = SqliteLedger(
        db=db,
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=_Clock(),
        ids=sqlite_ids,
        objects=sqlite_objects,
    )
    for adapter in (memory_ledger(command), sqlite):
        await adapter.append_batch(command)
        assert await adapter.load_task_change_base() is None
        first = await _task_change_base_ref(adapter, command, "a" * 40)
        later = await _task_change_base_ref(adapter, command, "b" * 40)
        assert await adapter.record_task_change_base(first) is True
        assert await adapter.record_task_change_base(later) is False
        assert await adapter.load_task_change_base() == first
        wrong_kind = replace(
            later, metadata=replace(later.metadata, kind=ObjectKind.CAPTURED_CONTENT)
        )
        with pytest.raises(ValueError, match="task_change_base_invalid"):
            await adapter.record_task_change_base(wrong_kind)

    kept = await sqlite.load_task_change_base()
    assert kept is not None
    inventory = db.execute(
        "SELECT kind, state FROM objects WHERE object_id=?", (kept.object_id,)
    ).fetchall()
    assert inventory == [("change_capture", "present")]
    db.close()
    restarted = SqliteLedger(
        db=apsw.Connection(str(database)),
        task_id=command.task_id,
        ownership_fence=_fence(),
        clock=_Clock(),
        ids=sqlite_ids,
        objects=sqlite_objects,
    )
    assert await restarted.load_task_change_base() == kept
