"""Conformance traces shared by the memory and SQLite start catalogs."""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import anyio
import apsw
import pytest

from yoetz.adapters.memory.start_catalog import (
    MemoryStartCatalogAdapter,
    MemoryStartCatalogState,
)
from yoetz.adapters.sqlite.start_catalog import SqliteStartCatalog
from yoetz.domain.coordination import SessionHealth, WorkState
from yoetz.domain.values import Frontier
from yoetz.ports.runtime import StartCompletionEvidence, StartMilestone
from yoetz.ports.start_catalog import (
    EncryptedResultRef,
    SafeReason,
    SessionState,
    StartAllocation,
    StartCommand,
    StartIdentityInput,
    StartMode,
    StartPhase,
    TaskRouteState,
)
from yoetz.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import PREFIX_BY_KIND, IdKind


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass(slots=True)
class _Clock:
    current: datetime

    def now_utc(self) -> datetime:
        return self.current

    def monotonic_seconds(self) -> float:
        return 0.0

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


class _Ids:
    def __init__(self) -> None:
        self._next = 1

    def new(self, kind: IdKind) -> str:
        value = self._next
        self._next += 1
        raw = bytearray(value.to_bytes(16, "big"))
        raw[6] = (raw[6] & 0x0F) | 0x40
        raw[8] = (raw[8] & 0x3F) | 0x80
        return PREFIX_BY_KIND[kind] + str(uuid.UUID(bytes=bytes(raw)))


class _Lookup:
    def __init__(self) -> None:
        self._key = b"\x91" * 32

    def mac(self, domain: bytes, message: bytes) -> str:
        return f"hmac-sha256:{hmac.new(self._key, domain + message, hashlib.sha256).hexdigest()}"


def _id(kind: IdKind, value: int) -> str:
    raw = bytearray(value.to_bytes(16, "big"))
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return PREFIX_BY_KIND[kind] + str(uuid.UUID(bytes=bytes(raw)))


def _sqlite_catalog(
    installation_id: str, clock: _Clock, *, schema_version: int = 3
) -> SqliteStartCatalog:
    db = apsw.Connection(":memory:")
    root = Path(__file__).resolve().parents[3]
    for version in (f"{number:04d}" for number in range(1, schema_version + 1)):
        db.execute((root / f"migrations/catalog/{version}.sql").read_text(encoding="utf-8"))
    db.executemany(
        "INSERT INTO catalog_meta(key, value) VALUES(?, ?)",
        (("installation_id", installation_id), ("owner_generation", "1")),
    )
    return SqliteStartCatalog(
        db,
        installation_id=installation_id,
        lookup=_Lookup(),
        clock=clock,
        ids=_Ids(),
    )


def _memory_catalog(
    installation_id: str, clock: _Clock
) -> tuple[MemoryStartCatalogAdapter, MemoryStartCatalogState]:
    state = MemoryStartCatalogState()
    return (
        MemoryStartCatalogAdapter(
            installation_id=installation_id,
            lookup=_Lookup(),
            state=state,
            transaction_lock=anyio.Lock(),
            clock=clock,
            ids=_Ids(),
        ),
        state,
    )


async def _command(
    catalog: MemoryStartCatalogAdapter | SqliteStartCatalog,
    *,
    operation_id: str,
    mode: StartMode = StartMode.CREATE_OR_ATTACH,
    session_id: str | None = None,
    title: str = "Exact task",
    workspace_ref: str = "workspace-A",
    external_ref: str = "external-A",
    repository_privacy_commitment: str | None = None,
) -> StartCommand:
    identity = StartIdentityInput(title, workspace_ref, external_ref)
    commitments = await catalog.commit_identity(identity)
    digest = canonical_digest(
        {
            "commitments": {
                "external": commitments.external_ref_commitment,
                "title": commitments.title_commitment,
                "workspace": commitments.workspace_ref_commitment,
            },
            "mode": mode.value,
            "repository_privacy_commitment": repository_privacy_commitment,
            "session_id": session_id,
        }
    )
    return StartCommand(
        operation_id,
        digest,
        mode,
        identity,
        commitments,
        session_id,
        repository_privacy_commitment,
    )


def _result(value: int = 900) -> EncryptedResultRef:
    canonical = canonical_encode({"outcome": "complete", "sequence": value})
    return EncryptedResultRef(
        _id(IdKind.OBJECT, value),
        f"sha256:{hashlib.sha256(b'envelope' + canonical).hexdigest()}",
        canonical,
        f"sha256:{hashlib.sha256(canonical).hexdigest()}",
    )


def _evidence(allocation: object, result: EncryptedResultRef) -> StartCompletionEvidence:
    from yoetz.ports.start_catalog import StartAllocation

    assert type(allocation) is StartAllocation
    frontier = Frontier(1, canonical_digest({"frontier": 1}))
    value: dict[str, JsonValue] = {
        "lifecycle_event_id": allocation.lifecycle_event_id,
        "lifecycle_frontier": dict(frontier.as_wire()),
        "milestone": StartMilestone.RESULT_PUBLISHED.value,
        "owner_generation": 1,
        "response_envelope_digest": result.envelope_digest,
        "response_object_id": result.response_object_id,
        "result_digest": result.result_digest,
        "route_generation": allocation.route_generation,
        "route_identity_digest": allocation.route_identity_digest,
        "session_id": allocation.session_id,
        "task_id": allocation.task_id,
        "writer_id": allocation.writer_id,
    }
    return StartCompletionEvidence(
        milestone=StartMilestone.RESULT_PUBLISHED,
        task_id=allocation.task_id,
        session_id=allocation.session_id,
        writer_id=allocation.writer_id,
        lifecycle_event_id=allocation.lifecycle_event_id,
        route_generation=allocation.route_generation,
        route_identity_digest=allocation.route_identity_digest,
        owner_generation=1,
        lifecycle_frontier=frontier,
        response_object_id=result.response_object_id,
        response_envelope_digest=result.envelope_digest,
        result_digest=result.result_digest,
        evidence_digest=canonical_digest(value),
    )


async def _finish(
    catalog: MemoryStartCatalogAdapter | SqliteStartCatalog,
    allocation: object,
) -> tuple[object, EncryptedResultRef]:
    from yoetz.ports.start_catalog import StartAllocation

    assert type(allocation) is StartAllocation
    allocation = await catalog.advance_phase(allocation, StartPhase.BUNDLE_READY)
    allocation = await catalog.advance_phase(allocation, StartPhase.LIFECYCLE_COMMITTED)
    result = _result()
    allocation = await catalog.advance_phase(allocation, StartPhase.RESULT_PUBLISHED, result)
    await catalog.complete(allocation, result, _evidence(allocation, result))
    return allocation, result


@pytest.mark.anyio
async def test_reserve_resume_complete_parity() -> None:
    installation_id = _id(IdKind.INSTALLATION, 700)
    memory_clock = _Clock(datetime(2026, 7, 19, 9, 0, tzinfo=UTC))
    sqlite_clock = _Clock(memory_clock.current)
    memory, _ = _memory_catalog(installation_id, memory_clock)
    sqlite = _sqlite_catalog(installation_id, sqlite_clock)
    memory_request = await _command(memory, operation_id=_id(IdKind.REQUEST, 701))
    sqlite_request = await _command(sqlite, operation_id=_id(IdKind.REQUEST, 701))

    memory_allocation = await memory.reserve_or_resume(memory_request)
    sqlite_allocation = await sqlite.reserve_or_resume(sqlite_request)
    assert memory_allocation == sqlite_allocation
    assert await memory.resolve_route(memory_allocation.session_id) == await sqlite.resolve_route(
        sqlite_allocation.session_id
    )

    memory_terminal, _ = await _finish(memory, memory_allocation)
    sqlite_terminal, _ = await _finish(sqlite, sqlite_allocation)
    assert memory_terminal == sqlite_terminal
    memory_replay = await memory.reserve_or_resume(memory_request)
    sqlite_replay = await sqlite.reserve_or_resume(sqlite_request)
    assert memory_replay == sqlite_replay
    assert memory_replay.outcome == "replayed"
    assert memory_replay.replayed_result is not None


@pytest.mark.anyio
async def test_session_lease_extension_is_monotonic_and_preserves_ended_fences() -> None:
    """Memory and SQLite apply lease offers atomically and never revive an ended route."""

    installation_id = _id(IdKind.INSTALLATION, 750)
    start = datetime(2026, 7, 19, 9, 5, tzinfo=UTC)
    memory_clock = _Clock(start)
    sqlite_clock = _Clock(start)
    memory, _ = _memory_catalog(installation_id, memory_clock)
    sqlite = _sqlite_catalog(installation_id, sqlite_clock, schema_version=4)

    states: list[tuple[SessionState, SessionState, SessionState, SessionState]] = []
    for catalog in (memory, sqlite):
        command = await _command(catalog, operation_id=_id(IdKind.REQUEST, 751))
        allocation = await catalog.reserve_or_resume(command)
        first = await catalog.extend_session_lease(
            allocation.task_id,
            allocation.session_id,
            changed_at=start,
            lease_expires_at=start + timedelta(seconds=60),
        )
        second = await catalog.extend_session_lease(
            allocation.task_id,
            allocation.session_id,
            changed_at=start + timedelta(seconds=1),
            lease_expires_at=start + timedelta(seconds=120),
        )
        stale = await catalog.extend_session_lease(
            allocation.task_id,
            allocation.session_id,
            changed_at=start,
            lease_expires_at=start + timedelta(seconds=90),
        )
        assert first.lease_expires_at == start + timedelta(seconds=60)
        assert second.lease_expires_at == start + timedelta(seconds=120)
        assert stale == second
        ended = await catalog.record_session_state(
            allocation.task_id,
            allocation.session_id,
            health=SessionHealth.ENDED,
            changed_at=start + timedelta(seconds=2),
        )
        offered_after_end = await catalog.extend_session_lease(
            allocation.task_id,
            allocation.session_id,
            changed_at=start + timedelta(seconds=3),
            lease_expires_at=start + timedelta(seconds=180),
        )
        assert ended.health is SessionHealth.ENDED
        assert offered_after_end == ended
        states.append((second, stale, ended, offered_after_end))

    memory_second, memory_stale, memory_ended, memory_after_end = states[0]
    sqlite_second, sqlite_stale, sqlite_ended, sqlite_after_end = states[1]
    assert memory_second == sqlite_second
    assert memory_stale == sqlite_stale
    assert memory_ended == sqlite_ended
    assert memory_after_end == sqlite_after_end


@pytest.mark.anyio
async def test_concurrent_same_pair_attaches_once_and_different_pairs_create_siblings() -> None:
    """The catalog lock preserves pair identity while allowing workspace siblings."""

    installation_id = _id(IdKind.INSTALLATION, 760)
    now = datetime(2026, 7, 19, 9, 12, tzinfo=UTC)
    memory, _ = _memory_catalog(installation_id, _Clock(now))
    sqlite = _sqlite_catalog(installation_id, _Clock(now))

    for catalog in (memory, sqlite):
        same_pair = [
            await _command(catalog, operation_id=_id(IdKind.REQUEST, 761)),
            await _command(catalog, operation_id=_id(IdKind.REQUEST, 762)),
        ]
        same_results: list[object | None] = [None, None]

        async def reserve_same(index: int) -> None:
            same_results[index] = await catalog.reserve_or_resume(same_pair[index])

        async with anyio.create_task_group() as tasks:
            for index in range(len(same_pair)):
                tasks.start_soon(reserve_same, index)

        same_allocations: list[StartAllocation] = []
        for result in same_results:
            assert isinstance(result, StartAllocation)
            same_allocations.append(result)
        assert {allocation.route_action for allocation in same_allocations} == {
            "created",
            "attached",
        }
        same_task_ids = {allocation.task_id for allocation in same_allocations}
        assert len(same_task_ids) == 1

        different_pairs = [
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 763),
                external_ref="external-B",
            ),
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 764),
                external_ref="external-C",
            ),
        ]
        different_results: list[object | None] = [None, None]

        async def reserve_different(index: int) -> None:
            different_results[index] = await catalog.reserve_or_resume(different_pairs[index])

        async with anyio.create_task_group() as tasks:
            for index in range(len(different_pairs)):
                tasks.start_soon(reserve_different, index)

        different_allocations: list[StartAllocation] = []
        for result in different_results:
            assert isinstance(result, StartAllocation)
            different_allocations.append(result)
        assert {allocation.route_action for allocation in different_allocations} == {"created"}
        assert len({allocation.task_id for allocation in different_allocations}) == 2
        assert not same_task_ids.intersection(
            allocation.task_id for allocation in different_allocations
        )


@pytest.mark.anyio
async def test_historical_session_binding_and_reattach_parity() -> None:
    """Memory and SQLite preserve the same capability-bounded session recovery (#438)."""

    installation_id = _id(IdKind.INSTALLATION, 730)
    now = datetime(2026, 7, 19, 9, 15, tzinfo=UTC)
    memory, _ = _memory_catalog(installation_id, _Clock(now))
    sqlite = _sqlite_catalog(installation_id, _Clock(now))

    memory_created = await memory.reserve_or_resume(
        await _command(memory, operation_id=_id(IdKind.REQUEST, 731))
    )
    sqlite_created = await sqlite.reserve_or_resume(
        await _command(sqlite, operation_id=_id(IdKind.REQUEST, 731))
    )
    assert memory_created == sqlite_created
    await _finish(memory, memory_created)
    await _finish(sqlite, sqlite_created)

    memory_attached = await memory.reserve_or_resume(
        await _command(memory, operation_id=_id(IdKind.REQUEST, 732))
    )
    sqlite_attached = await sqlite.reserve_or_resume(
        await _command(sqlite, operation_id=_id(IdKind.REQUEST, 732))
    )
    assert memory_attached == sqlite_attached
    await _finish(memory, memory_attached)
    await _finish(sqlite, sqlite_attached)

    assert await memory.resolve_route(memory_created.session_id) is None
    assert await sqlite.resolve_route(sqlite_created.session_id) is None
    memory_binding = await memory.session_binding(memory_created.session_id)
    sqlite_binding = await sqlite.session_binding(sqlite_created.session_id)
    assert memory_binding == sqlite_binding
    assert memory_binding is not None
    assert memory_binding.task_id == memory_created.task_id
    assert memory_binding.session_id == memory_attached.session_id
    assert memory_binding.writer_id == memory_attached.writer_id
    unknown = _id(IdKind.SESSION, 733)
    assert await memory.session_binding(unknown) is None
    assert await sqlite.session_binding(unknown) is None

    memory_rebound = await memory.reserve_or_resume(
        await _command(
            memory,
            operation_id=_id(IdKind.REQUEST, 734),
            mode=StartMode.ATTACH,
            session_id=memory_created.session_id,
        )
    )
    sqlite_rebound = await sqlite.reserve_or_resume(
        await _command(
            sqlite,
            operation_id=_id(IdKind.REQUEST, 734),
            mode=StartMode.ATTACH,
            session_id=sqlite_created.session_id,
        )
    )
    assert memory_rebound == sqlite_rebound
    assert memory_rebound.route_action == "attached"
    assert memory_rebound.task_id == memory_created.task_id
    await _finish(memory, memory_rebound)
    await _finish(sqlite, sqlite_rebound)
    assert await memory.session_binding(memory_created.session_id) == await sqlite.session_binding(
        sqlite_created.session_id
    )
    rebound_binding = await sqlite.session_binding(sqlite_created.session_id)
    assert rebound_binding is not None
    assert rebound_binding.session_id == sqlite_rebound.session_id
    assert rebound_binding.writer_id == sqlite_rebound.writer_id


@pytest.mark.anyio
async def test_active_session_can_recover_one_exact_workspace_under_a_new_pair() -> None:
    """#535: held selector + exact workspace admits one serialized host rotation."""

    installation_id = _id(IdKind.INSTALLATION, 740)
    now = datetime(2026, 7, 19, 9, 18, tzinfo=UTC)
    memory, _ = _memory_catalog(installation_id, _Clock(now))
    sqlite = _sqlite_catalog(installation_id, _Clock(now))
    privacy = "hmac-sha256:" + "c" * 64

    for catalog in (memory, sqlite):
        created = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 741),
                repository_privacy_commitment=privacy,
            )
        )
        await _finish(catalog, created)

        recovered = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 742),
                mode=StartMode.ATTACH,
                session_id=created.session_id,
                external_ref="external-B",
                repository_privacy_commitment=privacy,
            )
        )
        assert recovered.route_action == "attached"
        assert recovered.task_id == created.task_id

        with pytest.raises(PublicOperationError) as pending:
            await catalog.reserve_or_resume(
                await _command(
                    catalog,
                    operation_id=_id(IdKind.REQUEST, 743),
                    mode=StartMode.ATTACH,
                    session_id=created.session_id,
                    external_ref="external-C",
                    repository_privacy_commitment=privacy,
                )
            )
        assert pending.value.code is PublicErrorCode.OPERATION_PENDING
        assert pending.value.retryable is True

        await _finish(catalog, recovered)
        with pytest.raises(PublicOperationError) as historical:
            await catalog.reserve_or_resume(
                await _command(
                    catalog,
                    operation_id=_id(IdKind.REQUEST, 744),
                    mode=StartMode.ATTACH,
                    session_id=created.session_id,
                    external_ref="external-C",
                    repository_privacy_commitment=privacy,
                )
            )
        assert historical.value.code is PublicErrorCode.SESSION_CONFLICT


@pytest.mark.anyio
async def test_abandoned_pending_start_never_wedges_the_ordinary_same_pair_attach() -> None:
    """#535: the rotation gate is scoped; an orphaned reservation stays self-healing."""

    installation_id = _id(IdKind.INSTALLATION, 751)
    now = datetime(2026, 7, 19, 9, 20, tzinfo=UTC)
    memory, _ = _memory_catalog(installation_id, _Clock(now))
    sqlite = _sqlite_catalog(installation_id, _Clock(now))

    for catalog in (memory, sqlite):
        created = await catalog.reserve_or_resume(
            await _command(catalog, operation_id=_id(IdKind.REQUEST, 752))
        )
        await _finish(catalog, created)

        # A start that reserved and then lost its process: never completed, never
        # quarantined, and unreachable by any later request id.
        await catalog.reserve_or_resume(
            await _command(catalog, operation_id=_id(IdKind.REQUEST, 753))
        )

        # The ordinary create_or_attach on the very same pair still resolves.
        again = await catalog.reserve_or_resume(
            await _command(catalog, operation_id=_id(IdKind.REQUEST, 754))
        )
        assert again.route_action == "attached"
        assert again.task_id == created.task_id

        # Only the workspace-recovery rotation is serialized against it.
        with pytest.raises(PublicOperationError) as rotation:
            await catalog.reserve_or_resume(
                await _command(
                    catalog,
                    operation_id=_id(IdKind.REQUEST, 755),
                    mode=StartMode.ATTACH,
                    session_id=created.session_id,
                    external_ref="external-B",
                )
            )
        assert rotation.value.code is PublicErrorCode.OPERATION_PENDING
        assert rotation.value.retryable is True


@pytest.mark.anyio
async def test_workspace_rotation_selects_active_route_among_siblings() -> None:
    """A held selector chooses its route while sibling identity remains isolated."""

    installation_id = _id(IdKind.INSTALLATION, 745)
    now = datetime(2026, 7, 19, 9, 19, tzinfo=UTC)
    memory, _ = _memory_catalog(installation_id, _Clock(now))
    sqlite = _sqlite_catalog(installation_id, _Clock(now))

    privacy = "hmac-sha256:" + "a" * 64
    mismatched_privacy = "hmac-sha256:" + "b" * 64

    for catalog in (memory, sqlite):
        first = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 746),
                repository_privacy_commitment=privacy,
            )
        )
        await _finish(catalog, first)

        with pytest.raises(PublicOperationError) as wrong_workspace:
            await catalog.reserve_or_resume(
                await _command(
                    catalog,
                    operation_id=_id(IdKind.REQUEST, 747),
                    mode=StartMode.ATTACH,
                    session_id=first.session_id,
                    workspace_ref="workspace-B",
                    external_ref="external-B",
                )
            )
        assert wrong_workspace.value.code is PublicErrorCode.SESSION_CONFLICT

        sibling = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 748),
                mode=StartMode.CREATE,
                external_ref="external-B",
                repository_privacy_commitment=privacy,
            )
        )
        await _finish(catalog, sibling)
        sibling_route = await catalog.resolve_route(sibling.session_id)
        sibling_binding = await catalog.session_binding(sibling.session_id)
        assert sibling_route is not None
        assert sibling_binding is not None

        second_sibling = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 758),
                mode=StartMode.CREATE,
                external_ref="external-E",
                repository_privacy_commitment=privacy,
            )
        )
        await _finish(catalog, second_sibling)
        second_sibling_route = await catalog.resolve_route(second_sibling.session_id)
        second_sibling_binding = await catalog.session_binding(second_sibling.session_id)
        assert second_sibling_route is not None
        assert second_sibling_binding is not None

        with pytest.raises(PublicOperationError) as pair_conflict:
            await catalog.reserve_or_resume(
                await _command(
                    catalog,
                    operation_id=_id(IdKind.REQUEST, 749),
                    mode=StartMode.ATTACH,
                    session_id=first.session_id,
                    external_ref="external-B",
                )
            )
        assert pair_conflict.value.code is PublicErrorCode.SESSION_CONFLICT

        with pytest.raises(PublicOperationError) as privacy_conflict:
            await catalog.reserve_or_resume(
                await _command(
                    catalog,
                    operation_id=_id(IdKind.REQUEST, 750),
                    mode=StartMode.ATTACH,
                    session_id=first.session_id,
                    external_ref="external-D",
                    repository_privacy_commitment=mismatched_privacy,
                )
            )
        assert privacy_conflict.value.code is PublicErrorCode.SESSION_CONFLICT

        recovered = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 751),
                mode=StartMode.ATTACH,
                session_id=first.session_id,
                external_ref="external-C",
                repository_privacy_commitment=privacy,
            )
        )
        assert recovered.route_action == "attached"
        assert recovered.task_id == first.task_id
        assert recovered.task_id != sibling.task_id
        assert await catalog.resolve_route(sibling.session_id) == sibling_route
        assert await catalog.session_binding(sibling.session_id) == sibling_binding
        assert await catalog.resolve_route(second_sibling.session_id) == second_sibling_route
        assert await catalog.session_binding(second_sibling.session_id) == second_sibling_binding

        await _finish(catalog, recovered)
        assert await catalog.resolve_route(sibling.session_id) == sibling_route
        assert await catalog.session_binding(sibling.session_id) == sibling_binding
        assert await catalog.resolve_route(second_sibling.session_id) == second_sibling_route
        assert await catalog.session_binding(second_sibling.session_id) == second_sibling_binding

        with pytest.raises(PublicOperationError) as stale_selector:
            await catalog.reserve_or_resume(
                await _command(
                    catalog,
                    operation_id=_id(IdKind.REQUEST, 752),
                    mode=StartMode.ATTACH,
                    session_id=first.session_id,
                    external_ref="external-D",
                    repository_privacy_commitment=privacy,
                )
            )
        assert stale_selector.value.code is PublicErrorCode.SESSION_CONFLICT


@pytest.mark.anyio
async def test_workspace_recovery_ignores_unrelated_pending_sibling() -> None:
    """A pending sibling cannot block or mutate a selected route's recovery."""

    installation_id = _id(IdKind.INSTALLATION, 753)
    now = datetime(2026, 7, 19, 9, 21, tzinfo=UTC)
    memory, _ = _memory_catalog(installation_id, _Clock(now))
    sqlite = _sqlite_catalog(installation_id, _Clock(now))

    for catalog in (memory, sqlite):
        selected = await catalog.reserve_or_resume(
            await _command(catalog, operation_id=_id(IdKind.REQUEST, 754))
        )
        await _finish(catalog, selected)
        selected_route = await catalog.resolve_route(selected.session_id)
        assert selected_route is not None

        sibling_request = await _command(
            catalog,
            operation_id=_id(IdKind.REQUEST, 755),
            mode=StartMode.CREATE,
            external_ref="external-B",
        )
        sibling = await catalog.reserve_or_resume(sibling_request)
        sibling_route = await catalog.resolve_route(sibling.session_id)
        assert sibling_route is not None
        assert sibling_route.state is TaskRouteState.INITIALIZING

        recovered = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 756),
                mode=StartMode.ATTACH,
                session_id=selected.session_id,
                external_ref="external-C",
            )
        )
        assert recovered.route_action == "attached"
        assert recovered.task_id == selected.task_id
        assert recovered.task_id != sibling.task_id
        assert await catalog.resolve_route(selected.session_id) == selected_route
        assert await catalog.resolve_route(sibling.session_id) == sibling_route

        with pytest.raises(PublicOperationError) as selected_pending:
            await catalog.reserve_or_resume(
                await _command(
                    catalog,
                    operation_id=_id(IdKind.REQUEST, 757),
                    mode=StartMode.ATTACH,
                    session_id=selected.session_id,
                    external_ref="external-D",
                )
            )
        assert selected_pending.value.code is PublicErrorCode.OPERATION_PENDING
        assert selected_pending.value.retryable is True

        with pytest.raises(PublicOperationError) as sibling_pending:
            await catalog.reserve_or_resume(sibling_request)
        assert sibling_pending.value.code is PublicErrorCode.OPERATION_PENDING
        assert sibling_pending.value.retryable is True

        await _finish(catalog, recovered)
        assert await catalog.resolve_route(sibling.session_id) == sibling_route


@pytest.mark.anyio
async def test_initializing_route_preserves_its_pair_without_blocking_a_new_pair() -> None:
    """An unfinished task is never selected solely because it shares the workspace."""

    installation_id = _id(IdKind.INSTALLATION, 735)
    now = datetime(2026, 7, 19, 9, 20, tzinfo=UTC)
    memory, _ = _memory_catalog(installation_id, _Clock(now))
    sqlite = _sqlite_catalog(installation_id, _Clock(now))

    for catalog in (memory, sqlite):
        initializing = await catalog.reserve_or_resume(
            await _command(catalog, operation_id=_id(IdKind.REQUEST, 736))
        )
        route = await catalog.resolve_route(initializing.session_id)
        assert route is not None
        assert route.state is TaskRouteState.INITIALIZING

        automatic = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 737),
                external_ref="external-B",
            )
        )
        assert automatic.route_action == "created"
        assert automatic.task_id != initializing.task_id
        assert await catalog.resolve_route(initializing.session_id) == route

        sibling = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 738),
                mode=StartMode.CREATE,
                external_ref="external-C",
            )
        )
        assert sibling.route_action == "created"
        assert len({sibling.task_id, automatic.task_id, initializing.task_id}) == 3


@pytest.mark.anyio
@pytest.mark.parametrize("schema_version", [3, 4])
async def test_repository_binding_is_atomic_and_mismatch_precedes_operation_reservation(
    schema_version: int,
) -> None:
    installation_id = _id(IdKind.INSTALLATION, 705)
    clock = _Clock(datetime(2026, 7, 19, 9, 30, tzinfo=UTC))
    memory, memory_state = _memory_catalog(installation_id, clock)
    sqlite = _sqlite_catalog(installation_id, _Clock(clock.current), schema_version=schema_version)
    commitment_a = "hmac-sha256:" + "a" * 64
    commitment_b = "hmac-sha256:" + "b" * 64

    for catalog in (memory, sqlite):
        created = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 706),
                repository_privacy_commitment=commitment_a,
            )
        )
        route = await catalog.resolve_route(created.session_id)
        assert route is not None
        assert route.repository_privacy_commitment == commitment_a
        if isinstance(catalog, MemoryStartCatalogAdapter):
            before_operations = len(memory_state.operations)
        else:
            row = catalog._db.execute(  # pyright: ignore[reportPrivateUsage]
                "SELECT COUNT(*) FROM start_operations"
            ).fetchone()
            assert row is not None
            before_operations = int(row[0])
        mismatch = await _command(
            catalog,
            operation_id=_id(IdKind.REQUEST, 707),
            mode=StartMode.ATTACH,
            session_id=created.session_id,
            repository_privacy_commitment=commitment_b,
        )
        missing = await _command(
            catalog,
            operation_id=_id(IdKind.REQUEST, 709),
            mode=StartMode.ATTACH,
            session_id=created.session_id,
        )
        with pytest.raises(PublicOperationError) as missing_failure:
            await catalog.reserve_or_resume(missing)
        assert missing_failure.value.code is PublicErrorCode.SESSION_CONFLICT
        assert missing_failure.value.safe_details == {"reason_code": "repository_identity_required"}
        with pytest.raises(PublicOperationError) as failure:
            await catalog.reserve_or_resume(mismatch)
        assert failure.value.code is PublicErrorCode.SESSION_CONFLICT
        assert failure.value.safe_details == {"reason_code": "repository_identity_mismatch"}
        if isinstance(catalog, MemoryStartCatalogAdapter):
            after_operations = len(memory_state.operations)
        else:
            row = catalog._db.execute(  # pyright: ignore[reportPrivateUsage]
                "SELECT COUNT(*) FROM start_operations"
            ).fetchone()
            assert row is not None
            after_operations = int(row[0])
        assert after_operations == before_operations
        assert before_operations == after_operations == 1

        corrected = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 708),
                mode=StartMode.ATTACH,
                session_id=created.session_id,
                repository_privacy_commitment=commitment_a,
            )
        )
        assert corrected.task_id == created.task_id


@pytest.mark.anyio
async def test_quarantine_and_reclaim_parity() -> None:
    installation_id = _id(IdKind.INSTALLATION, 710)
    memory_clock = _Clock(datetime(2026, 7, 19, 10, 0, tzinfo=UTC))
    sqlite_clock = _Clock(memory_clock.current)
    memory, _ = _memory_catalog(installation_id, memory_clock)
    sqlite = _sqlite_catalog(installation_id, sqlite_clock)
    memory_request = await _command(memory, operation_id=_id(IdKind.REQUEST, 711))
    sqlite_request = await _command(sqlite, operation_id=_id(IdKind.REQUEST, 711))
    original_memory = await memory.reserve_or_resume(memory_request)
    original_sqlite = await sqlite.reserve_or_resume(sqlite_request)

    memory_clock.advance(61)
    sqlite_clock.advance(61)
    resumed_memory = await memory.reserve_or_resume(memory_request)
    resumed_sqlite = await sqlite.reserve_or_resume(sqlite_request)
    assert resumed_memory == resumed_sqlite
    assert resumed_memory.outcome == "resumed"
    assert resumed_memory.task_id == original_memory.task_id
    assert resumed_sqlite.writer_id == original_sqlite.writer_id

    reason = SafeReason("start_bundle_invalid")
    await memory.quarantine(resumed_memory, reason)
    await sqlite.quarantine(resumed_sqlite, reason)
    memory_replay = await memory.reserve_or_resume(memory_request)
    sqlite_replay = await sqlite.reserve_or_resume(sqlite_request)
    assert memory_replay == sqlite_replay
    assert memory_replay.replayed_result is not None


@pytest.mark.anyio
@pytest.mark.parametrize("mode", [StartMode.ATTACH, StartMode.CREATE_OR_ATTACH, StartMode.CREATE])
async def test_quarantined_pair_refuses_before_new_reservation(mode: StartMode) -> None:
    installation = _id(IdKind.INSTALLATION, 740)
    clock = _Clock(datetime(2026, 7, 19, 11, 0, tzinfo=UTC))
    memory, state = _memory_catalog(installation, clock)
    sqlite = _sqlite_catalog(installation, clock, schema_version=5)
    for catalog in (memory, sqlite):
        original = await _command(catalog, operation_id=_id(IdKind.REQUEST, 741))
        allocation = await catalog.reserve_or_resume(original)
        await catalog.quarantine(allocation, SafeReason("start_bundle_invalid"))
        route = await catalog.task_route(allocation.task_id)
        sessions = await catalog.task_session_states(allocation.task_id)
        replacement = await _command(catalog, operation_id=_id(IdKind.REQUEST, 742), mode=mode)
        with pytest.raises(PublicOperationError) as error:
            await catalog.reserve_or_resume(replacement)
        assert error.value.code is PublicErrorCode.STORAGE_CORRUPT
        assert await catalog.task_route(allocation.task_id) == route
        assert await catalog.task_session_states(allocation.task_id) == sessions
        if isinstance(catalog, MemoryStartCatalogAdapter):
            assert len(state.operations) == 1
        else:
            assert catalog._db.execute(  # pyright: ignore[reportPrivateUsage]
                "SELECT COUNT(*) FROM start_operations"
            ).fetchone() == (1,)
        # An exact retry still recovers the original terminal failure.
        replayed = await catalog.reserve_or_resume(original)
        assert replayed.outcome == "replayed"
        assert replayed.replayed_result is not None


@pytest.mark.anyio
@pytest.mark.parametrize("state", [WorkState.ABANDONED, WorkState.CLOSED])
@pytest.mark.parametrize("mode", [StartMode.ATTACH, StartMode.CREATE_OR_ATTACH])
async def test_terminal_work_refuses_resume_before_new_reservation(
    mode: StartMode, state: WorkState
) -> None:
    """Terminal work cannot be resumed, so no session is reserved or rotated (#837)."""

    installation = _id(IdKind.INSTALLATION, 760)
    clock = _Clock(datetime(2026, 7, 19, 11, 0, tzinfo=UTC))
    memory, memory_state = _memory_catalog(installation, clock)
    sqlite = _sqlite_catalog(installation, clock, schema_version=5)
    for catalog in (memory, sqlite):
        original = await _command(catalog, operation_id=_id(IdKind.REQUEST, 761))
        allocation, _result_ref = await _finish(catalog, await catalog.reserve_or_resume(original))
        assert type(allocation) is StartAllocation
        await catalog.set_task_work_state(allocation.task_id, state)
        route = await catalog.task_route(allocation.task_id)
        sessions = await catalog.task_session_states(allocation.task_id)
        resume = await _command(
            catalog,
            operation_id=_id(IdKind.REQUEST, 762),
            mode=mode,
            session_id=allocation.session_id if mode is StartMode.ATTACH else None,
        )
        with pytest.raises(PublicOperationError) as error:
            await catalog.reserve_or_resume(resume)
        assert error.value.code is PublicErrorCode.SESSION_CONFLICT
        assert error.value.safe_details["reason_code"] == "lineage_resume_work_terminal"
        assert error.value.safe_details["continuation"] == "lineage_successor_task"
        assert await catalog.task_route(allocation.task_id) == route
        assert await catalog.task_session_states(allocation.task_id) == sessions
        if isinstance(catalog, MemoryStartCatalogAdapter):
            assert len(memory_state.operations) == 1
        else:
            assert catalog._db.execute(  # pyright: ignore[reportPrivateUsage]
                "SELECT COUNT(*) FROM start_operations"
            ).fetchone() == (1,)
        # The completed original start still replays its recorded result.
        replayed = await catalog.reserve_or_resume(original)
        assert replayed.outcome == "replayed"
        # A deliberate new identity pair remains an ordinary successor task.
        successor = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 763),
                mode=StartMode.CREATE,
                external_ref="external-successor",
            )
        )
        assert successor.task_id != allocation.task_id


@pytest.mark.anyio
async def test_generation_and_route_identity_parity() -> None:
    installation_id = _id(IdKind.INSTALLATION, 720)
    memory_clock = _Clock(datetime(2026, 7, 19, 11, 0, tzinfo=UTC))
    sqlite_clock = _Clock(memory_clock.current)
    memory, state = _memory_catalog(installation_id, memory_clock)
    sqlite = _sqlite_catalog(installation_id, sqlite_clock)
    memory_request = await _command(memory, operation_id=_id(IdKind.REQUEST, 721))
    sqlite_request = await _command(sqlite, operation_id=_id(IdKind.REQUEST, 721))
    stale_memory = await memory.reserve_or_resume(memory_request)
    stale_sqlite = await sqlite.reserve_or_resume(sqlite_request)

    state.owner_generation = 2
    sqlite._db.execute(  # pyright: ignore[reportPrivateUsage]
        "UPDATE catalog_meta SET value = '2' WHERE key = 'owner_generation'"
    )
    resumed_memory = await memory.reserve_or_resume(memory_request)
    resumed_sqlite = await sqlite.reserve_or_resume(sqlite_request)
    assert resumed_memory == resumed_sqlite
    assert resumed_memory.route_identity_digest == stale_memory.route_identity_digest

    for catalog, allocation in ((memory, stale_memory), (sqlite, stale_sqlite)):
        with pytest.raises(PublicOperationError) as failure:
            await catalog.advance_phase(allocation, StartPhase.BUNDLE_READY)
        assert failure.value.code is PublicErrorCode.OPERATION_PENDING

    route_memory = await memory.resolve_route(resumed_memory.session_id)
    route_sqlite = await sqlite.resolve_route(resumed_sqlite.session_id)
    assert route_memory == route_sqlite
    assert route_memory is not None
    assert route_memory.state is TaskRouteState.INITIALIZING


@pytest.mark.anyio
@pytest.mark.parametrize("phase", list(StartPhase)[:-1])
async def test_yielded_start_preserves_each_milestone_and_fences_old_lease(
    phase: StartPhase,
) -> None:
    installation = _id(IdKind.INSTALLATION, 744)
    clock = _Clock(datetime(2026, 7, 19, 10, tzinfo=UTC))
    memory, _ = _memory_catalog(installation, clock)
    sqlite = _sqlite_catalog(installation, clock)
    allocations: list[StartAllocation] = []
    for catalog in (memory, sqlite):
        command = await _command(catalog, operation_id=_id(IdKind.REQUEST, 745))
        allocated = await catalog.reserve_or_resume(command)
        for milestone in list(StartPhase)[1:-1]:
            if allocated.phase is phase:
                break
            allocated = await catalog.advance_phase(
                allocated,
                milestone,
                _result() if milestone is StartPhase.RESULT_PUBLISHED else None,
            )
        with pytest.raises(PublicOperationError) as live:
            await catalog.reserve_or_resume(command)
        assert live.value.code is PublicErrorCode.OPERATION_PENDING
        assert live.value.safe_details == {
            "reason_code": "start_lease_pending",
            "continuation": "start_pending_same_identity",
        }
        await catalog.yield_lease(allocated)
        with pytest.raises(PublicOperationError) as changed:
            await catalog.reserve_or_resume(replace(command, request_digest="sha256:" + "a" * 64))
        assert changed.value.code is PublicErrorCode.IDEMPOTENCY_CONFLICT
        resumed = await catalog.reserve_or_resume(command)
        assert resumed.lease is not None and allocated.lease is not None
        assert resumed.lease.lease_generation == allocated.lease.lease_generation + 1
        assert replace(resumed, lease=allocated.lease, outcome=allocated.outcome) == allocated
        with pytest.raises(PublicOperationError) as stale:
            await catalog.yield_lease(allocated)
        assert stale.value.code is PublicErrorCode.OPERATION_PENDING
        allocations.append(resumed)
    assert allocations[0] == allocations[1]


@pytest.mark.anyio
async def test_yield_cannot_change_completed_quarantined_or_new_generation_start() -> None:
    installation = _id(IdKind.INSTALLATION, 746)
    clock = _Clock(datetime(2026, 7, 19, 10, tzinfo=UTC))
    memory, state = _memory_catalog(installation, clock)
    sqlite = _sqlite_catalog(installation, clock)
    for catalog in (memory, sqlite):
        command = await _command(catalog, operation_id=_id(IdKind.REQUEST, 747))
        allocated = await catalog.reserve_or_resume(command)
        await _finish(catalog, allocated)
        with pytest.raises(PublicOperationError):
            await catalog.yield_lease(allocated)
        assert (await catalog.reserve_or_resume(command)).outcome == "replayed"
        quarantine_command = await _command(
            catalog, operation_id=_id(IdKind.REQUEST, 748), workspace_ref="quarantined"
        )
        quarantined = await catalog.reserve_or_resume(quarantine_command)
        await catalog.quarantine(quarantined, SafeReason("start_bundle_invalid"))
        with pytest.raises(PublicOperationError):
            await catalog.yield_lease(quarantined)
        pending_command = await _command(
            catalog, operation_id=_id(IdKind.REQUEST, 749), workspace_ref="pending"
        )
        pending = await catalog.reserve_or_resume(pending_command)
        if catalog is memory:
            state.owner_generation = 2
        else:
            sqlite._db.execute(  # pyright: ignore[reportPrivateUsage]
                "UPDATE catalog_meta SET value = '2' WHERE key = 'owner_generation'"
            )
        with pytest.raises(PublicOperationError) as stale_owner:
            await catalog.yield_lease(pending)
        assert stale_owner.value.code is PublicErrorCode.OPERATION_PENDING
        recovered = await catalog.reserve_or_resume(pending_command)
        assert recovered.task_id == pending.task_id
        assert recovered.lease is not None and recovered.lease.owner_generation == 2
