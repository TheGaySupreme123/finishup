"""Durable phase-machine tests for the SQLite start catalog."""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import apsw
import pytest

from finishup.adapters.sqlite.migrations import initialize_catalog
from finishup.adapters.sqlite.start_catalog import SqliteStartCatalog
from finishup.domain.values import Frontier
from finishup.ports.runtime import StartCompletionEvidence, StartMilestone
from finishup.ports.start_catalog import (
    EncryptedResultRef,
    SafeReason,
    StartAllocation,
    StartCommand,
    StartIdentityInput,
    StartMode,
    StartPhase,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import PREFIX_BY_KIND, IdKind


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _id(kind: IdKind, value: int) -> str:
    raw = bytearray(value.to_bytes(16, "big"))
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return PREFIX_BY_KIND[kind] + str(uuid.UUID(bytes=bytes(raw)))


class _Ids:
    def __init__(self) -> None:
        self._value = 1

    def new(self, kind: IdKind) -> str:
        result = _id(kind, self._value)
        self._value += 1
        return result


class _Lookup:
    def mac(self, domain: bytes, message: bytes) -> str:
        digest = hmac.new(b"\x82" * 32, domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


@dataclass(slots=True)
class _Clock:
    value: datetime

    def now_utc(self) -> datetime:
        return self.value

    def monotonic_seconds(self) -> float:
        return 0.0

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


@dataclass(slots=True)
class _Harness:
    catalog: SqliteStartCatalog
    db: apsw.Connection
    clock: _Clock

    @classmethod
    def create(cls, seed: int) -> _Harness:
        installation_id = _id(IdKind.INSTALLATION, seed)
        db = apsw.Connection(":memory:")
        root = Path(__file__).resolve().parents[3]
        for version in ("0001", "0002", "0003"):
            db.execute((root / f"migrations/catalog/{version}.sql").read_text(encoding="utf-8"))
        db.executemany(
            "INSERT INTO catalog_meta(key, value) VALUES(?, ?)",
            (("installation_id", installation_id), ("owner_generation", "1")),
        )
        clock = _Clock(datetime(2026, 7, 19, 12, 0, tzinfo=UTC))
        return cls(
            SqliteStartCatalog(
                db,
                installation_id=installation_id,
                lookup=_Lookup(),
                clock=clock,
                ids=_Ids(),
            ),
            db,
            clock,
        )

    async def command(
        self,
        operation_seed: int,
        *,
        mode: StartMode = StartMode.CREATE_OR_ATTACH,
        refs: str = "A",
        session_id: str | None = None,
    ) -> StartCommand:
        identity = StartIdentityInput("Task title", f"workspace-{refs}", f"external-{refs}")
        commitments = await self.catalog.commit_identity(identity)
        request_digest = canonical_digest(
            {
                "external": commitments.external_ref_commitment,
                "mode": mode.value,
                "session_id": session_id,
                "title": commitments.title_commitment,
                "workspace": commitments.workspace_ref_commitment,
            }
        )
        return StartCommand(
            _id(IdKind.REQUEST, operation_seed),
            request_digest,
            mode,
            identity,
            commitments,
            session_id,
        )


def _result(seed: int) -> EncryptedResultRef:
    content = canonical_encode({"result": "started", "seed": seed})
    return EncryptedResultRef(
        _id(IdKind.OBJECT, seed),
        f"sha256:{hashlib.sha256(b'envelope' + content).hexdigest()}",
        content,
        f"sha256:{hashlib.sha256(content).hexdigest()}",
    )


def _evidence(allocation: StartAllocation, result: EncryptedResultRef) -> StartCompletionEvidence:
    frontier = Frontier(1, canonical_digest({"accepted": 1}))
    value: dict[str, JsonValue] = {
        "lifecycle_event_id": allocation.lifecycle_event_id,
        "lifecycle_frontier": dict(frontier.as_wire()),
        "milestone": "result_published",
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
        StartMilestone.RESULT_PUBLISHED,
        allocation.task_id,
        allocation.session_id,
        allocation.writer_id,
        allocation.lifecycle_event_id,
        allocation.route_generation,
        allocation.route_identity_digest,
        1,
        frontier,
        result.response_object_id,
        result.envelope_digest,
        result.result_digest,
        canonical_digest(value),
    )


async def _complete(
    catalog: SqliteStartCatalog, allocation: StartAllocation, result_seed: int
) -> EncryptedResultRef:
    allocation = await catalog.advance_phase(allocation, StartPhase.BUNDLE_READY)
    allocation = await catalog.advance_phase(allocation, StartPhase.LIFECYCLE_COMMITTED)
    result = _result(result_seed)
    allocation = await catalog.advance_phase(allocation, StartPhase.RESULT_PUBLISHED, result)
    await catalog.complete(allocation, result, _evidence(allocation, result))
    return result


@pytest.mark.anyio
async def test_reserve_resume_and_complete_paths() -> None:
    harness = _Harness.create(800)
    request = await harness.command(801)
    allocation = await harness.catalog.reserve_or_resume(request)
    with pytest.raises(PublicOperationError) as live:
        await harness.catalog.reserve_or_resume(request)
    assert live.value.code is PublicErrorCode.OPERATION_PENDING

    result = await _complete(harness.catalog, allocation, 802)
    replay = await harness.catalog.reserve_or_resume(request)
    assert replay.outcome == "replayed"
    assert replay.replayed_result == result.result_canonical
    assert replay.lease is None


@pytest.mark.anyio
async def test_crash_and_reclaim_paths() -> None:
    harness = _Harness.create(810)
    request = await harness.command(811)
    reserved = await harness.catalog.reserve_or_resume(request)
    harness.clock.advance(61)
    resumed = await harness.catalog.reserve_or_resume(request)
    assert resumed.outcome == "resumed"
    assert resumed.task_id == reserved.task_id
    assert resumed.session_id == reserved.session_id
    assert resumed.writer_id == reserved.writer_id
    assert resumed.lifecycle_event_id == reserved.lifecycle_event_id
    assert resumed.lease is not None and resumed.lease.lease_generation == 2


@pytest.mark.anyio
async def test_attachment_conflict_and_quarantine_paths() -> None:
    harness = _Harness.create(820)
    first_request = await harness.command(821, mode=StartMode.CREATE, refs="shared")
    first = await harness.catalog.reserve_or_resume(first_request)
    await _complete(harness.catalog, first, 822)

    attach_request = await harness.command(
        825,
        mode=StartMode.ATTACH,
        refs="shared",
        session_id=first.session_id,
    )
    attached = await harness.catalog.reserve_or_resume(attach_request)
    assert attached.route_action == "attached"
    assert attached.task_id == first.task_id
    assert attached.route_identity_digest == first.route_identity_digest
    assert await harness.catalog.resolve_route(attached.session_id) is None
    await _complete(harness.catalog, attached, 826)
    assert await harness.catalog.resolve_route(first.session_id) is None
    active = await harness.catalog.resolve_route(attached.session_id)
    assert active is not None and active.state.value == "active"

    conflict_request = await harness.command(823, mode=StartMode.CREATE, refs="shared")
    with pytest.raises(PublicOperationError) as conflict:
        await harness.catalog.reserve_or_resume(conflict_request)
    assert conflict.value.code is PublicErrorCode.SESSION_CONFLICT

    pending_request = await harness.command(824, mode=StartMode.CREATE, refs="other")
    pending = await harness.catalog.reserve_or_resume(pending_request)
    await harness.catalog.quarantine(pending, SafeReason("start_route_contradiction"))
    replay = await harness.catalog.reserve_or_resume(pending_request)
    assert replay.outcome == "replayed"
    assert replay.replayed_result is not None
    route = await harness.catalog.resolve_route(pending.session_id)
    assert route is not None and route.state.value == "quarantined"


@pytest.mark.anyio
async def test_workspace_ref_groups_sibling_tasks_and_pair_attaches() -> None:
    """A drifted pair creates an authorized sibling and later resumes that exact pair."""

    harness = _Harness.create(840)
    first_request = await harness.command(841, mode=StartMode.CREATE_OR_ATTACH, refs="A")
    first = await harness.catalog.reserve_or_resume(first_request)
    await _complete(harness.catalog, first, 842)

    identity_b = StartIdentityInput("Task title", "workspace-A", "external-B")
    commitments_b = await harness.catalog.commit_identity(identity_b)
    drifted_request = StartCommand(
        _id(IdKind.REQUEST, 843),
        canonical_digest(
            {
                "external": commitments_b.external_ref_commitment,
                "mode": StartMode.CREATE_OR_ATTACH.value,
                "session_id": None,
                "title": commitments_b.title_commitment,
                "workspace": commitments_b.workspace_ref_commitment,
            }
        ),
        StartMode.CREATE_OR_ATTACH,
        identity_b,
        commitments_b,
        None,
    )
    second = await harness.catalog.reserve_or_resume(drifted_request)
    assert second.route_action == "created"
    assert second.task_id != first.task_id
    await _complete(harness.catalog, second, 844)

    drifted_attach = StartCommand(
        _id(IdKind.REQUEST, 845),
        drifted_request.request_digest,
        StartMode.CREATE_OR_ATTACH,
        identity_b,
        commitments_b,
        None,
    )
    drifted_attach_result = await harness.catalog.reserve_or_resume(drifted_attach)
    assert drifted_attach_result.route_action == "attached"
    assert drifted_attach_result.task_id == second.task_id
    await _complete(harness.catalog, drifted_attach_result, 846)

    identity_c = StartIdentityInput("Task title", "workspace-A", "external-C")
    commitments_c = await harness.catalog.commit_identity(identity_c)
    create_request = StartCommand(
        _id(IdKind.REQUEST, 847),
        canonical_digest(
            {
                "external": commitments_c.external_ref_commitment,
                "mode": StartMode.CREATE.value,
                "session_id": None,
                "title": commitments_c.title_commitment,
                "workspace": commitments_c.workspace_ref_commitment,
            }
        ),
        StartMode.CREATE,
        identity_c,
        commitments_c,
        None,
    )
    third = await harness.catalog.reserve_or_resume(create_request)
    await _complete(harness.catalog, third, 848)

    assert third.task_id not in {first.task_id, second.task_id}
    workspace = first_request.identity_commitments.workspace_ref_commitment
    assert workspace is not None
    grouped = await harness.catalog.list_workspace_task_ids(workspace)
    assert grouped == tuple(sorted((first.task_id, second.task_id, third.task_id)))

    attach_request = await harness.command(849, mode=StartMode.CREATE_OR_ATTACH, refs="A")
    attached = await harness.catalog.reserve_or_resume(attach_request)
    assert attached.route_action == "attached"
    assert attached.task_id == first.task_id
    grouped_after = await harness.catalog.list_workspace_task_ids(workspace)
    assert grouped_after == grouped


@pytest.mark.anyio
async def test_prebirth_auto_grouping_preference_is_durable_without_project_birth() -> None:
    installation_id = _id(IdKind.INSTALLATION, 850)
    database = apsw.Connection(":memory:")
    initialize_catalog(database)
    database.executemany(
        "INSERT INTO catalog_meta(key, value) VALUES(?, ?)",
        (("installation_id", installation_id), ("owner_generation", "1")),
    )
    clock = _Clock(datetime(2026, 7, 19, 12, 0, tzinfo=UTC))
    catalog = SqliteStartCatalog(
        database,
        installation_id=installation_id,
        lookup=_Lookup(),
        clock=clock,
        ids=_Ids(),
    )
    repository = "hmac-sha256:" + "a" * 64

    assert await catalog.repository_auto_grouping_enabled(repository) is True
    assert await catalog.set_project_auto_grouping(repository, enabled=False) is None
    assert await catalog.repository_auto_grouping_enabled(repository) is False
    assert database.execute("SELECT COUNT(*) FROM projects").fetchone() == (0,)
    assert database.execute(
        "SELECT auto_grouping FROM repository_grouping_preferences WHERE repository_commitment = ?",
        (repository,),
    ).fetchone() == (0,)

    assert await catalog.ensure_repository_project_if_auto_grouping_enabled(repository) is None
    assert database.execute("SELECT COUNT(*) FROM projects").fetchone() == (0,)
    project = await catalog.ensure_repository_project(repository)
    assert project.auto_grouping is False
    assert database.execute("SELECT COUNT(*) FROM projects").fetchone() == (1,)

    updated = await catalog.set_project_auto_grouping(repository, enabled=True)
    assert updated is not None and updated.auto_grouping is True
    assert await catalog.repository_auto_grouping_enabled(repository) is True
    assert database.execute(
        "SELECT auto_grouping FROM repository_grouping_preferences WHERE repository_commitment = ?",
        (repository,),
    ).fetchone() == (1,)


@pytest.mark.anyio
async def test_pending_operation_recovery_preserves_workspace_before_explicit_sibling() -> None:
    """A pending pair can recover while a different pair creates one workspace sibling."""

    harness = _Harness.create(850)
    pending_request = await harness.command(851, mode=StartMode.CREATE_OR_ATTACH, refs="pending")
    pending = await harness.catalog.reserve_or_resume(pending_request)
    workspace = pending_request.identity_commitments.workspace_ref_commitment
    assert workspace is not None

    sibling_identity = StartIdentityInput(
        "Repaired verification", "workspace-pending", "external-repaired"
    )
    sibling_commitments = await harness.catalog.commit_identity(sibling_identity)
    sibling_digest = canonical_digest(
        {
            "external": sibling_commitments.external_ref_commitment,
            "mode": StartMode.CREATE_OR_ATTACH.value,
            "session_id": None,
            "title": sibling_commitments.title_commitment,
            "workspace": sibling_commitments.workspace_ref_commitment,
        }
    )
    implicit_sibling = StartCommand(
        _id(IdKind.REQUEST, 852),
        sibling_digest,
        StartMode.CREATE_OR_ATTACH,
        sibling_identity,
        sibling_commitments,
        None,
    )
    sibling = await harness.catalog.reserve_or_resume(implicit_sibling)
    assert sibling.outcome == "reserved"
    assert sibling.route_action == "created"
    assert sibling.task_id != pending.task_id
    assert sibling.session_id != pending.session_id
    assert sibling.writer_id != pending.writer_id
    assert sibling.lifecycle_event_id != pending.lifecycle_event_id
    assert await harness.catalog.list_workspace_task_ids(workspace) == tuple(
        sorted((pending.task_id, sibling.task_id))
    )
    pending_route = await harness.catalog.resolve_route(pending.session_id)
    sibling_route = await harness.catalog.resolve_route(sibling.session_id)
    assert pending_route is not None and pending_route.task_id == pending.task_id
    assert sibling_route is not None and sibling_route.task_id == sibling.task_id
    assert pending_route.session_id == pending.session_id
    assert sibling_route.session_id == sibling.session_id

    # Recover the pending operation with its exact request identity before advancing the original
    # task. The sibling remains a separate pending operation and route.
    harness.clock.advance(61)
    resumed = await harness.catalog.reserve_or_resume(pending_request)
    assert resumed.outcome == "resumed"
    assert resumed.task_id == pending.task_id
    assert resumed.session_id == pending.session_id
    assert resumed.writer_id == pending.writer_id
    assert resumed.lifecycle_event_id == pending.lifecycle_event_id
    assert resumed.route_generation == pending.route_generation
    assert resumed.route_identity_digest == pending.route_identity_digest
    await _complete(harness.catalog, resumed, 853)

    # The automatic sibling already owns this exact pair. An explicit create must retain its
    # collision guard and must not allocate a third task while the sibling operation is pending.
    explicit_sibling = StartCommand(
        _id(IdKind.REQUEST, 854),
        canonical_digest(
            {
                "external": sibling_commitments.external_ref_commitment,
                "mode": StartMode.CREATE.value,
                "session_id": None,
                "title": sibling_commitments.title_commitment,
                "workspace": sibling_commitments.workspace_ref_commitment,
            }
        ),
        StartMode.CREATE,
        sibling_identity,
        sibling_commitments,
        None,
    )
    with pytest.raises(PublicOperationError) as conflict:
        await harness.catalog.reserve_or_resume(explicit_sibling)
    assert conflict.value.code is PublicErrorCode.SESSION_CONFLICT
    assert conflict.value.safe_details == {"reason_code": "workspace_task_exists"}
    assert await harness.catalog.list_workspace_task_ids(workspace) == tuple(
        sorted((pending.task_id, sibling.task_id))
    )

    # Resume and complete the original automatic sibling by its exact request. The explicit create
    # collision above must leave this operation untouched and must not create a fourth route.
    sibling_resumed = await harness.catalog.reserve_or_resume(implicit_sibling)
    assert sibling_resumed.outcome == "resumed"
    assert sibling_resumed.task_id == sibling.task_id
    assert sibling_resumed.session_id == sibling.session_id
    assert sibling_resumed.writer_id == sibling.writer_id
    assert sibling_resumed.lifecycle_event_id == sibling.lifecycle_event_id
    await _complete(harness.catalog, sibling_resumed, 855)
    assert await harness.catalog.list_workspace_task_ids(workspace) == tuple(
        sorted((pending.task_id, sibling.task_id))
    )

    # Repeating the explicit create remains a collision after completion, with the same two routes
    # and no operation record or task multiplication introduced by the refused request.
    with pytest.raises(PublicOperationError) as completed_conflict:
        await harness.catalog.reserve_or_resume(explicit_sibling)
    assert completed_conflict.value.code is PublicErrorCode.SESSION_CONFLICT
    assert completed_conflict.value.safe_details == {"reason_code": "workspace_task_exists"}
    assert await harness.catalog.list_workspace_task_ids(workspace) == tuple(
        sorted((pending.task_id, sibling.task_id))
    )


@pytest.mark.anyio
async def test_expiry_and_stale_generation_reclaim() -> None:
    harness = _Harness.create(830)
    expired_request = await harness.command(831, refs="expired")
    expired = await harness.catalog.reserve_or_resume(expired_request)
    harness.clock.advance(61)
    reclaimed_expired = await harness.catalog.reserve_or_resume(expired_request)
    assert reclaimed_expired.task_id == expired.task_id

    stale_request = await harness.command(832, refs="stale")
    stale = await harness.catalog.reserve_or_resume(stale_request)
    harness.db.execute("UPDATE catalog_meta SET value = '2' WHERE key = 'owner_generation'")
    reclaimed_stale = await harness.catalog.reserve_or_resume(stale_request)
    assert reclaimed_stale.outcome == "resumed"
    assert reclaimed_stale.lease is not None
    assert reclaimed_stale.lease.owner_generation == 2
    with pytest.raises(PublicOperationError) as fenced:
        await harness.catalog.advance_phase(stale, StartPhase.BUNDLE_READY)
    assert fenced.value.code is PublicErrorCode.OPERATION_PENDING
