"""Durable host annotation and cooperative binding coverage."""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime

import apsw
import pytest

from finishup.adapters.sqlite.host_lineage import SqliteHostLineageRegistry
from finishup.domain.host_lineage import host_lineage_from_payload
from finishup.domain.observation import ObservationSource
from finishup.ports.host_lineage import (
    HostLineageRegistryError,
    HostLineageRegistryReason,
)
from finishup.protocol.ids import IdKind, new_id

pytestmark = pytest.mark.anyio


_INSTALLATION = new_id(IdKind.INSTALLATION)
_SESSION = "hmac-sha256:" + ("ab" * 32)


class _Mac:
    def mac(self, domain: bytes, message: bytes) -> str:
        return (
            "hmac-sha256:"
            + hmac.new(b"test-host-lineage", domain + message, hashlib.sha256).hexdigest()
        )


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=UTC)

    def now_utc(self) -> datetime:
        return self.value

    def monotonic_seconds(self) -> float:
        return self.value.timestamp()

    def advance(self) -> None:
        from datetime import timedelta

        self.value += timedelta(milliseconds=1)


def _task() -> str:
    return new_id(IdKind.TASK)


def _schema(db: apsw.Connection) -> None:
    db.execute("PRAGMA foreign_keys = ON")
    db.execute(
        """
        CREATE TABLE task_routes (
            task_id TEXT PRIMARY KEY,
            parent_task_id TEXT REFERENCES task_routes(task_id)
        ) STRICT
        """
    )
    db.execute(
        """
        CREATE TABLE host_lineage_annotations (
            installation_id TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            parent_task_id TEXT NOT NULL REFERENCES task_routes(task_id),
            host_profile TEXT NOT NULL,
            subagent_id_commitment TEXT NOT NULL,
            parent_tool_call_id_commitment TEXT,
            parent_conversation_id_commitment TEXT,
            conversation_id_commitment TEXT,
            phase_mask INTEGER NOT NULL,
            source_mask INTEGER NOT NULL,
            last_session_commitment TEXT NOT NULL,
            first_observed_at TEXT NOT NULL,
            last_observed_at TEXT NOT NULL,
            bound_child_task_id TEXT REFERENCES task_routes(task_id),
            bound_at TEXT,
            PRIMARY KEY (installation_id, correlation_id)
        ) STRICT, WITHOUT ROWID
        """
    )
    db.execute(
        """
        CREATE TABLE host_lineage_annotation_aliases (
            installation_id TEXT NOT NULL,
            parent_task_id TEXT NOT NULL REFERENCES task_routes(task_id),
            host_profile TEXT NOT NULL,
            alias_kind TEXT NOT NULL,
            alias_commitment TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            PRIMARY KEY (
                installation_id,
                parent_task_id,
                host_profile,
                alias_kind,
                alias_commitment,
                correlation_id
            ),
            FOREIGN KEY (installation_id, correlation_id)
                REFERENCES host_lineage_annotations(installation_id, correlation_id)
                ON DELETE CASCADE
        ) STRICT, WITHOUT ROWID
        """
    )


def _registry(db: apsw.Connection, clock: _Clock) -> SqliteHostLineageRegistry:
    return SqliteHostLineageRegistry(
        db,
        installation_id=_INSTALLATION,
        mac=_Mac(),
        clock=clock,
    )


def _observation(
    event_kind: str,
    subagent_id: str,
    *,
    parent_tool_call_id: str | None = None,
):
    payload: dict[str, str] = {"subagent_id": subagent_id}
    if parent_tool_call_id is not None:
        payload["parent_tool_call_id"] = parent_tool_call_id
    result = host_lineage_from_payload("codex", event_kind, payload)
    assert result is not None
    return result


def test_registry_requires_catalog_migration() -> None:
    db = apsw.Connection(":memory:")
    try:
        with pytest.raises(HostLineageRegistryError) as error:
            SqliteHostLineageRegistry(
                db,
                installation_id=_INSTALLATION,
                mac=_Mac(),
                clock=_Clock(),
            )
        assert error.value.reason is HostLineageRegistryReason.MIGRATION_REQUIRED
    finally:
        db.close(force=True)


async def test_registry_reconciles_hook_stream_aliases_and_replays_after_restart() -> None:
    db = apsw.Connection(":memory:")
    _schema(db)
    parent = _task()
    db.execute("INSERT INTO task_routes(task_id, parent_task_id) VALUES (?, NULL)", (parent,))
    clock = _Clock()
    registry = _registry(db, clock)
    try:
        start = await registry.record_host_lineage_observation(
            parent,
            _observation("SubagentStart", "worker-1", parent_tool_call_id="call-1"),
            observed_session_commitment=_SESSION,
            source=ObservationSource.CODEX_HOOK,
        )
        assert start.observed_phases == ("start",)
        assert start.source_mask == 1
        assert start.parent_tool_call_id is not None
        raw = db.execute(
            "SELECT COUNT(*) FROM host_lineage_annotations WHERE parent_task_id = ?", (parent,)
        ).fetchone()
        assert raw == (1,)

        clock.advance()
        stop = await registry.record_host_lineage_observation(
            parent,
            _observation("SubagentStop", "worker-1"),
            observed_session_commitment="hmac-sha256:" + ("cd" * 32),
            source=ObservationSource.CODEX_SESSION_STREAM,
        )
        assert stop.correlation_id == start.correlation_id
        assert stop.observed_phases == ("start", "stop")
        assert stop.source_mask == 3
        assert stop.parent_tool_call_id == start.parent_tool_call_id
        assert await registry.list_provisional_annotations(parent) == (stop,)
        resolved = await registry.find_host_lineage_observation(
            parent,
            _observation("SubagentStop", "worker-1"),
        )
        assert resolved == stop

        # Replaying either source is idempotent and does not create a second annotation.
        replay = await registry.record_host_lineage_observation(
            parent,
            _observation("SubagentStop", "worker-1"),
            observed_session_commitment="hmac-sha256:" + ("cd" * 32),
            source=ObservationSource.CODEX_SESSION_STREAM,
        )
        assert replay.correlation_id == stop.correlation_id
        assert db.execute(
            "SELECT COUNT(*) FROM host_lineage_annotations WHERE parent_task_id = ?", (parent,)
        ).fetchone() == (1,)

        # A fresh adapter over the same durable catalog retains the same correlation and aliases.
        reopened = _registry(db, clock)
        listed = await reopened.list_provisional_annotations(parent)
        assert tuple(item.correlation_id for item in listed) == (start.correlation_id,)
        assert listed[0].observed_phases == ("start", "stop")
    finally:
        db.close(force=True)


async def test_registry_scopes_reused_host_identity_to_parent_and_binds_hidden_row() -> None:
    db = apsw.Connection(":memory:")
    _schema(db)
    parent_a, parent_b = _task(), _task()
    child_a, child_b = _task(), _task()
    db.executemany(
        "INSERT INTO task_routes(task_id, parent_task_id) VALUES (?, ?)",
        ((parent_a, None), (parent_b, None), (child_a, parent_a), (child_b, parent_b)),
    )
    clock = _Clock()
    registry = _registry(db, clock)
    try:
        first = await registry.record_host_lineage_observation(
            parent_a,
            _observation("SubagentStart", "reused-worker", parent_tool_call_id="call-a"),
            observed_session_commitment=_SESSION,
            source=ObservationSource.CODEX_HOOK,
        )
        second = await registry.record_host_lineage_observation(
            parent_b,
            _observation("SubagentStart", "reused-worker", parent_tool_call_id="call-a"),
            observed_session_commitment=_SESSION,
            source=ObservationSource.CODEX_HOOK,
        )
        assert first.correlation_id != second.correlation_id
        assert len(await registry.list_provisional_annotations(parent_a)) == 1
        assert len(await registry.list_provisional_annotations(parent_b)) == 1

        bound = await registry.bind_provisional_annotation(parent_a, first.correlation_id, child_a)
        assert bound.bound_child_task_id == child_a
        assert bound.bound_at is not None
        assert await registry.list_provisional_annotations(parent_a) == ()
        resolved_bound = await registry.find_host_lineage_observation(
            parent_a,
            _observation("SubagentStop", "reused-worker", parent_tool_call_id="call-a"),
        )
        assert resolved_bound == bound
        assert (
            await registry.bind_provisional_annotation(parent_a, first.correlation_id, child_a)
        ).bound_child_task_id == child_a
        with pytest.raises(HostLineageRegistryError) as error:
            await registry.bind_provisional_annotation(parent_a, first.correlation_id, child_b)
        assert error.value.reason is HostLineageRegistryReason.BINDING_CONFLICT

        # The cooperative start seam can bind from raw host values; no raw value is returned.
        bound_second = await registry.bind_host_lineage_identity(
            parent_b,
            child_b,
            host="codex",
            subagent_id="reused-worker",
            parent_tool_call_id="call-a",
        )
        assert bound_second is not None
        assert bound_second.bound_child_task_id == child_b
        assert await registry.list_provisional_annotations(parent_b) == ()

        with pytest.raises(HostLineageRegistryError) as error:
            await registry.bind_host_lineage_identity(
                parent_b,
                child_b,
                host="claude",
                correlation_id=second.correlation_id,
            )
        assert error.value.reason is HostLineageRegistryReason.IDENTITY_CONFLICT
    finally:
        db.close(force=True)


async def test_registry_rejects_ambiguous_child_only_alias() -> None:
    db = apsw.Connection(":memory:")
    _schema(db)
    parent, child = _task(), _task()
    db.executemany(
        "INSERT INTO task_routes(task_id, parent_task_id) VALUES (?, ?)",
        ((parent, None), (child, parent)),
    )
    registry = _registry(db, _Clock())
    try:
        await registry.record_host_lineage_observation(
            parent,
            _observation("SubagentStart", "ambiguous-worker", parent_tool_call_id="call-a"),
            observed_session_commitment=_SESSION,
            source=ObservationSource.CODEX_HOOK,
        )
        await registry.record_host_lineage_observation(
            parent,
            _observation("SubagentStart", "ambiguous-worker", parent_tool_call_id="call-b"),
            observed_session_commitment=_SESSION,
            source=ObservationSource.CODEX_HOOK,
        )
        with pytest.raises(HostLineageRegistryError) as error:
            await registry.record_host_lineage_observation(
                parent,
                _observation("SubagentStop", "ambiguous-worker"),
                observed_session_commitment=_SESSION,
                source=ObservationSource.CODEX_SESSION_STREAM,
            )
        assert error.value.reason is HostLineageRegistryReason.ANNOTATION_AMBIGUOUS
        assert len(await registry.list_provisional_annotations(parent)) == 2
    finally:
        db.close(force=True)


async def test_registry_reports_child_anchor_context_conflict_without_duplicate_insert() -> None:
    db = apsw.Connection(":memory:")
    _schema(db)
    parent = _task()
    db.execute("INSERT INTO task_routes(task_id, parent_task_id) VALUES (?, NULL)", (parent,))
    registry = _registry(db, _Clock())
    first = host_lineage_from_payload(
        "codex",
        "SubagentStart",
        {"subagent_id": "worker-context", "parent_conversation_id": "conversation-a"},
    )
    second = host_lineage_from_payload(
        "codex",
        "SubagentStop",
        {"subagent_id": "worker-context", "parent_conversation_id": "conversation-b"},
    )
    assert first is not None and second is not None
    try:
        await registry.record_host_lineage_observation(
            parent,
            first,
            observed_session_commitment=_SESSION,
            source=ObservationSource.CODEX_HOOK,
        )
        with pytest.raises(HostLineageRegistryError) as error:
            await registry.record_host_lineage_observation(
                parent,
                second,
                observed_session_commitment=_SESSION,
                source=ObservationSource.CODEX_SESSION_STREAM,
            )
        assert error.value.reason is HostLineageRegistryReason.IDENTITY_CONFLICT
        assert len(await registry.list_provisional_annotations(parent)) == 1
    finally:
        db.close(force=True)


async def test_binding_preflight_validates_all_selectors_without_mutation() -> None:
    db = apsw.Connection(":memory:")
    _schema(db)
    parent, child = _task(), _task()
    db.executemany(
        "INSERT INTO task_routes(task_id, parent_task_id) VALUES (?, ?)",
        ((parent, None), (child, parent)),
    )
    clock = _Clock()
    registry = _registry(db, clock)
    try:
        annotation = await registry.record_host_lineage_observation(
            parent,
            _observation("SubagentStart", "worker", parent_tool_call_id="call-a"),
            observed_session_commitment=_SESSION,
            source=ObservationSource.CODEX_HOOK,
        )
        clock.advance()
        for selectors in (
            {"correlation_id": annotation.correlation_id, "parent_tool_call_id": "call-b"},
            {
                "correlation_id": annotation.correlation_id,
                "subagent_id": "worker",
                "parent_tool_call_id": "call-b",
            },
            {"correlation_id": "malformed", "subagent_id": "worker"},
        ):
            with pytest.raises(HostLineageRegistryError) as error:
                await registry.bind_host_lineage_identity(
                    parent,
                    child,
                    correlation_id=selectors.get("correlation_id"),
                    subagent_id=selectors.get("subagent_id"),
                    parent_tool_call_id=selectors.get("parent_tool_call_id"),
                )
            assert error.value.reason is HostLineageRegistryReason.IDENTITY_CONFLICT
        # Unknown direct selectors cannot be ignored to bind another annotation.
        assert (
            await registry.bind_host_lineage_identity(
                parent, child, correlation_id="hmac-sha256:" + "0" * 64, subagent_id="worker"
            )
            is None
        )
        validated = await registry.bind_host_lineage_identity(
            parent,
            child,
            host="codex",
            subagent_id="worker",
            parent_tool_call_id="call-a",
            correlation_id=annotation.correlation_id,
            validate_only=True,
        )
        assert validated == annotation
        assert await registry.list_provisional_annotations(parent) == (annotation,)
        bound = await registry.bind_host_lineage_identity(
            parent, child, host="codex", subagent_id="worker", parent_tool_call_id="call-a"
        )
        assert bound is not None and bound.bound_child_task_id == child
        assert (
            await registry.bind_host_lineage_identity(
                parent, child, correlation_id=annotation.correlation_id, validate_only=True
            )
            == bound
        )
    finally:
        db.close(force=True)


async def test_bound_child_only_row_cannot_absorb_later_strong_call() -> None:
    from types import SimpleNamespace
    from typing import cast

    from finishup.application.observation_coordinator import ObservationCoordinator
    from finishup.cli.observe_hooks import map_hook_payload_to_envelope

    db = apsw.Connection(":memory:")
    _schema(db)
    parent, child_a, child_b = _task(), _task(), _task()
    db.executemany(
        "INSERT INTO task_routes(task_id, parent_task_id) VALUES (?, ?)",
        ((parent, None), (child_a, parent), (child_b, parent)),
    )
    registry = _registry(db, _Clock())
    coordinator = cast(ObservationCoordinator, SimpleNamespace(host_lineage_registry=registry))
    strong = _observation("SubagentStop", "worker", parent_tool_call_id="call-b")
    envelope = map_hook_payload_to_envelope(
        "SubagentStop",
        {"subagent_id": "worker", "parent_tool_call_id": "call-b"},
        session_commitment=_SESSION,
        event_ordinal=1,
        key_material=b"k" * 32,
        source_generation=1,
    )

    async def advice_refs() -> tuple[tuple[str, str], ...]:
        return await ObservationCoordinator._lineage_refs_for_advice(  # pyright: ignore[reportPrivateUsage]
            coordinator, parent, (envelope,)
        )

    try:
        weak = await registry.record_host_lineage_observation(
            parent,
            _observation("SubagentStart", "worker"),
            observed_session_commitment=_SESSION,
            source=ObservationSource.CODEX_HOOK,
        )
        await registry.bind_provisional_annotation(parent, weak.correlation_id, child_a)
        assert await registry.find_host_lineage_observation(parent, strong) is None
        assert await advice_refs() == ()
        for validate_only in (True, False):
            assert (
                await registry.bind_host_lineage_identity(
                    parent,
                    child_b,
                    host="codex",
                    subagent_id="worker",
                    parent_tool_call_id="call-b",
                    validate_only=validate_only,
                )
                is None
            )
        later = await registry.record_host_lineage_observation(
            parent,
            strong,
            observed_session_commitment=_SESSION,
            source=ObservationSource.CODEX_HOOK,
        )
        assert later.correlation_id != weak.correlation_id
        assert later.bound_child_task_id is None
        assert await advice_refs() == ((envelope.source_identity, later.correlation_id),)
        bound = await registry.bind_host_lineage_identity(
            parent,
            child_b,
            host="codex",
            subagent_id="worker",
            parent_tool_call_id="call-b",
        )
        assert bound is not None and bound.bound_child_task_id == child_b
        assert await advice_refs() == ((envelope.source_identity, child_b),)
        # Neither recording nor binding the stronger pair rewrites the earlier attribution.
        prior = await registry.bind_provisional_annotation(parent, weak.correlation_id, child_a)
        assert prior.parent_tool_call_id is None
        assert prior.bound_child_task_id == child_a
        restarted = _registry(db, _Clock())
        assert await restarted.find_host_lineage_observation(parent, strong) == bound
    finally:
        db.close(force=True)


async def test_latest_open_host_operation_counts_only_unstopped_starts_in_bound() -> None:
    """The in-flight contact hold reads started, not yet stopped children per parent (#837)."""

    from datetime import timedelta

    from finishup.domain.values import timestamp_from_datetime

    db = apsw.Connection(":memory:")
    _schema(db)
    parent, other, child = _task(), _task(), _task()
    for task in (parent, other):
        db.execute("INSERT INTO task_routes(task_id, parent_task_id) VALUES (?, NULL)", (task,))
    db.execute("INSERT INTO task_routes(task_id, parent_task_id) VALUES (?, ?)", (child, parent))
    clock = _Clock()
    registry = _registry(db, clock)
    start = timestamp_from_datetime(clock.now_utc())
    try:
        assert (
            await registry.latest_open_host_operation(
                parent, not_before=start, session_commitment=_SESSION
            )
            is None
        )
        await registry.record_host_lineage_observation(
            parent,
            _observation("SubagentStart", "finished", parent_tool_call_id="call-1"),
            observed_session_commitment=_SESSION,
            source=ObservationSource.CODEX_HOOK,
        )
        clock.value += timedelta(minutes=5)
        await registry.record_host_lineage_observation(
            parent,
            _observation("SubagentStop", "finished"),
            observed_session_commitment=_SESSION,
            source=ObservationSource.CODEX_HOOK,
        )
        assert (
            await registry.latest_open_host_operation(
                parent, not_before=start, session_commitment=_SESSION
            )
            is None
        )

        running_at = timestamp_from_datetime(clock.now_utc())
        running = await registry.record_host_lineage_observation(
            parent,
            _observation("SubagentStart", "running", parent_tool_call_id="call-2"),
            observed_session_commitment=_SESSION,
            source=ObservationSource.CODEX_HOOK,
        )
        # A later stop-only observation of an unrelated child is not an open operation.
        await registry.record_host_lineage_observation(
            parent,
            _observation("SubagentStop", "stop-only"),
            observed_session_commitment=_SESSION,
            source=ObservationSource.CODEX_HOOK,
        )
        assert (
            await registry.latest_open_host_operation(
                parent, not_before=start, session_commitment=_SESSION
            )
            == running_at
        )
        assert (
            await registry.latest_open_host_operation(
                parent,
                not_before=start,
                session_commitment="hmac-sha256:" + ("ef" * 32),
            )
            is None
        )
        assert (
            await registry.latest_open_host_operation(
                other, not_before=start, session_commitment=_SESSION
            )
            is None
        )
        # Binding a FinishUP child does not end the host operation under the parent session.
        await registry.bind_provisional_annotation(parent, running.correlation_id, child)
        assert (
            await registry.latest_open_host_operation(
                parent, not_before=start, session_commitment=_SESSION
            )
            == running_at
        )
        # Starts older than the bound are ignored.
        later = timestamp_from_datetime(clock.now_utc() + timedelta(milliseconds=1))
        assert (
            await registry.latest_open_host_operation(
                parent, not_before=later, session_commitment=_SESSION
            )
            is None
        )
    finally:
        db.close(force=True)
