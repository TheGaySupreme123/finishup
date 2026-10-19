"""Focused regressions for shared-session child hook mapping ownership."""

from __future__ import annotations

from pathlib import Path

import pytest

from finishup.adapters.integrations.codex_lifecycle import (
    LifecycleMapping,
    acquire_session_lock,
    load_mapping,
    mapping_from_start_ids,
    mapping_path,
    queue_mapping_store,
    scoped_child_session_id,
    store_mapping,
)
from finishup.cli.hooks import bind_start_mapping_outcome, recover_pending_start_mapping
from finishup.protocol.canonical import JsonValue

PARENT_TASK = "tsk_00000000-0000-4000-8000-000000000001"
PARENT_SESSION = "ses_00000000-0000-4000-8000-000000000002"
PARENT_WRITER = "wri_00000000-0000-4000-8000-000000000003"
CHILD_TASK = "tsk_00000000-0000-4000-8000-000000000004"
CHILD_SESSION = "ses_00000000-0000-4000-8000-000000000005"
CHILD_WRITER = "wri_00000000-0000-4000-8000-000000000006"
OLD_CHILD_TASK = "tsk_00000000-0000-4000-8000-000000000007"
OLD_CHILD_SESSION = "ses_00000000-0000-4000-8000-000000000008"
OLD_CHILD_WRITER = "wri_00000000-0000-4000-8000-000000000009"
NEW_CHILD_TASK = "tsk_00000000-0000-4000-8000-00000000000a"
NEW_CHILD_SESSION = "ses_00000000-0000-4000-8000-00000000000b"
NEW_CHILD_WRITER = "wri_00000000-0000-4000-8000-00000000000c"


def _mapping(
    codex_session_id: str,
    *,
    task_id: str,
    session_id: str,
    writer_id: str,
    frontier: str | None = None,
) -> LifecycleMapping:
    return mapping_from_start_ids(
        codex_session_id=codex_session_id,
        finishup_task_id=task_id,
        finishup_session_id=session_id,
        finishup_writer_id=writer_id,
        last_frontier=frontier,
    )


def _child_start_payload(
    host_session: str,
    *,
    child_task: str,
    child_session: str,
    child_writer: str,
    parent_task: str = PARENT_TASK,
    **aliases: str,
) -> dict[str, JsonValue]:
    payload: dict[str, JsonValue] = {
        "session_id": host_session,
        "tool_name": "mcp__finishup__start",
        "tool_response": {
            "structuredContent": {
                "ok": True,
                "outcome": "attached",
                "task_id": child_task,
                "parent_task_id": parent_task,
                "session_id": child_session,
                "writer_id": child_writer,
            }
        },
    }
    payload.update(aliases)
    return payload


def test_queued_parent_survives_shared_session_child_attach(tmp_path: Path) -> None:
    """A queued parent route is recovered before attaching a child lane."""

    host_session = "codex-queued-shared-parent"
    parent = _mapping(
        host_session,
        task_id=PARENT_TASK,
        session_id=PARENT_SESSION,
        writer_id=PARENT_WRITER,
        frontier="4:sha256:" + "a" * 64,
    )
    queue_mapping_store(parent, _state=tmp_path)
    assert load_mapping(host_session, _state=tmp_path) is None

    payload = _child_start_payload(
        host_session,
        child_task=CHILD_TASK,
        child_session=CHILD_SESSION,
        child_writer=CHILD_WRITER,
        subagent_id="native-child-1",
    )

    assert bind_start_mapping_outcome(payload, _state=tmp_path, host="codex") == "bound"
    assert load_mapping(host_session, _state=tmp_path) == parent
    assert not recover_pending_start_mapping(host_session, _state=tmp_path).pending

    host_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity="native-child-1",
        identity_kind="host",
    )
    mapping = load_mapping(host_lane, _state=tmp_path)
    assert mapping is not None
    assert (mapping.finishup_task_id, mapping.finishup_session_id, mapping.finishup_writer_id) == (
        CHILD_TASK,
        CHILD_SESSION,
        CHILD_WRITER,
    )


def test_existing_host_child_alias_cannot_be_rebound_to_new_child(tmp_path: Path) -> None:
    """A reused native alias keeps its first task and rejects a stale result."""

    host_session = "codex-child-alias-reuse"
    parent = _mapping(
        host_session,
        task_id=PARENT_TASK,
        session_id=PARENT_SESSION,
        writer_id=PARENT_WRITER,
    )
    store_mapping(parent, _state=tmp_path)
    alias = "reused-native-child"
    host_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity=alias,
        identity_kind="host",
    )
    old_mapping = _mapping(
        host_lane,
        task_id=OLD_CHILD_TASK,
        session_id=OLD_CHILD_SESSION,
        writer_id=OLD_CHILD_WRITER,
        frontier="5:sha256:" + "b" * 64,
    )
    store_mapping(old_mapping, _state=tmp_path)

    stale_payload = _child_start_payload(
        host_session,
        child_task=NEW_CHILD_TASK,
        child_session=NEW_CHILD_SESSION,
        child_writer=NEW_CHILD_WRITER,
        subagent_id=alias,
    )

    assert (
        bind_start_mapping_outcome(stale_payload, _state=tmp_path, host="codex")
        == "start_bind_child_lane_unbound"
    )
    assert load_mapping(host_session, _state=tmp_path) == parent
    assert load_mapping(host_lane, _state=tmp_path) == old_mapping
    new_task_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity=NEW_CHILD_TASK,
        identity_kind="task",
    )
    assert load_mapping(new_task_lane, _state=tmp_path) is None


def test_pending_host_child_alias_conflict_does_not_apply_task_alias(
    tmp_path: Path,
) -> None:
    """A queued stale host alias cannot leave a new task alias partially bound."""

    host_session = "codex-pending-alias-reuse"
    parent = _mapping(
        host_session,
        task_id=PARENT_TASK,
        session_id=PARENT_SESSION,
        writer_id=PARENT_WRITER,
    )
    store_mapping(parent, _state=tmp_path)
    alias = "pending-reused-child"
    host_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity=alias,
        identity_kind="host",
    )
    stale = _mapping(
        host_lane,
        task_id=OLD_CHILD_TASK,
        session_id=OLD_CHILD_SESSION,
        writer_id=OLD_CHILD_WRITER,
    )
    queue_mapping_store(stale, _state=tmp_path)

    payload = _child_start_payload(
        host_session,
        child_task=NEW_CHILD_TASK,
        child_session=NEW_CHILD_SESSION,
        child_writer=NEW_CHILD_WRITER,
        subagent_id=alias,
    )

    assert (
        bind_start_mapping_outcome(payload, _state=tmp_path, host="codex")
        == "start_bind_child_lane_unbound"
    )
    # The stale queued operation remains unapplied and the new task alias is absent.
    assert load_mapping(host_lane, _state=tmp_path) is None
    new_task_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity=NEW_CHILD_TASK,
        identity_kind="task",
    )
    assert load_mapping(new_task_lane, _state=tmp_path) is None


def test_locked_child_lane_keeps_a_replayable_binding(tmp_path: Path) -> None:
    """A child start deferred by lane contention remains recoverable after lock release."""

    host_session = "codex-child-lock-replay"
    parent = _mapping(
        host_session,
        task_id=PARENT_TASK,
        session_id=PARENT_SESSION,
        writer_id=PARENT_WRITER,
    )
    store_mapping(parent, _state=tmp_path)
    alias = "locked-native-child"
    host_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity=alias,
        identity_kind="host",
    )
    payload = _child_start_payload(
        host_session,
        child_task=CHILD_TASK,
        child_session=CHILD_SESSION,
        child_writer=CHILD_WRITER,
        subagent_id=alias,
    )

    with acquire_session_lock(host_lane, _state=tmp_path) as owned:
        assert owned
        assert (
            bind_start_mapping_outcome(payload, _state=tmp_path, host="codex")
            == "start_bind_deferred"
        )
        assert load_mapping(host_lane, _state=tmp_path) is None

    recovery = recover_pending_start_mapping(host_lane, _state=tmp_path)
    assert not recovery.pending
    child_mapping = load_mapping(host_lane, _state=tmp_path)
    assert child_mapping is not None
    assert (
        child_mapping.finishup_task_id,
        child_mapping.finishup_session_id,
        child_mapping.finishup_writer_id,
    ) == (CHILD_TASK, CHILD_SESSION, CHILD_WRITER)
    assert load_mapping(host_session, _state=tmp_path) == parent


def test_applying_and_pending_child_aliases_cannot_change_owner(tmp_path: Path) -> None:
    """A newer queued child result cannot replace an alias while an older apply is recoverable."""

    host_session = "codex-child-applying-pending"
    parent = _mapping(
        host_session,
        task_id=PARENT_TASK,
        session_id=PARENT_SESSION,
        writer_id=PARENT_WRITER,
    )
    store_mapping(parent, _state=tmp_path)
    alias = "recoverable-native-child"
    host_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity=alias,
        identity_kind="host",
    )
    original = _mapping(
        host_lane,
        task_id=OLD_CHILD_TASK,
        session_id=OLD_CHILD_SESSION,
        writer_id=OLD_CHILD_WRITER,
    )
    newer = _mapping(
        host_lane,
        task_id=NEW_CHILD_TASK,
        session_id=NEW_CHILD_SESSION,
        writer_id=NEW_CHILD_WRITER,
    )
    store_mapping(original, _state=tmp_path)
    queue_mapping_store(original, _state=tmp_path)
    pending = mapping_path(host_lane, _state=tmp_path).with_name(f".{host_lane}.pending.json")
    applying = pending.with_name(pending.name + ".applying")
    pending.replace(applying)
    queue_mapping_store(newer, _state=tmp_path)

    payload = _child_start_payload(
        host_session,
        child_task=OLD_CHILD_TASK,
        child_session=OLD_CHILD_SESSION,
        child_writer=OLD_CHILD_WRITER,
        subagent_id=alias,
    )

    assert (
        bind_start_mapping_outcome(payload, _state=tmp_path, host="codex")
        == "start_bind_child_lane_unbound"
    )
    assert load_mapping(host_lane, _state=tmp_path) == original
    assert load_mapping(host_session, _state=tmp_path) == parent


@pytest.mark.parametrize(
    "aliases",
    [
        pytest.param({"subagent_id": "malformed/native/child"}, id="malformed"),
        pytest.param(
            {"subagent_id": "native-child-a", "agent_id": "native-child-b"},
            id="conflicting",
        ),
    ],
)
def test_invalid_child_aliases_do_not_create_task_fallback_lane(
    tmp_path: Path,
    aliases: dict[str, str],
) -> None:
    """Malformed or contradictory aliases fail closed instead of using the task id."""

    host_session = "codex-invalid-child-alias"
    parent = _mapping(
        host_session,
        task_id=PARENT_TASK,
        session_id=PARENT_SESSION,
        writer_id=PARENT_WRITER,
    )
    store_mapping(parent, _state=tmp_path)
    payload = _child_start_payload(
        host_session,
        child_task=CHILD_TASK,
        child_session=CHILD_SESSION,
        child_writer=CHILD_WRITER,
        **aliases,
    )

    assert (
        bind_start_mapping_outcome(payload, _state=tmp_path, host="codex")
        == "start_bind_child_lane_unbound"
    )
    assert load_mapping(host_session, _state=tmp_path) == parent
    task_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity=CHILD_TASK,
        identity_kind="task",
    )
    assert load_mapping(task_lane, _state=tmp_path) is None
