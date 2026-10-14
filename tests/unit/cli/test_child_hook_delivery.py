"""Child attribution gaps cannot consume parent advice or frontier notices."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from finishup.adapters.integrations.codex_lifecycle import (
    acquire_session_lock,
    load_mapping,
    mapping_from_start_ids,
    queue_mapping_store,
    scoped_child_session_id,
    store_mapping,
)
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli.hooks import bind_start_mapping_outcome, recover_pending_start_mapping
from finishup.cli.observe_hooks import handle_claude_observe, handle_observe
from finishup.domain.observation import ObservationSource
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, new_id


@pytest.fixture(autouse=True)
def isolated_codex_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(mode=0o700)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))


@pytest.mark.parametrize("attribution_gap", [False, True])
def test_attribution_gap_without_child_alias_never_peeks_parent_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attribution_gap: bool,
) -> None:
    """The ordinary parent control reaches delivery; an explicit child gap fences it."""

    host_session = "claude:shared-parent-delivery"
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, host_session)
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=host_session,
            yoetz_task_id=new_id(IdKind.TASK),
            yoetz_session_id=new_id(IdKind.SESSION),
            yoetz_writer_id=new_id(IdKind.WRITER),
            last_frontier="0:genesis",
        ),
        _state=tmp_path,
    )
    peeks: list[str] = []

    def peek_advice(*_args: object, **_kwargs: object) -> None:
        peeks.append("advice")

    def peek_frontier(*_args: object, **_kwargs: object) -> None:
        peeks.append("frontier")

    monkeypatch.setattr(LocalObservationStore, "peek_advice_for_delivery", peek_advice)
    monkeypatch.setattr(LocalObservationStore, "peek_frontier_motion", peek_frontier)
    payload = {
        "session_id": host_session,
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__plugin_finishup_finishup__check",
        "tool_use_id": "child-check-call",
        "success": False,
    }

    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(payload).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            source=ObservationSource.CLAUDE_HOOK,
            skip_service=True,
            _child_attribution_gap=attribution_gap,
        )
        == 0
    )

    # The hook never peeks frontier motion any more: observation-only motion is not a
    # notice (#915), so only the advice channel is consulted.
    assert peeks == ([] if attribution_gap else ["advice"])


@pytest.mark.parametrize("child_signal", ["unmapped_agent", "foreign_result", "failed_request"])
def test_unbound_child_callbacks_never_use_parent_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    child_signal: str,
) -> None:
    """Missing child routing remains a gap even when the parent has a healthy mapping."""

    host_session = "shared-parent"
    is_codex = child_signal == "unmapped_agent"
    parent_lane = host_session if is_codex else f"claude:{host_session}"
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, parent_lane)
    parent = mapping_from_start_ids(
        codex_session_id=parent_lane,
        yoetz_task_id=new_id(IdKind.TASK),
        yoetz_session_id=new_id(IdKind.SESSION),
        yoetz_writer_id=new_id(IdKind.WRITER),
        last_frontier="0:genesis",
    )
    store_mapping(parent, _state=tmp_path)
    peeks: list[str] = []

    def peek_advice(*_args: object, **_kwargs: object) -> None:
        peeks.append("advice")

    def peek_frontier(*_args: object, **_kwargs: object) -> None:
        peeks.append("frontier")

    monkeypatch.setattr(LocalObservationStore, "peek_advice_for_delivery", peek_advice)
    monkeypatch.setattr(LocalObservationStore, "peek_frontier_motion", peek_frontier)
    payload: dict[str, object] = {
        "session_id": host_session,
        "hook_event_name": "PostToolUse",
        "tool_name": "shell" if is_codex else "mcp__plugin_finishup_finishup__check",
        "tool_use_id": "unbound-child-call",
        "success": True,
    }
    if child_signal == "unmapped_agent":
        payload["agent_id"] = "native-child-without-mapping"
    elif child_signal == "foreign_result":
        payload["tool_response"] = {
            "structuredContent": {"ok": True, "task_id": new_id(IdKind.TASK)}
        }
    else:
        payload["hook_event_name"] = "PostToolUseFailure"
        payload["tool_input"] = {"session_id": new_id(IdKind.SESSION)}
        payload["success"] = False

    out = io.BytesIO()
    if is_codex:
        result = handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(payload).encode(),
            stdout=out,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
    else:
        result = handle_claude_observe(
            event_name="PostToolUseFailure" if child_signal == "failed_request" else "PostToolUse",
            stdin_bytes=json.dumps(payload).encode(),
            stdout=out,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )

    assert result == 0
    assert peeks == []
    assert LocalObservationStore(_state=tmp_path).list_pending_outbox_rows(workspace) == ()


@pytest.mark.parametrize("child_identity", [None, "native-standalone-child"])
def test_standalone_start_in_child_preserves_parent_route(
    tmp_path: Path, child_identity: str | None
) -> None:
    """A parent's explicit sibling start stays supported; a child's cannot replace it."""

    host_session = "standalone-shared-host"
    parent = mapping_from_start_ids(
        codex_session_id=host_session,
        yoetz_task_id=new_id(IdKind.TASK),
        yoetz_session_id=new_id(IdKind.SESSION),
        yoetz_writer_id=new_id(IdKind.WRITER),
        last_frontier="0:genesis",
    )
    store_mapping(parent, _state=tmp_path)
    next_task = new_id(IdKind.TASK)
    payload: dict[str, JsonValue] = {
        "session_id": host_session,
        "tool_name": "mcp__finishup__start",
        "tool_response": {
            "structuredContent": {
                "ok": True,
                "outcome": "created",
                "task_id": next_task,
                "parent_task_id": None,
                "session_id": new_id(IdKind.SESSION),
                "writer_id": new_id(IdKind.WRITER),
            }
        },
    }
    if child_identity is not None:
        payload["agent_id"] = child_identity

    outcome = bind_start_mapping_outcome(payload, _state=tmp_path)
    after = load_mapping(host_session, _state=tmp_path)
    if child_identity is None:
        assert outcome == "bound"
        assert after is not None and after.yoetz_task_id == next_task
    else:
        assert outcome in {"bound", "start_bind_child_lane_unbound"}
        assert after == parent


def test_claude_conflicting_nested_alias_does_not_persist_a_child_route(tmp_path: Path) -> None:
    """Sanitization cannot hide an alias conflict from start mapping admission."""

    host_session = "claude-conflicting-start"
    parent_lane = f"claude:{host_session}"
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, parent_lane)
    parent = mapping_from_start_ids(
        codex_session_id=parent_lane,
        yoetz_task_id=new_id(IdKind.TASK),
        yoetz_session_id=new_id(IdKind.SESSION),
        yoetz_writer_id=new_id(IdKind.WRITER),
        last_frontier="0:genesis",
    )
    store_mapping(parent, _state=tmp_path)
    child_task = new_id(IdKind.TASK)
    payload = {
        "session_id": host_session,
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__plugin_finishup_finishup__start",
        "tool_use_id": "conflicting-child-start",
        "agent_id": "native-child-a",
        "tool_input": {"agent_id": "native-child-b"},
        "tool_response": {
            "structuredContent": {
                "ok": True,
                "outcome": "attached",
                "task_id": child_task,
                "parent_task_id": parent.yoetz_task_id,
                "session_id": new_id(IdKind.SESSION),
                "writer_id": new_id(IdKind.WRITER),
            }
        },
    }
    assert (
        handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(payload).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert load_mapping(parent_lane, _state=tmp_path) == parent
    for kind, identity in (
        ("host", "native-child-a"),
        ("host", "native-child-b"),
        ("task", child_task),
    ):
        lane = scoped_child_session_id(
            parent_lane, host="claude", identity=identity, identity_kind=kind
        )
        assert not recover_pending_start_mapping(lane, _state=tmp_path).pending
        assert load_mapping(lane, _state=tmp_path) is None


def test_standalone_child_start_cannot_replace_a_locked_queued_parent(tmp_path: Path) -> None:
    """An unmaterialized parent mapping is still an owned lane during contention."""

    host_session = "queued-standalone-shared-host"
    parent = mapping_from_start_ids(
        codex_session_id=host_session,
        yoetz_task_id=new_id(IdKind.TASK),
        yoetz_session_id=new_id(IdKind.SESSION),
        yoetz_writer_id=new_id(IdKind.WRITER),
        last_frontier="0:genesis",
    )
    queue_mapping_store(parent, _state=tmp_path)
    payload: dict[str, JsonValue] = {
        "session_id": host_session,
        "agent_id": "queued-standalone-child",
        "tool_name": "mcp__finishup__start",
        "tool_response": {
            "structuredContent": {
                "ok": True,
                "outcome": "created",
                "task_id": new_id(IdKind.TASK),
                "parent_task_id": None,
                "session_id": new_id(IdKind.SESSION),
                "writer_id": new_id(IdKind.WRITER),
            }
        },
    }
    with acquire_session_lock(host_session, _state=tmp_path) as owned:
        assert owned
        bind_start_mapping_outcome(payload, _state=tmp_path)
        assert load_mapping(host_session, _state=tmp_path) is None

    assert not recover_pending_start_mapping(host_session, _state=tmp_path).pending
    assert load_mapping(host_session, _state=tmp_path) == parent
