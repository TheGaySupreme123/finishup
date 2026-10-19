"""Codex lifecycle hook handler unit tests."""

from __future__ import annotations

import io
import json
import threading
import uuid
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from finishup.adapters.integrations.codex_lifecycle import (
    load_mapping,
    mapping_from_start_ids,
    mapping_path,
    queue_mapping_store,
    scoped_child_session_id,
    store_mapping,
)
from finishup.cli import app as app_module
from finishup.cli import hooks as hooks_module
from finishup.cli.hooks import (
    FINISHUP_START_TOOL_NAMES,
    INACTIVE_CONTEXT,
    handle_post_tool_use,
    handle_session_start,
    handle_user_prompt_submit,
    intake_cue_text,
)
from finishup.ports.control import ControlClientKind, ControlError
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import OperationFailureModel, StatusRequest


def _task_ids() -> tuple[str, str, str]:
    return new_id(IdKind.TASK), new_id(IdKind.SESSION), new_id(IdKind.WRITER)


def test_user_prompt_submit_cli_forwards_the_explicit_workspace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def operation(name: str):
        assert name == "handle_user_prompt_submit"

        def handle(**kwargs: object) -> int:
            captured.update(kwargs)
            return 0

        return handle

    monkeypatch.setattr(app_module, "_hooks_operation", operation)
    result = CliRunner().invoke(
        app_module.app,
        ["hooks", "user-prompt-submit", "--workspace", "."],
    )

    assert result.exit_code == 0
    assert captured == {"workspace": "."}


def test_session_start_cli_forwards_the_explicit_workspace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The resume/compact status read needs the workspace the daemon fences on (#578)."""

    captured: dict[str, object] = {}

    def operation(name: str):
        assert name == "handle_session_start"

        def handle(**kwargs: object) -> int:
            captured.update(kwargs)
            return 0

        return handle

    monkeypatch.setattr(app_module, "_hooks_operation", operation)
    result = CliRunner().invoke(app_module.app, ["hooks", "session-start", "--workspace", "."])

    assert result.exit_code == 0
    assert captured == {"workspace": "."}


def test_user_prompt_submit_emits_intake_cue_without_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guidance = tmp_path / "guidance"
    guidance.mkdir()
    text = (
        "# When to use FinishUP\n\n"
        "Use FinishUP for material multi-step, delegated, resumable, or verification-heavy work. "
        "Call `start` before substantive work.\n\n"
        "# What FinishUP is\n\n"
        "FinishUP is a local work ledger.\n"
    )
    (guidance / "agent-instructions.md").write_text(text, encoding="utf-8")
    connects: list[object] = []

    async def forbidden_connect(_kind: object) -> object:
        connects.append(_kind)
        raise AssertionError("must not connect")

    monkeypatch.setattr("finishup.cli.hooks.connect_service", forbidden_connect)
    stdout = io.BytesIO()
    code = handle_user_prompt_submit(
        stdin_bytes=b'{"session_id":"s1","hook_event_name":"UserPromptSubmit"}',
        stdout=stdout,
        resource_root=tmp_path,
        _state=tmp_path,
    )
    assert code == 0
    assert connects == []
    payload = json.loads(stdout.getvalue().decode("utf-8"))
    context = payload["hookSpecificOutput"]["additionalContext"]
    assert "Call `start` before substantive work" in context
    assert intake_cue_text(resource_root=tmp_path) in context or context in intake_cue_text(
        resource_root=tmp_path
    )


@pytest.mark.parametrize(
    "tool_name",
    [
        "mcp__finishup__start",
        "mcp__plugin_finishup_finishup__start",
        # The legacy server name a 0.1-0.2.5 registration still carries (ADR-048).
        "mcp__yoetz__start",
        "mcp__plugin_yoetz_yoetz__start",
    ],
)
def test_post_tool_use_successful_start_creates_mapping(tmp_path: Path, tool_name: str) -> None:
    task_id, session_id, writer_id = _task_ids()
    codex_session = "codex-post-1"
    tool_response = {
        "structuredContent": {
            "ok": True,
            "task_id": task_id,
            "session_id": session_id,
            "writer_id": writer_id,
            "frontier": {"sequence": "0", "head_digest": "genesis"},
        }
    }
    payload = {
        "session_id": codex_session,
        "tool_name": tool_name,
        "tool_response": tool_response,
    }
    stdout = io.BytesIO()
    code = handle_post_tool_use(
        stdin_bytes=json.dumps(payload).encode("utf-8"),
        stdout=stdout,
        _state=tmp_path,
    )
    assert code == 0
    mapping = load_mapping(codex_session, _state=tmp_path)
    assert mapping is not None
    assert mapping.finishup_task_id == task_id
    assert mapping.finishup_session_id == session_id
    assert mapping.finishup_writer_id == writer_id
    assert mapping.last_frontier == "0:genesis"


def test_start_tool_names_are_the_closed_current_and_legacy_spellings() -> None:
    """``start`` under either server name binds (ADR-048); nothing resembling it does."""

    assert FINISHUP_START_TOOL_NAMES == {
        "start",
        "mcp__finishup__start",
        "mcp__plugin_finishup_finishup__start",
        "mcp__yoetz__start",
        "mcp__plugin_yoetz_yoetz__start",
    }


@pytest.mark.parametrize(
    "tool_name", ["mcp__yoetzx__start", "mcp__yoetz__restart", "yoetz:start", "mcp__other__start"]
)
def test_post_tool_use_near_miss_start_names_create_no_mapping(
    tmp_path: Path, tool_name: str
) -> None:
    task_id, session_id, writer_id = _task_ids()
    payload = {
        "session_id": "codex-post-near-miss",
        "tool_name": tool_name,
        "tool_response": {
            "structuredContent": {
                "ok": True,
                "task_id": task_id,
                "session_id": session_id,
                "writer_id": writer_id,
                "frontier": {"sequence": "0", "head_digest": "genesis"},
            }
        },
    }
    assert (
        handle_post_tool_use(
            stdin_bytes=json.dumps(payload).encode("utf-8"), stdout=io.BytesIO(), _state=tmp_path
        )
        == 0
    )
    assert load_mapping("codex-post-near-miss", _state=tmp_path) is None


def test_post_tool_use_delegated_start_preserves_parent_mapping(tmp_path: Path) -> None:
    """A delegated result names a child task but keeps the host session on its parent."""

    parent_task, parent_session, parent_writer = _task_ids()
    child_task, _child_session, _child_writer = _task_ids()
    codex_session = "codex-delegate-parent"
    parent_mapping = mapping_from_start_ids(
        codex_session_id=codex_session,
        finishup_task_id=parent_task,
        finishup_session_id=parent_session,
        finishup_writer_id=parent_writer,
        last_frontier="2:sha256:" + "b" * 64,
    )
    store_mapping(parent_mapping, _state=tmp_path)

    payload = {
        "session_id": codex_session,
        "tool_name": "mcp__finishup__start",
        "tool_response": {
            "structuredContent": {
                "ok": True,
                "outcome": "delegated",
                "task_id": child_task,
                "parent_task_id": parent_task,
                "session_id": parent_session,
                "writer_id": parent_writer,
                "frontier": {"sequence": "3", "head_digest": "sha256:" + "c" * 64},
            }
        },
    }

    assert (
        handle_post_tool_use(
            stdin_bytes=json.dumps(payload).encode("utf-8"),
            stdout=io.BytesIO(),
            _state=tmp_path,
        )
        == 0
    )
    mapping = load_mapping(codex_session, _state=tmp_path)
    assert mapping is not None
    assert mapping.finishup_task_id == parent_task
    assert mapping.finishup_session_id == parent_session
    assert mapping.finishup_writer_id == parent_writer
    assert mapping.last_frontier == "3:sha256:" + "c" * 64


def test_post_tool_use_delegated_start_without_parent_does_not_bind_child(
    tmp_path: Path,
) -> None:
    """A malformed delegated success cannot turn its child id into a parent-session mapping."""

    child_task, parent_session, parent_writer = _task_ids()
    codex_session = "codex-delegate-invalid-parent"
    payload = {
        "session_id": codex_session,
        "tool_name": "mcp__finishup__start",
        "tool_response": {
            "structuredContent": {
                "ok": True,
                "outcome": "delegated",
                "task_id": child_task,
                "session_id": parent_session,
                "writer_id": parent_writer,
            }
        },
    }

    assert (
        handle_post_tool_use(
            stdin_bytes=json.dumps(payload).encode("utf-8"),
            stdout=io.BytesIO(),
            _state=tmp_path,
        )
        == 0
    )
    assert load_mapping(codex_session, _state=tmp_path) is None
    assert '"reason":"start_bind_invalid_ids"' in _diagnostics_text(tmp_path)


def test_attached_child_shared_session_preserves_parent_and_binds_scoped_lanes(
    tmp_path: Path,
) -> None:
    parent_task, parent_session, parent_writer = _task_ids()
    child_task, child_session, child_writer = _task_ids()
    host_session = "codex-shared-parent"
    parent = mapping_from_start_ids(
        codex_session_id=host_session,
        finishup_task_id=parent_task,
        finishup_session_id=parent_session,
        finishup_writer_id=parent_writer,
        last_frontier="4:sha256:" + "a" * 64,
    )
    store_mapping(parent, _state=tmp_path)
    payload = {
        "session_id": host_session,
        "subagent_id": "native-child-1",
        "tool_name": "mcp__finishup__start",
        "tool_response": {
            "structuredContent": {
                "ok": True,
                "outcome": "attached",
                "task_id": child_task,
                "parent_task_id": parent_task,
                "session_id": child_session,
                "writer_id": child_writer,
                "frontier": {"sequence": "0", "head_digest": "genesis"},
            }
        },
    }

    assert hooks_module.bind_start_mapping_outcome(payload, _state=tmp_path) == "bound"
    assert load_mapping(host_session, _state=tmp_path) == parent
    host_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity="native-child-1",
        identity_kind="host",
    )
    child_mapping = load_mapping(host_lane, _state=tmp_path)
    assert child_mapping is not None
    assert child_mapping.finishup_task_id == child_task
    assert child_mapping.finishup_session_id == child_session


def test_child_start_reconciles_pending_parent_before_classification(tmp_path: Path) -> None:
    parent_task, parent_session, parent_writer = _task_ids()
    child_task, child_session, child_writer = _task_ids()
    host_session = "codex-pending-parent"
    parent = mapping_from_start_ids(
        codex_session_id=host_session,
        finishup_task_id=parent_task,
        finishup_session_id=parent_session,
        finishup_writer_id=parent_writer,
        last_frontier=None,
    )
    queue_mapping_store(parent, _state=tmp_path)
    payload = {
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

    assert (
        hooks_module.bind_start_mapping_outcome(payload, _state=tmp_path)
        == "start_bind_child_lane_unbound"
    )
    assert load_mapping(host_session, _state=tmp_path) == parent
    task_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity=child_task,
        identity_kind="task",
    )
    assert load_mapping(task_lane, _state=tmp_path) is None


def test_child_alias_cannot_be_rebound_to_another_task(tmp_path: Path) -> None:
    parent_task, parent_session, parent_writer = _task_ids()
    old_child_task, old_child_session, old_child_writer = _task_ids()
    new_child_task, new_child_session, new_child_writer = _task_ids()
    host_session = "codex-alias-reuse"
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=host_session,
            finishup_task_id=parent_task,
            finishup_session_id=parent_session,
            finishup_writer_id=parent_writer,
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    host_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity="reused-child",
        identity_kind="host",
    )
    old_mapping = mapping_from_start_ids(
        codex_session_id=host_lane,
        finishup_task_id=old_child_task,
        finishup_session_id=old_child_session,
        finishup_writer_id=old_child_writer,
        last_frontier=None,
    )
    store_mapping(old_mapping, _state=tmp_path)
    payload = {
        "session_id": host_session,
        "subagent_id": "reused-child",
        "tool_name": "mcp__finishup__start",
        "tool_response": {
            "structuredContent": {
                "ok": True,
                "outcome": "attached",
                "task_id": new_child_task,
                "parent_task_id": parent_task,
                "session_id": new_child_session,
                "writer_id": new_child_writer,
            }
        },
    }

    assert (
        hooks_module.bind_start_mapping_outcome(payload, _state=tmp_path)
        == "start_bind_child_lane_unbound"
    )
    assert load_mapping(host_lane, _state=tmp_path) == old_mapping


def test_conflicting_child_aliases_fail_closed_without_task_fallback(tmp_path: Path) -> None:
    parent_task, parent_session, parent_writer = _task_ids()
    child_task, child_session, child_writer = _task_ids()
    host_session = "codex-conflicting-child"
    parent = mapping_from_start_ids(
        codex_session_id=host_session,
        finishup_task_id=parent_task,
        finishup_session_id=parent_session,
        finishup_writer_id=parent_writer,
        last_frontier=None,
    )
    store_mapping(parent, _state=tmp_path)
    payload = {
        "session_id": host_session,
        "subagent_id": "child-a",
        "agent_id": "child-b",
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

    assert (
        hooks_module.bind_start_mapping_outcome(payload, _state=tmp_path)
        == "start_bind_child_lane_unbound"
    )
    assert load_mapping(host_session, _state=tmp_path) == parent
    task_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity=child_task,
        identity_kind="task",
    )
    assert load_mapping(task_lane, _state=tmp_path) is None


def test_post_tool_use_failed_start_creates_none(tmp_path: Path) -> None:
    payload = {
        "session_id": "codex-fail",
        "tool_name": "mcp__finishup__start",
        "tool_response": {"structuredContent": {"ok": False}},
    }
    code = handle_post_tool_use(
        stdin_bytes=json.dumps(payload).encode("utf-8"),
        stdout=io.BytesIO(),
        _state=tmp_path,
    )
    assert code == 0
    assert load_mapping("codex-fail", _state=tmp_path) is None


def test_post_tool_use_non_start_creates_none(tmp_path: Path) -> None:
    task_id, session_id, writer_id = _task_ids()
    payload = {
        "session_id": "codex-other",
        "tool_name": "mcp__finishup__status",
        "tool_response": {
            "structuredContent": {
                "ok": True,
                "task_id": task_id,
                "session_id": session_id,
                "writer_id": writer_id,
            }
        },
    }
    handle_post_tool_use(
        stdin_bytes=json.dumps(payload).encode("utf-8"),
        stdout=io.BytesIO(),
        _state=tmp_path,
    )
    assert load_mapping("codex-other", _state=tmp_path) is None


def test_post_tool_use_duplicate_idempotent(tmp_path: Path) -> None:
    task_id, session_id, writer_id = _task_ids()
    payload = {
        "session_id": "codex-dup",
        "tool_name": "start",
        "tool_response": {
            "ok": True,
            "task_id": task_id,
            "session_id": session_id,
            "writer_id": writer_id,
            "frontier": {"sequence": "1", "head_digest": "sha256:" + "a" * 64},
        },
    }
    raw = json.dumps(payload).encode("utf-8")
    handle_post_tool_use(stdin_bytes=raw, stdout=io.BytesIO(), _state=tmp_path)
    handle_post_tool_use(stdin_bytes=raw, stdout=io.BytesIO(), _state=tmp_path)
    mapping = load_mapping("codex-dup", _state=tmp_path)
    assert mapping is not None
    assert mapping.finishup_task_id == task_id


def test_start_bind_reconciles_crashed_applying_before_store(tmp_path: Path) -> None:
    """A queued owner result follows an interrupted apply before it is stored."""

    session = "codex-residual-start"
    old = mapping_from_start_ids(
        codex_session_id=session,
        finishup_task_id=new_id(IdKind.TASK),
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier="1:sha256:" + "a" * 64,
    )
    current = mapping_from_start_ids(
        codex_session_id=session,
        finishup_task_id=new_id(IdKind.TASK),
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier="3:sha256:" + "c" * 64,
    )
    queue_mapping_store(old, _state=tmp_path)
    pending = mapping_path(session, _state=tmp_path).with_name(f".{session}.pending.json")
    applying = pending.with_name(pending.name + ".applying")
    pending.replace(applying)

    payload = {
        "session_id": session,
        "tool_name": "mcp__finishup__start",
        "tool_response": {
            "structuredContent": {
                "ok": True,
                "task_id": current.finishup_task_id,
                "session_id": current.finishup_session_id,
                "writer_id": current.finishup_writer_id,
                "frontier": {
                    "sequence": "3",
                    "head_digest": "sha256:" + "c" * 64,
                },
            }
        },
    }

    assert hooks_module.bind_start_mapping_outcome(payload, _state=tmp_path) == "bound"
    assert load_mapping(session, _state=tmp_path) == current
    assert not pending.exists()
    assert not applying.exists()


def test_session_start_clear_reconciles_crashed_applying_before_clear(tmp_path: Path) -> None:
    """Clear removes the route after an interrupted predecessor apply is replayed."""

    session = "codex-residual-clear"
    existing = mapping_from_start_ids(
        codex_session_id=session,
        finishup_task_id=new_id(IdKind.TASK),
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier=None,
    )
    store_mapping(existing, _state=tmp_path)
    queue_mapping_store(existing, _state=tmp_path)
    pending = mapping_path(session, _state=tmp_path).with_name(f".{session}.pending.json")
    applying = pending.with_name(pending.name + ".applying")
    pending.replace(applying)
    assert (
        handle_session_start(
            stdin_bytes=json.dumps(
                {"session_id": session, "source": "clear", "hook_event_name": "SessionStart"}
            ).encode(),
            stdout=io.BytesIO(),
            _state=tmp_path,
        )
        == 0
    )
    assert load_mapping(session, _state=tmp_path) is None
    assert not pending.exists()
    assert not pending.with_name(pending.name + ".applying").exists()


def test_start_bind_owner_coalesces_loser_queue_before_reconcile(tmp_path: Path) -> None:
    """A lock loser queued during owner recovery cannot overwrite after owner return."""

    session = "codex-synchronized-bind"
    owner_mapping = mapping_from_start_ids(
        codex_session_id=session,
        finishup_task_id=new_id(IdKind.TASK),
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier="2:sha256:" + "a" * 64,
    )
    loser_mapping = mapping_from_start_ids(
        codex_session_id=session,
        finishup_task_id=new_id(IdKind.TASK),
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier="1:sha256:" + "b" * 64,
    )
    owner_queue_entered = threading.Event()
    loser_queued = threading.Event()
    errors: list[BaseException] = []
    outcomes: dict[str, str] = {}
    original_queue = hooks_module.queue_mapping_store

    def queue_with_owner_order(mapping: object, *, _state: Path | None = None) -> None:
        assert type(mapping) is type(owner_mapping)
        if mapping == owner_mapping:
            owner_queue_entered.set()
            assert loser_queued.wait(5)
        original_queue(mapping, _state=_state)  # type: ignore[arg-type]
        if mapping == loser_mapping:
            loser_queued.set()

    hooks_module.queue_mapping_store = queue_with_owner_order  # type: ignore[assignment]
    try:

        def owner() -> None:
            try:
                outcomes["owner"] = hooks_module.bind_start_mapping_outcome(
                    {
                        "session_id": session,
                        "tool_name": "mcp__finishup__start",
                        "tool_response": {
                            "structuredContent": {
                                "ok": True,
                                "task_id": owner_mapping.finishup_task_id,
                                "session_id": owner_mapping.finishup_session_id,
                                "writer_id": owner_mapping.finishup_writer_id,
                                "frontier": {
                                    "sequence": "2",
                                    "head_digest": "sha256:" + "a" * 64,
                                },
                            }
                        },
                    },
                    _state=tmp_path,
                )
            except BaseException as exc:  # pragma: no cover - failure relay
                errors.append(exc)

        def loser() -> None:
            try:
                outcomes["loser"] = hooks_module.bind_start_mapping_outcome(
                    {
                        "session_id": session,
                        "tool_name": "mcp__finishup__start",
                        "tool_response": {
                            "structuredContent": {
                                "ok": True,
                                "task_id": loser_mapping.finishup_task_id,
                                "session_id": loser_mapping.finishup_session_id,
                                "writer_id": loser_mapping.finishup_writer_id,
                                "frontier": {
                                    "sequence": "1",
                                    "head_digest": "sha256:" + "b" * 64,
                                },
                            }
                        },
                    },
                    _state=tmp_path,
                )
            except BaseException as exc:  # pragma: no cover - failure relay
                errors.append(exc)

        owner_thread = threading.Thread(target=owner)
        owner_thread.start()
        assert owner_queue_entered.wait(5)
        loser_thread = threading.Thread(target=loser)
        loser_thread.start()
        assert loser_queued.wait(5)
        owner_thread.join(5)
        loser_thread.join(5)
    finally:
        hooks_module.queue_mapping_store = original_queue

    assert not errors
    assert outcomes == {"loser": "start_bind_deferred", "owner": "bound"}
    assert load_mapping(session, _state=tmp_path) == owner_mapping
    pending = mapping_path(session, _state=tmp_path).with_name(f".{session}.pending.json")
    assert not pending.exists()
    assert not pending.with_name(pending.name + ".applying").exists()


def test_clear_owner_coalesces_loser_store_before_reconcile(tmp_path: Path) -> None:
    """A clear owner replaces a lock-loser store before the durable apply pass."""

    from finishup.cli import observe_hooks as observe_hooks_module

    session = "codex-synchronized-clear"
    existing = mapping_from_start_ids(
        codex_session_id=session,
        finishup_task_id=new_id(IdKind.TASK),
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier=None,
    )
    loser = mapping_from_start_ids(
        codex_session_id=session,
        finishup_task_id=new_id(IdKind.TASK),
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier=None,
    )
    store_mapping(existing, _state=tmp_path)
    clear_queue_entered = threading.Event()
    loser_queued = threading.Event()
    errors: list[BaseException] = []
    outcomes: dict[str, str] = {}
    original_clear_queue = observe_hooks_module.queue_mapping_clear
    original_store_queue = hooks_module.queue_mapping_store

    def clear_with_owner_order(codex_session_id: str, *, _state: Path | None = None) -> None:
        clear_queue_entered.set()
        assert loser_queued.wait(5)
        original_clear_queue(codex_session_id, _state=_state)

    def store_from_loser(mapping: object, *, _state: Path | None = None) -> None:
        original_store_queue(mapping, _state=_state)  # type: ignore[arg-type]
        loser_queued.set()

    observe_hooks_module.queue_mapping_clear = clear_with_owner_order  # type: ignore[assignment]
    hooks_module.queue_mapping_store = store_from_loser  # type: ignore[assignment]
    try:

        def owner() -> None:
            try:
                handle_session_start(
                    stdin_bytes=json.dumps(
                        {
                            "session_id": session,
                            "source": "clear",
                            "hook_event_name": "SessionStart",
                        }
                    ).encode(),
                    stdout=io.BytesIO(),
                    _state=tmp_path,
                )
            except BaseException as exc:  # pragma: no cover - failure relay
                errors.append(exc)

        def loser_thread_fn() -> None:
            try:
                outcomes["loser"] = hooks_module.bind_start_mapping_outcome(
                    {
                        "session_id": session,
                        "tool_name": "mcp__finishup__start",
                        "tool_response": {
                            "structuredContent": {
                                "ok": True,
                                "task_id": loser.finishup_task_id,
                                "session_id": loser.finishup_session_id,
                                "writer_id": loser.finishup_writer_id,
                            }
                        },
                    },
                    _state=tmp_path,
                )
            except BaseException as exc:  # pragma: no cover - failure relay
                errors.append(exc)

        owner_thread = threading.Thread(target=owner)
        owner_thread.start()
        assert clear_queue_entered.wait(5)
        loser_thread = threading.Thread(target=loser_thread_fn)
        loser_thread.start()
        assert loser_queued.wait(5)
        owner_thread.join(5)
        loser_thread.join(5)
    finally:
        observe_hooks_module.queue_mapping_clear = original_clear_queue
        hooks_module.queue_mapping_store = original_store_queue

    assert not errors
    assert outcomes == {"loser": "start_bind_deferred"}
    assert load_mapping(session, _state=tmp_path) is None
    pending = mapping_path(session, _state=tmp_path).with_name(f".{session}.pending.json")
    assert not pending.exists()
    assert not pending.with_name(pending.name + ".applying").exists()


def test_post_tool_use_malformed_json_no_traceback(tmp_path: Path) -> None:
    code = handle_post_tool_use(
        stdin_bytes=b"{not-json",
        stdout=io.BytesIO(),
        _state=tmp_path,
    )
    assert code == 0
    assert (
        list((tmp_path / "codex-lifecycle").glob("*.json")) == []
        if (tmp_path / "codex-lifecycle").exists()
        else True
    )


def test_session_start_no_mapping_inactive(tmp_path: Path) -> None:
    stdout = io.BytesIO()
    code = handle_session_start(
        stdin_bytes=json.dumps(
            {"session_id": "missing-map", "source": "resume", "hook_event_name": "SessionStart"}
        ).encode(),
        stdout=stdout,
        _state=tmp_path,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue().decode("utf-8"))
    assert payload["hookSpecificOutput"]["additionalContext"] == INACTIVE_CONTEXT
    assert "tsk_" not in payload["hookSpecificOutput"]["additionalContext"]


class _FakeStatusResult:
    def __init__(self, branch: object) -> None:
        self.root = branch


class _FakeSuccess:
    def __init__(self, task_id: str, session_id: str, writer_id: str) -> None:
        self.task_id = task_id
        self.session_id = session_id
        self.writer_id = writer_id
        self.head_frontier = type("F", (), {"sequence": "3", "head_digest": "sha256:" + "c" * 64})()


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.task_id = ""
        self.session_id = ""
        self.writer_id = ""

    async def status(self, request: object, *, deadline_ms: int | None = None) -> object:
        self.calls.append("status")
        assert deadline_ms is not None
        return _FakeStatusResult(_FakeSuccess(self.task_id, self.session_id, self.writer_id))

    async def start(self, *_args: Any, **_kwargs: Any) -> object:
        raise AssertionError("must not create ledger events")

    async def close(self) -> None:
        return None


def test_session_start_active_with_fake_service(tmp_path: Path) -> None:
    task_id, session_id, writer_id = _task_ids()
    store_mapping(
        mapping_from_start_ids(
            codex_session_id="codex-active",
            finishup_task_id=task_id,
            finishup_session_id=session_id,
            finishup_writer_id=writer_id,
            last_frontier="0:genesis",
        ),
        _state=tmp_path,
    )
    client = _FakeClient()
    client.task_id = task_id
    client.session_id = session_id
    client.writer_id = writer_id

    async def connect(_kind: ControlClientKind) -> _FakeClient:
        return client

    stdout = io.BytesIO()
    code = handle_session_start(
        stdin_bytes=json.dumps({"session_id": "codex-active", "source": "compact"}).encode(),
        stdout=stdout,
        _state=tmp_path,
        connect=connect,
    )
    assert code == 0
    # A compact start reads the compact status, then one bounded obligations view for the
    # post-compaction recap's deliverables (ADR-044); both are reads and create no ledger events.
    assert client.calls == ["status", "status"]
    text = json.loads(stdout.getvalue().decode("utf-8"))["hookSpecificOutput"]["additionalContext"]
    assert task_id in text
    # The context carries a selector guidance recognises (#580): the mapped
    # session/writer for `status`, and `mode=attach` by session id to continue.
    assert session_id in text
    assert writer_id in text
    assert "Then read status with the returned session/writer ids" in text
    assert text.index("call start with mode=attach") < text.index("Then read status")
    assert "for compaction in an already-started host session" in text
    # tb4 n5: one status read after resume or compaction, not a poll between steps.
    assert "read status once" in text
    assert "do not reread status between ordinary steps" in text
    assert f"mode=attach and session_id {session_id}" in text
    assert "create_or_attach" in text
    assert "3:sha256:" in text


def test_session_start_unreachable_service(tmp_path: Path) -> None:
    task_id, session_id, writer_id = _task_ids()
    store_mapping(
        mapping_from_start_ids(
            codex_session_id="codex-down",
            finishup_task_id=task_id,
            finishup_session_id=session_id,
            finishup_writer_id=writer_id,
            last_frontier=None,
        ),
        _state=tmp_path,
    )

    async def connect(_kind: ControlClientKind) -> object:
        raise ControlError("service_unavailable", retryable=True)

    stdout = io.BytesIO()
    code = handle_session_start(
        stdin_bytes=json.dumps({"session_id": "codex-down", "source": "resume"}).encode(),
        stdout=stdout,
        _state=tmp_path,
        connect=connect,  # pyright: ignore[reportArgumentType]
    )
    assert code == 0
    text = json.loads(stdout.getvalue().decode("utf-8"))["hookSpecificOutput"]["additionalContext"]
    assert text == hooks_module._UNAVAILABLE_CONTEXT  # pyright: ignore[reportPrivateUsage]


def _failure_result(
    code: PublicErrorCode,
    *,
    retryable: bool = False,
    safe_details: dict[str, object] | None = None,
) -> _FakeStatusResult:
    error: dict[str, object] = {
        "code": code.value,
        "message": "The requested task attachment conflicts.",
        "retryable": retryable,
        "correlation_id": f"err_{uuid.uuid4()}",
    }
    if safe_details is not None:
        error["safe_details"] = safe_details
    return _FakeStatusResult(
        OperationFailureModel.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "ok": False,
                "error": error,
            }
        )
    )


def _session_start_context_for_failure(
    tmp_path: Path,
    codex_session_id: str,
    result: _FakeStatusResult | Exception,
    *,
    workspace: str | None = None,
) -> str:
    task_id, session_id, writer_id = _task_ids()
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=codex_session_id,
            finishup_task_id=task_id,
            finishup_session_id=session_id,
            finishup_writer_id=writer_id,
            last_frontier="0:genesis",
        ),
        _state=tmp_path,
    )

    class _Client:
        async def status(self, request: object, *, deadline_ms: int | None = None) -> object:
            del request, deadline_ms
            if isinstance(result, Exception):
                raise result
            return result

        async def close(self) -> None:
            return None

    async def connect(_kind: ControlClientKind) -> _Client:
        return _Client()

    stdout = io.BytesIO()
    code = handle_session_start(
        stdin_bytes=json.dumps({"session_id": codex_session_id, "source": "resume"}).encode(),
        stdout=stdout,
        _state=tmp_path,
        connect=connect,  # pyright: ignore[reportArgumentType]
        workspace=workspace,
    )
    assert code == 0
    context = json.loads(stdout.getvalue().decode("utf-8"))["hookSpecificOutput"][
        "additionalContext"
    ]
    assert type(context) is str
    return context


@pytest.mark.parametrize(
    "code", [PublicErrorCode.SESSION_CONFLICT, PublicErrorCode.SESSION_NOT_FOUND]
)
def test_session_start_stale_mapping_is_not_reported_unavailable(
    tmp_path: Path, code: PublicErrorCode
) -> None:
    """SESSION_* means the mapping is stale, not that the service is down (#308)."""

    text = _session_start_context_for_failure(tmp_path, "codex-stale", _failure_result(code))
    mapping = load_mapping("codex-stale", _state=tmp_path)
    assert mapping is not None
    assert text == hooks_module._stale_mapping_context(mapping)  # pyright: ignore[reportPrivateUsage]
    assert mapping.finishup_session_id in text
    assert "mode=attach" in text
    assert "unavailable" not in text
    assert "start" in text
    # The mapping is kept: repair flows through the agent's own re-start via
    # handle_post_tool_use, never through hook-side guessing.
    assert load_mapping("codex-stale", _state=tmp_path) is not None
    diagnostics = (tmp_path / "observation" / "hook-diagnostics.jsonl").read_text()
    assert diagnostics.count('"reason":"mapping_stale"') == 1


def test_session_start_vault_locked_failure_is_locked(tmp_path: Path) -> None:
    text = _session_start_context_for_failure(
        tmp_path, "codex-locked", _failure_result(PublicErrorCode.VAULT_LOCKED, retryable=True)
    )
    assert text == hooks_module._LOCKED_CONTEXT  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "code",
    [
        PublicErrorCode.BUNDLE_BUSY,
        PublicErrorCode.OPERATION_PENDING,
        PublicErrorCode.FRONTIER_CONFLICT,
    ],
)
def test_session_start_transient_failure_is_retry(tmp_path: Path, code: PublicErrorCode) -> None:
    text = _session_start_context_for_failure(
        tmp_path, "codex-busy", _failure_result(code, retryable=True)
    )
    assert text == hooks_module._RETRY_CONTEXT  # pyright: ignore[reportPrivateUsage]
    assert "unavailable" not in text


def test_session_start_degraded_service_stays_unavailable(tmp_path: Path) -> None:
    text = _session_start_context_for_failure(
        tmp_path,
        "codex-degraded",
        _failure_result(PublicErrorCode.SERVICE_UNAVAILABLE, retryable=True),
    )
    assert text == hooks_module._UNAVAILABLE_CONTEXT  # pyright: ignore[reportPrivateUsage]


def test_session_start_privacy_failure_names_the_ceremony(tmp_path: Path) -> None:
    text = _session_start_context_for_failure(
        tmp_path,
        "codex-privacy",
        _failure_result(PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED),
    )
    assert text == hooks_module._PRIVACY_CONTEXT  # pyright: ignore[reportPrivateUsage]


def test_session_start_control_timeout_is_retry(tmp_path: Path) -> None:
    text = _session_start_context_for_failure(
        tmp_path, "codex-timeout", ControlError("request_timeout", retryable=True)
    )
    assert text == hooks_module._RETRY_CONTEXT  # pyright: ignore[reportPrivateUsage]


def test_status_error_class_table_is_exhaustive() -> None:
    """A new PublicErrorCode member must be classified, never silently collapsed."""

    table = hooks_module._STATUS_ERROR_CLASSES  # pyright: ignore[reportPrivateUsage]
    assert set(table) == set(PublicErrorCode)
    assert set(table.values()) <= {
        "stale",
        "locked",
        "retry",
        "privacy",
        "storage_unsafe",
        "storage_corrupt",
        "unavailable",
    }
    # The two storage codes prescribe opposite next steps and must never share
    # the generic class again (#338).
    assert table[PublicErrorCode.STORAGE_UNSAFE] == "storage_unsafe"
    assert table[PublicErrorCode.STORAGE_CORRUPT] == "storage_corrupt"


def test_session_start_storage_codes_carry_distinct_retryability(tmp_path: Path) -> None:
    """STORAGE_UNSAFE says retry once; STORAGE_CORRUPT says stop and escalate (#338)."""

    unsafe = _session_start_context_for_failure(
        tmp_path,
        "codex-storage-unsafe",
        _failure_result(PublicErrorCode.STORAGE_UNSAFE, retryable=True),
    )
    corrupt = _session_start_context_for_failure(
        tmp_path,
        "codex-storage-corrupt",
        _failure_result(PublicErrorCode.STORAGE_CORRUPT),
    )
    assert unsafe == hooks_module._STORAGE_UNSAFE_CONTEXT  # pyright: ignore[reportPrivateUsage]
    assert corrupt == hooks_module._STORAGE_CORRUPT_CONTEXT  # pyright: ignore[reportPrivateUsage]
    assert unsafe != corrupt
    assert "storage_unsafe" in unsafe and "Retry" in unsafe
    assert "storage_corrupt" in corrupt and "Do not retry" in corrupt
    for text in (unsafe, corrupt):
        assert text != hooks_module._UNAVAILABLE_CONTEXT  # pyright: ignore[reportPrivateUsage]
        assert "unavailable" not in text
        assert len(text) <= 2_000
    rows = [
        json.loads(line)
        for line in (tmp_path / "observation/hook-diagnostics.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    storage_rows = [row for row in rows if row["reason"].startswith("storage_")]
    assert [row["reason"] for row in storage_rows] == ["storage_unsafe", "storage_corrupt"]
    assert {row["event"] for row in storage_rows} == {"SessionStart"}


def test_control_error_class_table_is_exhaustive() -> None:
    from finishup.ports.control import (
        CONTROL_ERROR_REASONS,
    )

    table = hooks_module._CONTROL_ERROR_CLASSES  # pyright: ignore[reportPrivateUsage]
    assert set(table) == CONTROL_ERROR_REASONS
    assert set(table.values()) <= {"locked", "retry", "privacy", "unavailable"}


def test_session_start_clear_removes_mapping(tmp_path: Path) -> None:
    task_id, session_id, writer_id = _task_ids()
    store_mapping(
        mapping_from_start_ids(
            codex_session_id="codex-clear",
            finishup_task_id=task_id,
            finishup_session_id=session_id,
            finishup_writer_id=writer_id,
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    code = handle_session_start(
        stdin_bytes=json.dumps({"session_id": "codex-clear", "source": "clear"}).encode(),
        stdout=io.BytesIO(),
        _state=tmp_path,
    )
    assert code == 0
    assert load_mapping("codex-clear", _state=tmp_path) is None


def test_session_start_defers_service_while_pending_mapping_lock_is_busy(tmp_path: Path) -> None:
    """Legacy SessionStart keeps the local fence when recovery cannot claim its lock."""

    from finishup.adapters.integrations.observation_local import LocalObservationStore

    session = "codex-busy-session-start"
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, session)
    mapping = mapping_from_start_ids(
        codex_session_id=session,
        finishup_task_id=new_id(IdKind.TASK),
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier=None,
    )
    connects: list[str] = []

    async def connect(_kind: ControlClientKind) -> hooks_module._StatusClient:  # pyright: ignore[reportPrivateUsage]
        connects.append("connect")
        raise AssertionError("a fenced SessionStart must not call the service")

    with hooks_module.acquire_session_lock(session, _state=tmp_path) as owned:
        assert owned is True
        queue_mapping_store(mapping, _state=tmp_path)
        assert (
            handle_session_start(
                stdin_bytes=json.dumps(
                    {"session_id": session, "source": "resume", "hook_event_name": "SessionStart"}
                ).encode(),
                stdout=io.BytesIO(),
                _state=tmp_path,
                workspace=str(tmp_path),
                connect=connect,
            )
            == 0
        )
        assert connects == []
        assert load_mapping(session, _state=tmp_path) is None
        pending = mapping_path(session, _state=tmp_path).with_name(f".{session}.pending.json")
        assert pending.exists()


def test_session_start_startup_is_noop(tmp_path: Path) -> None:
    stdout = io.BytesIO()
    code = handle_session_start(
        stdin_bytes=json.dumps({"session_id": "codex-boot", "source": "startup"}).encode(),
        stdout=stdout,
        _state=tmp_path,
    )
    assert code == 0
    assert (
        stdout.getvalue().strip() in {b"{}", b""}
        or json.loads(stdout.getvalue().decode("utf-8")) == {}
    )


def test_session_start_resume_with_missing_mapping_runs_recovery_under_owned_lock(
    tmp_path: Path,
) -> None:
    """A resume handler's owned session lock must not suppress auto-attach."""

    from types import SimpleNamespace

    from finishup.adapters.integrations.observation_local import LocalObservationStore

    task_id, prior_session_id, prior_writer_id = _task_ids()
    successor_session_id = new_id(IdKind.SESSION)
    successor_writer_id = new_id(IdKind.WRITER)
    locator = str(tmp_path.resolve())
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    prior = "codex-resume-prior"
    prior_commitment = store.bind_codex_session(workspace, prior)
    store.note_session_end(workspace, prior_commitment)
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=prior,
            finishup_task_id=task_id,
            finishup_session_id=prior_session_id,
            finishup_writer_id=prior_writer_id,
            last_frontier=None,
        ),
        _state=tmp_path,
    )

    class _RecoveryClient:
        def __init__(self) -> None:
            self.requests: list[object] = []

        async def status(self, request: StatusRequest, *, deadline_ms: int | None = None) -> object:
            del request, deadline_ms
            return _failure_result(PublicErrorCode.SESSION_NOT_FOUND).root

        async def start(self, request: object, *, deadline_ms: int | None = None) -> object:
            del deadline_ms
            self.requests.append(request)
            if getattr(request, "mode", None) == "attach":
                assert getattr(request, "session_id", None) == prior_session_id
                return SimpleNamespace(
                    ok=True,
                    frontier=SimpleNamespace(sequence="3", head_digest="sha256:" + "a" * 64),
                    task_id=task_id,
                    session_id=successor_session_id,
                    writer_id=successor_writer_id,
                )
            if len(self.requests) == 1:
                return _failure_result(
                    PublicErrorCode.SESSION_CONFLICT,
                    safe_details={"reason_code": "workspace_task_exists"},
                ).root
            raise AssertionError("unexpected recovery start request")

        async def close(self) -> None:
            return None

    client = _RecoveryClient()

    async def connect(_kind: ControlClientKind) -> _RecoveryClient:
        return client

    stdout = io.BytesIO()
    code = handle_session_start(
        stdin_bytes=json.dumps({"session_id": "codex-resume-next", "source": "resume"}).encode(),
        stdout=stdout,
        _state=tmp_path,
        connect=connect,
        workspace=locator,
    )

    assert code == 0
    mapping = load_mapping("codex-resume-next", _state=tmp_path)
    assert mapping is not None
    assert mapping.finishup_task_id == task_id
    assert mapping.finishup_session_id == successor_session_id
    assert mapping.finishup_writer_id == successor_writer_id
    assert [getattr(request, "mode", None) for request in client.requests] == ["attach"]
    assert task_id in stdout.getvalue().decode()


# Claude Code 2.1.251 passes an MCP tool's structured result to PostToolUse as one bare JSON
# string (captured live on 2026-09-04 with a probe MCP server that returned both a text block
# and structuredContent; issue #581). The Codex path shares the binder, so the same shape is
# admitted for both hosts.
CLAUDE_2_1_251_START_TOOL_RESPONSE = (
    '{"protocol_version":"0.1","schema_version":"1.0.0","ok":true,"outcome":"created",'
    '"task_id":"tsk_00000000-0000-4000-8000-000000000001",'
    '"session_id":"ses_00000000-0000-4000-8000-000000000002",'
    '"writer_id":"wri_00000000-0000-4000-8000-000000000003",'
    '"frontier":{"sequence":"1","head_digest":"sha256:' + "a" * 64 + '"}}'
)


def _diagnostics_text(state: Path) -> str:
    path = state / "observation" / "hook-diagnostics.jsonl"
    return path.read_text() if path.exists() else ""


def test_post_tool_use_bare_json_string_start_result_binds(tmp_path: Path) -> None:
    """The live 2.1.251 `tool_response` shape binds the session (#581)."""

    payload = {
        "session_id": "codex-string-1",
        "tool_name": "mcp__plugin_finishup_finishup__start",
        "tool_response": CLAUDE_2_1_251_START_TOOL_RESPONSE,
    }
    code = handle_post_tool_use(
        stdin_bytes=json.dumps(payload).encode("utf-8"), stdout=io.BytesIO(), _state=tmp_path
    )
    assert code == 0
    mapping = load_mapping("codex-string-1", _state=tmp_path)
    assert mapping is not None
    assert mapping.finishup_task_id == "tsk_00000000-0000-4000-8000-000000000001"
    assert mapping.finishup_session_id == "ses_00000000-0000-4000-8000-000000000002"
    assert mapping.finishup_writer_id == "wri_00000000-0000-4000-8000-000000000003"
    assert mapping.last_frontier == "1:sha256:" + "a" * 64
    assert "start_bind" not in _diagnostics_text(tmp_path)


@pytest.mark.parametrize(
    ("tool_response", "reason"),
    [
        ("RESPONSE_CANARY", "start_bind_unparsed"),
        ({}, "start_bind_unparsed"),
        ({"structuredContent": {"ok": "true"}}, "start_bind_unparsed"),
        ('{"ok":null}', "start_bind_unparsed"),
        ({"content": "private output"}, "start_bind_unparsed"),
        ([{"type": "text", "text": "not json"}], "start_bind_unparsed"),
        (
            {"structuredContent": {"ok": True, "task_id": "tsk_not_an_id"}},
            "start_bind_invalid_ids",
        ),
        (
            {
                "structuredContent": {
                    "ok": True,
                    "task_id": "tsk_00000000-0000-4000-8000-000000000001",
                    "session_id": "ses_00000000-0000-4000-8000-000000000002",
                    "writer_id": "not-a-writer",
                }
            },
            "start_bind_invalid_ids",
        ),
    ],
)
def test_post_tool_use_unbound_start_result_records_typed_diagnostic(
    tmp_path: Path, tool_response: object, reason: str
) -> None:
    """A scoped start post-hook that binds nothing is no longer silent (#581)."""

    payload = {
        "session_id": "codex-unbound-1",
        "tool_name": "mcp__plugin_finishup_finishup__start",
        "tool_response": tool_response,
    }
    code = handle_post_tool_use(
        stdin_bytes=json.dumps(payload).encode("utf-8"), stdout=io.BytesIO(), _state=tmp_path
    )
    assert code == 0
    assert load_mapping("codex-unbound-1", _state=tmp_path) is None
    diagnostics = _diagnostics_text(tmp_path)
    assert diagnostics.count(f'"reason":"{reason}"') == 1
    assert '"event":"PostToolUse"' in diagnostics
    # Payload-free: the host response never lands in the diagnostics file.
    assert "RESPONSE_CANARY" not in diagnostics
    assert "private output" not in diagnostics


def test_post_tool_use_refused_start_records_no_bind_diagnostic(tmp_path: Path) -> None:
    """A start the service refused is nothing to bind, not a parsing failure."""

    for response in (
        {"structuredContent": {"ok": False}},
        '{"ok":false,"error":{"code":"SESSION_CONFLICT"}}',
    ):
        code = handle_post_tool_use(
            stdin_bytes=json.dumps(
                {
                    "session_id": "codex-refused-1",
                    "tool_name": "mcp__plugin_finishup_finishup__start",
                    "tool_response": response,
                }
            ).encode("utf-8"),
            stdout=io.BytesIO(),
            _state=tmp_path,
        )
        assert code == 0
    assert load_mapping("codex-refused-1", _state=tmp_path) is None
    assert "start_bind" not in _diagnostics_text(tmp_path)


def test_session_start_status_read_binds_the_workspace_locator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The resume probe carries the same repository locator `start` does (#578)."""

    from finishup.ports.control import WorkspaceLocator

    task_id, session_id, writer_id = _task_ids()
    store_mapping(
        mapping_from_start_ids(
            codex_session_id="codex-bound-1",
            finishup_task_id=task_id,
            finishup_session_id=session_id,
            finishup_writer_id=writer_id,
            last_frontier="0:genesis",
        ),
        _state=tmp_path,
    )
    client = _FakeClient()
    client.task_id, client.session_id, client.writer_id = task_id, session_id, writer_id
    captured: list[WorkspaceLocator | None] = []

    async def connect(
        _kind: ControlClientKind, *, workspace_locator: WorkspaceLocator | None = None
    ) -> _FakeClient:
        captured.append(workspace_locator)
        return client

    monkeypatch.setattr(hooks_module, "connect_service", connect)
    locator = str(tmp_path.resolve())

    stdout = io.BytesIO()
    code = handle_session_start(
        stdin_bytes=json.dumps({"session_id": "codex-bound-1", "source": "resume"}).encode(),
        stdout=stdout,
        _state=tmp_path,
        workspace=locator,
    )
    assert code == 0
    text = json.loads(stdout.getvalue().decode("utf-8"))["hookSpecificOutput"]["additionalContext"]
    assert session_id in text
    assert captured == [WorkspaceLocator(locator)]

    # Without an explicit --workspace the hook's own cwd is the locator, as for
    # every other repository-bound CLI call.
    monkeypatch.chdir(tmp_path)
    code = handle_session_start(
        stdin_bytes=json.dumps({"session_id": "codex-bound-1", "source": "compact"}).encode(),
        stdout=io.BytesIO(),
        _state=tmp_path,
    )
    assert code == 0
    assert captured == [WorkspaceLocator(locator), WorkspaceLocator(locator)]
    assert "mapping_stale" not in _diagnostics_text(tmp_path)


def _git_root(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    (path / ".git").mkdir(exist_ok=True)
    (path / ".git").chmod(0o700)
    return path


def test_resolve_session_workspace_orders_explicit_host_payload_then_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #659: the probe binds the project the host named even when the hook cwd is not it.

    Order is explicit project path, then the host payload's session cwd, then the hook cwd. The
    rendered bare `.` is the hook cwd, so a host cwd outranks it; a subdirectory cwd resolves to
    the repository root; an explicit path that cannot be canonicalized never falls through.
    """

    from finishup.cli.hooks import resolve_session_workspace

    project = _git_root(tmp_path / "project")
    elsewhere = _git_root(tmp_path / "elsewhere")
    monkeypatch.chdir(elsewhere)

    # Explicit project path wins over both the payload cwd and the hook cwd.
    chosen = resolve_session_workspace(str(project), {"cwd": str(elsewhere)})
    assert (chosen.locator, chosen.source) == (str(project), "explicit")

    # The bare `.` is the hook cwd; the host payload's cwd outranks it.
    chosen = resolve_session_workspace(".", {"cwd": str(project)})
    assert (chosen.locator, chosen.source) == (str(project), "host_payload")
    # A subdirectory cwd from the host resolves to the same repository root.
    subdirectory = project / "src" / "pkg"
    subdirectory.mkdir(parents=True)
    chosen = resolve_session_workspace(".", {"cwd": str(subdirectory)})
    assert (chosen.locator, chosen.source) == (str(project), "host_payload")

    # No host cwd: the hook cwd is the ordinary repository-bound default.
    chosen = resolve_session_workspace(".", {})
    assert (chosen.locator, chosen.source) == (str(elsewhere), "cwd")
    chosen = resolve_session_workspace(None, None)
    assert (chosen.locator, chosen.source) == (str(elsewhere), "cwd")

    # An unresolvable host cwd falls back to the hook cwd, and a non-string one is ignored.
    chosen = resolve_session_workspace(".", {"cwd": str(tmp_path / "missing")})
    assert (chosen.locator, chosen.source) == (str(elsewhere), "cwd")
    chosen = resolve_session_workspace(".", {"cwd": 7})
    assert (chosen.locator, chosen.source) == (str(elsewhere), "cwd")

    # An explicit project path that fails canonicalization is terminal: no fallback to the
    # payload cwd or the hook cwd may bind a different repository.
    chosen = resolve_session_workspace(str(tmp_path / "missing"), {"cwd": str(project)})
    assert (chosen.locator, chosen.source) == (None, "unresolvable")
    assert chosen.diagnostic_reason == "locator_unresolvable"

    # Nothing at all: the hook cwd is refused (home/root) and the selection stays absent.
    monkeypatch.setenv("HOME", str(elsewhere))
    chosen = resolve_session_workspace(None, None)
    assert (chosen.locator, chosen.source) == (None, "absent")
    assert chosen.diagnostic_reason == "locator_absent"


def test_session_start_probe_binds_the_host_payload_cwd_over_the_hook_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #659: a compaction hook launched outside the project still validates the mapping
    from the host's own session cwd, keeping the same task/session/writer."""

    from finishup.ports.control import WorkspaceLocator

    project = _git_root(tmp_path / "project")
    elsewhere = _git_root(tmp_path / "elsewhere")
    monkeypatch.chdir(elsewhere)
    task_id, session_id, writer_id = _task_ids()
    store_mapping(
        mapping_from_start_ids(
            codex_session_id="codex-compact-cwd",
            finishup_task_id=task_id,
            finishup_session_id=session_id,
            finishup_writer_id=writer_id,
            last_frontier="0:genesis",
        ),
        _state=tmp_path / "state",
    )
    client = _FakeClient()
    client.task_id, client.session_id, client.writer_id = task_id, session_id, writer_id
    captured: list[WorkspaceLocator | None] = []

    async def connect(
        _kind: ControlClientKind, *, workspace_locator: WorkspaceLocator | None = None
    ) -> _FakeClient:
        captured.append(workspace_locator)
        return client

    monkeypatch.setattr(hooks_module, "connect_service", connect)
    stdout = io.BytesIO()
    code = handle_session_start(
        stdin_bytes=json.dumps(
            {"session_id": "codex-compact-cwd", "source": "compact", "cwd": str(project)}
        ).encode(),
        stdout=stdout,
        _state=tmp_path / "state",
        workspace=".",
    )
    assert code == 0
    assert captured[0] == WorkspaceLocator(str(project))
    text = json.loads(stdout.getvalue().decode("utf-8"))["hookSpecificOutput"]["additionalContext"]
    assert session_id in text and writer_id in text
    refreshed = load_mapping("codex-compact-cwd", _state=tmp_path / "state")
    assert refreshed is not None
    assert (refreshed.finishup_session_id, refreshed.finishup_writer_id) == (session_id, writer_id)
    assert "status_workspace" not in _diagnostics_text(tmp_path / "state")


@pytest.mark.parametrize(
    ("reason_code", "kind"),
    [
        ("repository_identity_required", "workspace_unbound"),
        ("repository_identity_mismatch", "workspace_mismatch"),
    ],
)
def test_session_start_repository_fence_conflict_is_not_reported_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason_code: str, kind: str
) -> None:
    """A fence refusal is a live mapping the daemon could not bind, never `mapping_stale` (#578)."""

    monkeypatch.chdir(_git_root(tmp_path / "project"))
    text = _session_start_context_for_failure(
        tmp_path,
        f"codex-fence-{kind}",
        _failure_result(
            PublicErrorCode.SESSION_CONFLICT, safe_details={"reason_code": reason_code}
        ),
    )
    expected = (
        hooks_module._WORKSPACE_UNBOUND_CONTEXT  # pyright: ignore[reportPrivateUsage]
        if kind == "workspace_unbound"
        else hooks_module._WORKSPACE_MISMATCH_CONTEXT  # pyright: ignore[reportPrivateUsage]
    )
    assert text == expected
    assert "is stale" not in text
    assert "mode=attach" not in text
    assert f"status_{kind}" in text
    assert load_mapping(f"codex-fence-{kind}", _state=tmp_path) is not None
    diagnostics = _diagnostics_text(tmp_path)
    assert diagnostics.count(f'"reason":"status_{kind}"') == 1
    # The companion row names the probe's locator source (#659): the helper passes no
    # workspace and no host cwd, so the hook cwd was the source.
    assert diagnostics.count('"reason":"locator_source_cwd"') == 1
    assert "mapping_stale" not in diagnostics


def test_session_start_fence_refusal_names_an_absent_or_unresolvable_locator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #659: an absent context and a supplied context that failed to resolve are
    distinguishable in the diagnostics, and neither rotates the mapping or advises re-attach."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    text = _session_start_context_for_failure(
        tmp_path,
        "codex-fence-absent",
        _failure_result(
            PublicErrorCode.SESSION_CONFLICT,
            safe_details={"reason_code": "repository_identity_required"},
        ),
    )
    assert text == hooks_module._WORKSPACE_UNBOUND_CONTEXT  # pyright: ignore[reportPrivateUsage]
    assert load_mapping("codex-fence-absent", _state=tmp_path) is not None
    diagnostics = _diagnostics_text(tmp_path)
    assert diagnostics.count('"reason":"locator_absent"') == 1

    text = _session_start_context_for_failure(
        tmp_path,
        "codex-fence-unresolvable",
        _failure_result(
            PublicErrorCode.SESSION_CONFLICT,
            safe_details={"reason_code": "repository_identity_required"},
        ),
        workspace=str(tmp_path / "missing"),
    )
    assert text == hooks_module._WORKSPACE_UNBOUND_CONTEXT  # pyright: ignore[reportPrivateUsage]
    assert load_mapping("codex-fence-unresolvable", _state=tmp_path) is not None
    diagnostics = _diagnostics_text(tmp_path)
    assert diagnostics.count('"reason":"locator_unresolvable"') == 1
    assert "mapping_stale" not in diagnostics


def test_session_start_superseded_session_names_the_replacement_binding(tmp_path: Path) -> None:
    """A genuinely replaced session still yields the stale advisory, now with the new ids (#578)."""

    new_task, new_session, new_writer = _task_ids()
    text = _session_start_context_for_failure(
        tmp_path,
        "codex-superseded",
        _failure_result(
            PublicErrorCode.SESSION_NOT_FOUND,
            safe_details={
                "reason_code": "session_superseded",
                "task_id": new_task,
                "session_id": new_session,
                "writer_id": new_writer,
            },
        ),
    )
    mapping = load_mapping("codex-superseded", _state=tmp_path)
    assert mapping is not None
    assert text.startswith("FinishUP task mapping for this session is stale")
    assert new_task in text
    assert f"session_id {new_session} and writer_id {new_writer}" in text
    assert f"mode=attach and session_id {mapping.finishup_session_id}" in text
    assert "different external_ref" in text
    diagnostics = _diagnostics_text(tmp_path)
    assert diagnostics.count('"reason":"mapping_stale"') == 1


def test_session_start_superseded_with_invalid_replacement_ids_falls_back(tmp_path: Path) -> None:
    text = _session_start_context_for_failure(
        tmp_path,
        "codex-superseded-bad",
        _failure_result(
            PublicErrorCode.SESSION_NOT_FOUND,
            safe_details={
                "reason_code": "session_superseded",
                "task_id": "tsk_not_an_id",
                "session_id": "ses_not_an_id",
                "writer_id": "wri_not_an_id",
            },
        ),
    )
    mapping = load_mapping("codex-superseded-bad", _state=tmp_path)
    assert mapping is not None
    assert text == hooks_module._stale_mapping_context(mapping)  # pyright: ignore[reportPrivateUsage]
    assert "tsk_not_an_id" not in text


def test_mapped_resume_reads_grant_once_and_keeps_context(
    tmp_path: Path,
) -> None:
    """The discarded observation pass cannot spend a second admission grant read."""

    task_id, session_id, writer_id = _task_ids()
    store_mapping(
        mapping_from_start_ids(
            codex_session_id="codex-admission",
            finishup_task_id=task_id,
            finishup_session_id=session_id,
            finishup_writer_id=writer_id,
            last_frontier="0:genesis",
        ),
        _state=tmp_path,
    )

    class _Client(_FakeClient):
        async def privacy_get_setup(
            self, request: object, *, deadline_ms: int | None = None
        ) -> object:
            self.calls.append("privacy_get_setup")
            return {
                "grant_state": "granted",
                "composed_policy": {
                    "channel_policies": [{"channel": "llm_inference", "enabled": True}]
                },
            }

    client = _Client()
    client.task_id = task_id
    client.session_id = session_id
    client.writer_id = writer_id

    async def connect(_kind: ControlClientKind) -> _Client:
        return client

    def session_start() -> str:
        stdout = io.BytesIO()
        assert (
            handle_session_start(
                stdin_bytes=json.dumps(
                    {"session_id": "codex-admission", "source": "resume"}
                ).encode(),
                stdout=stdout,
                _state=tmp_path,
                connect=connect,
                workspace=str(tmp_path),
            )
            == 0
        )
        return json.loads(stdout.getvalue().decode("utf-8"))["hookSpecificOutput"][
            "additionalContext"
        ]

    spoken = session_start()
    assert task_id in spoken
    assert "finishup integrate codex admission grant" in spoken
    assert "Route and host approval remain unconfirmed" in spoken
    assert client.calls == ["status", "privacy_get_setup"]
