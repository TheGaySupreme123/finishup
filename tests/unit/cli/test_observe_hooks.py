"""Unit tests for unified hook observation ingress and consent plumbing."""

from __future__ import annotations

import asyncio
import io
import json
import os
import threading
import time
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, cast

import pytest

from finishup.adapters.integrations.codex_lifecycle import (
    LifecycleMapping,
    acquire_session_lock,
    acquire_workspace_recovery_lock,
    is_scoped_child_session_id,
    mapping_from_start_ids,
    scoped_child_session_id,
    store_mapping,
)
from finishup.adapters.integrations.hook_spool import HookSpool
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.recommendations import RecommendationState, store_recommendation_state
from finishup.cli import observe_hooks as observe_hooks_module
from finishup.cli.hook_io import MAX_HOOK_SKIM_BYTES, MAX_HOOK_STDIN_BYTES
from finishup.cli.observe_hooks import (
    SUPPORTED_HOOK_EVENTS,
    handle_claude_observe,
    handle_cursor_observe,
    handle_observe,
    handle_spool,
    map_hook_payload_to_envelope,
)
from finishup.domain.observation import (
    ObservationContentChunk,
    ObservationContentKind,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestResult,
    ObservationSource,
    ObservationStatusQuery,
    observation_ingest_result_to_json,
)
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import ProtocolValueError, PublicErrorCode, PublicOperationError
from finishup.protocol.models import StartRequest

_KEY = b"k" * 32


def test_map_supported_hook_payloads_structural_only(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    session = store.session_commitment("sess-1")
    for event in sorted(SUPPORTED_HOOK_EVENTS):
        payload = {
            "session_id": "sess-1",
            "hook_event_name": event,
            "tool_name": "shell",
            "correlation_id": "corr-1",
            "exit_status": 0,
            "transcript": "MUST_NOT_APPEAR",
            "prompt": "MUST_NOT_APPEAR",
        }
        envelope = map_hook_payload_to_envelope(
            event,
            payload,
            session_commitment=session,
            event_ordinal=1,
            key_material=store.key_material(),
        )
        assert envelope.source is ObservationSource.CODEX_HOOK
        assert envelope.event_kind == event
        assert "transcript" not in envelope.structural_payload
        assert "prompt" not in envelope.structural_payload
        assert envelope.structural_payload.get("tool_name") == "shell"
        assert envelope.cursor.last_source_commitment.startswith("hmac-sha256:")


def test_map_native_child_aliases_to_one_structural_identity(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    session = store.session_commitment("claude-child-parent")
    envelope = map_hook_payload_to_envelope(
        "SubagentStart",
        {
            "session_id": "claude-child-parent",
            "agent_id": "agent-claude-1",
            "agent_thread_id": "agent-claude-1",
            "parent_tool_call_id": "tool-parent-1",
            "tool_call_id": "tool-parent-1",
            "prompt": "must not cross the boundary",
            "transcript_path": "/private/transcript.jsonl",
        },
        session_commitment=session,
        event_ordinal=1,
        key_material=store.key_material(),
    )

    assert envelope.structural_payload == {
        "event_ordinal": 1,
        "hook_name": "SubagentStart",
        "parent_tool_call_id": "tool-parent-1",
        "subagent_id": "agent-claude-1",
    }
    assert "prompt" not in envelope.structural_payload
    assert "transcript_path" not in envelope.structural_payload


def test_map_actual_claude_child_hook_shape_without_parent_tool(tmp_path: Path) -> None:
    """Claude's native child hooks carry child identity but no parent tool identifier."""

    store = LocalObservationStore(_state=tmp_path)
    for event_name, extra in (
        ("SubagentStart", {"transcript_path": "/private/transcript.jsonl"}),
        (
            "SubagentStop",
            {
                "agent_transcript_path": "/private/agent-transcript.jsonl",
                "permission_mode": "dontAsk",
            },
        ),
    ):
        envelope = map_hook_payload_to_envelope(
            event_name,
            {
                "hook_event_name": event_name,
                "session_id": "claude-parent-session",
                "agent_id": "claude-agent-1",
                "agent_type": "general-purpose",
                "cwd": "/private/project",
                **extra,
            },
            session_commitment=store.session_commitment("claude-parent-session"),
            event_ordinal=1,
            key_material=store.key_material(),
        )

        assert envelope.structural_payload == {
            "event_ordinal": 1,
            "hook_name": event_name,
            "subagent_id": "claude-agent-1",
        }


def test_map_conflicting_native_child_aliases_leave_an_attribution_gap(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    envelope = map_hook_payload_to_envelope(
        "SubagentStop",
        {
            "session_id": "claude-child-parent",
            "subagent_id": "child-a",
            "agent_id": "child-b",
            "parent_tool_call_id": "tool-parent-a",
            "tool_call_id": "tool-parent-b",
        },
        session_commitment=store.session_commitment("claude-child-parent"),
        event_ordinal=1,
        key_material=store.key_material(),
    )

    assert "subagent_id" not in envelope.structural_payload
    assert "parent_tool_call_id" not in envelope.structural_payload


def test_observation_lane_requires_a_validated_child_mapping(tmp_path: Path) -> None:
    parent_task, parent_session, parent_writer = (
        "tsk_11111111-1111-4111-8111-111111111111",
        "ses_22222222-2222-4222-8222-222222222222",
        "wri_33333333-3333-4333-8333-333333333333",
    )
    child_task, child_session, child_writer = (
        "tsk_44444444-4444-4444-8444-444444444444",
        "ses_55555555-5555-4555-8555-555555555555",
        "wri_66666666-6666-4666-8666-666666666666",
    )
    host_session = "codex-lane-parent"
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=host_session,
            yoetz_task_id=parent_task,
            yoetz_session_id=parent_session,
            yoetz_writer_id=parent_writer,
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    task_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity=child_task,
        identity_kind="task",
    )
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=task_lane,
            yoetz_task_id=child_task,
            yoetz_session_id=child_session,
            yoetz_writer_id=child_writer,
            last_frontier=None,
        ),
        _state=tmp_path,
    )

    lane = observe_hooks_module._resolve_observation_lane(  # pyright: ignore[reportPrivateUsage]
        {
            "session_id": host_session,
            "tool_name": "mcp__finishup__publish_work",
            "tool_response": {
                "structuredContent": {
                    "ok": True,
                    "task_id": child_task,
                    "parent_task_id": parent_task,
                }
            },
        },
        event_name="PostToolUse",
        source=ObservationSource.CODEX_HOOK,
        _state=tmp_path,
    )
    assert lane.host_session_id == host_session
    assert lane.effective_session_id == task_lane
    assert lane.is_child is True
    assert lane.attribution_gap is False
    assert is_scoped_child_session_id(task_lane)


def test_observation_lane_keeps_parent_but_marks_known_child_gap(tmp_path: Path) -> None:
    parent_task, parent_session, parent_writer = (
        "tsk_77777777-7777-4777-8777-777777777777",
        "ses_88888888-8888-4888-8888-888888888888",
        "wri_99999999-9999-4999-8999-999999999999",
    )
    child_task = "tsk_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    host_session = "codex-lane-gap"
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=host_session,
            yoetz_task_id=parent_task,
            yoetz_session_id=parent_session,
            yoetz_writer_id=parent_writer,
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    lane = observe_hooks_module._resolve_observation_lane(  # pyright: ignore[reportPrivateUsage]
        {
            "session_id": host_session,
            "tool_name": "mcp__finishup__publish_work",
            "tool_response": {
                "structuredContent": {
                    "ok": True,
                    "task_id": child_task,
                    "parent_task_id": parent_task,
                }
            },
        },
        event_name="PostToolUse",
        source=ObservationSource.CODEX_HOOK,
        _state=tmp_path,
    )
    assert lane.effective_session_id == host_session
    assert lane.is_child is False
    assert lane.attribution_gap is True


def test_observation_lane_does_not_use_stale_host_alias_for_foreign_result(
    tmp_path: Path,
) -> None:
    """A host alias owned by one child cannot route a result for another child."""

    parent_task, parent_session, parent_writer = (
        "tsk_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "ses_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "wri_cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    )
    old_child_task, old_child_session, old_child_writer = (
        "tsk_dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        "ses_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        "wri_ffffffff-ffff-4fff-8fff-ffffffffffff",
    )
    foreign_child_task = "tsk_11111111-2222-4333-8444-555555555555"
    host_session = "codex-stale-host-alias"
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=host_session,
            yoetz_task_id=parent_task,
            yoetz_session_id=parent_session,
            yoetz_writer_id=parent_writer,
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    host_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity="native-child-a",
        identity_kind="host",
    )
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=host_lane,
            yoetz_task_id=old_child_task,
            yoetz_session_id=old_child_session,
            yoetz_writer_id=old_child_writer,
            last_frontier=None,
        ),
        _state=tmp_path,
    )

    lane = observe_hooks_module._resolve_observation_lane(  # pyright: ignore[reportPrivateUsage]
        {
            "session_id": host_session,
            "agent_id": "native-child-a",
            "tool_name": "mcp__finishup__publish_work",
            "tool_response": {
                "structuredContent": {
                    "ok": True,
                    "task_id": foreign_child_task,
                    "parent_task_id": parent_task,
                }
            },
        },
        event_name="PostToolUse",
        source=ObservationSource.CODEX_HOOK,
        _state=tmp_path,
    )
    assert lane.effective_session_id == host_session
    assert lane.is_child is False
    assert lane.attribution_gap is True


def test_observation_lane_routes_matching_result_through_task_alias_when_host_alias_is_stale(
    tmp_path: Path,
) -> None:
    """A validated task alias can recover a callback when its host alias is stale."""

    parent_task, parent_session, parent_writer = (
        "tsk_12121212-1212-4121-8121-121212121212",
        "ses_34343434-3434-4434-8434-343434343434",
        "wri_56565656-5656-4565-8565-565656565656",
    )
    old_child_task, old_child_session, old_child_writer = (
        "tsk_78787878-7878-4787-8787-787878787878",
        "ses_90909090-9090-4909-8909-909090909090",
        "wri_abababab-abab-4aba-8aba-abababababab",
    )
    current_child_task, current_child_session, current_child_writer = (
        "tsk_cdcdcdcd-cdcd-4cdc-8cdc-cdcdcdcdcdcd",
        "ses_efefefef-efef-4efe-8efe-efefefefefef",
        "wri_01010101-0101-4010-8010-010101010101",
    )
    host_session = "codex-stale-host-alias-task-route"
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=host_session,
            yoetz_task_id=parent_task,
            yoetz_session_id=parent_session,
            yoetz_writer_id=parent_writer,
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    host_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity="native-child-b",
        identity_kind="host",
    )
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=host_lane,
            yoetz_task_id=old_child_task,
            yoetz_session_id=old_child_session,
            yoetz_writer_id=old_child_writer,
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    task_lane = scoped_child_session_id(
        host_session,
        host="codex",
        identity=current_child_task,
        identity_kind="task",
    )
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=task_lane,
            yoetz_task_id=current_child_task,
            yoetz_session_id=current_child_session,
            yoetz_writer_id=current_child_writer,
            last_frontier=None,
        ),
        _state=tmp_path,
    )

    lane = observe_hooks_module._resolve_observation_lane(  # pyright: ignore[reportPrivateUsage]
        {
            "session_id": host_session,
            "agent_id": "native-child-b",
            "tool_name": "mcp__finishup__publish_work",
            "tool_response": {
                "structuredContent": {
                    "ok": True,
                    "task_id": current_child_task,
                    "parent_task_id": parent_task,
                }
            },
        },
        event_name="PostToolUse",
        source=ObservationSource.CODEX_HOOK,
        _state=tmp_path,
    )
    assert lane.effective_session_id == task_lane
    assert lane.is_child is True
    assert lane.attribution_gap is False


def test_valid_child_identity_without_lane_is_an_attribution_gap(tmp_path: Path) -> None:
    """A child-shaped identity with no owned lane cannot inherit the parent route."""

    parent_task, parent_session, parent_writer = (
        "tsk_23232323-2323-4232-8232-232323232323",
        "ses_45454545-4545-4454-8454-454545454545",
        "wri_67676767-6767-4676-8676-676767676767",
    )
    host_session = "codex-unbound-child-identity"
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=host_session,
            yoetz_task_id=parent_task,
            yoetz_session_id=parent_session,
            yoetz_writer_id=parent_writer,
            last_frontier=None,
        ),
        _state=tmp_path,
    )

    lane = observe_hooks_module._resolve_observation_lane(  # pyright: ignore[reportPrivateUsage]
        {
            "session_id": host_session,
            "agent_id": "native-child-without-lane",
            "tool_name": "shell",
        },
        event_name="PostToolUse",
        source=ObservationSource.CODEX_HOOK,
        _state=tmp_path,
    )
    assert lane.effective_session_id == host_session
    assert lane.is_child is False
    assert lane.attribution_gap is True


def test_reserved_child_lane_without_mapping_is_an_attribution_gap(tmp_path: Path) -> None:
    """An opaque derived lane cannot be promoted to a fresh parent session."""

    reserved_lane = scoped_child_session_id(
        "codex-reserved-parent",
        host="codex",
        identity="native-child-reserved",
        identity_kind="host",
    )
    lane = observe_hooks_module._resolve_observation_lane(  # pyright: ignore[reportPrivateUsage]
        {"session_id": reserved_lane, "tool_name": "shell"},
        event_name="PostToolUse",
        source=ObservationSource.CODEX_HOOK,
        _state=tmp_path,
    )
    assert lane.effective_session_id == reserved_lane
    assert lane.is_child is False
    assert lane.attribution_gap is True


def test_subagent_lifecycle_events_stay_on_parent_lane(tmp_path: Path) -> None:
    lane = observe_hooks_module._resolve_observation_lane(  # pyright: ignore[reportPrivateUsage]
        {"session_id": "codex-lineage-parent", "subagent_id": "child-1"},
        event_name="SubagentStart",
        source=ObservationSource.CODEX_HOOK,
        _state=tmp_path,
    )
    assert lane.effective_session_id == "codex-lineage-parent"
    assert lane.is_child is False


def test_unknown_future_hook_becomes_opaque_gap(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    session = store.session_commitment("sess-2")
    envelope = map_hook_payload_to_envelope(
        "FutureHostEvent",
        {"session_id": "sess-2"},
        session_commitment=session,
        event_ordinal=1,
        key_material=_KEY,
        gap_codes=(ObservationGapCode.UNSUPPORTED_EVENT.value,),
    )
    assert envelope.event_kind == "FutureHostEvent"
    assert ObservationGapCode.UNSUPPORTED_EVENT.value in envelope.gap_codes


def test_visible_unknown_content_is_redacted_and_hidden_fields_are_ignored(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    session = store.session_commitment("sess-visible")
    envelope = map_hook_payload_to_envelope(
        "FutureHostEvent",
        {"session_id": "sess-visible"},
        session_commitment=session,
        event_ordinal=1,
        key_material=_KEY,
    )
    chunks, truncated = observe_hooks_module._visible_content_chunks(  # pyright: ignore[reportPrivateUsage]
        "FutureHostEvent",
        {
            "visibility": "task",
            "visible_content": "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456",
            "reasoning": "HIDDEN_REASONING_CANARY",
            "system": "SYSTEM_PROMPT_CANARY",
        },
        envelope=envelope,
        workspace_locator=None,
    )
    assert truncated is False
    assert len(chunks) == 1
    assert chunks[0].redacted is True
    assert b"sk-abcdefghijklmnopqrstuvwxyz123456" not in chunks[0].content
    assert b"HIDDEN_REASONING_CANARY" not in chunks[0].content
    assert b"SYSTEM_PROMPT_CANARY" not in chunks[0].content


def test_visible_heuristic_only_content_is_kept_and_not_marked_redacted(tmp_path: Path) -> None:
    """Issue #982: capture keeps heuristic-only matches; only egress redacts them."""

    store = LocalObservationStore(_state=tmp_path)
    session = store.session_commitment("sess-heuristic")
    envelope = map_hook_payload_to_envelope(
        "FutureHostEvent",
        {"session_id": "sess-heuristic"},
        session_commitment=session,
        event_ordinal=1,
        key_material=_KEY,
    )
    content = 'self.bot_token = "<|tool_call_start|>"\napi_token = "a8F3kL9qZ2xV7mN4"\n'
    chunks, truncated = observe_hooks_module._visible_content_chunks(  # pyright: ignore[reportPrivateUsage]
        "FutureHostEvent",
        {"visibility": "task", "visible_content": content},
        envelope=envelope,
        workspace_locator=None,
    )
    assert truncated is False
    assert len(chunks) == 1
    assert chunks[0].redacted is False
    assert chunks[0].content == content.encode("utf-8")


def test_content_cap_sets_truncated_flag(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    session = store.session_commitment("sess-trunc")
    envelope = map_hook_payload_to_envelope(
        "AgentMessage",
        {"session_id": "sess-trunc", "message": "x" * 700_000},
        session_commitment=session,
        event_ordinal=1,
        key_material=_KEY,
    )
    chunks, truncated = observe_hooks_module._visible_content_chunks(  # pyright: ignore[reportPrivateUsage]
        "AgentMessage",
        {"message": "x" * 700_000},
        envelope=envelope,
        workspace_locator=None,
    )
    assert truncated is True
    assert chunks


def test_identical_tool_calls_remain_distinct(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    session = store.session_commitment("sess-dup")
    payload = {
        "session_id": "sess-dup",
        "tool_name": "shell",
        "tool_call_id": "same-call",
        "exit_status": 0,
    }
    first = map_hook_payload_to_envelope(
        "PostToolUse",
        payload,
        session_commitment=session,
        event_ordinal=1,
        key_material=_KEY,
    )
    second = map_hook_payload_to_envelope(
        "PostToolUse",
        payload,
        session_commitment=session,
        event_ordinal=2,
        key_material=_KEY,
    )
    assert first.source_identity != second.source_identity


@pytest.mark.parametrize(
    ("tool_name", "tool_input", "expected"),
    [
        ("Read", {"path": "ignored"}, True),
        ("exec_command", {"cmd": "rg -n observation src tests"}, True),
        ("exec_command", {"cmd": "git status --short"}, True),
        ("exec_command", {"cmd": "sed -n '1,20p' README.md"}, False),
        ("exec_command", {"cmd": "sed -i s/a/b/ README.md"}, False),
        ("exec_command", {"cmd": "rg --pre ./prepare term src"}, False),
        ("exec_command", {"cmd": "rg term src | tee report.txt"}, False),
        ("exec_command", {"cmd": "pytest -q"}, False),
        ("exec_command", {"cmd": "./ls"}, False),
        ("exec_command", {"cmd": "/tmp/head README.md"}, False),
        ("exec_command", {"cmd": "git diff --output=result.patch"}, False),
        ("exec_command", {"cmd": "git diff --ext-diff HEAD"}, False),
    ],
)
def test_routine_read_classification_is_conservative_and_structural(
    tool_name: str, tool_input: dict[str, str], expected: bool
) -> None:
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "session_id": "routine-read",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "exit_status": 0,
        },
        session_commitment=f"hmac-sha256:{'11' * 32}",
        event_ordinal=1,
        key_material=_KEY,
    )
    assert (envelope.structural_payload.get("action") == "routine_read") is expected
    assert "cmd" not in envelope.structural_payload


@pytest.mark.parametrize(
    ("payload_extra", "expected_routine"),
    [
        ({"exit_status": 0}, True),
        ({"success": True}, True),
        ({"success": False}, False),
        ({"denied": True}, False),
        ({"success": False, "exit_status": 0}, False),
    ],
)
def test_routine_read_label_excludes_explicit_failures(
    payload_extra: dict[str, bool | int], expected_routine: bool
) -> None:
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "session_id": "routine-read-outcome",
            "tool_name": "read",
            "tool_input": {"path": "ignored"},
            **payload_extra,
        },
        session_commitment=f"hmac-sha256:{'22' * 32}",
        event_ordinal=1,
        key_material=_KEY,
    )
    assert (envelope.structural_payload.get("action") == "routine_read") is expected_routine


def test_observe_without_consent_exits_zero_no_spool(tmp_path: Path) -> None:
    stdout = io.BytesIO()
    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {"session_id": "s1", "tool_name": "shell", "exit_status": 0}
        ).encode(),
        stdout=stdout,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    assert json.loads(stdout.getvalue().decode()) == {}


def test_legacy_spool_is_durable_without_touching_lived_in_observation_state(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    before = next((tmp_path / "observation" / "workspaces").glob("*.json")).read_bytes()

    assert (
        handle_spool(
            event_name="PreToolUse",
            stdin_bytes=b'{"session_id":"spool-test","tool_name":"shell","tool_input":{"cmd":"secret"}}',
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
        )
        == 0
    )
    assert next((tmp_path / "observation" / "workspaces").glob("*.json")).read_bytes() == before
    spool_files = list((tmp_path / "hook-spool").glob("*.jsonl"))
    assert len(spool_files) == 1
    assert b"secret" not in spool_files[0].read_bytes()


def test_legacy_spool_canonicalizes_git_subdirectory_to_consented_root(tmp_path: Path) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repo"
    nested = repository / "packages/app"
    nested.mkdir(parents=True)
    (repository / ".git").mkdir()
    store = LocalObservationStore(_state=state)
    root_commitment = store.workspace_commitment(str(repository))
    nested_commitment = store.workspace_commitment(str(nested))
    store.grant_consent(root_commitment)

    code = handle_spool(
        event_name="PreToolUse",
        stdin_bytes=b'{"session_id":"spool-git-root","tool_name":"shell"}',
        stdout=io.BytesIO(),
        workspace=str(nested),
        _state=state,
    )

    spool = HookSpool(_state=state)
    assert code == 0
    assert spool.pending_workspaces() == (root_commitment,)
    assert nested_commitment not in spool.pending_workspaces()
    with spool.claim(root_commitment) as records:
        assert len(records) == 1
        assert records[0].workspace_commitment == root_commitment


def test_post_tool_hook_never_delivers_observation_only_frontier_motion(tmp_path: Path) -> None:
    """Observation-authored motion leaves held frontiers valid, so it is no notice (#915).

    Every recorded frontier-motion notice describes observation-writer appends; the old text
    then asked for ``status`` between routine tool calls, against the workflow guidance.
    """

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "frontier-motion")
    payload = json.dumps(
        {"session_id": "frontier-motion", "tool_name": "Read", "exit_status": 0}
    ).encode()
    for from_sequence, to_sequence in ((4, 6), (6, 8)):
        store.note_frontier_motion(
            workspace,
            "frontier-motion",
            from_sequence=from_sequence,
            to_sequence=to_sequence,
            head_digest="sha256:" + str(to_sequence) * 64,
            observation_record_count=2,
            task_id="tsk-frontier-test",
        )
        stdout = io.BytesIO()
        assert (
            handle_observe(
                event_name="PostToolUse",
                stdin_bytes=payload,
                stdout=stdout,
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
            )
            == 0
        )
        # Observation-health and orphan plumbing stay out of hook context; no motion notice.
        emitted = stdout.getvalue()
        assert b"frontier moved" not in emitted and b"run status" not in emitted
        document = json.loads(emitted)
        context = document.get("hookSpecificOutput", {}).get("additionalContext")
        assert context in (None, "")


@pytest.mark.parametrize("tool_name", ["start", "mcp__finishup__publish_work"])
def test_codex_owned_tool_does_not_lease_frontier_advice(tmp_path: Path, tool_name: str) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = "codex:self-advice"
    store.bind_codex_session(workspace, session)
    store.note_frontier_motion(
        workspace,
        session,
        from_sequence=1,
        to_sequence=2,
        head_digest="sha256:" + "5" * 64,
        observation_record_count=1,
        task_id="tsk-codex-self-advice",
    )
    stdout = io.BytesIO()

    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {
                    "session_id": session,
                    "tool_name": tool_name,
                    "exit_status": 0,
                }
            ).encode(),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert stdout.getvalue() == b"{}\n"
    assert store.peek_frontier_motion(workspace, session) is not None


def test_stdout_teardown_failure_exits_zero_and_records_diagnostic(tmp_path: Path) -> None:
    class _ClosedStdout(io.BytesIO):
        def write(self, data: object) -> int:
            del data
            raise ValueError("I/O operation on closed file")

    code = handle_observe(
        event_name="Stop",
        stdin_bytes=json.dumps({"session_id": "stdout-failure"}).encode(),
        stdout=_ClosedStdout(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )

    assert code == 0
    diagnostics = tmp_path / "observation/hook-diagnostics.jsonl"
    assert diagnostics.exists()
    assert "stdout_write_failed" in diagnostics.read_text(encoding="utf-8")


def test_runtime_disabled_skips_capture_but_session_start_surfaces_cached_recommendation(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    store.set_runtime_enabled(False)
    store_recommendation_state(
        RecommendationState(last_evaluated_version="0.1.0", pending=("observation-enabled",)),
        root=tmp_path,
    )
    stdout = io.BytesIO()
    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps({"session_id": "disabled-session"}).encode(),
        stdout=stdout,
        workspace=str(tmp_path),
        _state=tmp_path,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    context = payload["hookSpecificOutput"]["additionalContext"]
    assert "Enable local observation" in context
    assert "workspace consent remains required" in context
    assert "finishup recommend accept observation-enabled" in context
    assert store.pending_workspaces() == ()
    workspace_state = tmp_path / "observation/workspaces"
    assert not workspace_state.exists() or not list(workspace_state.glob("*.json"))


def test_unsafe_runtime_gate_fails_closed_with_distinct_diagnostic(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    store.set_runtime_enabled(True)
    gate = tmp_path / "observation/runtime-gate.json"
    gate.write_text("not-json", encoding="utf-8")
    stdout = io.BytesIO()
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps({"session_id": "unsafe-gate", "tool_name": "shell"}).encode(),
        stdout=stdout,
        workspace=str(tmp_path),
        _state=tmp_path,
    )
    assert json.loads(stdout.getvalue()) == {}
    assert "hook_observe_degraded: runtime_gate_unsafe" in capsys.readouterr().err
    diagnostics = (tmp_path / "observation/hook-diagnostics.jsonl").read_text()
    assert '"reason":"runtime_gate_unsafe"' in diagnostics
    assert store.pending_workspaces() == ()


def test_unsafe_runtime_gate_records_workspace_gap_when_consented(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    gate = tmp_path / "observation/runtime-gate.json"
    gate.write_text("not-json", encoding="utf-8")
    stdout = io.BytesIO()
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps({"session_id": "unsafe-gate-gap", "tool_name": "shell"}).encode(),
        stdout=stdout,
        workspace=str(tmp_path),
        _state=tmp_path,
    )
    assert json.loads(stdout.getvalue()) == {}
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value in status.gaps


def test_unsafe_runtime_gate_canonicalizes_git_subdirectory_gap(tmp_path: Path) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repo"
    nested = repository / "packages/app"
    nested.mkdir(parents=True)
    (repository / ".git").mkdir()
    store = LocalObservationStore(_state=state)
    root_commitment = store.workspace_commitment(str(repository))
    nested_commitment = store.workspace_commitment(str(nested))
    store.grant_consent(root_commitment)
    store.set_runtime_enabled(True)
    gate = state / "observation/runtime-gate.json"
    gate.write_text("not-json", encoding="utf-8")

    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {"session_id": "unsafe-gate-subdirectory", "tool_name": "shell"}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(nested),
        _state=state,
    )

    status = store.status(ObservationStatusQuery(root_commitment))
    assert ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value in status.gaps
    assert store.consent_for(nested_commitment) is None


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO gate regression is POSIX-only")
def test_runtime_gate_fifo_fails_closed_without_blocking(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    store.set_runtime_enabled(True)
    gate = tmp_path / "observation/runtime-gate.json"
    gate.unlink()
    os.mkfifo(gate, mode=0o600)

    started = time.monotonic()
    with pytest.raises(PublicOperationError) as caught:
        store.runtime_enabled()

    assert caught.value.code is PublicErrorCode.STORAGE_UNSAFE
    assert time.monotonic() - started < 1.0


def test_unsafe_runtime_gate_falls_back_to_session_mapped_workspace(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    mapped_locator = tmp_path / "mapped-project"
    stale_locator = tmp_path / "stale-project"
    mapped = store.workspace_commitment(str(mapped_locator.resolve()))
    store.grant_consent(mapped)
    store.bind_codex_session(mapped, "unsafe-gate-mapped")
    gate = tmp_path / "observation/runtime-gate.json"
    gate.write_text("not-json", encoding="utf-8")

    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps({"session_id": "unsafe-gate-mapped", "tool_name": "shell"}).encode(),
        stdout=io.BytesIO(),
        workspace=str(stale_locator),
        _state=tmp_path,
    )

    status = store.status(ObservationStatusQuery(mapped))
    assert ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value in status.gaps


def test_runtime_gate_read_is_lock_free_under_store_contention(tmp_path: Path) -> None:
    """Holding the interprocess store lock must not block or fail the gate read (#273)."""

    store = LocalObservationStore(_state=tmp_path)
    store.set_runtime_enabled(True)
    acquired = threading.Event()
    release = threading.Event()

    def _hold() -> None:
        with store._lock:  # pyright: ignore[reportPrivateUsage]
            acquired.set()
            release.wait(timeout=10.0)

    holder = threading.Thread(target=_hold)
    holder.start()
    try:
        assert acquired.wait(timeout=5.0)
        started = time.monotonic()
        assert store.runtime_enabled() is True
        assert time.monotonic() - started < 1.0
    finally:
        release.set()
        holder.join()


def test_store_lock_contention_at_gate_does_not_discard_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    def _contended(self: LocalObservationStore) -> bool:
        raise TimeoutError("observation_store_lock_timeout")

    monkeypatch.setattr(LocalObservationStore, "runtime_enabled", _contended)
    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {"session_id": "contended-gate", "tool_name": "shell", "event_ordinal": 1}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    assert "hook_observe_degraded: runtime_gate_contended" in capsys.readouterr().err
    diagnostics = (tmp_path / "observation/hook-diagnostics.jsonl").read_text()
    assert '"reason":"runtime_gate_contended"' in diagnostics
    assert '"reason":"runtime_gate_unsafe"' not in diagnostics
    assert store.pending_workspaces() == (workspace,)


def test_service_unavailable_never_spools_visible_plaintext(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    canary = "VISIBLE_TASK_CANARY_6f4b2f"
    code = handle_observe(
        event_name="UserPromptSubmit",
        stdin_bytes=json.dumps(
            {"session_id": "no-spool", "prompt": canary, "event_ordinal": 1}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    persisted = b"".join(path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())
    assert canary.encode() not in persisted
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value in status.gaps


def test_advice_refresh_runs_after_local_capture_batch_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    original_refresh = LocalObservationStore.refresh_advice
    batch_states: list[bool] = []

    def refresh_outside_batch(self: LocalObservationStore, commitment: str, **kwargs: object):
        batch_states.append(commitment in self._batch)  # pyright: ignore[reportPrivateUsage]
        return original_refresh(self, commitment, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(LocalObservationStore, "refresh_advice", refresh_outside_batch)
    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {
                    "session_id": "advice-after-capture",
                    "tool_name": "shell",
                    "tool_call_id": "tool-1",
                    "exit_status": 0,
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert batch_states == [False]
    assert store.list_envelopes(workspace)
    assert store.list_pending_outbox_rows(workspace)


def test_service_failure_leaves_structural_capture_and_pairing_pending(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    async def unavailable_connect(_kind: object) -> object:
        raise ConnectionError("test service unavailable")

    def run_async(coro: object) -> object:
        return asyncio.run(coro)  # type: ignore[arg-type]

    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {
                    "session_id": "capture-before-drain",
                    "tool_name": "shell",
                    "tool_call_id": "tool-1",
                    "exit_status": 0,
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            connect=unavailable_connect,  # type: ignore[arg-type]
            run_async=run_async,  # type: ignore[arg-type]
        )
        == 0
    )

    envelopes = store.list_envelopes(workspace)
    pending = store.list_pending_outbox_rows(workspace)
    assert len(envelopes) == 1
    assert len(pending) == 1
    assert pending[0].envelope.source_identity == envelopes[0].source_identity


def test_observe_ingests_when_consented_and_pairs_pre_post(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    pre = handle_observe(
        event_name="PreToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "pair-1",
                "tool_name": "shell",
                "correlation_id": "c1",
                "tool_call_id": "c1",
            }
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert pre == 0
    post_out = io.BytesIO()
    post = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "pair-1",
                "tool_name": "shell",
                "correlation_id": "c1",
                "tool_call_id": "c1",
                "exit_status": 0,
            }
        ).encode(),
        stdout=post_out,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert post == 0
    status = store.status(
        __import__(
            "finishup.domain.observation", fromlist=["ObservationStatusQuery"]
        ).ObservationStatusQuery(workspace)
    )
    assert status.source_coverage[ObservationSource.CODEX_HOOK] is True
    assert ObservationGapCode.UNPAIRED_EVENT.value not in status.gaps


def test_tool_call_id_pairs_when_legacy_correlation_ids_differ(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    assert (
        handle_observe(
            event_name="PreToolUse",
            stdin_bytes=json.dumps(
                {
                    "session_id": "pair-alias",
                    "tool_name": "shell",
                    "correlation_id": "pre",
                    "tool_call_id": "shared",
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {
                    "session_id": "pair-alias",
                    "tool_name": "shell",
                    "tool_call_id": "shared",
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.UNPAIRED_EVENT.value not in status.gaps


def test_unpaired_post_records_gap(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "pair-2",
                "tool_name": "shell",
                "correlation_id": "missing-pre",
                "exit_status": 1,
            }
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    status = store.status(
        __import__(
            "finishup.domain.observation", fromlist=["ObservationStatusQuery"]
        ).ObservationStatusQuery(workspace)
    )
    assert ObservationGapCode.UNPAIRED_EVENT.value in status.gaps


def test_missing_codex_post_identity_is_retained_as_orphan_evidence(
    tmp_path: Path,
) -> None:
    """A paired result without a host id agrees across local status and materialization."""

    import uuid

    from finishup.application.observation_materialize import materialize_observation_envelope
    from finishup.protocol.ids import PREFIX_BY_KIND, IdKind

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    assert (
        handle_observe(
            event_name=None,
            stdin_bytes=json.dumps(
                {
                    "session_id": "no-id",
                    "hook_event_name": "PostToolUse",
                    "tool_name": "shell",
                    "exit_status": 1,
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    reopened = LocalObservationStore(_state=tmp_path)
    retained = reopened.list_envelopes(workspace)
    assert len(retained) == 1
    envelope = retained[0]
    assert ObservationGapCode.UNPAIRED_EVENT.value in envelope.gap_codes
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        in reopened.status(ObservationStatusQuery(workspace)).gaps
    )

    task_id = PREFIX_BY_KIND[IdKind.TASK] + str(uuid.uuid4())
    batch = materialize_observation_envelope(envelope, task_id=task_id)
    assert ObservationGapCode.UNPAIRED_EVENT.value in batch.gaps
    assert tuple(item.role for item in batch.drafts) == ("unpaired_evidence",)


@pytest.mark.parametrize("event_name", ("PostCompact", "SubagentStop"))
def test_missing_codex_lifecycle_identity_does_not_create_pairing_gap(
    tmp_path: Path, event_name: str
) -> None:
    """Lifecycle and child stop events have identity semantics separate from tool pairing."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    assert (
        handle_observe(
            event_name=None,
            stdin_bytes=json.dumps(
                {
                    "session_id": "no-id",
                    "hook_event_name": event_name,
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    retained = store.list_envelopes(workspace)
    assert len(retained) == 1
    assert ObservationGapCode.UNPAIRED_EVENT.value not in retained[0].gap_codes
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        not in store.status(ObservationStatusQuery(workspace)).gaps
    )


def _codex_0146_payload(event: str, tool_use_id: str, **extra: JsonValue) -> dict[str, JsonValue]:
    """A hook payload using only the field names the Codex 0.146.0 binary emits.

    The key set mirrors the wire-type table embedded in the shipped binary
    (#274): ``tool_use_id``, not ``tool_call_id``/``correlation_id``. Tests
    that feed our own key names back to us cannot catch a contract mismatch.
    """

    payload: dict[str, JsonValue] = {
        "session_id": "01a006a4-1111-4111-8111-000000000001",
        "turn_id": "turn-3",
        "agent_type": "main",
        "transcript_path": "/workspace/.codex/sessions/rollout-2026-08-15.jsonl",
        "cwd": "/workspace/project",
        "hook_event_name": event,
        "model": "gpt-5.3-codex",
        "permission_mode": "on-request",
        "trigger": "model",
        "tool_name": "shell",
        "tool_input": {"command": ["bash", "-lc", "pytest -q"]},
        "tool_use_id": tool_use_id,
    }
    payload.update(extra)
    return payload


def test_codex_tool_use_id_wins_over_legacy_tool_call_id(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    payload = _codex_0146_payload(
        "PreToolUse",
        "call_current",
        tool_call_id="call_legacy_conflict",
    )

    envelope = map_hook_payload_to_envelope(
        "PreToolUse",
        payload,
        session_commitment=store.session_commitment("codex-precedence"),
        event_ordinal=1,
        key_material=store.key_material(),
    )

    assert envelope.structural_payload.get("tool_call_id") == "call_current"


def test_codex_field_names_materialize_linked_action_and_result(tmp_path: Path) -> None:
    import uuid

    from finishup.application.observation_materialize import materialize_observation_envelope
    from finishup.protocol.ids import PREFIX_BY_KIND, IdKind

    store = LocalObservationStore(_state=tmp_path)
    session = store.session_commitment("codex-conformance")
    task = PREFIX_BY_KIND[IdKind.TASK] + str(uuid.uuid4())

    pre = map_hook_payload_to_envelope(
        "PreToolUse",
        _codex_0146_payload("PreToolUse", "call_p8H2mKfQ"),
        session_commitment=session,
        event_ordinal=1,
        key_material=store.key_material(),
    )
    # The host tool-call id survives ingress under the canonical structural key.
    assert pre.structural_payload.get("tool_call_id") == "call_p8H2mKfQ"
    pre_batch = materialize_observation_envelope(pre, task_id=task)
    assert pre_batch.skip_reason is None
    assert [item.draft.schema.name for item in pre_batch.drafts] == ["action_recorded"]

    post = map_hook_payload_to_envelope(
        "PostToolUse",
        _codex_0146_payload(
            "PostToolUse", "call_p8H2mKfQ", tool_response={"output": "ok"}, exit_status=0
        ),
        session_commitment=session,
        event_ordinal=2,
        key_material=store.key_material(),
    )
    post_batch = materialize_observation_envelope(post, task_id=task)
    assert post_batch.skip_reason is None
    assert [item.draft.schema.name for item in post_batch.drafts] == [
        "action_recorded",
        "result_recorded",
    ]
    assert ObservationGapCode.UNPAIRED_EVENT.value not in post_batch.gaps


def test_codex_delivery_pairs_pre_post_end_to_end(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    for event in ("PreToolUse", "PostToolUse"):
        # No event_name argument: the event resolves from ``hook_event_name``,
        # exactly as a real Codex delivery arrives.
        code = handle_observe(
            event_name=None,
            stdin_bytes=json.dumps(_codex_0146_payload(event, "call_e2e_1")).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        assert code == 0
    status = store.status(ObservationStatusQuery(workspace))
    assert status.source_coverage[ObservationSource.CODEX_HOOK] is True
    assert ObservationGapCode.UNPAIRED_EVENT.value not in status.gaps
    assert (
        store.has_open_pre(
            workspace,
            "call_e2e_1",
            source=ObservationSource.CODEX_HOOK,
            session_commitment=store.session_commitment("codex-precedence"),
            source_generation=1,
        )
        is False
    )


def test_issue_607_all_host_hook_shapes_keep_pairing_honest(tmp_path: Path) -> None:
    """Exercise the six reported cases through the real host ingress adapters."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    claude_common = {
        "session_id": "claude-607",
        "tool_name": "mcp__plugin_finishup_finishup__status",
        "tool_use_id": "claude-call-607",
    }
    assert (
        handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps({**claude_common, "hook_event_name": "PostToolUse"}).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert (
        handle_claude_observe(
            event_name="PostToolUseFailure",
            stdin_bytes=json.dumps(
                {**claude_common, "hook_event_name": "PostToolUseFailure"}
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    for event_name, session, generation in (
        ("afterMCPExecution", "cursor-607-mcp", "generation-mcp"),
        ("afterFileEdit", "cursor-607-edit", "generation-edit"),
    ):
        assert (
            handle_cursor_observe(
                event_name=event_name,
                stdin_bytes=json.dumps(
                    {
                        "conversation_id": session,
                        "hook_event_name": event_name,
                        "generation_id": generation,
                        "tool_name": "shell",
                        "file_path": "/private/607.py",
                    }
                ).encode(),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
            )
            == 0
        )

    handle_observe(
        event_name=None,
        stdin_bytes=json.dumps(_codex_0146_payload("PreToolUse", "codex-call-607")).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    handle_observe(
        event_name=None,
        stdin_bytes=json.dumps(_codex_0146_payload("PostToolUse", "codex-call-607")).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    handle_observe(
        event_name=None,
        stdin_bytes=json.dumps(_codex_0146_payload("PostToolUse", "codex-orphan-607")).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )

    envelopes = store.list_envelopes(workspace)
    assert len(envelopes) == 7
    assert all("unpaired_event" not in envelope.gap_codes for envelope in envelopes[:4])
    assert "unpaired_event" not in envelopes[5].gap_codes
    assert "unpaired_event" in envelopes[6].gap_codes
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_unpaired_event_gap_survives_an_unrelated_pair(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    handle_observe(
        event_name=None,
        stdin_bytes=json.dumps(_codex_0146_payload("PostToolUse", "call_orphan")).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )

    for event in ("PreToolUse", "PostToolUse"):
        handle_observe(
            event_name=None,
            stdin_bytes=json.dumps(_codex_0146_payload(event, "call_recovered")).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
    # A completed pair in another call lane cannot resolve the retained orphan.
    # Resolution must be scoped to the same source/session/generation/call, so
    # the true diagnostic remains visible (#607).
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )


@pytest.mark.parametrize("source", [ObservationSource.CLAUDE_HOOK, ObservationSource.CURSOR_HOOK])
def test_historical_host_pairing_gap_resolves_without_erasing_history(
    tmp_path: Path, source: ObservationSource
) -> None:
    """A pre-#607 host false positive is retired while its history stays auditable."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(f"{source.value}-historical")
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "session_id": f"{source.value}-historical",
            "tool_name": "shell",
            "tool_use_id": "historical-call",
        },
        session_commitment=session,
        event_ordinal=1,
        key_material=store.key_material(),
        source=source,
        gap_codes=(ObservationGapCode.UNPAIRED_EVENT.value,),
    )
    result = store.ingest(envelope, workspace_commitment=workspace)
    assert result.disposition is ObservationIngestDisposition.ACCEPTED

    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.UNPAIRED_EVENT.value not in status.gaps
    state_path = next((tmp_path / "observation" / "workspaces").glob("*.json"))
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["gap_history"][ObservationGapCode.UNPAIRED_EVENT.value]["active"] is False
    assert ObservationGapCode.UNPAIRED_EVENT.value in state["gaps"]


def test_pairing_history_fence_survives_a_pre11_writer_round_trip(tmp_path: Path) -> None:
    """A downgraded writer cannot turn lost orphan provenance into a clear gap."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("claude-downgrade-fence")
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "session_id": "claude-downgrade-fence",
            "tool_name": "shell",
            "tool_use_id": "call-downgrade-fence",
        },
        session_commitment=session,
        event_ordinal=1,
        key_material=store.key_material(),
        source=ObservationSource.CLAUDE_HOOK,
        gap_codes=(ObservationGapCode.UNPAIRED_EVENT.value,),
    )
    assert store.ingest(envelope, workspace_commitment=workspace).disposition.value == "accepted"
    # Simulate an older paired writer having recorded a true orphan before the
    # host's legacy post-only interpretation was applied.
    store.note_unpaired_event(
        workspace,
        source=ObservationSource.CLAUDE_HOOK,
        session_commitment=session,
        source_generation=envelope.cursor.source_generation,
        source_identity=envelope.source_identity,
    )
    state_path = next((tmp_path / "observation" / "workspaces").glob("*.json"))
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["schema"] = "yoetz.observation-local/10"
    state.pop("pairing_state_unknown", None)
    state.pop("unpaired_scopes", None)
    state_path.write_text(json.dumps(state), encoding="utf-8")

    reopened = LocalObservationStore(_state=tmp_path)
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        in reopened.status(ObservationStatusQuery(workspace)).gaps
    )
    reopened.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["schema"] == "yoetz.observation-local/15"
    assert persisted["pairing_state_unknown"] is True
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        in reopened.status(ObservationStatusQuery(workspace)).gaps
    )


def test_codex_pairing_contract_cannot_be_overridden_by_payload_marker(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    payload = _codex_0146_payload(
        "PostToolUse",
        "call-forged-profile",
        pairing_mode="post_only",
        correlation_kind="generation_id",
        generation_id="generation-forged",
    )
    handle_observe(
        event_name=None,
        stdin_bytes=json.dumps(payload).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_pairing_admission_serializes_shared_pre_and_two_posts(tmp_path: Path) -> None:
    """Only one concurrent post may consume a durable pre; the other stays orphaned."""

    from concurrent.futures import ThreadPoolExecutor

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("codex-atomic-pairing")

    def envelope(event: str, ordinal: int) -> ObservationEnvelope:
        return map_hook_payload_to_envelope(
            event,
            _codex_0146_payload(event, "shared-call", event_ordinal=ordinal),
            session_commitment=session,
            event_ordinal=ordinal,
            key_material=store.key_material(),
        )

    pre = envelope("PreToolUse", 1)
    pre_result, _ = store.ingest_with_pairing(
        pre,
        workspace_commitment=workspace,
        pairing_mode="paired",
        correlation_id="shared-call",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=1,
        is_pre_event=True,
        is_post_event=False,
    )
    assert pre_result.disposition is ObservationIngestDisposition.ACCEPTED

    posts = (envelope("PostToolUse", 2), envelope("PostToolUse", 3))

    def ingest(
        post: ObservationEnvelope,
    ) -> tuple[ObservationIngestDisposition, ObservationEnvelope]:
        result, admitted = store.ingest_with_pairing(
            post,
            workspace_commitment=workspace,
            pairing_mode="paired",
            correlation_id="shared-call",
            source=ObservationSource.CODEX_HOOK,
            session_commitment=session,
            source_generation=1,
            is_pre_event=False,
            is_post_event=True,
        )
        return result.disposition, admitted

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(ingest, posts))

    assert [result[0] for result in results].count(ObservationIngestDisposition.ACCEPTED) == 2
    retained_posts = store.list_envelopes(workspace)[1:]
    assert sorted("unpaired_event" in post.gap_codes for post in retained_posts) == [False, True]
    assert (
        store.has_open_pre(
            workspace,
            "shared-call",
            source=ObservationSource.CODEX_HOOK,
            session_commitment=session,
            source_generation=1,
        )
        is False
    )


def test_pairing_admission_derives_contract_from_envelope(tmp_path: Path) -> None:
    """Callers cannot mark a paired envelope post-only or switch its lane."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("codex-contract-validation")
    envelope = map_hook_payload_to_envelope(
        "PreToolUse",
        _codex_0146_payload("PreToolUse", "contract-call"),
        session_commitment=session,
        event_ordinal=1,
        key_material=store.key_material(),
    )

    def admit(
        *,
        pairing_mode: str = "paired",
        correlation_id: str | None = "contract-call",
        is_pre_event: bool = True,
    ) -> object:
        return store.ingest_with_pairing(
            envelope,
            workspace_commitment=workspace,
            pairing_mode=pairing_mode,
            correlation_id=correlation_id,
            source=ObservationSource.CODEX_HOOK,
            session_commitment=session,
            source_generation=envelope.cursor.source_generation,
            is_pre_event=is_pre_event,
            is_post_event=False,
        )

    with pytest.raises(ProtocolValueError):
        admit(pairing_mode="post_only")
    with pytest.raises(ProtocolValueError):
        admit(correlation_id="other-call")
    with pytest.raises(ProtocolValueError):
        admit(is_pre_event=False)
    assert store.list_envelopes(workspace) == ()


def test_reordered_post_then_pre_keeps_the_orphan_diagnostic(tmp_path: Path) -> None:
    """A late pre cannot retroactively prove an orphaned post was paired."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("codex-reordered-pairing")

    def envelope(event: str, ordinal: int) -> ObservationEnvelope:
        return map_hook_payload_to_envelope(
            event,
            _codex_0146_payload(event, "reordered-call", event_ordinal=ordinal),
            session_commitment=session,
            event_ordinal=ordinal,
            key_material=store.key_material(),
        )

    post_result, admitted_post = store.ingest_with_pairing(
        envelope("PostToolUse", 1),
        workspace_commitment=workspace,
        pairing_mode="paired",
        correlation_id="reordered-call",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=1,
        is_pre_event=False,
        is_post_event=True,
    )
    assert post_result.disposition is ObservationIngestDisposition.ACCEPTED
    assert ObservationGapCode.UNPAIRED_EVENT.value in admitted_post.gap_codes

    pre_result, admitted_pre = store.ingest_with_pairing(
        envelope("PreToolUse", 2),
        workspace_commitment=workspace,
        pairing_mode="paired",
        correlation_id="reordered-call",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=1,
        is_pre_event=True,
        is_post_event=False,
    )
    assert pre_result.disposition is ObservationIngestDisposition.ACCEPTED
    assert ObservationGapCode.UNPAIRED_EVENT.value not in admitted_pre.gap_codes
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_duplicate_post_does_not_consume_orphan_pairing_state(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("codex-duplicate-pairing")
    pre = map_hook_payload_to_envelope(
        "PreToolUse",
        _codex_0146_payload("PreToolUse", "duplicate-call"),
        session_commitment=session,
        event_ordinal=1,
        key_material=store.key_material(),
    )
    post = map_hook_payload_to_envelope(
        "PostToolUse",
        _codex_0146_payload("PostToolUse", "duplicate-call"),
        session_commitment=session,
        event_ordinal=2,
        key_material=store.key_material(),
    )
    store.ingest_with_pairing(
        pre,
        workspace_commitment=workspace,
        pairing_mode="paired",
        correlation_id="duplicate-call",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=1,
        is_pre_event=True,
        is_post_event=False,
    )

    def ingest_duplicate() -> ObservationIngestDisposition:
        result, _ = store.ingest_with_pairing(
            post,
            workspace_commitment=workspace,
            pairing_mode="paired",
            correlation_id="duplicate-call",
            source=ObservationSource.CODEX_HOOK,
            session_commitment=session,
            source_generation=1,
            is_pre_event=False,
            is_post_event=True,
        )
        return result.disposition

    def run_duplicate(_unused: int) -> ObservationIngestDisposition:
        del _unused
        return ingest_duplicate()

    with ThreadPoolExecutor(max_workers=2) as pool:
        dispositions = tuple(pool.map(run_duplicate, (0, 1)))
    assert sorted(disposition.value for disposition in dispositions) == ["accepted", "duplicate"]
    assert "unpaired_event" not in store.list_envelopes(workspace)[-1].gap_codes
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        not in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_issue_607_native_post_only_hooks_do_not_create_false_pairing_gaps(
    tmp_path: Path,
) -> None:
    """Claude/Cursor post-only carriers stay evidence-only; Codex orphaning remains visible."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    claude_payload = {
        "hook_event_name": "PostToolUse",
        "session_id": "claude-607",
        "tool_name": "mcp__plugin_finishup_finishup__status",
        "tool_use_id": "claude-call-607",
    }
    assert (
        handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(claude_payload).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert (
        handle_claude_observe(
            event_name="PostToolUseFailure",
            stdin_bytes=json.dumps(
                {**claude_payload, "hook_event_name": "PostToolUseFailure"}
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    for event_name, conversation, generation in (
        ("afterMCPExecution", "cursor-607-mcp", "generation-mcp"),
        ("afterFileEdit", "cursor-607-edit", "generation-edit"),
    ):
        assert (
            handle_cursor_observe(
                event_name=event_name,
                stdin_bytes=json.dumps(
                    {
                        "conversation_id": conversation,
                        "hook_event_name": event_name,
                        "generation_id": generation,
                        "tool_name": "shell",
                    }
                ).encode(),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
            )
            == 0
        )

    for event_name in ("PreToolUse", "PostToolUse"):
        handle_observe(
            event_name=None,
            stdin_bytes=json.dumps(_codex_0146_payload(event_name, "codex-paired-607")).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )

    # The paired Codex profile still distinguishes a real orphan from the
    # native post-only cases above.
    handle_observe(
        event_name=None,
        stdin_bytes=json.dumps(_codex_0146_payload("PostToolUse", "codex-orphan-607")).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )

    envelopes = store.list_envelopes(workspace)
    assert len(envelopes) == 7
    assert all(
        ObservationGapCode.UNPAIRED_EVENT.value not in envelope.gap_codes
        for envelope in envelopes[:4]
    )
    assert all(
        ObservationGapCode.UNPAIRED_EVENT.value not in envelope.gap_codes
        for envelope in envelopes[4:6]
    )
    assert ObservationGapCode.UNPAIRED_EVENT.value in envelopes[6].gap_codes
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_issue_607_post_only_materializes_evidence_without_a_fabricated_action(
    tmp_path: Path,
) -> None:
    import uuid

    from finishup.application.observation_materialize import materialize_observation_envelope
    from finishup.protocol.ids import PREFIX_BY_KIND, IdKind

    store = LocalObservationStore(_state=tmp_path)
    task_id = PREFIX_BY_KIND[IdKind.TASK] + str(uuid.uuid4())
    session = store.session_commitment("post-only-materialization")
    claude = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "tool_name": "shell",
            "tool_use_id": "claude-call-materialize",
            "capability_profile_id": "claude-code-cli-local-project-2.1.241",
            "pairing_mode": "post_only",
            "correlation_kind": "tool_call_id",
        },
        session_commitment=session,
        event_ordinal=1,
        key_material=store.key_material(),
        source=ObservationSource.CLAUDE_HOOK,
    )
    cursor = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "tool_name": "shell",
            "generation_id": "cursor-generation-materialize",
            "capability_profile_id": "cursor-ide-3.17.8",
            "pairing_mode": "post_only",
            "correlation_kind": "generation_id",
        },
        session_commitment=session,
        event_ordinal=2,
        key_material=store.key_material(),
        source=ObservationSource.CURSOR_HOOK,
    )
    for envelope in (claude, cursor):
        batch = materialize_observation_envelope(envelope, task_id=task_id)
        assert batch.skip_reason is None
        if envelope.source is ObservationSource.CLAUDE_HOOK:
            # Claude's post-only contract can carry a real tool-use id.  The
            # post-only action/result mapping preserves that identity without
            # claiming a missing pre-event; only Cursor's generation identity
            # remains evidence-only.
            assert [item.draft.schema.name for item in batch.drafts] == [
                "action_recorded",
                "result_recorded",
            ]
            assert [item.role for item in batch.drafts] == ["action", "result"]
        else:
            assert [item.draft.schema.name for item in batch.drafts] == ["evidence_recorded"]
            assert all(item.role == "post_only_evidence" for item in batch.drafts)
        assert ObservationGapCode.UNPAIRED_EVENT.value not in batch.gaps


def test_codex_pairing_is_scoped_and_reordered_or_duplicate_posts_stay_honest(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    def admit(
        event: str,
        *,
        session_id: str,
        call_id: str,
        ordinal: int,
        generation: int = 1,
    ) -> tuple[ObservationIngestDisposition, ObservationEnvelope]:
        session = store.session_commitment(session_id)
        envelope = map_hook_payload_to_envelope(
            event,
            _codex_0146_payload(event, call_id),
            session_commitment=session,
            event_ordinal=ordinal,
            source_generation=generation,
            key_material=store.key_material(),
        )
        result, retained = store.ingest_with_pairing(
            envelope,
            workspace_commitment=workspace,
            pairing_mode="paired",
            correlation_id=call_id,
            source=ObservationSource.CODEX_HOOK,
            session_commitment=session,
            source_generation=generation,
            is_pre_event=event == "PreToolUse",
            is_post_event=event == "PostToolUse",
        )
        return result.disposition, retained

    # Same call ids in different source sessions cannot consume one another's pre.
    _, first_pre = admit("PreToolUse", session_id="codex-scope-a", call_id="same-call", ordinal=1)
    _, foreign_post = admit(
        "PostToolUse", session_id="codex-scope-b", call_id="same-call", ordinal=1
    )
    assert ObservationGapCode.UNPAIRED_EVENT.value not in first_pre.gap_codes
    assert ObservationGapCode.UNPAIRED_EVENT.value in foreign_post.gap_codes

    # A post arriving before its pre remains an orphan after the late pre.
    _, reordered_post = admit(
        "PostToolUse", session_id="codex-reorder", call_id="reordered", ordinal=1
    )
    _, reordered_pre = admit(
        "PreToolUse", session_id="codex-reorder", call_id="reordered", ordinal=2
    )
    assert ObservationGapCode.UNPAIRED_EVENT.value in reordered_post.gap_codes
    assert ObservationGapCode.UNPAIRED_EVENT.value not in reordered_pre.gap_codes

    # Replaying the orphan after its late pre still returns the retained orphan; it cannot
    # retroactively pair that history or consume the newly opened pre.
    orphan_disposition, duplicate_orphan = admit(
        "PostToolUse", session_id="codex-reorder", call_id="reordered", ordinal=1
    )
    assert orphan_disposition is ObservationIngestDisposition.DUPLICATE
    assert duplicate_orphan == reordered_post
    assert store.has_open_pre(
        workspace,
        "reordered",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=store.session_commitment("codex-reorder"),
        source_generation=1,
    )

    # Duplicate delivery is idempotent and cannot consume or create a second
    # pairing transition.
    admit("PreToolUse", session_id="codex-duplicate", call_id="duplicate", ordinal=1)
    first_disposition, first_post = admit(
        "PostToolUse", session_id="codex-duplicate", call_id="duplicate", ordinal=2
    )
    duplicate_disposition, duplicate_post = admit(
        "PostToolUse", session_id="codex-duplicate", call_id="duplicate", ordinal=2
    )
    assert first_disposition is ObservationIngestDisposition.ACCEPTED
    assert duplicate_disposition is ObservationIngestDisposition.DUPLICATE
    assert ObservationGapCode.UNPAIRED_EVENT.value not in first_post.gap_codes
    assert ObservationGapCode.UNPAIRED_EVENT.value not in duplicate_post.gap_codes
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )


@pytest.mark.parametrize("source", [ObservationSource.CLAUDE_HOOK, ObservationSource.CURSOR_HOOK])
def test_legacy_post_only_gap_retires_current_projection_but_keeps_history(
    tmp_path: Path, source: ObservationSource
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(f"legacy-{source.value}")
    profile = (
        "claude-code-cli-local-project-2.1.241"
        if source is ObservationSource.CLAUDE_HOOK
        else "cursor-ide-3.17.8"
    )
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "capability_profile_id": profile,
            "generation_id": "cursor-generation"
            if source is ObservationSource.CURSOR_HOOK
            else None,
            "tool_name": "shell",
            "tool_use_id": "claude-call" if source is ObservationSource.CLAUDE_HOOK else None,
        },
        session_commitment=session,
        event_ordinal=1,
        key_material=store.key_material(),
        source=source,
        gap_codes=(ObservationGapCode.UNPAIRED_EVENT.value,),
    )
    assert store.ingest(envelope, workspace_commitment=workspace).disposition is (
        ObservationIngestDisposition.ACCEPTED
    )
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.UNPAIRED_EVENT.value not in status.gaps
    state_path = next((tmp_path / "observation" / "workspaces").glob("*.json"))
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["gap_history"][ObservationGapCode.UNPAIRED_EVENT.value]["active"] is False
    assert ObservationGapCode.UNPAIRED_EVENT.value in state["gaps"]

    # A pre-/11 state has no occurrence/provenance count.  Even when the one
    # retained candidate is post-only, an omitted historical occurrence must
    # remain an active unknown rather than being cleared from absence.
    state["schema"] = "yoetz.observation-local/10"
    state.pop("pairing_history_complete", None)
    state["gap_history"][ObservationGapCode.UNPAIRED_EVENT.value]["active"] = True
    state["gaps"] = [ObservationGapCode.UNPAIRED_EVENT.value]
    state_path.write_text(json.dumps(state), encoding="utf-8")
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        in LocalObservationStore(_state=tmp_path).status(ObservationStatusQuery(workspace)).gaps
    )


def test_pairing_transaction_rolls_back_an_admitted_pre_before_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("pairing-fault-pre")
    envelope = map_hook_payload_to_envelope(
        "PreToolUse",
        _codex_0146_payload("PreToolUse", "pairing-fault-pre"),
        session_commitment=session,
        event_ordinal=1,
        key_material=store.key_material(),
    )

    def fail_after_ingest(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("fault after envelope append")

    monkeypatch.setattr(LocalObservationStore, "note_open_pre", fail_after_ingest)
    with store.batched(workspace):
        with pytest.raises(RuntimeError, match="fault after envelope append"):
            store.ingest_with_pairing(
                envelope,
                workspace_commitment=workspace,
                pairing_mode="paired",
                correlation_id="pairing-fault-pre",
                source=ObservationSource.CODEX_HOOK,
                session_commitment=session,
                source_generation=1,
                is_pre_event=True,
                is_post_event=False,
            )

    reopened = LocalObservationStore(_state=tmp_path)
    assert reopened.list_envelopes(workspace) == ()
    assert not reopened.has_open_pre(
        workspace,
        "pairing-fault-pre",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=1,
    )

    monkeypatch.undo()
    result, _ = reopened.ingest_with_pairing(
        envelope,
        workspace_commitment=workspace,
        pairing_mode="paired",
        correlation_id="pairing-fault-pre",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=1,
        is_pre_event=True,
        is_post_event=False,
    )
    assert result.disposition is ObservationIngestDisposition.ACCEPTED
    assert reopened.has_open_pre(
        workspace,
        "pairing-fault-pre",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=1,
    )


def test_pairing_transaction_rolls_back_an_admitted_post_before_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("pairing-fault-post")

    def envelope(event: str, ordinal: int) -> ObservationEnvelope:
        return map_hook_payload_to_envelope(
            event,
            _codex_0146_payload(event, "pairing-fault-post"),
            session_commitment=session,
            event_ordinal=ordinal,
            key_material=store.key_material(),
        )

    pre = envelope("PreToolUse", 1)
    post = envelope("PostToolUse", 2)
    pre_result, _ = store.ingest_with_pairing(
        pre,
        workspace_commitment=workspace,
        pairing_mode="paired",
        correlation_id="pairing-fault-post",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=1,
        is_pre_event=True,
        is_post_event=False,
    )
    assert pre_result.disposition is ObservationIngestDisposition.ACCEPTED

    def fail_after_post(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("fault after post append")

    monkeypatch.setattr(LocalObservationStore, "consume_open_pre", fail_after_post)
    with pytest.raises(RuntimeError, match="fault after post append"):
        store.ingest_with_pairing(
            post,
            workspace_commitment=workspace,
            pairing_mode="paired",
            correlation_id="pairing-fault-post",
            source=ObservationSource.CODEX_HOOK,
            session_commitment=session,
            source_generation=1,
            is_pre_event=False,
            is_post_event=True,
        )

    reopened = LocalObservationStore(_state=tmp_path)
    assert len(reopened.list_envelopes(workspace)) == 1
    assert reopened.has_open_pre(
        workspace,
        "pairing-fault-post",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=1,
    )

    monkeypatch.undo()
    post_result, admitted = reopened.ingest_with_pairing(
        post,
        workspace_commitment=workspace,
        pairing_mode="paired",
        correlation_id="pairing-fault-post",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=1,
        is_pre_event=False,
        is_post_event=True,
    )
    assert post_result.disposition is ObservationIngestDisposition.ACCEPTED
    assert ObservationGapCode.UNPAIRED_EVENT.value not in admitted.gap_codes
    assert len(reopened.list_envelopes(workspace)) == 2
    assert not reopened.has_open_pre(
        workspace,
        "pairing-fault-post",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=1,
    )


def test_finishup_tool_still_ingests_but_skips_advice_loop(tmp_path: Path) -> None:
    from finishup.domain.observation import AdviceSnapshot
    from finishup.domain.values import finding_id
    from finishup.protocol.coverage import (
        ArtifactObservation,
        AuthorshipAssurance,
        CheckType,
        Coverage,
        EvidenceImmutability,
        LedgerFreshness,
        PublicationChannel,
    )

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.set_advice_snapshot(
        workspace,
        AdviceSnapshot(
            ranked_finding_ids=(finding_id("fnd_00000000-0000-4000-8000-000000000001"),),
            evidence_basis_digest="sha256:" + "a" * 64,
            confidence_coverage=Coverage(
                publication_channels=(PublicationChannel.HOOK_OBSERVED,),
                authorship_assurance=AuthorshipAssurance.HARNESS_OBSERVED,
                artifact_observation=ArtifactObservation.HOOK_OBSERVED,
                evidence_immutability=EvidenceImmutability.CONTENT_DIGEST,
                ledger_freshness=LedgerFreshness.CURRENT,
                check_types=(CheckType.DETERMINISTIC,),
                known_gaps=(),
            ),
            recommended_next_action="call_status",
            freshness_frontier="frontier-1",
            suppression_identity="suppress-1",
        ),
    )
    out = io.BytesIO()
    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {"session_id": "finishup-tool", "tool_name": "mcp__finishup__status"}
        ).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    assert json.loads(out.getvalue().decode()) == {}


def test_skip_service_session_start_never_opens_service_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.adapters.integrations.codex_lifecycle import (
        mapping_from_start_ids,
        store_mapping,
    )
    from finishup.protocol.ids import IdKind, new_id

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    service_touches: list[str] = []

    async def forbidden_connect(*_args: object, **_kwargs: object) -> object:
        service_touches.append("connect_service")
        raise AssertionError("skip_service must never open a service connection")

    async def forbidden_auto_start(*_args: object, **_kwargs: object) -> object:
        service_touches.append("_try_auto_start")
        raise AssertionError("skip_service must never auto-attach a ledger task")

    monkeypatch.setattr(observe_hooks_module, "connect_service", forbidden_connect)
    monkeypatch.setattr(observe_hooks_module, "_try_auto_start", forbidden_auto_start)

    # Unmapped session: the auto-attach branch must be gated by skip_service.
    unmapped = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {"session_id": "probe-unmapped", "hook_event_name": "SessionStart", "cwd": "."}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert unmapped == 0

    # Mapped session: the status-read branch must be gated as well.
    store_mapping(
        mapping_from_start_ids(
            codex_session_id="probe-mapped",
            yoetz_task_id=new_id(IdKind.TASK),
            yoetz_session_id=new_id(IdKind.SESSION),
            yoetz_writer_id=new_id(IdKind.WRITER),
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    mapped = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {"session_id": "probe-mapped", "hook_event_name": "SessionStart", "cwd": "."}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert mapped == 0
    assert service_touches == []
    # Local capture still ran: sessions bound and envelopes queued in the outbox.
    assert store.find_workspace_for_codex_session("probe-unmapped") == workspace
    assert store.find_workspace_for_codex_session("probe-mapped") == workspace
    assert store.list_pending_outbox(workspace)


def test_session_start_stale_mapping_advisory_keeps_advice_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A SESSION_CONFLICT status answer means the mapping is stale, not the
    service down: the observe path must emit the shared stale advisory (#308)
    and let pending advice join it instead of being starved."""

    import uuid

    from finishup.adapters.integrations.codex_lifecycle import (
        load_mapping,
        mapping_from_start_ids,
        store_mapping,
    )
    from finishup.adapters.integrations.observation_local import AdviceDelivery
    from finishup.cli import hooks as hooks_module
    from finishup.domain.observation import AdviceSnapshot
    from finishup.protocol.ids import IdKind, new_id
    from finishup.protocol.models import OperationFailureModel

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store_mapping(
        mapping_from_start_ids(
            codex_session_id="stale-observe",
            yoetz_task_id=new_id(IdKind.TASK),
            yoetz_session_id=new_id(IdKind.SESSION),
            yoetz_writer_id=new_id(IdKind.WRITER),
            last_frontier="0:genesis",
        ),
        _state=tmp_path,
    )
    failure = OperationFailureModel.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "ok": False,
            "error": {
                "code": "SESSION_CONFLICT",
                "message": "The requested task attachment conflicts.",
                "retryable": False,
                "correlation_id": f"err_{uuid.uuid4()}",
            },
        }
    )

    class _Result:
        root = failure

    class _Client:
        async def status(self, request: object, *, deadline_ms: int | None = None) -> object:
            del request, deadline_ms
            return _Result()

        async def observation_ingest(self, body: object, *, deadline_ms: int) -> object:
            del body, deadline_ms
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object) -> _Client:
        return _Client()

    advice = AdviceDelivery(
        snapshot=cast(AdviceSnapshot, object()),
        item=None,
        delivery_identity="advice-1",
        text="Standing advice: connect a provider.",
    )
    commits: list[str] = []

    def fake_peek(
        self: LocalObservationStore,
        workspace_arg: str,
        *,
        yoetz_session_id: str | None = None,
        allow_standing: bool = True,
        session_commitment: str | None = None,
    ) -> AdviceDelivery:
        del self, workspace_arg, yoetz_session_id, allow_standing, session_commitment
        return advice

    def fake_commit(
        self: LocalObservationStore,
        workspace_arg: str,
        identity: str,
        *,
        yoetz_session_id: str | None = None,
        session_commitment: str | None = None,
    ) -> None:
        del self, workspace_arg, yoetz_session_id, session_commitment
        commits.append(identity)

    monkeypatch.setattr(LocalObservationStore, "peek_advice_for_delivery", fake_peek)
    monkeypatch.setattr(LocalObservationStore, "commit_advice_delivery", fake_commit)

    out = io.BytesIO()
    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {"session_id": "stale-observe", "hook_event_name": "SessionStart", "cwd": "."}
        ).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )
    assert code == 0
    context = json.loads(out.getvalue().decode())["hookSpecificOutput"]["additionalContext"]
    mapping = load_mapping("stale-observe", _state=tmp_path)
    assert mapping is not None
    stale_text = hooks_module._stale_mapping_context(mapping)  # pyright: ignore[reportPrivateUsage]
    assert context.startswith(stale_text)
    assert "unavailable" not in context
    # The static stale advisory must not starve pending advice (#241, #280 pattern).
    assert advice.text in context
    assert commits == ["advice-1"]
    # The stale mapping survives: repair belongs to the agent's own re-start.
    assert load_mapping("stale-observe", _state=tmp_path) is not None
    diagnostics = (tmp_path / "observation" / "hook-diagnostics.jsonl").read_text()
    assert '"reason":"mapping_stale"' in diagnostics


def _status_active_client(task_id: str, session_id: str, writer_id: str) -> object:
    class _Head:
        sequence = "3"
        head_digest = "sha256:" + "c" * 64

    class _Success:
        pass

    success = _Success()
    success.task_id = task_id  # type: ignore[attr-defined]
    success.session_id = session_id  # type: ignore[attr-defined]
    success.writer_id = writer_id  # type: ignore[attr-defined]
    success.head_frontier = _Head()  # type: ignore[attr-defined]

    class _Result:
        root = success

    class _Client:
        async def status(self, request: object, *, deadline_ms: int | None = None) -> object:
            del request, deadline_ms
            return _Result()

        async def observation_ingest(self, body: object, *, deadline_ms: int) -> object:
            del body, deadline_ms
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    return _Client()


def test_session_start_status_read_carries_the_consented_locator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The resume/compact status probe is repository-bound like the auto-attach start (#578).

    Before, the shared observe path connected bare, the daemon's repository fence answered
    `SESSION_CONFLICT`, and every compaction reported a live mapping as `mapping_stale`.
    """

    from finishup.adapters.integrations.codex_lifecycle import (
        load_mapping,
        mapping_from_start_ids,
        store_mapping,
    )
    from finishup.ports.control import WorkspaceLocator
    from finishup.protocol.ids import IdKind, new_id

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    task_id, session_id, writer_id = (
        new_id(IdKind.TASK),
        new_id(IdKind.SESSION),
        new_id(IdKind.WRITER),
    )
    store_mapping(
        mapping_from_start_ids(
            codex_session_id="claude:compact-1",
            yoetz_task_id=task_id,
            yoetz_session_id=session_id,
            yoetz_writer_id=writer_id,
            last_frontier="0:genesis",
        ),
        _state=tmp_path,
    )
    captured: list[WorkspaceLocator | None] = []
    client = _status_active_client(task_id, session_id, writer_id)

    async def connect(_kind: object, *, workspace_locator: WorkspaceLocator | None = None):
        captured.append(workspace_locator)
        return client

    monkeypatch.setattr(observe_hooks_module, "connect_service", connect, raising=False)

    out = io.BytesIO()
    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {
                "session_id": "claude:compact-1",
                "hook_event_name": "SessionStart",
                "source": "compact",
            }
        ).encode(),
        stdout=out,
        workspace=locator,
        _state=tmp_path,
    )
    assert code == 0
    assert captured[0] == WorkspaceLocator(locator)
    context = json.loads(out.getvalue().decode())["hookSpecificOutput"]["additionalContext"]
    assert task_id in context
    assert f"session_id {session_id} and writer_id {writer_id}" in context
    assert "3:sha256:" in context
    refreshed = load_mapping("claude:compact-1", _state=tmp_path)
    assert refreshed is not None
    assert refreshed.last_frontier == "3:sha256:" + "c" * 64
    diagnostics_path = tmp_path / "observation" / "hook-diagnostics.jsonl"
    assert not diagnostics_path.exists() or "mapping_stale" not in diagnostics_path.read_text()


def test_legacy_bound_session_probe_carries_the_host_payload_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #659: the shared mapped SessionStart without an explicit workspace recovers its
    commitment from the legacy session binding, and the status probe now carries a locator derived
    from the host payload's cwd instead of connecting bare."""

    from finishup.adapters.integrations.codex_lifecycle import (
        load_mapping,
        mapping_from_start_ids,
        store_mapping,
    )
    from finishup.ports.control import WorkspaceLocator
    from finishup.protocol.ids import IdKind, new_id

    project = tmp_path / "project"
    project.mkdir()
    project.chmod(0o700)
    (project / ".git").mkdir()
    (project / "src").mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    elsewhere.chmod(0o700)
    monkeypatch.chdir(elsewhere)
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    locator = str(project)
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "codex:legacy-compact-1")
    task_id, session_id, writer_id = (
        new_id(IdKind.TASK),
        new_id(IdKind.SESSION),
        new_id(IdKind.WRITER),
    )
    store_mapping(
        mapping_from_start_ids(
            codex_session_id="codex:legacy-compact-1",
            yoetz_task_id=task_id,
            yoetz_session_id=session_id,
            yoetz_writer_id=writer_id,
            last_frontier="0:genesis",
        ),
        _state=state,
    )
    captured: list[WorkspaceLocator | None] = []
    client = _status_active_client(task_id, session_id, writer_id)

    async def connect(_kind: object, *, workspace_locator: WorkspaceLocator | None = None):
        captured.append(workspace_locator)
        return client

    monkeypatch.setattr(observe_hooks_module, "connect_service", connect, raising=False)

    out = io.BytesIO()
    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {
                "session_id": "codex:legacy-compact-1",
                "hook_event_name": "SessionStart",
                "source": "compact",
                "cwd": str(project / "src"),
            }
        ).encode(),
        stdout=out,
        workspace=None,
        _state=state,
    )
    assert code == 0
    # The subdirectory cwd resolved to the repository root the mapping was consented under.
    assert captured and captured[0] == WorkspaceLocator(locator)
    context = json.loads(out.getvalue().decode())["hookSpecificOutput"]["additionalContext"]
    assert f"session_id {session_id} and writer_id {writer_id}" in context
    refreshed = load_mapping("codex:legacy-compact-1", _state=state)
    assert refreshed is not None
    assert (refreshed.yoetz_session_id, refreshed.yoetz_writer_id) == (session_id, writer_id)
    diagnostics_path = state / "observation" / "hook-diagnostics.jsonl"
    assert not diagnostics_path.exists() or "status_workspace" not in (diagnostics_path.read_text())


@pytest.mark.parametrize(
    ("reason_code", "kind"),
    [
        ("repository_identity_required", "workspace_unbound"),
        ("repository_identity_mismatch", "workspace_mismatch"),
    ],
)
def test_session_start_repository_fence_refusal_is_a_distinct_diagnostic(
    tmp_path: Path, reason_code: str, kind: str
) -> None:
    """A fence refusal keeps the live mapping and never advises a re-attach (#578)."""

    import uuid

    from finishup.adapters.integrations.codex_lifecycle import (
        load_mapping,
        mapping_from_start_ids,
        store_mapping,
    )
    from finishup.cli import hooks as hooks_module
    from finishup.protocol.ids import IdKind, new_id
    from finishup.protocol.models import OperationFailureModel

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=f"fence-{kind}",
            yoetz_task_id=new_id(IdKind.TASK),
            yoetz_session_id=new_id(IdKind.SESSION),
            yoetz_writer_id=new_id(IdKind.WRITER),
            last_frontier="0:genesis",
        ),
        _state=tmp_path,
    )
    failure = OperationFailureModel.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "ok": False,
            "error": {
                "code": "SESSION_CONFLICT",
                "message": "The requested task attachment conflicts.",
                "retryable": False,
                "correlation_id": f"err_{uuid.uuid4()}",
                "safe_details": {"reason_code": reason_code},
            },
        }
    )

    class _Result:
        root = failure

    class _Client:
        async def status(self, request: object, *, deadline_ms: int | None = None) -> object:
            del request, deadline_ms
            return _Result()

        async def observation_ingest(self, body: object, *, deadline_ms: int) -> object:
            del body, deadline_ms
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object) -> _Client:
        return _Client()

    out = io.BytesIO()
    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {"session_id": f"fence-{kind}", "hook_event_name": "SessionStart", "source": "resume"}
        ).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )
    assert code == 0
    context = json.loads(out.getvalue().decode())["hookSpecificOutput"]["additionalContext"]
    expected = (
        hooks_module._WORKSPACE_UNBOUND_CONTEXT  # pyright: ignore[reportPrivateUsage]
        if kind == "workspace_unbound"
        else hooks_module._WORKSPACE_MISMATCH_CONTEXT  # pyright: ignore[reportPrivateUsage]
    )
    assert context.startswith(expected)
    assert "mode=attach" not in context
    assert load_mapping(f"fence-{kind}", _state=tmp_path) is not None
    diagnostics = (tmp_path / "observation" / "hook-diagnostics.jsonl").read_text()
    assert f'"reason":"status_{kind}"' in diagnostics
    # The companion row names the probe's locator source (#659): this hook passed an explicit
    # consented workspace, so the refusal is the daemon's, not a missing locator.
    assert '"reason":"locator_source_explicit"' in diagnostics
    assert "mapping_stale" not in diagnostics


def test_malformed_stdin_exits_zero(tmp_path: Path) -> None:
    code = handle_observe(
        event_name="Stop",
        stdin_bytes=b"{not-json",
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0


def _drain_envelope(store: LocalObservationStore, session: str, identity: str, ordinal: int):
    payload = {
        "session_id": session,
        "hook_event_name": "PostToolUse",
        "tool_name": "shell",
        "correlation_id": f"corr-{ordinal}",
        "exit_status": 1,
    }
    commitment = store.session_commitment(session)
    return map_hook_payload_to_envelope(
        "PostToolUse",
        payload,
        session_commitment=commitment,
        event_ordinal=ordinal,
        key_material=store.key_material(),
    )


@pytest.mark.anyio
async def test_drain_quarantines_terminal_head_and_delivers_next_row(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "sess-drain")
    perm = _drain_envelope(store, "sess-drain", "hook:perm", 1)
    retry = _drain_envelope(store, "sess-drain", "hook:retry", 2)
    store.enqueue_outbox(workspace, "sess-drain", perm)
    store.enqueue_outbox(workspace, "sess-drain", retry)
    assert store.pending_outbox_count(workspace) == 2
    calls = 0

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            nonlocal calls
            del deadline_ms
            del body
            calls += 1
            if calls == 1:
                result = ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.LEDGER_REJECTED.value,
                    None,
                )
            else:
                result = ObservationIngestResult(
                    ObservationIngestDisposition.DUPLICATE,
                    None,
                    None,
                )
            return observation_ingest_result_to_json(result)

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    await observe_hooks_module._drain_outbox(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="sess-drain",
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
    )

    # Permanent -> quarantined (never dropped); the next lane row still delivers.
    assert store.quarantined_count(workspace) == 1
    assert store.list_quarantine(workspace)[0][1].source_identity == perm.source_identity
    await observe_hooks_module._drain_outbox(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="sess-drain",
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
    )
    assert calls == 2
    assert store.list_pending_outbox(workspace) == ()
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.LEDGER_REJECTED.value in status.gaps
    assert ObservationGapCode.OUTBOX_QUARANTINED.value in status.gaps
    assert ObservationGapCode.SERVICE_UNAVAILABLE.value not in status.gaps
    diagnostics = (tmp_path / "observation/hook-diagnostics.jsonl").read_text()
    assert '"reason":"ledger_rejected"' in diagnostics
    assert '"reason":"service_unavailable"' not in diagnostics


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("control_reason", "retryable", "expected"),
    [
        ("frame_invalid", False, "control_frame_invalid"),
        ("service_unavailable", True, "control_service_unavailable"),
        ("vault_locked", False, "control_vault_locked"),
    ],
)
async def test_service_ingest_preserves_control_error_retryability(
    tmp_path: Path,
    control_reason: str,
    retryable: bool,
    expected: str,
) -> None:
    """#540: transport failures do not make terminal control errors immortal."""

    from finishup.ports.control import ControlError

    store = LocalObservationStore(_state=tmp_path)
    envelope = _drain_envelope(store, "control-error", "hook:control-error", 1)

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            raise ControlError(control_reason, retryable=retryable)

    result = await observe_hooks_module._try_service_ingest(  # pyright: ignore[reportPrivateUsage]
        Client(),  # type: ignore[arg-type]
        "control-error",
        envelope,
        deadline_ms=100,
    )

    assert result.disposition is ObservationIngestDisposition.REJECTED
    assert result.reason == expected


@pytest.mark.anyio
async def test_drain_is_round_robin_across_all_workspace_sessions(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    for session in ("current", "recovered"):
        store.bind_codex_session(workspace, session)
        for ordinal in (1, 2):
            store.enqueue_outbox(
                workspace,
                session,
                _drain_envelope(store, session, f"hook:{session}:{ordinal}", ordinal),
            )
    calls: list[str] = []

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del deadline_ms
            calls.append(body["codex_session_id"])  # type: ignore[index]
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="current",
        connect=connect,  # type: ignore[arg-type]
        monotonic=lambda: 0.0,
    )
    assert calls == ["current", "recovered", "current", "recovered"]
    assert store.pending_outbox_count(workspace) == 0


@pytest.mark.anyio
async def test_drain_preflight_failure_skips_rows_and_records_diagnostic(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "preflight")
    store.enqueue_outbox(workspace, "preflight", _drain_envelope(store, "preflight", "x", 1))

    async def unavailable(_kind: object):
        raise RuntimeError("offline")

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="preflight",
        connect=unavailable,
        _state=tmp_path,
    )
    assert store.list_pending_outbox_rows(workspace)[0].attempts == 0
    diagnostics = (tmp_path / "observation/hook-diagnostics.jsonl").read_text()
    assert '"reason":"drain_connect_failed"' in diagnostics


@pytest.mark.anyio
async def test_drain_empty_outbox_never_connects_or_records_diagnostics(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "idle")
    connects: list[object] = []

    async def recording_connect(kind: object):
        connects.append(kind)
        raise RuntimeError("offline")

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="idle",
        connect=recording_connect,
        _state=tmp_path,
    )
    assert connects == []
    assert not (tmp_path / "observation/hook-diagnostics.jsonl").exists()


@pytest.mark.anyio
async def test_drain_budget_stops_without_advancing_unfinished_row(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "budget")
    store.enqueue_outbox(workspace, "budget", _drain_envelope(store, "budget", "x", 1))

    class SlowClient:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            await asyncio.sleep(1)

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return SlowClient()

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="budget",
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
        budget_seconds=0.01,
    )
    assert store.list_pending_outbox_rows(workspace)[0].attempts == 0
    diagnostics = (tmp_path / "observation/hook-diagnostics.jsonl").read_text()
    assert '"reason":"drain_budget_exhausted"' in diagnostics


@pytest.mark.anyio
async def test_drain_timeout_after_commit_replays_and_acknowledges_pending_row(
    tmp_path: Path,
) -> None:
    """#539: client timeout loses only the reply, not replayability."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session_id = "committed-timeout"
    store.bind_codex_session(workspace, session_id)
    envelope = _drain_envelope(store, session_id, "hook:committed-timeout", 1)
    store.enqueue_outbox(workspace, session_id, envelope)
    calls = 0
    committed = False

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            nonlocal calls, committed
            del deadline_ms
            calls += 1
            if calls == 1:
                assert body["content_chunks"]  # type: ignore[index]
                committed = True
                await asyncio.sleep(1)
                raise AssertionError("the hook deadline must cancel the lost reply")
            assert committed is True
            assert "content_chunks" not in body  # type: ignore[operator]
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    chunk = ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        "corr-1",
        f"hmac-sha256:{'12' * 32}",
        "text/plain",
        0,
        1,
        b"captured output",
    )
    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id=session_id,
        connect=connect,  # type: ignore[arg-type]
        content_by_source_identity={envelope.source_identity: (chunk,)},
        _state=tmp_path,
        budget_seconds=0.01,
    )
    assert store.list_pending_outbox_rows(workspace)[0].attempts == 0

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id=session_id,
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
        budget_seconds=1.0,
    )
    assert calls == 2
    assert store.list_pending_outbox_rows(workspace) == ()


@pytest.mark.anyio
async def test_native_content_priority_drains_fresh_row_after_same_session_prefix(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session_id = "native-content-priority"
    store.bind_codex_session(workspace, session_id)
    other_session_id = "native-content-other"
    store.bind_codex_session(workspace, other_session_id)
    prefix = [
        _drain_envelope(store, session_id, f"hook:prefix-{index}", index) for index in range(1, 5)
    ]
    target = _drain_envelope(store, session_id, "hook:native-target", 5)
    tail = _drain_envelope(store, session_id, "hook:tail", 6)
    other = _drain_envelope(store, other_session_id, "hook:other", 1)
    for envelope in (*prefix, target, tail):
        store.enqueue_outbox(workspace, session_id, envelope)
    # The older session's row is deliberately appended through its own lane.
    store.enqueue_outbox(workspace, other_session_id, other)
    seen: list[object] = []

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del deadline_ms
            seen.append(body)
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object) -> Client:
        return Client()

    chunk = ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        "hook:native-target:tool-output",
        target.cursor.last_source_commitment,
        "text/plain",
        0,
        1,
        b"authorized native output",
    )
    await observe_hooks_module._drain_outbox(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id=session_id,
        connect=connect,  # type: ignore[arg-type]
        content_by_source_identity={target.source_identity: (chunk,)},
        content_capture_profile="claude-code-ordinary-observation-v1",
        priority_source_identity=target.source_identity,
        budget_seconds=1.0,
        _state=tmp_path,
    )

    assert len(seen) == 7
    delivered_sources = [
        cast(Mapping[str, object], cast(Mapping[str, object], body)["envelope"])["source_identity"]
        for body in seen
    ]
    assert delivered_sources[:5] == [item.source_identity for item in (*prefix, target)]
    assert set(delivered_sources[5:]) == {tail.source_identity, other.source_identity}
    target_body = next(
        cast(Mapping[str, object], body)
        for body in seen
        if cast(Mapping[str, object], body).get("content_chunks")
    )
    assert target_body["content_chunks"]
    assert store.list_pending_outbox_rows(workspace) == ()
    assert (
        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
        not in store.status(ObservationStatusQuery(workspace)).gaps
    )


@pytest.mark.anyio
async def test_drain_probes_a_mapping_missing_session_once_per_pass(tmp_path: Path) -> None:
    """#211's recurrence tax: a dead-session backlog must not eat the drain budget.

    mapping_missing is session-scoped and cannot heal mid-pass, so one
    rejection retires the whole session for the rest of the pass while other
    sessions still deliver.
    """

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    for session, count in (("dead", 5), ("healthy", 2)):
        store.bind_codex_session(workspace, session)
        for ordinal in range(1, count + 1):
            store.enqueue_outbox(
                workspace, session, _drain_envelope(store, session, f"hook:{session}", ordinal)
            )

    attempts: list[str] = []

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del deadline_ms
            session = str(body["codex_session_id"])  # type: ignore[index]
            attempts.append(session)
            if session == "dead":
                return observation_ingest_result_to_json(
                    ObservationIngestResult(
                        ObservationIngestDisposition.REJECTED,
                        ObservationGapCode.MAPPING_MISSING.value,
                        None,
                    )
                )
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="dead",
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
        monotonic=lambda: 0.0,
    )
    assert attempts.count("dead") == 1, "a mapping_missing session must be probed once per pass"
    assert attempts.count("healthy") == 2, "healthy sessions must still deliver in the same pass"
    remaining = store.list_pending_outbox_rows(workspace)
    assert {row.codex_session_id for row in remaining} == {"dead"}
    assert len(remaining) == 5
    # Retired siblings carry the shared cause so `observe status` reports
    # mapping_missing=5, never a misleading not_attempted.
    assert all(row.last_reason == ObservationGapCode.MAPPING_MISSING.value for row in remaining)


@pytest.mark.anyio
async def test_drain_quarantines_mapping_missing_rows_of_an_ended_session(tmp_path: Path) -> None:
    """A session that ended unmapped has no future; its rows retire terminally (#275)."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    ended_commitment = store.bind_codex_session(workspace, "ended")
    for ordinal in (1, 2):
        store.enqueue_outbox(
            workspace, "ended", _drain_envelope(store, "ended", "hook:ended", ordinal)
        )
    store.note_session_end(workspace, ended_commitment)

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            return observation_ingest_result_to_json(
                ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.MAPPING_MISSING.value,
                    None,
                )
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    with acquire_session_lock("ended", _state=tmp_path) as owned:
        assert owned is True
        await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
            store,
            workspace_commitment=workspace,
            codex_session_id="ended",
            connect=connect,  # type: ignore[arg-type]
            _state=tmp_path,
        )

    assert len(store.list_pending_outbox_rows(workspace)) == 2
    assert store.quarantined_count(workspace) == 0

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="ended",
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
    )
    assert store.list_pending_outbox_rows(workspace) == ()
    assert store.quarantined_count(workspace) == 2
    assert {entry[2] for entry in store.list_quarantine(workspace)} == {
        ObservationGapCode.MAPPING_MISSING.value
    }


def test_later_hook_recovers_pending_mapping_before_delivery(tmp_path: Path) -> None:
    """A deferred start mapping is replayed before a later hook drains its lane (#509)."""

    from finishup.adapters.integrations.codex_lifecycle import (
        load_mapping,
        mapping_from_start_ids,
        queue_mapping_store,
    )
    from finishup.cli.hooks import recover_pending_start_mapping
    from finishup.domain.observation import ObservationSource
    from finishup.protocol.ids import IdKind, new_id

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    codex_session_id = "claude:pending-recovery"
    mapping = mapping_from_start_ids(
        codex_session_id=codex_session_id,
        yoetz_task_id=new_id(IdKind.TASK),
        yoetz_session_id=new_id(IdKind.SESSION),
        yoetz_writer_id=new_id(IdKind.WRITER),
        last_frontier=None,
    )

    # Model a cancelled/contended SessionStart: the valid result is queued
    # while the lifecycle lock is held, but no mapping has been materialized.
    with acquire_session_lock(codex_session_id, _state=tmp_path) as owned:
        assert owned is True
        queue_mapping_store(mapping, _state=tmp_path)
        recovery = recover_pending_start_mapping(codex_session_id, _state=tmp_path)
        assert recovery.applied is False
        assert recovery.pending is True
        assert load_mapping(codex_session_id, _state=tmp_path) is None

    store.bind_codex_session(workspace, codex_session_id)
    store.enqueue_outbox(
        workspace,
        codex_session_id,
        _drain_envelope(store, codex_session_id, "hook:pending-recovery", 1),
    )
    delivered: list[str] = []

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del deadline_ms
            session = str(body["codex_session_id"])  # type: ignore[index]
            if load_mapping(session, _state=tmp_path) is None:
                return observation_ingest_result_to_json(
                    ObservationIngestResult(
                        ObservationIngestDisposition.REJECTED,
                        ObservationGapCode.MAPPING_MISSING.value,
                        None,
                    )
                )
            delivered.append(session)
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    out = io.BytesIO()
    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {
                    "session_id": codex_session_id,
                    "hook_event_name": "PostToolUse",
                    "tool_name": "shell",
                }
            ).encode(),
            stdout=out,
            workspace=str(tmp_path),
            _state=tmp_path,
            connect=connect,  # type: ignore[arg-type]
            source=ObservationSource.CLAUDE_HOOK,
        )
        == 0
    )

    assert load_mapping(codex_session_id, _state=tmp_path) == mapping
    assert delivered == [codex_session_id, codex_session_id]
    assert store.list_pending_outbox_rows(workspace) == ()
    assert store.list_quarantine(workspace) == ()
    diagnostics_path = tmp_path / "observation" / "hook-diagnostics.jsonl"
    if diagnostics_path.exists():
        assert '"reason":"mapping_missing"' not in diagnostics_path.read_text()


def test_later_hook_defers_delivery_while_pending_mapping_lock_is_busy(
    tmp_path: Path,
) -> None:
    """A fenced pending mapping keeps the row local until its session lock clears (#509)."""

    from finishup.adapters.integrations.codex_lifecycle import (
        load_mapping,
        mapping_from_start_ids,
        queue_mapping_store,
    )
    from finishup.protocol.ids import IdKind, new_id

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    codex_session_id = "claude:busy-pending-recovery"
    mapping = mapping_from_start_ids(
        codex_session_id=codex_session_id,
        yoetz_task_id=new_id(IdKind.TASK),
        yoetz_session_id=new_id(IdKind.SESSION),
        yoetz_writer_id=new_id(IdKind.WRITER),
        last_frontier=None,
    )
    store.bind_codex_session(workspace, codex_session_id)
    store.enqueue_outbox(
        workspace,
        codex_session_id,
        _drain_envelope(store, codex_session_id, "hook:busy-pending", 1),
    )
    service_connects: list[str] = []

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        service_connects.append("connect")
        return Client()

    payload = json.dumps(
        {
            "session_id": codex_session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "shell",
        }
    ).encode()
    with acquire_session_lock(codex_session_id, _state=tmp_path) as owned:
        assert owned is True
        queue_mapping_store(mapping, _state=tmp_path)
        assert (
            handle_observe(
                event_name="PostToolUse",
                stdin_bytes=payload,
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path,
                connect=connect,  # type: ignore[arg-type]
                source=ObservationSource.CLAUDE_HOOK,
            )
            == 0
        )
        assert service_connects == []
        assert load_mapping(codex_session_id, _state=tmp_path) is None
        assert store.list_pending_outbox_rows(workspace)
        assert store.list_quarantine(workspace) == ()

    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=payload,
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            connect=connect,  # type: ignore[arg-type]
            source=ObservationSource.CLAUDE_HOOK,
        )
        == 0
    )
    assert service_connects == ["connect"]
    assert load_mapping(codex_session_id, _state=tmp_path) == mapping
    assert store.list_pending_outbox_rows(workspace) == ()
    assert store.list_quarantine(workspace) == ()


def test_pending_child_mapping_recovery_is_exact_session_scoped(tmp_path: Path) -> None:
    """A child alias cannot overwrite its parent's route or frontier (#509)."""

    from finishup.adapters.integrations.codex_lifecycle import (
        load_mapping,
        mapping_from_start_ids,
        queue_mapping_store,
        store_mapping,
    )
    from finishup.cli.hooks import recover_pending_start_mapping
    from finishup.protocol.ids import IdKind, new_id

    parent_session = "claude:parent-alias"
    child_session = "claude:parent-alias:child"
    parent = mapping_from_start_ids(
        codex_session_id=parent_session,
        yoetz_task_id=new_id(IdKind.TASK),
        yoetz_session_id=new_id(IdKind.SESSION),
        yoetz_writer_id=new_id(IdKind.WRITER),
        last_frontier="7:sha256:" + "a" * 64,
    )
    child = mapping_from_start_ids(
        codex_session_id=child_session,
        yoetz_task_id=new_id(IdKind.TASK),
        yoetz_session_id=new_id(IdKind.SESSION),
        yoetz_writer_id=new_id(IdKind.WRITER),
        last_frontier="2:sha256:" + "b" * 64,
    )
    store_mapping(parent, _state=tmp_path)
    with acquire_session_lock(child_session, _state=tmp_path) as owned:
        assert owned is True
        queue_mapping_store(child, _state=tmp_path)

    recovery = recover_pending_start_mapping(child_session, _state=tmp_path)
    assert recovery.applied is True
    assert recovery.pending is False
    assert load_mapping(child_session, _state=tmp_path) == child
    assert load_mapping(parent_session, _state=tmp_path) == parent


def test_unmapped_session_reattempts_auto_attach_on_turn_events_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missed SessionStart attach is retried on turn-boundary events, never per tool call (#275)."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    calls: list[str] = []

    async def fake_auto_start(codex_session_id: str, **_kwargs: object) -> object | None:
        calls.append(codex_session_id)
        return observe_hooks_module.AutoAttachOutcome(None, "service_unavailable")

    monkeypatch.setattr(observe_hooks_module, "_try_auto_start", fake_auto_start)

    async def connect(_kind: object):
        return _InstantAckClient()

    code = handle_observe(
        event_name="UserPromptSubmit",
        stdin_bytes=json.dumps(
            {"session_id": "late-attach", "hook_event_name": "UserPromptSubmit"}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )
    assert code == 0
    assert calls == ["late-attach"]
    diagnostics = (tmp_path / "observation/hook-diagnostics.jsonl").read_text()
    assert '"reason":"auto_attach_retry_failed"' in diagnostics
    # The typed cause lands next to the path marker (#459).
    assert '"reason":"service_unavailable"' in diagnostics

    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "late-attach",
                "tool_name": "shell",
                "correlation_id": "attach-1",
                "exit_status": 0,
            }
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )
    assert code == 0
    assert calls == ["late-attach"], "tool-call storms must never re-attempt auto-attach"


def test_claude_session_start_auto_attach_preserves_the_harness_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    calls: list[tuple[str, str, str | None]] = []

    async def fake_auto_start(
        codex_session_id: str,
        *,
        _state: Path | None,
        harness_id: str = "codex",
        workspace_locator: str | None,
        recovery_mapping: LifecycleMapping | None = None,
        connect: object = None,
        _session_lock_owned: bool = False,
    ) -> object | None:
        del _state, recovery_mapping, connect, _session_lock_owned
        calls.append((codex_session_id, harness_id, workspace_locator))
        return observe_hooks_module.AutoAttachOutcome(None, "service_unavailable")

    monkeypatch.setattr(observe_hooks_module, "_try_auto_start", fake_auto_start)

    async def connect(_kind: object):
        return _InstantAckClient()

    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {"session_id": "claude:auto-attach", "hook_event_name": "SessionStart"}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
        source=ObservationSource.CLAUDE_HOOK,
    )

    assert code == 0
    assert calls == [("claude:auto-attach", "claude", str(tmp_path.resolve()))]


def test_auto_attach_retry_exception_records_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    async def fail_auto_start(codex_session_id: str, **_kwargs: object) -> object | None:
        del codex_session_id
        raise TimeoutError("bounded auto-attach timeout")

    monkeypatch.setattr(observe_hooks_module, "_try_auto_start", fail_auto_start)

    async def connect(_kind: object):
        return _InstantAckClient()

    code = handle_observe(
        event_name="UserPromptSubmit",
        stdin_bytes=json.dumps(
            {"session_id": "late-attach-timeout", "hook_event_name": "UserPromptSubmit"}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert code == 0
    diagnostics = (tmp_path / "observation/hook-diagnostics.jsonl").read_text()
    assert diagnostics.count('"reason":"auto_attach_retry_failed"') == 1
    assert diagnostics.count('"reason":"timeout"') == 1


def test_session_reason_stamping_preserves_a_rows_observed_cause(tmp_path: Path) -> None:
    """Skipped siblings inherit the cause without rewriting a prior real attempt."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "mixed-reasons")
    for ordinal in (1, 2):
        store.enqueue_outbox(
            workspace,
            "mixed-reasons",
            _drain_envelope(store, "mixed-reasons", "hook:mixed-reasons", ordinal),
        )
    attempted, skipped = store.list_pending_outbox_rows(workspace)
    assert (
        store.bump_outbox_row_attempt(
            workspace,
            attempted,
            reason=ObservationGapCode.SERVICE_UNAVAILABLE.value,
        )
        is not None
    )

    stamped = store.note_outbox_session_reason(
        workspace,
        "mixed-reasons",
        ObservationGapCode.MAPPING_MISSING.value,
    )

    assert stamped == 1
    attempted_after, skipped_after = store.list_pending_outbox_rows(workspace)
    assert attempted_after.last_reason == ObservationGapCode.SERVICE_UNAVAILABLE.value
    assert skipped_after.row_identity == skipped.row_identity
    assert skipped_after.last_reason == ObservationGapCode.MAPPING_MISSING.value


@pytest.mark.anyio
async def test_drain_service_unavailable_retires_its_session_but_not_the_workspace(
    tmp_path: Path,
) -> None:
    """One poisoned session must not wedge the workspace drain — nor be reordered.

    service_unavailable is the catch-all for row-scoped failures (bundle
    contention, one malformed envelope). Other sessions keep delivering, but
    the failed row stays the head of its own lane: delivering a later row of
    the same session would advance the ingest cursor past it and destroy it
    as terminal cursor_stale (#272).
    """

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "poisoned")
    store.bind_codex_session(workspace, "healthy")
    for ordinal in (1, 2):
        store.enqueue_outbox(
            workspace, "poisoned", _drain_envelope(store, "poisoned", "hook:poisoned", ordinal)
        )
        store.enqueue_outbox(
            workspace, "healthy", _drain_envelope(store, "healthy", "hook:healthy", ordinal)
        )
    poisoned_head = store.list_pending_outbox_rows(workspace, codex_session_id="poisoned")[0]
    poisoned = poisoned_head.envelope.source_identity

    attempts: list[str] = []

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del deadline_ms
            identity = str(body["envelope"]["source_identity"])  # type: ignore[index]
            attempts.append(identity)
            if identity == poisoned:
                return observation_ingest_result_to_json(
                    ObservationIngestResult(
                        ObservationIngestDisposition.REJECTED,
                        ObservationGapCode.SERVICE_UNAVAILABLE.value,
                        None,
                    )
                )
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="poisoned",
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
        # This test owns ordering/fairness, not the 200 ms hook deadline. Deadline
        # exhaustion is covered by the dedicated shared-budget tests below.
        budget_seconds=30.0,
    )
    assert attempts.count(poisoned) == 1, "the failed head is probed once, never stepped over"
    assert len(attempts) == 3, "the healthy session still delivers fully"
    remaining = store.list_pending_outbox_rows(workspace)
    assert [row.codex_session_id for row in remaining] == ["poisoned", "poisoned"]
    assert [row.envelope.cursor.event_position for row in remaining] == [1, 2]
    assert [row.last_reason for row in remaining] == [
        ObservationGapCode.SERVICE_UNAVAILABLE.value,
        ObservationGapCode.SERVICE_UNAVAILABLE.value,
    ]


@pytest.mark.anyio
async def test_drain_budget_starts_after_a_slow_connect(
    tmp_path: Path,
) -> None:
    """tb4n1 B4: the connect has its own preflight bound; delivery gets its whole budget.

    Before, a 0.9 s connect consumed the shared clock, so 94% of hooks recorded
    ``drain_budget_exhausted`` without delivering a single row.
    """

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "slow-connect")
    store.enqueue_outbox(workspace, "slow-connect", _drain_envelope(store, "slow-connect", "x", 1))

    clock = {"now": 0.0}

    async def slow_connect(_kind: object):
        clock["now"] += 0.9  # slower than the whole 0.75s SessionEnd budget
        return _InstantAckClient()

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="slow-connect",
        connect=slow_connect,  # type: ignore[arg-type]
        _state=tmp_path,
        budget_seconds=0.75,
        monotonic=lambda: clock["now"],
    )
    assert store.pending_outbox_count(workspace) == 0
    diagnostics_path = tmp_path / "observation/hook-diagnostics.jsonl"
    if diagnostics_path.exists():
        assert '"reason":"drain_budget_exhausted"' not in diagnostics_path.read_text()


@pytest.mark.anyio
async def test_absolute_deadline_clamps_the_connect_and_the_delivery(
    tmp_path: Path,
) -> None:
    """A pass deadline (the Stop pass keeps the closure gate's reserve) bounds both stages."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "deadline")
    store.enqueue_outbox(workspace, "deadline", _drain_envelope(store, "deadline", "x", 1))
    clock = {"now": 0.0}
    connects = 0

    async def connect(_kind: object):
        nonlocal connects
        connects += 1
        return _InstantAckClient()

    owned = await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="deadline",
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
        budget_seconds=2.5,
        monotonic=lambda: clock["now"],
        deadline=0.0,
    )
    assert owned is True
    assert connects == 0, "an expired deadline never opens a connection"
    assert store.pending_outbox_count(workspace) == 1
    diagnostic = (tmp_path / "observation/hook-diagnostics.jsonl").read_text()
    assert '"reason":"drain_budget_exhausted"' in diagnostic


@pytest.mark.anyio
async def test_workspace_global_rejection_ends_the_pass(tmp_path: Path) -> None:
    """vault_locked cannot heal mid-pass, so one rejection ends the drain."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    for session in ("one", "two"):
        store.bind_codex_session(workspace, session)
        for ordinal in (1, 2):
            store.enqueue_outbox(
                workspace, session, _drain_envelope(store, session, f"hook:{session}", ordinal)
            )

    attempts = 0

    class LockedClient:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            nonlocal attempts
            attempts += 1
            return observation_ingest_result_to_json(
                ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.VAULT_LOCKED.value,
                    None,
                )
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return LockedClient()

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="one",
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
    )
    assert attempts == 1, "a workspace-global rejection must end the pass after one probe"
    assert store.pending_outbox_count(workspace) == 4


@pytest.mark.anyio
async def test_drain_lease_prevents_concurrent_hooks_from_double_draining(
    tmp_path: Path,
) -> None:
    """#209 made hooks genuinely concurrent; only one may drain at a time."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "leased")
    store.enqueue_outbox(workspace, "leased", _drain_envelope(store, "leased", "x", 1))

    connects: list[object] = []

    async def recording_connect(kind: object):
        connects.append(kind)
        raise RuntimeError("offline")

    with store.drain_lease(workspace) as owned:
        assert owned is True
        # A second store instance (another hook process) must lose the lease
        # and skip the drain entirely — no connect. Losing to a live owner is
        # designed coordination, so no failure-shaped diagnostic is recorded
        # (#351): one row per contending hook buried genuine failures.
        other = LocalObservationStore(_state=tmp_path)
        await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
            other,
            workspace_commitment=workspace,
            codex_session_id="leased",
            connect=recording_connect,
            _state=tmp_path,
        )
    assert connects == []
    diagnostics = tmp_path / "observation/hook-diagnostics.jsonl"
    if diagnostics.exists():
        assert "drain_lease_contended" not in diagnostics.read_text(encoding="utf-8")


@pytest.mark.anyio
async def test_budget_expiry_after_delivery_progress_is_a_silent_yield(tmp_path: Path) -> None:
    """A bounded slice that moved backlog and then yielded is working as designed (#351).

    drain_budget_exhausted remains reserved for a pass that timed out before
    any progress; a capacity yield to the service sweeper is not a failure.
    """

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "yield")
    for ordinal in (1, 2, 3):
        store.enqueue_outbox(
            workspace, "yield", _drain_envelope(store, "yield", "hook:yield", ordinal)
        )

    clock = {"now": 0.0}

    class OneThenSlowClient:
        def __init__(self) -> None:
            self.calls = 0

        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            self.calls += 1
            # First row delivers instantly; afterwards the budget is exhausted.
            clock["now"] += 0.05 if self.calls == 1 else 1.0
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return OneThenSlowClient()

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="yield",
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
        budget_seconds=0.2,
        monotonic=lambda: clock["now"],
    )
    assert store.pending_outbox_count(workspace) == 1, "two rows delivered before the yield"
    diagnostics = tmp_path / "observation/hook-diagnostics.jsonl"
    if diagnostics.exists():
        assert '"reason":"drain_budget_exhausted"' not in diagnostics.read_text()


@pytest.mark.anyio
async def test_operation_pending_deferral_keeps_row_without_gap_or_diagnostic(
    tmp_path: Path,
) -> None:
    """An ADR-022 check-barrier deferral is expected back-pressure, not failure (#351)."""

    from finishup.domain.observation import OBSERVATION_BACKPRESSURE_REASON

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "deferred")
    for ordinal in (1, 2):
        store.enqueue_outbox(
            workspace, "deferred", _drain_envelope(store, "deferred", "hook:deferred", ordinal)
        )

    attempts = 0

    class BarrierClient:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            nonlocal attempts
            attempts += 1
            return observation_ingest_result_to_json(
                ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    OBSERVATION_BACKPRESSURE_REASON,
                    None,
                )
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return BarrierClient()

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="deferred",
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
    )
    # The deferred head retires its lane for the pass; both rows stay pending
    # with the honest annotation, and neither a coverage gap nor a hook
    # diagnostic reports the designed barrier as a failure.
    assert attempts == 1
    pending = store.list_pending_outbox_rows(workspace)
    assert [row.last_reason for row in pending] == [
        OBSERVATION_BACKPRESSURE_REASON,
        OBSERVATION_BACKPRESSURE_REASON,
    ]
    status = store.status(ObservationStatusQuery(workspace))
    assert OBSERVATION_BACKPRESSURE_REASON not in status.gaps
    assert ObservationGapCode.SERVICE_UNAVAILABLE.value not in status.gaps
    diagnostics = tmp_path / "observation/hook-diagnostics.jsonl"
    if diagnostics.exists():
        assert OBSERVATION_BACKPRESSURE_REASON not in diagnostics.read_text()


def test_drain_lease_refuses_a_symlink_lock_file(tmp_path: Path) -> None:
    """A project-local symlink cannot redirect the advisory-lock target."""

    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("host has no O_NOFOLLOW")

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    target = tmp_path / "redirected-lock-target"
    target.write_text("unchanged", encoding="utf-8")
    digest = workspace.removeprefix("hmac-sha256:")
    lock_path = tmp_path / "observation" / f".drain-{digest}.lock"
    lock_path.symlink_to(target)

    with pytest.raises(OSError):
        with store.drain_lease(workspace):
            raise AssertionError("a symlinked drain lease must not be acquired")
    assert target.read_text(encoding="utf-8") == "unchanged"


def _populate_realistic_store(
    store: LocalObservationStore,
    workspace: str,
    session: str,
    *,
    envelopes: int = 250,
    pending: int = 60,
    quarantined: int = 199,
) -> None:
    """Grow one workspace state to the shape the 2026-08-12 regression ran at.

    Hook cost is store-size-dependent, so latency guards against a small
    fixture pass trivially (#209). The live store that measured 3.06-4.89s
    held 256 envelopes, 73 pending rows, and 199 quarantine entries in a
    ~384KB file; this builds the same order of magnitude in one save.
    """

    state = store._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert state.envelopes is not None
    assert state.pending_outbox is not None
    assert state.quarantine is not None
    assert state.dedup is not None
    from datetime import UTC, datetime

    from finishup.adapters.integrations.observation_local import (
        ObservationOutboxRow,
        _dedup_key,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.domain.values import timestamp_from_datetime

    quarantined_at = timestamp_from_datetime(datetime.now(UTC).replace(microsecond=0))
    for ordinal in range(1, envelopes + pending + quarantined + 1):
        envelope = _drain_envelope(store, session, f"hook:bulk:{ordinal}", ordinal)
        if ordinal <= envelopes:
            state.envelopes.append(envelope)
            state.dedup.add(_dedup_key(workspace, envelope))
        elif ordinal <= envelopes + pending:
            state.pending_outbox.append(
                ObservationOutboxRow(codex_session_id=session, envelope=envelope)
            )
        else:
            state.quarantine.append((session, envelope, "service_unavailable", quarantined_at))
    store._save(workspace, state)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


class _InstantAckClient:
    async def observation_ingest(self, body: object, *, deadline_ms: int):
        del body, deadline_ms
        # DUPLICATE routes to ACKNOWLEDGE without needing a service cursor.
        return observation_ingest_result_to_json(
            ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
        )

    async def close(self) -> None:
        return None


_START_IDS = {
    "task_id": "tsk_1b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5b",
    "session_id": "ses_1b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5c",
    "writer_id": "wri_1b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5d",
}
_SUCCESSOR_IDS = {
    "task_id": _START_IDS["task_id"],
    "session_id": "ses_2b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5c",
    "writer_id": "wri_2b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5d",
}


def _seed_legacy_cross_workspace_binding(
    store: LocalObservationStore,
    workspace_commitment: str,
    codex_session_id: str,
) -> None:
    """Model an already-persisted ambiguous route without weakening admission."""

    with pytest.raises(PublicOperationError) as raised:
        store.bind_codex_session(workspace_commitment, codex_session_id)
    assert raised.value.code is PublicErrorCode.SESSION_CONFLICT

    state = store._load(workspace_commitment)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert state.session_workspaces is not None
    assert state.codex_session_bindings is not None
    session_commitment = store.session_commitment(codex_session_id)
    state.session_workspaces[session_commitment] = workspace_commitment
    state.codex_session_bindings[codex_session_id] = session_commitment
    store._save(workspace_commitment, state)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


class _StartOkClient(_InstantAckClient):
    """A start client that answers like the service and records the exact request."""

    def __init__(self, sink: list[object] | None = None) -> None:
        self.requests: list[object] = [] if sink is None else sink

    async def start(self, request: object, *, deadline_ms: int | None = None) -> object:
        del deadline_ms
        self.requests.append(request)
        return SimpleNamespace(
            ok=True,
            frontier=SimpleNamespace(sequence="3", head_digest="sha256:" + "a" * 64),
            **_START_IDS,
        )


class _StartFailureClient(_InstantAckClient):
    def __init__(self, code: PublicErrorCode) -> None:
        self.code = code
        self.requests: list[object] = []

    async def start(self, request: object, *, deadline_ms: int | None = None) -> object:
        del deadline_ms
        self.requests.append(request)
        from finishup.protocol.ids import IdKind, new_id
        from finishup.protocol.models import OperationFailureModel

        return OperationFailureModel.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "ok": False,
                "error": {
                    "code": self.code.value,
                    "message": "refused",
                    "retryable": False,
                    "correlation_id": new_id(IdKind.CORRELATION),
                },
            }
        )


class _WorkspaceConflictThenAttachClient(_InstantAckClient):
    """Model one workspace route: create once, then recover only by known session selector."""

    def __init__(
        self,
        *,
        successor_task_id: str = _START_IDS["task_id"],
        expected_session_id: str = _START_IDS["session_id"],
    ) -> None:
        self.requests: list[StartRequest] = []
        self.created = False
        self.successor_task_id = successor_task_id
        # The selector a recovery attach must carry: the predecessor's session id.
        self.expected_session_id = expected_session_id

    async def start(self, request: object, *, deadline_ms: int | None = None) -> object:
        del deadline_ms
        from finishup.protocol.ids import IdKind, new_id
        from finishup.protocol.models import OperationFailureModel

        assert isinstance(request, StartRequest)
        self.requests.append(request)
        if request.mode == "create_or_attach" and not self.created:
            self.created = True
            return SimpleNamespace(
                ok=True,
                frontier=SimpleNamespace(sequence="3", head_digest="sha256:" + "a" * 64),
                **_START_IDS,
            )
        if request.mode == "create_or_attach":
            return OperationFailureModel.model_validate(
                {
                    "protocol_version": "0.1",
                    "schema_version": "1.0.0",
                    "ok": False,
                    "error": {
                        "code": PublicErrorCode.SESSION_CONFLICT.value,
                        "message": "workspace occupied",
                        "retryable": False,
                        "correlation_id": new_id(IdKind.CORRELATION),
                        "safe_details": {"reason_code": "workspace_task_exists"},
                    },
                }
            )
        assert request.mode == "attach"
        assert request.session_id == self.expected_session_id
        return SimpleNamespace(
            ok=True,
            frontier=SimpleNamespace(sequence="4", head_digest="sha256:" + "b" * 64),
            **{**_SUCCESSOR_IDS, "task_id": self.successor_task_id},
        )


def _connector(client: object):
    async def connect(_kind: object):
        return client

    return connect


def _auto_start(
    harness_id: str,
    session: str,
    *,
    _state: Path,
    workspace_locator: str | None,
    connect: object,
    recovery_mapping: LifecycleMapping | None = None,
) -> observe_hooks_module.AutoAttachOutcome:
    return asyncio.run(
        observe_hooks_module._try_auto_start(  # pyright: ignore[reportPrivateUsage]
            session,
            _state=_state,
            harness_id=cast(Literal["claude", "codex", "cursor"], harness_id),
            workspace_locator=workspace_locator,
            recovery_mapping=recovery_mapping,
            connect=cast(observe_hooks_module.HookStartConnector, connect),
        )
    )


@pytest.mark.parametrize(
    ("harness_id", "session"),
    [("claude", "claude:auto-1"), ("codex", "codex-auto-1"), ("cursor", "cursor:auto-1")],
)
def test_auto_start_request_is_a_valid_paired_start_for_every_harness(
    tmp_path: Path, harness_id: str, session: str
) -> None:
    """The real request construction validates through StartRequest with paired refs (#459)."""

    from finishup.protocol.models import StartRequest

    client = _StartOkClient()
    locator = str(tmp_path.resolve())
    outcome = _auto_start(
        harness_id, session, _state=tmp_path, workspace_locator=locator, connect=_connector(client)
    )

    assert outcome.reason is None
    assert outcome.mapping is not None
    assert outcome.mapping.codex_session_id == session
    assert outcome.mapping.yoetz_task_id == _START_IDS["task_id"]
    assert outcome.mapping.last_frontier == "3:sha256:" + "a" * 64
    stored = observe_hooks_module.load_mapping(session, _state=tmp_path)
    assert stored == outcome.mapping

    (request,) = client.requests
    assert isinstance(request, StartRequest)
    assert request.mode == "create_or_attach"
    assert request.session_id is None
    assert request.workspace_ref == locator
    assert request.external_ref == f"{harness_id}-session:{session.removeprefix(harness_id + ':')}"
    assert request.actor.actor_id == f"yoetz:{harness_id}-observe"
    # Byte-level contract: the wire shape round-trips through the public schema.
    wire = request.model_dump(mode="json", exclude_none=True)
    assert "session_id" not in wire
    StartRequest.model_validate(wire)


def test_auto_start_without_a_workspace_locator_stops_before_any_service_call(
    tmp_path: Path,
) -> None:
    calls: list[object] = []

    async def connect(_kind: object):
        calls.append(_kind)
        raise AssertionError("no service call without a paired workspace reference")

    outcome = _auto_start(
        "codex", "unbound-1", _state=tmp_path, workspace_locator=None, connect=connect
    )
    assert outcome.mapping is None
    assert outcome.reason == "auto_attach_workspace_unbound"
    assert calls == []
    assert observe_hooks_module.load_mapping("unbound-1", _state=tmp_path) is None


@pytest.mark.parametrize(
    ("harness_id", "session"),
    [("claude", "claude:next-1"), ("codex", "codex-next-1"), ("cursor", "cursor:next-1")],
)
def test_auto_start_recovers_before_create_with_a_known_local_selector(
    tmp_path: Path, harness_id: str, session: str
) -> None:
    """#497: recovery uses the persisted selector before admission can create work."""

    prior = observe_hooks_module.mapping_from_start_ids(
        codex_session_id=f"{harness_id}:ended-1",
        yoetz_task_id=_START_IDS["task_id"],
        yoetz_session_id=_START_IDS["session_id"],
        yoetz_writer_id=_START_IDS["writer_id"],
        last_frontier="3:sha256:" + "a" * 64,
    )
    observe_hooks_module.store_mapping(prior, _state=tmp_path)
    client = _WorkspaceConflictThenAttachClient()
    client.created = True

    outcome = _auto_start(
        harness_id,
        session,
        _state=tmp_path,
        workspace_locator=str(tmp_path.resolve()),
        recovery_mapping=prior,
        connect=_connector(client),
    )

    assert outcome.reason is None
    assert outcome.mapping is not None
    assert outcome.mapping.yoetz_task_id == _START_IDS["task_id"]
    assert outcome.mapping.yoetz_session_id == _SUCCESSOR_IDS["session_id"]
    rewritten = observe_hooks_module.load_mapping(prior.codex_session_id, _state=tmp_path)
    assert rewritten is not None
    assert rewritten.yoetz_session_id == _SUCCESSOR_IDS["session_id"]
    assert rewritten.yoetz_writer_id == _SUCCESSOR_IDS["writer_id"]
    assert rewritten.last_frontier == prior.last_frontier
    (request,) = client.requests
    assert request.mode == "attach"
    assert request.session_id == _START_IDS["session_id"]
    assert request.workspace_ref == str(tmp_path.resolve())
    assert request.external_ref == f"{harness_id}-session:{session.removeprefix(harness_id + ':')}"


def test_workspace_conflict_recovery_never_selects_a_live_host_session(tmp_path: Path) -> None:
    """The recovery selector is eligible only after the prior host lifecycle ended."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    previous = "codex-live-1"
    previous_commitment = store.bind_codex_session(workspace, previous)
    observe_hooks_module.store_mapping(
        observe_hooks_module.mapping_from_start_ids(
            codex_session_id=previous,
            yoetz_task_id=_START_IDS["task_id"],
            yoetz_session_id=_START_IDS["session_id"],
            yoetz_writer_id=_START_IDS["writer_id"],
            last_frontier=None,
        ),
        _state=tmp_path,
    )

    assert (
        observe_hooks_module._scan_ended_workspace_recovery(  # pyright: ignore[reportPrivateUsage]
            store, workspace, "codex-next-1", harness_id="codex", _state=tmp_path
        ).mapping
        is None
    )

    store.note_session_end(workspace, previous_commitment)
    recovered = observe_hooks_module._scan_ended_workspace_recovery(  # pyright: ignore[reportPrivateUsage]
        store, workspace, "codex-next-1", harness_id="codex", _state=tmp_path
    ).mapping
    assert recovered is not None
    assert recovered.codex_session_id == previous


def test_auto_start_does_not_create_after_recovery_is_refused(tmp_path: Path) -> None:
    """A refused attach never falls back to creating a replacement task."""

    prior = observe_hooks_module.mapping_from_start_ids(
        codex_session_id="codex-ended-1",
        yoetz_task_id=_START_IDS["task_id"],
        yoetz_session_id=_START_IDS["session_id"],
        yoetz_writer_id=_START_IDS["writer_id"],
        last_frontier=None,
    )
    client = _StartFailureClient(PublicErrorCode.SESSION_CONFLICT)

    outcome = _auto_start(
        "codex",
        "codex-next-1",
        _state=tmp_path,
        workspace_locator=str(tmp_path.resolve()),
        recovery_mapping=prior,
        connect=_connector(client),
    )

    assert outcome.mapping is None
    assert outcome.reason == "auto_attach_conflict"
    assert len(client.requests) == 1


def test_auto_start_rejects_a_recovery_response_for_a_different_task(tmp_path: Path) -> None:
    """The private selector can authorize only the task identity already held locally."""

    prior = observe_hooks_module.mapping_from_start_ids(
        codex_session_id="codex-ended-1",
        yoetz_task_id=_START_IDS["task_id"],
        yoetz_session_id=_START_IDS["session_id"],
        yoetz_writer_id=_START_IDS["writer_id"],
        last_frontier=None,
    )
    client = _WorkspaceConflictThenAttachClient(
        successor_task_id="tsk_3b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5b"
    )
    client.created = True

    outcome = _auto_start(
        "codex",
        "codex-next-1",
        _state=tmp_path,
        workspace_locator=str(tmp_path.resolve()),
        recovery_mapping=prior,
        connect=_connector(client),
    )

    assert outcome.mapping is None
    assert outcome.reason == "auto_attach_result_invalid"
    assert observe_hooks_module.load_mapping("codex-next-1", _state=tmp_path) is None


def test_workspace_conflict_recovery_rejects_a_cross_workspace_session_binding(
    tmp_path: Path,
) -> None:
    """A host session ID seen in two workspaces is ambiguous and cannot authorize attachment."""

    store = LocalObservationStore(_state=tmp_path)
    first_locator = str((tmp_path / "first").resolve())
    second_locator = str((tmp_path / "second").resolve())
    first_workspace = store.workspace_commitment(first_locator)
    second_workspace = store.workspace_commitment(second_locator)
    store.grant_consent(first_workspace)
    store.grant_consent(second_workspace)
    previous = "codex-cross-workspace"
    first_session_commitment = store.bind_codex_session(first_workspace, previous)
    _seed_legacy_cross_workspace_binding(store, second_workspace, previous)
    store.note_session_end(first_workspace, first_session_commitment)
    observe_hooks_module.store_mapping(
        observe_hooks_module.mapping_from_start_ids(
            codex_session_id=previous,
            yoetz_task_id=_START_IDS["task_id"],
            yoetz_session_id=_START_IDS["session_id"],
            yoetz_writer_id=_START_IDS["writer_id"],
            last_frontier=None,
        ),
        _state=tmp_path,
    )

    recovered = observe_hooks_module._scan_ended_workspace_recovery(  # pyright: ignore[reportPrivateUsage]
        store,
        first_workspace,
        "codex-next-1",
        harness_id="codex",
        _state=tmp_path,
    ).mapping
    assert recovered is None


@pytest.mark.parametrize(
    ("harness_id", "previous", "successor"),
    [
        ("claude", "claude:ended-race", "claude:next-race"),
        ("codex", "codex-ended-race", "codex-next-race"),
        ("cursor", "cursor:ended-race", "cursor:next-race"),
    ],
)
def test_recovery_rejects_cross_workspace_binding_during_revalidation_for_all_hosts(
    tmp_path: Path,
    harness_id: str,
    previous: str,
    successor: str,
) -> None:
    """#605: a newly ambiguous predecessor invalidates the cached recovery scan."""

    first_locator = str((tmp_path / "first").resolve())
    second_locator = str((tmp_path / "second").resolve())
    initial_store = LocalObservationStore(_state=tmp_path)
    first_workspace = initial_store.workspace_commitment(first_locator)
    second_workspace = initial_store.workspace_commitment(second_locator)
    initial_store.grant_consent(first_workspace)
    initial_store.grant_consent(second_workspace)
    previous_commitment = initial_store.bind_codex_session(first_workspace, previous)
    initial_store.note_session_end(first_workspace, previous_commitment)
    observe_hooks_module.store_mapping(
        observe_hooks_module.mapping_from_start_ids(
            codex_session_id=previous,
            yoetz_task_id=_START_IDS["task_id"],
            yoetz_session_id=_START_IDS["session_id"],
            yoetz_writer_id=_START_IDS["writer_id"],
            last_frontier=None,
        ),
        _state=tmp_path,
    )

    class _AmbiguousOnRevalidation(LocalObservationStore):
        calls = 0

        def codex_session_lifecycles_for_workspace(
            self, workspace_commitment: str
        ) -> tuple[tuple[str, bool], ...]:
            self.calls += 1
            if self.calls == 2:
                _seed_legacy_cross_workspace_binding(self, second_workspace, previous)
            return super().codex_session_lifecycles_for_workspace(workspace_commitment)

    store = _AmbiguousOnRevalidation(_state=tmp_path)
    store.bind_codex_session(first_workspace, successor)
    client = _WorkspaceConflictThenAttachClient()
    client.created = True

    outcome = asyncio.run(
        observe_hooks_module._try_workspace_auto_start(  # pyright: ignore[reportPrivateUsage]
            successor,
            store=store,
            workspace_commitment=first_workspace,
            workspace_locator=first_locator,
            harness_id=cast(Literal["claude", "codex", "cursor"], harness_id),
            _state=tmp_path,
            connect=cast(observe_hooks_module.HookStartConnector, _connector(client)),
        )
    )

    assert outcome.mapping is None
    assert outcome.reason == "auto_attach_recovery_busy"
    assert client.requests == []
    assert store.codex_sessions_for_workspace(second_workspace) == (previous,)


@pytest.mark.parametrize(
    ("harness_id", "older", "newer", "successor"),
    [
        ("claude", "claude:ended-a", "claude:ended-b", "claude:next-race"),
        ("codex", "codex-ended-a", "codex-ended-b", "codex-next-race"),
        ("cursor", "cursor:ended-a", "cursor:ended-b", "cursor:next-race"),
    ],
)
def test_recovery_rejects_a_changed_nonselected_candidate_for_all_hosts(
    tmp_path: Path,
    harness_id: str,
    older: str,
    newer: str,
    successor: str,
) -> None:
    """#605: every eligible candidate remains part of the revalidation contract."""

    locator = str(tmp_path.resolve())
    initial_store = LocalObservationStore(_state=tmp_path)
    workspace = initial_store.workspace_commitment(locator)
    initial_store.grant_consent(workspace)
    _bind_ended_predecessors(initial_store, workspace, (older, newer), _state=tmp_path)
    # Make ``older`` the selected mapping so the non-selected candidate is the
    # one changed by the deterministic interleaving.
    older_path = observe_hooks_module.mapping_path(older, _state=tmp_path)
    newer_path = observe_hooks_module.mapping_path(newer, _state=tmp_path)
    stamp = 10**15
    os.utime(older_path, ns=(stamp + 2, stamp + 2))
    os.utime(newer_path, ns=(stamp + 1, stamp + 1))
    other_task = "tsk_4b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5b"

    class _CandidateChangedOnRevalidation(LocalObservationStore):
        calls = 0

        def codex_session_lifecycles_for_workspace(
            self, workspace_commitment: str
        ) -> tuple[tuple[str, bool], ...]:
            self.calls += 1
            if self.calls == 2:
                observe_hooks_module.store_mapping(
                    observe_hooks_module.mapping_from_start_ids(
                        codex_session_id=newer,
                        yoetz_task_id=other_task,
                        yoetz_session_id="ses_4b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5c",
                        yoetz_writer_id="wri_4b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5d",
                        last_frontier=None,
                    ),
                    _state=tmp_path,
                )
            return super().codex_session_lifecycles_for_workspace(workspace_commitment)

    store = _CandidateChangedOnRevalidation(_state=tmp_path)
    store.bind_codex_session(workspace, successor)
    client = _WorkspaceConflictThenAttachClient()
    client.created = True

    outcome = asyncio.run(
        observe_hooks_module._try_workspace_auto_start(  # pyright: ignore[reportPrivateUsage]
            successor,
            store=store,
            workspace_commitment=workspace,
            workspace_locator=locator,
            harness_id=cast(Literal["claude", "codex", "cursor"], harness_id),
            _state=tmp_path,
            connect=cast(observe_hooks_module.HookStartConnector, _connector(client)),
        )
    )

    assert outcome.mapping is None
    assert outcome.reason == "auto_attach_recovery_busy"
    assert client.requests == []
    changed = observe_hooks_module.load_mapping(newer, _state=tmp_path)
    assert changed is not None and changed.yoetz_task_id == other_task


def test_workspace_conflict_recovery_does_not_cross_host_families(tmp_path: Path) -> None:
    """A Codex session never silently continues an ended Claude or Cursor mapping."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    previous = "claude:ended-1"
    previous_commitment = store.bind_codex_session(workspace, previous)
    store.note_session_end(workspace, previous_commitment)
    observe_hooks_module.store_mapping(
        observe_hooks_module.mapping_from_start_ids(
            codex_session_id=previous,
            yoetz_task_id=_START_IDS["task_id"],
            yoetz_session_id=_START_IDS["session_id"],
            yoetz_writer_id=_START_IDS["writer_id"],
            last_frontier=None,
        ),
        _state=tmp_path,
    )

    recovered = observe_hooks_module._scan_ended_workspace_recovery(  # pyright: ignore[reportPrivateUsage]
        store, workspace, "codex-next-1", harness_id="codex", _state=tmp_path
    ).mapping
    assert recovered is None


def test_workspace_conflict_recovery_rejects_multiple_local_task_ids(tmp_path: Path) -> None:
    """Mapping-file recency never selects silently among sibling tasks."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    task_ids = (
        _START_IDS["task_id"],
        "tsk_4b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5b",
    )
    for index, task_id in enumerate(task_ids):
        previous = f"codex-ended-{index}"
        commitment = store.bind_codex_session(workspace, previous)
        store.note_session_end(workspace, commitment)
        observe_hooks_module.store_mapping(
            observe_hooks_module.mapping_from_start_ids(
                codex_session_id=previous,
                yoetz_task_id=task_id,
                yoetz_session_id=(
                    _START_IDS["session_id"]
                    if index == 0
                    else "ses_4b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5c"
                ),
                yoetz_writer_id=(
                    _START_IDS["writer_id"]
                    if index == 0
                    else "wri_4b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5d"
                ),
                last_frontier=None,
            ),
            _state=tmp_path,
        )

    recovered = observe_hooks_module._scan_ended_workspace_recovery(  # pyright: ignore[reportPrivateUsage]
        store, workspace, "codex-next-1", harness_id="codex", _state=tmp_path
    ).mapping
    assert recovered is None


def test_workspace_recovery_does_not_attach_while_predecessor_lock_is_held(
    tmp_path: Path,
) -> None:
    """A predecessor resume wins before local recovery can rotate its route."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    previous = "codex-ended-1"
    commitment = store.bind_codex_session(workspace, previous)
    store.note_session_end(workspace, commitment)
    observe_hooks_module.store_mapping(
        observe_hooks_module.mapping_from_start_ids(
            codex_session_id=previous,
            yoetz_task_id=_START_IDS["task_id"],
            yoetz_session_id=_START_IDS["session_id"],
            yoetz_writer_id=_START_IDS["writer_id"],
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    client = _WorkspaceConflictThenAttachClient()
    client.created = True

    with acquire_session_lock(previous, _state=tmp_path) as owned:
        assert owned is True
        outcome = asyncio.run(
            observe_hooks_module._try_workspace_auto_start(  # pyright: ignore[reportPrivateUsage]
                "codex-next-1",
                store=store,
                workspace_commitment=workspace,
                workspace_locator=locator,
                harness_id="codex",
                _state=tmp_path,
                connect=cast(observe_hooks_module.HookStartConnector, _connector(client)),
            )
        )

    assert outcome.mapping is None
    assert outcome.reason == "auto_attach_recovery_busy"
    assert client.requests == []


@pytest.mark.parametrize(
    ("harness_id", "older", "newer", "successor", "foreign"),
    [
        ("claude", "claude:ended-a", "claude:ended-b", "claude:next-1", "cursor:ended-x"),
        ("codex", "codex-ended-a", "codex-ended-b", "codex-next-1", "claude:ended-x"),
        ("cursor", "cursor:ended-a", "cursor:ended-b", "cursor:next-1", "codex-ended-x"),
    ],
)
def test_recovery_rewrites_every_ended_same_task_predecessor_mapping(
    tmp_path: Path,
    harness_id: str,
    older: str,
    newer: str,
    successor: str,
    foreign: str,
) -> None:
    """#577: every ended same-host predecessor follows the rotated ids; other hosts do not."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    for session_id in (older, newer, foreign):
        commitment = store.bind_codex_session(workspace, session_id)
        store.note_session_end(workspace, commitment)
        observe_hooks_module.store_mapping(
            observe_hooks_module.mapping_from_start_ids(
                codex_session_id=session_id,
                yoetz_task_id=_START_IDS["task_id"],
                yoetz_session_id=_START_IDS["session_id"],
                yoetz_writer_id=_START_IDS["writer_id"],
                last_frontier="3:sha256:" + "a" * 64,
            ),
            _state=tmp_path,
        )
    client = _WorkspaceConflictThenAttachClient()
    client.created = True

    outcome = asyncio.run(
        observe_hooks_module._try_workspace_auto_start(  # pyright: ignore[reportPrivateUsage]
            successor,
            store=store,
            workspace_commitment=workspace,
            workspace_locator=locator,
            harness_id=cast(Literal["claude", "codex", "cursor"], harness_id),
            _state=tmp_path,
            connect=cast(observe_hooks_module.HookStartConnector, _connector(client)),
        )
    )

    assert outcome.mapping is not None
    assert outcome.mapping.yoetz_session_id == _SUCCESSOR_IDS["session_id"]
    for session_id in (older, newer):
        rewritten = observe_hooks_module.load_mapping(session_id, _state=tmp_path)
        assert rewritten is not None
        assert rewritten.yoetz_session_id == _SUCCESSOR_IDS["session_id"]
        assert rewritten.yoetz_writer_id == _SUCCESSOR_IDS["writer_id"]
        assert rewritten.last_frontier == "3:sha256:" + "a" * 64
    foreign_mapping = observe_hooks_module.load_mapping(foreign, _state=tmp_path)
    assert foreign_mapping is not None
    assert foreign_mapping.yoetz_session_id == _START_IDS["session_id"]
    assert foreign_mapping.yoetz_writer_id == _START_IDS["writer_id"]


@pytest.mark.parametrize(
    ("harness_id", "authorized", "ambiguous", "successor"),
    [
        ("claude", "claude:ended-authorized", "claude:ended-ambiguous", "claude:next-authorized"),
        ("codex", "codex-ended-authorized", "codex-ended-ambiguous", "codex-next-authorized"),
        ("cursor", "cursor:ended-authorized", "cursor:ended-ambiguous", "cursor:next-authorized"),
    ],
)
def test_recovery_leaves_an_ambiguous_predecessor_mapping_untouched_for_all_hosts(
    tmp_path: Path,
    harness_id: str,
    authorized: str,
    ambiguous: str,
    successor: str,
) -> None:
    """#605: rewrite consumes only the unambiguous candidates it selected."""

    locator = str(tmp_path.resolve())
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(locator)
    foreign_workspace = store.workspace_commitment(str((tmp_path / "foreign").resolve()))
    store.grant_consent(workspace)
    store.grant_consent(foreign_workspace)
    for session_id in (authorized, ambiguous):
        commitment = store.bind_codex_session(workspace, session_id)
        store.note_session_end(workspace, commitment)
        observe_hooks_module.store_mapping(
            observe_hooks_module.mapping_from_start_ids(
                codex_session_id=session_id,
                yoetz_task_id=_START_IDS["task_id"],
                yoetz_session_id=_START_IDS["session_id"],
                yoetz_writer_id=_START_IDS["writer_id"],
                last_frontier=None,
            ),
            _state=tmp_path,
        )
    _seed_legacy_cross_workspace_binding(store, foreign_workspace, ambiguous)
    store.bind_codex_session(workspace, successor)
    client = _WorkspaceConflictThenAttachClient()
    client.created = True

    outcome = asyncio.run(
        observe_hooks_module._try_workspace_auto_start(  # pyright: ignore[reportPrivateUsage]
            successor,
            store=store,
            workspace_commitment=workspace,
            workspace_locator=locator,
            harness_id=cast(Literal["claude", "codex", "cursor"], harness_id),
            _state=tmp_path,
            connect=cast(observe_hooks_module.HookStartConnector, _connector(client)),
        )
    )

    assert outcome.mapping is not None and outcome.recovered is True
    authorized_mapping = observe_hooks_module.load_mapping(authorized, _state=tmp_path)
    ambiguous_mapping = observe_hooks_module.load_mapping(ambiguous, _state=tmp_path)
    assert authorized_mapping is not None
    assert authorized_mapping.yoetz_session_id == _SUCCESSOR_IDS["session_id"]
    assert ambiguous_mapping is not None
    assert ambiguous_mapping.yoetz_session_id == _START_IDS["session_id"]
    assert store.codex_sessions_for_workspace(foreign_workspace) == (ambiguous,)


def test_rewrite_skips_live_and_other_task_mappings(tmp_path: Path) -> None:
    """The rewrite helper never rotates a live session or a sibling task."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    live = "codex-live-1"
    other = "codex-ended-other-task"
    store.bind_codex_session(workspace, live)
    other_commitment = store.bind_codex_session(workspace, other)
    store.note_session_end(workspace, other_commitment)
    other_task = "tsk_4b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5b"
    for session_id, task_id in ((live, _START_IDS["task_id"]), (other, other_task)):
        observe_hooks_module.store_mapping(
            observe_hooks_module.mapping_from_start_ids(
                codex_session_id=session_id,
                yoetz_task_id=task_id,
                yoetz_session_id=_START_IDS["session_id"],
                yoetz_writer_id=_START_IDS["writer_id"],
                last_frontier=None,
            ),
            _state=tmp_path,
        )
    successor = observe_hooks_module.mapping_from_start_ids(
        codex_session_id="codex-next-1",
        yoetz_task_id=_START_IDS["task_id"],
        yoetz_session_id=_SUCCESSOR_IDS["session_id"],
        yoetz_writer_id=_SUCCESSOR_IDS["writer_id"],
        last_frontier=None,
    )
    observe_hooks_module._rewrite_ended_predecessor_mappings(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace,
        successor,
        harness_id="codex",
        _state=tmp_path,
    )
    for session_id in (live, other):
        untouched = observe_hooks_module.load_mapping(session_id, _state=tmp_path)
        assert untouched is not None
        assert untouched.yoetz_session_id == _START_IDS["session_id"]


def test_new_sibling_admission_does_not_rewrite_live_predecessors(tmp_path: Path) -> None:
    """Rewrite runs only after recovery attach of the same task, not a fresh create."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    previous = "codex-ended-1"
    store.bind_codex_session(workspace, previous)
    observe_hooks_module.store_mapping(
        observe_hooks_module.mapping_from_start_ids(
            codex_session_id=previous,
            yoetz_task_id=_START_IDS["task_id"],
            yoetz_session_id=_START_IDS["session_id"],
            yoetz_writer_id=_START_IDS["writer_id"],
            last_frontier="3:sha256:" + "a" * 64,
        ),
        _state=tmp_path,
    )

    class _CreateSucceedsWithRotatedIds(_InstantAckClient):
        async def start(self, request: object, *, deadline_ms: int | None = None) -> object:
            del deadline_ms
            assert isinstance(request, StartRequest)
            assert request.mode == "create_or_attach"
            return SimpleNamespace(
                ok=True,
                frontier=SimpleNamespace(sequence="4", head_digest="sha256:" + "b" * 64),
                **_SUCCESSOR_IDS,
            )

    outcome = asyncio.run(
        observe_hooks_module._try_workspace_auto_start(  # pyright: ignore[reportPrivateUsage]
            "codex-next-1",
            store=store,
            workspace_commitment=workspace,
            workspace_locator=locator,
            harness_id="codex",
            _state=tmp_path,
            connect=cast(
                observe_hooks_module.HookStartConnector,
                _connector(_CreateSucceedsWithRotatedIds()),
            ),
        )
    )

    assert outcome.mapping is not None
    assert outcome.mapping.yoetz_session_id == _SUCCESSOR_IDS["session_id"]
    predecessor = observe_hooks_module.load_mapping(previous, _state=tmp_path)
    assert predecessor is not None
    assert predecessor.yoetz_session_id == _START_IDS["session_id"]
    assert predecessor.yoetz_writer_id == _START_IDS["writer_id"]


def test_locked_nonselected_predecessor_blocks_recovery_until_its_state_is_stable(
    tmp_path: Path,
) -> None:
    """A concurrent predecessor resume wins over recovery rather than racing its rewrite."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    older = "codex-ended-a"
    newer = "codex-ended-b"
    for session_id in (older, newer):
        commitment = store.bind_codex_session(workspace, session_id)
        store.note_session_end(workspace, commitment)
        observe_hooks_module.store_mapping(
            observe_hooks_module.mapping_from_start_ids(
                codex_session_id=session_id,
                yoetz_task_id=_START_IDS["task_id"],
                yoetz_session_id=_START_IDS["session_id"],
                yoetz_writer_id=_START_IDS["writer_id"],
                last_frontier=None,
            ),
            _state=tmp_path,
        )
    client = _WorkspaceConflictThenAttachClient()
    client.created = True

    with acquire_session_lock(older, _state=tmp_path) as owned:
        assert owned is True
        outcome = asyncio.run(
            observe_hooks_module._try_workspace_auto_start(  # pyright: ignore[reportPrivateUsage]
                "codex-next-1",
                store=store,
                workspace_commitment=workspace,
                workspace_locator=locator,
                harness_id="codex",
                _state=tmp_path,
                connect=cast(observe_hooks_module.HookStartConnector, _connector(client)),
            )
        )

    assert outcome.mapping is None
    assert outcome.reason == "auto_attach_recovery_busy"
    assert client.requests == []
    for session_id in (older, newer):
        predecessor = observe_hooks_module.load_mapping(session_id, _state=tmp_path)
        assert predecessor is not None
        assert predecessor.yoetz_session_id == _START_IDS["session_id"]


def test_session_restart_cannot_clear_ended_state_while_recovery_holds_lock(
    tmp_path: Path,
) -> None:
    """Generation restart and recovery selection share one lifecycle lock."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    previous = "codex-ended-1"
    commitment = store.bind_codex_session(workspace, previous)
    store.note_session_end(workspace, commitment)

    with acquire_session_lock(previous, _state=tmp_path) as owned:
        assert owned is True
        output = io.BytesIO()
        assert (
            handle_observe(
                event_name="SessionStart",
                stdin_bytes=json.dumps(
                    {
                        "session_id": previous,
                        "hook_event_name": "SessionStart",
                        "source": "resume",
                    }
                ).encode(),
                stdout=output,
                workspace=locator,
                _state=tmp_path,
                skip_service=True,
            )
            == 0
        )

    assert output.getvalue() == b"{}\n"
    assert store.codex_session_ended(workspace, previous) is True


def _count_mapping_loads(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every host session id whose mapping file the hook module reads."""

    loads: list[str] = []
    real_load = observe_hooks_module.load_mapping

    def counting_load(codex_session_id: str, *, _state: Path | None = None):
        loads.append(codex_session_id)
        return real_load(codex_session_id, _state=_state)

    monkeypatch.setattr(observe_hooks_module, "load_mapping", counting_load)
    return loads


def _bind_ended_predecessors(
    store: LocalObservationStore,
    workspace: str,
    session_ids: tuple[str, ...],
    *,
    _state: Path,
    task_id: str | None = _START_IDS["task_id"],
) -> None:
    """Bind, end, and (unless ``task_id`` is None) map each predecessor to one task."""

    for session_id in session_ids:
        commitment = store.bind_codex_session(workspace, session_id)
        store.note_session_end(workspace, commitment)
        if task_id is None:
            continue
        observe_hooks_module.store_mapping(
            observe_hooks_module.mapping_from_start_ids(
                codex_session_id=session_id,
                yoetz_task_id=task_id,
                yoetz_session_id=_START_IDS["session_id"],
                yoetz_writer_id=_START_IDS["writer_id"],
                last_frontier=None,
            ),
            _state=_state,
        )


def _recover(
    store: LocalObservationStore,
    workspace: str,
    locator: str,
    successor: str,
    *,
    _state: Path,
    client: object | None = None,
    prune_surplus: bool = True,
) -> observe_hooks_module.AutoAttachOutcome:
    if client is None:
        client = _WorkspaceConflictThenAttachClient()
        client.created = True
    # handle_observe binds the current session at ingest, before any attach.
    store.bind_codex_session(workspace, successor)
    return asyncio.run(
        observe_hooks_module._try_workspace_auto_start(  # pyright: ignore[reportPrivateUsage]
            successor,
            store=store,
            workspace_commitment=workspace,
            workspace_locator=locator,
            harness_id="codex",
            _state=_state,
            connect=cast(observe_hooks_module.HookStartConnector, _connector(client)),
            prune_surplus=prune_surplus,
        )
    )


def test_recovery_scan_reads_each_predecessor_mapping_once_per_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#549/#605: bounded scan, rewrite, and durable-route verification."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    predecessors = tuple(f"codex-ended-{index}" for index in range(6))
    _bind_ended_predecessors(store, workspace, predecessors, _state=tmp_path)
    loads = _count_mapping_loads(monkeypatch)

    outcome = _recover(store, workspace, locator, "codex-next-1", _state=tmp_path)

    assert outcome.mapping is not None and outcome.recovered is True
    per_predecessor = {session_id: loads.count(session_id) for session_id in predecessors}
    # Scan once, revalidate every bounded candidate under its lock, then the
    # #577 rewrite reads each ended predecessor once more, and the durable
    # queue reconciliation verifies the exact route after that rewrite.
    assert sum(per_predecessor.values()) == 4 * len(predecessors)
    assert set(per_predecessor.values()) == {4}
    # Every consumed predecessor was drained, so only the live successor stays bound.
    assert store.codex_session_lifecycles_for_workspace(workspace) == (("codex-next-1", False),)
    for session_id in predecessors:
        rewritten = observe_hooks_module.load_mapping(session_id, _state=tmp_path)
        assert rewritten is not None
        assert rewritten.yoetz_session_id == _SUCCESSOR_IDS["session_id"]


def test_recovery_scan_is_not_repeated_while_the_predecessor_lock_is_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#549: a contended predecessor lock costs the single scan and nothing more."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    predecessors = tuple(f"codex-ended-{index}" for index in range(4))
    _bind_ended_predecessors(store, workspace, predecessors, _state=tmp_path)
    loads = _count_mapping_loads(monkeypatch)
    # The newest mapping is the selector; hold its lock as a resuming session would.
    selected = predecessors[-1]
    newest = time.time_ns() + 10**12
    os.utime(observe_hooks_module.mapping_path(selected, _state=tmp_path), ns=(newest, newest))

    with acquire_session_lock(selected, _state=tmp_path) as owned:
        assert owned is True
        outcome = _recover(store, workspace, locator, "codex-next-1", _state=tmp_path)

    assert outcome.mapping is None
    assert outcome.reason == "auto_attach_recovery_busy"
    assert sorted(loads) == sorted(predecessors)
    # Nothing was consumed, so nothing was pruned.
    assert store.codex_session_lifecycles_for_workspace(workspace) == tuple(
        (session_id, session_id != "codex-next-1")
        for session_id in sorted((*predecessors, "codex-next-1"))
    )


def test_recovery_prunes_consumed_predecessors_but_keeps_undrained_and_foreign_bindings(
    tmp_path: Path,
) -> None:
    """#549: pruning follows consumption, never a live session or an undrained lane."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    _bind_ended_predecessors(
        store, workspace, ("codex-ended-clean", "codex-ended-pending"), _state=tmp_path
    )
    # A different host family's ended session is neither a candidate nor consumed.
    _bind_ended_predecessors(store, workspace, ("cursor:ended-x",), _state=tmp_path)
    store.enqueue_outbox(
        workspace,
        "codex-ended-pending",
        _drain_envelope(store, "codex-ended-pending", "hook:pending", 1),
    )

    outcome = _recover(store, workspace, locator, "codex-next-1", _state=tmp_path)

    assert outcome.mapping is not None and outcome.recovered is True
    assert store.codex_session_lifecycles_for_workspace(workspace) == (
        ("codex-ended-pending", True),
        ("codex-next-1", False),
        ("cursor:ended-x", True),
    )
    # The retained predecessor still routes its pending row on the successor
    # route and still answers the ended-unmapped quarantine question.
    pending = observe_hooks_module.load_mapping("codex-ended-pending", _state=tmp_path)
    assert pending is not None
    assert pending.yoetz_writer_id == _SUCCESSOR_IDS["writer_id"]
    assert store.codex_session_ended(workspace, "codex-ended-pending") is True
    # The pruned predecessor's mapping file stays for any late row that names it.
    assert observe_hooks_module.load_mapping("codex-ended-clean", _state=tmp_path) is not None


def test_session_start_retention_keeps_the_newest_ended_bindings(tmp_path: Path) -> None:
    """#549: over the cap, unmapped ended sessions go first, then the oldest mappings."""

    cap = observe_hooks_module._MAX_ENDED_SESSION_BINDINGS  # pyright: ignore[reportPrivateUsage]
    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    other_task = "tsk_3b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5b"
    mapped = tuple(f"codex-old-{index:03d}" for index in range(cap + 2))
    # Two tasks in one workspace keep recovery inadmissible, so only retention acts.
    for index, session_id in enumerate(mapped):
        _bind_ended_predecessors(
            store,
            workspace,
            (session_id,),
            _state=tmp_path,
            task_id=_START_IDS["task_id"] if index % 2 else other_task,
        )
        path = observe_hooks_module.mapping_path(session_id, _state=tmp_path)
        stamp = 10**15 + index * 10**9
        os.utime(path, ns=(stamp, stamp))
    unmapped = ("codex-unmapped-a", "codex-unmapped-b", "codex-unmapped-c", "codex-unmapped-d")
    _bind_ended_predecessors(store, workspace, unmapped, _state=tmp_path, task_id=None)
    live = store.bind_codex_session(workspace, "codex-live-1")
    del live

    outcome = _recover(
        store, workspace, locator, "codex-next-1", _state=tmp_path, client=_StartOkClient()
    )

    assert outcome.mapping is not None and outcome.recovered is False
    lifecycles = dict(store.codex_session_lifecycles_for_workspace(workspace))
    ended = sorted(session_id for session_id, is_ended in lifecycles.items() if is_ended)
    assert lifecycles["codex-live-1"] is False and lifecycles["codex-next-1"] is False
    # Surplus was 6: all four unmapped sessions and the two oldest mappings.
    assert len(ended) == cap
    assert ended == sorted(mapped[2:])


def test_retry_pass_scan_is_bounded_by_binding_count_and_skips_retention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#549: a retry event reads each ended binding's mapping once and prunes nothing."""

    cap = observe_hooks_module._MAX_ENDED_SESSION_BINDINGS  # pyright: ignore[reportPrivateUsage]
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    ended = tuple(f"codex-unmapped-{index:03d}" for index in range(cap + 8))
    _bind_ended_predecessors(store, workspace, ended, _state=tmp_path, task_id=None)
    loads = _count_mapping_loads(monkeypatch)
    starts: list[LifecycleMapping | None] = []

    async def unavailable(codex_session_id: str, **kwargs: object) -> object:
        del codex_session_id
        starts.append(cast(LifecycleMapping | None, kwargs.get("recovery_mapping")))
        return observe_hooks_module.AutoAttachOutcome(None, "service_unavailable")

    monkeypatch.setattr(observe_hooks_module, "_try_auto_start", unavailable)

    for event in ("UserPromptSubmit", "SessionStart"):
        del loads[:]
        code = handle_observe(
            event_name=event,
            stdin_bytes=json.dumps(
                {"session_id": "codex-retry-1", "hook_event_name": event}
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            connect=_connector(_InstantAckClient()),  # type: ignore[arg-type]
        )
        assert code == 0
        remaining = [
            session_id
            for session_id, is_ended in store.codex_session_lifecycles_for_workspace(workspace)
            if is_ended
        ]
        scanned = [session_id for session_id in loads if session_id in ended]
        # No candidate maps, so the scan is one read per ended binding, never two.
        assert sorted(scanned) == sorted(remaining)
        if event == "UserPromptSubmit":
            assert len(remaining) == len(ended)
        else:
            assert len(remaining) == cap
    assert starts == [None, None]


def test_many_ended_bindings_cost_one_scan_and_then_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#549: weeks of ended sessions are consumed by one recovery; the next pass is O(1)."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    history = tuple(f"codex-week-{index:03d}" for index in range(96))
    _bind_ended_predecessors(store, workspace, history, _state=tmp_path)
    loads = _count_mapping_loads(monkeypatch)

    first = _recover(store, workspace, locator, "codex-next-1", _state=tmp_path)
    assert first.mapping is not None and first.recovered is True
    # Retention trimmed the history to the cap before the scan, so the pass read
    # each retained predecessor once for scan, once for full revalidation, once
    # for rewrite, and once for durable-route verification, never the whole
    # history.
    cap = observe_hooks_module._MAX_ENDED_SESSION_BINDINGS  # pyright: ignore[reportPrivateUsage]
    assert len(loads) == 4 * cap + 1
    assert set(loads) - {"codex-next-1"} == set(history[-cap:])
    assert store.codex_session_lifecycles_for_workspace(workspace) == (("codex-next-1", False),)

    store.note_session_end(workspace, store.session_commitment("codex-next-1"))
    del loads[:]
    # The sole predecessor now carries the rotated route, so its selector is the
    # successor session id the first recovery minted.
    rotated = _WorkspaceConflictThenAttachClient(expected_session_id=_SUCCESSOR_IDS["session_id"])
    rotated.created = True
    second = _recover(store, workspace, locator, "codex-next-2", _state=tmp_path, client=rotated)
    assert second.mapping is not None and second.recovered is True
    # Scan the sole predecessor, revalidate it, rewrite it, and verify it: four
    # predecessor reads plus one exact read of the new successor route, not ~400.
    assert loads.count("codex-next-1") == 4
    assert loads.count("codex-next-2") == 1
    assert len(loads) == 5
    assert store.codex_session_lifecycles_for_workspace(workspace) == (("codex-next-2", False),)


def test_real_auto_start_connector_receives_the_canonical_workspace_locator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Repository privacy context is bound by the hook's real control handshake."""

    from finishup.ports.control import WorkspaceLocator

    captured: list[WorkspaceLocator | None] = []
    client = _StartOkClient()

    async def connect(_kind: object, *, workspace_locator: WorkspaceLocator | None = None):
        captured.append(workspace_locator)
        return client

    monkeypatch.setattr(observe_hooks_module, "connect_service", connect, raising=False)
    locator = str(tmp_path.resolve())
    outcome = asyncio.run(
        observe_hooks_module._try_auto_start(  # pyright: ignore[reportPrivateUsage]
            "codex-next-1",
            _state=tmp_path,
            workspace_locator=locator,
        )
    )

    assert outcome.mapping is not None
    assert captured == [WorkspaceLocator(locator)]


@pytest.mark.parametrize(
    ("code", "reason"),
    [
        (PublicErrorCode.VAULT_LOCKED, "vault_locked"),
        (PublicErrorCode.SESSION_CONFLICT, "auto_attach_conflict"),
        (PublicErrorCode.IDEMPOTENCY_CONFLICT, "auto_attach_conflict"),
        (PublicErrorCode.INVALID_REQUEST, "auto_attach_refused"),
        (PublicErrorCode.OPERATION_PENDING, "service_unavailable"),
        (PublicErrorCode.STORAGE_UNSAFE, "storage_unsafe"),
        (PublicErrorCode.STORAGE_CORRUPT, "storage_corrupt"),
        (PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED, "privacy_authority_required"),
    ],
)
def test_auto_start_service_refusals_map_to_closed_diagnostic_reasons(
    tmp_path: Path, code: PublicErrorCode, reason: str
) -> None:
    outcome = _auto_start(
        "claude",
        "claude:refused",
        _state=tmp_path,
        workspace_locator=str(tmp_path.resolve()),
        connect=_connector(_StartFailureClient(code)),
    )
    assert outcome.mapping is None
    assert outcome.reason == reason
    assert observe_hooks_module.load_mapping("claude:refused", _state=tmp_path) is None


def test_auto_start_error_classes_stay_closed_hook_diagnostic_reasons() -> None:
    from finishup.cli import hook_diagnostics

    reasons = hook_diagnostics._REASONS  # pyright: ignore[reportPrivateUsage]
    classified = set(
        observe_hooks_module._AUTO_ATTACH_ERROR_REASONS.values()  # pyright: ignore[reportPrivateUsage]
    ) | set(
        observe_hooks_module._AUTO_ATTACH_CONTROL_REASONS.values()  # pyright: ignore[reportPrivateUsage]
    )
    classified |= {
        "auto_attach_workspace_unbound",
        "auto_attach_request_invalid",
        "auto_attach_result_invalid",
        "auto_attach_mapping_write_failed",
        "timeout",
    }
    assert classified <= reasons


@pytest.mark.parametrize(
    ("control_reason", "reason"),
    [
        ("service_unavailable", "service_unavailable"),
        ("vault_locked", "vault_locked"),
        ("request_timeout", "timeout"),
        ("privacy_projection_blocked", "privacy_authority_required"),
        ("service_incompatible", "service_incompatible"),
    ],
)
def test_auto_start_transport_failures_map_to_closed_diagnostic_reasons(
    tmp_path: Path, control_reason: str, reason: str
) -> None:
    from finishup.ports.control import ControlError

    async def connect(_kind: object):
        raise ControlError(control_reason)

    outcome = _auto_start(
        "cursor",
        "cursor:transport",
        _state=tmp_path,
        workspace_locator=str(tmp_path.resolve()),
        connect=connect,
    )
    assert outcome.mapping is None
    assert outcome.reason == reason


def test_auto_start_malformed_success_is_result_invalid_not_a_mapping(tmp_path: Path) -> None:
    class _Malformed(_InstantAckClient):
        async def start(self, request: object, *, deadline_ms: int | None = None) -> object:
            del request, deadline_ms
            return SimpleNamespace(ok=True, task_id="tsk_not-a-uuid", session_id=None)

    outcome = _auto_start(
        "codex",
        "malformed",
        _state=tmp_path,
        workspace_locator=str(tmp_path.resolve()),
        connect=_connector(_Malformed()),
    )
    assert outcome.mapping is None
    assert outcome.reason == "auto_attach_result_invalid"
    assert observe_hooks_module.load_mapping("malformed", _state=tmp_path) is None


def test_auto_attach_outcome_requires_exactly_one_of_mapping_or_reason() -> None:
    with pytest.raises(ValueError, match="auto_attach_outcome_invalid"):
        observe_hooks_module.AutoAttachOutcome(None, None)


@pytest.mark.parametrize(
    ("source", "session"),
    [
        (ObservationSource.CODEX_HOOK, "codex-start-1"),
        (ObservationSource.CLAUDE_HOOK, "claude:start-1"),
        (ObservationSource.CURSOR_HOOK, "cursor:start-1"),
    ],
)
def test_session_start_auto_attaches_maps_and_drains_for_every_host(
    tmp_path: Path, source: ObservationSource, session: str
) -> None:
    """Natural SessionStart produces mapping_present and a drained outbox (#459)."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    client = _StartOkClient()
    out = io.BytesIO()

    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {"session_id": session, "hook_event_name": "SessionStart", "source": "startup"}
        ).encode(),
        stdout=out,
        workspace=locator,
        _state=tmp_path,
        connect=_connector(client),  # type: ignore[arg-type]
        source=source,
        # The cursor-observe entry passes the raw host event for output rendering.
        _output_event_name="sessionStart" if source is ObservationSource.CURSOR_HOOK else None,
    )

    assert code == 0
    assert len(client.requests) == 1
    mapping = observe_hooks_module.load_mapping(session, _state=tmp_path)
    assert mapping is not None
    assert mapping.yoetz_task_id == _START_IDS["task_id"]
    assert store.find_workspace_for_codex_session(session) == workspace
    assert store.list_pending_outbox_rows(workspace) == ()
    rendered = out.getvalue().decode()
    assert _START_IDS["task_id"] in rendered
    assert "no ledger task is mapped yet" not in rendered
    assert "after guidance reads and tool/schema discovery" in rendered
    assert "before substantive material work" in rendered
    assert rendered.index("call start with mode=attach") < rendered.index("Then call status")
    assert "Then call status with the returned session/writer ids" in rendered
    assert "same-request recovery first" in rendered
    assert "ask the user for intro and guidance" in rendered
    diagnostics_path = tmp_path / "observation/hook-diagnostics.jsonl"
    if diagnostics_path.exists():
        assert "auto_attach" not in diagnostics_path.read_text()
        assert '"reason":"service_unavailable"' not in diagnostics_path.read_text()


@pytest.mark.parametrize(
    ("source", "first_session", "second_session"),
    [
        (ObservationSource.CODEX_HOOK, "codex-ended-1", "codex-next-1"),
        (ObservationSource.CLAUDE_HOOK, "claude:ended-1", "claude:next-1"),
        (ObservationSource.CURSOR_HOOK, "cursor:ended-1", "cursor:next-1"),
    ],
)
def test_fresh_session_reattaches_the_ended_workspace_task_and_drains_without_mapping_gap(
    tmp_path: Path,
    source: ObservationSource,
    first_session: str,
    second_session: str,
) -> None:
    """#535: an ended host session supplies a local selector for the shared recovery path."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    client = _WorkspaceConflictThenAttachClient()

    def observe(event: str, session: str) -> bytes:
        out = io.BytesIO()
        code = handle_observe(
            event_name=event,
            stdin_bytes=json.dumps(
                {
                    "session_id": session,
                    "hook_event_name": event,
                    "source": "startup" if event == "SessionStart" else "other",
                }
            ).encode(),
            stdout=out,
            workspace=locator,
            _state=tmp_path,
            connect=_connector(client),  # type: ignore[arg-type]
            source=source,
            _output_event_name="sessionStart" if source is ObservationSource.CURSOR_HOOK else None,
        )
        assert code == 0
        return out.getvalue()

    observe("SessionStart", first_session)
    observe("SessionEnd", first_session)
    rendered = observe("SessionStart", second_session).decode()

    mapping = observe_hooks_module.load_mapping(second_session, _state=tmp_path)
    assert mapping is not None
    assert mapping.yoetz_task_id == _START_IDS["task_id"]
    assert mapping.yoetz_session_id == _SUCCESSOR_IDS["session_id"]
    predecessor = observe_hooks_module.load_mapping(first_session, _state=tmp_path)
    assert predecessor is not None
    assert predecessor.yoetz_session_id == _SUCCESSOR_IDS["session_id"]
    assert predecessor.yoetz_writer_id == _SUCCESSOR_IDS["writer_id"]
    assert store.list_pending_outbox_rows(workspace) == ()
    assert _START_IDS["task_id"] in rendered
    assert [request.mode for request in client.requests] == [
        "create_or_attach",
        "attach",
    ]
    diagnostics_path = tmp_path / "observation/hook-diagnostics.jsonl"
    if diagnostics_path.exists():
        diagnostics = diagnostics_path.read_text()
        assert '"reason":"auto_attach_conflict"' not in diagnostics
        assert '"reason":"mapping_missing"' not in diagnostics


@pytest.mark.parametrize(
    "source",
    [ObservationSource.CODEX_HOOK, ObservationSource.CLAUDE_HOOK, ObservationSource.CURSOR_HOOK],
)
def test_session_start_records_the_typed_cause_when_auto_attach_fails(
    tmp_path: Path, source: ObservationSource
) -> None:
    from finishup.ports.control import ControlError

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)

    async def connect(_kind: object):
        raise ControlError("vault_locked")

    out = io.BytesIO()
    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {"session_id": "claude:locked", "hook_event_name": "SessionStart"}
        ).encode(),
        stdout=out,
        workspace=locator,
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
        source=source,
        _output_event_name="sessionStart" if source is ObservationSource.CURSOR_HOOK else None,
    )

    assert code == 0
    assert observe_hooks_module.load_mapping("claude:locked", _state=tmp_path) is None
    rendered = out.getvalue().decode()
    assert "no ledger task is mapped yet" in rendered
    assert "attachment incomplete: no mapping was produced" in rendered
    assert "mapping_missing" not in rendered
    assert "After guidance reads, tool/schema discovery" in rendered
    assert "call start to attach a task before substantive material work" in rendered
    assert "same-request recovery first" in rendered
    assert "ask the user for intro and guidance" in rendered
    diagnostics = (tmp_path / "observation/hook-diagnostics.jsonl").read_text()
    assert '"reason":"vault_locked"' in diagnostics
    assert '"event":"SessionStart"' in diagnostics


def test_hook_invocation_parses_the_state_file_once_not_seventeen_times(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#209: one hook process loads the store once and reuses the parse.

    Before the stat-validated parse cache, every store method re-read and
    re-parsed the whole workspace state file — 17 times per hook invocation
    against the live 384KB store.
    """

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "parse-count")
    _populate_realistic_store(store, workspace, "parse-count", pending=8, quarantined=40)

    parses = 0
    original = LocalObservationStore._state_from_json  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    def counting(self: LocalObservationStore, raw: object, **kwargs: object):
        nonlocal parses
        parses += 1
        return original(self, raw, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(LocalObservationStore, "_state_from_json", counting)

    async def connect(_kind: object):
        return _InstantAckClient()

    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "parse-count",
                "tool_name": "shell",
                "correlation_id": "pc-1",
                "exit_status": 0,
            }
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )
    assert code == 0
    assert parses == 1, (
        f"one hook invocation parsed the workspace state {parses} times; "
        "the per-instance parse cache is not being hit (33 parses measured "
        "with the cache neutered at this fixture shape)"
    )


@pytest.mark.slow
def test_legacy_spool_hook_meets_slo_on_a_realistic_store(
    tmp_path: Path,
) -> None:
    """#362's guard: legacy ingress does not hydrate a lived-in store.

    The 2026-08-12 regression measured 3.06-4.89s per hook at exactly this
    store shape against a declared 3s, and nothing went red because no test
    asserted wall clock at a realistic store size. The bound is the declared
    timeout with a safety margin: absolute machine-calibrated bounds flake
    (a 3.0s bound measured 0.5s locally and 3.09s on a shared CI runner), so
    the machine-independent cache-regression duty lives in the parse-count
    test above, and this test owns the contract that a hook never comes near
    the budget Codex kills it at.
    """

    import time as time_module

    from finishup.adapters.integrations.codex_plugin import parse_hooks_json, render_plugin_tree

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "latency")
    _populate_realistic_store(store, workspace, "latency")
    state_file = next((tmp_path / "observation" / "workspaces").glob("*.json"))
    assert state_file.stat().st_size >= 250_000, (
        "latency guard must run against a realistically-sized store; "
        f"got {state_file.stat().st_size} bytes"
    )

    started = time_module.monotonic()
    code = handle_spool(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "latency",
                "tool_name": "shell",
                "correlation_id": "lat-1",
                "exit_status": 0,
            }
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
    )
    elapsed = time_module.monotonic() - started
    assert code == 0
    hooks = parse_hooks_json(render_plugin_tree()["hooks/hooks.json"])
    events = hooks["hooks"]
    declared = None
    for group in events["PostToolUse"]:  # type: ignore[index, call-overload]
        for handler in group["hooks"]:  # type: ignore[index, call-overload]
            if "spool" in str(handler["command"]):  # type: ignore[index]
                assert declared is None, "more than one spool handler declared for PostToolUse"
                declared = handler["timeout"]  # type: ignore[index]
    assert isinstance(declared, int)
    assert elapsed <= 0.5, (
        f"legacy spool hook took {elapsed:.2f}s against a realistic store; "
        "the proposed hard cap is 500ms including hook work"
    )


def test_legacy_spool_diagnostics_identify_the_path_and_hard_breach(tmp_path: Path) -> None:
    from finishup.cli.hook_diagnostics import hook_diagnostic_summary, record_hook_timing

    record_hook_timing(
        "PostToolUse",
        ms=501,
        stages={"total": 501},
        path="sync_fallback_spool",
        _state=tmp_path,
    )
    summary = hook_diagnostic_summary(_state=tmp_path)
    timings = cast(Mapping[str, object], summary["timings"])
    paths = cast(Mapping[str, object], timings["paths"])
    spool = cast(Mapping[str, object], paths["sync_fallback_spool"])
    assert spool == {
        "count": 1,
        "recent_count": 1,
        "recent_p95_ms": 501,
        "p95_target_ms": None,
        "hard_cap_ms": 500,
        "recent_hard_cap_breach_count": 1,
    }


def _write_counter(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the name of every file the store atomically writes."""

    import finishup.adapters.integrations.observation_local as local_mod

    written: list[str] = []
    original = local_mod._atomic_write  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    def counting(path: Path, payload: bytes) -> None:
        written.append(path.name)
        original(path, payload)

    monkeypatch.setattr(local_mod, "_atomic_write", counting)
    return written


def _state_writes(written: list[str]) -> int:
    return sum(1 for name in written if name.endswith(".json"))


def _suffix_counts(written: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name in written:
        suffix = Path(name).suffix
        counts[suffix] = counts.get(suffix, 0) + 1
    return counts


def test_hook_invocation_writes_the_state_file_once_not_fourteen_times(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#242: one hook pass serializes the workspace state a bounded number of times.

    The parse-count guard above pins reads; nothing pinned writes, so 10-18
    serialize+fsync cycles per hook survived #209/#213. At the live 525KB store
    each cycle measured ~91ms of encode alone — 0.9-1.6s per hook.
    """

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "write-count")
    _populate_realistic_store(store, workspace, "write-count", pending=8, quarantined=40)

    written = _write_counter(monkeypatch)

    async def connect(_kind: object):
        return _InstantAckClient()

    out = io.BytesIO()
    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "write-count",
                "tool_name": "shell",
                "correlation_id": "wc-1",
                "exit_status": 0,
            }
        ).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
        _monotonic=lambda: 0.0,
    )
    assert code == 0
    emitted = cast(dict[str, Any], json.loads(out.getvalue() or b"{}"))
    context = cast(
        str,
        cast(dict[str, Any], emitted.get("hookSpecificOutput") or {}).get("additionalContext")
        or "",
    )
    delivered = bool(context.strip())
    # Exact accounting, so a regression cannot hide inside a loose ceiling:
    #   1 local-pass batch flush
    # + 1 per drained outbox row, bounded by _HOOK_DRAIN_ROW_LIMIT (8 here)
    # + 1 advice-snapshot persistence now that oversized advice projects safely
    # + 1 advice-delivery commit, and only when advice actually reached stdout.
    # Seventeen were measured before the write batch. Nothing else writes: the
    # advice sidecar and the async-pair sample are gone.
    assert _suffix_counts(written) == {".json": 10 + int(delivered)}, written


def test_refresh_advice_does_not_rewrite_state_when_the_snapshot_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "noop-advice")
    _populate_realistic_store(
        store, workspace, "noop-advice", envelopes=8, pending=0, quarantined=0
    )

    first = store.refresh_advice(workspace)
    written = _write_counter(monkeypatch)
    second = store.refresh_advice(workspace)

    assert first is not None and second is first
    assert _state_writes(written) == 0, (
        "an unchanged advice snapshot was rewritten; the build returns the prior "
        "object identically when nothing moved"
    )


def test_quarantine_pruning_still_runs_on_a_hook_whose_advice_refresh_no_ops(
    tmp_path: Path,
) -> None:
    """The no-op-save guard must not cost a pruning opportunity (#242 risk 16).

    ``_save`` is what drives quarantine expiry and the size trims, so skipping
    it in ``refresh_advice`` is only safe because the write batch guarantees the
    pass still flushes exactly once.
    """

    from datetime import UTC, datetime, timedelta

    from finishup.domain.values import timestamp_from_datetime

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "prune")
    _populate_realistic_store(store, workspace, "prune", envelopes=4, pending=0, quarantined=0)

    stale = timestamp_from_datetime((datetime.now(UTC) - timedelta(days=90)).replace(microsecond=0))
    state = store._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert state.quarantine is not None
    state.quarantine.append(
        (
            session,
            _drain_envelope(store, session, "hook:stale", 9_000),
            "service_unavailable",
            stale,
        )
    )
    store._save(workspace, state)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert store.quarantined_count(workspace) == 1

    # A second identical refresh no-ops; the hook pass must still prune.
    store.refresh_advice(workspace)
    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {"session_id": "prune", "tool_name": "shell", "exit_status": 0}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    assert store.quarantined_count(workspace) == 0


def _seed_standing_only_advice(store: LocalObservationStore, workspace: str) -> None:
    """Persist an advice snapshot whose every action is a standing machine condition."""

    from finishup.application.observation_advice import (
        ObservationAdviceBuildInput,
        build_observation_advice_snapshot,
    )
    from finishup.domain.observation import ObservationLifecycle
    from finishup.kernel.policies.observation_advice import ObservationCompositionFact

    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=store.list_envelopes(workspace),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            composition=ObservationCompositionFact(
                semantic_configured=True,
                semantic_ready=False,
                provider_factory_ids=("fireworks",),
                connected_provider_ids=(),
            ),
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    assert {item.recommended_next_action for item in snapshot.ranked_items} == {"connect_provider"}
    store.set_advice_snapshot(workspace, snapshot)


def _refresh_counter(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls = [0]
    original = LocalObservationStore.refresh_advice

    def counting(self: LocalObservationStore, workspace_commitment: str, **kwargs: object):
        calls[0] += 1
        return original(self, workspace_commitment, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(LocalObservationStore, "refresh_advice", counting)
    return calls


def test_advice_stage_runs_on_every_advice_safe_event_including_inert_envelopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No relevance gate: an inert envelope still recomputes and still may deliver.

    The removed fast path could not fire in the sessions it targeted (any
    workspace with a coverage gap carries ``refresh_observation``), and where it
    did fire it reasoned over the workspace snapshot while delivery prefers the
    session snapshot — so it could withhold actionable session advice. The
    advice stage is unconditional on advice-safe events.
    """

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {"session_id": "fast", "tool_name": "shell", "exit_status": 0}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    _seed_standing_only_advice(store, workspace)
    before = len(store.list_envelopes(workspace))

    refreshes = _refresh_counter(monkeypatch)
    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps({"session_id": "fast", "tool_name": "Read"}).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    assert refreshes[0] == 1, "the advice stage was skipped on an advice-safe event"
    assert len(store.list_envelopes(workspace)) == before + 1


def test_post_tool_use_still_recomputes_advice_for_a_trigger_bearing_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {"session_id": "trigger", "tool_name": "shell", "exit_status": 0}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    _seed_standing_only_advice(store, workspace)

    refreshes = _refresh_counter(monkeypatch)
    out = io.BytesIO()
    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "trigger",
                "tool_name": "shell",
                "exit_status": 1,
                "correlation_id": "t1",
            }
        ).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    assert refreshes[0] == 1
    assert "resolve_failed_command" in out.getvalue().decode()


def test_timing_rows_attribute_the_store_stage(tmp_path: Path) -> None:
    """Session-boundary timing rows carry hydrate/encode/write sub-stages (#290)."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    out = io.BytesIO()
    code = handle_observe(
        event_name="Stop",
        stdin_bytes=json.dumps({"session_id": "attributed", "tool_name": "shell"}).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    rows = [
        cast(dict[str, object], json.loads(line))
        for line in (tmp_path / "observation/hook-diagnostics.jsonl").read_text().splitlines()
    ]
    timing_rows = [row for row in rows if row.get("kind") == "timing"]
    assert timing_rows
    stages = cast(Mapping[str, object], timing_rows[-1]["stages"])
    assert {"store", "store_hydrate", "store_encode", "store_write"} <= set(stages)


def test_timing_rows_partition_the_whole_pass(tmp_path: Path) -> None:
    """#310/#311: stage sums covered as little as 14% of the reported total."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    out = io.BytesIO()
    code = handle_observe(
        event_name="Stop",
        stdin_bytes=json.dumps({"session_id": "partitioned", "tool_name": "shell"}).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    rows = [
        cast(dict[str, object], json.loads(line))
        for line in (tmp_path / "observation/hook-diagnostics.jsonl").read_text().splitlines()
    ]
    stages = cast(
        Mapping[str, int], [row for row in rows if row.get("kind") == "timing"][-1]["stages"]
    )
    # The formerly unwindowed regions, plus lock queueing wherever it happened.
    assert {"resolve", "deliver", "store_lock_wait", "unattributed"} <= set(stages)
    partition = ("import", "resolve", "store", "advice", "drain", "deliver")
    total = stages["total"]
    assert sum(stages[name] for name in partition) + stages["unattributed"] >= total - 5
    # Nothing is left unexplained on an uncontended local pass.
    assert stages["unattributed"] <= max(5, total // 4)


def test_hook_total_budget_covers_the_budgets_nested_inside_one_pass() -> None:
    """The end-to-end contract must be satisfiable by a healthy pass (#288).

    The connect preflight and drain budgets are enforced sequentially inside a
    single pass, so a total below their sum fires hook_budget_exceeded on
    passes that are working exactly as designed.
    """

    module = observe_hooks_module
    preflight = module._HOOK_CONNECT_PREFLIGHT_SECONDS  # pyright: ignore[reportPrivateUsage]
    service_start = module._HOOK_SERVICE_START_BUDGET_SECONDS  # pyright: ignore[reportPrivateUsage]
    drain = module._HOOK_DRAIN_BUDGET_SECONDS  # pyright: ignore[reportPrivateUsage]
    end_drain = module._SESSION_END_DRAIN_BUDGET_SECONDS  # pyright: ignore[reportPrivateUsage]
    allowance = module._HOOK_LOCAL_STAGE_ALLOWANCE_SECONDS  # pyright: ignore[reportPrivateUsage]
    total = module._HOOK_TOTAL_BUDGET_SECONDS  # pyright: ignore[reportPrivateUsage]
    attach = module._AUTO_ATTACH_RETRY_BUDGET_SECONDS  # pyright: ignore[reportPrivateUsage]
    retry_service_start = module._AUTO_ATTACH_RETRY_SERVICE_START_BUDGET_SECONDS  # pyright: ignore[reportPrivateUsage]
    attach_events = module._AUTO_ATTACH_RETRY_EVENTS  # pyright: ignore[reportPrivateUsage]
    budget_for = module._hook_total_budget_seconds  # pyright: ignore[reportPrivateUsage]

    # Beyond the enforced budgets, a pass pays the local stages (import,
    # store, advice); the measured cost on a full 1 MiB store is ~0.5s.
    assert total >= preflight + service_start + max(drain, end_drain) + 0.5
    # Derivation, not coincidence: the total is the sum of its parts.
    assert total == preflight + service_start + drain + allowance
    assert 0 < retry_service_start < attach
    # Events that may legitimately retry auto-attach carry that budget too.
    for event in (*attach_events, "SessionStart"):
        assert budget_for(event) >= total + attach
    assert "SessionEnd" not in attach_events
    assert budget_for("SessionEnd") == total
    assert budget_for("PostToolUse", native_content=True) == (
        total
        + observe_hooks_module._NATIVE_CONTENT_DRAIN_BUDGET_SECONDS  # pyright: ignore[reportPrivateUsage]
        - drain
    )
    for event in ("PreToolUse", "PostToolUse"):
        assert budget_for(event) == total


def test_healthy_pass_shapes_fit_under_the_total_budget(tmp_path: Path) -> None:
    """The two measured healthy drain shapes must not trip the diagnostic (#288)."""

    from finishup.cli.hook_diagnostics import hook_diagnostic_summary
    from finishup.cli.observe_hooks import (
        _record_pass_timing,  # pyright: ignore[reportPrivateUsage]
    )

    # Cold drain: preflight + drain + encode (~1.3s) on top of a full-store
    # local pass (~0.55s) — the dominant healthy PreToolUse shape measured in
    # #288. Under the old 1.0s total every such pass was flagged.
    for event, total_seconds in (("PreToolUse", 2.1), ("PostToolUse", 1.3)):
        _record_pass_timing(
            event,
            entry_started=0.0,
            stages={"import": 25, "store": 520},
            monotonic=lambda total=total_seconds: total,
            _state=tmp_path,
        )
    summary = hook_diagnostic_summary(_state=tmp_path)
    reasons = dict(cast(Mapping[str, object], summary["reasons"]))
    assert "hook_budget_exceeded" not in reasons


def test_end_to_end_hook_budget_is_recorded_and_exceeding_it_is_diagnosed(
    tmp_path: Path,
) -> None:
    """The budget is an observability contract: over it, the hook still succeeds."""

    from finishup.cli.hook_diagnostics import hook_diagnostic_summary

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    elapsed = [0.0]

    def creeping() -> float:
        elapsed[0] += 5.0
        return elapsed[0]

    out = io.BytesIO()
    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {"session_id": "budget", "tool_name": "shell", "exit_status": 0}
        ).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
        _monotonic=creeping,
    )
    assert code == 0
    assert out.getvalue().endswith(b"\n")
    summary = hook_diagnostic_summary(_state=tmp_path)
    reasons = dict(cast(Mapping[str, object], summary["reasons"]))
    budget = dict(cast(Mapping[str, object], reasons["hook_budget_exceeded"]))
    assert budget["count"] == 1
    assert budget["recent"] == 1
    timings = dict(cast(Mapping[str, object], summary["timings"]))
    assert timings["count"] == 1


def test_codex_explicit_locator_drops_record_typed_workspace_diagnostics(tmp_path: Path) -> None:
    """The Codex ingress shares the host-agnostic binding diagnostics (#420)."""

    state = tmp_path / "state"
    repository = tmp_path / "repo"
    nested = repository / "packages/app"
    nested.mkdir(parents=True)
    (repository / ".git").mkdir()
    diagnostics_path = state / "observation/hook-diagnostics.jsonl"

    def reasons() -> list[str]:
        if not diagnostics_path.exists():
            return []
        return [
            json.loads(line)["reason"]
            for line in diagnostics_path.read_text(encoding="utf-8").splitlines()
        ]

    payload = json.dumps({"session_id": "codex-subdir", "hook_event_name": "PostToolUse"}).encode()
    for locator in (str(nested), "", str(tmp_path / "absent")):
        stdout = io.BytesIO()
        assert (
            handle_observe(
                event_name="PostToolUse",
                stdin_bytes=payload,
                stdout=stdout,
                workspace=locator,
                _state=state,
                skip_service=True,
            )
            == 0
        )
        assert stdout.getvalue() == b"{}\n"
    assert reasons() == [
        "workspace_unconsented",
        "workspace_unresolvable",
        "workspace_unresolvable",
    ]

    # Consent at the Git root makes the subdirectory hook attach with no new diagnostic.
    store = LocalObservationStore(_state=state)
    store.grant_consent(store.workspace_commitment(str(repository)))
    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=payload,
            stdout=io.BytesIO(),
            workspace=str(nested),
            _state=state,
            skip_service=True,
        )
        == 0
    )
    assert len(reasons()) == 3
    assert str(repository).encode() not in diagnostics_path.read_bytes()


def test_mapping_rotation_keeps_hook_ordinals_and_generation_monotonic(tmp_path: Path) -> None:
    """#560: a reattach rotates the mapped FinishUP session, never the host-session counters.

    Hook ordinals, the session generation, and the host session commitment are
    keyed on the Codex session, so a second ``start`` in the same session (which
    stores a new mapping) cannot restart them and re-mint an earlier source
    identity.
    """

    import uuid

    from finishup.adapters.integrations.codex_lifecycle import load_mapping, store_mapping
    from finishup.protocol.ids import PREFIX_BY_KIND, IdKind

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    codex_id = "codex-reattach-560"
    session = store.bind_codex_session(workspace, codex_id)
    generation = store.begin_session_generation(workspace, session)
    task_id = PREFIX_BY_KIND[IdKind.TASK] + str(uuid.uuid4())

    def _mapping() -> LifecycleMapping:
        return LifecycleMapping(
            mapping_version=1,
            codex_session_id=codex_id,
            yoetz_task_id=task_id,
            yoetz_session_id=PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4()),
            yoetz_writer_id=PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4()),
            last_frontier=None,
        )

    first = _mapping()
    store_mapping(first, _state=tmp_path)
    ordinals = [store.allocate_hook_ordinal(workspace, session) for _ in range(2)]

    second = _mapping()
    store_mapping(second, _state=tmp_path)
    third = _mapping()
    store_mapping(third, _state=tmp_path)
    ordinals.append(store.allocate_hook_ordinal(workspace, session))

    stored = load_mapping(codex_id, _state=tmp_path)
    assert stored is not None
    assert stored.yoetz_session_id == third.yoetz_session_id
    assert stored.yoetz_task_id == task_id
    assert len({first.yoetz_session_id, second.yoetz_session_id, third.yoetz_session_id}) == 3
    assert ordinals == [1, 2, 3]
    assert store.bind_codex_session(workspace, codex_id) == session
    assert store.current_session_generation(workspace, session) == generation


def test_retention_stress_matches_linear_removal_with_bounded_encodes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#689: the 700/176/700 shape preserves the reference removal outcome."""
    from finishup.adapters.integrations import observation_local as local

    store = LocalObservationStore(_state=tmp_path, _wall=lambda: 1_788_998_400.0)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "retention")
    original_save = store._save  # pyright: ignore[reportPrivateUsage]
    original_encode = store._encode_state  # pyright: ignore[reportPrivateUsage]
    initial: list[local._WorkspaceState] = []  # pyright: ignore[reportPrivateUsage]
    encodes = 0

    def save(
        workspace: str,
        state: local._WorkspaceState,  # pyright: ignore[reportPrivateUsage]
        *,
        projected: bytes | None = None,
    ) -> None:  # pyright: ignore[reportPrivateUsage]
        initial.append(local._copy_state(state))  # pyright: ignore[reportPrivateUsage]
        return original_save(workspace, state, projected=projected)

    def encode(workspace: str, state: local._WorkspaceState) -> bytes:  # pyright: ignore[reportPrivateUsage]
        nonlocal encodes
        encodes += 1
        return original_encode(workspace, state)

    monkeypatch.setattr(store, "_save", save)
    monkeypatch.setattr(store, "_encode_state", encode)
    _populate_realistic_store(
        store, workspace, "retention", envelopes=700, pending=176, quarantined=700
    )
    assert encodes <= 16
    path = store._workspace_path(workspace)  # pyright: ignore[reportPrivateUsage]
    optimized = path.read_bytes()
    assert len(store.list_pending_outbox_rows(workspace)) == 176

    def linear(
        workspace: str,
        state: local._WorkspaceState,  # pyright: ignore[reportPrivateUsage]
        count: int,
        limit: int,
        remove: Callable[[local._WorkspaceState, int], None],  # pyright: ignore[reportPrivateUsage]
    ) -> bytes:  # pyright: ignore[reportPrivateUsage]
        payload = b""
        for _ in range(count):
            remove(state, 1)
            payload = original_encode(workspace, state)
            if len(payload) <= limit:
                return payload
        return payload

    monkeypatch.setattr(store, "_trim_retained_prefix", linear)
    original_save(workspace, initial[0])
    assert path.read_bytes() == optimized
    reopened = LocalObservationStore(_state=tmp_path, _wall=lambda: 1_788_998_400.0)
    assert len(reopened.list_pending_outbox_rows(workspace)) == 176


@pytest.mark.anyio
@pytest.mark.parametrize("source", list(ObservationSource))
@pytest.mark.parametrize(
    "reason",
    [
        "frame_invalid",
        "frame_too_large",
        "method_forbidden",
        "protocol_mismatch",
        "service_unavailable",
    ],
)
async def test_control_failure_stops_batch_without_fabricating_other_row_refusals(
    tmp_path: Path, source: ObservationSource, reason: str
) -> None:
    from dataclasses import replace

    from finishup.cli.hook_diagnostics import hook_diagnostic_summary
    from finishup.ports.control import ControlError

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    for index in range(5):
        session = f"control-lane-{index}"
        store.bind_codex_session(workspace, session)
        envelope = replace(_drain_envelope(store, session, f"hook:{index}", 1), source=source)
        assert store.enqueue_outbox(workspace, session, envelope) is None
    calls = 0
    closed = False
    correlation = "err_c7c1c39f-1249-491c-ae43-6bbd23f6e047"

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            nonlocal calls
            calls += 1
            raise ControlError(
                reason, retryable=reason == "service_unavailable", correlation_id=correlation
            )

        async def close(self) -> None:
            nonlocal closed
            closed = True

    async def connect(_kind: object):
        return Client()

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="control-lane-0",
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
    )
    assert calls == 1
    assert closed
    terminal = reason == "frame_too_large"
    rows = store.list_pending_outbox_rows(workspace)
    assert len(rows) == 5 - terminal
    assert store.quarantined_count(workspace) == terminal
    assert sum(row.attempts for row in rows) == (0 if terminal else 1)
    assert "ledger_rejected" not in store.status(ObservationStatusQuery(workspace)).gaps
    diagnostics = hook_diagnostic_summary(_state=tmp_path)
    (failure,) = cast(tuple[Mapping[str, object], ...], diagnostics["drain_failures"])
    assert failure["control_reason"] == reason
    assert failure["correlation_id"] == correlation
    assert failure["disposition"] == ("quarantine" if terminal else "retry")
    assert failure["source"] == source.value


@pytest.mark.anyio
@pytest.mark.parametrize("hydration_seconds", [0.0, 1.1, 1.3])
async def test_preflight_and_delivery_budgets_ignore_local_hydration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hydration_seconds: float
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "allowance")
    store.enqueue_outbox(workspace, "allowance", _drain_envelope(store, "allowance", "x", 1))
    clock = {"now": 0.0}
    original_list = store.list_pending_outbox_rows

    def hydrated(commitment: str):
        rows = original_list(commitment)
        clock["now"] += hydration_seconds
        return rows

    monkeypatch.setattr(store, "list_pending_outbox_rows", hydrated)
    timeouts: list[float] = []
    original_wait = asyncio.wait_for

    async def measured_wait[T](awaitable: Awaitable[T], timeout: float) -> T:
        timeouts.append(timeout)
        return await original_wait(awaitable, timeout=timeout)

    monkeypatch.setattr(asyncio, "wait_for", measured_wait)

    async def connect(_kind: object):
        clock["now"] += 0.3
        return _InstantAckClient()

    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="allowance",
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
        budget_seconds=0.2,
        monotonic=lambda: clock["now"],
    )
    # tb4n1 B4: local hydration and the connect no longer spend the delivery budget. The
    # connect keeps its own one-second preflight bound and the row gets the full 0.2 s.
    assert timeouts[0] == pytest.approx(1.0)
    assert timeouts[1:] == [pytest.approx(0.2)]
    assert store.pending_outbox_count(workspace) == 0
    diagnostics_path = tmp_path / "observation/hook-diagnostics.jsonl"
    diagnostic = diagnostics_path.read_text() if diagnostics_path.exists() else ""
    assert '"reason":"drain_budget_exhausted"' not in diagnostic
    assert "drain_preflight_failed" not in diagnostic


def test_deferred_followup_records_stdout_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.cli import hook_io

    store = LocalObservationStore(_state=tmp_path)
    workspace = str(tmp_path.resolve())
    store.grant_consent(store.workspace_commitment(workspace))
    clock = {"now": 0.0}

    def advancing_clock() -> float:
        clock["now"] += 1.0
        return clock["now"]

    def failed_write(*args: object, **kwargs: object) -> bool:
        return False

    monkeypatch.setattr(hook_io, "stdout_json", failed_write)
    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {"session_id": "deferred", "tool_name": "shell", "exit_status": 0}
            ).encode(),
            stdout=io.BytesIO(),
            workspace=workspace,
            _state=tmp_path,
            skip_service=True,
            _monotonic=advancing_clock,
        )
        == 0
    )
    diagnostic = (tmp_path / "observation/hook-diagnostics.jsonl").read_text()
    assert '"reason":"hook_followup_deferred"' in diagnostic
    assert '"reason":"stdout_write_failed"' in diagnostic


@pytest.mark.parametrize(
    "source",
    [ObservationSource.CODEX_HOOK, ObservationSource.CLAUDE_HOOK, ObservationSource.CURSOR_HOOK],
)
def test_session_start_update_advice_without_observation_consent(
    tmp_path: Path, source: ObservationSource
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    store.set_runtime_enabled(True)
    store_recommendation_state(
        RecommendationState(
            last_evaluated_version="0.2.0",
            pending=("package-update",),
            pending_package_version="0.3.0",
        ),
        root=tmp_path,
    )
    stdout = io.BytesIO()
    assert (
        handle_observe(
            event_name="SessionStart",
            stdin_bytes=json.dumps({"session_id": "no-consent"}).encode(),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
            source=source,
            _output_event_name="sessionStart"
            if source is ObservationSource.CURSOR_HOOK
            else "SessionStart",
        )
        == 0
    )
    payload = json.loads(stdout.getvalue())
    context = (
        payload["additional_context"]
        if source is ObservationSource.CURSOR_HOOK
        else payload["hookSpecificOutput"]["additionalContext"]
    )
    assert "Update FinishUP to 0.3.0" in context
    assert "decline package-update --release-version 0.3.0" in context
    assert not store.pending_workspaces()


def _oversize_hook_body(session_id: str) -> bytes:
    """Return a valid hook object past the skim cap, so no host can keep a row for it.

    A body between the trusted cap and the skim cap keeps a structural row since tb4n1 (B5);
    ``tests/unit/cli/test_hook_oversize_skim.py`` owns that range.
    """

    body = (
        b'{"session_id":"'
        + session_id.encode()
        + b'","tool_name":"shell","command":"COMMAND_CANARY '
        + b"x" * MAX_HOOK_SKIM_BYTES
        + b'"}'
    )
    assert len(body) > MAX_HOOK_SKIM_BYTES > MAX_HOOK_STDIN_BYTES
    return body


def _diagnostic_rows(state: Path) -> list[dict[str, str]]:
    raw = (state / "observation/hook-diagnostics.jsonl").read_text(encoding="utf-8")
    return [cast(dict[str, str], json.loads(line)) for line in raw.splitlines()]


def test_oversized_codex_payload_names_its_size_and_scopes_the_gap(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    stdout = io.BytesIO()

    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=_oversize_hook_body("codex-oversize"),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    assert json.loads(stdout.getvalue()) == {}
    rows = _diagnostic_rows(tmp_path)
    # Before this the refusal reached the outer handler as the bare `observe`
    # reason, which named neither the cause nor the affected event (#667).
    assert rows == [
        {"event": "PostToolUse", "reason": "codex_payload_too_large", "ts": rows[0]["ts"]}
    ]
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.PAYLOAD_TOO_LARGE.value in status.gaps
    assert store.list_envelopes(workspace) == ()
    errors = capsys.readouterr().err
    assert "payload_too_large" in errors
    assert str(MAX_HOOK_STDIN_BYTES) in errors
    assert "COMMAND_CANARY" not in errors


def test_oversized_event_does_not_block_the_next_ordinary_event(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=_oversize_hook_body("codex-oversize-then-normal"),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {
                    "session_id": "codex-oversize-then-normal",
                    "tool_name": "shell",
                    "tool_call_id": "tool-after-oversize",
                    "exit_status": 0,
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    # The refused event costs exactly itself: the gap stands and the next
    # ordinary event still reaches the structural store.
    envelopes = store.list_envelopes(workspace)
    assert len(envelopes) == 1
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.PAYLOAD_TOO_LARGE.value in status.gaps


def test_oversized_claude_payload_names_its_host_instead_of_recording_nothing(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    stdout = io.BytesIO()

    assert (
        handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=_oversize_hook_body("claude-oversize"),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    assert json.loads(stdout.getvalue()) == {}
    rows = _diagnostic_rows(tmp_path)
    # This ingress previously swallowed every refusal into a bare `{}` with no
    # record at all (issue #667).
    assert [row["reason"] for row in rows] == ["claude_payload_too_large"]
    assert (
        ObservationGapCode.PAYLOAD_TOO_LARGE.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_codex_post_tool_use_entry_point_routes_an_oversized_body_to_the_gap(
    tmp_path: Path,
) -> None:
    from finishup.cli import hooks

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    # This entry point parses the body itself before handing the same bytes to
    # the observation ingress, so its degraded branch is the only place the
    # loss can be named.
    assert (
        hooks.handle_post_tool_use(
            stdin_bytes=_oversize_hook_body("codex-entry-oversize"),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
        )
        == 0
    )

    assert [row["reason"] for row in _diagnostic_rows(tmp_path)] == ["codex_payload_too_large"]
    assert (
        ObservationGapCode.PAYLOAD_TOO_LARGE.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )


@pytest.mark.parametrize(
    "response,expected",
    [
        ({"exit_code": 0}, True),
        ({"exit_code": 1}, False),
        ({"exit_code": 0, "is_error": True}, False),
        ({}, False),
    ],
)
def test_nested_routine_outcome_survives_structural_mapping(
    response: dict[str, JsonValue], expected: bool
) -> None:
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "tool_name": "Bash",
            "tool_input": {"command": "head invoice.py"},
            "tool_response": response,
        },
        session_commitment="hmac-sha256:" + "a" * 64,
        event_ordinal=1,
        key_material=_KEY,
    )
    assert (envelope.structural_payload.get("success") is True) is expected
    assert "tool_response" not in envelope.structural_payload
    assert "command" not in envelope.structural_payload


@pytest.mark.parametrize(
    ("source", "session"),
    [
        (ObservationSource.CODEX_HOOK, "cold-codex"),
        (ObservationSource.CLAUDE_HOOK, "claude:cold"),
        (ObservationSource.CURSOR_HOOK, "cursor:cold"),
    ],
)
def test_cold_session_start_primes_selected_service_and_maps_each_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: ObservationSource, session: str
) -> None:
    import finishup.service.client as service_client
    from finishup.ports.control import ControlError, WorkspaceLocator

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    client = _StartOkClient()
    attempts: list[object] = []
    spawned: list[bool] = []

    async def cold_connect(_kind: object, **kwargs: object) -> object:
        attempts.append(kwargs["workspace_locator"])
        assert 0 < cast(float, kwargs["timeout_seconds"]) <= 1.0
        if len(attempts) == 1:
            raise ControlError("service_unavailable", retryable=True)
        return client

    def forbidden(**_kwargs: object) -> None:
        raise AssertionError("hooks cannot supersede a holder")

    monkeypatch.setattr(service_client, "_connect_service_attempt", cold_connect)
    monkeypatch.setattr(service_client, "service_holder_identity", lambda: None)
    monkeypatch.setattr(service_client, "_spawn_service_process", lambda: spawned.append(True))
    monkeypatch.setattr(service_client, "supersede_incompatible_service", forbidden)
    # Drain remains connect-only; only the attachment path invokes cold startup.
    monkeypatch.setattr(observe_hooks_module, "_connect_service", lambda: _connector(client))
    out = io.BytesIO()
    assert (
        handle_observe(
            event_name="SessionStart",
            stdin_bytes=json.dumps({"session_id": session, "source": "startup"}).encode(),
            stdout=out,
            workspace=locator,
            _state=tmp_path,
            source=source,
            _output_event_name="sessionStart" if source is ObservationSource.CURSOR_HOOK else None,
        )
        == 0
    )
    assert spawned == [True]
    assert attempts == [WorkspaceLocator(locator), WorkspaceLocator(locator)]
    assert observe_hooks_module.load_mapping(session, _state=tmp_path) is not None
    assert store.list_pending_outbox_rows(workspace) == ()
    assert "call start with mode=attach" in out.getvalue().decode()


@pytest.mark.parametrize(
    ("reason", "cue"),
    [
        ("service_unavailable", "attachment pending: service_unavailable"),
        ("service_incompatible", "hook did not replace it"),
        ("request_timeout", "attachment pending: service_unavailable"),
    ],
)
@pytest.mark.parametrize(
    "source",
    [ObservationSource.CODEX_HOOK, ObservationSource.CLAUDE_HOOK, ObservationSource.CURSOR_HOOK],
)
def test_startup_failure_context_exposes_only_trusted_recovery_tokens(
    tmp_path: Path, source: ObservationSource, reason: str, cue: str
) -> None:
    from finishup.ports.control import ControlError

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)

    async def unavailable(_kind: object) -> object:
        raise ControlError(reason)

    out = io.BytesIO()
    assert (
        handle_observe(
            event_name="SessionStart",
            stdin_bytes=json.dumps({"session_id": "failure-670", "source": "startup"}).encode(),
            stdout=out,
            workspace=locator,
            _state=tmp_path,
            connect=unavailable,  # type: ignore[arg-type]
            source=source,
            _output_event_name="sessionStart" if source is ObservationSource.CURSOR_HOOK else None,
        )
        == 0
    )
    assert cue in out.getvalue().decode()
    assert observe_hooks_module.load_mapping("failure-670", _state=tmp_path) is None
    assert store.list_pending_outbox_rows(workspace)


@pytest.mark.parametrize(
    "source",
    [ObservationSource.CODEX_HOOK, ObservationSource.CLAUDE_HOOK, ObservationSource.CURSOR_HOOK],
)
def test_bootstrap_backlog_keeps_pair_identity_and_missing_content_gap(
    tmp_path: Path, source: ObservationSource
) -> None:
    from finishup.domain.observation_profiles import (
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    )

    profile = {
        ObservationSource.CLAUDE_HOOK: CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        ObservationSource.CURSOR_HOOK: CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    }.get(source)
    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace, content_capture_profiles=() if profile is None else (profile,))
    client = _StartOkClient()
    session = "bootstrap-pair"
    canary = "TRANSIENT_BOOTSTRAP_CONTENT_670"

    def observe(event: str, *, deferred: bool) -> None:
        assert (
            handle_observe(
                event_name=event,
                stdin_bytes=json.dumps(
                    {
                        "session_id": session,
                        "tool_name": "shell",
                        "tool_call_id": "bootstrap-tool",
                        "correlation_id": "bootstrap-tool",
                        "exit_status": 0,
                        "visibility": "task",
                        "visible_content": canary,
                    }
                ).encode(),
                stdout=io.BytesIO(),
                workspace=locator,
                _state=tmp_path,
                skip_service=deferred,
                connect=_connector(client),  # type: ignore[arg-type]
                source=source,
                _content_capture_profile=profile,
            )
            == 0
        )

    observe("SessionStart", deferred=True)
    observe("PreToolUse", deferred=True)
    observe("PostToolUse", deferred=True)
    pending = store.list_pending_outbox_rows(workspace)
    assert len(pending) == 3
    before = store.list_envelopes(workspace)
    identities = {row.source_identity for row in before}
    assert "unpaired_event" not in before[-1].gap_codes
    assert "content_capture_unavailable" in store.status(ObservationStatusQuery(workspace)).gaps
    observe("Stop", deferred=False)
    assert observe_hooks_module.load_mapping(session, _state=tmp_path) is not None
    # Contentless native-profile hooks defer bulk delivery to the normal drain.
    asyncio.run(
        observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
            store,
            workspace_commitment=workspace,
            codex_session_id=session,
            connect=cast(observe_hooks_module.HookDrainConnector, _connector(client)),
            _state=tmp_path,
        )
    )
    assert store.list_pending_outbox_rows(workspace) == ()
    assert store.quarantined_count(workspace) == 0
    assert identities <= {row.source_identity for row in store.list_envelopes(workspace)}
    assert "content_capture_unavailable" in store.status(ObservationStatusQuery(workspace)).gaps
    assert canary.encode() not in b"".join(
        path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    )


@pytest.mark.parametrize(
    "source",
    [ObservationSource.CODEX_HOOK, ObservationSource.CLAUDE_HOOK, ObservationSource.CURSOR_HOOK],
)
def test_reachable_service_admission_conflict_has_distinct_native_context(
    tmp_path: Path, source: ObservationSource
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    store.grant_consent(store.workspace_commitment(locator))
    client = _StartFailureClient(PublicErrorCode.SESSION_CONFLICT)
    out = io.BytesIO()
    assert (
        handle_observe(
            event_name="SessionStart",
            stdin_bytes=json.dumps({"session_id": "admission-670", "source": "startup"}).encode(),
            stdout=out,
            workspace=locator,
            _state=tmp_path,
            connect=_connector(client),  # type: ignore[arg-type]
            source=source,
            _output_event_name="sessionStart" if source is ObservationSource.CURSOR_HOOK else None,
        )
        == 0
    )
    assert "attachment refused: auto_attach_conflict" in out.getvalue().decode()
    assert "restarting the service does not select a task" in out.getvalue().decode()
    assert len(client.requests) == 1
    assert observe_hooks_module.load_mapping("admission-670", _state=tmp_path) is None


@pytest.mark.anyio
async def test_hook_connector_cannot_supersede_an_answering_incompatible_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.service.client as service_client
    from finishup.ports.control import ControlError

    signals: list[bool] = []
    spawns: list[bool] = []

    async def incompatible(_kind: object, **_kwargs: object) -> object:
        raise ControlError("service_incompatible", retryable=True)

    async def supersede(**_kwargs: object) -> bool:
        signals.append(True)
        return True

    monkeypatch.setattr(service_client, "_connect_service_attempt", incompatible)
    monkeypatch.setattr(service_client, "supersede_incompatible_service", supersede)
    monkeypatch.setattr(service_client, "_spawn_service_process", lambda: spawns.append(True))
    result = await observe_hooks_module._try_auto_start(  # pyright: ignore[reportPrivateUsage]
        "incompatible-670", _state=tmp_path, workspace_locator=str(tmp_path.resolve())
    )
    assert result.reason == "service_incompatible"
    assert result.mapping is None
    assert signals == []
    assert spawns == []


@pytest.mark.anyio
async def test_hook_cold_connection_enforces_budget_when_transport_never_returns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.service.client as service_client

    spawns: list[bool] = []

    async def stalled() -> object:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    monkeypatch.setattr(service_client, "connect_control", stalled)
    monkeypatch.setattr(service_client, "_spawn_service_process", lambda: spawns.append(True))
    monkeypatch.setattr(observe_hooks_module, "_HOOK_SERVICE_START_BUDGET_SECONDS", 0.1)
    started = time.monotonic()
    result = await observe_hooks_module._try_auto_start(  # pyright: ignore[reportPrivateUsage]
        "budget-670", _state=tmp_path, workspace_locator=str(tmp_path.resolve())
    )
    assert time.monotonic() - started < 0.75
    assert result.mapping is None
    assert result.reason == "service_unavailable"
    assert spawns == []


@pytest.mark.parametrize(
    ("event_name", "consented"),
    [
        ("PreToolUse", True),
        ("PostToolUse", True),
        ("SessionEnd", True),
        ("SessionStart", False),
    ],
)
def test_non_attachment_hooks_never_spawn_a_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_name: str,
    consented: bool,
) -> None:
    """Only consented session/turn-boundary attachment may use the on-demand launcher."""

    import finishup.service.client as service_client

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    if consented:
        store.grant_consent(workspace)
    spawned: list[bool] = []

    def forbidden_spawn() -> None:
        spawned.append(True)
        raise AssertionError(f"{event_name} must not start the service")

    monkeypatch.setattr(service_client, "_spawn_service_process", forbidden_spawn)
    payload: dict[str, object] = {"session_id": "no-start", "hook_event_name": event_name}
    if event_name in {"PreToolUse", "PostToolUse"}:
        payload.update({"tool_name": "shell", "exit_status": 0})
    assert (
        handle_observe(
            event_name=event_name,
            stdin_bytes=json.dumps(payload).encode(),
            stdout=io.BytesIO(),
            workspace=locator,
            _state=tmp_path,
            connect=_connector(_InstantAckClient()) if consented else None,  # type: ignore[arg-type]
            _output_event_name="sessionStart" if event_name == "SessionStart" else None,
        )
        == 0
    )
    assert spawned == []


# --- #843: session end after capacity is lowered above the 1 MiB fallback ---


def _lowered_over_target_session(
    tmp_path: Path, source: ObservationSource, host_session: str
) -> tuple[LocalObservationStore, str, str, Callable[[str], int]]:
    """Start a real host session, accept a backlog under Largest, then revoke it."""

    from finishup.adapters.integrations.observation_local import ObservationOutboxRow
    from finishup.domain.observation import ObservationCursor
    from finishup.domain.observation_budget import LARGEST_CAPACITY
    from finishup.domain.observation_settings import ObservationDetailProfile, ObservationSelection
    from finishup.domain.values import JsonObject, Timestamp

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)

    def observe(event: str) -> int:
        return handle_observe(
            event_name=event,
            stdin_bytes=json.dumps(
                {
                    "session_id": host_session,
                    "hook_event_name": event,
                    "source": "startup" if event == "SessionStart" else "other",
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=locator,
            _state=tmp_path,
            connect=None,
            source=source,
        )

    assert observe("SessionStart") == 0
    bindings = store._load(workspace).codex_session_bindings  # pyright: ignore[reportPrivateUsage]
    assert bindings is not None
    session = bindings[host_session]
    store.set_session_selection(
        workspace,
        session,
        ObservationSelection(detail=ObservationDetailProfile.FOCUSED, capacity=LARGEST_CAPACITY),
    )
    with store._lock:  # pyright: ignore[reportPrivateUsage]
        state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
        assert state.pending_outbox is not None
        state.pending_outbox.extend(
            ObservationOutboxRow(
                codex_session_id=host_session,
                envelope=ObservationEnvelope(
                    session_commitment=session,
                    event_kind="PostToolUse",
                    source_identity=f"backlog:{index}",
                    source=source,
                    cursor=ObservationCursor(
                        source_generation=1,
                        byte_position=0,
                        event_position=index + 1,
                        last_source_commitment="hmac-sha256:" + "a" * 64,
                        mapping_version="codex-obs-hook/1.0.0",
                    ),
                    receipt_time=Timestamp("2026-09-10T00:01:00.000Z"),
                    structural_payload=JsonObject({"tool_name": "shell", "exit_status": 1}),
                    content_object_refs=(),
                    gap_codes=(),
                ),
            )
            for index in range(3_000)
        )
        store._save(workspace, state)  # pyright: ignore[reportPrivateUsage]
    size = store._workspace_path(workspace).stat().st_size  # pyright: ignore[reportPrivateUsage]
    assert size > 1_048_576
    store.clear_session_selection(workspace, session)
    return store, workspace, session, observe


_OVER_TARGET_HOSTS = pytest.mark.parametrize(
    ("source", "host_session"),
    [
        (ObservationSource.CODEX_HOOK, "codex-over-target"),
        (ObservationSource.CLAUDE_HOOK, "claude:over-target"),
        (ObservationSource.CURSOR_HOOK, "cursor:over-target"),
    ],
)


@_OVER_TARGET_HOSTS
def test_session_end_is_recorded_after_capacity_is_lowered_above_the_byte_ceiling(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    source: ObservationSource,
    host_session: str,
) -> None:
    from finishup.cli.hook_diagnostics import hook_diagnostic_summary

    store, workspace, session, observe = _lowered_over_target_session(
        tmp_path, source, host_session
    )
    accepted = len(store.list_pending_outbox_rows(workspace))
    capsys.readouterr()

    assert observe("SessionEnd") == 0

    reopened = LocalObservationStore(_state=tmp_path)
    state = reopened._load(workspace)  # pyright: ignore[reportPrivateUsage]
    assert state.ended_sessions is not None and session in state.ended_sessions
    assert len(reopened.list_pending_outbox_rows(workspace)) == accepted
    # The over-target queue refuses the SessionEnd observation itself; the
    # refusal is durably accounted instead of rolled back with the end.
    assert reopened.selection_accounting(workspace)["unrecoverable_input_count"] == 1
    assert state.gaps is not None and state.gaps["_local_outbox_overflow"].active
    err = capsys.readouterr().err
    assert "hook_observe_degraded: outbox_overflow; loss accounted" in err
    assert "durability unknown" not in err
    reasons = hook_diagnostic_summary(_state=tmp_path)["reasons"]
    assert isinstance(reasons, Mapping)
    assert "outbox_overflow" in reasons
    assert "observe" not in reasons
    assert "session_end_unrecorded" not in reasons


@_OVER_TARGET_HOSTS
@pytest.mark.parametrize("failure", ["end_call", "capture_commit", "after_commit"])
def test_an_unpersisted_session_end_is_named_not_swallowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    source: ObservationSource,
    host_session: str,
    failure: str,
) -> None:
    from finishup.cli.hook_diagnostics import hook_diagnostic_summary

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)

    def observe(event: str) -> int:
        return handle_observe(
            event_name=event,
            stdin_bytes=json.dumps({"session_id": host_session, "hook_event_name": event}).encode(),
            stdout=io.BytesIO(),
            workspace=locator,
            _state=tmp_path,
            connect=None,
            source=source,
        )

    assert observe("SessionStart") == 0
    bindings = store._load(workspace).codex_session_bindings  # pyright: ignore[reportPrivateUsage]
    assert bindings is not None
    session = bindings[host_session]

    def unsafe(*_args: object, **_kwargs: object) -> None:
        raise PublicOperationError(
            PublicErrorCode.STORAGE_UNSAFE,
            "Observation state exceeds its safe local bound.",
            retryable=False,
        )

    if failure == "end_call":
        monkeypatch.setattr(LocalObservationStore, "note_session_end", unsafe)
    elif failure == "capture_commit":
        # The end is saved with the capture batch; a refused batch loses it.
        monkeypatch.setattr(LocalObservationStore, "_save_unchecked", unsafe)
    else:
        # A fault after the batch committed must not claim the end was lost.
        monkeypatch.setattr(observe_hooks_module, "_record_pass_timing", unsafe)
    capsys.readouterr()

    # Teardown stays fail-open for the host either way.
    assert observe("SessionEnd") == 0

    err = capsys.readouterr().err
    reasons = hook_diagnostic_summary(_state=tmp_path)["reasons"]
    assert isinstance(reasons, Mapping)
    ended = session in (
        LocalObservationStore(_state=tmp_path)._load(workspace).ended_sessions or set()  # pyright: ignore[reportPrivateUsage]
    )
    if failure == "after_commit":
        assert ended
        assert "session_end_unrecorded" not in err
        assert "session_end_unrecorded" not in reasons
    else:
        assert not ended
        assert "hook_observe_degraded: session_end_unrecorded" in err
        # Reported once, not again by the outer handler.
        assert cast(Mapping[str, object], reasons["session_end_unrecorded"])["count"] == 1


def test_deferred_session_end_batch_failure_is_named(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A lock-contended end intent must not be swallowed by a failed batch."""

    from finishup.cli.hook_diagnostics import hook_diagnostic_summary

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    host_session = "codex-deferred-end"

    def observe(event: str) -> int:
        return handle_observe(
            event_name=event,
            stdin_bytes=json.dumps({"session_id": host_session, "hook_event_name": event}).encode(),
            stdout=io.BytesIO(),
            workspace=locator,
            _state=tmp_path,
            connect=None,
            source=ObservationSource.CODEX_HOOK,
        )

    assert observe("SessionStart") == 0

    def unsafe(*_args: object, **_kwargs: object) -> None:
        raise PublicOperationError(
            PublicErrorCode.STORAGE_UNSAFE,
            "Observation state exceeds its safe local bound.",
            retryable=False,
        )

    monkeypatch.setattr(LocalObservationStore, "_save_unchecked", unsafe)
    capsys.readouterr()
    with acquire_workspace_recovery_lock(workspace, _state=tmp_path) as owned:
        assert owned
        assert observe("SessionEnd") == 0

    state = LocalObservationStore(_state=tmp_path)._load(workspace)  # pyright: ignore[reportPrivateUsage]
    assert not state.pending_lifecycles
    assert not state.ended_sessions
    err = capsys.readouterr().err
    reasons = hook_diagnostic_summary(_state=tmp_path)["reasons"]
    assert "hook_observe_degraded: session_end_unrecorded" in err
    assert isinstance(reasons, Mapping)
    assert cast(Mapping[str, object], reasons["session_end_unrecorded"])["count"] == 1


def test_deferred_session_end_pending_cap_is_named(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A full deferred-lifecycle queue leaves the missing end visible."""

    from finishup.cli.hook_diagnostics import hook_diagnostic_summary

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    for index in range(256):
        assert store.record_pending_session_lifecycle(
            workspace,
            f"codex-pending-{index}",
            "hmac-sha256:" + f"{index + 1:064x}",
            "SessionEnd",
            1,
        )

    host_session = "codex-pending-target"
    capsys.readouterr()
    with acquire_workspace_recovery_lock(workspace, _state=tmp_path) as owned:
        assert owned
        assert (
            handle_observe(
                event_name="SessionEnd",
                stdin_bytes=json.dumps(
                    {"session_id": host_session, "hook_event_name": "SessionEnd"}
                ).encode(),
                stdout=io.BytesIO(),
                workspace=locator,
                _state=tmp_path,
                connect=None,
                source=ObservationSource.CODEX_HOOK,
            )
            == 0
        )

    state = LocalObservationStore(_state=tmp_path)._load(workspace)  # pyright: ignore[reportPrivateUsage]
    assert state.pending_lifecycles is not None and len(state.pending_lifecycles) == 256
    assert not state.ended_sessions
    err = capsys.readouterr().err
    reasons = hook_diagnostic_summary(_state=tmp_path)["reasons"]
    assert "hook_observe_degraded: session_end_unrecorded" in err
    assert isinstance(reasons, Mapping)
    assert cast(Mapping[str, object], reasons["session_end_unrecorded"])["count"] == 1
