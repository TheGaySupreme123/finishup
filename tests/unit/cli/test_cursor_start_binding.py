"""Cursor-owned explicit starts bind before observation, without accepting foreign results."""

from __future__ import annotations

import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.integrations.codex_lifecycle import (
    acquire_session_lock,
    load_mapping,
    mapping_from_start_ids,
    store_mapping,
)
from finishup.adapters.integrations.cursor_integration import render_cursor_plugin
from finishup.cli import hooks, observe_hooks
from finishup.domain.observation_profiles import CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
from finishup.ports.plugin_artifacts import PluginFormatProfile
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

_START: dict[str, JsonValue] = {
    "ok": True,
    "task_id": "tsk_11111111-1111-4111-8111-111111111111",
    "session_id": "ses_22222222-2222-4222-8222-222222222222",
    "writer_id": "wri_33333333-3333-4333-8333-333333333333",
    "frontier": {"sequence": "4", "head_digest": "sha256:" + "a" * 64},
}
_SESSION = "cursor:cursor-661"


@pytest.mark.parametrize(
    "event,tool,field,server",
    [
        ("afterMCPExecution", "start", "result_json", "finishup"),
        ("postToolUse", "MCP:start", "tool_output", None),
    ],
)
def test_cursor_3_20_0_redacted_live_failure_shape(
    tmp_path: Path,
    event: str,
    tool: str,
    field: str,
    server: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """2026-09-08 IDE probe: retain identity/response types, redact all content.

    The real plugin start failed with repository_identity_required before task
    creation. This fixture pins the host carrier, NOT a successful native bind.
    Both carriers serialized content/isError, without structuredContent; only
    afterMCPExecution carried mcp_server_name. All IDs below are replacements.
    """
    payload: dict[str, JsonValue] = {
        "hook_event_name": event,
        "session_id": "cursor-661",
        "conversation_id": "cursor-661",
        "cursor_version": "3.20.0",
        "tool_name": tool,
        field: '{"content":[{"type":"text","text":"{\\"ok\\":false}"}],"isError":true}',
    }
    if server is not None:
        payload["mcp_server_name"] = server

    def observe(**_kwargs: object) -> int:
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", observe)
    _run(tmp_path, payload)
    assert load_mapping(_SESSION, _state=tmp_path) is None
    assert _diagnostics(tmp_path) == []


def _payload(event: str = "afterMCPExecution", **changes: JsonValue) -> dict[str, JsonValue]:
    response_field = "result_json" if event == "afterMCPExecution" else "tool_output"
    return {
        "hook_event_name": event,
        "conversation_id": "cursor-661",
        "cursor_version": "3.20.0",
        "tool_name": "start" if event == "afterMCPExecution" else "mcp__finishup__start",
        **({"mcp_server_name": "finishup"} if event == "afterMCPExecution" else {}),
        response_field: json.dumps({"structuredContent": _START, "isError": False}),
        "tool_use_id": "call-661",
        **changes,
    }


def _run(state: Path, payload: dict[str, JsonValue], *, ordinary: bool = True) -> bytes:
    out = io.BytesIO()
    assert (
        observe_hooks.handle_cursor_observe(
            event_name=cast(str, payload["hook_event_name"]),
            stdin_bytes=canonical_encode(payload),
            stdout=out,
            workspace=str(state),
            _state=state,
            skip_service=True,
            observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID if ordinary else None,
        )
        == 0
    )
    return out.getvalue()


def _diagnostics(state: Path) -> list[str]:
    path = state / "observation/hook-diagnostics.jsonl"
    return (
        [json.loads(line)["reason"] for line in path.read_text().splitlines()]
        if path.exists()
        else []
    )


@pytest.mark.parametrize("ordinary,event", [(True, "postToolUse"), (False, "afterMCPExecution")])
@pytest.mark.parametrize("shape", ["bare", "structured", "text", "serialized"])
def test_owned_start_binds_before_forwarding_and_drops_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ordinary: bool, event: str, shape: str
) -> None:
    responses: dict[str, JsonValue] = {
        "bare": _START,
        "structured": {"structuredContent": _START, "isError": False},
        "text": {"content": [{"type": "text", "text": json.dumps(_START)}]},
        "serialized": json.dumps(
            {"content": [{"type": "text", "text": json.dumps(_START)}], "isError": False}
        ),
    }
    seen: list[object] = []

    def observe(**kwargs: object) -> int:
        mapping = load_mapping(_SESSION, _state=tmp_path)
        assert mapping is not None
        assert mapping.finishup_task_id == _START["task_id"]
        assert mapping.finishup_session_id == _START["session_id"]
        assert mapping.finishup_writer_id == _START["writer_id"]
        assert mapping.last_frontier == "4:sha256:" + "a" * 64
        structural = strict_json_parse(cast(bytes, kwargs["stdin_bytes"]))
        assert isinstance(structural, Mapping)
        assert {"result_json", "tool_output", "task_id", "writer_id", "tool_input"}.isdisjoint(
            structural
        )
        seen.append(structural)
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", observe)
    field = "result_json" if event == "afterMCPExecution" else "tool_output"
    _run(tmp_path, _payload(event, **{field: responses[shape]}), ordinary=ordinary)
    assert len(seen) == 1
    assert _diagnostics(tmp_path) == []


def test_ordinary_mcp_hook_binds_only_and_generic_hook_observes_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []

    def observe(**kwargs: object) -> int:
        assert load_mapping(_SESSION, _state=tmp_path) is not None
        calls.append(kwargs)
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", observe)
    assert json.loads(_run(tmp_path, _payload())) == {}
    assert calls == []
    _run(tmp_path, _payload("postToolUse", tool_name="MCP:start"))
    assert len(calls) == 1


@pytest.mark.parametrize(
    "name,server",
    [
        ("start", "finishup"),
        ("start", "plugin-finishup-finishup"),
        ("mcp__finishup__start", "finishup"),
        ("mcp__plugin_finishup_finishup__start", "plugin-finishup-finishup"),
        ("finishup:start", "finishup"),
        ("plugin-finishup-finishup:start", "plugin-finishup-finishup"),
        # The legacy server name a 0.1-0.2.5 registration still carries (ADR-048).
        ("start", "yoetz"),
        ("start", "plugin-yoetz-yoetz"),
        ("mcp__yoetz__start", "yoetz"),
        ("mcp__plugin_yoetz_yoetz__start", "plugin-yoetz-yoetz"),
        ("yoetz:start", "yoetz"),
        ("plugin-yoetz-yoetz:start", "plugin-yoetz-yoetz"),
    ],
)
def test_exact_cursor_owner_names(tmp_path: Path, name: str, server: str) -> None:
    _run(tmp_path, _payload(tool_name=name, mcp_server_name=server))
    assert load_mapping(_SESSION, _state=tmp_path) is not None


@pytest.mark.parametrize(
    "event,name,server",
    [
        ("afterMCPExecution", "start", None),
        ("afterMCPExecution", "start", "foreign"),
        ("afterMCPExecution", "start", "finishup-extra"),
        ("afterMCPExecution", "mcp__finishup__start", "foreign"),
        ("afterMCPExecution", "mcp__foreign__start", "finishup"),
        ("afterMCPExecution", "restart", "finishup"),
        ("afterMCPExecution", "finishup:start", "plugin-finishup-finishup"),
        # A spelling pairs only with its own server key, across the rename too (ADR-048).
        ("afterMCPExecution", "yoetz:start", "finishup"),
        ("afterMCPExecution", "finishup:start", "yoetz"),
        ("afterMCPExecution", "mcp__yoetz__start", "plugin-yoetz-yoetz"),
        ("afterMCPExecution", "start", "yoetz-extra"),
        ("afterMCPExecution", "start", "plugin-yoetz-finishup"),
        ("postToolUse", "start", "finishup"),
        ("postToolUse", "MCP:start", None),
        ("postToolUse", "MCP:start", "finishup"),
        ("postToolUse", "mcp__foreign__start", None),
        ("postToolUseFailure", "mcp__finishup__start", None),
        ("preToolUse", "mcp__finishup__start", None),
    ],
)
def test_foreign_ambiguous_or_non_success_carrier_cannot_bind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, event: str, name: str, server: str | None
) -> None:
    def observe(**_kwargs: object) -> int:
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", observe)
    p = _payload(event, tool_name=name)
    p.pop("mcp_server_name", None)
    if server is not None:
        p["mcp_server_name"] = server
    _run(tmp_path, p)
    assert load_mapping(_SESSION, _state=tmp_path) is None
    assert _diagnostics(tmp_path) == []


@pytest.mark.parametrize(
    "response,diagnostic",
    [
        ("PRIVATE_RESPONSE_CANARY", "start_bind_unparsed"),
        ('{"ok":true,"ok":false}', "start_bind_unparsed"),
        ({"ok": 1}, "start_bind_unparsed"),
        ({**_START, "task_id": "bad_PRIVATE_ID_CANARY"}, "start_bind_invalid_ids"),
        ({**_START, "writer_id": None}, "start_bind_invalid_ids"),
        ({"ok": False}, None),
        ({"structuredContent": _START, "isError": True}, None),
        (json.dumps({"structuredContent": _START, "isError": True}), None),
        ({"content": [{"type": "text", "text": json.dumps(_START)}], "isError": True}, None),
        ({"content": [{"type": "text", "text": json.dumps(_START)}] * 2}, "start_bind_unparsed"),
    ],
)
def test_invalid_start_preserves_mapping_and_emits_only_closed_diagnostics(
    tmp_path: Path, response: JsonValue, diagnostic: str | None, capsys: pytest.CaptureFixture[str]
) -> None:
    original = mapping_from_start_ids(
        codex_session_id=_SESSION,
        last_frontier=None,
        finishup_task_id=cast(str, _START["task_id"]),
        finishup_session_id=cast(str, _START["session_id"]),
        finishup_writer_id=cast(str, _START["writer_id"]),
    )
    store_mapping(original, _state=tmp_path)
    _run(tmp_path, _payload(result_json=response))
    assert load_mapping(_SESSION, _state=tmp_path) == original
    assert _diagnostics(tmp_path) == ([diagnostic] if diagnostic else [])
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert b"PRIVATE_" not in path.read_bytes()
    assert "PRIVATE_" not in capsys.readouterr().err


@pytest.mark.parametrize("same_task", [True, False])
def test_explicit_start_replaces_previous_task_or_session(tmp_path: Path, same_task: bool) -> None:
    previous = mapping_from_start_ids(
        codex_session_id=_SESSION,
        last_frontier=None,
        finishup_task_id=cast(str, _START["task_id"])
        if same_task
        else "tsk_44444444-4444-4444-8444-444444444444",
        finishup_session_id="ses_55555555-5555-4555-8555-555555555555",
        finishup_writer_id="wri_66666666-6666-4666-8666-666666666666",
    )
    store_mapping(previous, _state=tmp_path)
    _run(tmp_path, _payload())
    current = load_mapping(_SESSION, _state=tmp_path)
    assert current is not None and current != previous
    assert current.finishup_task_id == _START["task_id"]
    assert current.finishup_session_id == _START["session_id"]
    assert current.finishup_writer_id == _START["writer_id"]


def test_canonical_session_alias_is_used_and_conflicting_pair_is_rejected(tmp_path: Path) -> None:
    _run(tmp_path, _payload(session_id="canonical-661"))
    assert load_mapping(_SESSION, _state=tmp_path) is None
    mapped = load_mapping("cursor:canonical-661", _state=tmp_path)
    assert mapped is not None
    _run(tmp_path, _payload(session_id="conflicting-661"))
    assert load_mapping("cursor:conflicting-661", _state=tmp_path) is None
    assert _diagnostics(tmp_path) == ["cursor_session_ambiguous"]
    _run(tmp_path, _payload())
    assert load_mapping("cursor:canonical-661", _state=tmp_path) == mapped


def test_start_mapping_deferred_under_lifecycle_lock_applies_on_next_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with acquire_session_lock(_SESSION, _state=tmp_path) as owned:
        assert owned
        _run(tmp_path, _payload())
        assert load_mapping(_SESSION, _state=tmp_path) is None
    assert _diagnostics(tmp_path) == ["start_bind_deferred"]

    def observe(**_kwargs: object) -> int:
        assert load_mapping(_SESSION, _state=tmp_path) is not None
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", observe)
    _run(tmp_path, _payload("postToolUse", tool_name="Shell", tool_output="{}"))
    mapping = load_mapping(_SESSION, _state=tmp_path)
    assert mapping is not None and mapping.finishup_task_id == _START["task_id"]


@pytest.mark.parametrize("deferred", [False, True])
def test_mapping_write_failure_has_bounded_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, deferred: bool
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("PRIVATE_WRITE_CANARY")

    # Immediate and lock-deferred start results share the durable queue/replay writer. Patching
    # that boundary keeps this regression meaningful after child-lane binding made the write
    # protocol transactional for every lane.
    monkeypatch.setattr(hooks, "queue_mapping_store", fail)
    if deferred:
        with acquire_session_lock(_SESSION, _state=tmp_path) as owned:
            assert owned
            _run(tmp_path, _payload())
    else:
        _run(tmp_path, _payload())
    assert load_mapping(_SESSION, _state=tmp_path) is None
    assert _diagnostics(tmp_path) == ["start_bind_write_failed"]


@pytest.mark.parametrize("boundary", ["bind_start_mapping_outcome", "record_start_bind_diagnostic"])
def test_unexpected_binding_fault_does_not_drop_the_ordinary_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("PRIVATE_BIND_FAULT")

    seen: list[object] = []

    def observe(**kwargs: object) -> int:
        seen.append(kwargs)
        return 0

    monkeypatch.setattr(hooks, boundary, fail)
    monkeypatch.setattr(observe_hooks, "handle_observe", observe)
    _run(tmp_path, _payload("postToolUse"))
    assert len(seen) == 1


def test_ordinary_renderer_installs_the_owner_bearing_binding_hook(tmp_path: Path) -> None:
    launcher = tmp_path / "finishup"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    rendered = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        finishup_launcher=(str(launcher),),
        observation_profile="ordinary",
    )
    definition = json.loads(rendered.members["hooks/hooks.json"])["hooks"]
    assert set(definition) == {
        "afterMCPExecution",
        "postToolUse",
        "postToolUseFailure",
        "preToolUse",
        "sessionStart",
        "sessionEnd",
        "stop",
    }
    hook = definition["afterMCPExecution"]
    assert len(hook) == 1 and hook[0]["timeout"] == 5
    assert (
        "--observation-profile cursor-ordinary-observation-v1 --event afterMCPExecution"
        in hook[0]["command"]
    )
