"""Host advice channels for private and intended-provider facts (#844).

Composition records effective review intent on ``semantic_configured``. These
tests follow that fact through Codex, Claude Code, and Cursor stdout. They do
not re-decide the policy or the service composition that produced it.
"""

from __future__ import annotations

import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.cli.observe_hooks import handle_claude_observe, handle_cursor_observe, handle_observe
from yoetz.domain.observation_profiles import CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
from yoetz.kernel.policies.observation_advice import ObservationCompositionFact
from yoetz.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

_PROVIDER_REPAIR_TOKENS = (
    "connect_provider",
    "renew_provider_sign_in",
    "repair_semantic_provider",
)
_PRIVATE = ObservationCompositionFact(
    semantic_configured=False,
    semantic_ready=False,
    provider_factory_ids=(),
    connected_provider_ids=(),
)
_INTENDED_UNUSABLE = ObservationCompositionFact(
    semantic_configured=True,
    semantic_ready=False,
    provider_factory_ids=(),
    connected_provider_ids=(),
)


def _install_composition(
    monkeypatch: pytest.MonkeyPatch, facts: list[ObservationCompositionFact]
) -> None:
    original = LocalObservationStore.refresh_advice

    def patched(self: LocalObservationStore, workspace: str, **kwargs: object) -> object:
        kwargs.setdefault("composition", facts[-1])
        return original(self, workspace, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(LocalObservationStore, "refresh_advice", patched)


def _consented(tmp_path: Path) -> tuple[LocalObservationStore, str]:
    store = LocalObservationStore(_state=tmp_path)
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)
    return store, commitment


def _parsed(stdout: io.BytesIO) -> Mapping[str, JsonValue]:
    parsed = strict_json_parse(stdout.getvalue())
    assert isinstance(parsed, Mapping)
    return cast(Mapping[str, JsonValue], parsed)


def _assert_no_provider_repair(text: str) -> None:
    for token in _PROVIDER_REPAIR_TOKENS:
        assert token not in text


def _codex(tmp_path: Path, event: str, session: str) -> Mapping[str, JsonValue]:
    stdout = io.BytesIO()
    assert (
        handle_observe(
            event_name=event,
            stdin_bytes=canonical_encode({"session_id": session, "hook_event_name": event}),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    return _parsed(stdout)


def _claude(tmp_path: Path, event: str, session: str) -> Mapping[str, JsonValue]:
    stdout = io.BytesIO()
    assert (
        handle_claude_observe(
            event_name=event,
            stdin_bytes=canonical_encode({"session_id": session, "hook_event_name": event}),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    return _parsed(stdout)


def _cursor(
    tmp_path: Path, event: str, session: str, *, source: str | None = None
) -> Mapping[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "conversation_id": session,
        "hook_event_name": event,
        "cursor_version": "3.17.8",
    }
    if source is not None:
        body["source"] = source
    stdout = io.BytesIO()
    assert (
        handle_cursor_observe(
            event_name=event,
            stdin_bytes=canonical_encode(body),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    return _parsed(stdout)


def test_private_install_advice_reaches_no_host_as_a_provider_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Absent intent stays off Codex Stop, Claude Stop, and Cursor sessionStart (#844)."""

    _install_composition(monkeypatch, [_PRIVATE])
    _consented(tmp_path)
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)

    codex_start = _codex(tmp_path, "SessionStart", "codex-private")
    codex_stop = _codex(tmp_path, "Stop", "codex-private")
    claude_stop = _claude(tmp_path, "Stop", "claude-private")
    cursor_start = _cursor(tmp_path, "sessionStart", "cursor-private", source="clear")
    cursor_stop = _cursor(tmp_path, "stop", "cursor-private")

    for emitted in (codex_start, codex_stop, claude_stop, cursor_start, cursor_stop):
        _assert_no_provider_repair(json.dumps(emitted))
    assert cursor_stop == {}
    assert "decision" not in claude_stop


def _codex_tool(root: Path, session: str) -> Mapping[str, JsonValue]:
    stdout = io.BytesIO()
    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {"session_id": session, "hook_event_name": "PostToolUse", "tool_name": "Read"}
            ),
            stdout=stdout,
            workspace=str(root),
            _state=root,
            skip_service=True,
        )
        == 0
    )
    return _parsed(stdout)


def _claude_tool(root: Path, session: str, tool_use_id: str) -> Mapping[str, JsonValue]:
    stdout = io.BytesIO()
    assert (
        handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {
                    "session_id": session,
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Read",
                    "tool_use_id": tool_use_id,
                }
            ),
            stdout=stdout,
            workspace=str(root),
            _state=root,
            observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            skip_service=True,
        )
        == 0
    )
    return _parsed(stdout)


def _host_root(tmp_path: Path, name: str) -> Path:
    root = tmp_path / name
    root.mkdir(mode=0o700)
    return root


def test_intended_unusable_provider_uses_each_hosts_advice_channel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Effective intent with no usable factory still asks each host, on its own channel (#844).

    No host receives it at Stop; Codex and Claude Code get it on the first tool event after the
    Stop that withheld it, Cursor at sessionStart (#985).
    """

    facts = [_PRIVATE]
    _install_composition(monkeypatch, facts)
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    codex_root = _host_root(tmp_path, "codex")
    claude_root = _host_root(tmp_path, "claude")
    cursor_root = _host_root(tmp_path, "cursor")
    codex_store, codex_commitment = _consented(codex_root)
    claude_store, claude_commitment = _consented(claude_root)
    cursor_store, cursor_commitment = _consented(cursor_root)

    assert "decision" not in _codex(codex_root, "SessionStart", "codex-intended")
    assert "decision" not in _claude(claude_root, "SessionStart", "claude-intended")
    cursor_session = "cursor-intended"
    assert _cursor(cursor_root, "sessionStart", cursor_session, source="clear")
    facts.append(_INTENDED_UNUSABLE)
    codex_store.refresh_advice(codex_commitment)
    claude_store.refresh_advice(claude_commitment)
    cursor_store.refresh_advice(cursor_commitment)

    codex_tool = io.BytesIO()
    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {
                    "session_id": "codex-intended",
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Read",
                }
            ),
            stdout=codex_tool,
            workspace=str(codex_root),
            _state=codex_root,
            skip_service=True,
        )
        == 0
    )
    _assert_no_provider_repair(codex_tool.getvalue().decode())
    claude_tool = io.BytesIO()
    assert (
        handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {
                    "session_id": "claude-intended",
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Read",
                    "tool_use_id": "tool-claude-intended",
                }
            ),
            stdout=claude_tool,
            workspace=str(claude_root),
            _state=claude_root,
            skip_service=True,
        )
        == 0
    )
    _assert_no_provider_repair(claude_tool.getvalue().decode())

    # Ordinary advice never rides a Stop on any host (#985): Codex would render it as
    # `decision: block` and Claude's Stop feedback also continues the turn, spending the
    # continuation the closure gate needs. Standing advice a Stop withheld rides the first
    # later PostToolUse instead, once.
    codex_stop = _codex(codex_root, "Stop", "codex-intended")
    assert codex_stop == {}
    claude_stop = _claude(claude_root, "Stop", "claude-intended")
    assert claude_stop == {}

    codex_next = _codex_tool(codex_root, "codex-intended")
    codex_context = cast(
        str, cast(Mapping[str, JsonValue], codex_next["hookSpecificOutput"])["additionalContext"]
    )
    assert "connect_provider" in codex_context
    assert "semantic:not_ready" in codex_context
    assert "decision" not in codex_next
    _assert_no_provider_repair(json.dumps(_codex_tool(codex_root, "codex-intended")))

    claude_next = _claude_tool(claude_root, "claude-intended", "tool-claude-next")
    specific = cast(Mapping[str, JsonValue], claude_next["hookSpecificOutput"])
    assert specific["hookEventName"] == "PostToolUse"
    assert "connect_provider" in cast(str, specific["additionalContext"])
    assert "semantic:not_ready" in cast(str, specific["additionalContext"])
    assert "decision" not in claude_next
    _assert_no_provider_repair(
        json.dumps(_claude_tool(claude_root, "claude-intended", "tool-claude-after"))
    )

    cursor_session_commitment = cursor_store.session_commitment(f"cursor:{cursor_session}")
    assert (
        cursor_store.peek_advice_for_delivery(
            cursor_commitment,
            allow_standing=True,
            session_commitment=cursor_session_commitment,
        )
        is not None
    )
    assert _cursor(cursor_root, "stop", cursor_session) == {}
    assert (
        cursor_store.peek_advice_for_delivery(
            cursor_commitment,
            allow_standing=True,
            session_commitment=cursor_session_commitment,
        )
        is not None
    )
    cursor_start = _cursor(cursor_root, "sessionStart", cursor_session, source="clear")
    assert "connect_provider" in cast(str, cursor_start["additional_context"])
    assert "semantic:not_ready" in cast(str, cursor_start["additional_context"])
    assert "followup_message" not in cursor_start
    assert (
        cursor_store.peek_advice_for_delivery(
            cursor_commitment,
            allow_standing=True,
            session_commitment=cursor_session_commitment,
        )
        is None
    )
