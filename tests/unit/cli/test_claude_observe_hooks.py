from __future__ import annotations

import io
import json
from collections.abc import Coroutine, Mapping
from pathlib import Path
from typing import NoReturn, cast

import pytest

from finishup.adapters.integrations.codex_lifecycle import (
    load_mapping,
    mapping_from_start_ids,
    store_mapping,
)
from finishup.adapters.integrations.observation_local import AdviceDelivery, LocalObservationStore
from finishup.cli import observe_hooks
from finishup.domain.observation import (
    AdviceSnapshot,
    ObservationControlCommand,
    ObservationRevokeCommand,
    ObservationSource,
)
from finishup.domain.observation_profiles import CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
from finishup.kernel.policies.observation_advice import ObservationCompositionFact
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, new_id


def test_claude_hook_ingress_retains_only_closed_structural_mcp_fields(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inherited = tmp_path / "inherited"
    inherited.mkdir(mode=0o700)
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", str(inherited))
    local_state = tmp_path / "local-state"
    captured: dict[str, object] = {}

    def fake_handle_observe(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    payload: dict[str, JsonValue] = {
        "cwd": "/private/project",
        "hook_event_name": "PostToolUse",
        "permission_mode": "bypassPermissions",
        "session_id": "session-1",
        "tool_input": {"secret": "private prompt"},
        "tool_name": "mcp__plugin_finishup_finishup__start",
        "tool_response": {"content": "private output"},
        "tool_use_id": "tool-1",
        "transcript_path": "/private/transcript.jsonl",
    }

    assert (
        observe_hooks.handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(payload),
            stdout=io.BytesIO(),
            workspace=".",
            _state=local_state,
        )
        == 0
    )
    sanitized = strict_json_parse(cast(bytes, captured["stdin_bytes"]))
    assert isinstance(sanitized, Mapping)
    assert sanitized == {
        "action": "claude_mcp_success",
        "correlation_kind": "tool_call_id",
        "hook_event_name": "PostToolUse",
        "pairing_mode": "post_only",
        "session_id": "claude:session-1",
        "success": True,
        "tool_name": "mcp__plugin_finishup_finishup__start",
        "tool_use_id": "tool-1",
    }
    assert captured["source"] is ObservationSource.CLAUDE_HOOK
    assert _recorded_diagnostics(local_state) == [("start_bind_unparsed", "PostToolUse")]
    assert list(inherited.iterdir()) == []


@pytest.mark.parametrize("event_name", ["SubagentStart", "SubagentStop"])
def test_claude_native_child_ingress_keeps_child_identity_without_parent_tool(
    monkeypatch: pytest.MonkeyPatch,
    event_name: str,
) -> None:
    captured: dict[str, object] = {}

    def fake_handle_observe(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    payload: dict[str, JsonValue] = {
        "agent_id": "claude-agent-1",
        "agent_type": "general-purpose",
        "agent_transcript_path": "/private/agent-transcript.jsonl",
        "cwd": "/private/project",
        "hook_event_name": event_name,
        "permission_mode": "dontAsk",
        "session_id": "claude-parent-session",
        "transcript_path": "/private/transcript.jsonl",
    }

    assert (
        observe_hooks.handle_claude_observe(
            event_name=event_name,
            stdin_bytes=canonical_encode(payload),
            stdout=io.BytesIO(),
        )
        == 0
    )
    sanitized = strict_json_parse(cast(bytes, captured["stdin_bytes"]))
    assert isinstance(sanitized, Mapping)
    assert sanitized == {
        "action": "claude_subagent",
        "correlation_kind": "tool_call_id",
        "hook_event_name": event_name,
        "pairing_mode": "post_only",
        "session_id": "claude:claude-parent-session",
        "subagent_id": "claude-agent-1",
    }
    assert captured["source"] is ObservationSource.CLAUDE_HOOK


@pytest.mark.parametrize(
    "tool_name",
    # The legacy plugin scope a 0.1-0.2.5 plugin still installs binds alike (ADR-048).
    ["mcp__plugin_finishup_finishup__start", "mcp__plugin_yoetz_yoetz__start"],
)
@pytest.mark.parametrize("response_shape", ["structured", "content_blocks", "json_string"])
def test_claude_successful_start_binds_only_structural_mapping(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    response_shape: str,
    tool_name: str,
) -> None:
    captured: dict[str, object] = {}

    def fake_handle_observe(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    start_result: dict[str, JsonValue] = {
        "ok": True,
        "task_id": "tsk_11111111-1111-4111-8111-111111111111",
        "session_id": "ses_22222222-2222-4222-8222-222222222222",
        "writer_id": "wri_33333333-3333-4333-8333-333333333333",
        "frontier": {"sequence": "4", "head_digest": "sha256:" + "a" * 64},
    }
    tool_response: JsonValue
    if response_shape == "structured":
        tool_response = {"structuredContent": start_result}
    elif response_shape == "content_blocks":
        tool_response = [{"type": "text", "text": canonical_encode(start_result).decode("utf-8")}]
    else:
        # The live Claude Code 2.1.251 shape: the structured MCP result serialized as one
        # bare JSON string, key order as the server emitted it (captured 2026-09-04, #581).
        tool_response = json.dumps(start_result, separators=(",", ":"))
    payload: dict[str, JsonValue] = {
        "hook_event_name": "PostToolUse",
        "session_id": "session-bind",
        "tool_name": tool_name,
        "tool_response": tool_response,
        "tool_use_id": "tool-bind",
    }

    assert (
        observe_hooks.handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(payload),
            stdout=io.BytesIO(),
            workspace=".",
            _state=tmp_path,
        )
        == 0
    )
    mapping = load_mapping("claude:session-bind", _state=tmp_path)
    assert mapping is not None
    assert mapping.finishup_task_id == start_result["task_id"]
    assert mapping.finishup_session_id == start_result["session_id"]
    assert mapping.finishup_writer_id == start_result["writer_id"]
    assert mapping.last_frontier == "4:sha256:" + "a" * 64

    sanitized = strict_json_parse(cast(bytes, captured["stdin_bytes"]))
    assert isinstance(sanitized, Mapping)
    assert "tool_response" not in sanitized
    assert "task_id" not in sanitized
    assert "writer_id" not in sanitized


def test_claude_failed_or_non_start_result_creates_no_mapping(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_handle_observe(**_kwargs: object) -> int:
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    for index, (tool_name, response) in enumerate(
        (
            ("mcp__plugin_finishup_finishup__start", {"structuredContent": {"ok": False}}),
            (
                "mcp__plugin_finishup_finishup__status",
                {
                    "structuredContent": {
                        "ok": True,
                        "task_id": "tsk_11111111-1111-4111-8111-111111111111",
                        "session_id": "ses_22222222-2222-4222-8222-222222222222",
                        "writer_id": "wri_33333333-3333-4333-8333-333333333333",
                    }
                },
            ),
        )
    ):
        session = f"session-negative-{index}"
        observe_hooks.handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {
                    "hook_event_name": "PostToolUse",
                    "session_id": session,
                    "tool_name": tool_name,
                    "tool_response": response,
                }
            ),
            stdout=io.BytesIO(),
            _state=tmp_path,
        )
        assert load_mapping(f"claude:{session}", _state=tmp_path) is None


def test_claude_live_2_1_251_start_tool_response_binds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Pin the exact `tool_response` Claude Code 2.1.251 passes for a scoped start (#581).

    Captured on 2026-09-04 from a live PostToolUse hook (probe MCP server returning a
    non-JSON text block plus structuredContent): the host forwards the structured result
    as a bare compact JSON string and drops the text block. A binder regression on this
    shape leaves every Claude session observed under its auto-attached task.
    """

    from tests.unit.cli.test_hooks import CLAUDE_2_1_251_START_TOOL_RESPONSE

    def fake_handle_observe(**_kwargs: object) -> int:
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    assert (
        observe_hooks.handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {
                    "hook_event_name": "PostToolUse",
                    "session_id": "session-live",
                    "tool_name": "mcp__plugin_finishup_finishup__start",
                    "tool_response": CLAUDE_2_1_251_START_TOOL_RESPONSE,
                    "tool_use_id": "toolu_01Axu9wAQ7QBfVTEdkWoorSK",
                }
            ),
            stdout=io.BytesIO(),
            workspace=".",
            _state=tmp_path,
        )
        == 0
    )
    mapping = load_mapping("claude:session-live", _state=tmp_path)
    assert mapping is not None
    assert mapping.finishup_task_id == "tsk_00000000-0000-4000-8000-000000000001"
    assert mapping.finishup_session_id == "ses_00000000-0000-4000-8000-000000000002"
    assert mapping.finishup_writer_id == "wri_00000000-0000-4000-8000-000000000003"
    assert mapping.last_frontier == "1:sha256:" + "a" * 64


@pytest.mark.parametrize("tool_response", ["RESPONSE_CANARY", "{}", '{"ok":1}'])
def test_claude_unbound_start_result_records_typed_diagnostic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tool_response: str
) -> None:
    """A scoped start post-hook that cannot bind leaves a visible, payload-free trace (#581)."""

    def fake_handle_observe(**_kwargs: object) -> int:
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    out = io.BytesIO()
    assert (
        observe_hooks.handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {
                    "hook_event_name": "PostToolUse",
                    "session_id": "session-unbound",
                    "tool_name": "mcp__plugin_finishup_finishup__start",
                    "tool_response": tool_response,
                    "tool_use_id": "tool-unbound",
                }
            ),
            stdout=out,
            workspace=".",
            _state=tmp_path,
        )
        == 0
    )
    assert load_mapping("claude:session-unbound", _state=tmp_path) is None
    diagnostics = (tmp_path / "observation" / "hook-diagnostics.jsonl").read_text()
    assert diagnostics.count('"reason":"start_bind_unparsed"') == 1
    assert "RESPONSE_CANARY" not in diagnostics


def test_claude_capability_profile_requires_exact_evidenced_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[Mapping[str, JsonValue]] = []

    def fake_handle_observe(**kwargs: object) -> int:
        value = strict_json_parse(cast(bytes, kwargs["stdin_bytes"]))
        assert isinstance(value, Mapping)
        captured.append(cast(Mapping[str, JsonValue], value))
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    for version, expected in (
        ("2.1.241", "claude-code-cli-local-project-2.1.241"),
        # A neighboring version whose contract was never proven stays
        # explicitly untested rather than emitting evidence for the 2.1.241
        # profile. An omitted version uses the legacy carrier fallback and is
        # therefore represented by an omitted profile field.
        ("2.1.240", "untested"),
        (None, None),
    ):
        payload: dict[str, JsonValue] = {
            "hook_event_name": "Stop",
            "session_id": "session-version",
        }
        if version is not None:
            payload["claude_code_version"] = version
        assert (
            observe_hooks.handle_claude_observe(
                event_name="Stop",
                stdin_bytes=canonical_encode(payload),
                stdout=io.BytesIO(),
            )
            == 0
        )
        assert captured[-1].get("capability_profile_id") == expected
        assert captured[-1]["pairing_mode"] == (
            "post_only" if version in {"2.1.241", None} else "paired"
        )


def test_claude_read_guidance_calls_survive_the_scoped_ingress_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[Mapping[str, JsonValue]] = []

    def fake_handle_observe(**kwargs: object) -> int:
        value = strict_json_parse(cast(bytes, kwargs["stdin_bytes"]))
        assert isinstance(value, Mapping)
        captured.append(cast(Mapping[str, JsonValue], value))
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    payload: dict[str, JsonValue] = {
        "hook_event_name": "PostToolUse",
        "session_id": "session-guidance",
        "tool_name": "mcp__plugin_finishup_finishup__read_guidance",
        "tool_use_id": "tool-guidance",
    }
    assert (
        observe_hooks.handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(payload),
            stdout=io.BytesIO(),
        )
        == 0
    )
    assert captured[0]["tool_name"] == "mcp__plugin_finishup_finishup__read_guidance"


def test_claude_failure_discards_raw_error_and_bare_mcp_names_are_negative_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[Mapping[str, JsonValue]] = []

    def fake_handle_observe(**kwargs: object) -> int:
        value = strict_json_parse(cast(bytes, kwargs["stdin_bytes"]))
        assert isinstance(value, Mapping)
        captured.append(cast(Mapping[str, JsonValue], value))
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    failure: dict[str, JsonValue] = {
        "error": "secret exception",
        "hook_event_name": "PostToolUseFailure",
        "session_id": "session-2",
        "tool_input": {"prompt": "private"},
        "tool_name": "mcp__plugin_finishup_finishup__publish_work",
        "tool_use_id": "tool-2",
    }
    assert (
        observe_hooks.handle_claude_observe(
            event_name="PostToolUseFailure",
            stdin_bytes=canonical_encode(failure),
            stdout=io.BytesIO(),
        )
        == 0
    )
    assert captured[0]["hook_event_name"] == "PostToolUse"
    assert captured[0]["success"] is False
    assert "error" not in captured[0]

    bare = {**failure, "tool_name": "mcp__finishup__publish_work"}
    assert (
        observe_hooks.handle_claude_observe(
            event_name="PostToolUseFailure",
            stdin_bytes=canonical_encode(cast(JsonValue, bare)),
            stdout=io.BytesIO(),
        )
        == 0
    )
    assert len(captured) == 1


def test_claude_session_source_is_closed_and_content_never_survives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[Mapping[str, JsonValue]] = []

    def fake_handle_observe(**kwargs: object) -> int:
        value = strict_json_parse(cast(bytes, kwargs["stdin_bytes"]))
        assert isinstance(value, Mapping)
        captured.append(cast(Mapping[str, JsonValue], value))
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    for source in ("resume", "attacker-controlled"):
        payload: dict[str, JsonValue] = {
            "cwd": "/private/project",
            "hook_event_name": "SessionStart",
            "session_id": f"session-{source}",
            "source": source,
            "transcript_path": "/private/transcript.jsonl",
        }
        observe_hooks.handle_claude_observe(
            event_name="SessionStart",
            stdin_bytes=canonical_encode(payload),
            stdout=io.BytesIO(),
        )

    assert captured[0]["action"] == "claude_session_resume"
    assert captured[1]["action"] == "claude_session"
    for item in captured:
        assert "cwd" not in item
        assert "source" not in item
        assert "transcript_path" not in item


def test_claude_stop_retains_only_the_boolean_loop_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[Mapping[str, JsonValue]] = []

    def fake_handle_observe(**kwargs: object) -> int:
        value = strict_json_parse(cast(bytes, kwargs["stdin_bytes"]))
        assert isinstance(value, Mapping)
        captured.append(cast(Mapping[str, JsonValue], value))
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    for value in (True, False, "true"):
        observe_hooks.handle_claude_observe(
            event_name="Stop",
            stdin_bytes=canonical_encode(
                {
                    "hook_event_name": "Stop",
                    "session_id": "session-stop",
                    "stop_hook_active": value,
                }
            ),
            stdout=io.BytesIO(),
        )

    assert captured[0]["stop_hook_active"] is True
    assert "stop_hook_active" not in captured[1]
    assert "stop_hook_active" not in captured[2]


def _consented_store(tmp_path: Path) -> tuple[LocalObservationStore, str]:
    store = LocalObservationStore(_state=tmp_path)
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)
    return store, commitment


def _recorded_diagnostics(tmp_path: Path) -> list[tuple[str, str]]:
    path = tmp_path / "observation/hook-diagnostics.jsonl"
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    return [(row["reason"], row["event"]) for row in rows if "reason" in row]


def test_claude_real_ingress_session_start_emits_native_context_and_privacy_canaries(
    tmp_path: Path,
) -> None:
    """The unstubbed ingress stores one structural envelope and answers in Claude's contract."""

    store, commitment = _consented_store(tmp_path)
    stdout = io.BytesIO()
    canaries: dict[str, JsonValue] = {
        "cwd": "/private/CWD_CANARY",
        "transcript_path": "/private/TRANSCRIPT_CANARY.jsonl",
        "prompt": "PROMPT_CANARY",
        "tool_input": {"command": "INPUT_CANARY"},
        "tool_response": "RESPONSE_CANARY",
    }
    payload: dict[str, JsonValue] = {
        "session_id": "claude-real-start",
        "hook_event_name": "SessionStart",
        "source": "startup",
        "claude_code_version": "2.1.241",
        **canaries,
    }
    assert (
        observe_hooks.handle_claude_observe(
            event_name="SessionStart",
            stdin_bytes=canonical_encode(payload),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    emitted = cast(Mapping[str, JsonValue], strict_json_parse(stdout.getvalue()))
    assert set(emitted) == {"hookSpecificOutput"}
    specific = cast(Mapping[str, JsonValue], emitted["hookSpecificOutput"])
    assert specific["hookEventName"] == "SessionStart"
    assert "no ledger task is mapped yet" in cast(str, specific["additionalContext"])

    envelopes = store.list_envelopes(commitment)
    assert len(envelopes) == 1
    assert envelopes[0].source is ObservationSource.CLAUDE_HOOK
    structural = envelopes[0].structural_payload
    assert structural["capability_profile_id"] == "claude-code-cli-local-project-2.1.241"
    assert structural["hook_name"] == "SessionStart"
    state_bytes = b"".join(
        path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    for canary in (
        "CWD_CANARY",
        "TRANSCRIPT_CANARY",
        "PROMPT_CANARY",
        "INPUT_CANARY",
        "RESPONSE_CANARY",
    ):
        assert canary.encode() not in canonical_encode(structural)
        assert canary.encode() not in state_bytes
        assert canary.encode() not in stdout.getvalue()
    assert _recorded_diagnostics(tmp_path) == []


def test_claude_received_clear_clears_existing_lifecycle_mapping(tmp_path: Path) -> None:
    """The closed Claude source=clear flag reaches the shared mapping fence."""

    _store, _commitment = _consented_store(tmp_path)
    session = "claude:received-clear"
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=session,
            finishup_task_id=new_id(IdKind.TASK),
            finishup_session_id=new_id(IdKind.SESSION),
            finishup_writer_id=new_id(IdKind.WRITER),
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    assert load_mapping(session, _state=tmp_path) is not None

    assert (
        observe_hooks.handle_claude_observe(
            event_name="SessionStart",
            stdin_bytes=canonical_encode(
                {
                    "hook_event_name": "SessionStart",
                    "session_id": "received-clear",
                    "source": "clear",
                }
            ),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert load_mapping(session, _state=tmp_path) is None


def test_claude_received_clear_does_not_reopen_service_or_advisory(tmp_path: Path) -> None:
    """The native clear action fences locally without a later status or attach RPC."""

    _store, _commitment = _consented_store(tmp_path)
    session = "claude:received-clear-service"
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=session,
            finishup_task_id=new_id(IdKind.TASK),
            finishup_session_id=new_id(IdKind.SESSION),
            finishup_writer_id=new_id(IdKind.WRITER),
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    connects: list[object] = []

    async def forbidden_connect(_kind: object) -> NoReturn:
        connects.append(_kind)
        raise AssertionError("native clear must not reopen the service")

    stdout = io.BytesIO()
    assert (
        observe_hooks.handle_claude_observe(
            event_name="SessionStart",
            stdin_bytes=canonical_encode(
                {
                    "hook_event_name": "SessionStart",
                    "session_id": "received-clear-service",
                    "source": "clear",
                }
            ),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            connect=forbidden_connect,
            skip_service=False,
        )
        == 0
    )
    assert connects == []
    assert load_mapping(session, _state=tmp_path) is None
    assert stdout.getvalue() in {b"{}\n", b""}


def test_claude_failure_advice_preserves_raw_event_and_commits_after_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The host sees PostToolUseFailure even though FinishUP uses PostToolUse cadence internally."""

    store, commitment = _consented_store(tmp_path)
    advice = AdviceDelivery(
        snapshot=cast(AdviceSnapshot, object()),
        item=None,
        delivery_identity="failure-advice-1",
        text="Review the failed FinishUP operation before continuing.",
    )
    commits: list[str] = []

    def fake_peek(
        self: LocalObservationStore,
        workspace: str,
        *,
        finishup_session_id: str | None = None,
        allow_standing: bool = True,
        session_commitment: str | None = None,
    ) -> AdviceDelivery:
        del self, workspace, finishup_session_id, allow_standing, session_commitment
        return advice

    def fake_commit(
        self: LocalObservationStore,
        workspace: str,
        identity: str,
        *,
        finishup_session_id: str | None = None,
        session_commitment: str | None = None,
    ) -> None:
        del self, workspace, finishup_session_id, session_commitment
        commits.append(identity)

    monkeypatch.setattr(LocalObservationStore, "peek_advice_for_delivery", fake_peek)
    monkeypatch.setattr(LocalObservationStore, "commit_advice_delivery", fake_commit)
    stdout = io.BytesIO()
    assert (
        observe_hooks.handle_claude_observe(
            event_name="PostToolUseFailure",
            stdin_bytes=canonical_encode(
                {
                    "hook_event_name": "PostToolUseFailure",
                    "session_id": "claude-failure-advice",
                    "tool_name": "Bash",
                    "tool_use_id": "tool-failure-advice",
                }
            ),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            skip_service=True,
        )
        == 0
    )
    emitted = cast(Mapping[str, JsonValue], strict_json_parse(stdout.getvalue()))
    specific = cast(Mapping[str, JsonValue], emitted["hookSpecificOutput"])
    assert specific["hookEventName"] == "PostToolUseFailure"
    context = cast(str, specific["additionalContext"])
    assert context.startswith("Review the failed FinishUP operation before continuing.")
    # The paired ordinary profile saw no pre for this call. The orphan remains a
    # standing coverage record and is not injected into hook context (#974).
    assert "FinishUP notice (no response needed)" not in context
    assert commits == ["failure-advice-1"]
    envelope = store.list_envelopes(commitment)[0]
    assert envelope.structural_payload["hook_name"] == "PostToolUse"
    assert envelope.structural_payload["success"] is False


def test_claude_plugin_tool_does_not_lease_frontier_advice_for_its_own_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Claude's plugin-scoped spelling participates in the shared self-call guard."""

    store, commitment = _consented_store(tmp_path)
    session = "claude:plugin-self-advice"
    store.bind_codex_session(commitment, session)
    store.note_frontier_motion(
        commitment,
        session,
        from_sequence=1,
        to_sequence=2,
        head_digest="sha256:" + "3" * 64,
        observation_record_count=1,
        task_id="tsk_claude_self_advice",
    )
    lease_calls: list[str] = []
    original_lease = LocalObservationStore.advice_delivery_lease

    def tracked_lease(self: LocalObservationStore, workspace: str) -> object:
        lease_calls.append(workspace)
        return original_lease(self, workspace)

    monkeypatch.setattr(LocalObservationStore, "advice_delivery_lease", tracked_lease)
    stdout = io.BytesIO()
    assert (
        observe_hooks.handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {
                    "hook_event_name": "PostToolUse",
                    "session_id": "plugin-self-advice",
                    "tool_name": "mcp__plugin_finishup_finishup__publish_work",
                    "tool_use_id": "tool-plugin-self-advice",
                    "tool_response": {},
                }
            ),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert stdout.getvalue() == b"{}\n"
    assert lease_calls == []
    assert store.peek_frontier_motion(commitment, session) is not None


def test_claude_stop_withholds_ordinary_advice_for_the_next_session_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Claude Stop feedback continues the turn, so ordinary advice waits (#420, #985).

    Claude Code's Stop ``additionalContext`` is non-error feedback, but the conversation still
    continues so Claude can act on it: it spends the continuation the closure gate needs, and
    the next Stop arrives with ``stop_hook_active``. Advice stays pending and reaches the agent
    on the next SessionStart through the same additionalContext channel.
    """

    store, commitment = _consented_store(tmp_path)
    # SessionStart would deliver any advice pending at that moment together
    # with the attach advisory, so the not-ready provider fact only appears
    # after the session is bound: the Stop pass is then the first delivery.
    compositions = [
        ObservationCompositionFact(
            semantic_configured=False,
            semantic_ready=False,
            provider_factory_ids=(),
            connected_provider_ids=(),
        )
    ]
    original_refresh = LocalObservationStore.refresh_advice

    def refresh_with_composition(
        self: LocalObservationStore, workspace: str, **kwargs: object
    ) -> object:
        kwargs.setdefault("composition", compositions[-1])
        return original_refresh(self, workspace, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(LocalObservationStore, "refresh_advice", refresh_with_composition)
    session = "claude-stop-advice"
    start_out = io.BytesIO()
    assert (
        observe_hooks.handle_claude_observe(
            event_name="SessionStart",
            stdin_bytes=canonical_encode(
                {"session_id": session, "hook_event_name": "SessionStart", "source": "startup"}
            ),
            stdout=start_out,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    session_commitment = store.session_commitment(f"claude:{session}")
    assert store.peek_advice_for_delivery(commitment, session_commitment=session_commitment) is None
    compositions.append(
        ObservationCompositionFact(
            semantic_configured=True,
            semantic_ready=False,
            provider_factory_ids=("fireworks",),
            connected_provider_ids=(),
        )
    )
    store.refresh_advice(commitment)
    assert (
        store.peek_advice_for_delivery(
            commitment, allow_standing=True, session_commitment=session_commitment
        )
        is not None
    )

    stop_out = io.BytesIO()
    assert (
        observe_hooks.handle_claude_observe(
            event_name="Stop",
            stdin_bytes=canonical_encode(
                {"session_id": session, "hook_event_name": "Stop", "stop_hook_active": False}
            ),
            stdout=stop_out,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert stop_out.getvalue() == b"{}\n"
    assert (
        store.peek_advice_for_delivery(
            commitment, allow_standing=True, session_commitment=session_commitment
        )
        is not None
    )

    # A second Stop in the same host loop is the documented loop guard: nothing
    # is re-delivered and the output stays empty.
    guarded_out = io.BytesIO()
    assert (
        observe_hooks.handle_claude_observe(
            event_name="Stop",
            stdin_bytes=canonical_encode(
                {"session_id": session, "hook_event_name": "Stop", "stop_hook_active": True}
            ),
            stdout=guarded_out,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert guarded_out.getvalue() == b"{}\n"

    resume_out = io.BytesIO()
    assert (
        observe_hooks.handle_claude_observe(
            event_name="SessionStart",
            stdin_bytes=canonical_encode(
                {"session_id": session, "hook_event_name": "SessionStart", "source": "resume"}
            ),
            stdout=resume_out,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    resumed = cast(Mapping[str, JsonValue], strict_json_parse(resume_out.getvalue()))
    specific = cast(Mapping[str, JsonValue], resumed["hookSpecificOutput"])
    assert specific["hookEventName"] == "SessionStart"
    assert "connect_provider" in cast(str, specific["additionalContext"])
    assert b"decision" not in resume_out.getvalue()


@pytest.mark.parametrize(
    ("workspace", "expected"),
    [
        pytest.param("", "workspace_unresolvable", id="empty-locator-from-unset-project-dir"),
        pytest.param("/private/does-not-exist/CANARY", "workspace_unresolvable", id="missing"),
        pytest.param(None, "workspace_unconsented", id="unconsented-explicit"),
    ],
)
def test_claude_ingress_records_a_typed_diagnostic_when_nothing_is_ingested(
    tmp_path: Path, workspace: str | None, expected: str
) -> None:
    """A fail-open `{}` still leaves a payload-free trace naming the dropped layer (#435)."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path) if workspace is None else workspace
    stdout = io.BytesIO()
    assert (
        observe_hooks.handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {
                    "session_id": "claude-dropped",
                    "hook_event_name": "PostToolUse",
                    "tool_name": "mcp__plugin_finishup_finishup__status",
                    "cwd": "/private/CWD_CANARY",
                }
            ),
            stdout=stdout,
            workspace=locator,
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert stdout.getvalue() == b"{}\n"
    assert _recorded_diagnostics(tmp_path) == [(expected, "PostToolUse")]
    assert store.list_envelopes(store.workspace_commitment(str(tmp_path.resolve()))) == ()
    diagnostics_bytes = (tmp_path / "observation/hook-diagnostics.jsonl").read_bytes()
    for canary in (b"CANARY", b"does-not-exist", str(tmp_path).encode()):
        assert canary not in diagnostics_bytes


def test_claude_ingress_names_paused_consent_distinctly(tmp_path: Path) -> None:
    store, commitment = _consented_store(tmp_path)
    store.pause(ObservationControlCommand(commitment))
    stdout = io.BytesIO()
    assert (
        observe_hooks.handle_claude_observe(
            event_name="SessionStart",
            stdin_bytes=canonical_encode(
                {"session_id": "claude-paused", "hook_event_name": "SessionStart"}
            ),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert stdout.getvalue() == b"{}\n"
    assert _recorded_diagnostics(tmp_path) == [("paused", "SessionStart")]

    # Revocation keeps the pause flag in the stored record; the diagnostic must
    # still say unconsented, as the `observe status` consent label does.
    store.revoke(ObservationRevokeCommand(commitment, retain_evidence=True))
    assert (
        observe_hooks.handle_claude_observe(
            event_name="SessionStart",
            stdin_bytes=canonical_encode(
                {"session_id": "claude-revoked", "hook_event_name": "SessionStart"}
            ),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert _recorded_diagnostics(tmp_path)[-1] == ("workspace_unconsented", "SessionStart")


@pytest.mark.parametrize(
    ("tool_name", "source", "expected"),
    [
        ("mcp__finishup__check", "auto_mode", "host_auto_review_denied"),
        ("mcp__plugin_finishup_finishup__check", None, "host_auto_review_denied"),
        ("mcp__finishup__check", "permission_rule", "host_permission_rule_denied"),
        ("mcp__plugin_finishup_finishup__check", "hook", "host_permission_rule_denied"),
        # The legacy server scopes a 0.1-0.2.5 registration still carries (ADR-048).
        ("mcp__yoetz__check", "auto_mode", "host_auto_review_denied"),
        ("mcp__plugin_yoetz_yoetz__check", "permission_rule", "host_permission_rule_denied"),
    ],
)
def test_claude_permission_denied_on_a_scoped_check_records_one_payload_free_diagnostic(
    tmp_path: Path, tool_name: str, source: str | None, expected: str
) -> None:
    """A host reviewer held the check before FinishUP saw it (issue #467).

    The typed reason is the separate representation #187 asked for: it is host tool-call
    authorization, never an AI-powered review status, and nothing from the host payload survives.
    """

    store, _commitment = _consented_store(tmp_path)
    payload: dict[str, object] = {
        "session_id": "claude-denied",
        "hook_event_name": "PermissionDenied",
        "tool_name": tool_name,
        "tool_input": {"claim": "CLAIM_CANARY"},
        "tool_use_id": "toolu_CANARY",
        "reason": "classifier_denied",
        "cwd": "/private/CWD_CANARY",
        "permission_mode": "auto",
    }
    if source is not None:
        payload["source"] = source
    stdout = io.BytesIO()
    assert (
        observe_hooks.handle_claude_observe(
            event_name="PermissionDenied",
            stdin_bytes=canonical_encode(cast(JsonValue, payload)),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    # With the service skipped the grant is unread, so the advisory tells the agent to stop and
    # ask, offers no retry, and names the closed reason (issue #857).
    emitted = strict_json_parse(stdout.getvalue())
    assert isinstance(emitted, Mapping)
    specific = emitted["hookSpecificOutput"]
    assert isinstance(specific, Mapping)
    assert specific["hookEventName"] == "PermissionDenied"
    assert specific["retry"] is False
    context = emitted["systemMessage"]
    assert isinstance(context, str)
    if source in {"permission_rule", "hook"}:
        assert context.startswith("FinishUP: the owner's own Claude Code permission rule")
        advisory_diagnostic = "host_denial_retry_exhausted"
    else:
        assert "could not confirm a repository grant" in context
        assert "(reason: service_skipped)" in context
        advisory_diagnostic = "host_denial_grant_unconfirmed"
    assert "do not retry" in context.lower()
    assert isinstance(emitted["systemMessage"], str)
    assert _recorded_diagnostics(tmp_path) == [
        (expected, "PermissionDenied"),
        (advisory_diagnostic, "PermissionDenied"),
    ]
    assert store.list_envelopes(store.workspace_commitment(str(tmp_path.resolve()))) == ()
    diagnostics_bytes = (tmp_path / "observation/hook-diagnostics.jsonl").read_bytes()
    for canary in (b"CANARY", b"classifier_denied", str(tmp_path).encode()):
        assert canary not in diagnostics_bytes
        assert canary not in stdout.getvalue()


class _FakePrivacyClient:
    def __init__(self, setup: object, *, error: Exception | None = None) -> None:
        self._setup = setup
        self._error = error
        self.closed = False
        self.deadlines: list[int | None] = []

    async def privacy_get_setup(self, request: object, *, deadline_ms: int | None = None) -> object:
        self.deadlines.append(deadline_ms)
        if self._error is not None:
            raise self._error
        return self._setup

    async def close(self) -> None:
        self.closed = True


def _granted_setup() -> dict[str, object]:
    return {
        "grant_state": "granted",
        "composed_policy": {
            "channel_policies": [
                {"channel": "llm_inference", "enabled": True},
                {"channel": "telemetry", "enabled": False},
            ]
        },
    }


def _run_denied_hook(
    tmp_path: Path,
    *,
    client: _FakePrivacyClient,
    session_id: str = "claude-held",
    source: str | None = "auto_mode",
    observation_profile: str | None = None,
    reason: str = "[Safety Rule]",
) -> tuple[Mapping[str, JsonValue], bytes]:
    import asyncio

    async def connect(_kind: object) -> _FakePrivacyClient:
        return client

    payload: dict[str, object] = {
        "session_id": session_id,
        "hook_event_name": "PermissionDenied",
        "tool_name": "mcp__plugin_finishup_finishup__check",
        "tool_input": {"claim": "CLAIM_CANARY"},
        "tool_use_id": "toolu_CANARY",
        "reason": reason,
        "cwd": "/private/CWD_CANARY",
        "permission_mode": "auto",
    }
    if source is not None:
        payload["source"] = source
    stdout = io.BytesIO()
    assert (
        observe_hooks.handle_claude_observe(
            event_name="PermissionDenied",
            stdin_bytes=canonical_encode(cast(JsonValue, payload)),
            stdout=stdout,
            workspace=str(tmp_path),
            observation_profile=observation_profile,
            _state=tmp_path,
            connect=cast("observe_hooks.ServiceConnector", connect),
            run_async=lambda fn: asyncio.run(cast("Coroutine[object, object, object]", fn())),
        )
        == 0
    )
    emitted = strict_json_parse(stdout.getvalue())
    assert isinstance(emitted, Mapping)
    return emitted, stdout.getvalue()


def test_claude_permission_denied_with_a_confirmed_grant_offers_exactly_one_retry(
    tmp_path: Path,
) -> None:
    """The owner already authorized review (issue #857): say so and offer the host's retry once.

    The grant is read first-hand through the repository-bound service inside the hook deadline.
    The second hold of the same session gets the same confirmation but no retry: after one retry
    the human decides, which keeps #187's "never retry until a classifier happens to allow".
    """

    _consented_store(tmp_path)
    client = _FakePrivacyClient(_granted_setup())
    first, raw = _run_denied_hook(tmp_path, client=client)
    specific = first["hookSpecificOutput"]
    assert isinstance(specific, Mapping)
    assert specific["hookEventName"] == "PermissionDenied"
    assert specific["retry"] is True
    context = first["systemMessage"]
    assert isinstance(context, str)
    assert context.startswith(
        "FinishUP confirms: the repository owner already authorized external AI-powered review"
    )
    assert "Retry the identical check exactly once now" in context
    assert "no provider dispatch occurred" in context
    assert "do not switch to deterministic_only" in context
    assert "finishup integrate claude admission grant" in context  # admission is absent here
    assert len(context) <= 2_000
    shown = first["systemMessage"]
    assert isinstance(shown, str)
    assert shown.startswith("FinishUP confirms:")
    assert "decision" not in specific and "permissionDecision" not in specific
    assert client.closed
    assert client.deadlines == [2_500]
    for canary in (b"CANARY", b"classifier_denied", str(tmp_path).encode()):
        assert canary not in raw

    second, _ = _run_denied_hook(tmp_path, client=_FakePrivacyClient(_granted_setup()))
    again = second["hookSpecificOutput"]
    assert isinstance(again, Mapping)
    assert again["retry"] is False
    repeat_context = second["systemMessage"]
    assert isinstance(repeat_context, str)
    assert repeat_context.startswith("FinishUP confirms:")
    assert "Do not retry on your own" in repeat_context

    other, _ = _run_denied_hook(
        tmp_path, client=_FakePrivacyClient(_granted_setup()), session_id="claude-other"
    )
    other_specific = other["hookSpecificOutput"]
    assert isinstance(other_specific, Mapping)
    assert other_specific["retry"] is True

    assert _recorded_diagnostics(tmp_path) == [
        ("host_auto_review_denied", "PermissionDenied"),
        ("host_denial_retry_offered", "PermissionDenied"),
        ("host_auto_review_denied", "PermissionDenied"),
        ("host_denial_retry_exhausted", "PermissionDenied"),
        ("host_auto_review_denied", "PermissionDenied"),
        ("host_denial_retry_offered", "PermissionDenied"),
    ]
    ledger = (tmp_path / "observation/host-hold-retries.json").read_bytes()
    assert b"claude-held" not in ledger and b"claude-other" not in ledger


def test_claude_permission_denied_never_retries_on_the_owners_rule_or_without_a_verdict(
    tmp_path: Path,
) -> None:
    """A confirmed grant is not enough: the owner's own rule and a no-verdict denial get no retry."""

    _consented_store(tmp_path)
    ruled, _ = _run_denied_hook(
        tmp_path, client=_FakePrivacyClient(_granted_setup()), source="permission_rule"
    )
    ruled_specific = ruled["hookSpecificOutput"]
    assert isinstance(ruled_specific, Mapping)
    assert ruled_specific["retry"] is False
    assert str(ruled["systemMessage"]).startswith(
        "FinishUP: the owner's own Claude Code permission rule"
    )
    assert not (tmp_path / "observation/host-hold-retries.json").exists()

    unverdicted, _ = _run_denied_hook(
        tmp_path,
        client=_FakePrivacyClient(_granted_setup()),
        reason="Auto mode could not evaluate this action and is blocking it for safety",
    )
    unverdicted_specific = unverdicted["hookSpecificOutput"]
    assert isinstance(unverdicted_specific, Mapping)
    assert unverdicted_specific["retry"] is False
    assert "classifier verdict was not established" in str(unverdicted["systemMessage"])
    # Neither branch consulted the retry ledger, so the session's one retry is still available.
    assert not (tmp_path / "observation/host-hold-retries.json").exists()
    assert [reason for reason, _event in _recorded_diagnostics(tmp_path)] == [
        "host_permission_rule_denied",
        "host_denial_retry_exhausted",
        "host_auto_review_denied",
        "host_denial_retry_exhausted",
    ]


@pytest.mark.parametrize(
    ("client", "expected_reason"),
    [
        (
            _FakePrivacyClient(
                {
                    "grant_state": "missing",
                    "composed_policy": {
                        "channel_policies": [{"channel": "llm_inference", "enabled": True}]
                    },
                }
            ),
            "grant_absent",
        ),
        (
            _FakePrivacyClient(
                {
                    "grant_state": "granted",
                    "composed_policy": {
                        "channel_policies": [{"channel": "llm_inference", "enabled": False}]
                    },
                }
            ),
            "grant_absent",
        ),
        (_FakePrivacyClient({"grant_state": "granted"}), "grant_unread"),
        (_FakePrivacyClient(None, error=RuntimeError("boom")), "service_unavailable"),
    ],
)
def test_claude_permission_denied_without_a_confirmed_grant_tells_the_agent_to_ask(
    tmp_path: Path, client: _FakePrivacyClient, expected_reason: str
) -> None:
    """No first-hand grant, no assertion of authorization and no retry; the reason is a token."""

    _consented_store(tmp_path)
    emitted, raw = _run_denied_hook(tmp_path, client=client)
    specific = emitted["hookSpecificOutput"]
    assert isinstance(specific, Mapping)
    assert specific["retry"] is False
    context = str(emitted["systemMessage"])
    assert context.startswith("FinishUP could not confirm a repository grant")
    assert f"(reason: {expected_reason})" in context
    assert "Authorization remains unconfirmed" in context
    assert ("finishup --privacy" in context) == (expected_reason == "grant_absent")
    assert f"(reason: {expected_reason})" in str(emitted["systemMessage"])
    assert b"boom" not in raw
    assert _recorded_diagnostics(tmp_path) == [
        ("host_auto_review_denied", "PermissionDenied"),
        ("host_denial_grant_unconfirmed", "PermissionDenied"),
    ]
    assert not (tmp_path / "observation/host-hold-retries.json").exists()


def test_claude_permission_denied_maps_control_refusals_to_closed_grant_reasons(
    tmp_path: Path,
) -> None:
    from finishup.ports.control import ControlError

    _consented_store(tmp_path)
    for control_reason, expected in (
        ("vault_locked", "vault_locked"),
        ("privacy_projection_blocked", "privacy_authority_required"),
        ("service_unavailable", "service_unavailable"),
    ):
        emitted, _ = _run_denied_hook(
            tmp_path, client=_FakePrivacyClient(None, error=ControlError(control_reason))
        )
        specific = emitted["hookSpecificOutput"]
        assert isinstance(specific, Mapping)
        assert f"(reason: {expected})" in str(emitted["systemMessage"])
        assert specific["retry"] is False


def test_claude_permission_denied_for_any_other_tool_records_nothing(tmp_path: Path) -> None:
    _consented_store(tmp_path)
    for tool_name in ("mcp__plugin_finishup_finishup__start", "Bash", "mcp__other__check"):
        stdout = io.BytesIO()
        assert (
            observe_hooks.handle_claude_observe(
                event_name="PermissionDenied",
                stdin_bytes=canonical_encode(
                    {
                        "session_id": "claude-denied",
                        "hook_event_name": "PermissionDenied",
                        "tool_name": tool_name,
                        "source": "auto_mode",
                    }
                ),
                stdout=stdout,
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
            )
            == 0
        )
        assert stdout.getvalue() == b"{}\n"
    assert not (tmp_path / "observation/hook-diagnostics.jsonl").exists()


# The legacy plugin scope a 0.1-0.2.5 plugin still installs is read alike (ADR-048).
@pytest.mark.parametrize("prefix", ["mcp__plugin_finishup_finishup__", "mcp__plugin_yoetz_yoetz__"])
def test_claude_scoped_finishup_calls_follow_the_self_observation_policy(
    tmp_path: Path, prefix: str
) -> None:
    """#564 on Claude Code: reads stay local, mutations and failures ship one row each."""

    store = LocalObservationStore(_state=tmp_path)
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)

    def hook(raw_event: str, tool: str, call: str) -> None:
        payload: dict[str, JsonValue] = {
            "cwd": str(tmp_path),
            "hook_event_name": raw_event,
            "session_id": "claude-self-observation",
            "tool_input": {"secret": "private prompt"},
            "tool_name": tool,
            "tool_response": {"content": "private output"},
            "tool_use_id": call,
        }
        assert (
            observe_hooks.handle_claude_observe(
                event_name=raw_event,
                stdin_bytes=canonical_encode(payload),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
            )
            == 0
        )

    hook("PostToolUse", f"{prefix}status", "claude-status-1")
    hook("PostToolUse", f"{prefix}receipt", "claude-receipt-1")
    hook("PostToolUse", f"{prefix}read_guidance", "claude-guidance-1")
    hook("PostToolUse", f"{prefix}respond", "claude-respond-1")
    hook("PostToolUse", f"{prefix}check", "claude-check-1")
    hook("PostToolUseFailure", f"{prefix}status", "claude-status-2")

    rows = store.list_pending_outbox_rows(commitment)
    assert [
        (row.envelope.structural_payload["tool_name"], row.envelope.structural_payload["action"])
        for row in rows
    ] == [
        (f"{prefix}respond", "claude_mcp_success"),
        (f"{prefix}check", "claude_mcp_success"),
        (f"{prefix}status", "claude_mcp_failure"),
    ]
    # Every call remains in the bounded local store as structural-only evidence.
    assert len(store.list_envelopes(commitment)) == 6


def test_claude_unknown_version_keeps_untested_token_and_paired_contract() -> None:
    """Issue #656: hook version mapping stays fail-closed. An unproven version is admitted for
    ingest under the conservative paired contract as ``untested``; it is never aliased to the
    proven 2.1.241 profile, and an omitted version takes the legacy post-only path."""

    from finishup.ports.integrations import observation_pairing_contract

    mapper = observe_hooks._claude_capability_profile_id  # pyright: ignore[reportPrivateUsage]
    assert mapper("2.1.241") == "claude-code-cli-local-project-2.1.241"
    for version in ("2.1.240", "2.1.242", "2.2.0", "3.0.0"):
        assert mapper(version) == "untested", version
        assert observation_pairing_contract("claude", "untested") == ("paired", "tool_call_id")
    assert mapper(None) is None
    assert mapper("") is None
    assert observation_pairing_contract("claude", None) == ("post_only", "tool_call_id")
    assert observation_pairing_contract("claude", "claude-code-cli-local-project-2.1.241") == (
        "post_only",
        "tool_call_id",
    )


def test_claude_ordinary_profile_keeps_denial_observation_and_returns_supported_advisory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[dict[str, object]] = []

    def observe(**kwargs: object) -> int:
        captured.append(kwargs)
        output = cast(io.BytesIO, kwargs["stdout"])
        output.write(b"{}\n")
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", observe)
    emitted, raw = _run_denied_hook(
        tmp_path,
        client=_FakePrivacyClient(_granted_setup()),
        observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    )
    assert len(captured) == 1 and captured[0]["event_name"] == "PermissionDecision"
    assert emitted["hookSpecificOutput"] == {"hookEventName": "PermissionDenied", "retry": True}
    assert "FinishUP confirms" in str(emitted["systemMessage"])
    assert len(raw.splitlines()) == 1


@pytest.mark.parametrize("mode", ["deterministic_only", "inspect"])
def test_claude_local_only_check_does_not_get_a_semantic_retry_notice(
    tmp_path: Path, mode: str
) -> None:
    """A check that asks for no AI-powered review gets no review notice or retry offer.

    ``inspect`` (#1048) is a read that runs no review either, so a denied inspection spends no
    retry offer and shows no AI-powered review notice (PR #1054 review).
    """

    output = io.BytesIO()
    payload: dict[str, JsonValue] = {
        "session_id": "local-check",
        "hook_event_name": "PermissionDenied",
        "tool_name": "mcp__finishup__check",
        "tool_input": {"mode": mode},
        "reason": "[Rule]",
    }
    assert (
        observe_hooks.handle_claude_observe(
            event_name="PermissionDenied",
            stdin_bytes=canonical_encode(payload),
            stdout=output,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert output.getvalue() == b"{}\n"
    assert not (tmp_path / "observation/host-hold-retries.json").exists()
