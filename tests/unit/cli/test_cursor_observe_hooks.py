from __future__ import annotations

import io
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from finishup.adapters.integrations.codex_lifecycle import (
    load_mapping,
    mapping_from_start_ids,
    store_mapping,
)
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.recommendations import (
    RecommendationState,
    cached_pending_recommendations,
    store_recommendation_state,
)
from finishup.cli import observe_hooks
from finishup.cli.hook_io import MAX_HOOK_SKIM_BYTES, MAX_HOOK_STDIN_BYTES
from finishup.domain.observation import (
    ObservationGapCode,
    ObservationSource,
    ObservationStatusQuery,
)
from finishup.domain.observation_profiles import CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
from finishup.kernel.policies.observation_advice import ObservationCompositionFact
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, new_id


@pytest.mark.parametrize("payload", [b"broken", b"{}", b'{"hook_event_name":"preToolUse"}'])
def test_passive_pretool_output_never_blocks_cursor(tmp_path: Path, payload: bytes) -> None:
    out = io.BytesIO()
    assert (
        observe_hooks.handle_cursor_observe(
            event_name="preToolUse",
            stdin_bytes=payload,
            stdout=out,
            _state=tmp_path,
            skip_service=True,
            observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        )
        == 0
    )
    assert json.loads(out.getvalue()) == {"permission": "allow"}


def test_passive_pretool_keeps_observation_and_emits_one_response(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    observed: list[str] = []

    def observe(**kwargs: object) -> int:
        observed.append(str(kwargs["event_name"]))
        stream = cast(io.BytesIO, kwargs["stdout"])
        stream.write(b"{}\n")
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", observe)
    out = io.BytesIO()
    observe_hooks.handle_cursor_observe(
        event_name="preToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "s",
                "conversation_id": "s",
                "workspace_roots": [str(tmp_path.resolve())],
                "tool_name": "Read",
                "tool_use_id": "call",
            }
        ).encode(),
        stdout=out,
        _state=tmp_path,
        skip_service=True,
        observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    )
    assert observed == ["PreToolUse"]
    assert out.getvalue() == b'{"permission":"allow"}\n'


def _consented_store(tmp_path: Path) -> tuple[LocalObservationStore, str]:
    store = LocalObservationStore(_state=tmp_path)
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)
    return store, commitment


def test_cursor_git_subdirectory_uses_canonical_root_consent(tmp_path: Path) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repo"
    nested = repository / "packages/app"
    nested.mkdir(parents=True)
    (repository / ".git").mkdir()
    store = LocalObservationStore(_state=state)
    root_commitment = store.workspace_commitment(str(repository))
    store.grant_consent(root_commitment)

    assert (
        observe_hooks.handle_cursor_observe(
            event_name="sessionStart",
            stdin_bytes=canonical_encode(
                {
                    "conversation_id": "cursor-git-subdirectory",
                    "hook_event_name": "sessionStart",
                    "workspace_roots": [str(nested)],
                }
            ),
            stdout=io.BytesIO(),
            workspace=str(nested),
            _state=state,
            skip_service=True,
        )
        == 0
    )

    assert (
        store.find_workspace_for_codex_session("cursor:cursor-git-subdirectory") == root_commitment
    )


def test_cursor_hook_ingress_drops_every_content_and_identity_denylist_field(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_handle_observe(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    payload: dict[str, JsonValue] = {
        "conversation_id": "cursor-session-1",
        "cursor_version": "3.17.8",
        "generation_id": "generation-1",
        "hook_event_name": "afterMCPExecution",
        "model_id": "cursor-grok-4.6-medium",
        "model_params": [{"id": "effort", "value": "medium"}],
        "tool_name": "mcp__finishup__start",
        "tool_input": "secret prompt and arguments",
        "result_json": "private tool result",
        "transcript_path": "/private/transcript.jsonl",
        "user_email": "private@example.com",
        "workspace_roots": [str(tmp_path)],
    }
    assert (
        observe_hooks.handle_cursor_observe(
            event_name="afterMCPExecution",
            stdin_bytes=canonical_encode(payload),
            workspace=str(tmp_path),
            _state=tmp_path,
        )
        == 0
    )

    sanitized = strict_json_parse(cast(bytes, captured["stdin_bytes"]))
    assert isinstance(sanitized, Mapping)
    assert sanitized["session_id"] == "cursor:cursor-session-1"
    assert sanitized["cursor_version"] == "3.17.8"
    assert sanitized["capability_profile_id"] == "cursor-ide-3.17.8"
    assert sanitized["model_id"] == "cursor-grok-4.6-medium"
    assert sanitized["model_effort"] == "medium"
    assert captured["source"] is ObservationSource.CURSOR_HOOK
    assert captured["_output_event_name"] == "afterMCPExecution"
    assert "result_status" not in sanitized
    assert "success" not in sanitized
    forbidden = {
        "tool_input",
        "result_json",
        "transcript_path",
        "user_email",
        "workspace_roots",
        "prompt",
        "response",
        "file_path",
        "edits",
    }
    assert forbidden.isdisjoint(sanitized)


@pytest.mark.parametrize(
    ("event_name", "extra", "expected_duration"),
    [
        (
            "afterMCPExecution",
            {"duration": 428.607, "model": "grok-4.6"},
            428,
        ),
        (
            "afterFileEdit",
            {"model": "grok-4.6"},
            None,
        ),
    ],
)
def test_cursor_raw_vendor_fields_reach_structural_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_name: str,
    extra: dict[str, object],
    expected_duration: int | None,
) -> None:
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    captured: dict[str, object] = {}

    def fake_handle_observe(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    payload: dict[str, object] = {
        "conversation_id": "cursor-raw-vendor-fields",
        "cursor_version": "3.17.8",
        "generation_id": "generation-1",
        "hook_event_name": event_name,
        "tool_name": "status",
        "tool_input": {"private": 1.5},
        "result_json": "private result",
        **extra,
    }

    assert (
        observe_hooks.handle_cursor_observe(
            event_name=event_name,
            stdin_bytes=json.dumps(payload, separators=(",", ":")).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
        )
        == 0
    )

    sanitized = strict_json_parse(cast(bytes, captured["stdin_bytes"]))
    assert isinstance(sanitized, Mapping)
    assert sanitized["model_id"] == "grok-4.6"
    if expected_duration is None:
        assert "duration_ms" not in sanitized
    else:
        assert sanitized["duration_ms"] == expected_duration
    assert sanitized["tool_name"] == "status"
    assert "tool_input" not in sanitized
    assert "result_json" not in sanitized


def test_cursor_model_id_takes_precedence_over_vendor_model_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_handle_observe(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    payload = json.dumps(
        {
            "conversation_id": "cursor-model-precedence",
            "hook_event_name": "stop",
            "model": "cursor-grok-4.6-medium-fast",
            "model_id": "grok-4.6",
        },
        separators=(",", ":"),
    ).encode()

    assert (
        observe_hooks.handle_cursor_observe(
            event_name="stop",
            stdin_bytes=payload,
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
        )
        == 0
    )

    sanitized = strict_json_parse(cast(bytes, captured["stdin_bytes"]))
    assert isinstance(sanitized, Mapping)
    assert sanitized["model_id"] == "grok-4.6"


def test_cursor_raw_fractional_duration_is_stored_structurally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    store, commitment = _consented_store(tmp_path)
    canaries = {
        "tool_input": {"prompt": "PROMPT_CANARY", "ratio": 1.5},
        "result_json": "RESULT_CANARY",
        "transcript_path": "/private/TRANSCRIPT_CANARY",
    }
    payload = {
        "conversation_id": "cursor-stored-fraction",
        "hook_event_name": "afterMCPExecution",
        "model": "grok-4.6",
        "duration": 428.607,
        "tool_name": "status",
        **canaries,
    }

    assert (
        observe_hooks.handle_cursor_observe(
            event_name="afterMCPExecution",
            stdin_bytes=json.dumps(payload, separators=(",", ":")).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    envelopes = store.list_envelopes(commitment)
    assert len(envelopes) == 1
    structural = envelopes[0].structural_payload
    assert structural["duration_ms"] == 428
    assert structural["model_id"] == "grok-4.6"
    assert structural["tool_name"] == "status"
    stored = b"".join(
        path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    for canary in ("PROMPT_CANARY", "RESULT_CANARY", "TRANSCRIPT_CANARY"):
        assert canary.encode() not in stored


def test_cursor_invalid_vendor_payload_records_bounded_diagnostic(
    tmp_path: Path,
) -> None:
    stdout = io.BytesIO()

    assert (
        observe_hooks.handle_cursor_observe(
            event_name="afterMCPExecution",
            stdin_bytes=b'{"conversation_id":"cursor-invalid","duration":-1.0}',
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
        )
        == 0
    )

    assert stdout.getvalue() == b"{}\n"
    diagnostic = tmp_path / "observation/hook-diagnostics.jsonl"
    row = json.loads(diagnostic.read_text(encoding="utf-8"))
    assert row == {
        "event": "PostToolUse",
        "reason": "cursor_payload_invalid",
        "ts": row["ts"],
    }
    assert "cursor-invalid" not in diagnostic.read_text(encoding="utf-8")


def test_cursor_file_edit_uses_keyed_path_commitment_and_drops_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_handle_observe(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    path = "/private/project/secret.py"
    payload: dict[str, JsonValue] = {
        "conversation_id": "cursor-session-2",
        "hook_event_name": "afterFileEdit",
        "file_path": path,
        "edits": [{"old_string": "secret", "new_string": "private"}],
    }

    assert (
        observe_hooks.handle_cursor_observe(
            event_name="afterFileEdit",
            stdin_bytes=canonical_encode(payload),
            stdout=io.BytesIO(),
            workspace=".",
            _state=tmp_path,
        )
        == 0
    )

    sanitized = strict_json_parse(cast(bytes, captured["stdin_bytes"]))
    assert isinstance(sanitized, Mapping)
    commitment = sanitized["changed_paths_digest"]
    assert isinstance(commitment, str) and commitment.startswith("hmac-sha256:")
    assert path not in canonical_encode(cast(JsonValue, sanitized)).decode("utf-8")
    assert "result_status" not in sanitized
    assert "success" not in sanitized
    assert "capability_profile_id" not in sanitized


def test_cursor_session_prefix_reserves_space_inside_token_bound(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: list[Mapping[str, JsonValue]] = []

    def fake_handle_observe(**kwargs: object) -> int:
        payload = strict_json_parse(cast(bytes, kwargs["stdin_bytes"]))
        assert isinstance(payload, Mapping)
        captured.append(payload)
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)

    for length in (121, 122):
        payload: dict[str, JsonValue] = {
            "conversation_id": "s" * length,
            "hook_event_name": "sessionStart",
        }
        assert (
            observe_hooks.handle_cursor_observe(
                event_name="sessionStart",
                stdin_bytes=canonical_encode(payload),
                stdout=io.BytesIO(),
                workspace=".",
                _state=tmp_path,
            )
            == 0
        )

    assert len(captured) == 1
    assert captured[0]["session_id"] == "cursor:" + ("s" * 121)
    assert len(cast(str, captured[0]["session_id"])) == 128


def test_cursor_cached_recommendation_uses_cursor_session_start_renderer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real ingress must emit Cursor's raw event contract, not Codex's envelope."""

    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    store = LocalObservationStore(_state=tmp_path)
    store.set_runtime_enabled(False)
    store_recommendation_state(
        RecommendationState(last_evaluated_version="0.1.0", pending=("observation-enabled",)),
        root=tmp_path,
    )
    stdout = io.BytesIO()

    assert (
        observe_hooks.handle_cursor_observe(
            event_name="sessionStart",
            stdin_bytes=canonical_encode(
                {
                    "conversation_id": "cursor-cache",
                    "hook_event_name": "sessionStart",
                    "cursor_version": "3.17.8",
                }
            ),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
        )
        == 0
    )

    emitted = json.loads(stdout.getvalue())
    assert set(emitted) == {"additional_context"}
    assert "Enable local observation" in emitted["additional_context"]
    assert "hookSpecificOutput" not in emitted

    # A Cursor event without a consumable stdout channel cannot spend the same
    # cached recommendation or manufacture a follow-up message.
    stdout = io.BytesIO()
    assert (
        observe_hooks.handle_cursor_observe(
            event_name="afterMCPExecution",
            stdin_bytes=canonical_encode(
                {
                    "conversation_id": "cursor-cache",
                    "hook_event_name": "afterMCPExecution",
                    "cursor_version": "3.17.8",
                }
            ),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
        )
        == 0
    )
    assert json.loads(stdout.getvalue()) == {}
    assert cached_pending_recommendations(root=tmp_path, limit=1)


@pytest.mark.parametrize(
    ("cursor_version", "profile"),
    [
        ("3.17.8", "cursor-ide-3.17.8"),
        ("2026.07.09-a3815c0", "untested"),
        ("1.0.24", "untested"),
        ("999.0", "untested"),
    ],
)
def test_cursor_real_ingress_uses_bounded_profile_and_privacy_canaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cursor_version: str,
    profile: str,
) -> None:
    monkeypatch.setenv("CURSOR_PROJECT_DIR", str(tmp_path))
    store, commitment = _consented_store(tmp_path)
    stdout = io.BytesIO()
    other_root = tmp_path / "ROOT_CANARY"
    other_root.mkdir()
    canaries: dict[str, JsonValue] = {
        "tool_input": "PROMPT_CANARY",
        "result_json": "RESULT_CANARY",
        "transcript_path": "/private/TRANSCRIPT_CANARY",
        "user_email": "EMAIL_CANARY@example.com",
        "file_path": "/private/FILE_CANARY.py",
        "edits": [{"old_string": "OLD_CANARY", "new_string": "NEW_CANARY"}],
        "workspace_roots": [str(tmp_path), str(other_root)],
    }
    payload: dict[str, JsonValue] = {
        "conversation_id": "cursor-real-profile",
        "hook_event_name": "sessionStart",
        "source": "clear",
        "cursor_version": cursor_version,
        **canaries,
    }

    assert (
        observe_hooks.handle_cursor_observe(
            event_name="sessionStart",
            stdin_bytes=canonical_encode(payload),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    emitted = json.loads(stdout.getvalue())
    assert set(emitted) == {"additional_context"}
    assert "no ledger task is mapped yet" in emitted["additional_context"]
    context = emitted["additional_context"]
    assert "After guidance reads, tool/schema discovery" in context
    assert "call start to attach a task before substantive material work" in context
    assert "same-request recovery first" in context
    assert "ask the user for intro and guidance" in context

    envelopes = store.list_envelopes(commitment)
    assert len(envelopes) == 1
    structural = envelopes[0].structural_payload
    assert structural["capability_profile_id"] == profile
    assert structural["hook_name"] == "SessionStart"
    stored = canonical_encode(structural)
    state_bytes = b"".join(
        path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    for canary in (
        "PROMPT_CANARY",
        "RESULT_CANARY",
        "TRANSCRIPT_CANARY",
        "EMAIL_CANARY",
        "FILE_CANARY",
        "OLD_CANARY",
        "NEW_CANARY",
        "ROOT_CANARY",
        "workspace_roots",
    ):
        assert canary.encode() not in stored
        assert canary.encode() not in state_bytes


def test_cursor_received_clear_clears_existing_lifecycle_mapping(tmp_path: Path) -> None:
    """The closed Cursor source=clear flag reaches the shared mapping fence."""

    _store, _commitment = _consented_store(tmp_path)
    session = "cursor:received-clear"
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
        observe_hooks.handle_cursor_observe(
            event_name="sessionStart",
            stdin_bytes=canonical_encode(
                {
                    "hook_event_name": "sessionStart",
                    "conversation_id": "received-clear",
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


def test_cursor_outputless_event_does_not_lease_or_commit_frontier_motion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    store, commitment = _consented_store(tmp_path)
    session = "cursor:cursor-pending"
    store.bind_codex_session(commitment, session)
    store.note_frontier_motion(
        commitment,
        session,
        from_sequence=1,
        to_sequence=2,
        head_digest="sha256:" + "3" * 64,
        observation_record_count=1,
        task_id="tsk_cursor_pending",
    )
    lease_calls: list[str] = []
    original_lease = LocalObservationStore.advice_delivery_lease

    def tracked_lease(self: LocalObservationStore, workspace: str) -> object:
        lease_calls.append(workspace)
        return original_lease(self, workspace)

    monkeypatch.setattr(LocalObservationStore, "advice_delivery_lease", tracked_lease)
    stdout = io.BytesIO()

    assert (
        observe_hooks.handle_cursor_observe(
            event_name="afterMCPExecution",
            stdin_bytes=canonical_encode(
                {
                    "conversation_id": "cursor-pending",
                    "hook_event_name": "afterMCPExecution",
                    "cursor_version": "3.17.8",
                    "tool_name": "shell",
                }
            ),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    assert json.loads(stdout.getvalue()) == {}
    assert lease_calls == []
    assert store.peek_frontier_motion(commitment, session) is not None


def test_cursor_advice_delivery_stays_pending_until_session_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real AdviceDelivery state survives every Cursor output-less hook."""

    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    store, commitment = _consented_store(tmp_path)
    composition = ObservationCompositionFact(
        semantic_configured=True,
        semantic_ready=False,
        provider_factory_ids=("fireworks",),
        connected_provider_ids=(),
    )
    original_refresh = LocalObservationStore.refresh_advice

    def refresh_with_composition(
        self: LocalObservationStore, workspace: str, **kwargs: object
    ) -> object:
        kwargs.setdefault("composition", composition)
        return original_refresh(self, workspace, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(LocalObservationStore, "refresh_advice", refresh_with_composition)
    lease_calls: list[str] = []
    original_lease = LocalObservationStore.advice_delivery_lease

    def tracked_lease(self: LocalObservationStore, workspace: str) -> object:
        lease_calls.append(workspace)
        return original_lease(self, workspace)

    monkeypatch.setattr(LocalObservationStore, "advice_delivery_lease", tracked_lease)

    session = "cursor-pending-advice"
    session_commitment = store.session_commitment(f"cursor:{session}")
    initial_out = io.BytesIO()
    assert (
        observe_hooks.handle_cursor_observe(
            event_name="sessionStart",
            stdin_bytes=canonical_encode(
                {
                    "conversation_id": session,
                    "hook_event_name": "sessionStart",
                    "cursor_version": "3.17.8",
                    "tool_name": "mcp__finishup__start",
                    "source": "clear",
                }
            ),
            stdout=initial_out,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert json.loads(initial_out.getvalue()) == {}
    assert store.advice_snapshot_for(commitment) is not None
    assert store.peek_advice_for_delivery(commitment) is not None
    assert lease_calls == []

    for event_name, extra in (
        ("afterFileEdit", {"file_path": "/private/cursor-canary.py"}),
        ("afterMCPExecution", {}),
        ("sessionEnd", {}),
        ("stop", {}),
    ):
        output = io.BytesIO()
        assert (
            observe_hooks.handle_cursor_observe(
                event_name=event_name,
                stdin_bytes=canonical_encode(
                    {
                        "conversation_id": session,
                        "hook_event_name": event_name,
                        "cursor_version": "3.17.8",
                        **extra,
                    }
                ),
                stdout=output,
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
            )
            == 0
        )
        assert output.getvalue() == b"{}\n"
        assert store.peek_advice_for_delivery(commitment) is not None

    final_out = io.BytesIO()
    assert (
        observe_hooks.handle_cursor_observe(
            event_name="sessionStart",
            stdin_bytes=canonical_encode(
                {
                    "conversation_id": session,
                    "hook_event_name": "sessionStart",
                    "cursor_version": "3.17.8",
                    "source": "clear",
                }
            ),
            stdout=final_out,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    emitted = json.loads(final_out.getvalue())
    assert set(emitted) == {"additional_context"}
    assert "connect_provider" in emitted["additional_context"]
    assert len(lease_calls) == 1
    assert (
        store.peek_advice_for_delivery(
            commitment,
            session_commitment=session_commitment,
        )
        is None
    )


@pytest.mark.parametrize(
    ("event_name", "event_fields", "delivers_advice"),
    [
        (
            "postToolUse",
            {
                "tool_name": "Shell",
                # Cursor's command result carries only the nonzero exit code;
                # the host does not send a separate success/result_status flag.
                "tool_output": '{"exitCode":7}',
            },
            True,
        ),
        (
            "postToolUse",
            {"tool_name": "Read", "tool_output": "{}"},
            True,
        ),
        (
            "postToolUseFailure",
            {
                "tool_name": "Shell",
                "error_message": "command failed",
                "failure_type": "error",
            },
            False,
        ),
        (
            "afterMCPExecution",
            {"tool_name": "MCP:fixture_echo", "result_json": "fixture result"},
            False,
        ),
        (
            "postToolUse",
            {"tool_name": "finishup:publish_work", "tool_output": "{}"},
            False,
        ),
        (
            "postToolUse",
            {"tool_name": "plugin-finishup-finishup:publish_work", "tool_output": "{}"},
            False,
        ),
    ],
)
def test_cursor_ordinary_advice_delivery_matches_native_output_channels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_name: str,
    event_fields: dict[str, JsonValue],
    delivers_advice: bool,
) -> None:
    """Only ordinary postToolUse can consume advice on Cursor's native channel."""

    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    store, commitment = _consented_store(tmp_path)
    lease_calls: list[str] = []
    original_lease = LocalObservationStore.advice_delivery_lease

    def tracked_lease(self: LocalObservationStore, workspace: str) -> object:
        lease_calls.append(workspace)
        return original_lease(self, workspace)

    monkeypatch.setattr(LocalObservationStore, "advice_delivery_lease", tracked_lease)
    session = "cursor-ordinary-advice"
    session_commitment = store.session_commitment(f"cursor:{session}")

    # Seed a real task-scoped, transient failed-command finding. The loop
    # guard leaves it pending, while the later native hook is the event under
    # test. Standing provider configuration advice is intentionally excluded
    # from PostToolUse cadence.
    seed_out = io.BytesIO()
    assert (
        observe_hooks.handle_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {
                    "session_id": f"cursor:{session}",
                    "hook_event_name": "PostToolUse",
                    "capability_profile_id": CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
                    "tool_call_id": "seed-failed-command",
                    "tool_name": "shell",
                    "exit_status": 7,
                    "stop_hook_active": True,
                }
            ),
            stdout=seed_out,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
            source=ObservationSource.CURSOR_HOOK,
            _output_event_name="postToolUse",
            _content_capture_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        )
        == 0
    )
    assert seed_out.getvalue() == b"{}\n"
    assert store.peek_advice_for_delivery(commitment, session_commitment=session_commitment)
    assert lease_calls == []

    output = io.BytesIO()
    payload: dict[str, JsonValue] = {
        "conversation_id": session,
        "hook_event_name": event_name,
        "cursor_version": "3.17.8",
        **event_fields,
    }
    assert (
        observe_hooks.handle_cursor_observe(
            event_name=event_name,
            stdin_bytes=canonical_encode(payload),
            stdout=output,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
            observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        )
        == 0
    )

    emitted = json.loads(output.getvalue())
    if delivers_advice:
        assert emitted == {"additional_context": emitted["additional_context"]}
        assert "resolve_failed_command" in emitted["additional_context"]
        assert lease_calls == [commitment]
        assert (
            store.peek_advice_for_delivery(
                commitment,
                session_commitment=session_commitment,
            )
            is None
        )
    else:
        assert emitted == {}
        assert lease_calls == []
        assert store.peek_advice_for_delivery(commitment, session_commitment=session_commitment)


def test_cursor_workspace_diagnostics_distinguish_unconsented_and_unresolvable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    diagnostics: list[str] = []

    def record(reason: str, event: str, *, _state: Path | None = None) -> None:
        del event, _state
        diagnostics.append(reason)

    monkeypatch.setattr(observe_hooks, "record_hook_diagnostic", record)
    unconsented_out = io.BytesIO()
    assert (
        observe_hooks.handle_cursor_observe(
            event_name="sessionStart",
            stdin_bytes=canonical_encode(
                {"conversation_id": "unconsented", "hook_event_name": "sessionStart"}
            ),
            stdout=unconsented_out,
            workspace=str(tmp_path),
            _state=tmp_path,
        )
        == 0
    )
    assert json.loads(unconsented_out.getvalue()) == {}
    assert diagnostics == ["workspace_unconsented"]

    first = tmp_path / "first"
    second = tmp_path / "second"
    outside = tmp_path / "outside"
    first.mkdir()
    second.mkdir()
    outside.mkdir()
    monkeypatch.setenv("CURSOR_PROJECT_DIR", str(outside))
    unresolved_out = io.BytesIO()
    assert (
        observe_hooks.handle_cursor_observe(
            event_name="sessionStart",
            stdin_bytes=canonical_encode(
                {
                    "conversation_id": "unresolvable",
                    "hook_event_name": "sessionStart",
                    "workspace_roots": [str(first), str(second)],
                }
            ),
            stdout=unresolved_out,
            workspace=str(tmp_path),
            _state=tmp_path,
        )
        == 0
    )
    assert json.loads(unresolved_out.getvalue()) == {}
    assert diagnostics[-1] == "workspace_unresolvable"


def test_cursor_lifecycle_identifiers_bind_one_conversation_to_one_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_sessions: list[object] = []

    def fake_handle_observe(**kwargs: object) -> int:
        sanitized = strict_json_parse(cast(bytes, kwargs["stdin_bytes"]))
        assert isinstance(sanitized, Mapping)
        observed_sessions.append(sanitized["session_id"])
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)

    def dispatch(event: str, payload: dict[str, JsonValue]) -> int:
        return observe_hooks.handle_cursor_observe(
            event_name=event,
            stdin_bytes=canonical_encode({"hook_event_name": event, **payload}),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
        )

    # sessionStart validates the (conversation, session) pair and persists it.
    assert dispatch("sessionStart", {"conversation_id": "c-1", "session_id": "s-1"}) == 0
    # A later event carrying only the conversation identifier resolves through
    # the alias instead of splitting the conversation into a second session.
    assert dispatch("stop", {"conversation_id": "c-1"}) == 0
    assert observed_sessions == ["cursor:s-1", "cursor:s-1"]

    # A non-sessionStart pair contradicting the validated alias is ambiguous
    # and never produces an envelope under either identity.
    assert dispatch("afterMCPExecution", {"conversation_id": "c-1", "session_id": "s-2"}) == 0
    assert observed_sessions == ["cursor:s-1", "cursor:s-1"]

    # A new sessionStart re-validates the pair; the conversation follows it.
    assert dispatch("sessionStart", {"conversation_id": "c-1", "session_id": "s-2"}) == 0
    assert dispatch("stop", {"conversation_id": "c-1"}) == 0
    assert observed_sessions[-2:] == ["cursor:s-2", "cursor:s-2"]

    # An unaliased conversation-only event keeps its deterministic fallback.
    assert dispatch("stop", {"conversation_id": "c-solo"}) == 0
    assert observed_sessions[-1] == "cursor:c-solo"


def test_cursor_mcp_executions_of_finishup_tools_follow_the_self_observation_policy(
    tmp_path: Path,
) -> None:
    """#564 on Cursor: a ``status`` execution stays local, a ``respond`` ships one row."""

    store, commitment = _consented_store(tmp_path)

    def hook(tool: str, generation: str) -> None:
        payload: dict[str, JsonValue] = {
            "conversation_id": "cursor-self-observation",
            "cursor_version": "3.17.8",
            "generation_id": generation,
            "hook_event_name": "afterMCPExecution",
            "tool_name": tool,
            "tool_input": "private arguments",
            "result_json": "private result",
            "workspace_roots": [str(tmp_path)],
        }
        assert (
            observe_hooks.handle_cursor_observe(
                event_name="afterMCPExecution",
                stdin_bytes=canonical_encode(payload),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
            )
            == 0
        )

    hook("mcp__finishup__status", "generation-1")
    hook("mcp__finishup__receipt", "generation-2")
    hook("mcp__finishup__respond", "generation-3")
    hook("plugin-finishup-finishup:status", "generation-4")
    hook("plugin-finishup-finishup:check", "generation-5")

    rows = store.list_pending_outbox_rows(commitment)
    assert [row.envelope.structural_payload["tool_name"] for row in rows] == [
        "mcp__finishup__respond",
        "plugin-finishup-finishup:check",
    ]
    assert all(row.envelope.structural_payload["action"] == "cursor_mcp" for row in rows)
    assert len(store.list_envelopes(commitment)) == 5


def test_cursor_version_mapping_distinguishes_ide_cli_unknown_and_omitted() -> None:
    """Issue #656: Cursor keeps its exact table. The IDE cell is proven; the Agent CLI build and
    any unknown version are ``untested`` on the conservative paired contract; an omitted version
    takes the legacy post-only carrier. Compatible events ingest in every branch (see the
    parametrized ingress test above); none is promoted to the proven profile."""

    from finishup.ports.integrations import observation_pairing_contract

    mapper = observe_hooks._cursor_capability_profile_id  # pyright: ignore[reportPrivateUsage]
    assert mapper("3.17.8") == "cursor-ide-3.17.8"
    assert observation_pairing_contract("cursor", "cursor-ide-3.17.8") == (
        "post_only",
        "generation_id",
    )
    for version in ("2026.07.09-a3815c0", "3.17.9", "3.18.0", "1.0.24"):
        assert mapper(version) == "untested", version
        assert observation_pairing_contract("cursor", "untested") == ("paired", "tool_call_id")
    assert mapper(None) is None
    assert mapper("") is None
    assert observation_pairing_contract("cursor", None) == ("post_only", "generation_id")


def _structural_text(envelope: object) -> str:
    payload = getattr(envelope, "structural_payload")
    return canonical_encode(payload).decode("utf-8")


def test_cursor_oversized_edit_keeps_identity_and_omits_content(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store, commitment = _consented_store(tmp_path)
    oversize = (
        b'{"conversation_id":"cursor-oversize","hook_event_name":"afterFileEdit",'
        b'"file_path":"/EDIT_CANARY.md","edits":[{"new_string":"'
        + b"x" * MAX_HOOK_STDIN_BYTES
        + b'"}]}'
    )
    assert MAX_HOOK_STDIN_BYTES < len(oversize) <= MAX_HOOK_SKIM_BYTES
    stdout = io.BytesIO()

    assert (
        observe_hooks.handle_cursor_observe(
            event_name="afterFileEdit",
            stdin_bytes=oversize,
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    assert stdout.getvalue() == b"{}\n"
    diagnostic = (tmp_path / "observation/hook-diagnostics.jsonl").read_text(encoding="utf-8")
    row = json.loads(diagnostic.splitlines()[0])
    assert row == {
        "event": "PostToolUse",
        "reason": "cursor_payload_content_omitted",
        "ts": row["ts"],
    }
    assert "cursor_payload_invalid" not in diagnostic
    assert "cursor_payload_too_large" not in diagnostic
    assert "EDIT_CANARY" not in diagnostic
    envelopes = store.list_envelopes(commitment)
    assert len(envelopes) == 1
    omitted = envelopes[0]
    assert ObservationGapCode.PAYLOAD_CONTENT_OMITTED.value in omitted.gap_codes
    assert ObservationGapCode.PAYLOAD_TOO_LARGE.value not in omitted.gap_codes
    assert omitted.content_object_refs == ()
    assert omitted.structural_payload["changed_paths_digest"]
    structural = _structural_text(omitted)
    assert "EDIT_CANARY" not in structural
    assert "xxxxx" not in structural
    gaps = store.status(ObservationStatusQuery(commitment)).gaps
    assert ObservationGapCode.PAYLOAD_CONTENT_OMITTED.value in gaps
    assert ObservationGapCode.PAYLOAD_TOO_LARGE.value not in gaps
    captured = capsys.readouterr().err
    assert "payload_content_omitted" in captured
    assert "EDIT_CANARY" not in captured

    # The omission costs only that edit: the next ordinary edit still ingests
    # without inheriting the content-omission gap on its own row.
    assert (
        observe_hooks.handle_cursor_observe(
            event_name="afterFileEdit",
            stdin_bytes=canonical_encode(
                {
                    "conversation_id": "cursor-oversize",
                    "file_path": str(tmp_path / "small.md"),
                    "hook_event_name": "afterFileEdit",
                }
            ),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    follow = store.list_envelopes(commitment)
    assert len(follow) == 2
    assert ObservationGapCode.PAYLOAD_CONTENT_OMITTED.value not in follow[1].gap_codes


def test_cursor_ordinary_oversize_write_pairs_pre_and_post_without_content(
    tmp_path: Path,
) -> None:
    store, commitment = _consented_store(tmp_path)
    store.grant_consent(
        commitment,
        content_capture_profiles=(CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,),
    )
    contents = b"Y" * MAX_HOOK_STDIN_BYTES

    def body(event: str) -> bytes:
        encoded = (
            b'{"conversation_id":"cursor-write","hook_event_name":"'
            + event.encode()
            + b'","tool_name":"Write","tool_use_id":"toolu_write_interfaces",'
            b'"tool_input":{"path":"docs/INTERFACES.md","contents":"' + contents + b'"}}'
        )
        assert MAX_HOOK_STDIN_BYTES < len(encoded) <= MAX_HOOK_SKIM_BYTES
        return encoded

    for event in ("preToolUse", "postToolUse"):
        assert (
            observe_hooks.handle_cursor_observe(
                event_name=event,
                stdin_bytes=body(event),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
                observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )

    envelopes = store.list_envelopes(commitment)
    assert [envelope.event_kind for envelope in envelopes] == ["PreToolUse", "PostToolUse"]
    assert {envelope.structural_payload["tool_call_id"] for envelope in envelopes} == {
        "toolu_write_interfaces"
    }
    assert {envelope.structural_payload["tool_name"] for envelope in envelopes} == {"Write"}
    # Only the completed edit commits its path; the pending call changed nothing.
    pre, post = envelopes
    assert "changed_paths_digest" not in pre.structural_payload
    assert post.structural_payload["changed_paths_digest"]
    for envelope in envelopes:
        assert ObservationGapCode.PAYLOAD_CONTENT_OMITTED.value in envelope.gap_codes
        assert envelope.content_object_refs == ()
        structural = _structural_text(envelope)
        assert "INTERFACES.md" not in structural
        assert "YYYYY" not in structural


def _ordinary_oversize(tmp_path: Path, event: str, fields: bytes) -> None:
    body = (
        b'{"conversation_id":"cursor-skim","hook_event_name":"'
        + event.encode()
        + b'",'
        + fields
        + b',"pad":"'
        + b"Z" * MAX_HOOK_STDIN_BYTES
        + b'"}'
    )
    assert MAX_HOOK_STDIN_BYTES < len(body) <= MAX_HOOK_SKIM_BYTES
    assert (
        observe_hooks.handle_cursor_observe(
            event_name=event,
            stdin_bytes=body,
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
            observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        )
        == 0
    )


def test_cursor_oversized_read_does_not_commit_a_changed_path(tmp_path: Path) -> None:
    store, commitment = _consented_store(tmp_path)

    _ordinary_oversize(
        tmp_path,
        "postToolUse",
        b'"tool_name":"Read","tool_use_id":"toolu_read","tool_input":{"path":"README.md"}',
    )

    (envelope,) = store.list_envelopes(commitment)
    assert ObservationGapCode.PAYLOAD_CONTENT_OMITTED.value in envelope.gap_codes
    assert "changed_paths_digest" not in envelope.structural_payload


def test_cursor_oversized_failed_edit_keeps_failure_without_error_text(tmp_path: Path) -> None:
    store, commitment = _consented_store(tmp_path)

    _ordinary_oversize(
        tmp_path,
        "postToolUse",
        b'"tool_name":"Write","tool_use_id":"toolu_fail","tool_input":{"path":"a.md"},'
        b'"tool_output":{"error":"ERROR_CANARY","success":true}',
    )

    (envelope,) = store.list_envelopes(commitment)
    assert envelope.structural_payload["action"] == "cursor_tool_failure"
    assert "changed_paths_digest" not in envelope.structural_payload
    assert "ERROR_CANARY" not in _structural_text(envelope)


def test_cursor_oversized_invalid_workspace_roots_is_refused_like_full_size(
    tmp_path: Path,
) -> None:
    store, commitment = _consented_store(tmp_path)

    _ordinary_oversize(
        tmp_path,
        "postToolUse",
        b'"tool_name":"Write","tool_use_id":"toolu_roots","workspace_roots":[""]',
    )

    assert store.list_envelopes(commitment) == ()


def test_cursor_oversized_skipped_mcp_execution_is_not_a_coverage_loss(
    tmp_path: Path,
) -> None:
    store, commitment = _consented_store(tmp_path)

    _ordinary_oversize(
        tmp_path,
        "afterMCPExecution",
        b'"tool_name":"MCP:fixture_echo","tool_use_id":"toolu_mcp"',
    )

    assert store.list_envelopes(commitment) == ()
    assert (
        ObservationGapCode.PAYLOAD_TOO_LARGE.value
        not in store.status(ObservationStatusQuery(commitment)).gaps
    )


def test_cursor_oversized_body_without_event_flag_keeps_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, commitment = _consented_store(tmp_path)
    body = (
        b'{"conversation_id":"cursor-stdin","hook_event_name":"postToolUse",'
        b'"tool_name":"Write","tool_use_id":"toolu_stdin","tool_input":{"path":"a.md",'
        b'"contents":"' + b"W" * MAX_HOOK_STDIN_BYTES + b'"}}'
    )
    assert MAX_HOOK_STDIN_BYTES < len(body) <= MAX_HOOK_SKIM_BYTES
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(body)))

    assert (
        observe_hooks.handle_cursor_observe(
            event_name=None,
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
            observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        )
        == 0
    )

    (envelope,) = store.list_envelopes(commitment)
    assert envelope.structural_payload["tool_call_id"] == "toolu_stdin"
    assert ObservationGapCode.PAYLOAD_CONTENT_OMITTED.value in envelope.gap_codes


def test_cursor_body_over_skim_cap_stays_an_unparsed_gap(
    tmp_path: Path,
) -> None:
    store, commitment = _consented_store(tmp_path)
    oversize = b'{"hook_event_name":"afterFileEdit","pad":"' + (b"x" * MAX_HOOK_SKIM_BYTES) + b'"}'
    assert len(oversize) > MAX_HOOK_SKIM_BYTES

    assert (
        observe_hooks.handle_cursor_observe(
            event_name="afterFileEdit",
            stdin_bytes=oversize,
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    diagnostic = (tmp_path / "observation/hook-diagnostics.jsonl").read_text(encoding="utf-8")
    row = json.loads(diagnostic.splitlines()[0])
    assert row["reason"] == "cursor_payload_too_large"
    assert "cursor_payload_content_omitted" not in diagnostic
    assert store.list_envelopes(commitment) == ()
    assert (
        ObservationGapCode.PAYLOAD_TOO_LARGE.value
        in store.status(ObservationStatusQuery(commitment)).gaps
    )


def test_cursor_oversize_without_identity_stays_an_unparsed_gap(tmp_path: Path) -> None:
    store, commitment = _consented_store(tmp_path)
    anonymous = b'{"edits":[{"new_string":"' + b"x" * MAX_HOOK_STDIN_BYTES + b'"}]}'
    assert MAX_HOOK_STDIN_BYTES < len(anonymous) <= MAX_HOOK_SKIM_BYTES

    assert (
        observe_hooks.handle_cursor_observe(
            event_name="afterFileEdit",
            stdin_bytes=anonymous,
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    assert store.list_envelopes(commitment) == ()
    assert (
        ObservationGapCode.PAYLOAD_TOO_LARGE.value
        in store.status(ObservationStatusQuery(commitment)).gaps
    )


def test_cursor_oversized_malformed_body_is_not_a_structural_row(tmp_path: Path) -> None:
    store, commitment = _consented_store(tmp_path)
    duplicate = (
        b'{"hook_event_name":"afterFileEdit","hook_event_name":"afterFileEdit","pad":"'
        + b"x" * MAX_HOOK_STDIN_BYTES
        + b'"}'
    )
    assert MAX_HOOK_STDIN_BYTES < len(duplicate) <= MAX_HOOK_SKIM_BYTES

    assert (
        observe_hooks.handle_cursor_observe(
            event_name="afterFileEdit",
            stdin_bytes=duplicate,
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    diagnostic = (tmp_path / "observation/hook-diagnostics.jsonl").read_text(encoding="utf-8")
    reasons = {json.loads(line)["reason"] for line in diagnostic.splitlines()}
    assert reasons == {"cursor_payload_invalid", "cursor_payload_too_large"}
    assert store.list_envelopes(commitment) == ()
