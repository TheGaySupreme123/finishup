"""Claude Code and Cursor materialization is unchanged by the paired-call fix (#917).

The installed Claude Code and Cursor carriers are post-only profiles. Their real
hook payloads go through the real host ingress here, and the ledger drafts their
envelopes materialize are pinned byte for byte to the digest the pre-#917
materializer produced for exactly these inputs. A paired profile (Codex, and the
opt-in Claude/Cursor ordinary profiles) is the only one whose pre and post now
share one action.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import io
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.application.observation_materialize import (
    materialize_observation_envelope,
    paired_action_link,
)
from yoetz.cli import observe_hooks
from yoetz.domain.observation import ObservationEnvelope
from yoetz.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from yoetz.domain.values import JsonObject, Timestamp
from yoetz.protocol.canonical import canonical_digest, canonical_encode

_TASK = "tsk_7a3f1c52-6a0e-4c1b-9d2e-8b5f4a3c2d10"
_KEY = bytes(range(32))
_RECEIPT = Timestamp("2026-09-29T17:55:00.957Z")

_CLAUDE_POSTS: tuple[tuple[str, dict[str, Any], str | None], ...] = (
    (
        "PostToolUse",
        {
            "cwd": "/app",
            "hook_event_name": "PostToolUse",
            "permission_mode": "bypassPermissions",
            "session_id": "7c1e2f4a-claude-session",
            "tool_input": {"dry_run": True},
            "tool_name": "mcp__plugin_yoetz_yoetz__publish_work",
            "tool_response": {"content": [{"text": "published", "type": "text"}]},
            "tool_use_id": "toolu_01PublishWork",
            "transcript_path": "/private/transcript.jsonl",
        },
        None,
    ),
    (
        "PostToolUse",
        {
            "claude_code_version": "2.1.241",
            "cwd": "/app",
            "hook_event_name": "PostToolUse",
            "permission_mode": "default",
            "session_id": "7c1e2f4a-claude-session",
            "tool_input": {},
            "tool_name": "mcp__plugin_yoetz_yoetz__check",
            "tool_response": {"content": [{"text": "verdict", "type": "text"}]},
            "tool_use_id": "toolu_01Check",
            "transcript_path": "/private/transcript.jsonl",
        },
        None,
    ),
    (
        "PostToolUse",
        {
            "cwd": "/app",
            "hook_event_name": "PostToolUse",
            "permission_mode": "default",
            "session_id": "7c1e2f4a-claude-session",
            "tool_input": {"command": "pytest -q"},
            "tool_name": "Bash",
            "tool_response": {"interrupted": False, "stderr": "", "stdout": "3 passed"},
            "tool_use_id": "toolu_01Bash",
            "transcript_path": "/private/transcript.jsonl",
        },
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    ),
)

_CURSOR_POSTS: tuple[tuple[str, dict[str, Any], str | None], ...] = (
    (
        "postToolUse",
        {
            "conversation_id": "c0ffee00-cursor-conversation",
            "cursor_version": "3.17.8",
            "generation_id": "gen-0001",
            "hook_event_name": "postToolUse",
            "session_id": "c0ffee00-cursor-conversation",
            "tool_input": {"command": "npm test"},
            "tool_name": "Shell",
            "tool_output": '{"exitCode":0}',
            "workspace_roots": [],
        },
        None,
    ),
    (
        "afterMCPExecution",
        {
            "conversation_id": "c0ffee00-cursor-conversation",
            "cursor_version": "3.17.8",
            "generation_id": "gen-0002",
            "hook_event_name": "afterMCPExecution",
            "result_json": '{"isError":false}',
            "session_id": "c0ffee00-cursor-conversation",
            "tool_input": "{}",
            "tool_name": "publish_work",
            "workspace_roots": [],
        },
        None,
    ),
    (
        "postToolUse",
        {
            "conversation_id": "c0ffee00-cursor-conversation",
            "generation_id": "gen-0003",
            "hook_event_name": "postToolUse",
            "session_id": "c0ffee00-cursor-conversation",
            "tool_input": {"command": "npm test"},
            "tool_name": "Shell",
            "tool_output": '{"exitCode":1}',
            "tool_use_id": "cursor-call-3",
            "workspace_roots": [],
        },
        CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    ),
)

# Recomputed on the pre-#917 materializer for exactly these envelopes. A change
# here is a change to Claude Code or Cursor ledger records and needs its own
# review; #917 must not move either value. Re-pinned when #909 (keyed command
# identity, tool-named action description) was merged beneath #910: the values
# are what the #909 materializer alone produces, so #917 and #910 move neither.
# Re-pinned again for the bounded command runner class (#961/#968): the host
# ingress now records ``runner_class`` in the structural payload, which moves the
# derived event/evidence ids, and post-only action descriptions gain the closed
# ``(runner <class>)`` suffix. No other draft byte changed.
# Re-pinned for tb4n3 RC-5 (#1028, ADR-045): a two-argument command such as ``pytest -q`` now
# carries ``command_composition`` and its canonical flag commitment in the structural payload, so
# the derived evidence ids of the unpaired results move. The action and result payloads do not.
_PINNED = {
    "claude": "sha256:9ca41d959b716cee3ab2b8776632137f1b87196ec161c06429b659090b4978be",
    "cursor": "sha256:5d800c50f0c6f4d6793fa1602e397050ed6616b28748e68b68d9c9e17c3b1dd6",
}


def _ingress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[..., int],
    cases: tuple[tuple[str, dict[str, Any], str | None], ...],
) -> tuple[ObservationEnvelope, ...]:
    def _fixed_key(_store: LocalObservationStore) -> bytes:
        return _KEY

    monkeypatch.setattr(LocalObservationStore, "key_material", _fixed_key)
    workspace = tmp_path / "app"
    workspace.mkdir()
    root = tmp_path / "isolated"
    store = LocalObservationStore(_state=root)
    commitment = store.workspace_commitment(str(workspace.resolve()))
    store.grant_consent(commitment)
    for event, payload, profile in cases:
        assert (
            handler(
                event_name=event,
                stdin_bytes=canonical_encode(JsonObject(payload)),
                stdout=io.BytesIO(),
                workspace=str(workspace),
                _state=root,
                skip_service=True,
                observation_profile=profile,
            )
            == 0
        )
    rows = store.list_pending_outbox_rows(commitment)
    return tuple(replace(row.envelope, receipt_time=_RECEIPT) for row in rows)


def _materialized_digest(envelopes: tuple[ObservationEnvelope, ...]) -> str:
    batches: list[object] = []
    for envelope in envelopes:
        batch = materialize_observation_envelope(envelope, task_id=_TASK)
        assert paired_action_link(envelope, batch, task_id=_TASK) is None or (
            envelope.structural_payload.get("capability_profile_id")
            in {CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID, CURSOR_ORDINARY_OBSERVATION_PROFILE_ID}
        )
        batches.append(
            {
                "event_kind": envelope.event_kind,
                "gaps": list(batch.gaps),
                "known_gaps": list(batch.coverage.known_gaps),
                "skip_reason": batch.skip_reason,
                "drafts": [
                    {
                        "role": item.role,
                        "event_id": str(item.draft.event_id),
                        "schema": item.draft.schema.name,
                        "parents": [str(parent) for parent in item.draft.causal_parents],
                        "evidence_refs": [str(ref) for ref in item.draft.evidence_refs],
                        "payload": item.payload_bytes.hex(),
                    }
                    for item in batch.drafts
                ],
            }
        )
    return canonical_digest(JsonObject({"batches": batches}))  # type: ignore[arg-type]


def test_claude_code_materialization_is_byte_identical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelopes = _ingress(tmp_path, monkeypatch, observe_hooks.handle_claude_observe, _CLAUDE_POSTS)
    assert len(envelopes) == len(_CLAUDE_POSTS)
    assert _materialized_digest(envelopes) == _PINNED["claude"]


def test_cursor_materialization_is_byte_identical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelopes = _ingress(tmp_path, monkeypatch, observe_hooks.handle_cursor_observe, _CURSOR_POSTS)
    assert envelopes
    assert _materialized_digest(envelopes) == _PINNED["cursor"]


def test_ordinary_profile_pre_and_post_share_one_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The opt-in Claude ordinary profile is paired, so it gets the same single action."""

    from yoetz.domain.events import ActionRecordedPayload, ResultRecordedPayload

    pre, post = _ingress(
        tmp_path,
        monkeypatch,
        observe_hooks.handle_claude_observe,
        (
            (
                "PreToolUse",
                {
                    "cwd": "/app",
                    "hook_event_name": "PreToolUse",
                    "permission_mode": "default",
                    "session_id": "7c1e2f4a-claude-session",
                    "tool_input": {"command": "pytest -q"},
                    "tool_name": "Bash",
                    "tool_use_id": "toolu_01Paired",
                },
                CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            ),
            _CLAUDE_POSTS[2][:1]
            + ({**_CLAUDE_POSTS[2][1], "tool_use_id": "toolu_01Paired"},)
            + _CLAUDE_POSTS[2][2:],
        ),
    )
    pre_batch = materialize_observation_envelope(pre, task_id=_TASK)
    post_batch = materialize_observation_envelope(post, task_id=_TASK)
    pre_action = pre_batch.drafts[0]
    assert type(pre_action.draft.payload) is ActionRecordedPayload
    assert "via Claude Code hook" in pre_action.draft.payload.description
    link = paired_action_link(post, post_batch, task_id=_TASK)
    assert link is not None
    assert link.action_event_id == str(pre_action.draft.event_id)
    assert link.action_id == str(pre_action.draft.payload.action_id)
    linked_result = link.linked.drafts[-1].draft.payload
    assert type(linked_result) is ResultRecordedPayload
    assert str(linked_result.action_id) == link.action_id
