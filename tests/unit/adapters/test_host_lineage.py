"""Unit coverage for host subagent correlation normalization."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from finishup.application.observation_materialize import (
    canonical_logical_identity,
    materialize_observation_envelope,
)
from finishup.domain.host_lineage import (
    HostLineageHost,
    host_lineage_from_envelope,
    host_lineage_from_payload,
)
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp

_SESSION = "hmac-sha256:" + ("ab" * 32)
_COMMITMENT = "hmac-sha256:" + ("cd" * 32)


def _envelope(
    *,
    source: ObservationSource,
    event_kind: str,
    identity: str,
    subagent_id: str = "agent-1",
    parent_tool_call_id: str | None = "call-parent-1",
) -> ObservationEnvelope:
    structural: dict[str, str] = {"subagent_id": subagent_id}
    if parent_tool_call_id is not None:
        structural["parent_tool_call_id"] = parent_tool_call_id
    return ObservationEnvelope(
        session_commitment=_SESSION,
        event_kind=event_kind,
        source_identity=identity,
        source=source,
        cursor=ObservationCursor(1, 0, 1, _COMMITMENT, "obs-ledger/1.5.0"),
        receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
        structural_payload=JsonObject(structural),
        content_object_refs=(),
        gap_codes=(),
    )


def test_claude_agent_id_is_normalized_without_transcript_or_prompt() -> None:
    signal = host_lineage_from_payload(
        "claude",
        "SubagentStart",
        {
            "agent_id": "agent-claude-1",
            "agent_type": "reviewer",
            "parent_conversation_id": "conversation-1",
            "prompt": "private prompt",
            "transcript_path": "/private/transcript.jsonl",
        },
    )

    assert signal is not None
    assert signal.phase == "start"
    assert signal.correlation.subagent_id == "agent-claude-1"
    assert signal.origin == "host_observed"
    assert signal.acceptance == "pending"
    fields = signal.structural_fields()
    assert fields["subagent_id"] == "agent-claude-1"
    assert "agent_type" not in fields
    assert "prompt" not in fields
    assert "transcript_path" not in fields
    assert signal.correlation_identity.startswith("lineage:")


def test_codex_stop_and_start_share_pair_identity_across_optional_context() -> None:
    start = host_lineage_from_payload(
        "codex",
        "SubagentStart",
        {
            "subagent_id": "sub-1",
            "parent_tool_call_id": "call-1",
            "parent_conversation_id": "parent-1",
        },
    )
    stop = host_lineage_from_payload(
        "codex",
        "SubagentStop",
        {
            "subagent_id": "sub-1",
            "parent_tool_call_id": "call-1",
            "conversation_id": "child-1",
            "status": "completed",
            "duration_ms": 42,
        },
    )

    assert start is not None and stop is not None
    assert start.correlation_identity == stop.correlation_identity
    assert start.correlation.logical_identity == stop.correlation.logical_identity
    assert start.correlation.aliases[0] == stop.correlation.aliases[0]
    assert stop.result_status == "completed"
    assert stop.duration_ms == 42

    # A late event with only the child id remains explicitly reconcilable by
    # the service, while its weaker identity cannot silently masquerade as the
    # stronger child/parent pair.
    late = host_lineage_from_payload("codex", "SubagentStop", {"subagent_id": "sub-1"})
    assert late is not None
    assert late.correlation_identity != start.correlation_identity
    assert late.correlation.aliases[-1] in start.correlation.aliases


def test_path_like_or_incomplete_host_identity_is_an_explicit_gap() -> None:
    assert host_lineage_from_payload("claude", "SubagentStart", {}) is None
    assert (
        host_lineage_from_payload(
            "claude", "SubagentStart", {"agent_id": "/private/transcript.jsonl"}
        )
        is None
    )
    assert (
        host_lineage_from_payload(
            cast(HostLineageHost, "unknown"), "SubagentStart", {"subagent_id": "x"}
        )
        is None
    )


def test_conflicting_identity_aliases_are_an_explicit_gap() -> None:
    assert (
        host_lineage_from_payload(
            "codex",
            "SubagentStart",
            {"subagent_id": "child-a", "agent_thread_id": "child-b"},
        )
        is None
    )
    assert (
        host_lineage_from_payload(
            "codex",
            "SubagentStart",
            {
                "subagent_id": "child-a",
                "parent_tool_call_id": "parent-a",
                "tool_call_id": "parent-b",
            },
        )
        is None
    )


def test_materialization_is_source_stable_and_keeps_host_observed_pending() -> None:
    hook = _envelope(
        source=ObservationSource.CODEX_HOOK,
        event_kind="SubagentStart",
        identity="hook:subagent-1",
    )
    replay = _envelope(
        source=ObservationSource.CODEX_SESSION_STREAM,
        event_kind="SubagentStart",
        identity="stream:subagent-1",
    )

    assert canonical_logical_identity(hook) == canonical_logical_identity(replay)
    first = materialize_observation_envelope(
        hook, task_id="tsk_00000000-0000-4000-8000-000000000001"
    )
    second = materialize_observation_envelope(
        replay, task_id="tsk_00000000-0000-4000-8000-000000000001"
    )
    assert first.skip_reason is None
    assert second.skip_reason is None
    assert len(first.drafts) == len(second.drafts) == 1
    assert first.drafts[0].draft.event_id == second.drafts[0].draft.event_id
    assert first.drafts[0].draft.payload == second.drafts[0].draft.payload
    payload = first.drafts[0].draft.payload
    assert getattr(payload, "reference", "").startswith("host-lineage:lineage:")
    assert "origin=host_observed" in (getattr(payload, "description", "") or "")
    assert "acceptance=pending" in (getattr(payload, "description", "") or "")


def test_materialization_keeps_missing_identity_as_one_gap() -> None:
    envelope = _envelope(
        source=ObservationSource.CODEX_HOOK,
        event_kind="SubagentStop",
        identity="hook:missing",
        subagent_id="agent-1",
        parent_tool_call_id="call-parent-1",
    )
    envelope = ObservationEnvelope(
        session_commitment=envelope.session_commitment,
        event_kind=envelope.event_kind,
        source_identity=envelope.source_identity,
        source=envelope.source,
        cursor=envelope.cursor,
        receipt_time=envelope.receipt_time,
        structural_payload=JsonObject({}),
        content_object_refs=(),
        gap_codes=(),
    )
    batch = materialize_observation_envelope(
        envelope, task_id="tsk_00000000-0000-4000-8000-000000000001"
    )
    assert batch.drafts == ()
    assert batch.skip_reason == "missing_subagent_identity"
    assert "missing_subagent_identity" in batch.gaps
    assert "missing_subagent_identity" in batch.coverage.known_gaps


def test_envelope_source_selects_host_normalizer() -> None:
    envelope = _envelope(
        source=ObservationSource.CURSOR_HOOK,
        event_kind="SubagentStop",
        identity="hook:cursor-subagent-1",
    )
    signal = host_lineage_from_envelope(envelope)
    assert signal is not None
    assert signal.correlation.host == "cursor"


@pytest.mark.parametrize("field", ["conversation_id", "parent_conversation_id"])
@pytest.mark.parametrize("invalid", ["/private/transcript.jsonl", "private text", 42])
def test_invalid_optional_identity_never_degrades_to_child_only(
    field: str, invalid: object
) -> None:
    assert (
        host_lineage_from_payload(
            "codex", "SubagentStart", JsonObject({"subagent_id": "agent-1", field: invalid})
        )
        is None
    )


def test_distinct_parent_calls_cannot_collapse_materialized_evidence() -> None:
    first = _envelope(
        source=ObservationSource.CODEX_HOOK,
        event_kind="SubagentStart",
        identity="hook:call-a",
        parent_tool_call_id="call-a",
    )
    second = replace(
        first,
        structural_payload=JsonObject(
            {
                "subagent_id": "agent-1",
                "parent_tool_call_id": "call-b",
            }
        ),
    )
    assert canonical_logical_identity(first) != canonical_logical_identity(second)
    batches = [
        materialize_observation_envelope(item, task_id="tsk_00000000-0000-4000-8000-000000000001")
        for item in (first, second)
    ]
    assert batches[0].drafts[0].draft.event_id != batches[1].drafts[0].draft.event_id
    # Explicit historical interpretation keeps its original identity and bytes.
    assert canonical_logical_identity(
        first, mapping_version="obs-ledger/1.6.0"
    ) == canonical_logical_identity(second, mapping_version="obs-ledger/1.6.0")
