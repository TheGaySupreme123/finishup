"""Host-attribution boundary rows for the multi-agent conformance matrix."""

from __future__ import annotations

from dataclasses import replace

import pytest

from finishup.application.observation_materialize import (
    canonical_logical_identity,
    materialize_observation_envelope,
)
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp

_TASK = "tsk_00000000-0000-4000-8000-000000000001"
_SESSION = "hmac-sha256:" + ("ab" * 32)
_SOURCE_COMMITMENT = "hmac-sha256:" + ("cd" * 32)


def _envelope(
    source: ObservationSource,
    event_kind: str,
    *,
    parent_tool_call_id: str | None = "parent-call-1",
) -> ObservationEnvelope:
    fields: dict[str, str] = {"subagent_id": "host-child-1"}
    if parent_tool_call_id is not None:
        fields["parent_tool_call_id"] = parent_tool_call_id
    return ObservationEnvelope(
        session_commitment=_SESSION,
        event_kind=event_kind,
        source_identity=f"{source.value}:child-1",
        source=source,
        cursor=ObservationCursor(1, 1, 1, _SOURCE_COMMITMENT, "obs-ledger/1.5.0"),
        receipt_time=Timestamp("2026-09-05T18:00:00.000Z"),
        structural_payload=JsonObject(fields),
        content_object_refs=(),
        gap_codes=(),
    )


@pytest.mark.parametrize(
    ("source", "event_kind"),
    (
        (ObservationSource.CLAUDE_HOOK, "SubagentStart"),
        (ObservationSource.CODEX_HOOK, "SubagentStart"),
        (ObservationSource.CURSOR_HOOK, "SubagentStart"),
    ),
)
def test_each_host_identity_is_pending_service_observation_without_child_mint(
    source: ObservationSource,
    event_kind: str,
) -> None:
    batch = materialize_observation_envelope(_envelope(source, event_kind), task_id=_TASK)

    assert batch.skip_reason is None
    assert len(batch.drafts) == 1
    draft = batch.drafts[0]
    assert draft.role == "subagent"
    payload = draft.draft.payload
    assert "origin=host_observed" in (getattr(payload, "description", "") or "")
    assert "acceptance=pending" in (getattr(payload, "description", "") or "")
    assert (getattr(payload, "reference", "") or "").startswith("host-lineage:lineage:")


def test_missing_child_identity_is_one_explicit_gap_without_an_annotation() -> None:
    envelope = _envelope(ObservationSource.CODEX_HOOK, "SubagentStop")
    missing = replace(envelope, structural_payload=JsonObject({}))

    batch = materialize_observation_envelope(missing, task_id=_TASK)

    assert batch.drafts == ()
    assert batch.skip_reason == "missing_subagent_identity"
    assert batch.gaps == ("missing_subagent_identity",)
    assert "missing_subagent_identity" in batch.coverage.known_gaps


def test_hook_and_stream_same_pair_share_one_parent_scoped_observation_key() -> None:
    hook = _envelope(ObservationSource.CODEX_HOOK, "SubagentStop")
    stream = _envelope(
        ObservationSource.CODEX_SESSION_STREAM,
        "SubagentStop",
    )

    assert canonical_logical_identity(hook) == canonical_logical_identity(stream)
    hook_batch = materialize_observation_envelope(hook, task_id=_TASK)
    stream_batch = materialize_observation_envelope(stream, task_id=_TASK)
    assert hook_batch.drafts[0].draft.event_id == stream_batch.drafts[0].draft.event_id
    assert hook_batch.drafts[0].draft.payload == stream_batch.drafts[0].draft.payload


def test_v2_child_header_and_parent_activity_are_one_delegation_identity() -> None:
    """Issue #754: a multi-agent v2 delegation seen from both sides is one annotation.

    The parent's ``SubAgentActivity`` spawn item and the child's own ``session_meta`` header name
    the same child thread and neither carries a parent call, so they reconcile through one
    parent-scoped key instead of minting a second host annotation per delegation.
    """

    parent_side = _envelope(
        ObservationSource.CODEX_SESSION_STREAM, "SubagentStart", parent_tool_call_id=None
    )
    child_side = replace(
        parent_side,
        source_identity="codex_session_stream:child-header-1",
        structural_payload=JsonObject(
            {"stream_kind": "session_meta", "subagent_id": "host-child-1"}
        ),
    )

    assert canonical_logical_identity(parent_side) == canonical_logical_identity(child_side)
    parent_batch = materialize_observation_envelope(parent_side, task_id=_TASK)
    child_batch = materialize_observation_envelope(child_side, task_id=_TASK)
    assert parent_batch.skip_reason is None and child_batch.skip_reason is None
    assert parent_batch.drafts[0].draft.event_id == child_batch.drafts[0].draft.event_id
