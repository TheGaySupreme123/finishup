"""One action identity per paired host call (#917), at the materialization seam."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

from finishup.application.observation_materialize import (
    PAIRED_ACTION_ROLE,
    materialize_observation_envelope,
    paired_action_link,
    paired_action_linked_roles,
)
from finishup.domain.events import (
    ActionRecordedPayload,
    EvidenceRecordedPayload,
    ResultRecordedPayload,
)
from finishup.domain.observation import (
    ObservationContentKind,
    ObservationContentManifest,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp
from fixture_loader import load_fixture_json

_TASK = "tsk_2c7e5a91-4b3d-4e8f-a1c6-0d9b8e7f6a52"
_SESSION = f"hmac-sha256:{'5d' * 32}"


def _codex(
    kind: str, identity: str, *, tool: str = "Bash", call: str = "call_n1"
) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=_SESSION,
        event_kind=kind,
        source_identity=identity,
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(1, 0, 1, f"hmac-sha256:{'ab' * 32}", "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-09-29T17:58:11.363Z"),
        structural_payload=JsonObject({"tool_name": tool, "tool_call_id": call}),
        content_object_refs=(),
        gap_codes=(),
    )


def test_paired_pre_and_post_name_the_same_action() -> None:
    pre = materialize_observation_envelope(_codex("PreToolUse", "hook:pre"), task_id=_TASK)
    post = materialize_observation_envelope(_codex("PostToolUse", "hook:post"), task_id=_TASK)

    pre_action = cast(ActionRecordedPayload, pre.drafts[0].draft.payload)
    post_action = cast(ActionRecordedPayload, post.drafts[0].draft.payload)
    assert pre_action.action_id == post_action.action_id
    assert pre.drafts[0].draft.event_id == post.drafts[0].draft.event_id
    # Distinct phases keep distinct role sets (and operations); only the action
    # identity is shared.
    assert [item.role for item in pre.drafts] == [PAIRED_ACTION_ROLE]
    assert [item.role for item in post.drafts] == [PAIRED_ACTION_ROLE, "result"]

    pre_link = paired_action_link(_codex("PreToolUse", "hook:pre"), pre, task_id=_TASK)
    post_link = paired_action_link(_codex("PostToolUse", "hook:post"), post, task_id=_TASK)
    assert pre_link is not None and post_link is not None
    assert pre_link.action_event_id == post_link.action_event_id
    assert pre_link.linked.drafts == ()
    assert [item.role for item in post_link.linked.drafts] == ["result"]
    result = cast(ResultRecordedPayload, post_link.linked.drafts[0].draft.payload)
    assert str(result.action_id) == post_link.action_id
    assert post_link.linked.coverage == post.coverage

    # Different calls, sessions or generations never share an action.
    other_call = materialize_observation_envelope(
        _codex("PreToolUse", "hook:pre-2", call="call_n2"), task_id=_TASK
    )
    assert other_call.drafts[0].draft.event_id != pre.drafts[0].draft.event_id
    other_generation = _codex("PreToolUse", "hook:pre-3")
    other_generation = replace(
        other_generation, cursor=replace(other_generation.cursor, source_generation=2)
    )
    assert (
        materialize_observation_envelope(other_generation, task_id=_TASK).drafts[0].draft.event_id
        != pre.drafts[0].draft.event_id
    )


def test_linked_post_keeps_captured_evidence_under_the_shared_action() -> None:
    """Delay, not drop: linking removes only the duplicate action draft."""

    fixture = cast(
        dict[str, Any], load_fixture_json("canonical/OBS-001-captured-evidence.case.json")
    )
    raw = fixture["input"]["envelope"]
    cursor = raw["cursor"]
    envelope = ObservationEnvelope(
        session_commitment=raw["session_commitment"],
        event_kind=raw["event_kind"],
        source_identity=raw["source_identity"],
        source=ObservationSource(raw["source"]),
        cursor=ObservationCursor(
            cursor["hook_seq"],
            cursor["session_stream_pos"],
            cursor["source_ordinal"],
            cursor["last_commitment"],
            cursor["mapping_version"],
        ),
        receipt_time=Timestamp(raw["receipt_time"]),
        structural_payload=JsonObject(raw["structural_payload"]),
        content_object_refs=tuple(raw["content_object_refs"]),
        gap_codes=tuple(raw["gap_codes"]),
    )
    manifests = tuple(
        ObservationContentManifest(
            object_id=item["object_id"],
            envelope_digest=item["envelope_digest"],
            content_kind=ObservationContentKind(item["content_kind"]),
            part_index=item["part_index"],
            part_count=item["part_count"],
            redacted=item["redacted"],
            content_digest=item["content_digest"],
            content_bytes=item["content_bytes"],
        )
        for item in fixture["input"]["manifests"]
    )
    task = fixture["input"]["task_id"]
    batch = materialize_observation_envelope(envelope, task_id=task, captured_content=manifests)
    link = paired_action_link(envelope, batch, task_id=task)
    assert link is not None
    assert paired_action_linked_roles(tuple(item.role for item in batch.drafts)) == tuple(
        item.role for item in link.linked.drafts
    )
    evidence = [
        item for item in link.linked.drafts if type(item.draft.payload) is EvidenceRecordedPayload
    ]
    assert evidence
    for item in evidence:
        assert item.draft.causal_parents == (link.action_event_id,)
    result = cast(ResultRecordedPayload, link.linked.drafts[-1].draft.payload)
    assert set(result.evidence_refs) == {
        cast(EvidenceRecordedPayload, item.draft.payload).evidence_id for item in evidence
    }
    assert link.action_event_id in {
        str(parent) for parent in link.linked.drafts[-1].draft.causal_parents
    }


def test_unpaired_and_post_only_batches_have_no_paired_action() -> None:
    unpaired = replace(
        _codex("PostToolUse", "hook:orphan"),
        gap_codes=(ObservationGapCode.UNPAIRED_EVENT.value,),
    )
    assert (
        paired_action_link(
            unpaired, materialize_observation_envelope(unpaired, task_id=_TASK), task_id=_TASK
        )
        is None
    )
    claude = replace(
        _codex("PostToolUse", "claude:post", tool="mcp__plugin_finishup_finishup__check"),
        source=ObservationSource.CLAUDE_HOOK,
    )
    batch = materialize_observation_envelope(claude, task_id=_TASK)
    assert [item.role for item in batch.drafts] == [PAIRED_ACTION_ROLE, "result"]
    assert paired_action_link(claude, batch, task_id=_TASK) is None
