"""Source-order, outcome and durability boundaries for early routine selection."""

from __future__ import annotations

from dataclasses import replace

from finishup.adapters.integrations.observation_admission import (
    AdmissionBuffer,
    BufferedInput,
    admission_buffer_from_json,
    admission_buffer_to_json,
    build_routine_read_summary,
    flush_admission,
    plan_admission,
)
from finishup.application.observation_materialize import materialize_observation_envelope
from finishup.domain.observation import ObservationCursor, ObservationEnvelope, ObservationSource
from finishup.domain.values import JsonObject, Timestamp

FENCE = "sha256:" + "1" * 64


def envelope(position: int, kind: str = "PostToolUse", call: str = "call1") -> ObservationEnvelope:
    return ObservationEnvelope(
        "hmac-sha256:" + "1" * 64,
        kind,
        f"native:{position}",
        ObservationSource.CODEX_HOOK,
        ObservationCursor(1, 0, position, "hmac-sha256:" + "2" * 64, "codex-obs-hook/1.0.0"),
        Timestamp("2026-09-10T00:00:00.000Z"),
        JsonObject(
            {
                "tool_name": "Read",
                "tool_call_id": call,
                **({"success": True} if kind == "PostToolUse" else {}),
            }
        ),
        (),
        (),
    )


def summary(inputs: tuple[ObservationEnvelope, ...], fence: str) -> ObservationEnvelope:
    assert fence.startswith("sha256:")
    assert all(item.event_kind in {"PreToolUse", "PostToolUse"} for item in inputs)
    return replace(
        inputs[-1],
        event_kind="RoutineReadSummary",
        source_identity="summary:" + ":".join(str(item.cursor.event_position) for item in inputs),
    )


def admit(
    buffer: AdmissionBuffer,
    event: ObservationEnvelope,
    *,
    focused: bool = True,
    candidate: bool = True,
    success: bool = True,
    fence: str = FENCE,
    now: int = 100,
):
    return plan_admission(
        buffer,
        event,
        host_session="host1",
        fence=fence,
        focused=focused,
        routine_candidate=candidate,
        proven_routine_success=success,
        now_ms=now,
        summary_builder=summary,
    )


def test_proven_pair_survives_reload_then_flushes_as_one_account() -> None:
    pre = admit(AdmissionBuffer(), envelope(1, "PreToolUse"), success=False)
    assert not pre.deliveries
    assert pre.buffer.pending_attempt_count == 1
    restored = admission_buffer_from_json(admission_buffer_to_json(pre.buffer))
    post = admit(restored, envelope(2))
    assert post.buffer.pending_attempt_count == 0
    assert post.buffer.summarized_call_count == 1
    flush = flush_admission(post.buffer, now_ms=2_100, summary_builder=summary)
    assert [item.source_identity for _, item in flush.deliveries] == ["summary:1:2"]
    assert not flush.buffer.inputs


def test_failed_or_unknown_post_preserves_original_pre_and_post() -> None:
    pre_event = envelope(1, "PreToolUse")
    post_event = envelope(2)
    pre = admit(AdmissionBuffer(), pre_event, success=False)
    post = admit(pre.buffer, post_event, success=False)
    assert [item for _, item in post.deliveries] == [pre_event, post_event]
    assert not post.buffer.inputs


def test_interleaving_never_passes_an_incomplete_native_attempt() -> None:
    a = admit(AdmissionBuffer(), envelope(1, "PreToolUse", "a"), success=False)
    b = admit(a.buffer, envelope(2, "PreToolUse", "b"), success=False)
    assert [item.source_identity for _, item in b.deliveries] == ["native:1"]
    a_post = admit(b.buffer, envelope(3, call="a"))
    assert [item.source_identity for _, item in a_post.deliveries] == ["native:2"]
    assert [item.envelope.source_identity for item in a_post.buffer.inputs] == ["native:3"]


def test_protected_event_flushes_earlier_summary_in_source_order() -> None:
    read = admit(AdmissionBuffer(), envelope(1))
    edit = envelope(2, "Mutation")
    result = admit(read.buffer, edit, candidate=False, success=False)
    assert [item.event_kind for _, item in result.deliveries] == ["RoutineReadSummary", "Mutation"]
    assert result.deliveries[1][1] is edit


def test_detailed_and_unknown_fences_keep_individual_identity() -> None:
    event = envelope(1)
    detailed = admit(AdmissionBuffer(), event, focused=False)
    unknown = admit(AdmissionBuffer(), event, fence="")
    assert detailed.deliveries == unknown.deliveries == (("host1", event),)


def test_scope_change_flushes_old_scope_and_keeps_new_scope_separate() -> None:
    old = admit(AdmissionBuffer(), envelope(1))
    new = admit(old.buffer, envelope(2), fence="sha256:" + "3" * 64)
    assert [item.source_identity for _, item in new.deliveries] == ["summary:1"]
    assert new.buffer.inputs[0].fence != FENCE


def test_due_pending_attempt_remains_an_individual_attempt() -> None:
    pending = admit(AdmissionBuffer(), envelope(1, "PreToolUse"), success=False)
    early = flush_admission(pending.buffer, now_ms=5_099, summary_builder=summary)
    assert not early.deliveries
    due = flush_admission(pending.buffer, now_ms=5_100, summary_builder=summary)
    assert due.deliveries == (("host1", envelope(1, "PreToolUse")),)


def test_due_routine_pre_materializes_as_pending_action() -> None:
    pre = envelope(1, "PreToolUse")
    pre = replace(
        pre,
        structural_payload=JsonObject({**pre.structural_payload, "action": "routine_read"}),
    )
    pending = admit(AdmissionBuffer(), pre, success=False)
    due = flush_admission(pending.buffer, now_ms=5_100, summary_builder=summary)

    assert due.deliveries == (("host1", pre),)
    batch = materialize_observation_envelope(
        due.deliveries[0][1], task_id="tsk_00000000-0000-4000-8000-000000000001"
    )
    assert batch.skip_reason is None
    assert [item.draft.schema.name for item in batch.drafts] == ["action_recorded"]


def test_historical_input_loss_gap_still_allows_later_success_summary() -> None:
    pre = replace(
        envelope(1, "PreToolUse"),
        gap_codes=("observation_input_loss",),
    )
    pending = admit(AdmissionBuffer(), pre, success=False)
    completed = admit(pending.buffer, envelope(2), success=True)
    flushed = flush_admission(completed.buffer, now_ms=2_100, summary_builder=summary)

    assert [item.event_kind for _, item in flushed.deliveries] == ["RoutineReadSummary"]


def test_clock_regression_flushes_instead_of_extending_retention() -> None:
    read = admit(AdmissionBuffer(), envelope(1), now=10_000)
    flushed = flush_admission(read.buffer, now_ms=9_999, summary_builder=summary)
    assert len(flushed.deliveries) == 1


def test_count_bound_flushes_without_rewriting_an_accepted_individual() -> None:
    buffer = AdmissionBuffer()
    for position in range(1, 16):
        result = admit(buffer, envelope(position, call=f"call{position}"))
        assert not result.deliveries
        buffer = result.buffer
    result = admit(buffer, envelope(16, call="call16"))
    assert len(result.deliveries) == 1
    assert not result.buffer.inputs


def test_classification_without_durable_success_is_delivered_individually() -> None:
    event = replace(
        envelope(1), structural_payload=JsonObject({"action": "routine_read", "tool_name": "Read"})
    )
    result = admit(AdmissionBuffer(), event, success=True)
    assert result.deliveries == (("host1", event),)
    assert not result.buffer.inputs


def test_legacy_buffer_without_success_does_not_block_later_work() -> None:
    event = replace(
        envelope(1), structural_payload=JsonObject({"action": "routine_read", "tool_name": "Read"})
    )
    buffer = AdmissionBuffer((BufferedInput("host1", FENCE, event, "success", 100),))
    restored = admission_buffer_from_json(admission_buffer_to_json(buffer))
    flushed = flush_admission(restored, now_ms=2100, summary_builder=build_routine_read_summary)
    # The original record is delivered in source order. On the 0.3 line the unprovable
    # summary is also accounted for: the input carries the ``routine_summary_invalid``
    # coverage gap and the lane records one bounded refusal (#764, #786).
    demoted = replace(event, gap_codes=("routine_summary_invalid",))
    assert flushed.deliveries == (("host1", demoted),)
    assert [(refusal.reason, refusal.input_count) for refusal in flushed.refusals] == [
        ("invalid_event_value_type", 1)
    ]
    assert not flushed.buffer.inputs
    later = plan_admission(
        restored,
        envelope(2, "Mutation"),
        host_session="host1",
        fence=FENCE,
        focused=True,
        routine_candidate=False,
        proven_routine_success=False,
        now_ms=2100,
        summary_builder=build_routine_read_summary,
    )
    assert later.deliveries == (("host1", demoted), ("host1", envelope(2, "Mutation")))
    assert not later.buffer.inputs
