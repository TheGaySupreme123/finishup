"""Bounded routine-read summary accounting and materialization tests."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator, ValidationError

from finishup.adapters.integrations.observation_admission import build_routine_read_summary
from finishup.application.observation_materialize import materialize_observation_envelope
from finishup.domain.events import EvidenceRecordedPayload
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationSource,
    observation_envelope_to_json,
    observation_selection_route,
    routine_read_summary_from_envelope,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.errors import ProtocolValueError

_SESSION_COMMITMENT = "hmac-sha256:" + "a" * 64
_CURSOR_COMMITMENT = "hmac-sha256:" + "b" * 64
_FENCE = "sha256:" + "c" * 64
_AUTHORITY_GENERATION = "sha256:" + "d" * 64
_SUBJECT_STATE = "sha256:" + "e" * 64
_TASK = "tsk_00000000-0000-4000-8000-000000000001"
_SELECTION_SESSION = "ses_00000000-0000-4000-8000-000000000002"
_WRITER = "wri_00000000-0000-4000-8000-000000000003"


def _route() -> dict[str, str]:
    return {
        "selection_task_id": _TASK,
        "selection_session_id": _SELECTION_SESSION,
        "selection_writer_id": _WRITER,
        "selection_authority_generation": _AUTHORITY_GENERATION,
    }


def _envelope(
    position: int,
    event_kind: str,
    *,
    call_id: str = "call-1",
    success: bool | None = None,
    gaps: tuple[str, ...] = (),
    route: dict[str, str] | None = None,
) -> ObservationEnvelope:
    payload: dict[str, object] = {
        "action": "routine_read",
        "tool_name": "Read",
        "tool_call_id": call_id,
        "subject_state_digest": _SUBJECT_STATE,
        **(route or _route()),
    }
    if success is not None:
        payload["success"] = success
    return ObservationEnvelope(
        session_commitment=_SESSION_COMMITMENT,
        event_kind=event_kind,
        source_identity=f"native:{position}",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=position * 10,
            event_position=position,
            last_source_commitment=_CURSOR_COMMITMENT,
            mapping_version="codex-obs-hook/1.0.0",
        ),
        receipt_time=Timestamp(f"2026-09-10T00:00:0{position}.000Z"),
        structural_payload=JsonObject(payload),
        content_object_refs=(),
        gap_codes=gaps,
    )


def test_summary_round_trip_binds_members_route_and_content_gap() -> None:
    gaps = ("content_unselected", "observation_input_loss")
    pre = _envelope(1, "PreToolUse", gaps=gaps)
    post = _envelope(2, "PostToolUse", gaps=gaps, success=True)

    summary_envelope = build_routine_read_summary((pre, post), _FENCE)
    summary = routine_read_summary_from_envelope(summary_envelope)

    assert summary.summary_count == 1
    assert summary.input_count == 2
    assert summary.coverage_gaps == gaps
    assert summary.cursor == post.cursor
    assert summary.selection_task_id == _TASK
    assert summary.selection_session_id == _SELECTION_SESSION
    assert summary.selection_writer_id == _WRITER
    assert summary.selection_authority_generation == _AUTHORITY_GENERATION
    assert tuple(member.phase for member in summary.members) == ("pre", "post")
    assert summary.members[0].receipt_time == pre.receipt_time
    assert summary.members[1].receipt_time == post.receipt_time


def test_summary_schema_accepts_wire_and_rejects_missing_route_or_extra_member() -> None:
    summary = build_routine_read_summary(
        (_envelope(1, "PreToolUse"), _envelope(2, "PostToolUse", success=True)),
        _FENCE,
    )
    wire = observation_envelope_to_json(summary)
    schema_path = (
        Path(__file__).parents[3] / "schemas/observations/routine-read-summary-1.0.0.schema.json"
    )
    validator: Any = Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))
    plain_wire = json.loads(canonical_encode(wire))
    validator.validate(plain_wire)

    missing_route = dict(plain_wire["structural_payload"])
    missing_route.pop("selection_task_id")
    with pytest.raises(ValidationError):
        validator.validate({**plain_wire, "structural_payload": missing_route})

    member = dict(plain_wire["structural_payload"]["members"][0])
    member["unexpected"] = "value"
    forged_members = (member, plain_wire["structural_payload"]["members"][1])
    with pytest.raises(ValidationError):
        validator.validate(
            {
                **plain_wire,
                "structural_payload": {
                    **plain_wire["structural_payload"],
                    "members": forged_members,
                },
            }
        )


@pytest.mark.parametrize(
    "success",
    [
        False,
        None,
    ],
)
def test_summary_rejects_unproven_post_and_orphan_pre(
    success: bool | None,
) -> None:
    pre = _envelope(1, "PreToolUse")
    post = _envelope(2, "PostToolUse", success=success)
    with pytest.raises(ProtocolValueError):
        build_routine_read_summary((pre, post), _FENCE)

    with pytest.raises(ProtocolValueError):
        build_routine_read_summary((pre,), _FENCE)


def test_summary_requires_post_cursor_to_follow_matching_pre() -> None:
    pre = _envelope(1, "PreToolUse")
    same_position_post = replace(
        _envelope(2, "PostToolUse", success=True),
        cursor=pre.cursor,
    )

    with pytest.raises(ProtocolValueError):
        build_routine_read_summary((pre, same_position_post), _FENCE)


def test_summary_rejects_cross_route_and_unsupported_gap() -> None:
    pre = _envelope(1, "PreToolUse")
    other_route = _route()
    other_route["selection_task_id"] = "tsk_00000000-0000-4000-8000-000000000004"
    post = _envelope(2, "PostToolUse", success=True, route=other_route)
    with pytest.raises(ProtocolValueError):
        build_routine_read_summary((pre, post), _FENCE)

    unsupported = _envelope(2, "PostToolUse", success=True, gaps=("truncated_payload",))
    with pytest.raises(ProtocolValueError):
        build_routine_read_summary((pre, unsupported), _FENCE)


def test_materializer_rejects_forged_summary_before_draft() -> None:
    summary = build_routine_read_summary(
        (_envelope(1, "PreToolUse"), _envelope(2, "PostToolUse", success=True)),
        _FENCE,
    )
    forged_payload = dict(summary.structural_payload)
    forged_payload["summary_count"] = 2
    forged = replace(summary, structural_payload=JsonObject(forged_payload))

    batch = materialize_observation_envelope(forged, task_id=_TASK)
    assert batch.drafts == ()
    assert batch.skip_reason == "invalid_routine_read_summary"
    assert batch.gaps == (ObservationGapCode.ROUTINE_READ_SUMMARY_INVALID.value,)


def test_materializer_emits_one_metadata_pointer_with_honest_summary_gap() -> None:
    summary = build_routine_read_summary(
        (
            _envelope(1, "PreToolUse", gaps=("content_unselected",)),
            _envelope(2, "PostToolUse", success=True, gaps=("content_unselected",)),
        ),
        _FENCE,
    )
    batch = materialize_observation_envelope(summary, task_id=_TASK)

    assert len(batch.drafts) == 1
    assert batch.summary is not None
    assert ObservationGapCode.ROUTINE_READ_SUMMARY_DETAIL_OMITTED.value in batch.gaps
    assert "content_unselected" in batch.gaps
    payload = cast(EvidenceRecordedPayload, batch.drafts[0].draft.payload)
    assert payload.description is not None
    assert payload.description.startswith("Routine-read summary observed")


def test_selection_route_is_closed_and_legacy_payload_remains_unbound() -> None:
    assert observation_selection_route(JsonObject({"tool_name": "Read"})) is None
    partial = _route()
    partial.pop("selection_writer_id")
    with pytest.raises(ProtocolValueError):
        observation_selection_route(JsonObject(partial))


@pytest.mark.parametrize(
    "reference",
    [
        "obl_00000000-0000-4000-8000-000000000004",
        "clm_00000000-0000-4000-8000-000000000005",
        "fnd_00000000-0000-4000-8000-000000000006",
    ],
)
def test_protection_reference_is_a_closed_structural_identifier(reference: str) -> None:
    envelope = _envelope(1, "PostToolUse", success=True)
    stamped = replace(
        envelope,
        structural_payload=JsonObject(
            {**envelope.structural_payload, "protection_reference": reference}
        ),
    )
    assert stamped.structural_payload["protection_reference"] == reference

    with pytest.raises(ProtocolValueError):
        replace(
            envelope,
            structural_payload=JsonObject(
                {**envelope.structural_payload, "protection_reference": "fnd_not-an-id"}
            ),
        )
