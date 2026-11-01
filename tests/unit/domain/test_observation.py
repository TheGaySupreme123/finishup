"""Unit tests for live observation domain values."""

from __future__ import annotations

from dataclasses import replace

import pytest

from finishup.domain.observation import (
    AdviceItem,
    AdviceSnapshot,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationLifecycle,
    ObservationSource,
    ObservationStatus,
    advice_item_from_json,
    advice_item_to_json,
    advice_snapshot_from_json,
    advice_snapshot_to_json,
    observation_cursor_from_json,
    observation_cursor_to_json,
    observation_earns_hook_observed,
    observation_envelope_from_json,
    observation_envelope_to_json,
    workspace_commitment_from_path,
)
from finishup.domain.values import JsonObject, Timestamp, finding_id
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from finishup.protocol.errors import ProtocolValueError

_COMMITMENT = "hmac-sha256:" + "a" * 64
_COMMITMENT_B = "hmac-sha256:" + "b" * 64
_DIGEST = "sha256:" + "c" * 64
_TIME = Timestamp("2026-07-22T21:00:00.000Z")
_FINDING = finding_id("fnd_00000000-0000-4000-8000-000000000001")


def _coverage() -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.HOOK_OBSERVED,),
        authorship_assurance=AuthorshipAssurance.HARNESS_OBSERVED,
        artifact_observation=ArtifactObservation.HOOK_OBSERVED,
        evidence_immutability=EvidenceImmutability.CONTENT_DIGEST,
        ledger_freshness=LedgerFreshness.CURRENT,
        check_types=(CheckType.DETERMINISTIC,),
        known_gaps=(),
    )


def _cursor(*, generation: int = 1, byte_pos: int = 0, event_pos: int = 0) -> ObservationCursor:
    return ObservationCursor(
        source_generation=generation,
        byte_position=byte_pos,
        event_position=event_pos,
        last_source_commitment=_COMMITMENT,
        mapping_version="codex-obs-1",
    )


def _envelope(**overrides: object) -> ObservationEnvelope:
    values: dict[str, object] = {
        "session_commitment": _COMMITMENT,
        "event_kind": "PostToolUse",
        "source_identity": "hook:1",
        "source": ObservationSource.CODEX_HOOK,
        "cursor": _cursor(),
        "receipt_time": _TIME,
        "structural_payload": JsonObject({"tool_name": "shell", "exit_status": 0}),
        "content_object_refs": (),
        "gap_codes": (),
    }
    values.update(overrides)
    return ObservationEnvelope(**values)  # type: ignore[arg-type]


def test_cursor_orders_by_generation_then_position() -> None:
    older = _cursor(generation=1, byte_pos=10, event_pos=2)
    newer_same_gen = _cursor(generation=1, byte_pos=11, event_pos=2)
    next_gen = _cursor(generation=2, byte_pos=0, event_pos=0)
    assert older < newer_same_gen < next_gen
    assert older.is_stale_relative_to(newer_same_gen)
    assert next_gen.is_stale_relative_to(older) is False


def test_envelope_rejects_transcript_and_path_keys() -> None:
    with pytest.raises(ProtocolValueError):
        _envelope(structural_payload=JsonObject({"transcript": "secret prose"}))
    with pytest.raises(ProtocolValueError):
        _envelope(structural_payload=JsonObject({"reasoning": "hidden"}))
    with pytest.raises(ProtocolValueError):
        _envelope(session_commitment="/tmp/codex/session.jsonl")
    with pytest.raises(ProtocolValueError):
        _envelope(structural_payload=JsonObject({"cwd": "/workspace/project"}))


def test_envelope_accepts_allowlisted_structural_facts() -> None:
    envelope = _envelope(
        structural_payload=JsonObject(
            {
                "tool_name": "apply_patch",
                "action": "write",
                "changed_paths_digest": _DIGEST,
                "result_status": "ok",
            }
        ),
        gap_codes=(ObservationGapCode.UNSUPPORTED_EVENT.value,),
    )
    assert envelope.source is ObservationSource.CODEX_HOOK
    wire = observation_envelope_to_json(envelope)
    assert observation_envelope_from_json(wire).event_kind == "PostToolUse"


@pytest.mark.parametrize("field", ["cursor_version", "model_id", "model_effort"])
def test_envelope_rejects_free_form_cursor_identity_tokens(field: str) -> None:
    with pytest.raises(ProtocolValueError):
        _envelope(structural_payload=JsonObject({field: "private value with spaces"}))


def test_envelope_accepts_bounded_cursor_identity_tokens() -> None:
    envelope = _envelope(
        structural_payload=JsonObject(
            {
                "cursor_version": "3.17.8",
                "model_id": "cursor-grok-4.6-medium",
                "model_effort": "medium",
            }
        )
    )
    assert envelope.structural_payload["cursor_version"] == "3.17.8"


def test_cursor_json_round_trip() -> None:
    cursor = _cursor(generation=3, byte_pos=99, event_pos=7)
    assert observation_cursor_from_json(observation_cursor_to_json(cursor)) == cursor


def test_workspace_commitment_from_path_is_hmac_and_path_free() -> None:
    commitment = workspace_commitment_from_path(b"k" * 32, "/tmp/project")
    assert commitment.startswith("hmac-sha256:")
    assert "/tmp" not in commitment
    other = workspace_commitment_from_path(b"k" * 32, "/tmp/other")
    assert commitment != other


def test_workspace_commitment_does_not_alias_unicode_normalization_forms() -> None:
    key = b"k" * 32

    nfc = workspace_commitment_from_path(key, "/tmp/\u00e9")
    nfd = workspace_commitment_from_path(key, "/tmp/e\u0301")

    assert nfc != nfd


def test_advice_snapshot_and_coverage_helper() -> None:
    item = AdviceItem(
        finding_id=_FINDING,
        rule_code="failed_command_unresolved",
        priority=1,
        summary="Unresolved failed command observed",
        detail="A tool result failed and was not followed by a successful retry",
        recommended_next_action="resolve_failed_command",
        evidence_refs=("hook:1",),
        coverage=_coverage(),
        freshness_frontier="frontier-1",
        origin="deterministic",
    )
    advice = AdviceSnapshot(
        ranked_finding_ids=(_FINDING,),
        evidence_basis_digest=_DIGEST,
        confidence_coverage=_coverage(),
        recommended_next_action="reground_status",
        freshness_frontier="frontier-1",
        suppression_identity="suppress-1",
        ranked_items=(item,),
    )
    assert advice.ranked_items[0].summary.startswith("Unresolved")
    assert advice.recommended_next_action == "reground_status"
    status = ObservationStatus(
        lifecycle=ObservationLifecycle.ACTIVE,
        workspace_commitment=_COMMITMENT,
        source_coverage={ObservationSource.CODEX_HOOK: True},
        last_observation_receipt_time=_TIME,
        lag_events=0,
        gaps=(),
        unsupported_events=(),
        advice_frontier="suppress-1",
    )
    assert observation_earns_hook_observed(status, True) is True
    assert observation_earns_hook_observed(status, False) is False
    degraded = ObservationStatus(
        lifecycle=ObservationLifecycle.DEGRADED,
        workspace_commitment=_COMMITMENT,
        source_coverage={ObservationSource.CODEX_HOOK: False},
        last_observation_receipt_time=None,
        lag_events=0,
        gaps=(ObservationGapCode.SOURCE_LAG.value,),
        unsupported_events=(),
        advice_frontier=None,
    )
    assert observation_earns_hook_observed(degraded, True) is False
    assert advice.semantic_attempt_state == "disabled"
    encoded = advice_snapshot_to_json(advice)
    assert encoded["semantic_attempt_state"] == "disabled"
    legacy = JsonObject(
        {key: value for key, value in encoded.items() if key != "semantic_attempt_state"}
    )
    assert advice_snapshot_from_json(legacy).semantic_attempt_state == "disabled"
    ready = AdviceSnapshot(
        ranked_finding_ids=(_FINDING,),
        evidence_basis_digest=_DIGEST,
        confidence_coverage=_coverage(),
        recommended_next_action="reground_status",
        freshness_frontier="frontier-1",
        suppression_identity="suppress-1",
        ranked_items=(item,),
        semantic_attempt_state="ready",
    )
    assert (
        advice_snapshot_from_json(advice_snapshot_to_json(ready)).semantic_attempt_state == "ready"
    )
    # A pre-#742 snapshot holding AI-powered items records a review that succeeded.
    semantic_item = replace(item, origin="semantic_model_derived")
    legacy_semantic = JsonObject(
        {
            key: value
            for key, value in advice_snapshot_to_json(
                replace(advice, ranked_items=(semantic_item,))
            ).items()
            if key != "semantic_attempt_state"
        }
    )
    assert advice_snapshot_from_json(legacy_semantic).semantic_attempt_state == "ready"


def test_advice_item_rejects_non_string_condition_identity_from_json() -> None:
    item = AdviceItem(
        finding_id=_FINDING,
        rule_code="failed_command_unresolved",
        priority=1,
        summary="Unresolved failed command observed",
        detail="A tool result failed and was not followed by a successful retry",
        recommended_next_action="resolve_failed_command",
        evidence_refs=("hook:1",),
        coverage=_coverage(),
        freshness_frontier="frontier-1",
        condition_identity="condition-1",
    )
    encoded = JsonObject({**advice_item_to_json(item), "condition_identity": 123})

    with pytest.raises(ProtocolValueError, match="invalid_event_value_type"):
        advice_item_from_json(encoded)
