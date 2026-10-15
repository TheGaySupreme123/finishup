"""Projection construction, snapshot, and digest conformance."""

from __future__ import annotations

import os
import subprocess
import sys
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from builders.policy_cases import evd, evidence_record
from finishup.domain.events import (
    EVIDENCE_SCHEMA_VERSION,
    ActionKind,
    ActionRecordedPayload,
    EventSchema,
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationChangeKind,
    ObligationPublishedPayload,
    ObligationStatus,
    decode_payload,
    encode_payload,
)
from finishup.domain.values import action_id, event_id, obligation_id, timestamp_from_datetime
from finishup.kernel.projections import (
    PROJECTION_GENERATION,
    PROJECTION_VERSION,
    ObligationProjectionRecord,
    ProjectionRecord,
    ProjectionState,
    empty_projection_state,
    projection_digest,
    projection_from_snapshot,
    projection_snapshot,
)
from finishup.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse
from finishup.protocol.coverage import EvidenceImmutability, LedgerFreshness
from fixture_loader import load_fixture_json

_DIGEST = "sha256:" + "1" * 64
_EVENT_ID = event_id("evt_00000000-0000-4000-8000-000000000001")
_ACTION_ID = action_id("act_00000000-0000-4000-8000-000000000002")
_OBLIGATION_ID = obligation_id("obl_00000000-0000-4000-8000-000000000003")
_SRC_ROOT = Path(__file__).resolve().parents[3] / "src"


def _fixture_expected_projection() -> dict[str, Any]:
    document = cast(dict[str, Any], load_fixture_json("replay/empty.case.json"))
    expected = cast(dict[str, Any], document["expected"])
    return cast(dict[str, Any], expected["final_projection"])


def _action_payload() -> ActionRecordedPayload:
    return ActionRecordedPayload(
        action_id=_ACTION_ID,
        action_kind=ActionKind.OTHER,
        description="Exercise projection snapshots",
        obligation_refs=(),
    )


def _action_record() -> ProjectionRecord[ActionRecordedPayload]:
    payload = _action_payload()
    return ProjectionRecord(
        payload=payload,
        payload_digest=canonical_digest(encode_payload(payload)),
        redacted=False,
        source_event_id=_EVENT_ID,
        source_frontier=1,
    )


def _state_with_actions(
    actions: dict[object, object],
) -> ProjectionState:
    return replace(
        empty_projection_state(),
        frontier=1,
        head_digest=_DIGEST,
        actions=cast(Any, actions),
        freshness=LedgerFreshness.CURRENT,
    )


def test_empty_full_incremental_replay_match() -> None:
    first = empty_projection_state()
    second = empty_projection_state()
    assert first == second
    assert projection_snapshot(first) == projection_snapshot(second)
    assert projection_digest(first) == projection_digest(second)


def test_projection_snapshot_order_is_stable() -> None:
    snapshot = projection_snapshot(empty_projection_state())
    assert tuple(snapshot) == (
        "frontier",
        "head_digest",
        "plans",
        "obligations",
        "decisions",
        "assignments",
        "actions",
        "results",
        "evidence",
        "claims",
        "contradictions",
        "findings",
        "responses",
        "latest_tested_state",
        "freshness",
        "unknown_event_count",
        "coverage_gaps",
    )


@pytest.mark.parametrize("hash_seed", ("0", "1", "4294967295"))
def test_projection_digest_is_hash_seed_and_locale_stable(
    hash_seed: str,
    tmp_path: Path,
) -> None:
    script = (
        "import sys;"
        f"sys.path.insert(0,{str(_SRC_ROOT)!r});"
        "from finishup.kernel.projections import empty_projection_state,projection_digest;"
        "print(projection_digest(empty_projection_state()))"
    )
    environment = os.environ.copy()
    environment.update({"PYTHONHASHSEED": hash_seed, "LC_ALL": "C", "TZ": "UTC"})
    result = subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert result.stdout == _fixture_expected_projection()["digest"] + "\n"


def test_projection_record_and_snapshot_shapes_are_exact() -> None:
    assert PROJECTION_VERSION == "yoetz/0.1.0"
    assert PROJECTION_GENERATION == 1
    expected = _fixture_expected_projection()
    state = empty_projection_state()
    assert projection_snapshot(state) == expected["snapshot"]
    assert projection_digest(state) == expected["digest"]

    action_state = _state_with_actions({_ACTION_ID: _action_record()})
    record_snapshot = cast(dict[str, Any], projection_snapshot(action_state)["actions"])[_ACTION_ID]
    assert tuple(cast(dict[str, Any], record_snapshot)) == (
        "payload",
        "payload_digest",
        "redacted",
        "source_event_id",
        "source_frontier",
    )
    assert cast(dict[str, Any], record_snapshot)["source_frontier"] == "1"


def test_projection_snapshot_codec_round_trips_canonical_bytes() -> None:
    state = _state_with_actions({_ACTION_ID: _action_record()})
    snapshot = projection_snapshot(state)
    decoded = projection_from_snapshot(snapshot)
    assert decoded == state
    assert canonical_encode(projection_snapshot(decoded)) == canonical_encode(snapshot)


def _digest_bound_evidence_payload() -> EvidenceRecordedPayload:
    """An evidence payload only ``evidence_recorded/1.1.0`` admits (it carries a digest binding)."""

    return EvidenceRecordedPayload(
        evidence_id=evd(1),
        evidence_kind=EvidenceKind.ARTIFACT,
        strength=EvidenceImmutability.CONTENT_DIGEST,
        observed_at=timestamp_from_datetime(datetime(2026, 8, 27, 17, 5, tzinfo=UTC)),
        content_digest="sha256:" + "11" * 32,
        description="Diff of the reviewed change.",
        digest_binding=EvidenceDigestBinding(
            subject=EvidenceDigestSubject.SOURCE_DIFF,
            content_availability=EvidenceContentAvailability.DIGEST_ONLY,
            byte_count=128,
            provenance=EvidenceDigestProvenance.CALLER_ASSERTED,
        ),
    )


def test_projection_snapshot_codec_round_trips_later_schema_versions() -> None:
    """A record whose payload only a later wire version admits still rehydrates (issue #427).

    Snapshot records carry no schema version. The decoder used to pin every family to "1.0.0", so
    an evidence record published as ``evidence_recorded/1.1.0`` with a ``digest_binding`` encoded
    fine but could never be decoded again: every frozen-case rehydration (privacy-wait replay,
    ledger recovery) of a task holding such evidence failed as ``invalid_projection_state`` and was
    reported as non-retryable STORAGE_CORRUPT on an intact bundle.
    """

    payload = _digest_bound_evidence_payload()
    encoded = encode_payload(payload)
    with pytest.raises(ValueError):
        decode_payload(EventSchema("evidence_recorded", "1.0.0"), encoded)
    assert decode_payload(EventSchema("evidence_recorded", EVIDENCE_SCHEMA_VERSION), encoded) == (
        payload
    )

    state = replace(
        empty_projection_state(),
        frontier=1,
        head_digest=_DIGEST,
        evidence=cast(Any, {payload.evidence_id: evidence_record(payload, 1)}),
        freshness=LedgerFreshness.CURRENT,
    )
    snapshot = projection_snapshot(state)
    decoded = projection_from_snapshot(snapshot)
    assert decoded == state
    assert decoded.evidence[payload.evidence_id].payload == payload
    assert canonical_encode(projection_snapshot(decoded)) == canonical_encode(snapshot)


def test_projection_snapshot_decoder_rejects_open_or_contradictory_shapes() -> None:
    snapshot = cast(
        dict[str, Any],
        strict_json_parse(
            canonical_encode(
                projection_snapshot(_state_with_actions({_ACTION_ID: _action_record()}))
            )
        ),
    )
    with_extra = deepcopy(snapshot)
    with_extra["unexpected"] = None
    with pytest.raises(ValueError, match="invalid_projection_state"):
        projection_from_snapshot(with_extra)

    wrong_source = deepcopy(snapshot)
    action = cast(
        dict[str, Any],
        cast(dict[str, Any], wrong_source["actions"])[_ACTION_ID],
    )
    cast(dict[str, Any], action["payload"])["action_id"] = (
        "act_00000000-0000-4000-8000-000000000099"
    )
    with pytest.raises(ValueError, match="invalid_projection_state"):
        projection_from_snapshot(wrong_source)


def test_obligation_plan_change_emits_exact_empty_replacement_array() -> None:
    payload = ObligationPublishedPayload(
        obligation_id=_OBLIGATION_ID,
        description="Retain the disclosed obligation",
        evidence_expectation="A reviewed resolution",
        status=ObligationStatus.OPEN,
    )
    record = ObligationProjectionRecord(
        payload=payload,
        payload_digest=canonical_digest(encode_payload(payload)),
        redacted=False,
        source_event_id=_EVENT_ID,
        source_frontier=1,
        plan_change=ObligationChangeKind.WAIVED,
        plan_change_reason="The waiver retains history.",
        superseded_by_obligation_ids=(),
    )
    state = replace(
        empty_projection_state(),
        frontier=1,
        head_digest=_DIGEST,
        obligations={_OBLIGATION_ID: record},
        freshness=LedgerFreshness.CURRENT,
    )
    obligations = cast(dict[str, Any], projection_snapshot(state)["obligations"])
    snapshot = cast(dict[str, Any], obligations[_OBLIGATION_ID])
    assert snapshot["plan_change"] == "waived"
    assert snapshot["superseded_by_obligation_ids"] == []


def test_null_payload_tombstone_bit_does_not_claim_redaction_cause() -> None:
    tombstone: ProjectionRecord[ActionRecordedPayload] = ProjectionRecord(
        payload=None,
        payload_digest=_DIGEST,
        redacted=True,
        source_event_id=_EVENT_ID,
        source_frontier=1,
    )
    state = _state_with_actions({_ACTION_ID: tombstone})
    snapshot = projection_snapshot(state)
    action = cast(dict[str, Any], cast(dict[str, Any], snapshot["actions"])[_ACTION_ID])
    assert action["payload"] is None
    assert action["redacted"] is True
    assert snapshot["coverage_gaps"] == []


def test_projection_mappings_are_defensive_and_records_are_frozen() -> None:
    source: dict[object, object] = {_ACTION_ID: _action_record()}
    state = _state_with_actions(source)
    source.clear()
    assert tuple(state.actions) == (_ACTION_ID,)
    with pytest.raises(TypeError):
        cast(dict[object, object], state.actions)[_ACTION_ID] = _action_record()
    with pytest.raises(FrozenInstanceError):
        cast(Any, _action_record()).redacted = True


def test_corruption_requires_rebuild() -> None:
    payload = _action_payload()
    corrupt = ProjectionRecord(
        payload=payload,
        payload_digest=_DIGEST,
        redacted=False,
        source_event_id=_EVENT_ID,
        source_frontier=1,
    )
    with pytest.raises(ValueError, match="invalid_projection_state"):
        _state_with_actions({_ACTION_ID: corrupt})

    with pytest.raises(ValueError, match="invalid_projection_state"):
        ProjectionRecord[ActionRecordedPayload](
            payload=None,
            payload_digest=_DIGEST,
            redacted=False,
            source_event_id=_EVENT_ID,
            source_frontier=1,
        )

    with pytest.raises(ValueError, match="invalid_projection_state"):
        replace(
            empty_projection_state(),
            frontier=1,
            head_digest=_DIGEST,
            freshness=LedgerFreshness.PARTIAL,
            coverage_gaps=(f"unknown_event:{_EVENT_ID}:future_family@2.0.0",),
            unknown_event_count=0,
        )
