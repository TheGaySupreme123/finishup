"""The latest assessed review's missing-item request survives replay and snapshots (issue #907)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import cast

import pytest

import unit.kernel.test_claim_correction_replay as claim_replay
from finishup.domain.events import (
    CheckMode,
    CheckRecordedPayload,
    EventSchema,
    LedgerRecord,
    MissingForAssessmentItem,
    PolicyVersion,
    decode_payload,
    encode_payload,
)
from finishup.domain.findings import CheckVerdict, SemanticDispatchKind, SemanticProvenance
from finishup.domain.values import Frontier
from finishup.kernel.projections import projection_from_snapshot, projection_snapshot
from finishup.kernel.reducers import replay
from finishup.ports.semantic import SamplingParams
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
from finishup.protocol.models import (
    CheckPolicyExecutionModel,
    CheckScopeModel,
    SemanticReason,
    SemanticStatus,
)

_DIGEST = "sha256:" + "a" * 64
_CLAIM = "clm_00000000-0000-4000-8000-000000000001"
_ITEMS = (
    MissingForAssessmentItem("command_identity", (), "structurally_unavailable_on_this_host"),
    MissingForAssessmentItem("verification_output", (_CLAIM,), "agent_suppliable"),
)


def _check(
    conclusion: str, items: tuple[MissingForAssessmentItem, ...] = ()
) -> CheckRecordedPayload:
    return CheckRecordedPayload(
        mode=CheckMode.SEMANTIC_IF_CONFIGURED,
        policies=(PolicyVersion("work-integrity", "0.1.0"),),
        scope=CheckScopeModel(claim_ids=(), obligation_ids=()),
        policy_executions=(
            CheckPolicyExecutionModel.model_validate(
                {
                    "policy_id": "work-integrity",
                    "policy_version": "0.1.0",
                    "outcome": "run",
                    "reason": "completed",
                }
            ),
        ),
        subject_frontier=Frontier(0, "genesis"),
        verdict=CheckVerdict.INSUFFICIENT_COVERAGE,
        returned_finding_ids=(),
        suppressed_count=0,
        coverage=Coverage(
            publication_channels=(PublicationChannel.ENGINE_DERIVED,),
            authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
            artifact_observation=ArtifactObservation.CONTENT_CAPTURED,
            evidence_immutability=EvidenceImmutability.METADATA_ONLY,
            ledger_freshness=LedgerFreshness.PARTIAL,
            check_types=(CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED),
            known_gaps=("semantic_packet_insufficient",),
        ),
        semantic_status=SemanticStatus.SUCCEEDED,
        semantic_reason=SemanticReason.SEMANTIC_COMPLETED,
        engine_version="0.1.0",
        projection_version="yoetz/0.1.0",
        semantic_provenance=SemanticProvenance(
            provider="fake",
            endpoint_profile_id="fake",
            endpoint_profile_version="1.0.0",
            model="fake/model",
            sdk_version="1.0.0",
            prompt_digest=_DIGEST,
            schema_digest=_DIGEST,
            policy_digest=_DIGEST,
            privacy_policy_digest=_DIGEST,
            sampling_params=SamplingParams(128),
            latency_ms=1,
            semantic_attempt_id="att_30000000-0000-4000-8000-000000000001",
            dispatch_kind=SemanticDispatchKind.EXTERNAL,
            privacy_receipt_id="egr_30000000-0000-4000-8000-000000000001",
            status=SemanticStatus.SUCCEEDED,
            reason=SemanticReason.SEMANTIC_COMPLETED,
            provider_request_id="fake-semantic-request-1",
            egress_authorization_id="aut_30000000-0000-4000-8000-000000000001",
            request_commitment="hmac-sha256:" + "b" * 64,
        ),
        semantic_conclusion=conclusion,
        missing_for_assessment=items,
    )


def _chain(*payloads: tuple[EventSchema, CheckRecordedPayload]) -> tuple[LedgerRecord, ...]:
    """Ledger-ordered check events built by the shared replay test builder.

    That builder keys only claim/action/result events; a check event is keyed by its own id.
    """

    original = claim_replay._logical_key  # pyright: ignore[reportPrivateUsage]
    records: list[LedgerRecord] = []
    previous = "genesis"
    try:
        for sequence, (schema, payload) in enumerate(payloads, 1):
            event = str(claim_replay._evt(sequence))  # pyright: ignore[reportPrivateUsage]

            def key(*_args: object, _event: str = event) -> str:
                return _event

            claim_replay._logical_key = key  # pyright: ignore[reportPrivateUsage]
            record = claim_replay._accepted(sequence, schema, payload, previous)  # pyright: ignore[reportPrivateUsage]
            records.append(record)
            previous = record.entry_digest
    finally:
        claim_replay._logical_key = original  # pyright: ignore[reportPrivateUsage]
    return tuple(records)


def test_named_items_decode_on_check_recorded_1_3_and_round_trip() -> None:
    payload = _check("insufficient_packet", _ITEMS)
    wire = encode_payload(payload)
    assert decode_payload(EventSchema("check_recorded", "1.3.0"), wire) == payload
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema("check_recorded", "1.2.0"), wire)
    # The field is optional on the unreleased 1.3.0: a check without items keeps its bytes.
    plain = encode_payload(_check("insufficient_packet"))
    assert "missing_for_assessment" not in cast(Mapping[str, object], plain)
    assert decode_payload(EventSchema("check_recorded", "1.3.0"), plain) == _check(
        "insufficient_packet"
    )
    with pytest.raises(ProtocolValueError):
        _check("no_material_discrepancy", _ITEMS)
    with pytest.raises(ProtocolValueError):
        _check("insufficient_packet", tuple(reversed(_ITEMS)))


def test_replay_keeps_the_latest_request_until_an_assessed_review_clears_it() -> None:
    requested = replay(
        _chain((EventSchema("check_recorded", "1.3.0"), _check("insufficient_packet", _ITEMS)))
    )
    pending = requested.pending_missing_for_assessment
    assert pending is not None and pending.items == _ITEMS and pending.source_frontier == 1

    snapshot = projection_snapshot(requested)
    assert projection_from_snapshot(snapshot) == requested

    cleared = replay(
        _chain(
            (EventSchema("check_recorded", "1.3.0"), _check("insufficient_packet", _ITEMS)),
            (EventSchema("check_recorded", "1.3.0"), _check("no_material_discrepancy")),
        )
    )
    assert cleared.pending_missing_for_assessment is None
    assert "pending_missing_for_assessment" not in projection_snapshot(cleared)

    # Greptile P1 on #940: an insufficient_packet that recorded no item (a 1.0.0-shape reply
    # that named nothing, or whose items were all dropped) assessed nothing and supplied nothing,
    # so the earlier request and its supplied_since context stay pending for the next packet.
    unnamed = replay(
        _chain(
            (EventSchema("check_recorded", "1.3.0"), _check("insufficient_packet", _ITEMS)),
            (EventSchema("check_recorded", "1.3.0"), _check("insufficient_packet")),
        )
    )
    kept = unnamed.pending_missing_for_assessment
    assert kept is not None and kept.items == _ITEMS and kept.source_frontier == 1
    assert projection_from_snapshot(projection_snapshot(unnamed)) == unnamed
    # A later assessed review still clears it.
    after = replay(
        _chain(
            (EventSchema("check_recorded", "1.3.0"), _check("insufficient_packet", _ITEMS)),
            (EventSchema("check_recorded", "1.3.0"), _check("insufficient_packet")),
            (EventSchema("check_recorded", "1.3.0"), _check("challenges_returned")),
        )
    )
    assert after.pending_missing_for_assessment is None


def test_a_projection_without_a_request_snapshots_unchanged() -> None:
    state = replay(_chain((EventSchema("check_recorded", "1.3.0"), _check("challenges_returned"))))
    assert state.pending_missing_for_assessment is None
    snapshot = projection_snapshot(state)
    assert "pending_missing_for_assessment" not in snapshot
    assert projection_from_snapshot(snapshot) == replace(state)
