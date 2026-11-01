"""tb4n1 B3 (#998): the receipt names the closed cause of a recorded observation input loss."""

from __future__ import annotations

from builders.observed_runs import ObservedLedger, receipt_limitations
from finishup.application.observation_materialize import materialize_selection_loss
from finishup.domain.events import EventSchema, EvidenceRecordedPayload
from finishup.domain.observation import ObservationSource
from finishup.domain.observation_loss import ObservationSelectionLoss
from finishup.domain.values import timestamp_from_string

_SESSION_COMMITMENT = "hmac-sha256:" + "a" * 64


def _loss(causes: tuple[str, ...]) -> ObservationSelectionLoss:
    return ObservationSelectionLoss(
        lane="sha256:" + "b" * 64,
        source=ObservationSource.CODEX_HOOK,
        session_commitment=_SESSION_COMMITMENT,
        source_generation=1,
        task_id="tsk_00000000-0000-4000-8000-000000000001",
        session_id="ses_00000000-0000-4000-8000-000000000001",
        writer_id="wri_00000000-0000-4000-8000-000000000001",
        authority_generation="sha256:" + "c" * 64,
        causes=causes,
    )


def _marker_payload(causes: tuple[str, ...]) -> EvidenceRecordedPayload:
    batch = materialize_selection_loss(
        _loss(causes), observed_at=timestamp_from_string("2026-10-07T09:00:00.000Z")
    )
    (draft,) = batch.drafts
    payload = draft.draft.payload
    assert isinstance(payload, EvidenceRecordedPayload)
    return payload


def test_the_loss_marker_names_its_refusal_cause() -> None:
    payload = _marker_payload(("capture_scope_unknown",))
    assert payload.description is not None
    assert "Refusal cause: capture_scope_unknown. " in payload.description
    assert "Refusal cause" not in (_marker_payload(()).description or "")


def test_the_receipt_discloses_the_recorded_cause_only_from_service_markers() -> None:
    schema = EventSchema("evidence_recorded", "1.0.0")
    ledger = ObservedLedger()
    ledger.append(schema, _marker_payload(("capture_scope_unknown",)), observed=True)
    body = receipt_limitations(ledger, extra_gaps=("observation_input_loss",))
    assert "Recorded refusal cause: capture_scope_unknown." in body

    forged = ObservedLedger()
    forged.append(schema, _marker_payload(("queue_bytes",)), observed=False)
    body = receipt_limitations(forged, extra_gaps=("observation_input_loss",))
    assert "Recorded refusal cause" not in body
