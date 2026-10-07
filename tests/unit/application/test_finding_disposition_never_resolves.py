"""Only a later qualifying check resolves a finding; no response disposition ever does.

The 2026-07-30 dogfood agent repaired the record, recorded an evidence-backed ``acknowledged``
response, saw the next check return no findings, and still received ``unresolved_findings_remain``.
Half of that was deliberate and still is: a disposition is an answer on the record, not proof.
The other half was a defect (issue #458): ``application/receipt._finding_states`` hard-wired every
current finding to ``resolved=False``, so a repaired record could never earn a clean receipt. These
cases lock both halves of the contract the agent guidance now makes: dispositions never resolve,
and a later local qualifying check that finds the same issue absent does.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from yoetz.application.receipt import (
    _finding_states,  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
)
from yoetz.domain.events import ResponseRecordedPayload, encode_payload
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
    WaiverScope,
)
from yoetz.domain.values import (
    Frontier,
    event_id,
    evidence_id,
    finding_id,
    obligation_id,
    timestamp_from_string,
)
from yoetz.kernel.projections import (
    FindingProjectionRecord,
    ProjectionRecord,
    empty_projection_state,
    unanswered_finding_count,
)
from yoetz.kernel.receipt_capacity import receipt_blocking_finding_count
from yoetz.protocol.canonical import canonical_digest
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)

_DIGEST = "sha256:" + "1" * 64
_HEAD = "sha256:" + "2" * 64
_FINDING_ID = finding_id("fnd_00000000-0000-4000-8000-000000000001")
_SOURCE_EVENT_ID = event_id("evt_00000000-0000-4000-8000-000000000001")
_RESPONSE_EVENT_ID = event_id("evt_00000000-0000-4000-8000-000000000003")
_CHECK_EVENT_ID = event_id("evt_00000000-0000-4000-8000-000000000004")


def _coverage() -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.ARTIFACT_VERIFIED,
        evidence_immutability=EvidenceImmutability.CONTENT_DIGEST,
        ledger_freshness=LedgerFreshness.CURRENT,
        check_types=(CheckType.DETERMINISTIC,),
        known_gaps=(),
    )


def _finding(kind: FindingKind) -> Finding:
    return Finding(
        finding_id=_FINDING_ID,
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="A requested item was never attempted.",
        detail="Record the exact attempted items.",
        subject_refs=(obligation_id("obl_00000000-0000-4000-8000-000000000001"),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=Frontier(1, _DIGEST),
        coverage=_coverage(),
    )


def _response(disposition: ResponseDisposition) -> ResponseRecordedPayload:
    reason = None if disposition is ResponseDisposition.ACKNOWLEDGED else "Stated on the record."
    waiver_scope = WaiverScope.FINDING_ONLY if disposition is ResponseDisposition.WAIVED else None
    # Deliberately far future: this case is about an *unexpired* waiver still failing to resolve
    # its finding. A near-term date would silently become the expired-waiver path once it passed,
    # and a clock-derived one would make the payload digest nondeterministic.
    waiver_expiry = (
        timestamp_from_string("2999-01-01T00:00:00.000Z")
        if disposition is ResponseDisposition.WAIVED
        else None
    )
    return ResponseRecordedPayload(
        finding_id=_FINDING_ID,
        finding_frontier=Frontier(1, _DIGEST),
        disposition=disposition,
        # Issue #984: a self-verification always cites the agent's own recorded evidence.
        evidence_refs=(
            (evidence_id("evd_00000000-0000-4000-8000-000000000984"),)
            if disposition is ResponseDisposition.SELF_VERIFIED
            else ()
        ),
        reason=reason,
        waiver_scope=waiver_scope,
        waiver_expiry=waiver_expiry,
        # Issue #996: a duplicate link names an earlier finding; this one is not recorded here,
        # so the link does not hold and the finding keeps its own (open) state.
        duplicate_of_finding_id=(
            finding_id("fnd_00000000-0000-4000-8000-000000000996")
            if disposition is ResponseDisposition.DUPLICATE_OF
            else None
        ),
    )


def _projection(
    response: ResponseRecordedPayload | None,
    kind: FindingKind = FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
    *,
    resolved: bool = False,
):
    finding = _finding(kind)
    findings = {
        _FINDING_ID: FindingProjectionRecord(
            payload=finding,
            payload_digest=canonical_digest(encode_payload(finding)),
            redacted=False,
            source_event_id=_SOURCE_EVENT_ID,
            source_frontier=1,
            resolved_by_check_event_id=_CHECK_EVENT_ID if resolved else None,
        )
    }
    responses: dict[object, object] = {}
    if response is not None:
        responses[response.finding_id] = ProjectionRecord(
            payload=response,
            payload_digest=canonical_digest(encode_payload(response)),
            redacted=False,
            source_event_id=_RESPONSE_EVENT_ID,
            source_frontier=2,
        )
    return replace(
        empty_projection_state(),
        frontier=2,
        head_digest=_HEAD,
        findings=findings,
        responses=responses,
        freshness=LedgerFreshness.CURRENT,
    )


@pytest.mark.parametrize("disposition", tuple(ResponseDisposition))
def test_no_disposition_marks_a_finding_resolved(disposition: ResponseDisposition) -> None:
    projection = _projection(_response(disposition))
    states = _finding_states(projection)
    assert [state.resolved for state in states] == [False], (
        f"{disposition.value} resolved the finding; the agent guidance promises it does not"
    )
    assert unanswered_finding_count(projection, ()) == 0
    # ``self_verified`` (issue #984) is never resolved, but it is not agent work: it leaves the
    # receipt-blocking count and keeps the conclusion from reading clean instead.
    expected = 0 if disposition is ResponseDisposition.SELF_VERIFIED else 1
    assert receipt_blocking_finding_count(projection) == expected


def test_an_unanswered_finding_is_also_unresolved() -> None:
    states = _finding_states(_projection(None))
    assert [state.resolved for state in states] == [False]


def test_non_actionable_finding_is_unanswered_but_does_not_block_a_clean_receipt() -> None:
    # No accepted record says the observation service authored this row, so it is ordinary
    # response work; only an observation-authored limitation leaves the counter (issue #911).
    projection = _projection(None, FindingKind.LEDGER_STALE_OR_INCOMPLETE)
    assert unanswered_finding_count(projection, ()) == 1
    assert receipt_blocking_finding_count(projection) == 0


def test_the_finding_kind_the_dogfood_hit_is_actionable() -> None:
    """Actionable kinds are the ones that bind the receipt conclusion."""

    assert FINDING_KIND_TRAITS[FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED][1] is True


@pytest.mark.parametrize(
    "disposition",
    (None, ResponseDisposition.ACKNOWLEDGED, ResponseDisposition.REJECTED),
)
def test_a_later_qualifying_check_resolves_whatever_the_disposition(
    disposition: ResponseDisposition | None,
) -> None:
    """The proof lives on the finding record, set only by the reducer from a qualifying check.

    The receipt state and the status counter read that one fact, so a repaired record whose
    issue a later check found absent earns a clean receipt with or without a response. A
    verified-resolved row with no response is final (``respond`` refuses it), so it is not
    response work either: counting it would leave an item no action can clear.
    """

    projection = _projection(None if disposition is None else _response(disposition), resolved=True)
    assert [state.resolved for state in _finding_states(projection)] == [True]
    assert receipt_blocking_finding_count(projection) == 0
    assert unanswered_finding_count(projection, ()) == 0


def test_provenance_dispute_pins_the_row_unresolved_on_the_released_wire() -> None:
    """``status-result`` 1.1.0 freezes ``provenance_disputed`` rows to ``resolved=false``.

    The shared rule honours that pin instead of letting the receipt and the status view disagree,
    so a disputed finding keeps blocking even when a later check proved the issue absent.
    """

    projection = _projection(_response(ResponseDisposition.PROVENANCE_DISPUTED), resolved=True)
    assert [state.resolved for state in _finding_states(projection)] == [False]
    assert receipt_blocking_finding_count(projection) == 1


def test_an_unreadable_response_keeps_a_proven_row_conservatively_unresolved() -> None:
    projection = _projection(None, resolved=True)
    tombstone: ProjectionRecord[ResponseRecordedPayload] = ProjectionRecord(
        payload=None,
        payload_digest=_DIGEST,
        redacted=True,
        source_event_id=_RESPONSE_EVENT_ID,
        source_frontier=2,
    )
    projection = replace(projection, responses={_FINDING_ID: tombstone})
    assert [state.resolved for state in _finding_states(projection)] == [False]
    assert receipt_blocking_finding_count(projection) == 1
