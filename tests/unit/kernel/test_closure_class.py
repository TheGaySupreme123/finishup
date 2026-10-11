"""The one closure classifier: who owes the next move on a finding or an obligation (ADR-046).

tb4n3 measured the cost of about fourteen private answers to "does this item still bound
closure?": readiness called an acknowledged finding settled while the counter and the receipt
called it blocking. Every case below is a state the real runs reached, asserted through the one
function every surface now reads.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

import pytest

from builders.observed_runs import ObservedLedger
from builders.policy_cases import evd, evt, finding_record, fnd, obl, record
from yoetz.domain.events import (
    DecisionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    ResponseRecordedPayload,
)
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingChallenge,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
    SemanticDispatchKind,
    SemanticProvenance,
    finding_policy_identity,
)
from yoetz.domain.values import FindingId, Frontier, actor_id, obligation_id
from yoetz.kernel.closure_class import (
    FINDING_BASES,
    FindingClosureClass,
    ObligationClosureClass,
    ReceiptEffect,
    closure_counts,
    finding_closure,
    finding_closures,
    obligation_closures,
    review_can_rule,
)
from yoetz.kernel.projections import (
    FindingProjectionRecord,
    ProjectionRecord,
    ProjectionState,
    empty_projection_state,
)
from yoetz.kernel.reducers import replay
from yoetz.ports.semantic import SamplingParams
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from yoetz.protocol.models import SemanticReason, SemanticStatus

_DIGEST = "sha256:" + "3" * 64
_LIMITATION_STEP = "state_unresolved_limitation"


def _coverage(*, semantic: bool) -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.CURRENT,
        check_types=(
            (CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED)
            if semantic
            else (CheckType.DETERMINISTIC,)
        ),
        known_gaps=(),
    )


def _provenance() -> SemanticProvenance:
    return SemanticProvenance(
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
        semantic_attempt_id="att_00000000-0000-4000-8000-000000000001",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_00000000-0000-4000-8000-000000000001",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id="fake-1",
        egress_authorization_id="aut_00000000-0000-4000-8000-000000000001",
        request_commitment="hmac-sha256:" + "b" * 64,
    )


def _finding(
    number: int,
    *,
    kind: FindingKind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
    semantic: bool = False,
    next_step: str | None = None,
    refs: tuple[str, ...] | None = None,
) -> Finding:
    policy_id, policy_version = finding_policy_identity(kind)
    challenge = (
        FindingChallenge(
            discrepancy="The requirement cannot be reproduced here.",
            alternative_interpretation="A hidden evaluator may measure it.",
            requested_next_step=next_step,
            uncertainty="Unknown.",
        )
        if semantic and next_step is not None
        else None
    )
    return Finding(
        finding_id=fnd(number),
        kind=kind,
        origin=FindingOrigin.SEMANTIC_MODEL_DERIVED if semantic else FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="A requirement is not shown.",
        detail="Do it or state the limit.",
        subject_refs=(obl(number),) if refs is None else refs,  # type: ignore[arg-type]
        policy_id=policy_id,
        policy_version=policy_version,
        subject_frontier=Frontier(3, _DIGEST),
        coverage=_coverage(semantic=semantic),
        provenance=_provenance() if semantic else None,
        challenge=challenge,
    )


def _response(
    number: int, disposition: ResponseDisposition, *, frontier: int = 6, reasoned: bool = False
) -> ProjectionRecord[ResponseRecordedPayload]:
    reason = (
        None
        if disposition is ResponseDisposition.ACKNOWLEDGED and not reasoned
        else "A recorded reason."
    )
    refs = (evd(number),) if disposition is ResponseDisposition.SELF_VERIFIED else ()
    return record(
        ResponseRecordedPayload(
            fnd(number), Frontier(5, _DIGEST), disposition, reason, evidence_refs=refs
        ),
        frontier,
    )


def _state(
    findings: Mapping[FindingId, FindingProjectionRecord],
    responses: Mapping[FindingId, ProjectionRecord[ResponseRecordedPayload]] | None = None,
) -> ProjectionState:
    return replace(
        empty_projection_state(),
        frontier=20,
        head_digest=_DIGEST,
        findings=findings,
        responses={} if responses is None else responses,
        freshness=LedgerFreshness.CURRENT,
    )


def _one(
    finding: Finding,
    response: ResponseDisposition | None = None,
    *,
    reasoned: bool = False,
    **fields: object,
):
    findings = {finding.finding_id: replace(finding_record(finding, 4), **fields)}
    responses = (
        {}
        if response is None
        else {
            finding.finding_id: _response(
                int(str(finding.finding_id).rsplit("-", 1)[1]), response, reasoned=reasoned
            )
        }
    )
    state = _state(findings, responses)
    closure = finding_closure(state, finding.finding_id)
    assert closure is not None
    return state, closure


def test_every_basis_has_exactly_one_class_and_effect_pair() -> None:
    for basis, (klass, effect) in FINDING_BASES.items():
        assert isinstance(klass, FindingClosureClass), basis
        assert isinstance(effect, ReceiptEffect), basis
    # Settled is not harmless: only an accepted rejection leaves the label untouched.
    assert {
        basis
        for basis, (klass, effect) in FINDING_BASES.items()
        if klass is FindingClosureClass.SETTLED_DISCLOSED and effect is ReceiptEffect.NONE
    } == {"rejection_accepted"}


def test_an_open_finding_is_agent_work_whether_or_not_it_was_answered() -> None:
    _, silent = _one(_finding(1))
    assert (silent.closure_class, silent.basis) == (
        FindingClosureClass.AGENT_WORK,
        "open_unanswered",
    )
    assert silent.receipt_effect is ReceiptEffect.UNRESOLVED_FINDINGS_REMAIN
    assert silent.next_actions == ("repair", "reject", "acknowledge_not_done")
    _, answered = _one(_finding(2), ResponseDisposition.ACKNOWLEDGED)
    assert (answered.closure_class, answered.basis) == (
        FindingClosureClass.AGENT_WORK,
        "open_answered",
    )


def test_an_acknowledged_requirement_is_final_and_still_unresolved() -> None:
    """ks S / lake S: a genuine unmet requirement keeps ``unresolved_findings_remain``."""

    _, closure = _one(_finding(1), ResponseDisposition.ACKNOWLEDGED_NOT_DONE)
    assert (closure.closure_class, closure.basis) == (
        FindingClosureClass.SETTLED_UNMET,
        "acknowledged_not_done_requirement",
    )
    assert closure.receipt_effect is ReceiptEffect.UNRESOLVED_FINDINGS_REMAIN


def test_an_acknowledged_bookkeeping_finding_is_disclosed_not_unmet() -> None:
    """cargo D: the two ``action_without_result`` acknowledgements stop reading unresolved."""

    finding = _finding(1, kind=FindingKind.ACTION_WITHOUT_RESULT)
    _, closure = _one(finding, ResponseDisposition.ACKNOWLEDGED_NOT_DONE)
    assert (closure.closure_class, closure.basis) == (
        FindingClosureClass.SETTLED_DISCLOSED,
        "acknowledged_not_done_bookkeeping",
    )
    assert closure.receipt_effect is ReceiptEffect.INSUFFICIENT_COVERAGE


def test_a_self_verified_answer_is_disclosed_and_never_clean() -> None:
    _, closure = _one(_finding(1), ResponseDisposition.SELF_VERIFIED)
    assert (closure.closure_class, closure.basis, closure.receipt_effect) == (
        FindingClosureClass.SETTLED_DISCLOSED,
        "self_verified",
        ReceiptEffect.INSUFFICIENT_COVERAGE,
    )


def test_a_withdrawn_rejection_is_settled_and_leaves_the_label_alone() -> None:
    finding = _finding(1, semantic=True, next_step="act")
    findings = {fnd(1): finding_record(finding, 4)}
    responses = {fnd(1): _response(1, ResponseDisposition.REJECTED)}
    findings[fnd(1)] = replace(findings[fnd(1)], rejection_accepted_by_check_event_id=evt(9))
    closure = finding_closure(_state(findings, responses), fnd(1))
    assert closure is not None
    assert (closure.basis, closure.receipt_effect) == ("rejection_accepted", ReceiptEffect.NONE)
    assert evt(9) in closure.source_event_ids


def test_a_disputed_rebuttal_is_disclosed_and_never_clean() -> None:
    finding = _finding(1, semantic=True, next_step="act")
    findings = {
        fnd(1): replace(
            finding_record(finding, 4), disputed_after_rebuttal_by_check_event_id=evt(9)
        )
    }
    closure = finding_closure(
        _state(findings, {fnd(1): _response(1, ResponseDisposition.REJECTED)}), fnd(1)
    )
    assert closure is not None
    assert (closure.basis, closure.receipt_effect) == (
        "disputed_after_rebuttal",
        ReceiptEffect.INSUFFICIENT_COVERAGE,
    )


def test_a_reasoned_rejection_of_an_ai_finding_awaits_the_reviewer_ruling() -> None:
    """ks S, Stop 1: the gate offered repair / acknowledge and never "run check so the reviewer rules"."""

    finding = _finding(1, semantic=True, next_step="act")
    state, closure = _one(finding, ResponseDisposition.REJECTED)
    assert (closure.closure_class, closure.basis) == (
        FindingClosureClass.AWAITING_RULING,
        "rejected_awaiting_ruling",
    )
    assert closure.receipt_effect is ReceiptEffect.UNRESOLVED_FINDINGS_REMAIN
    assert closure.next_actions == ("recheck", "repair", "acknowledge_not_done")
    assert "acknowledge" not in closure.next_actions
    assert closure.since_frontier == 6
    # A route that cannot dispatch a review can never rule: the label says so instead of nagging.
    unavailable = finding_closure(state, fnd(1), review_can_rule_=False)
    assert unavailable is not None
    assert (unavailable.closure_class, unavailable.basis, unavailable.receipt_effect) == (
        FindingClosureClass.SETTLED_DISCLOSED,
        "rejected_review_unavailable",
        ReceiptEffect.INSUFFICIENT_COVERAGE,
    )


def test_a_rejected_local_finding_has_no_reviewer_to_wait_for() -> None:
    _, closure = _one(_finding(1), ResponseDisposition.REJECTED)
    assert closure.closure_class is FindingClosureClass.AGENT_WORK
    assert closure.basis == "open_answered"


# -- Owner decision Q4: a limitation request needs exactly one agent disclosure -----------------


def _limitation(number: int = 1, **kwargs: object) -> Finding:
    return _finding(
        number,
        kind=FindingKind.TASK_REQUIREMENT_UNMET,
        semantic=True,
        next_step=_LIMITATION_STEP,
        **kwargs,  # type: ignore[arg-type]
    )


def test_a_limitation_request_is_agent_work_to_disclose_not_blocking_work() -> None:
    _, closure = _one(_limitation())
    assert (closure.closure_class, closure.basis) == (
        FindingClosureClass.AGENT_WORK,
        "limitation_requested",
    )
    assert closure.next_actions == ("acknowledge",)
    assert closure.receipt_effect is ReceiptEffect.INSUFFICIENT_COVERAGE
    counts = closure_counts((closure,), ())
    assert (counts.findings_to_do, counts.findings_to_disclose) == (0, 1)
    assert counts.receipt_blocking_findings == 0


@pytest.mark.parametrize(
    "response", [ResponseDisposition.ACKNOWLEDGED, ResponseDisposition.ACKNOWLEDGED_NOT_DONE]
)
def test_one_acknowledgement_discloses_a_limitation(response: ResponseDisposition) -> None:
    # The disclosure is a reasoned answer (``respond`` requires the reason on a reviewer finding).
    _, closure = _one(_limitation(), response, reasoned=True)
    assert (closure.closure_class, closure.basis, closure.receipt_effect) == (
        FindingClosureClass.SETTLED_DISCLOSED,
        "limitation_disclosed",
        ReceiptEffect.INSUFFICIENT_COVERAGE,
    )
    counts = closure_counts((closure,), ())
    assert (counts.findings_disclosed, counts.findings_to_disclose, counts.findings_to_do) == (
        1,
        0,
        0,
    )


def test_an_unreasoned_acknowledgement_does_not_disclose_a_limitation() -> None:
    _, closure = _one(_limitation(), ResponseDisposition.ACKNOWLEDGED)
    assert (closure.closure_class, closure.basis) == (
        FindingClosureClass.AGENT_WORK,
        "limitation_requested",
    )


def test_an_act_challenge_never_qualifies_as_a_limitation_request() -> None:
    """Guard G1 (pretrain S): the reviewer saw an obtainable path, so giving up stays unmet."""

    finding = _finding(1, kind=FindingKind.TASK_REQUIREMENT_UNMET, semantic=True, next_step="act")
    _, silent = _one(finding)
    assert silent.basis == "open_unanswered"
    _, gave_up = _one(finding, ResponseDisposition.ACKNOWLEDGED_NOT_DONE)
    assert (gave_up.closure_class, gave_up.basis) == (
        FindingClosureClass.SETTLED_UNMET,
        "acknowledged_not_done_requirement",
    )


def test_a_verification_limit_decision_discloses_the_request_without_a_response() -> None:
    ledger = ObservedLedger()
    obligation = obl(1)
    ledger.append(
        EventSchema("obligation_published", "1.0.0"),
        ObligationPublishedPayload(
            obligation_id=obligation_id(obligation),
            description="Hit the hidden accuracy target",
            evidence_expectation="A private evaluator",
            status=ObligationStatus.OPEN,
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (obligation_id(obligation),)),
        observed=False,
    )
    before = replay(ledger.prefix)
    finding = _limitation(refs=(obligation,))
    state = replace(before, findings={fnd(1): finding_record(finding, before.frontier)})
    undisclosed = finding_closure(state, fnd(1))
    assert undisclosed is not None and undisclosed.basis == "limitation_requested"

    ledger.append(
        EventSchema("decision_recorded", "1.0.0"),
        DecisionRecordedPayload(
            statement=f"yoetz-verification-limit:{obligation}",
            rationale="The evaluator is hidden; I cannot run it.",
            authority=actor_id("agt_codex"),
        ),
        observed=False,
    )
    replayed = replay(ledger.prefix)
    after = replace(replayed, findings={fnd(1): finding_record(finding, before.frontier)})
    disclosed = finding_closure(after, fnd(1))
    assert disclosed is not None
    assert (disclosed.closure_class, disclosed.basis) == (
        FindingClosureClass.SETTLED_DISCLOSED,
        "limitation_disclosed",
    )
    # The obligation is then disclosed as verifiable only outside this environment.
    classes = obligation_closures(after, records=ledger.prefix)
    assert classes[obligation_id(obligation)].basis == "externally_evaluated"
    assert (
        classes[obligation_id(obligation)].closure_class is ObligationClosureClass.SETTLED_DISCLOSED
    )


def test_the_agents_own_words_never_make_a_finding_a_limitation() -> None:
    """Guard G2: an acknowledgement reason that says "could not find it" changes nothing."""

    plain = _finding(1, kind=FindingKind.TASK_REQUIREMENT_UNMET, semantic=True, next_step="act")
    findings = {fnd(1): finding_record(plain, 4)}
    gave_up = record(
        ResponseRecordedPayload(
            fnd(1),
            Frontier(5, _DIGEST),
            ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
            "I could not find the data and this is a verification limit.",
        ),
        6,
    )
    closure = finding_closure(_state(findings, {fnd(1): gave_up}), fnd(1))
    assert closure is not None and closure.closure_class is FindingClosureClass.SETTLED_UNMET


def test_a_linked_duplicate_pair_counts_once_under_the_earlier_finding() -> None:
    first = _finding(1)
    second = _finding(2)
    findings = {
        fnd(1): finding_record(first, 4),
        fnd(2): finding_record(second, 6),
    }
    responses = {
        fnd(1): _response(1, ResponseDisposition.ACKNOWLEDGED_NOT_DONE),
        fnd(2): record(
            ResponseRecordedPayload(
                fnd(2),
                Frontier(5, _DIGEST),
                ResponseDisposition.DUPLICATE_OF,
                None,
                duplicate_of_finding_id=fnd(1),
            ),
            8,
        ),
    }
    state = _state(findings, responses)
    closures = finding_closures(state)
    assert closures[fnd(2)].counts_as == fnd(1)
    counts = closure_counts(closures.values(), ())
    assert counts.findings_unmet == 1


def test_a_coverage_only_kind_is_not_a_work_kind() -> None:
    quiet = _finding(1, kind=FindingKind.LEDGER_STALE_OR_INCOMPLETE)
    state = _state({fnd(1): finding_record(quiet, 4)})
    assert finding_closure(state, fnd(1)) is None
    assert finding_closures(state) == {}


def test_a_later_absence_proof_resolves_the_finding() -> None:
    finding = _finding(1)
    state = _state({fnd(1): finding_record(finding, 4, resolved_by_check_event_id=evt(9))})
    closure = finding_closure(state, fnd(1))
    assert closure is not None
    assert (closure.closure_class, closure.basis, closure.receipt_effect) == (
        FindingClosureClass.RESOLVED,
        "absence_proved",
        ReceiptEffect.NONE,
    )


def test_review_can_rule_follows_the_latest_check_only() -> None:
    assert review_can_rule(empty_projection_state()) is True


def test_replaying_the_same_state_gives_the_same_classes() -> None:
    findings = {
        fnd(1): finding_record(_finding(1), 4),
        fnd(2): finding_record(_finding(2, semantic=True, next_step="act"), 4),
    }
    responses = {fnd(2): _response(2, ResponseDisposition.REJECTED)}
    state = _state(findings, responses)
    first = finding_closures(state)
    assert first == finding_closures(state)
    assert [item.closure_class for item in first.values()] == [
        FindingClosureClass.AGENT_WORK,
        FindingClosureClass.AWAITING_RULING,
    ]
