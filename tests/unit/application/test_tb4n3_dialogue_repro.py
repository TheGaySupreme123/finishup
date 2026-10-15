"""tb4n3 family D (finding dialogue) repros, issues #1024 and #1030.

Moved from the tb4n3 verification scratch (``scratch_D_dialogue/test_d_dialogue_repro.py``), where
all seven failed on 26e9cecf. Each test asserts the DESIRED behaviour, so a failure reproduces the
defect:

* D-6 (cargo S fnd_334854f8): a ``withdrawn`` or ``fixed`` ruling over a rejection survives a
  trimmed citation instead of becoming an open ``unassessable`` round.
* D-1 (ks S, vpp S, lake S): a reviewer limitation request (``state_unresolved_limitation``) is no
  longer receipt-blocking agent work. Changed from the scratch version, which asserted that no
  candidate has an actionable *kind*: under owner decision Q4 the request is still minted (it is a
  to-disclose item the agent acknowledges once), so the assertion is that it does not *demand work*.
* D-3 (vpp S): a re-raise over a settled answer under another kind mints nothing.
* D-2: a re-raise over a reasoned acknowledgement without newer material is a standing
  disagreement, not another review round.
* D-5 (N3-5): a later absence proof supersedes ``acknowledged_not_done``. Changed from the scratch
  version: the finding record carries ``resolution_frontier`` (the tested frontier of the proving
  check), the replay-derived fact that tells a proof recorded after the answer from one before it.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from dataclasses import replace

from builders.policy_cases import clm, evt, finding_record, fnd, obl, record, res
from finishup.application.check import SemanticJudgmentReview, validate_semantic_judgment
from finishup.domain.events import ResponseDisposition, ResponseRecordedPayload
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    CandidateFinding,
    Finding,
    FindingKind,
    finding_demands_work,
    finding_policy_identity,
    is_limitation_request,
)
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.kernel.finding_todo import (
    FindingTodoState,
    finding_blocks_receipt,
    finding_todo_state,
)
from finishup.ports.semantic import ReviewerChallenge, SemanticJudgment
from unit.application import test_semantic_post_validation as T

_FOREIGN = "evd_99999999-9999-4999-8999-999999999999"


def _review(
    case: DeterministicCase,
    judgment: SemanticJudgment,
    *,
    prior_finding_refs: frozenset[str] | None = None,
    settled_finding_refs: frozenset[str] | None = None,
) -> SemanticJudgmentReview:
    return validate_semantic_judgment(
        case,
        (),
        judgment,
        T._provenance(),
        expected_frontier=case.frontier,
        prior_finding_refs=prior_finding_refs,
        settled_finding_refs=settled_finding_refs,
    )


def _payload(case: DeterministicCase) -> Finding:
    payload = case.projection.findings[fnd(1)].payload
    assert payload is not None
    return payload


def _as_finding(candidate: CandidateFinding) -> Finding:
    """The finding the commit path records for an accepted candidate."""

    return Finding(
        finding_id=fnd(9),
        kind=candidate.kind,
        origin=candidate.origin,
        priority=candidate.priority,
        summary=candidate.summary,
        detail=candidate.detail,
        subject_refs=candidate.subject_refs,
        policy_id=candidate.policy_id,
        policy_version=candidate.policy_version,
        subject_frontier=candidate.subject_frontier,
        coverage=candidate.coverage,
        provenance=candidate.provenance,
        challenge=candidate.challenge,
        related_finding_ids=candidate.related_finding_ids,
    )


# --- D-2 (cargo S fnd_334854f8): a reviewer that ACCEPTS the rebuttal is recorded unassessable --


def test_withdrawn_over_a_rejection_survives_a_trimmed_citation() -> None:
    """cargo S: rejected at 599, closing review 628 had refs_reduced=12 and
    semantic_prior_verdicts_unsupported; the finding came back reviewer_verdict_unassessable,
    open with a round, and the agent had to self_verify a defect that never existed."""

    case = T._formal_crypto_case()  # fnd(1) rejected with a reason at 8
    review = _review(
        case,
        SemanticJudgment(
            "no_material_discrepancy", (), (T._verdict(1, "withdrawn", str(clm(1)), _FOREIGN),)
        ),
        prior_finding_refs=frozenset({str(fnd(1))}),
    )
    assert [(f, v) for f, v, _c in T._rulings(review)] == [(str(fnd(1)), "withdrawn")]


def test_fixed_over_a_rejection_with_a_trimmed_citation_is_not_an_open_round() -> None:
    case = T._formal_crypto_case()  # res(2) recorded at 12, after the finding (5)
    review = _review(
        case,
        SemanticJudgment(
            "no_material_discrepancy", (), (T._verdict(1, "fixed", str(res(2)), _FOREIGN),)
        ),
        prior_finding_refs=frozenset({str(fnd(1))}),
    )
    # The reviewer says the issue is gone and the agent says it never existed: neither side holds
    # it open, so it must not become an `unassessable` open round.
    assert [v for _f, v, _c in T._rulings(review)] != ["unassessable"]


# --- D-1 (ks S fnd_28afe22a, vpp S, lake S): the reviewer obeys P0-3 and FinishUP mints a blocker ---


def test_a_state_unresolved_limitation_challenge_is_not_receipt_blocking_work() -> None:
    """ks S: the reviewer wrote 'you cannot produce it ... record this as an unresolved verification
    limitation' (requested_next_step state_unresolved_limitation), citing the agent's own
    finishup-verification-limit decision. FinishUP minted it as an actionable priority-1
    task_requirement_unmet finding; the receipt of a reward-1.0 run read unresolved_findings_remain."""

    base = T._formal_crypto_case()
    case = replace(base, projection=replace(base.projection, findings={}, responses={}))
    challenge = replace(
        T._challenge(str(obl(1)), str(clm(1)), summary="Hidden-point accuracy not established"),
        finding_kind=FindingKind.TASK_REQUIREMENT_UNMET,
        requested_next_step="state_unresolved_limitation",
    )
    review = _review(case, SemanticJudgment("challenges_returned", (challenge,)))
    # Owner decision Q4: the request is minted (a to-disclose item the agent acknowledges once),
    # but it never demands work and never counts as receipt-blocking.
    minted = [_as_finding(c) for c in review.candidates]
    assert [is_limitation_request(f) for f in minted] == [True]
    blocking = [f for f in minted if finding_demands_work(f)]
    assert blocking == [], "a limitation-only challenge must not mint receipt-blocking agent work"


# --- D-3 (vpp S): re-raise over a settled answer under another kind mints a fresh finding --------


def _settled_case(disposition: ResponseDisposition) -> DeterministicCase:
    base = T._formal_crypto_case()
    finding = replace(
        _payload(base),
        kind=FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        priority=FINDING_KIND_TRAITS[FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS][0],
        policy_id=finding_policy_identity(FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS)[0],
        policy_version=finding_policy_identity(FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS)[1],
    )
    answer = ResponseRecordedPayload(
        finding_id=fnd(1),
        finding_frontier=T.FRONTIER,
        disposition=disposition,
        reason="The private reference is unavailable; claim narrowed and limitation disclosed.",
        evidence_refs=(res(2),) if disposition is ResponseDisposition.SELF_VERIFIED else (),
    )
    return replace(
        base,
        projection=replace(
            base.projection,
            findings={fnd(1): finding_record(finding, 5)},
            responses={fnd(1): record(answer, 13)},
        ),
    )


def _bookkeeping_reraise(restates: str | None) -> ReviewerChallenge:
    return replace(
        T._challenge(str(obl(1)), str(clm(1)), summary="Reference comparison still not done"),
        finding_kind=FindingKind.TASK_REQUIREMENT_UNMET,  # vpp: kind flipped on the re-raise
        requested_next_step="state_unresolved_limitation",
        restates=restates,
    )


def test_vpp_kind_switched_reraise_over_acknowledged_not_done_mints_nothing() -> None:
    case = _settled_case(ResponseDisposition.ACKNOWLEDGED_NOT_DONE)
    for restates in (str(fnd(1)), None):
        review = _review(
            case,
            SemanticJudgment("challenges_returned", (_bookkeeping_reraise(restates),)),
            prior_finding_refs=frozenset(),
            settled_finding_refs=frozenset({str(fnd(1))}),
        )
        assert review.candidates == (), f"restates={restates}: minted a new open finding"


def test_vpp_bookkeeping_reraise_over_self_verified_mints_nothing() -> None:
    case = _settled_case(ResponseDisposition.SELF_VERIFIED)
    for restates in (str(fnd(1)), None):
        challenge = replace(
            _bookkeeping_reraise(restates),
            finding_kind=FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        )
        review = _review(
            case,
            SemanticJudgment("challenges_returned", (challenge,)),
            prior_finding_refs=frozenset(),
            settled_finding_refs=frozenset({str(fnd(1))}),
        )
        assert review.candidates == (), f"restates={restates}: bookkeeping-only re-raise minted"


def test_reraise_over_a_reasoned_acknowledgement_without_newer_material_is_not_a_new_round() -> (
    None
):
    """vpp/cargo: agents answer `acknowledged` ('Agreed ... cannot be done'), never `rejected`. A
    same-kind repeat citing nothing newer than that answer is ruled answered_not_fixed (a round
    toward the budget), not a standing disagreement."""

    case = _settled_case(ResponseDisposition.ACKNOWLEDGED)
    challenge = replace(
        _bookkeeping_reraise(str(fnd(1))), finding_kind=FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    )
    review = _review(
        case,
        SemanticJudgment("challenges_returned", (challenge,)),
        prior_finding_refs=frozenset({str(fnd(1))}),
    )
    assert [(f, v) for f, v, _c in T._rulings(review)] == [(str(fnd(1)), "disputed_after_rebuttal")]


# --- D-5 (N3-5 generalised): acknowledged_not_done is a one-way door ----------------------------


def test_a_later_absence_proof_supersedes_acknowledged_not_done() -> None:
    base = T._formal_crypto_case()
    gave_up = ResponseRecordedPayload(
        finding_id=fnd(1),
        finding_frontier=T.FRONTIER,
        disposition=ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
        reason="Cannot link the result.",
    )
    proved = finding_record(
        _payload(base),
        5,
        resolved_by_check_event_id=evt(20),
        resolution_frontier=20,
    )
    projection = replace(
        base.projection, findings={fnd(1): proved}, responses={fnd(1): record(gave_up, 8)}
    )
    assert finding_todo_state(projection, fnd(1)) is FindingTodoState.VERIFIED_RESOLVED
    assert not finding_blocks_receipt(projection, fnd(1))
